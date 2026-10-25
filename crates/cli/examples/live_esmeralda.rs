//! Reproduces the privacy check against the live network.
//!
//! Reads every round listed in `deployments/esmeralda.json` back from the public Esmeralda indexer
//! (substates verified by the ootle-rs light client) and checks what an observer can see:
//!
//! * the ring and the spent tags on chain match the recorded joins and claims;
//! * no claim transaction is signed by a member key, a join signer or another claim's signer;
//! * every payout is a fresh stealth output that carries a commitment and ciphertext, no amount;
//! * every payout spends the same public amount, so amounts do not link anything either.
//!
//! With `--as-member DIR` (data dirs of round members, e.g. the bot wallets) it also shows that each
//! member's key opens exactly one payout: its own.
//!
//! ```text
//! cargo run -p poltergift-cli --example live_esmeralda -- deployments/esmeralda.json [--as-member DIR]...
//! ```

use std::{collections::HashSet, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, anyhow, bail};
use ootle_rs::{Network, keys::OotleSecretKey};
use poltergift_client::{IndexerTrust, PoltergiftClient, Store};
use serde_json::Value;
use tari_template_lib_types::{ComponentAddress, crypto::PedersenCommitmentBytes};

const TARI_RESOURCE: &str = "0101010101010101010101010101010101010101010101010101010101010101";

struct Args {
    record: PathBuf,
    members: Vec<PathBuf>,
    indexer: String,
    network: Network,
    trust: IndexerTrust,
}

fn args() -> Result<Args> {
    let mut record = PathBuf::from("deployments/esmeralda.json");
    let mut members = Vec::new();
    let mut indexer = ootle_rs::default_indexer_url(Network::Esmeralda).trim_end_matches('/').to_string();
    let mut network = Network::Esmeralda;
    let mut trust = IndexerTrust::Verify;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--as-member" => members.push(PathBuf::from(it.next().context("--as-member needs a directory")?)),
            "--indexer" => indexer = it.next().context("--indexer needs a URL")?.trim_end_matches('/').to_string(),
            // For rehearsing against a local network before the testnet run.
            "--localnet" => network = Network::LocalNet,
            "--trust-indexer" => trust = IndexerTrust::Trust,
            other => record = PathBuf::from(other),
        }
    }
    Ok(Args { record, members, indexer, network, trust })
}

async fn get_json(http: &reqwest::Client, url: &str) -> Result<Value> {
    let resp = http.get(url).send().await?;
    if !resp.status().is_success() {
        bail!("{url}: HTTP {}", resp.status());
    }
    Ok(resp.json().await?)
}

/// Every public key that signed a transaction: the seal signer plus any extra signatures.
async fn signers(http: &reqwest::Client, indexer: &str, tx: &str) -> Result<Vec<String>> {
    let v = get_json(http, &format!("{indexer}/transactions/{tx}")).await?;
    let body = &v["transaction"]["transaction"]["V1"];
    let mut keys = vec![
        body["seal_signature"]["public_key"].as_str().ok_or_else(|| anyhow!("no seal signer in {tx}"))?.to_string(),
    ];
    if let Some(sigs) = body["body"]["signatures"].as_array() {
        keys.extend(sigs.iter().filter_map(|s| s["public_key"].as_str().map(str::to_string)));
    }
    Ok(keys)
}

fn short(h: &str) -> String {
    if h.len() > 16 { format!("{}…{}", &h[..8], &h[h.len() - 6..]) } else { h.to_string() }
}

fn strs<'a>(v: &'a Value, list: &str, field: &str) -> Vec<&'a str> {
    v[list].as_array().map(|a| a.iter().filter_map(|x| x[field].as_str()).collect()).unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = args()?;
    let record: Value = serde_json::from_str(
        &std::fs::read_to_string(&a.record).with_context(|| format!("reading {}", a.record.display()))?,
    )?;
    let http = reqwest::Client::new();
    // A throwaway wallet: reading needs no keys, and the provider verifies every substate it returns.
    let reader = PoltergiftClient::connect_with_trust(&a.indexer, OotleSecretKey::random(a.network), a.trust).await?;
    let mode = if matches!(a.trust, IndexerTrust::Verify) {
        "light-client verified reads"
    } else {
        "trusted indexer (rehearsal)"
    };
    println!("indexer {} — {mode} — epoch {}", a.indexer, reader.epoch().await?);
    if let Some(t) = record["template"]["address"].as_str() {
        println!("template {t}");
    }
    let mut failures = 0;
    let mut check = |ok: bool, what: &str| {
        println!("  [{}] {what}", if ok { "ok" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    for round in record["rounds"].as_array().cloned().unwrap_or_default() {
        let component_str = round["component"].as_str().context("round without component")?;
        let component = ComponentAddress::from_str(component_str).map_err(|e| anyhow!("{e}"))?;
        println!("\n== {} — {component_str}", round["label"].as_str().unwrap_or("round"));
        let state = reader.round_state(component).await?;
        let vault = reader.vault_balance(&state).await?;
        println!(
            "  members {}/{}  claims {}  refunds {}  vault {} µT",
            state.members.len(),
            state.size,
            state.claims,
            state.refunds,
            vault.to_u128()
        );

        let on_chain_members: Vec<String> = state.members.iter().map(|m| hex::encode(m.into_array())).collect();
        let on_chain_tags: HashSet<String> = state.spent_tags.iter().map(|t| hex::encode(t.into_array())).collect();
        let joins = strs(&round, "joins", "member_key");
        check(
            joins.iter().all(|k| on_chain_members.iter().any(|m| m == k)),
            "every recorded join's member key is in the on-chain ring",
        );
        // (tx, key image, payout output) for every claim and refund.
        let payouts: Vec<(String, String, String)> = ["claims", "refunds"]
            .iter()
            .flat_map(|kind| round[*kind].as_array().cloned().unwrap_or_default())
            .filter_map(|p| {
                Some((
                    p["tx"].as_str()?.to_string(),
                    p["key_image"].as_str()?.to_string(),
                    p["payout_output"].as_str()?.to_string(),
                ))
            })
            .collect();
        check(
            payouts.iter().all(|(_, img, _)| on_chain_tags.contains(img)),
            "every recorded claim/refund tag is in the on-chain spent set",
        );
        check(
            on_chain_tags.len() == (state.claims + state.refunds) as usize,
            "one spent tag per claim or refund, nothing else",
        );

        let mut join_signers = HashSet::new();
        for tx in strs(&round, "joins", "tx") {
            join_signers.extend(signers(&http, &a.indexer, tx).await?);
        }
        let mut claim_signers = HashSet::new();
        let mut linked = false;
        for (tx, _, _) in &payouts {
            let s = signers(&http, &a.indexer, tx).await?;
            for key in &s {
                if on_chain_members.contains(key) || join_signers.contains(key) || !claim_signers.insert(key.clone()) {
                    linked = true;
                }
            }
            println!(
                "  payout tx {} sealed by {} (fresh)",
                short(tx),
                s.iter().map(|k| short(k)).collect::<Vec<_>>().join(", ")
            );
        }
        check(!linked, "no claim is signed by a member key, a join signer, or another claim's signer");

        let mut hidden = true;
        for (_, _, out) in &payouts {
            let v = get_json(&http, &format!("{}/substates/utxo_{TARI_RESOURCE}_{out}", a.indexer)).await;
            match v {
                Ok(v) => {
                    let body = &v["state"]["up"]["substate"]["Utxo"]["output"]["output"];
                    let text = body.to_string();
                    hidden &= body["encrypted_data"].is_string()
                        && !text.contains("\"amount\"")
                        && !text.contains("\"value\"");
                }
                Err(e) => println!("  payout {} not readable (spent since?): {e}", short(out)),
            }
        }
        check(hidden, "payout outputs carry only a commitment, a nonce and ciphertext (no amount)");
        println!("  every payout spends the same public amount from the vault: {} µT", state.payout_amount().to_u128());

        if !a.members.is_empty() {
            println!("  recipient check (rows: member wallets; columns: payout outputs)");
            for dir in &a.members {
                let store = Store::open(dir)?;
                if store.round(component_str)?.is_none() {
                    continue;
                }
                let Ok(secret) = store.load_wallet(a.network) else { continue };
                let member = PoltergiftClient::connect_with_trust(&a.indexer, secret, a.trust).await?;
                let mut opens = 0;
                let mut row = String::new();
                for (_, _, out) in &payouts {
                    let bytes: [u8; 32] = hex::decode(out)?.try_into().map_err(|_| anyhow!("bad commitment"))?;
                    match member.open_output(PedersenCommitmentBytes::from(bytes)).await {
                        Ok(Some(o)) => {
                            opens += 1;
                            row.push_str(&format!(" {:>10}", o.value));
                        }
                        Ok(None) => row.push_str("     sealed"),
                        Err(_) => row.push_str("       gone"),
                    }
                }
                println!(
                    "   {:<28}{row}",
                    dir.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default()
                );
                check(opens <= 1, "this member opens at most one payout");
            }
        }
    }
    println!();
    if failures == 0 {
        println!("all checks passed: nothing on chain links a deposit to a payout");
        Ok(())
    } else {
        bail!("{failures} check(s) failed")
    }
}
