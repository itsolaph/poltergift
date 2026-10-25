//! Appends public facts (addresses, transaction ids, public keys, tags) to a deployment record such
//! as `deployments/esmeralda.json`. Never writes secrets.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use ootle_rs::Network;
use poltergift_client::{Payout, RoundParams};
use serde_json::{Value, json};

pub struct Recorder {
    path: PathBuf,
}

impl Recorder {
    pub fn open(path: &Path, network: Network, indexer: &str) -> Result<Self> {
        let r = Self { path: path.to_path_buf() };
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            r.write(&json!({
                "network": format!("{network:?}").to_lowercase(),
                "indexer": indexer,
                "template": null,
                "rounds": [],
            }))?;
        }
        Ok(r)
    }

    fn read(&self) -> Result<Value> {
        Ok(serde_json::from_str(&fs::read_to_string(&self.path)?)?)
    }

    fn write(&self, v: &Value) -> Result<()> {
        fs::write(&self.path, serde_json::to_string_pretty(v)? + "\n")?;
        Ok(())
    }

    fn update<F: FnOnce(&mut Value)>(&self, f: F) -> Result<()> {
        let mut v = self.read()?;
        f(&mut v);
        self.write(&v)
    }

    fn round_mut<'a>(v: &'a mut Value, component: &str) -> Option<&'a mut Value> {
        v["rounds"].as_array_mut()?.iter_mut().find(|r| r["component"] == component)
    }

    pub fn template(&self, address: &str, tx: &str, wasm: &[u8]) -> Result<()> {
        let digest = hex::encode(poltergift_ring::blake2b(&[wasm]));
        self.update(|v| {
            v["template"] = json!({
                "address": format!("template_{address}"),
                "publish_tx": tx,
                "wasm_bytes": wasm.len(),
                "wasm_blake2b_256": digest,
            });
        })
    }

    /// Funding and setup transactions (faucet, burn claims, deposits, bot funding).
    pub fn setup(&self, kind: &str, tx: &str) -> Result<()> {
        self.update(|v| {
            if !v["setup"].is_array() {
                v["setup"] = json!([]);
            }
            v["setup"].as_array_mut().expect("setup array").push(json!({ "kind": kind, "tx": tx }));
        })
    }

    pub fn round_created(&self, label: &str, component: &str, p: &RoundParams, tx: &str) -> Result<()> {
        self.update(|v| {
            v["rounds"].as_array_mut().expect("rounds array").push(json!({
                "label": label,
                "component": component,
                "params": {
                    "gift_amount_utari": p.gift_amount,
                    "size": p.size,
                    "join_deadline_epoch": p.join_deadline,
                    "claim_deadline_epoch": p.claim_deadline,
                    "claim_fee_utari": p.claim_fee,
                },
                "create_tx": tx,
                "joins": [],
                "claims": [],
                "refunds": [],
            }));
        })
    }

    pub fn join(&self, component: &str, tx: &str, member_public: &str, funding: &str) -> Result<()> {
        self.update(|v| {
            if let Some(r) = Self::round_mut(v, component) {
                r["joins"].as_array_mut().expect("joins").push(json!({
                    "tx": tx,
                    "member_key": member_public,
                    "funded_from": funding,
                }));
            }
        })
    }

    pub fn payout(&self, component: &str, kind: &str, p: &Payout) -> Result<()> {
        self.update(|v| {
            if let Some(r) = Self::round_mut(v, component) {
                r[kind].as_array_mut().expect("payout list").push(json!({
                    "tx": p.finalized.tx_id.to_string(),
                    "key_image": hex::encode(p.key_image),
                    "payout_output": hex::encode(p.output_commitment.into_array()),
                    "fee_paid_utari": p.finalized.fee_paid(),
                }));
            }
        })
    }
}
