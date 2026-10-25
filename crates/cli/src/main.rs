//! `poltergift`: create, join, claim and inspect secret gift rounds on the Tari Ootle.

mod amount;
mod record;

use std::{path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use ootle_rs::{Address, Network, default_indexer_url};
use poltergift_client::{IndexerTrust, MemberRecord, PoltergiftClient, RoundParams, RoundState, Store};
use poltergift_ring::{self as ring, SecretKey};
use rand::RngExt;
use tari_template_lib_types::{ComponentAddress, TemplateAddress, crypto::PedersenCommitmentBytes};

use crate::{
    amount::{format_tari, parse_tari},
    record::Recorder,
};

#[derive(Parser)]
#[command(name = "poltergift", version, about = "Secret gift rounds on the Tari Ootle")]
struct Cli {
    /// Network: esmeralda or localnet.
    #[arg(long, global = true, env = "POLTERGIFT_NETWORK", default_value = "esmeralda")]
    network: String,
    /// Indexer REST URL (defaults to the network's public indexer).
    #[arg(long, global = true, env = "POLTERGIFT_INDEXER")]
    indexer: Option<String>,
    /// Directory holding the wallet and member keys (secret!).
    #[arg(long, global = true, env = "POLTERGIFT_DATA_DIR", default_value = ".poltergift")]
    data_dir: PathBuf,
    /// Skip verifying the indexer's substate proofs (development only).
    #[arg(long, global = true, env = "POLTERGIFT_TRUST_INDEXER")]
    trust_indexer: bool,
    /// Append what happened (addresses and transaction ids, never secrets) to this JSON file.
    #[arg(long, global = true, env = "POLTERGIFT_RECORD")]
    record: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create (or show) this data dir's wallet.
    Init,
    /// Show the wallet address, account and balance.
    Balance,
    /// Take the network faucet's fixed amount into the account (localnet; Esmeralda when funded).
    Faucet,
    /// Publish the Poltergift template (prints the template address).
    Publish {
        /// Path to the template WASM (optimized with wasm-opt, custom sections stripped).
        #[arg(long)]
        wasm: PathBuf,
    },
    /// Send TARI from the account to fresh stealth outputs (e.g. to fund a member's stealth join).
    SendStealth {
        /// Recipient Ootle address.
        #[arg(long)]
        to: String,
        /// Amount in TARI.
        #[arg(long)]
        amount: String,
    },
    #[command(subcommand)]
    Round(RoundCmd),
    /// What an observer sees: members, tags, counts and the vault, with no secrets.
    Inspect {
        component: String,
        /// Also try every member key stored under these data dirs and show which tag each owns.
        #[arg(long = "as-member")]
        member_dirs: Vec<PathBuf>,
    },
    /// Play a whole round with freshly generated bot members (each with its own wallet).
    Bots(BotsArgs),
    /// Scan the chain for this wallet's stealth outputs and open them.
    Scan,
}

#[derive(Subcommand)]
enum RoundCmd {
    /// Open a new round.
    Create {
        #[arg(long)]
        template: String,
        /// Gift per member, in TARI.
        #[arg(long, default_value = "5")]
        gift: String,
        #[arg(long, default_value_t = 5)]
        size: u32,
        /// Joins close this many epochs from now.
        #[arg(long, default_value_t = 3)]
        join_epochs: u64,
        /// Claims close this many epochs from now.
        #[arg(long, default_value_t = 8)]
        claim_epochs: u64,
        /// Fee each claim or refund may spend from the vault, in TARI.
        #[arg(long, default_value = "0.05")]
        claim_fee: String,
        /// A label for the record file.
        #[arg(long, default_value = "round")]
        label: String,
    },
    /// Join a round with a fresh member key.
    Join {
        component: String,
        /// Pay the gift from a stealth output `COMMITMENT:VALUE_TARI` instead of the account.
        #[arg(long)]
        from_utxo: Option<String>,
    },
    /// Show a round's state.
    Status { component: String },
    /// Claim a gift anonymously into a fresh stealth output.
    Claim {
        component: String,
        /// Pay to this Ootle address (default: this wallet).
        #[arg(long)]
        to: Option<String>,
    },
    /// Take your gift back after a deadline.
    Refund {
        component: String,
        #[arg(long)]
        to: Option<String>,
    },
}

#[derive(Args)]
struct BotsArgs {
    #[arg(long)]
    template: String,
    #[arg(long, default_value_t = 5)]
    size: u32,
    #[arg(long, default_value = "5")]
    gift: String,
    #[arg(long, default_value = "0.05")]
    claim_fee: String,
    #[arg(long, default_value_t = 3)]
    join_epochs: u64,
    #[arg(long, default_value_t = 8)]
    claim_epochs: u64,
    /// Extra TARI per bot for its join fee (returned to the bot as change).
    #[arg(long, default_value = "0.5")]
    fee_budget: String,
    /// Maximum random pause between claims, in seconds (claims should not follow joins in order).
    #[arg(long, default_value_t = 20)]
    max_claim_delay: u64,
    #[arg(long, default_value = "bot round")]
    label: String,
}

struct Ctx {
    trust: IndexerTrust,
    network: Network,
    indexer: String,
    data_dir: PathBuf,
    recorder: Option<Recorder>,
}

fn parse_network(s: &str) -> Result<Network> {
    match s.to_ascii_lowercase().as_str() {
        "esmeralda" | "esme" => Ok(Network::Esmeralda),
        "localnet" | "local" => Ok(Network::LocalNet),
        other => bail!("unsupported network {other:?} (use esmeralda or localnet)"),
    }
}

fn parse_component(s: &str) -> Result<ComponentAddress> {
    ComponentAddress::from_str(s).map_err(|e| anyhow!("invalid component address {s:?}: {e}"))
}

fn parse_template(s: &str) -> Result<TemplateAddress> {
    let s = s.strip_prefix("template_").unwrap_or(s);
    TemplateAddress::from_hex(s).map_err(|e| anyhow!("invalid template address: {e:?}"))
}

fn parse_commitment(s: &str) -> Result<PedersenCommitmentBytes> {
    let bytes: [u8; 32] =
        hex::decode(s.trim_start_matches("utxo_"))?.try_into().map_err(|_| anyhow!("commitment must be 32 bytes"))?;
    Ok(PedersenCommitmentBytes::from(bytes))
}

impl Ctx {
    async fn client_for(&self, dir: &PathBuf) -> Result<(PoltergiftClient, Store)> {
        let store = Store::open(dir)?;
        let secret = store.load_wallet(self.network)?;
        let client = PoltergiftClient::connect_with_trust(&self.indexer, secret, self.trust).await?;
        Ok((client, store))
    }

    async fn client(&self) -> Result<(PoltergiftClient, Store)> {
        self.client_for(&self.data_dir).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let network = parse_network(&cli.network)?;
    let indexer = cli.indexer.clone().unwrap_or_else(|| match network {
        Network::LocalNet => "http://127.0.0.1:12500".to_string(),
        n => default_indexer_url(n).to_string(),
    });
    let recorder = cli.record.as_ref().map(|p| Recorder::open(p, network, &indexer)).transpose()?;
    let ctx = Ctx {
        trust: if cli.trust_indexer { IndexerTrust::Trust } else { IndexerTrust::Verify },
        network,
        indexer,
        data_dir: cli.data_dir.clone(),
        recorder,
    };

    match cli.command {
        Command::Init => {
            let store = Store::open(&ctx.data_dir)?;
            let (secret, created) = store.load_or_create_wallet(network)?;
            println!("{} wallet in {}", if created { "created" } else { "existing" }, store.dir().display());
            println!("address: {}", secret.to_address());
        }
        Command::Balance => {
            let (client, _) = ctx.client().await?;
            println!("address: {}", client.address());
            println!("account: {}", client.account());
            println!("account balance: {}", format_tari(client.account_balance().await?));
        }
        Command::Faucet => {
            let (mut client, _) = ctx.client().await?;
            let f = client.take_faucet().await?;
            println!("faucet tx {} (fee {} µT)", f.tx_id, f.fee_paid());
        }
        Command::Publish { wasm } => {
            let bytes = std::fs::read(&wasm).with_context(|| format!("reading {}", wasm.display()))?;
            let (mut client, _) = ctx.client().await?;
            let (template, f) = client.publish_template(bytes.clone()).await?;
            println!("template_{template}");
            println!("publish tx {} (fee {} µT, {} bytes)", f.tx_id, f.fee_paid(), bytes.len());
            if let Some(r) = &ctx.recorder {
                r.template(&template.to_string(), &f.tx_id.to_string(), &bytes)?;
            }
        }
        Command::SendStealth { to, amount } => {
            let (mut client, _) = ctx.client().await?;
            let to = Address::from_str(&to).map_err(|e| anyhow!("bad address: {e}"))?;
            let amount = parse_tari(&amount)?;
            let (f, commitments) = client.send_stealth(&[(to, amount)]).await?;
            println!("tx {}", f.tx_id);
            for c in commitments {
                println!("utxo {}:{}", hex::encode(c.into_array()), format_tari_u64(amount));
            }
        }
        Command::Round(cmd) => round_command(&ctx, cmd).await?,
        Command::Inspect { component, member_dirs } => inspect(&ctx, &component, &member_dirs).await?,
        Command::Bots(args) => bots(&ctx, args).await?,
        Command::Scan => {
            let (client, _) = ctx.client().await?;
            let owned = client.scan_owned().await?;
            let total: u64 = owned.iter().map(|o| o.value).sum();
            for o in &owned {
                println!("utxo {}:{}", hex::encode(o.commitment.into_array()), format_tari_u64(o.value));
            }
            println!("{} stealth outputs, {} in total", owned.len(), format_tari_u64(total));
        }
    }
    Ok(())
}

fn format_tari_u64(v: u64) -> String {
    format_tari(v.into())
}

async fn round_command(ctx: &Ctx, cmd: RoundCmd) -> Result<()> {
    match cmd {
        RoundCmd::Create { template, gift, size, join_epochs, claim_epochs, claim_fee, label } => {
            let (mut client, _) = ctx.client().await?;
            let epoch = client.epoch().await?;
            let params = RoundParams {
                gift_amount: parse_tari(&gift)?,
                size,
                join_deadline: epoch + join_epochs,
                claim_deadline: epoch + claim_epochs,
                claim_fee: parse_tari(&claim_fee)?,
            };
            let (component, f) = client.create_round(parse_template(&template)?, params).await?;
            println!("{component}");
            println!(
                "create tx {} (fee {} µT); joins close at epoch {}, claims at epoch {}",
                f.tx_id,
                f.fee_paid(),
                params.join_deadline,
                params.claim_deadline
            );
            if let Some(r) = &ctx.recorder {
                r.round_created(&label, &component.to_string(), &params, &f.tx_id.to_string())?;
            }
        }
        RoundCmd::Join { component, from_utxo } => {
            let (mut client, store) = ctx.client().await?;
            let c = parse_component(&component)?;
            join(ctx, &mut client, &store, c, from_utxo.as_deref()).await?;
        }
        RoundCmd::Status { component } => {
            let (client, store) = ctx.client().await?;
            let c = parse_component(&component)?;
            let state = client.round_state(c).await?;
            print_status(&client, &state).await?;
            if let Some(rec) = store.round(&c.to_string())? {
                let me = rec.secret()?;
                let tag = me.key_image(&state.round_id_bytes()).map_err(|e| anyhow!("{e}"))?;
                let index = state.member_index(&me.public_key());
                let claimed = state.spent_tags.iter().any(|t| t.into_array() == tag);
                println!(
                    "you: member #{} — tag {} — {}",
                    index.map(|i| i.to_string()).unwrap_or("?".into()),
                    short(&tag),
                    if claimed { "spent" } else { "unspent" }
                );
            }
        }
        RoundCmd::Claim { component, to } => {
            let (mut client, store) = ctx.client().await?;
            let c = parse_component(&component)?;
            let to = resolve_to(&client, to)?;
            let mut rec = store
                .round(&c.to_string())?
                .ok_or_else(|| anyhow!("no member key for this round in {}", ctx.data_dir.display()))?;
            let p = client.claim(c, &rec.secret()?, &to).await?;
            rec.claim_tx = Some(p.finalized.tx_id.to_string());
            rec.payout_commitment = Some(hex::encode(p.output_commitment.into_array()));
            store.save_round(&c.to_string(), &rec)?;
            println!(
                "claim tx {} — tag {} — payout output {}",
                p.finalized.tx_id,
                short(&p.key_image),
                short(&p.output_commitment.into_array())
            );
            if let Some(r) = &ctx.recorder {
                r.payout(&c.to_string(), "claims", &p)?;
            }
        }
        RoundCmd::Refund { component, to } => {
            let (mut client, store) = ctx.client().await?;
            let c = parse_component(&component)?;
            let to = resolve_to(&client, to)?;
            let mut rec = store.round(&c.to_string())?.ok_or_else(|| anyhow!("no member key for this round"))?;
            let p = client.refund(c, &rec.secret()?, &to).await?;
            rec.refund_tx = Some(p.finalized.tx_id.to_string());
            rec.payout_commitment = Some(hex::encode(p.output_commitment.into_array()));
            store.save_round(&c.to_string(), &rec)?;
            println!("refund tx {} — tag {}", p.finalized.tx_id, short(&p.key_image));
            if let Some(r) = &ctx.recorder {
                r.payout(&c.to_string(), "refunds", &p)?;
            }
        }
    }
    Ok(())
}

fn resolve_to(client: &PoltergiftClient, to: Option<String>) -> Result<Address> {
    match to {
        Some(s) => Address::from_str(&s).map_err(|e| anyhow!("bad address: {e}")),
        None => Ok(client.address()),
    }
}

async fn join(
    ctx: &Ctx,
    client: &mut PoltergiftClient,
    store: &Store,
    c: ComponentAddress,
    from_utxo: Option<&str>,
) -> Result<MemberRecord> {
    if let Some(existing) = store.round(&c.to_string())? {
        bail!("this data dir already joined the round as {}", existing.member_public);
    }
    let member = SecretKey::random(&mut rand::rng());
    // Persist the member key before submitting: losing it after a successful join loses the gift.
    let mut rec = MemberRecord {
        member_secret: hex::encode(member.to_bytes()),
        member_public: hex::encode(member.public_key()),
        ..Default::default()
    };
    store.save_round(&c.to_string(), &rec)?;
    let (f, funding) = match from_utxo {
        Some(spec) => {
            let (commitment, value) = spec.split_once(':').ok_or_else(|| anyhow!("use COMMITMENT:VALUE"))?;
            let f = client.join_from_stealth(c, &member, parse_commitment(commitment)?, parse_tari(value)?).await?;
            (f, "stealth")
        }
        None => (client.join_from_account(c, &member).await?, "account"),
    };
    rec.join_tx = Some(f.tx_id.to_string());
    store.save_round(&c.to_string(), &rec)?;
    println!("join tx {} — member key {} (funded from {funding})", f.tx_id, short(&member.public_key()));
    if let Some(r) = &ctx.recorder {
        r.join(&c.to_string(), &f.tx_id.to_string(), &rec.member_public, funding)?;
    }
    Ok(rec)
}

fn short(b: &[u8; 32]) -> String {
    let h = hex::encode(b);
    format!("{}…{}", &h[..8], &h[56..])
}

async fn print_status(client: &PoltergiftClient, state: &RoundState) -> Result<()> {
    let epoch = client.epoch().await?;
    let balance = client.vault_balance(state).await?;
    println!("phase: {} (epoch {epoch})", state.phase(epoch));
    println!("members: {}/{}  claims: {}  refunds: {}", state.members.len(), state.size, state.claims, state.refunds);
    println!(
        "gift: {}  claim fee: {}  payout: {}",
        format_tari(state.gift_amount),
        format_tari(state.claim_fee),
        format_tari(state.payout_amount())
    );
    println!("joins close at epoch {}, claims close at epoch {}", state.join_deadline, state.claim_deadline);
    println!("vault: {}", format_tari(balance));
    Ok(())
}

async fn inspect(ctx: &Ctx, component: &str, member_dirs: &[PathBuf]) -> Result<()> {
    let (client, _) = ctx.client().await?;
    let c = parse_component(component)?;
    let state = client.round_state(c).await?;
    println!("== observer view of {c}");
    print_status(&client, &state).await?;
    println!("member keys (public, from joins):");
    for (i, m) in state.members.iter().enumerate() {
        println!("  #{i} {}", short(&m.into_array()));
    }
    println!("spent tags (one per claim/refund; no member index anywhere):");
    for t in &state.spent_tags {
        println!("  {}", short(&t.into_array()));
    }
    let (_, h) = ring::tag_base(&state.round_id_bytes()).map_err(|e| anyhow!("{e}"))?;
    println!(
        "tag base H = {} (recomputed from the round id; matches state: {})",
        short(&h),
        h == state.tag_base.into_array()
    );
    println!("deciding which member owns a tag means solving DDH in (G, H, P_i, I): an observer cannot.");
    if member_dirs.is_empty() {
        return Ok(());
    }
    println!("== recipient view: each member key against every payout output");
    let mut members = Vec::new();
    for dir in member_dirs {
        let (member_client, store) = ctx.client_for(dir).await?;
        let Some(rec) = store.round(&c.to_string())? else {
            println!("{}: not a member", dir.display());
            continue;
        };
        let me = rec.secret()?;
        let tag = me.key_image(&state.round_id_bytes()).map_err(|e| anyhow!("{e}"))?;
        let spent = state.spent_tags.iter().any(|t| t.into_array() == tag);
        println!(
            "{}: member #{} owns tag {} ({})",
            dir.display(),
            state.member_index(&me.public_key()).map(|i| i.to_string()).unwrap_or("?".into()),
            short(&tag),
            if spent { "spent" } else { "unspent" }
        );
        members.push((dir.clone(), member_client, rec.payout_commitment.clone()));
    }
    let outputs: Vec<String> = members.iter().filter_map(|(_, _, p)| p.clone()).collect();
    for (dir, member_client, _) in &members {
        for out in &outputs {
            let opened = member_client.open_output(parse_commitment(out)?).await;
            let verdict = match opened {
                Ok(Some(o)) => format!("OPENS: {}", format_tari_u64(o.value)),
                Ok(None) => "sealed (not yours)".to_string(),
                Err(e) => format!("unavailable ({e})"),
            };
            println!("  {} × output {}…  {verdict}", dir.display(), &out[..16]);
        }
    }
    Ok(())
}

async fn bots(ctx: &Ctx, a: BotsArgs) -> Result<()> {
    let (mut main, _) = ctx.client().await?;
    let gift = parse_tari(&a.gift)?;
    let budget = parse_tari(&a.fee_budget)?;
    let epoch = main.epoch().await?;
    let params = RoundParams {
        gift_amount: gift,
        size: a.size,
        join_deadline: epoch + a.join_epochs,
        claim_deadline: epoch + a.claim_epochs,
        claim_fee: parse_tari(&a.claim_fee)?,
    };
    let (component, f) = main.create_round(parse_template(&a.template)?, params).await?;
    println!("round {component} created in {}", f.tx_id);
    if let Some(r) = &ctx.recorder {
        r.round_created(&a.label, &component.to_string(), &params, &f.tx_id.to_string())?;
    }

    // Every bot gets its own wallet; the main wallet funds each with one stealth output.
    let short_id = &component.to_string()[10..18];
    let mut bot_dirs = Vec::new();
    let mut recipients = Vec::new();
    for k in 0..a.size {
        let dir = ctx.data_dir.join("bots").join(short_id).join(format!("bot-{k}"));
        let store = Store::open(&dir)?;
        let (secret, _) = store.load_or_create_wallet(ctx.network)?;
        recipients.push((secret.to_address(), gift + budget));
        bot_dirs.push(dir);
    }
    let (f, utxos) = main.send_stealth(&recipients).await?;
    println!("funded {} bots with stealth outputs in {}", a.size, f.tx_id);

    for (dir, utxo) in bot_dirs.iter().zip(&utxos) {
        let (mut bot, store) = ctx.client_for(dir).await?;
        let spec = format!("{}:{}", hex::encode(utxo.into_array()), format_tari_u64(gift + budget));
        join(ctx, &mut bot, &store, component, Some(&spec)).await?;
    }
    let state = main.round_state(component).await?;
    println!("sealed: {} ({}/{})", state.is_sealed(), state.members.len(), state.size);

    // Claim in a random order with random pauses, so claim order and timing say nothing about joins.
    let mut order: Vec<usize> = (0..bot_dirs.len()).collect();
    let mut rng = rand::rng();
    for i in (1..order.len()).rev() {
        let j = rng.random_range(0..=i);
        order.swap(i, j);
    }
    for k in order {
        let pause = rng.random_range(0..=a.max_claim_delay);
        tokio::time::sleep(Duration::from_secs(pause)).await;
        let (mut bot, store) = ctx.client_for(&bot_dirs[k]).await?;
        let mut rec = store.round(&component.to_string())?.expect("bot joined");
        let to = bot.address();
        let p = bot.claim(component, &rec.secret()?, &to).await?;
        rec.claim_tx = Some(p.finalized.tx_id.to_string());
        rec.payout_commitment = Some(hex::encode(p.output_commitment.into_array()));
        store.save_round(&component.to_string(), &rec)?;
        println!("a ghost claimed: tx {} tag {}", p.finalized.tx_id, short(&p.key_image));
        if let Some(r) = &ctx.recorder {
            r.payout(&component.to_string(), "claims", &p)?;
        }
    }
    let state = main.round_state(component).await?;
    print_status(&main, &state).await?;
    Ok(())
}
