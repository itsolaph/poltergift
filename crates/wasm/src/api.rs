//! The JSON API the browser calls. Every request is `{"op": ..., ...}` and every reply is
//! `{"ok": true, ...}` or `{"ok": false, "error": "..."}`. Byte strings are hex. Randomness always
//! comes from a caller-supplied 32-byte `seed` (the page draws it from `crypto.getRandomValues`),
//! so this module has no hidden entropy source and is fully reproducible in tests.

use poltergift_model::{Params, PayoutShape, RoundModel};
use poltergift_ring::{self as ring, PointBytes, Purpose, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::demo_output::DemoOutput;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// A fresh secret key and its public key.
    Keygen { seed: String },
    TagBase { round_id: String },
    KeyImage { round_id: String, secret: String },
    Create { params: Params, round_id: String, now: u64 },
    /// `pop_secret` signs the proof of possession; honest joins use the member's own secret.
    Join {
        state: RoundModel,
        now: u64,
        member: String,
        pop_secret: String,
        gift: u64,
        #[serde(default = "yes")]
        gift_is_tari: bool,
        seed: String,
    },
    /// A demo payout output for a wallet, and the message a claim over it signs.
    Payout { view_public: String, spend_public: String, amount: u64, seed: String },
    SignClaim {
        round_id: String,
        ring: Vec<String>,
        index: usize,
        secret: String,
        message: String,
        seed: String,
    },
    Claim {
        state: RoundModel,
        now: u64,
        key_image: String,
        signature: String,
        message: String,
        #[serde(default)]
        shape: Option<PayoutShape>,
        fee_charged: u64,
    },
    SignRefund { round_id: String, secret: String, message: String, seed: String },
    Refund {
        state: RoundModel,
        now: u64,
        member: String,
        key_image: String,
        proof: String,
        message: String,
        fee_charged: u64,
    },
    Open { view_secret: String, spend_public: String, output: DemoOutput },
}

fn yes() -> bool {
    true
}

fn h32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| format!("bad hex: {e}"))?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

fn secret(s: &str) -> Result<SecretKey, String> {
    SecretKey::from_bytes(&h32(s)?).map_err(|e| e.to_string())
}

fn rng(seed: &str) -> Result<ChaCha20Rng, String> {
    Ok(ChaCha20Rng::from_seed(h32(seed)?))
}

fn hexes(v: &[PointBytes]) -> Vec<String> {
    v.iter().map(hex::encode).collect()
}

/// The round as the UI shows it, next to the opaque state blob it hands back on the next call.
fn view(state: &RoundModel) -> Value {
    let (joined, size, claims, refunds, sealed) = state.status();
    json!({
        "joined": joined,
        "size": size,
        "claims": claims,
        "refunds": refunds,
        "sealed": sealed,
        "vault": state.vault as u64,
        "payout": state.payout_amount() as u64,
        "members": hexes(&state.members),
        "spent_tags": hexes(&state.spent_tags),
        "tag_base": hex::encode(state.tag_base),
        "solvent": state.is_solvent(),
        "outstanding": state.outstanding(),
    })
}

fn outcome(state: RoundModel, result: poltergift_model::Outcome) -> Result<Value, String> {
    match result {
        Ok(()) => Ok(json!({ "ok": true, "view": view(&state), "state": state })),
        Err(rejected) => Ok(json!({ "ok": false, "rejected": true, "error": rejected.0 })),
    }
}

fn handle(req: Request) -> Result<Value, String> {
    match req {
        Request::Keygen { seed } => {
            let sk = SecretKey::random(&mut rng(&seed)?);
            Ok(json!({ "ok": true, "secret": hex::encode(sk.to_bytes()), "public": hex::encode(sk.public_key()) }))
        },
        Request::TagBase { round_id } => {
            let (_, h) = ring::tag_base(&h32(&round_id)?).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "tag_base": hex::encode(h) }))
        },
        Request::KeyImage { round_id, secret: s } => {
            let image = secret(&s)?.key_image(&h32(&round_id)?).map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "key_image": hex::encode(image) }))
        },
        Request::Create { params, round_id, now } => match RoundModel::create(params, h32(&round_id)?, now) {
            Ok(state) => Ok(json!({ "ok": true, "view": view(&state), "state": state })),
            Err(r) => Ok(json!({ "ok": false, "rejected": true, "error": r.0 })),
        },
        Request::Join {
            mut state,
            now,
            member,
            pop_secret,
            gift,
            gift_is_tari,
            seed,
        } => {
            let pop = ring::sign_pop(&state.round_id, &secret(&pop_secret)?, &mut rng(&seed)?);
            let result = state.join(now, h32(&member)?, &pop, gift as u128, gift_is_tari, false);
            outcome(state, result)
        },
        Request::Payout {
            view_public,
            spend_public,
            amount,
            seed,
        } => {
            let out = DemoOutput::create(&h32(&view_public)?, &h32(&spend_public)?, amount, &mut rng(&seed)?)
                .ok_or("invalid wallet keys")?;
            let message = ring::payout_message(&out.signing_bytes());
            Ok(json!({ "ok": true, "output": out, "message": hex::encode(message) }))
        },
        Request::SignClaim {
            round_id,
            ring: members,
            index,
            secret: s,
            message,
            seed,
        } => {
            let members = members.iter().map(|m| h32(m)).collect::<Result<Vec<_>, _>>()?;
            let (sig, image) = ring::sign(
                Purpose::Claim,
                &h32(&round_id)?,
                &members,
                index,
                &secret(&s)?,
                &h32(&message)?,
                &mut rng(&seed)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "key_image": hex::encode(image), "signature": hex::encode(sig.to_bytes()) }))
        },
        Request::Claim {
            mut state,
            now,
            key_image,
            signature,
            message,
            shape,
            fee_charged,
        } => {
            let shape = shape.unwrap_or_else(|| PayoutShape::valid(state.payout_amount()));
            let sig = hex::decode(&signature).map_err(|e| e.to_string())?;
            let result = state.claim(now, h32(&key_image)?, &sig, &shape, &h32(&message)?, fee_charged as u128);
            outcome(state, result)
        },
        Request::SignRefund { round_id, secret: s, message, seed } => {
            let sk = secret(&s)?;
            let (sig, image) = ring::sign(
                Purpose::Refund,
                &h32(&round_id)?,
                &[sk.public_key()],
                0,
                &sk,
                &h32(&message)?,
                &mut rng(&seed)?,
            )
            .map_err(|e| e.to_string())?;
            Ok(json!({ "ok": true, "key_image": hex::encode(image), "proof": hex::encode(sig.to_bytes()) }))
        },
        Request::Refund {
            mut state,
            now,
            member,
            key_image,
            proof,
            message,
            fee_charged,
        } => {
            let proof = hex::decode(&proof).map_err(|e| e.to_string())?;
            let shape = PayoutShape::valid(state.payout_amount());
            let result = state.refund(now, h32(&member)?, h32(&key_image)?, &proof, &shape, &h32(&message)?, fee_charged as u128);
            outcome(state, result)
        },
        Request::Open {
            view_secret,
            spend_public,
            output,
        } => {
            let amount = output.open(&secret(&view_secret)?, &h32(&spend_public)?);
            Ok(json!({ "ok": true, "amount": amount }))
        },
    }
}

/// Handles one JSON request and returns the JSON reply. Never panics on bad input.
pub fn call(input: &str) -> String {
    let reply = match serde_json::from_str::<Request>(input) {
        Ok(req) => handle(req).unwrap_or_else(|e| json!({ "ok": false, "error": e })),
        Err(e) => json!({ "ok": false, "error": format!("bad request: {e}") }),
    };
    reply.to_string()
}
