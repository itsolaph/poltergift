//! A compact stand-in for a Tari stealth output, used only by the browser demo.
//!
//! It has the same shape and the same privacy property as the real thing: the sender derives a
//! shared secret `s = H(r·V)` with the recipient's view key `V`, the output carries a one-time owner
//! key `H(s)·G + K` that nobody can link to the recipient's spend key `K`, a Pedersen commitment to
//! the amount, and the amount and mask encrypted under `s`. Only the holder of `v` can recompute `s`
//! and open it. The real client (`poltergift-client`) builds genuine Tari stealth outputs with
//! `ootle-rs` (range proofs, XChaCha20-Poly1305 AEAD, UTXO tags); this module is a readable demo
//! encoding and is labelled as such in the UI.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use poltergift_ring::{self as ring, PointBytes, SecretKey};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};

const DST_SHARED: &[u8] = b"poltergift/demo/shared";
const DST_OWNER: &[u8] = b"poltergift/demo/owner";
const DST_MASK: &[u8] = b"poltergift/demo/mask";
const DST_STREAM: &[u8] = b"poltergift/demo/stream";
const VALUE_GENERATOR_ID: [u8; 32] = *b"poltergift/demo/value-generator!";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoOutput {
    /// `R = r·G`, published so the recipient can recompute the shared secret.
    pub nonce: String,
    /// One-time owner key `H(s)·G + K`.
    pub owner_key: String,
    /// `amount·Hv + mask·G`.
    pub commitment: String,
    /// `(amount ‖ mask) XOR keystream(s)`.
    pub ciphertext: String,
}

fn value_generator() -> RistrettoPoint {
    ring::tag_base(&VALUE_GENERATOR_ID).expect("generator exists").0
}

fn shared_secret(point: &RistrettoPoint) -> [u8; 32] {
    ring::blake2b(&[DST_SHARED, point.compress().as_bytes()])
}

fn keystream(s: &[u8; 32]) -> [u8; 40] {
    let a = ring::blake2b(&[DST_STREAM, s, &[0]]);
    let b = ring::blake2b(&[DST_STREAM, s, &[1]]);
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(&a);
    out[32..].copy_from_slice(&b[..8]);
    out
}

fn decode(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

impl DemoOutput {
    pub fn create<R: CryptoRng + ?Sized>(view: &PointBytes, spend: &PointBytes, amount: u64, rng: &mut R) -> Option<Self> {
        let view = ring::decode_nonidentity_point(view).ok()?;
        let spend = ring::decode_nonidentity_point(spend).ok()?;
        let r = SecretKey::random(rng);
        let nonce = RistrettoPoint::mul_base(r.as_scalar());
        let s = shared_secret(&(view * r.as_scalar()));
        let owner = RistrettoPoint::mul_base(&ring::hash_to_scalar(&[DST_OWNER, &s])) + spend;
        let mask = ring::hash_to_scalar(&[DST_MASK, &s]);
        let commitment = value_generator() * Scalar::from(amount) + RistrettoPoint::mul_base(&mask);
        let mut plain = [0u8; 40];
        plain[..8].copy_from_slice(&amount.to_le_bytes());
        plain[8..].copy_from_slice(&mask.to_bytes());
        let ks = keystream(&s);
        let cipher: Vec<u8> = plain.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        Some(Self {
            nonce: hex::encode(nonce.compress().as_bytes()),
            owner_key: hex::encode(owner.compress().as_bytes()),
            commitment: hex::encode(commitment.compress().as_bytes()),
            ciphertext: hex::encode(cipher),
        })
    }

    /// The bytes a claim signs (the demo's counterpart of the CBOR payout statement).
    pub fn signing_bytes(&self) -> Vec<u8> {
        [&self.nonce, &self.owner_key, &self.commitment, &self.ciphertext]
            .iter()
            .flat_map(|h| hex::decode(h).unwrap_or_default())
            .collect()
    }

    /// Opens the output with view secret `v` and spend public key `K`: `Some(amount)` only for its
    /// owner, `None` for everyone else.
    pub fn open(&self, view_secret: &SecretKey, spend: &PointBytes) -> Option<u64> {
        let nonce = ring::decode_nonidentity_point(&decode(&self.nonce)?).ok()?;
        let s = shared_secret(&(nonce * view_secret.as_scalar()));
        let spend = ring::decode_nonidentity_point(spend).ok()?;
        let owner = RistrettoPoint::mul_base(&ring::hash_to_scalar(&[DST_OWNER, &s])) + spend;
        if hex::encode(owner.compress().as_bytes()) != self.owner_key {
            return None;
        }
        let cipher = hex::decode(&self.ciphertext).ok()?;
        if cipher.len() != 40 {
            return None;
        }
        let ks = keystream(&s);
        let plain: Vec<u8> = cipher.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
        let amount = u64::from_le_bytes(plain[..8].try_into().ok()?);
        let mask = ring::decode_scalar(&plain[8..40].try_into().ok()?).ok()?;
        let expected = value_generator() * Scalar::from(amount) + RistrettoPoint::mul_base(&mask);
        (hex::encode(expected.compress().as_bytes()) == self.commitment).then_some(amount)
    }
}
