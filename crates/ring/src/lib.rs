//! Poltergift cryptography: a linkable ring signature over Ristretto255.
//!
//! The scheme is the linkable spontaneous anonymous group signature of Liu, Wei and Wong (2004)
//! with a per-round generator `H` (their `h = H2(L)`), written in the bLSAG layout. A member with
//! secret `x` and public key `P = x·G` proves "I own one of the ring keys" and publishes the key
//! image `I = x·H`. The same key always yields the same `I` within a round, which is what stops a
//! second claim, while deciding which ring key produced `I` is a DDH problem.
//!
//! Every byte that is hashed here is hashed identically by the on-chain template (which uses the
//! engine's native intrinsics instead of this crate), so all framing is fixed-width and documented
//! next to the function that produces it. Changing any of it breaks verification on chain.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use blake2::{Blake2b, Digest, digest::consts::U32};
use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use rand_core::CryptoRng;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A compressed Ristretto point (canonical encoding).
pub type PointBytes = [u8; 32];
/// A canonically reduced scalar, little endian.
pub type ScalarBytes = [u8; 32];
/// A 32-byte round identifier (the round component's address).
pub type RoundId = [u8; 32];

/// The largest ring the template accepts. Verification cost grows linearly with the ring.
pub const MAX_RING_SIZE: usize = 16;
/// The most attempts `tag_base` makes before giving up. Each attempt succeeds with probability
/// about 1/8, so failing all of them has probability below 2^-49.
pub const TAG_BASE_MAX_ATTEMPTS: u32 = 256;

/// Domain separation tags. Each is hashed as `len(tag) as u8 ‖ tag`.
pub mod dst {
    pub const TAG_BASE: &[u8] = b"poltergift/v1/tag-base";
    pub const RING: &[u8] = b"poltergift/v1/ring";
    pub const CLAIM: &[u8] = b"poltergift/v1/claim";
    pub const REFUND: &[u8] = b"poltergift/v1/refund";
    pub const JOIN_POP: &[u8] = b"poltergift/v1/join-pop";
    pub const PAYOUT: &[u8] = b"poltergift/v1/payout";
}

/// Which statement a ring signature authorises. The two never verify for each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Anonymous claim: ring = all round members.
    Claim,
    /// Refund: ring = the single refunding member, which makes the signature a DLEQ proof that
    /// `log_G(P) = log_H(I)`.
    Refund,
}

impl Purpose {
    pub fn dst(self) -> &'static [u8] {
        match self {
            Purpose::Claim => dst::CLAIM,
            Purpose::Refund => dst::REFUND,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ring is empty or larger than [`MAX_RING_SIZE`].
    RingSize,
    /// Bytes are not the canonical encoding of a Ristretto point.
    NonCanonicalPoint,
    /// A point that must not be the identity is the identity.
    IdentityPoint,
    /// Bytes are not a canonically reduced scalar.
    NonCanonicalScalar,
    /// The secret key does not match the ring member at the signer index.
    SignerMismatch,
    /// The signer index is outside the ring.
    SignerIndex,
    /// A serialised signature or proof has the wrong length.
    Length,
    /// The signature does not verify.
    Invalid,
    /// No tag base was found within [`TAG_BASE_MAX_ATTEMPTS`] (never happens in practice).
    TagBase,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::RingSize => "ring size out of range",
            Error::NonCanonicalPoint => "non-canonical point encoding",
            Error::IdentityPoint => "identity point not allowed",
            Error::NonCanonicalScalar => "non-canonical scalar encoding",
            Error::SignerMismatch => "secret key does not match the ring member",
            Error::SignerIndex => "signer index out of range",
            Error::Length => "wrong encoded length",
            Error::Invalid => "signature does not verify",
            Error::TagBase => "no tag base found",
        };
        f.write_str(msg)
    }
}

fn framed_dst(tag: &[u8]) -> [u8; 1] {
    debug_assert!(tag.len() < 256);
    [tag.len() as u8]
}

/// Blake2b-256 over the concatenation of `parts`.
pub fn blake2b(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-512 over the concatenation of `parts`, reduced to a scalar (wide reduction).
pub fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Decodes a canonical point encoding.
pub fn decode_point(bytes: &PointBytes) -> Result<RistrettoPoint, Error> {
    CompressedRistretto(*bytes).decompress().ok_or(Error::NonCanonicalPoint)
}

/// Decodes a canonical point encoding that must not be the identity.
pub fn decode_nonidentity_point(bytes: &PointBytes) -> Result<RistrettoPoint, Error> {
    let p = decode_point(bytes)?;
    if p == RistrettoPoint::identity() {
        return Err(Error::IdentityPoint);
    }
    Ok(p)
}

/// Decodes a canonically reduced scalar.
pub fn decode_scalar(bytes: &ScalarBytes) -> Result<Scalar, Error> {
    Option::from(Scalar::from_canonical_bytes(*bytes)).ok_or(Error::NonCanonicalScalar)
}

/// The per-round tag base `H`, by try-and-increment:
/// `b_ctr = Blake2b-256(len ‖ "poltergift/v1/tag-base" ‖ round_id ‖ ctr as u32 LE)`, and `H` is the
/// first `b_ctr` (ctr = 0, 1, ...) that is a canonical encoding of a non-identity point.
///
/// Every group element has exactly one canonical encoding, so `H` is a uniformly random point whose
/// discrete log nobody knows.
pub fn tag_base(round_id: &RoundId) -> Result<(RistrettoPoint, PointBytes), Error> {
    for ctr in 0..TAG_BASE_MAX_ATTEMPTS {
        let candidate = blake2b(&[
            &framed_dst(dst::TAG_BASE),
            dst::TAG_BASE,
            round_id,
            &ctr.to_le_bytes(),
        ]);
        if let Ok(p) = decode_nonidentity_point(&candidate) {
            return Ok((p, candidate));
        }
    }
    Err(Error::TagBase)
}

/// `Blake2b-256(len ‖ "poltergift/v1/ring" ‖ round_id ‖ n as u32 LE ‖ P_0 ‖ … ‖ P_{n-1})`.
pub fn ring_hash(round_id: &RoundId, ring: &[PointBytes]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(framed_dst(dst::RING));
    h.update(dst::RING);
    h.update(round_id);
    h.update((ring.len() as u32).to_le_bytes());
    for p in ring {
        h.update(p);
    }
    h.finalize().into()
}

/// The message a claim or refund signs: `Blake2b-256(len ‖ "poltergift/v1/payout" ‖ cbor)`, where
/// `cbor` is the CBOR encoding of the payout `StealthTransferStatement`.
pub fn payout_message(statement_cbor: &[u8]) -> [u8; 32] {
    blake2b(&[&framed_dst(dst::PAYOUT), dst::PAYOUT, statement_cbor])
}

/// A member secret key. Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Scalar);

impl SecretKey {
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        loop {
            let s = Scalar::random(rng);
            if s != Scalar::ZERO {
                return Self(s);
            }
        }
    }

    pub fn from_bytes(bytes: &ScalarBytes) -> Result<Self, Error> {
        let s = decode_scalar(bytes)?;
        if s == Scalar::ZERO {
            return Err(Error::NonCanonicalScalar);
        }
        Ok(Self(s))
    }

    pub fn to_bytes(&self) -> ScalarBytes {
        self.0.to_bytes()
    }

    pub fn public_point(&self) -> RistrettoPoint {
        RistrettoPoint::mul_base(&self.0)
    }

    pub fn public_key(&self) -> PointBytes {
        self.public_point().compress().to_bytes()
    }

    /// `I = x·H` for this round.
    pub fn key_image(&self, round_id: &RoundId) -> Result<PointBytes, Error> {
        let (h, _) = tag_base(round_id)?;
        Ok((h * self.0).compress().to_bytes())
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// A ring signature `(c_0, s_0, …, s_{n-1})`. Encoded as `c_0 ‖ s_0 ‖ … ‖ s_{n-1}`, 32 bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSignature {
    pub c0: ScalarBytes,
    pub s: Vec<ScalarBytes>,
}

impl RingSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * (self.s.len() + 1));
        out.extend_from_slice(&self.c0);
        for s in &self.s {
            out.extend_from_slice(s);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 64 || bytes.len() % 32 != 0 {
            return Err(Error::Length);
        }
        let mut chunks = bytes.chunks_exact(32).map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        });
        let c0 = chunks.next().ok_or(Error::Length)?;
        Ok(Self { c0, s: chunks.collect() })
    }

    pub fn ring_size(&self) -> usize {
        self.s.len()
    }
}

/// `len ‖ dst ‖ round_id ‖ ring_hash ‖ I ‖ msg`, the fixed prefix of every challenge hash.
fn challenge_prefix(purpose: Purpose, round_id: &RoundId, ring_hash: &[u8; 32], image: &PointBytes, msg: &[u8; 32]) -> Vec<u8> {
    let tag = purpose.dst();
    let mut prefix = Vec::with_capacity(1 + tag.len() + 32 * 4);
    prefix.extend_from_slice(&framed_dst(tag));
    prefix.extend_from_slice(tag);
    prefix.extend_from_slice(round_id);
    prefix.extend_from_slice(ring_hash);
    prefix.extend_from_slice(image);
    prefix.extend_from_slice(msg);
    prefix
}

/// `c = Scalar(SHA-512(prefix ‖ L ‖ R))`.
fn challenge(prefix: &[u8], l: &PointBytes, r: &PointBytes) -> Scalar {
    hash_to_scalar(&[prefix, l, r])
}

fn decode_ring(ring: &[PointBytes]) -> Result<Vec<RistrettoPoint>, Error> {
    if ring.is_empty() || ring.len() > MAX_RING_SIZE {
        return Err(Error::RingSize);
    }
    ring.iter().map(decode_nonidentity_point).collect()
}

/// Signs `msg` as one of `ring`, returning the signature and the key image.
pub fn sign<R: CryptoRng + ?Sized>(
    purpose: Purpose,
    round_id: &RoundId,
    ring: &[PointBytes],
    signer_index: usize,
    secret: &SecretKey,
    msg: &[u8; 32],
    rng: &mut R,
) -> Result<(RingSignature, PointBytes), Error> {
    let points = decode_ring(ring)?;
    let n = points.len();
    if signer_index >= n {
        return Err(Error::SignerIndex);
    }
    let x = secret.as_scalar();
    if points[signer_index] != RistrettoPoint::mul_base(x) {
        return Err(Error::SignerMismatch);
    }

    let (h, _) = tag_base(round_id)?;
    let image_point = h * x;
    let image = image_point.compress().to_bytes();
    let prefix = challenge_prefix(purpose, round_id, &ring_hash(round_id, ring), &image, msg);

    let mut c = alloc::vec![Scalar::ZERO; n];
    let mut s = alloc::vec![Scalar::ZERO; n];

    let mut alpha = Scalar::random(rng);
    let l = RistrettoPoint::mul_base(&alpha).compress().to_bytes();
    let r = (h * alpha).compress().to_bytes();
    let mut i = (signer_index + 1) % n;
    c[i] = challenge(&prefix, &l, &r);

    while i != signer_index {
        s[i] = Scalar::random(rng);
        let l = RistrettoPoint::vartime_multiscalar_mul([s[i], c[i]], [RISTRETTO_BASEPOINT_POINT, points[i]]);
        let r = RistrettoPoint::vartime_multiscalar_mul([s[i], c[i]], [h, image_point]);
        let next = (i + 1) % n;
        c[next] = challenge(&prefix, &l.compress().to_bytes(), &r.compress().to_bytes());
        i = next;
    }
    s[signer_index] = alpha - c[signer_index] * x;
    alpha.zeroize();

    Ok((
        RingSignature {
            c0: c[0].to_bytes(),
            s: s.iter().map(Scalar::to_bytes).collect(),
        },
        image,
    ))
}

/// Verifies a ring signature. The checks match the template's exactly: ring size, canonical and
/// non-identity points (ring and image), canonical scalars, and closure of the challenge chain.
pub fn verify(
    purpose: Purpose,
    round_id: &RoundId,
    ring: &[PointBytes],
    image: &PointBytes,
    msg: &[u8; 32],
    sig: &RingSignature,
) -> Result<(), Error> {
    let points = decode_ring(ring)?;
    if sig.s.len() != points.len() {
        return Err(Error::Length);
    }
    let image_point = decode_nonidentity_point(image)?;
    let c0 = decode_scalar(&sig.c0)?;
    let s = sig.s.iter().map(decode_scalar).collect::<Result<Vec<_>, _>>()?;

    let (h, _) = tag_base(round_id)?;
    let prefix = challenge_prefix(purpose, round_id, &ring_hash(round_id, ring), image, msg);

    let mut c = c0;
    for (p, s_i) in points.iter().zip(&s) {
        let l = RistrettoPoint::vartime_multiscalar_mul([*s_i, c], [RISTRETTO_BASEPOINT_POINT, *p]);
        let r = RistrettoPoint::vartime_multiscalar_mul([*s_i, c], [h, image_point]);
        c = challenge(&prefix, &l.compress().to_bytes(), &r.compress().to_bytes());
    }
    if c == c0 { Ok(()) } else { Err(Error::Invalid) }
}

/// A Schnorr proof of possession for a member key, bound to one round:
/// `c = Scalar(SHA-512(len ‖ "poltergift/v1/join-pop" ‖ round_id ‖ P ‖ R))`, `s = k + c·x`.
/// Encoded as `R ‖ s` (64 bytes). It reveals nothing about the key image.
pub fn sign_pop<R: CryptoRng + ?Sized>(round_id: &RoundId, secret: &SecretKey, rng: &mut R) -> [u8; 64] {
    let mut k = SecretKey::random(rng);
    let r = RistrettoPoint::mul_base(k.as_scalar()).compress().to_bytes();
    let c = pop_challenge(round_id, &secret.public_key(), &r);
    let s = k.as_scalar() + c * secret.as_scalar();
    k.zeroize();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s.to_bytes());
    out
}

fn pop_challenge(round_id: &RoundId, public: &PointBytes, r: &PointBytes) -> Scalar {
    hash_to_scalar(&[&framed_dst(dst::JOIN_POP), dst::JOIN_POP, round_id, public, r])
}

/// Verifies a proof of possession: `s·G − c·P == R`.
pub fn verify_pop(round_id: &RoundId, public: &PointBytes, pop: &[u8]) -> Result<(), Error> {
    if pop.len() != 64 {
        return Err(Error::Length);
    }
    let p = decode_nonidentity_point(public)?;
    let mut r = [0u8; 32];
    r.copy_from_slice(&pop[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&pop[32..]);
    decode_point(&r)?;
    let s = decode_scalar(&s)?;
    let c = pop_challenge(round_id, public, &r);
    let lhs = RistrettoPoint::vartime_multiscalar_mul([s, -c], [RISTRETTO_BASEPOINT_POINT, p]);
    if lhs.compress().to_bytes() == r { Ok(()) } else { Err(Error::Invalid) }
}

/// The compressed base point, as the template hard-codes it.
pub const BASEPOINT_BYTES: PointBytes = RISTRETTO_BASEPOINT_COMPRESSED.0;

#[cfg(test)]
mod tests;
