//! On-chain verification for Poltergift, built only from engine intrinsics.
//!
//! This is the verifier half of `poltergift-ring`. Every hashed byte string must match that crate
//! exactly (framing, order, widths); the template tests sign with `poltergift-ring` and verify here,
//! which is what keeps the two in step.

use tari_template_lib::{
    prelude::*,
    types::{Hash32, crypto::Scalar32Bytes},
};

/// The largest ring the template accepts. Keeps a claim's verification well inside the fee intent's
/// compute budget.
pub const MAX_RING_SIZE: usize = 16;
const TAG_BASE_MAX_ATTEMPTS: u32 = 256;

pub mod dst {
    pub const TAG_BASE: &[u8] = b"poltergift/v1/tag-base";
    pub const RING: &[u8] = b"poltergift/v1/ring";
    pub const CLAIM: &[u8] = b"poltergift/v1/claim";
    pub const REFUND: &[u8] = b"poltergift/v1/refund";
    pub const JOIN_POP: &[u8] = b"poltergift/v1/join-pop";
    pub const PAYOUT: &[u8] = b"poltergift/v1/payout";
}

/// The compressed Ristretto base point `G`.
const BASEPOINT: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f, 0x58, 0xe3, 0x0b,
    0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

/// The canonical encoding of the identity point is all zeros, and it is the only encoding of the
/// identity, so a byte comparison on a canonical point is an exact identity test.
const IDENTITY: [u8; 32] = [0u8; 32];

fn framed(tag: &[u8]) -> [u8; 1] {
    [tag.len() as u8]
}

/// Whether `p` is a canonical, non-identity point: the requirement for member keys and key images.
pub fn is_valid_point(p: &RistrettoPublicKeyBytes) -> bool {
    p.into_array() != IDENTITY && intrinsics::ristretto_is_canonical(p)
}

/// The per-round tag base `H` (try-and-increment over Blake2b-256; see `poltergift_ring::tag_base`).
pub fn tag_base(round_id: &[u8; 32]) -> RistrettoPublicKeyBytes {
    for ctr in 0..TAG_BASE_MAX_ATTEMPTS {
        let candidate =
            intrinsics::hash_blake2b_parts(&[&framed(dst::TAG_BASE), dst::TAG_BASE, round_id, &ctr.to_le_bytes()]);
        let candidate = RistrettoPublicKeyBytes::from(candidate.into_array());
        if is_valid_point(&candidate) {
            return candidate;
        }
    }
    panic!("no tag base found for this round id");
}

pub fn ring_hash(round_id: &[u8; 32], ring: &[RistrettoPublicKeyBytes]) -> Hash32 {
    let tag_len = framed(dst::RING);
    let count = (ring.len() as u32).to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![&tag_len, dst::RING, round_id, &count];
    parts.extend(ring.iter().map(|p| p.as_ref()));
    intrinsics::hash_blake2b_parts(&parts)
}

pub fn payout_message(statement_cbor: &[u8]) -> Hash32 {
    intrinsics::hash_blake2b_parts(&[&framed(dst::PAYOUT), dst::PAYOUT, statement_cbor])
}

fn scalar_at(bytes: &[u8], index: usize) -> Scalar32Bytes {
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes[index * 32..(index + 1) * 32]);
    Scalar32Bytes::from(a)
}

fn challenge(prefix: &[u8], l: &RistrettoPublicKeyBytes, r: &RistrettoPublicKeyBytes) -> Scalar32Bytes {
    let wide = intrinsics::hash_sha512_parts(&[prefix, l.as_ref(), r.as_ref()]);
    intrinsics::scalar_from_uniform_bytes(&wide.into_array())
}

/// The reason a ring signature was rejected. Panic messages in the template use these strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    RingSize,
    Length,
    BadKeyImage,
    NonCanonicalScalar,
    Invalid,
}

impl RingError {
    pub fn as_str(self) -> &'static str {
        match self {
            RingError::RingSize => "ring size out of range",
            RingError::Length => "signature length does not match the ring",
            RingError::BadKeyImage => "key image must be a canonical non-identity point",
            RingError::NonCanonicalScalar => "signature scalar is not canonical",
            RingError::Invalid => "ring signature does not verify",
        }
    }
}

/// Inputs to a ring signature verification. Ring members are assumed already validated (they were
/// checked when they joined).
pub struct RingCheck<'a> {
    pub purpose_dst: &'static [u8],
    pub round_id: &'a [u8; 32],
    pub ring: &'a [RistrettoPublicKeyBytes],
    pub ring_hash: &'a Hash32,
    pub tag_base: &'a RistrettoPublicKeyBytes,
    pub key_image: &'a RistrettoPublicKeyBytes,
    pub message: &'a Hash32,
    pub signature: &'a [u8],
}

/// Verifies `c_0 ‖ s_0 ‖ … ‖ s_{n-1}`: recomputes `c_{i+1} = H(prefix ‖ s_i·G + c_i·P_i ‖ s_i·H + c_i·I)`
/// around the ring and accepts iff it returns to `c_0`.
pub fn verify_ring(check: &RingCheck<'_>) -> Result<(), RingError> {
    let n = check.ring.len();
    if n == 0 || n > MAX_RING_SIZE {
        return Err(RingError::RingSize);
    }
    if check.signature.len() != 32 * (n + 1) {
        return Err(RingError::Length);
    }
    if !is_valid_point(check.key_image) {
        return Err(RingError::BadKeyImage);
    }
    let scalars: Vec<Scalar32Bytes> = (0..=n).map(|i| scalar_at(check.signature, i)).collect();
    if !scalars.iter().all(intrinsics::scalar_is_canonical) {
        return Err(RingError::NonCanonicalScalar);
    }

    let mut prefix = Vec::with_capacity(1 + check.purpose_dst.len() + 128);
    prefix.extend_from_slice(&framed(check.purpose_dst));
    prefix.extend_from_slice(check.purpose_dst);
    prefix.extend_from_slice(check.round_id);
    prefix.extend_from_slice(check.ring_hash.as_ref());
    prefix.extend_from_slice(check.key_image.as_ref());
    prefix.extend_from_slice(check.message.as_ref());

    let g = RistrettoPublicKeyBytes::from(BASEPOINT);
    let c0 = scalars[0];
    let mut c = c0;
    for (p, s) in check.ring.iter().zip(&scalars[1..]) {
        let l = intrinsics::ristretto_msm(&[g, *p], &[*s, c]);
        let r = intrinsics::ristretto_msm(&[*check.tag_base, *check.key_image], &[*s, c]);
        c = challenge(&prefix, &l, &r);
    }
    if c == c0 { Ok(()) } else { Err(RingError::Invalid) }
}

/// Verifies a member's proof of possession `R ‖ s`: `s·G − c·P == R` with
/// `c = H(len ‖ "poltergift/v1/join-pop" ‖ round_id ‖ P ‖ R)`.
pub fn verify_pop(round_id: &[u8; 32], member: &RistrettoPublicKeyBytes, pop: &[u8]) -> bool {
    if pop.len() != 64 {
        return false;
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&pop[..32]);
    let s = scalar_at(pop, 1);
    if !intrinsics::scalar_is_canonical(&s) {
        return false;
    }
    let wide = intrinsics::hash_sha512_parts(&[&framed(dst::JOIN_POP), dst::JOIN_POP, round_id, member.as_ref(), &r]);
    let c = intrinsics::scalar_from_uniform_bytes(&wide.into_array());
    let neg_c = intrinsics::scalar_negate(&c);
    let lhs = intrinsics::ristretto_msm(&[RistrettoPublicKeyBytes::from(BASEPOINT), *member], &[s, neg_c]);
    lhs.into_array() == r
}
