use alloc::vec::Vec;

use curve25519_dalek::scalar::Scalar;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::*;

const ROUND: RoundId = [7u8; 32];
const MSG: [u8; 32] = [42u8; 32];

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn members(n: usize, seed: u64) -> (Vec<SecretKey>, Vec<PointBytes>) {
    let mut r = rng(seed);
    let sks: Vec<_> = (0..n).map(|_| SecretKey::random(&mut r)).collect();
    let pks = sks.iter().map(SecretKey::public_key).collect();
    (sks, pks)
}

/// The group order `l`, little endian. Adding it to a canonical scalar gives a non-canonical
/// encoding of the same value.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn add_l(bytes: &ScalarBytes) -> Option<ScalarBytes> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = bytes[i] as u16 + L[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    (carry == 0).then_some(out)
}

#[test]
fn sign_verify_every_index() {
    let (sks, ring) = members(5, 1);
    for (i, sk) in sks.iter().enumerate() {
        let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, i, sk, &MSG, &mut rng(100 + i as u64)).unwrap();
        verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &sig).unwrap();
        assert_eq!(image, sk.key_image(&ROUND).unwrap());
    }
}

#[test]
fn key_image_is_deterministic_per_round_and_differs_across_rounds() {
    let (sks, ring) = members(3, 2);
    let (_, a) = sign(Purpose::Claim, &ROUND, &ring, 1, &sks[1], &MSG, &mut rng(1)).unwrap();
    let (_, b) = sign(Purpose::Claim, &ROUND, &ring, 1, &sks[1], &[1u8; 32], &mut rng(2)).unwrap();
    assert_eq!(a, b, "same key, same round: same tag");
    let other_round = [8u8; 32];
    let (_, c) = sign(Purpose::Claim, &other_round, &ring, 1, &sks[1], &MSG, &mut rng(3)).unwrap();
    assert_ne!(a, c, "tags must not link across rounds");
}

#[test]
fn rejects_wrong_message_round_purpose() {
    let (sks, ring) = members(4, 3);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 2, &sks[2], &MSG, &mut rng(9)).unwrap();
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &image, &[0u8; 32], &sig), Err(Error::Invalid));
    assert_eq!(verify(Purpose::Claim, &[9u8; 32], &ring, &image, &MSG, &sig), Err(Error::Invalid));
    assert_eq!(verify(Purpose::Refund, &ROUND, &ring, &image, &MSG, &sig), Err(Error::Invalid));
}

#[test]
fn rejects_tampered_ring_order_and_membership() {
    let (sks, ring) = members(4, 4);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 0, &sks[0], &MSG, &mut rng(10)).unwrap();
    let mut swapped = ring.clone();
    swapped.swap(1, 2);
    assert_eq!(verify(Purpose::Claim, &ROUND, &swapped, &image, &MSG, &sig), Err(Error::Invalid));
    let (_, outsider) = members(1, 99);
    let mut replaced = ring.clone();
    replaced[3] = outsider[0];
    assert_eq!(verify(Purpose::Claim, &ROUND, &replaced, &image, &MSG, &sig), Err(Error::Invalid));
}

#[test]
fn rejects_tampered_scalars_and_image() {
    let (sks, ring) = members(3, 5);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 1, &sks[1], &MSG, &mut rng(11)).unwrap();
    let mut bad = sig.clone();
    bad.s[0][0] ^= 1;
    assert!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &bad).is_err());
    let mut bad = sig.clone();
    bad.c0[5] ^= 0x10;
    assert!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &bad).is_err());
    let other_image = sks[0].key_image(&ROUND).unwrap();
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &other_image, &MSG, &sig), Err(Error::Invalid));
}

#[test]
fn rejects_non_canonical_scalar_malleation() {
    let (sks, ring) = members(3, 6);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 0, &sks[0], &MSG, &mut rng(12)).unwrap();
    let mut found = false;
    for idx in 0..3 {
        if let Some(m) = add_l(&sig.s[idx]) {
            let mut bad = sig.clone();
            bad.s[idx] = m;
            assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &bad), Err(Error::NonCanonicalScalar));
            found = true;
        }
    }
    if let Some(m) = add_l(&sig.c0) {
        let mut bad = sig.clone();
        bad.c0 = m;
        assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &bad), Err(Error::NonCanonicalScalar));
        found = true;
    }
    assert!(found, "at least one scalar small enough to malleate");
}

#[test]
fn rejects_identity_and_garbage_points() {
    let (sks, ring) = members(2, 7);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 0, &sks[0], &MSG, &mut rng(13)).unwrap();
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &[0u8; 32], &MSG, &sig), Err(Error::IdentityPoint));
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &[0xffu8; 32], &MSG, &sig), Err(Error::NonCanonicalPoint));
    let mut bad_ring = ring.clone();
    bad_ring[1] = [0u8; 32];
    assert_eq!(verify(Purpose::Claim, &ROUND, &bad_ring, &image, &MSG, &sig), Err(Error::IdentityPoint));
}

#[test]
fn rejects_wrong_lengths_and_sizes() {
    let (sks, ring) = members(3, 8);
    let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 0, &sks[0], &MSG, &mut rng(14)).unwrap();
    let mut short = sig.clone();
    short.s.pop();
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &short), Err(Error::Length));
    assert_eq!(RingSignature::from_bytes(&[0u8; 33]), Err(Error::Length));
    assert_eq!(RingSignature::from_bytes(&[0u8; 32]), Err(Error::Length));
    assert_eq!(RingSignature::from_bytes(&sig.to_bytes()).unwrap(), sig);
    assert_eq!(verify(Purpose::Claim, &ROUND, &[], &image, &MSG, &sig), Err(Error::RingSize));
    let (_, big) = members(MAX_RING_SIZE + 1, 9);
    assert_eq!(sign(Purpose::Claim, &ROUND, &big, 0, &sks[0], &MSG, &mut rng(1)).unwrap_err(), Error::RingSize);
}

#[test]
fn signer_must_be_in_ring() {
    let (sks, ring) = members(3, 10);
    assert_eq!(sign(Purpose::Claim, &ROUND, &ring, 1, &sks[0], &MSG, &mut rng(1)).unwrap_err(), Error::SignerMismatch);
    assert_eq!(sign(Purpose::Claim, &ROUND, &ring, 3, &sks[0], &MSG, &mut rng(1)).unwrap_err(), Error::SignerIndex);
}

#[test]
fn refund_proof_is_a_ring_of_one() {
    let (sks, _) = members(1, 11);
    let ring = [sks[0].public_key()];
    let (sig, image) = sign(Purpose::Refund, &ROUND, &ring, 0, &sks[0], &MSG, &mut rng(2)).unwrap();
    verify(Purpose::Refund, &ROUND, &ring, &image, &MSG, &sig).unwrap();
    assert_eq!(image, sks[0].key_image(&ROUND).unwrap());
    assert_eq!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &sig), Err(Error::Invalid));
}

#[test]
fn pop_roundtrip_and_binding() {
    let (sks, pks) = members(2, 12);
    let pop = sign_pop(&ROUND, &sks[0], &mut rng(5));
    verify_pop(&ROUND, &pks[0], &pop).unwrap();
    assert_eq!(verify_pop(&[1u8; 32], &pks[0], &pop), Err(Error::Invalid));
    assert_eq!(verify_pop(&ROUND, &pks[1], &pop), Err(Error::Invalid));
    assert_eq!(verify_pop(&ROUND, &pks[0], &pop[..63]), Err(Error::Length));
    let mut bad = pop;
    bad[40] ^= 1;
    assert!(verify_pop(&ROUND, &pks[0], &bad).is_err());
}

#[test]
fn tag_base_is_stable() {
    let (_, a) = tag_base(&ROUND).unwrap();
    let (_, b) = tag_base(&ROUND).unwrap();
    assert_eq!(a, b);
    let (_, c) = tag_base(&[0u8; 32]).unwrap();
    assert_ne!(a, c);
    assert_ne!(a, BASEPOINT_BYTES);
}

#[test]
fn scalar_helpers_match_dalek() {
    assert_eq!(decode_scalar(&Scalar::ONE.to_bytes()).unwrap(), Scalar::ONE);
    assert_eq!(decode_scalar(&L), Err(Error::NonCanonicalScalar));
    assert!(SecretKey::from_bytes(&[0u8; 32]).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_any_member_any_ring_size_verifies(n in 1usize..=MAX_RING_SIZE, seed in any::<u64>(), msg in any::<[u8; 32]>(), round in any::<[u8; 32]>()) {
        let (sks, ring) = members(n, seed);
        let idx = (seed as usize) % n;
        let (sig, image) = sign(Purpose::Claim, &round, &ring, idx, &sks[idx], &msg, &mut rng(seed ^ 0xabc)).unwrap();
        prop_assert!(verify(Purpose::Claim, &round, &ring, &image, &msg, &sig).is_ok());
        prop_assert_eq!(image, sks[idx].key_image(&round).unwrap());
    }

    #[test]
    fn prop_any_single_bit_flip_breaks_signature(seed in any::<u64>(), byte in 0usize..128, bit in 0u8..8) {
        let (sks, ring) = members(3, seed);
        let (sig, image) = sign(Purpose::Claim, &ROUND, &ring, 1, &sks[1], &MSG, &mut rng(seed)).unwrap();
        let mut bytes = sig.to_bytes();
        bytes[byte] ^= 1 << bit;
        let bad = RingSignature::from_bytes(&bytes).unwrap();
        prop_assert!(verify(Purpose::Claim, &ROUND, &ring, &image, &MSG, &bad).is_err());
    }
}
