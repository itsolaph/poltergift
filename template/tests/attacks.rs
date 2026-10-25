//! Attack tests. Each test is named for the attack it attempts and asserts the exact reason the
//! template gives for refusing it. THREAT_MODEL.md maps every threat to the tests here.

mod common;

use common::*;
use poltergift_ring::{self as ring, Purpose, SecretKey};
use tari_template_test_tooling::{
    support::stealth,
    template_lib_types::{Amount, constants::TARI_TOKEN},
    transaction::args,
    wallet_crypto::MaskAndValue,
    crypto::{RistrettoSecretKey, SecretKey as _},
};

/// The group order `l`, little endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `s + l`, a second encoding of the same scalar, or `None` if it would not fit in 256 bits.
fn add_order(s: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s[i] as u16 + L[i] as u16 + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    (carry == 0 && out[31] & 0x80 == 0).then_some(out)
}

// ------------------------------------------------------------------------------------------------
// create: parameter abuse, zero and overflow values
// ------------------------------------------------------------------------------------------------

#[test]
fn create_rejects_round_of_one() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 1, JOIN_DEADLINE, CLAIM_DEADLINE, FEE);
    assert_reject_reason_str(r, "round size must be between 2 and 16");
}

#[test]
fn create_rejects_round_of_zero() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 0, JOIN_DEADLINE, CLAIM_DEADLINE, FEE);
    assert_reject_reason_str(r, "round size must be between 2 and 16");
}

#[test]
fn create_rejects_ring_larger_than_verifier_limit() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 17, JOIN_DEADLINE, CLAIM_DEADLINE, FEE);
    assert_reject_reason_str(r, "round size must be between 2 and 16");
}

#[test]
fn create_rejects_zero_claim_fee() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 3, JOIN_DEADLINE, CLAIM_DEADLINE, 0);
    assert_reject_reason_str(r, "claim fee must be positive");
}

#[test]
fn create_rejects_fee_that_eats_the_whole_gift() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 3, JOIN_DEADLINE, CLAIM_DEADLINE, GIFT);
    assert_reject_reason_str(r, "claim fee must be smaller than the gift");
}

#[test]
fn create_rejects_zero_gift() {
    let mut h = Harness::new();
    let r = h.try_create(0, 3, JOIN_DEADLINE, CLAIM_DEADLINE, 1);
    assert_reject_reason_str(r, "claim fee must be smaller than the gift");
}

#[test]
fn create_rejects_gift_too_large_for_a_stealth_output() {
    let mut h = Harness::new();
    let tx = h
        .test
        .transaction()
        .call_function(h.template, "create", args![
            Amount::new(u64::MAX as u128 + 1),
            3u32,
            JOIN_DEADLINE,
            CLAIM_DEADLINE,
            Amount::from(FEE)
        ])
        .build_and_seal(&h.account_key.clone());
    assert_reject_reason_str(h.execute(tx, vec![]), "gift amount too large");
}

#[test]
fn create_rejects_join_deadline_in_the_past() {
    let mut h = Harness::new();
    h.set_epoch(5);
    let r = h.try_create(GIFT, 3, 5, CLAIM_DEADLINE, FEE);
    assert_reject_reason_str(r, "join deadline must be in the future");
}

#[test]
fn create_rejects_claim_deadline_not_after_join_deadline() {
    let mut h = Harness::new();
    let r = h.try_create(GIFT, 3, JOIN_DEADLINE, JOIN_DEADLINE, FEE);
    assert_reject_reason_str(r, "claim deadline must be after the join deadline");
}

// ------------------------------------------------------------------------------------------------
// join: wrong gifts, late joins, key abuse
// ------------------------------------------------------------------------------------------------

#[test]
fn join_rejects_gift_below_round_amount() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let m = h.new_member();
    let pop = ring::sign_pop(&round.round_id, &m, &mut h.rng).to_vec();
    let r = h.try_join_raw(round.component, m.public_key(), pop, GIFT - 1);
    assert_reject_reason_str(r, "gift must be exactly the round's gift amount");
}

#[test]
fn join_rejects_gift_above_round_amount() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let m = h.new_member();
    let pop = ring::sign_pop(&round.round_id, &m, &mut h.rng).to_vec();
    let r = h.try_join_raw(round.component, m.public_key(), pop, GIFT + 1);
    assert_reject_reason_str(r, "gift must be exactly the round's gift amount");
}

#[test]
fn join_rejects_fake_token_named_tari() {
    let mut h = Harness::with_templates(&[".", "tests/templates/fake_token"]);
    let fake = h.test.get_template_address("FakeToken");
    let round = h.create_round(3);
    let m = h.new_member();
    let pop = ring::sign_pop(&round.round_id, &m, &mut h.rng).to_vec();
    let tx = h
        .test
        .transaction()
        .call_function(fake, "mint", args![Amount::from(GIFT)])
        .put_last_instruction_output_on_workspace("gift")
        .call_method(round.component, "join", args![pk_bytes(m.public_key()), pop, Workspace("gift")])
        .build_and_seal(&h.account_key.clone());
    assert_reject_reason_str(h.execute(tx, vec![]), "gift must be TARI");
}

#[test]
fn join_rejects_late_join_after_deadline() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    h.set_epoch(JOIN_DEADLINE);
    let m = h.new_member();
    assert_reject_reason_str(h.try_join(&round, &m), "join deadline has passed");
}

#[test]
fn join_rejects_extra_member_after_seal() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let m = h.new_member();
    assert_reject_reason_str(h.try_join(&round, &m), "round is sealed");
}

#[test]
fn join_rejects_same_key_twice() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let m = h.new_member();
    h.try_join(&round, &m).unwrap();
    assert_reject_reason_str(h.try_join(&round, &m), "member key already joined");
}

#[test]
fn join_rejects_identity_point_as_member_key() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let r = h.try_join_raw(round.component, [0u8; 32], vec![0u8; 64], GIFT);
    assert_reject_reason_str(r, "member key must be a canonical non-identity point");
}

#[test]
fn join_rejects_non_canonical_member_key() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let r = h.try_join_raw(round.component, [0xffu8; 32], vec![0u8; 64], GIFT);
    assert_reject_reason_str(r, "member key must be a canonical non-identity point");
}

#[test]
fn join_rejects_missing_proof_of_possession() {
    let mut h = Harness::new();
    let round = h.create_round(3);
    let m = h.new_member();
    let r = h.try_join_raw(round.component, m.public_key(), vec![], GIFT);
    assert_reject_reason_str(r, "invalid proof of possession");
}

#[test]
fn join_rejects_registering_someone_elses_key() {
    // The attacker knows the victim's public key but not its secret, and signs with their own key.
    let mut h = Harness::new();
    let round = h.create_round(3);
    let victim = h.new_member();
    let attacker = h.new_member();
    let pop = ring::sign_pop(&round.round_id, &attacker, &mut h.rng).to_vec();
    let r = h.try_join_raw(round.component, victim.public_key(), pop, GIFT);
    assert_reject_reason_str(r, "invalid proof of possession");
}

#[test]
fn join_rejects_proof_of_possession_replayed_from_another_round() {
    let mut h = Harness::new();
    let first = h.create_round(3);
    let second = h.create_round(3);
    let m = h.new_member();
    let pop_for_first = ring::sign_pop(&first.round_id, &m, &mut h.rng).to_vec();
    h.try_join_raw(first.component, m.public_key(), pop_for_first.clone(), GIFT).unwrap();
    let r = h.try_join_raw(second.component, m.public_key(), pop_for_first, GIFT);
    assert_reject_reason_str(r, "invalid proof of possession");
}

// ------------------------------------------------------------------------------------------------
// claim: double claims, outsiders, forgeries, replays, redirection, shape abuse
// ------------------------------------------------------------------------------------------------

#[test]
fn claim_rejects_claim_before_round_is_sealed() {
    let mut h = Harness::new();
    let mut round = h.create_round(3);
    for _ in 0..2 {
        let m = h.new_member();
        h.try_join(&round, &m).unwrap();
        round.members.push(m);
    }
    assert_reject_reason_str(h.claim(&round, 0), "round is not sealed");
}

#[test]
fn claim_rejects_double_claim_with_the_same_tag() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (image, sig) = h.sign_claim(&round, 1, &statement);
    h.submit_claim(round.component, image, sig.clone(), statement.clone()).unwrap();
    let r = h.submit_claim(round.component, image, sig, statement);
    assert_reject_reason_str(r, "gift already claimed with this tag");
}

#[test]
fn claim_rejects_second_claim_with_fresh_signature_and_payout() {
    // A fresh signature over a fresh payout still carries the member's deterministic key image.
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.claim(&round, 2).unwrap();
    assert_reject_reason_str(h.claim(&round, 2), "gift already claimed with this tag");
    assert_eq!(h.status(round.component).2, 1);
}

#[test]
fn claim_rejects_outsider_who_substitutes_own_key_into_ring() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let outsider = h.new_member();
    let mut fake_ring = round.ring();
    fake_ring[0] = outsider.public_key();
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let (sig, image) =
        ring::sign(Purpose::Claim, &round.round_id, &fake_ring, 0, &outsider, &msg, &mut h.rng).unwrap();
    let r = h.submit_claim(round.component, image, sig.to_bytes(), statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_forged_signature_of_random_scalars() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let image = h.new_member().key_image(&round.round_id).unwrap();
    let forged: Vec<u8> = (0..4).flat_map(|_| h.new_member().to_bytes()).collect();
    let r = h.submit_claim(round.component, image, forged, statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_malleated_signature_with_non_canonical_scalar() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (image, sig) = h.sign_claim(&round, 0, &statement);
    let mut malleated = None;
    for chunk in 0..4 {
        if let Some(m) = add_order(&sig[chunk * 32..(chunk + 1) * 32]) {
            let mut bad = sig.clone();
            bad[chunk * 32..(chunk + 1) * 32].copy_from_slice(&m);
            malleated = Some(bad);
            break;
        }
    }
    let bad = malleated.expect("one of four random scalars is below 2^255 - l");
    let r = h.submit_claim(round.component, image, bad, statement);
    assert_reject_reason_str(r, "signature scalar is not canonical");
}

#[test]
fn claim_rejects_signature_with_another_members_key_image() {
    // Swapping in member 2's tag would let member 0 burn member 2's claim; the signature binds I.
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (_, sig) = h.sign_claim(&round, 0, &statement);
    let other_image = round.members[2].key_image(&round.round_id).unwrap();
    let r = h.submit_claim(round.component, other_image, sig, statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_identity_key_image() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (_, sig) = h.sign_claim(&round, 0, &statement);
    let r = h.submit_claim(round.component, [0u8; 32], sig, statement);
    assert_reject_reason_str(r, "key image must be a canonical non-identity point");
}

#[test]
fn claim_rejects_non_canonical_key_image() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (_, sig) = h.sign_claim(&round, 0, &statement);
    let r = h.submit_claim(round.component, [0xeeu8; 32], sig, statement);
    assert_reject_reason_str(r, "key image must be a canonical non-identity point");
}

#[test]
fn claim_rejects_replay_into_round_with_identical_ring() {
    // The same three keys join two rounds. A claim from round A must not verify in round B: the
    // round id is in every challenge and the tag base differs per round.
    let mut h = Harness::new();
    let mut a = h.create_round(3);
    let mut b = h.create_round(3);
    for _ in 0..3 {
        let m = h.new_member();
        h.try_join(&a, &m).unwrap();
        h.try_join(&b, &m).unwrap();
        b.members.push(m.clone());
        a.members.push(m);
    }
    assert_eq!(a.ring(), b.ring());
    let statement = payout(PAYOUT);
    let (image, sig) = h.sign_claim(&a, 1, &statement);
    let r = h.submit_claim(b.component, image, sig.clone(), statement.clone());
    assert_reject_reason_str(r, "ring signature does not verify");
    assert_ne!(image, a.members[1].key_image(&b.round_id).unwrap(), "tags differ across rounds");
    h.submit_claim(a.component, image, sig, statement).unwrap();
}

#[test]
fn claim_rejects_redirected_payout() {
    // A relayer or front-runner keeps the valid signature but swaps in their own payout output.
    let mut h = Harness::new();
    let round = h.full_round(3);
    let honest = payout(PAYOUT);
    let (image, sig) = h.sign_claim(&round, 0, &honest);
    let thief = payout(PAYOUT);
    let r = h.submit_claim(round.component, image, sig, thief);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_payout_larger_than_gift_minus_fee() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let greedy = payout(GIFT);
    let (image, sig) = h.sign_claim(&round, 0, &greedy);
    let r = h.submit_claim(round.component, image, sig, greedy);
    assert_reject_reason_str(r, "payout must spend exactly the gift minus the claim fee");
}

#[test]
fn claim_rejects_payout_smaller_than_gift_minus_fee() {
    // Under-claiming would strand funds in the vault and skew the accounting.
    let mut h = Harness::new();
    let round = h.full_round(3);
    let small = payout(PAYOUT - 1);
    let (image, sig) = h.sign_claim(&round, 0, &small);
    let r = h.submit_claim(round.component, image, sig, small);
    assert_reject_reason_str(r, "payout must spend exactly the gift minus the claim fee");
}

#[test]
fn claim_rejects_payout_with_revealed_output_bucket() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let leaky = stealth::generate_transfer_data(stealth::NO_INPUTS, PAYOUT, [PAYOUT - 1000], 1000u64).statement;
    let (image, sig) = h.sign_claim(&round, 0, &leaky);
    let r = h.submit_claim(round.component, image, sig, leaky);
    assert_reject_reason_str(r, "payout must not have a revealed output");
}

#[test]
fn claim_rejects_payout_split_into_two_outputs() {
    // Two outputs would let payouts differ in shape and fingerprint claimants.
    let mut h = Harness::new();
    let round = h.full_round(3);
    let split = stealth::generate_transfer_data(stealth::NO_INPUTS, PAYOUT, [PAYOUT - 100, 100], 0u64).statement;
    let (image, sig) = h.sign_claim(&round, 0, &split);
    let r = h.submit_claim(round.component, image, sig, split);
    assert_reject_reason_str(r, "payout must have exactly one stealth output");
}

#[test]
fn claim_rejects_payout_that_spends_extra_stealth_inputs() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let mask = RistrettoSecretKey::random(&mut h.rng);
    let mixed = stealth::generate_transfer_data(
        [MaskAndValue { mask, value: 1_000 }],
        PAYOUT,
        [PAYOUT + 1_000],
        0u64,
    )
    .statement;
    let (image, sig) = h.sign_claim(&round, 0, &mixed);
    let r = h.submit_claim(round.component, image, sig, mixed);
    assert_reject_reason_str(r, "payout must not spend stealth inputs");
}

#[test]
fn claim_rejects_claim_after_claim_deadline() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.set_epoch(CLAIM_DEADLINE);
    assert_reject_reason_str(h.claim(&round, 0), "claim deadline has passed");
}

#[test]
fn claim_rejects_call_from_main_intent() {
    // Outside the fee intent the vault may not pay fees, so the claim cannot be smuggled into a
    // transaction whose fee intent pays from some other source.
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (image, sig) = h.sign_claim(&round, 0, &statement);
    let key = h.ephemeral_key();
    let tx = h
        .test
        .transaction()
        .call_method(round.component, "claim", args![pk_bytes(image), sig, statement])
        .build_and_seal(&key);
    assert_reject_reason_str(h.execute(tx, vec![]), "main intent");
}

#[test]
fn claim_rejects_signature_over_a_shorter_ring() {
    // Ring tampering: the signer drops a member to shrink the ring.
    let mut h = Harness::new();
    let round = h.full_round(4);
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let short_ring = &round.ring()[..3];
    let (sig, image) =
        ring::sign(Purpose::Claim, &round.round_id, short_ring, 0, &round.members[0], &msg, &mut h.rng).unwrap();
    let r = h.submit_claim(round.component, image, sig.to_bytes(), statement);
    assert_reject_reason_str(r, "signature length does not match the ring");
}

#[test]
fn claim_rejects_signature_over_a_reordered_ring() {
    let mut h = Harness::new();
    let round = h.full_round(4);
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let mut reordered = round.ring();
    reordered.swap(1, 3);
    let (sig, image) =
        ring::sign(Purpose::Claim, &round.round_id, &reordered, 0, &round.members[0], &msg, &mut h.rng).unwrap();
    let r = h.submit_claim(round.component, image, sig.to_bytes(), statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_signature_padded_with_extra_scalars() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let statement = payout(PAYOUT);
    let (image, mut sig) = h.sign_claim(&round, 0, &statement);
    sig.extend_from_slice(&[1u8; 32]);
    let r = h.submit_claim(round.component, image, sig, statement);
    assert_reject_reason_str(r, "signature length does not match the ring");
}

#[test]
fn claim_rejects_refund_proof_presented_as_claim() {
    let mut h = Harness::new();
    let round = h.full_round(2);
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    // A refund-domain signature over the full ring must not pass as a claim.
    let (sig, image) =
        ring::sign(Purpose::Refund, &round.round_id, &round.ring(), 0, &round.members[0], &msg, &mut h.rng).unwrap();
    let r = h.submit_claim(round.component, image, sig.to_bytes(), statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_events_and_state_carry_no_identity() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    let result = h.claim(&round, 1).unwrap();
    let claim_events: Vec<_> = result
        .finalize
        .events
        .iter()
        .filter(|e| e.topic().contains("Claimed"))
        .collect();
    assert_eq!(claim_events.len(), 1);
    let payload = claim_events[0].payload();
    let keys: Vec<_> = payload.iter().map(|(k, _)| k.to_string()).collect();
    assert_eq!(keys, vec!["count".to_string()], "claim event leaks only a counter");
    for m in &round.members {
        let pk = Hash32Display(m.public_key()).to_string();
        assert!(!payload.to_string().contains(&pk));
    }
}

struct Hash32Display([u8; 32]);
impl std::fmt::Display for Hash32Display {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
// refund: early refunds, theft, double refunds, claim+refund combinations
// ------------------------------------------------------------------------------------------------

fn half_round(h: &mut Harness) -> Round {
    let mut round = h.create_round(3);
    for _ in 0..2 {
        let m = h.new_member();
        h.try_join(&round, &m).unwrap();
        round.members.push(m);
    }
    round
}

#[test]
fn refund_rejects_open_round_before_join_deadline() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    assert_reject_reason_str(h.refund(&round, 0), "round is open and the join deadline has not passed");
}

#[test]
fn refund_rejects_sealed_round_before_claim_deadline() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.set_epoch(JOIN_DEADLINE + 1);
    assert_reject_reason_str(h.refund(&round, 0), "round is sealed and the claim deadline has not passed");
}

#[test]
fn refund_rejects_member_who_already_claimed() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.claim(&round, 0).unwrap();
    h.set_epoch(CLAIM_DEADLINE);
    assert_reject_reason_str(h.refund(&round, 0), "gift already claimed with this tag");
    h.refund(&round, 1).unwrap();
    h.refund(&round, 2).unwrap();
    assert_eq!(h.status(round.component), (3, 3, 1, 2, true));
}

#[test]
fn refund_rejects_claimed_member_using_a_made_up_key_image() {
    // The claimed member tries to dodge the spent-tag check by presenting a different tag. The DLEQ
    // proof pins the tag to x·H, so any other tag fails verification.
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.claim(&round, 0).unwrap();
    h.set_epoch(CLAIM_DEADLINE);
    let statement = payout(PAYOUT);
    let (_, proof) = h.sign_refund(&round, 0, &statement);
    let fake_image = h.new_member().key_image(&round.round_id).unwrap();
    let r = h.submit_refund(round.component, round.members[0].public_key(), fake_image, proof, statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn refund_rejects_outsider_stealing_a_members_gift() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    let outsider = h.new_member();
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let (proof, image) = ring::sign(
        Purpose::Refund,
        &round.round_id,
        &[outsider.public_key()],
        0,
        &outsider,
        &msg,
        &mut h.rng,
    )
    .unwrap();
    let victim = round.members[0].public_key();
    let r = h.submit_refund(round.component, victim, image, proof.to_bytes(), statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn refund_rejects_non_member_key() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    let outsider = h.new_member();
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let (proof, image) = ring::sign(
        Purpose::Refund,
        &round.round_id,
        &[outsider.public_key()],
        0,
        &outsider,
        &msg,
        &mut h.rng,
    )
    .unwrap();
    let r = h.submit_refund(round.component, outsider.public_key(), image, proof.to_bytes(), statement);
    assert_reject_reason_str(r, "not a member of this round");
}

#[test]
fn refund_rejects_member_signing_for_another_member() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    let statement = payout(PAYOUT);
    let (image, proof) = h.sign_refund(&round, 0, &statement);
    let other = round.members[1].public_key();
    let r = h.submit_refund(round.component, other, image, proof, statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn refund_rejects_double_refund() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    h.refund(&round, 1).unwrap();
    assert_reject_reason_str(h.refund(&round, 1), "member already refunded");
}

#[test]
fn refund_rejects_redirected_payout() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    let honest = payout(PAYOUT);
    let (image, proof) = h.sign_refund(&round, 0, &honest);
    let r = h.submit_refund(round.component, round.members[0].public_key(), image, proof, payout(PAYOUT));
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn refund_rejects_claim_domain_signature_as_refund_proof() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    let statement = payout(PAYOUT);
    let msg = payout_message(&statement);
    let member = &round.members[0];
    let (sig, image) =
        ring::sign(Purpose::Claim, &round.round_id, &[member.public_key()], 0, member, &msg, &mut h.rng).unwrap();
    let r = h.submit_refund(round.component, member.public_key(), image, sig.to_bytes(), statement);
    assert_reject_reason_str(r, "ring signature does not verify");
}

#[test]
fn claim_rejects_member_after_their_refund() {
    let mut h = Harness::new();
    let round = h.full_round(3);
    h.set_epoch(CLAIM_DEADLINE);
    h.refund(&round, 2).unwrap();
    // Claims are closed after the deadline, and the refund also spent the member's tag.
    assert_reject_reason_str(h.claim(&round, 2), "claim deadline has passed");
}

#[test]
fn refund_after_join_deadline_returns_every_gift_of_unfilled_round() {
    let mut h = Harness::new();
    let round = half_round(&mut h);
    h.set_epoch(JOIN_DEADLINE);
    assert_eq!(h.vault_balance(round.component), 2 * GIFT);
    h.refund(&round, 0).unwrap();
    h.refund(&round, 1).unwrap();
    assert_eq!(h.status(round.component), (2, 3, 0, 2, false));
    assert!(h.vault_balance(round.component) <= 2 * FEE);
    // The round can no longer fill.
    let m = h.new_member();
    assert_reject_reason_str(h.try_join(&round, &m), "join deadline has passed");
}

#[test]
fn stealth_funded_join_uses_no_account() {
    // The gift comes from a stealth UTXO; the transaction is sealed by a throwaway key that is
    // also the revealed-output receiver, so no account appears in the join.
    let mut h = Harness::new();
    let round = h.create_round(2);

    // Fund a stealth UTXO from the test account (setup only).
    let value = GIFT + 1_000_000;
    let funding = stealth::generate_transfer_data(stealth::NO_INPUTS, value, [value], 0u64);
    let tx = h
        .test
        .transaction()
        .call_method(h.account, "withdraw", args![TARI_TOKEN, Amount::from(value)])
        .put_last_instruction_output_on_workspace("b")
        .stealth_transfer_with_input_bucket(TARI_TOKEN, funding.statement.clone(), "b")
        .build_and_seal(&h.account_key.clone());
    h.execute(tx, vec![h.owner_proof.clone()]).unwrap();

    let sealer = h.ephemeral_key();
    let sealer_pk = public_key_of(&sealer);
    let spend = stealth::generate_transfer_data_to(
        [MaskAndValue { mask: funding.output_masks[0].clone(), value }],
        0u64,
        [value - GIFT],
        GIFT,
        sealer_pk,
    );
    let m = h.new_member();
    let pop = ring::sign_pop(&round.round_id, &m, &mut h.rng).to_vec();
    let tx = h
        .test
        .transaction()
        .stealth_transfer(TARI_TOKEN, spend.statement)
        .put_last_instruction_output_on_workspace("gift")
        .call_method(round.component, "join", args![pk_bytes(m.public_key()), pop, Workspace("gift")])
        .finish()
        .add_signer(&sealer_pk, &funding.output_masks[0])
        .seal(&sealer);
    h.execute(tx, vec![]).unwrap();
    assert_eq!(h.status(round.component).0, 1);
}

#[track_caller]
fn assert_reject_reason_str<T>(result: Result<T, tari_template_test_tooling::engine_types::commit_result::RejectReason>, reason: &str) {
    match result {
        Ok(_) => panic!("expected rejection containing {reason:?}, but it succeeded"),
        Err(r) => {
            let s = r.to_string();
            assert!(s.contains(reason), "expected reject reason containing {reason:?}, got {s:?}");
        },
    }
}

#[allow(dead_code)]
fn unused(_: SecretKey) {}
