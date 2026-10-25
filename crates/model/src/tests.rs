use poltergift_ring::SecretKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::*;

const GIFT: u128 = 5_000_000;
const FEE: u128 = 20_000;

fn params(size: u32) -> Params {
    Params {
        gift_amount: GIFT,
        size,
        join_deadline: 10,
        claim_deadline: 20,
        claim_fee: FEE,
    }
}

fn filled(size: u32, rng: &mut ChaCha20Rng) -> (RoundModel, Vec<SecretKey>) {
    let mut round = RoundModel::create(params(size), [3u8; 32], 1).unwrap();
    let keys: Vec<_> = (0..size).map(|_| SecretKey::random(rng)).collect();
    for k in &keys {
        let pop = ring::sign_pop(&round.round_id, k, rng);
        round.join(1, k.public_key(), &pop, GIFT, true, false).unwrap();
    }
    (round, keys)
}

fn claim(round: &mut RoundModel, keys: &[SecretKey], i: usize, rng: &mut ChaCha20Rng) -> Outcome {
    let msg = [i as u8; 32];
    let ring_keys = round.members.clone();
    let (sig, image) = ring::sign(Purpose::Claim, &round.round_id, &ring_keys, i, &keys[i], &msg, rng).unwrap();
    let shape = PayoutShape::valid(round.payout_amount());
    round.claim(2, image, &sig.to_bytes(), &shape, &msg, 0)
}

#[test]
fn full_round_conserves_value() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (mut round, keys) = filled(4, &mut rng);
    assert!(round.is_sealed());
    for i in [2, 0, 3, 1] {
        claim(&mut round, &keys, i, &mut rng).unwrap();
        assert!(round.is_solvent());
    }
    assert_eq!(round.status(), (4, 4, 4, 0, true));
    assert_eq!(round.vault, 4 * GIFT - 4 * (GIFT - FEE));
}

#[test]
fn double_claim_and_wrong_shape_rejected_with_template_messages() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let (mut round, keys) = filled(3, &mut rng);
    claim(&mut round, &keys, 1, &mut rng).unwrap();
    assert_eq!(claim(&mut round, &keys, 1, &mut rng), Err(Rejected(msg::TAG_SPENT)));
    let mut shape = PayoutShape::valid(round.payout_amount());
    shape.stealth_outputs = 2;
    assert_eq!(
        round.claim(2, [9u8; 32], &[0u8; 128], &shape, &[0u8; 32], 0),
        Err(Rejected(msg::PAYOUT_OUTPUTS))
    );
}

#[test]
fn refunds_follow_deadlines() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut round = RoundModel::create(params(3), [4u8; 32], 1).unwrap();
    let k = SecretKey::random(&mut rng);
    let pop = ring::sign_pop(&round.round_id, &k, &mut rng);
    round.join(1, k.public_key(), &pop, GIFT, true, false).unwrap();
    let msg = [1u8; 32];
    let (proof, image) =
        ring::sign(Purpose::Refund, &round.round_id, &[k.public_key()], 0, &k, &msg, &mut rng).unwrap();
    let shape = PayoutShape::valid(round.payout_amount());
    assert_eq!(
        round.refund(5, k.public_key(), image, &proof.to_bytes(), &shape, &msg, 0),
        Err(Rejected(msg::OPEN_BEFORE_JOIN_DEADLINE))
    );
    round.refund(10, k.public_key(), image, &proof.to_bytes(), &shape, &msg, 0).unwrap();
    assert_eq!(round.vault, FEE);
    assert_eq!(round.outstanding(), 0);
}

#[test]
fn create_rejects_bad_parameters() {
    let mut p = params(1);
    assert_eq!(RoundModel::create(p, [0u8; 32], 1).unwrap_err(), Rejected(msg::SIZE));
    p = params(3);
    p.gift_amount = u64::MAX as u128 + 1;
    assert_eq!(RoundModel::create(p, [0u8; 32], 1).unwrap_err(), Rejected(msg::GIFT_TOO_LARGE));
    p = params(3);
    p.join_deadline = 1;
    assert_eq!(RoundModel::create(p, [0u8; 32], 1).unwrap_err(), Rejected(msg::JOIN_DEADLINE_FUTURE));
}
