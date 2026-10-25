//! Model-vs-template equivalence and money conservation.
//!
//! Random sequences of joins, claims, refunds, forgeries and epoch jumps are applied both to the
//! real template (official engine) and to `poltergift-model` (the rules the browser demo runs).
//! After every step:
//!   * both accept, or both reject with the same template message;
//!   * `status()` and the vault balance agree;
//!   * the vault can pay every outstanding gift (solvency), and value paid out never exceeds
//!     value deposited (conservation).

mod common;

use common::*;
use poltergift_model::{Params, PayoutShape, RoundModel};
use poltergift_ring::{self as ring, Purpose, SecretKey};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tari_template_test_tooling::template_lib_types::stealth::StealthTransferStatement;

#[derive(Debug, Clone)]
enum Op {
    /// Join with a fresh key (`dup` re-uses an existing member key; `bad_pop` signs for another key;
    /// `delta` changes the gift amount).
    Join { dup: bool, bad_pop: bool, delta: i8 },
    /// Claim as member `who` (an outsider when out of range), optionally redirected or mis-sized.
    Claim { who: u8, redirect: bool, wrong_amount: bool },
    /// Refund as member `who` (an outsider when out of range).
    Refund { who: u8, steal: bool },
    /// Move the epoch forward.
    Advance { epochs: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (prop::bool::weighted(0.1), prop::bool::weighted(0.1), prop_oneof![8 => Just(0i8), 1 => Just(-1i8), 1 => Just(1i8)])
            .prop_map(|(dup, bad_pop, delta)| Op::Join { dup, bad_pop, delta }),
        4 => (0u8..6, prop::bool::weighted(0.1), prop::bool::weighted(0.1))
            .prop_map(|(who, redirect, wrong_amount)| Op::Claim { who, redirect, wrong_amount }),
        2 => (0u8..6, prop::bool::weighted(0.15)).prop_map(|(who, steal)| Op::Refund { who, steal }),
        2 => (1u8..12).prop_map(|epochs| Op::Advance { epochs }),
    ]
}

struct Sim {
    h: Harness,
    round: Round,
    model: RoundModel,
    rng: ChaCha20Rng,
    now: u64,
    deposited: u128,
}

fn shape_of(s: &StealthTransferStatement) -> PayoutShape {
    PayoutShape {
        stealth_inputs: s.stealth_inputs().len(),
        covenant_claims: s.covenant_claims.len(),
        revealed_output: s.revealed_output_amount().to_u128(),
        stealth_outputs: s.stealth_outputs().len(),
        revealed_input: s.revealed_input_amount().to_u128(),
    }
}

fn reason<T>(r: &Result<T, tari_template_test_tooling::engine_types::commit_result::RejectReason>) -> Option<String> {
    r.as_ref().err().map(|e| e.to_string())
}

impl Sim {
    fn new(size: u32, seed: u64) -> Self {
        let mut h = Harness::new();
        let round = h.create_round(size);
        let model = RoundModel::create(
            Params {
                gift_amount: GIFT as u128,
                size,
                join_deadline: JOIN_DEADLINE,
                claim_deadline: CLAIM_DEADLINE,
                claim_fee: FEE as u128,
            },
            round.round_id,
            1,
        )
        .unwrap();
        Self { h, round, model, rng: ChaCha20Rng::seed_from_u64(seed), now: 1, deposited: 0 }
    }

    fn check(&self, label: &str, template: Option<String>, model: Result<(), poltergift_model::Rejected>) {
        match (&template, &model) {
            (None, Ok(())) => {}
            (Some(t), Err(m)) => assert!(t.contains(m.0), "{label}: template said {t:?}, model said {m:?}"),
            _ => panic!("{label}: outcomes differ: template {template:?}, model {model:?}"),
        }
    }

    fn apply(&mut self, op: &Op) {
        match *op {
            Op::Advance { epochs } => {
                self.now += epochs as u64;
                self.h.set_epoch(self.now);
            }
            Op::Join { dup, bad_pop, delta } => {
                let key = if dup && !self.round.members.is_empty() {
                    self.round.members[0].clone()
                } else {
                    SecretKey::random(&mut self.rng)
                };
                let signer = if bad_pop { SecretKey::random(&mut self.rng) } else { key.clone() };
                let pop = ring::sign_pop(&self.round.round_id, &signer, &mut self.rng).to_vec();
                let amount = (GIFT as i64 + delta as i64) as u64;
                let t = self.h.try_join_raw(self.round.component, key.public_key(), pop.clone(), amount);
                let m = self.model.join(self.now, key.public_key(), &pop, amount as u128, true, false);
                self.check("join", reason(&t), m);
                if t.is_ok() {
                    self.round.members.push(key);
                    self.deposited += amount as u128;
                }
            }
            Op::Claim { who, redirect, wrong_amount } => {
                let amount = if wrong_amount { PAYOUT + 1 } else { PAYOUT };
                let signed = payout(amount);
                let submitted = if redirect { payout(amount) } else { signed.clone() };
                let msg_signed = payout_message(&signed);
                let ring_keys = self.round.ring();
                let (image, sig) = if ring_keys.is_empty() {
                    (SecretKey::random(&mut self.rng).key_image(&self.round.round_id).unwrap(), vec![1u8; 64])
                } else if (who as usize) < self.round.members.len() {
                    let (s, i) = ring::sign(
                        Purpose::Claim,
                        &self.round.round_id,
                        &ring_keys,
                        who as usize,
                        &self.round.members[who as usize],
                        &msg_signed,
                        &mut self.rng,
                    )
                    .unwrap();
                    (i, s.to_bytes())
                } else {
                    let outsider = SecretKey::random(&mut self.rng);
                    let mut fake = ring_keys.clone();
                    fake[0] = outsider.public_key();
                    let (s, i) = ring::sign(
                        Purpose::Claim,
                        &self.round.round_id,
                        &fake,
                        0,
                        &outsider,
                        &msg_signed,
                        &mut self.rng,
                    )
                    .unwrap();
                    (i, s.to_bytes())
                };
                let t = self.h.submit_claim(self.round.component, image, sig.clone(), submitted.clone());
                let m = self.model.claim(self.now, image, &sig, &shape_of(&submitted), &payout_message(&submitted), 0);
                self.check("claim", reason(&t), m);
            }
            Op::Refund { who, steal } => {
                let statement = payout(PAYOUT);
                let msg = payout_message(&statement);
                let (member, signer) = if (who as usize) < self.round.members.len() {
                    let m = self.round.members[who as usize].clone();
                    let s = if steal { SecretKey::random(&mut self.rng) } else { m.clone() };
                    (m, s)
                } else {
                    let o = SecretKey::random(&mut self.rng);
                    (o.clone(), o)
                };
                let (proof, image) = ring::sign(
                    Purpose::Refund,
                    &self.round.round_id,
                    &[signer.public_key()],
                    0,
                    &signer,
                    &msg,
                    &mut self.rng,
                )
                .unwrap();
                let proof = proof.to_bytes();
                let t = self.h.submit_refund(
                    self.round.component,
                    member.public_key(),
                    image,
                    proof.clone(),
                    statement.clone(),
                );
                let m = self.model.refund(self.now, member.public_key(), image, &proof, &shape_of(&statement), &msg, 0);
                self.check("refund", reason(&t), m);
            }
        }
        self.check_invariants();
    }

    fn check_invariants(&mut self) {
        let status = self.h.status(self.round.component);
        assert_eq!(status, self.model.status(), "status diverged");
        let vault = self.h.vault_balance(self.round.component) as u128;
        assert_eq!(vault, self.model.vault, "vault diverged");
        assert!(self.model.is_solvent(), "vault cannot pay outstanding gifts");
        let paid_out = (self.model.claims + self.model.refunds) as u128 * self.model.payout_amount();
        assert_eq!(self.deposited, vault + paid_out, "value not conserved");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, max_shrink_iters: 64, ..ProptestConfig::default() })]

    #[test]
    fn template_matches_model_and_conserves_value(
        size in 2u32..=4,
        seed in any::<u64>(),
        ops in prop::collection::vec(op_strategy(), 1..28),
    ) {
        let mut sim = Sim::new(size, seed);
        for op in &ops {
            sim.apply(op);
        }
    }
}

/// A fixed sequence that is guaranteed to walk every path: fill, seal, claims (good and forged),
/// the claim deadline, refunds for the members who did not claim, and refusals afterwards.
#[test]
fn scripted_sequence_covers_every_path() {
    let mut sim = Sim::new(4, 7);
    let script = [
        Op::Join { dup: false, bad_pop: false, delta: 0 },
        Op::Join { dup: true, bad_pop: false, delta: 0 },
        Op::Join { dup: false, bad_pop: true, delta: 0 },
        Op::Join { dup: false, bad_pop: false, delta: -1 },
        Op::Claim { who: 0, redirect: false, wrong_amount: false },
        Op::Join { dup: false, bad_pop: false, delta: 0 },
        Op::Join { dup: false, bad_pop: false, delta: 0 },
        Op::Join { dup: false, bad_pop: false, delta: 0 },
        Op::Join { dup: false, bad_pop: false, delta: 0 },
        Op::Claim { who: 2, redirect: false, wrong_amount: false },
        Op::Claim { who: 2, redirect: false, wrong_amount: false },
        Op::Claim { who: 1, redirect: true, wrong_amount: false },
        Op::Claim { who: 1, redirect: false, wrong_amount: true },
        Op::Claim { who: 5, redirect: false, wrong_amount: false },
        Op::Refund { who: 3, steal: false },
        Op::Claim { who: 0, redirect: false, wrong_amount: false },
        Op::Advance { epochs: 25 },
        Op::Claim { who: 1, redirect: false, wrong_amount: false },
        Op::Refund { who: 0, steal: false },
        Op::Refund { who: 1, steal: true },
        Op::Refund { who: 1, steal: false },
        Op::Refund { who: 1, steal: false },
        Op::Refund { who: 3, steal: false },
        Op::Refund { who: 5, steal: false },
    ];
    for op in &script {
        sim.apply(op);
    }
    assert_eq!(sim.model.status(), (4, 4, 2, 2, true));
    assert_eq!(sim.model.outstanding(), 0);
}
