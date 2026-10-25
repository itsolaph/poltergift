//! Full rounds played end to end against the real engine.

mod common;

use common::*;

fn play_full_round(size: u32) {
    let mut h = Harness::new();
    let round = h.full_round(size);
    assert_eq!(h.status(round.component), (size, size, 0, 0, true));
    assert_eq!(h.vault_balance(round.component), size as u64 * GIFT);

    // Claim in a scrambled order: claim order must not depend on join order.
    let mut order: Vec<usize> = (0..size as usize).collect();
    order.reverse();
    order.rotate_left(size as usize / 2);
    for (n, i) in order.into_iter().enumerate() {
        h.claim(&round, i).unwrap_or_else(|e| panic!("claim by member {i} failed: {e}"));
        let (_, _, claims, _, _) = h.status(round.component);
        assert_eq!(claims, n as u32 + 1);
    }
    assert_eq!(h.status(round.component), (size, size, size, 0, true));
    // Each claim removes exactly one payout plus at most one claim fee (unused fee is refunded).
    let balance = h.vault_balance(round.component);
    assert!(balance <= size as u64 * FEE, "vault keeps at most fee dust, has {balance}");
}

#[test]
fn round_of_3() {
    play_full_round(3);
}

#[test]
fn round_of_5() {
    play_full_round(5);
}

#[test]
fn round_of_8() {
    play_full_round(8);
}
