//! Measures what a claim costs on the network's fee table, for ring sizes 4, 8 and 16, and checks
//! the vault accounting when fees are real: a claim removes the payout plus the fee actually
//! charged, and the unused part of `claim_fee` is refunded into the vault.

mod common;

use common::*;

/// The Esmeralda fee table as published in tari-ootle `applications/tari_ootle_app_utilities/src/fee_tables.rs`
/// (fields this engine version knows about). Every network currently uses the same table.
fn network_fee_table(h: &Harness) -> tari_template_test_tooling::engine_types::fees::FeeTable {
    let mut table = h.test.fee_table().clone();
    table.per_transaction_weight_cost = 1;
    table.per_module_call_cost = 1;
    table.per_byte_storage_cost = 1;
    table.per_template_load_cost_unit = 10;
    table.per_substate_create_cost = 250;
    table.per_wasm_point_cost = 1;
    table.storage_cost_divisor = 1;
    table.template_load_bytes_cost_divisor = 3000;
    table.wasm_points_cost_divisor = 1000;
    table.log_bytes_cost_divisor = 64;
    table
}

const GENEROUS_CLAIM_FEE: u64 = 1_000_000;

struct Measurement {
    size: u32,
    fee_charged: u64,
    native_points: u64,
    wasm_points: u64,
}

fn measure(size: u32) -> Measurement {
    let mut h = Harness::new();
    let table = network_fee_table(&h);
    h.test.set_fee_table(table);
    h.test.enable_fees();
    h.account_fee = Some(2_000_000);

    let component = h
        .try_create(GIFT, size, JOIN_DEADLINE, CLAIM_DEADLINE, GENEROUS_CLAIM_FEE)
        .expect("create with fees");
    let mut round = Round {
        component,
        round_id: component.as_object_key().into_array(),
        members: Vec::new(),
    };
    for _ in 0..size {
        let m = h.new_member();
        h.try_join(&round, &m).expect("join with fees");
        round.members.push(m);
    }
    let before = h.vault_balance(component);
    assert_eq!(before, size as u64 * GIFT);

    let payout_amount = GIFT - GENEROUS_CLAIM_FEE;
    let statement = payout(payout_amount);
    let (image, sig) = h.sign_claim(&round, size as usize - 1, &statement);
    let result = h.submit_claim(component, image, sig, statement).expect("claim with fees");
    let points = h.test.last_execution_points();
    let fee_charged = result.finalize.fee_receipt.total_fees_charged();

    let after = h.vault_balance(component);
    assert_eq!(
        before - after,
        payout_amount + fee_charged,
        "vault pays exactly the payout plus the fee actually charged"
    );
    assert!(fee_charged < GENEROUS_CLAIM_FEE);
    Measurement {
        size,
        fee_charged,
        native_points: points.native,
        wasm_points: points.wasm,
    }
}

#[test]
fn claim_cost_for_ring_sizes_4_8_16() {
    let rows: Vec<_> = [4u32, 8, 16].into_iter().map(measure).collect();
    println!("| ring size | fee charged (µT) | native points | wasm points |");
    println!("|---|---|---|---|");
    for r in &rows {
        println!("| {} | {} | {} | {} |", r.size, r.fee_charged, r.native_points, r.wasm_points);
    }
    // Verification must stay inside the fee intent's free compute grace even for the largest ring.
    let largest = rows.last().unwrap();
    assert!(largest.native_points + largest.wasm_points < 32_000_000);
    assert!(rows.windows(2).all(|w| w[0].native_points < w[1].native_points));
}
