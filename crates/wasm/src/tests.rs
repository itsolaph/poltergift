//! Drives the JSON API the way the web page does: a full round of five ghosts, attack attempts,
//! and the recipient check that each wallet opens only its own gift.

use serde_json::{Value, json};

use crate::api::call;

fn req(v: Value) -> Value {
    serde_json::from_str(&call(&v.to_string())).unwrap()
}

fn seed(n: u8) -> String {
    hex::encode([n; 32])
}

struct Ghost {
    member: (String, String),
    view: (String, String),
    spend: (String, String),
}

fn keygen(n: u8) -> (String, String) {
    let r = req(json!({"op": "keygen", "seed": seed(n)}));
    (r["secret"].as_str().unwrap().into(), r["public"].as_str().unwrap().into())
}

const GIFT: u64 = 5_000_000;
const FEE: u64 = 50_000;
const ROUND_ID: [u8; 32] = [0x42; 32];

fn round(size: u32) -> (Value, Vec<Ghost>) {
    let params =
        json!({"gift_amount": GIFT, "size": size, "join_deadline": 10, "claim_deadline": 20, "claim_fee": FEE});
    let created = req(json!({"op": "create", "params": params, "round_id": hex::encode(ROUND_ID), "now": 1}));
    assert_eq!(created["ok"], true, "{created}");
    let mut state = created["state"].clone();
    let mut ghosts = Vec::new();
    for g in 0..size as u8 {
        let ghost = Ghost { member: keygen(10 + g), view: keygen(50 + g), spend: keygen(90 + g) };
        let r = req(json!({"op": "join", "state": state, "now": 2, "member": ghost.member.1,
            "pop_secret": ghost.member.0, "gift": GIFT, "seed": seed(130 + g)}));
        assert_eq!(r["ok"], true, "{r}");
        state = r["state"].clone();
        ghosts.push(ghost);
    }
    (state, ghosts)
}

fn claim(state: &Value, ghosts: &[Ghost], i: usize, salt: u8) -> (Value, Value) {
    let ring: Vec<String> = ghosts.iter().map(|g| g.member.1.clone()).collect();
    let payout = req(json!({"op": "payout", "view_public": ghosts[i].view.1, "spend_public": ghosts[i].spend.1,
        "amount": GIFT - FEE, "seed": seed(200 + salt)}));
    let signed = req(json!({"op": "sign_claim", "round_id": hex::encode(ROUND_ID), "ring": ring, "index": i,
        "secret": ghosts[i].member.0, "message": payout["message"], "seed": seed(220 + salt)}));
    let r = req(json!({"op": "claim", "state": state, "now": 3, "key_image": signed["key_image"],
        "signature": signed["signature"], "message": payout["message"], "fee_charged": 19_500}));
    (r, payout)
}

#[test]
fn five_ghosts_full_round_and_private_gifts() {
    let (mut state, ghosts) = round(5);
    let mut outputs = Vec::new();
    for (n, i) in [3usize, 0, 4, 1, 2].into_iter().enumerate() {
        let (r, payout) = claim(&state, &ghosts, i, n as u8);
        assert_eq!(r["ok"], true, "{r}");
        state = r["state"].clone();
        outputs.push((i, payout["output"].clone()));
    }
    let view = &req(json!({"op": "tag_base", "round_id": hex::encode(ROUND_ID)}));
    assert_eq!(view["ok"], true);
    for (owner, output) in &outputs {
        for (g, ghost) in ghosts.iter().enumerate() {
            let opened = req(
                json!({"op": "open", "view_secret": ghost.view.0, "spend_public": ghost.spend.1, "output": output}),
            );
            if g == *owner {
                assert_eq!(opened["amount"], GIFT - FEE);
            } else {
                assert!(opened["amount"].is_null(), "ghost {g} must not open ghost {owner}'s gift");
            }
        }
    }
}

#[test]
fn double_claim_and_redirect_rejected_with_template_messages() {
    let (state, ghosts) = round(3);
    let (r, payout) = claim(&state, &ghosts, 1, 1);
    let state2 = r["state"].clone();
    let (again, _) = claim(&state2, &ghosts, 1, 2);
    assert_eq!(again["error"], "gift already claimed with this tag");

    // Redirect: keep ghost 0's signature, swap in a payout to a thief's wallet.
    let ring: Vec<String> = ghosts.iter().map(|g| g.member.1.clone()).collect();
    let honest = req(
        json!({"op": "payout", "view_public": ghosts[0].view.1, "spend_public": ghosts[0].spend.1, "amount": GIFT - FEE, "seed": seed(1)}),
    );
    let signed = req(json!({"op": "sign_claim", "round_id": hex::encode(ROUND_ID), "ring": ring, "index": 0,
        "secret": ghosts[0].member.0, "message": honest["message"], "seed": seed(2)}));
    let r = req(json!({"op": "claim", "state": state2, "now": 3, "key_image": signed["key_image"],
        "signature": signed["signature"], "message": payout["message"], "fee_charged": 0}));
    assert_eq!(r["error"], "ring signature does not verify");
}

#[test]
fn bad_requests_do_not_panic() {
    for bad in ["", "{}", "{\"op\":\"nope\"}", "{\"op\":\"keygen\",\"seed\":\"zz\"}", "[1,2]"] {
        let r: Value = serde_json::from_str(&call(bad)).unwrap();
        assert_eq!(r["ok"], false);
    }
}

#[test]
fn ffi_round_trip() {
    let input = json!({"op": "keygen", "seed": seed(7)}).to_string();
    let ptr = crate::pg_alloc(input.len());
    unsafe {
        core::ptr::copy_nonoverlapping(input.as_ptr(), ptr, input.len());
        let out = crate::pg_call(ptr, input.len());
        let len = u32::from_le_bytes(core::slice::from_raw_parts(out, 4).try_into().unwrap()) as usize;
        let body = core::str::from_utf8(core::slice::from_raw_parts(out.add(4), len)).unwrap().to_string();
        crate::pg_free(out, 4 + len);
        crate::pg_free(ptr, input.len());
        assert!(body.contains("\"ok\":true"));
    }
}
