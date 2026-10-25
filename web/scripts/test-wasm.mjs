// Smoke test of the built site's engine: loads dist/poltergift.wasm the way the page does and plays
// a full round, an attack, and the recipient check through the JSON API.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "../dist");
const { instance } = await WebAssembly.instantiate(readFileSync(join(dist, "poltergift.wasm")), {});
const w = instance.exports;
const enc = new TextEncoder();
const dec = new TextDecoder();
let counter = 0;
const seed = () => (++counter).toString(16).padStart(2, "0").repeat(32);

function call(req) {
  const input = enc.encode(JSON.stringify(req));
  const p = w.pg_alloc(input.length);
  new Uint8Array(w.memory.buffer, p, input.length).set(input);
  const out = w.pg_call(p, input.length);
  const len = new DataView(w.memory.buffer).getUint32(out, true);
  const text = dec.decode(new Uint8Array(w.memory.buffer, out + 4, len));
  w.pg_free(out, 4 + len);
  w.pg_free(p, input.length);
  return JSON.parse(text);
}

const keygen = () => call({ op: "keygen", seed: seed() });

test("five ghosts play a full round in the browser engine", () => {
  const GIFT = 5_000_000, FEE = 50_000;
  const roundId = "ab".repeat(32);
  let r = call({ op: "create", round_id: roundId, now: 1, params: { gift_amount: GIFT, size: 5, join_deadline: 10, claim_deadline: 20, claim_fee: FEE } });
  assert.equal(r.ok, true, r.error);
  let state = r.state;
  const ghosts = Array.from({ length: 5 }, () => ({ m: keygen(), v: keygen(), s: keygen() }));
  for (const g of ghosts) {
    r = call({ op: "join", state, now: 2, member: g.m.public, pop_secret: g.m.secret, gift: GIFT, seed: seed() });
    assert.equal(r.ok, true, r.error);
    state = r.state;
  }
  assert.equal(r.view.sealed, true);
  const ring = ghosts.map((g) => g.m.public);
  const outputs = [];
  for (const i of [4, 2, 0, 3, 1]) {
    const p = call({ op: "payout", view_public: ghosts[i].v.public, spend_public: ghosts[i].s.public, amount: GIFT - FEE, seed: seed() });
    const s = call({ op: "sign_claim", round_id: roundId, ring, index: i, secret: ghosts[i].m.secret, message: p.message, seed: seed() });
    r = call({ op: "claim", state, now: 3, key_image: s.key_image, signature: s.signature, message: p.message, fee_charged: 19_500 });
    assert.equal(r.ok, true, r.error);
    state = r.state;
    outputs.push([i, p.output]);
    const again = call({ op: "claim", state, now: 3, key_image: s.key_image, signature: s.signature, message: p.message, fee_charged: 0 });
    assert.equal(again.error, "gift already claimed with this tag");
  }
  assert.equal(r.view.claims, 5);
  assert.equal(r.view.solvent, true);
  for (const [owner, output] of outputs) {
    ghosts.forEach((g, i) => {
      const o = call({ op: "open", view_secret: g.v.secret, spend_public: g.s.public, output });
      assert.equal(o.amount, i === owner ? GIFT - FEE : null);
    });
  }
});
