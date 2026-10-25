// Records the live rounds listed in deployments/esmeralda.json into web/public/recorded.json, so the
// "Live on Esmeralda" screen still has something honest to show (labelled as recorded) if the public
// indexer is unreachable. Run after `npm run build` (it uses dist/poltergift.wasm to re-check H).
//
//   node scripts/snapshot.mjs [indexer-url]
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const indexer = (process.argv[2] ?? "https://esme-indexer-a.ootle.tari.com").replace(/\/$/, "");
const deployment = JSON.parse(readFileSync(join(web, "../deployments/esmeralda.json"), "utf8"));

const { instance } = await WebAssembly.instantiate(readFileSync(join(web, "dist/poltergift.wasm")), {});
const w = instance.exports;
function call(req) {
  const input = new TextEncoder().encode(JSON.stringify(req));
  const p = w.pg_alloc(input.length);
  new Uint8Array(w.memory.buffer, p, input.length).set(input);
  const out = w.pg_call(p, input.length);
  const len = new DataView(w.memory.buffer).getUint32(out, true);
  const text = new TextDecoder().decode(new Uint8Array(w.memory.buffer, out + 4, len));
  w.pg_free(out, 4 + len);
  w.pg_free(p, input.length);
  return JSON.parse(text);
}

const get = async (path) => {
  const r = await fetch(`${indexer}/${path}`);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
};
const bytes = (v) => (v["@cbor"] === "tag" ? bytes(v.value) : v.hex);

const stats = await get("epoch-manager/stats");
const rounds = [];
for (const r of deployment.rounds) {
  const s = await get(`substates/${r.component}`);
  const [vault, gift, claimFee, size, joinDeadline, claimDeadline, roundId, tagBase, members, ringHash, spent, , claims, refunds] =
    s.state.up.substate.Component.body.state;
  const v = await get(`substates/vault_${bytes(vault)}`);
  const h = call({ op: "tag_base", round_id: bytes(roundId) });
  rounds.push({
    component: r.component,
    vaultId: bytes(vault),
    gift,
    claimFee,
    size,
    joinDeadline,
    claimDeadline,
    roundId: bytes(roundId),
    tagBase: bytes(tagBase),
    members: members.map(bytes),
    sealed: ringHash !== null,
    spentTags: spent.map(bytes),
    claims,
    refunds,
    vault: Number(v.state.up.substate.Vault.resource_container.Stealth.revealed_amount),
    tagBaseVerified: h.tag_base === bytes(tagBase),
  });
}
const snapshot = { taken_at: new Date().toISOString(), epoch: stats.consensus_epoch ?? stats.current_epoch, indexer, rounds };
writeFileSync(join(web, "public/recorded.json"), JSON.stringify(snapshot, null, 2) + "\n");
console.log(`recorded ${rounds.length} round(s) at epoch ${snapshot.epoch} into web/public/recorded.json`);
