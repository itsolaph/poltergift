// Reads the real Poltergift rounds on Esmeralda straight from the public indexer (CORS is open).
// If the indexer cannot be reached, it falls back to a snapshot taken by web/scripts/snapshot.mjs,
// and says so.

import { call, type Reply } from "./pg";

export const INDEXERS = ["https://esme-indexer-a.ootle.tari.com", "https://ootle-indexer-a.tari.com"];
export const EXPLORER = "https://explorer.tari.mw";

export type Deployment = {
  network: string;
  template: { address: string; publish_tx: string; wasm_bytes: number } | null;
  rounds: {
    label: string;
    component: string;
    create_tx: string;
    params: { gift_amount_utari: number; size: number; join_deadline_epoch: number; claim_deadline_epoch: number; claim_fee_utari: number };
    joins: { tx: string; member_key: string; funded_from: string }[];
    claims: { tx: string; key_image: string; payout_output: string }[];
    refunds: { tx: string; key_image: string; payout_output: string }[];
  }[];
};

export type LiveRound = {
  component: string;
  vaultId: string;
  gift: number;
  claimFee: number;
  size: number;
  joinDeadline: number;
  claimDeadline: number;
  roundId: string;
  tagBase: string;
  members: string[];
  sealed: boolean;
  spentTags: string[];
  claims: number;
  refunds: number;
  vault: number;
  tagBaseVerified: boolean;
};

export type Snapshot = { taken_at: string; epoch: number; rounds: LiveRound[] };

type Cbor = { "@cbor": string; hex?: string; tag?: number; value?: Cbor } | number | null | Cbor[];

const HEX = /^[0-9a-f]+$/i;
const COMPONENT = /^component_[0-9a-f]{64}$/;
const TX = /^[0-9a-f]{64}$/;

/** Everything rendered from the indexer or the deployment file is validated to these shapes first. */
export function assertComponent(id: string): string {
  if (!COMPONENT.test(id)) throw new Error("malformed component address");
  return id;
}

export function assertTx(id: string): string {
  if (!TX.test(id)) throw new Error("malformed transaction id");
  return id;
}

function bytes(v: Cbor): string {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    if (v["@cbor"] === "bytes" && typeof v.hex === "string" && HEX.test(v.hex)) return v.hex.toLowerCase();
    if (v["@cbor"] === "tag" && v.value) return bytes(v.value);
  }
  throw new Error(`expected bytes, got ${JSON.stringify(v)}`);
}

function num(v: Cbor): number {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  throw new Error(`expected a number, got ${JSON.stringify(v)}`);
}

async function get(path: string): Promise<unknown> {
  let last: unknown = null;
  for (const base of INDEXERS) {
    try {
      const r = await fetch(`${base}/${path}`, { signal: AbortSignal.timeout(8000) });
      if (r.ok) return await r.json();
      last = new Error(`${base}: HTTP ${r.status}`);
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

export async function epoch(): Promise<number> {
  const s = (await get("epoch-manager/stats")) as { consensus_epoch?: number; current_epoch: number };
  return s.consensus_epoch ?? s.current_epoch;
}

/** Decodes a round component (the template's `Round` struct, a positional CBOR array). */
export function decodeRound(component: string, state: Cbor[]): Omit<LiveRound, "vault" | "tagBaseVerified"> {
  const [vault, gift, claimFee, size, joinDeadline, claimDeadline, roundId, tagBase, members, ringHash, spent, , claims, refunds] = state;
  return {
    component,
    vaultId: bytes(vault),
    gift: num(gift),
    claimFee: num(claimFee),
    size: num(size),
    joinDeadline: num(joinDeadline),
    claimDeadline: num(claimDeadline),
    roundId: bytes(roundId),
    tagBase: bytes(tagBase),
    members: (members as Cbor[]).map(bytes),
    sealed: ringHash !== null,
    spentTags: (spent as Cbor[]).map(bytes),
    claims: num(claims),
    refunds: num(refunds),
  };
}

export async function fetchRound(component: string): Promise<LiveRound> {
  assertComponent(component);
  const s = (await get(`substates/${component}`)) as {
    state: { up: { substate: { Component: { body: { state: Cbor[] } } } } };
  };
  const round = decodeRound(component, s.state.up.substate.Component.body.state);
  const v = (await get(`substates/vault_${round.vaultId}`)) as {
    state: { up: { substate: { Vault: { resource_container: { Stealth: { revealed_amount: string } } } } } };
  };
  const vault = Number(v.state.up.substate.Vault.resource_container.Stealth.revealed_amount);
  if (!Number.isFinite(vault)) throw new Error("malformed vault balance");
  const recomputed = call<Reply & { tag_base: string }>({ op: "tag_base", round_id: round.roundId });
  return { ...round, vault, tagBaseVerified: recomputed.ok && recomputed.tag_base === round.tagBase };
}

export async function loadDeployment(): Promise<Deployment | null> {
  try {
    const r = await fetch("deployments.json");
    return r.ok ? ((await r.json()) as Deployment) : null;
  } catch {
    return null;
  }
}

export async function loadSnapshot(): Promise<Snapshot | null> {
  try {
    const r = await fetch("recorded.json");
    return r.ok ? ((await r.json()) as Snapshot) : null;
  } catch {
    return null;
  }
}
