// Thin wrapper over poltergift.wasm: the same Rust ring-signature code and round model as the
// native client, compiled to WebAssembly. Requests and replies are JSON (see crates/wasm/src/api.rs).

type Exports = {
  memory: WebAssembly.Memory;
  pg_alloc(len: number): number;
  pg_free(ptr: number, len: number): void;
  pg_call(ptr: number, len: number): number;
};

let wasm: Exports | null = null;

export async function loadWasm(url = "poltergift.wasm"): Promise<void> {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`could not load ${url}: ${resp.status}`);
  const { instance } = await WebAssembly.instantiate(await resp.arrayBuffer(), {});
  wasm = instance.exports as unknown as Exports;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export type Reply = { ok: boolean; error?: string; rejected?: boolean; [k: string]: unknown };

export function call<T extends Reply = Reply>(request: Record<string, unknown>): T {
  if (!wasm) throw new Error("wasm not loaded");
  const input = enc.encode(JSON.stringify(request));
  const inPtr = wasm.pg_alloc(input.length);
  new Uint8Array(wasm.memory.buffer, inPtr, input.length).set(input);
  const outPtr = wasm.pg_call(inPtr, input.length);
  const len = new DataView(wasm.memory.buffer).getUint32(outPtr, true);
  const text = dec.decode(new Uint8Array(wasm.memory.buffer, outPtr + 4, len));
  wasm.pg_free(outPtr, 4 + len);
  wasm.pg_free(inPtr, input.length);
  return JSON.parse(text) as T;
}

/** 32 fresh random bytes as hex, from the browser's CSPRNG. */
export function seed(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return hex(b);
}

export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function short(h: string): string {
  const m = /^([a-z]+_)?([0-9a-f]+)$/.exec(h);
  if (m && m[2].length > 16) return `${m[1] ?? ""}${m[2].slice(0, 8)}…${m[2].slice(-6)}`;
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-6)}` : h;
}

export function tari(micro: number | string): string {
  const v = typeof micro === "string" ? Number(micro) : micro;
  return `${(v / 1_000_000).toLocaleString("en-US", { maximumFractionDigits: 6 })} tTARI`;
}

export type Keys = { secret: string; public: string };

export function keygen(): Keys {
  const r = call<Reply & Keys>({ op: "keygen", seed: seed() });
  if (!r.ok) throw new Error(r.error);
  return { secret: r.secret, public: r.public };
}

export type RoundView = {
  joined: number;
  size: number;
  claims: number;
  refunds: number;
  sealed: boolean;
  vault: number;
  payout: number;
  members: string[];
  spent_tags: string[];
  tag_base: string;
  solvent: boolean;
  outstanding: number;
};

export type DemoOutput = { nonce: string; owner_key: string; commitment: string; ciphertext: string };
