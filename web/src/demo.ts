// A Poltergift round played entirely in the browser.
//
// Every rule check, signature and key image comes from poltergift.wasm: the Rust round model that CI
// replays against the real template in the official Tari engine (template/tests/equivalence.rs).
// What is simulated here is only the chain around it: the epoch clock, the fee the network charges,
// and the stealth output encoding (a readable demo version; the native client builds real Tari
// stealth outputs).

import { call, keygen, seed, type DemoOutput, type Keys, type Reply, type RoundView } from "./pg";

export const GIFT = 5_000_000;
export const CLAIM_FEE = 50_000;
/** A typical fee a 5-member claim is charged on the network fee table (measured: 17.7k µT for 4, 23.5k µT for 8). */
export const CHARGED = 19_500;
export const JOIN_DEADLINE = 10;
export const CLAIM_DEADLINE = 20;

export type Ghost = {
  name: string;
  member: Keys;
  view: Keys;
  spend: Keys;
  joined: boolean;
  claimed: boolean;
  tag?: string;
  output?: DemoOutput;
};

export type Deposit = { member: string; amount: number };
export type Payout = { tag: string; output: DemoOutput; message: string };
export type Outcome = { ok: boolean; message: string };

type StateReply = Reply & { state: unknown; view: RoundView };

const NAMES = ["Boo", "Wisp", "Shade", "Murk", "Haunt", "Gloom", "Shiver", "Mist"];

export class DemoRound {
  readonly roundId = seed();
  readonly ghosts: Ghost[];
  state: unknown = null;
  view: RoundView | null = null;
  deposits: Deposit[] = [];
  payouts: Payout[] = [];
  now = 1;
  feesCharged = 0;
  private emptyState: unknown = null;
  private sealedState: unknown = null;

  constructor(readonly size = 5) {
    this.ghosts = Array.from({ length: size }, (_, i) => ({
      name: NAMES[i % NAMES.length],
      member: keygen(),
      view: keygen(),
      spend: keygen(),
      joined: false,
      claimed: false,
    }));
  }

  private apply(r: StateReply): Outcome {
    if (!r.ok) return { ok: false, message: r.error ?? "rejected" };
    this.state = r.state;
    this.view = r.view;
    return { ok: true, message: "accepted" };
  }

  create(): Outcome {
    const r = call<StateReply>({
      op: "create",
      round_id: this.roundId,
      now: this.now,
      params: {
        gift_amount: GIFT,
        size: this.size,
        join_deadline: JOIN_DEADLINE,
        claim_deadline: CLAIM_DEADLINE,
        claim_fee: CLAIM_FEE,
      },
    });
    const out = this.apply(r);
    this.emptyState = this.state;
    return out;
  }

  join(i: number): Outcome {
    const g = this.ghosts[i];
    const out = this.apply(
      call<StateReply>({
        op: "join",
        state: this.state,
        now: this.now,
        member: g.member.public,
        pop_secret: g.member.secret,
        gift: GIFT,
        seed: seed(),
      }),
    );
    if (out.ok) {
      g.joined = true;
      this.deposits.push({ member: g.member.public, amount: GIFT });
      if (this.view?.sealed) this.sealedState = this.state;
    }
    return out;
  }

  private payoutFor(g: Ghost): { output: DemoOutput; message: string } {
    const p = call<Reply & { output: DemoOutput; message: string }>({
      op: "payout",
      view_public: g.view.public,
      spend_public: g.spend.public,
      amount: GIFT - CLAIM_FEE,
      seed: seed(),
    });
    return { output: p.output, message: p.message };
  }

  private sign(roundId: string, ring: string[], index: number, secret: string, message: string) {
    return call<Reply & { key_image: string; signature: string }>({
      op: "sign_claim",
      round_id: roundId,
      ring,
      index,
      secret,
      message,
      seed: seed(),
    });
  }

  private submitClaim(state: unknown, keyImage: string, signature: string, message: string): StateReply {
    return call<StateReply>({
      op: "claim",
      state,
      now: this.now,
      key_image: keyImage,
      signature,
      message,
      fee_charged: CHARGED,
    });
  }

  ring(): string[] {
    return this.ghosts.map((g) => g.member.public);
  }

  claim(i: number): Outcome {
    const g = this.ghosts[i];
    const { output, message } = this.payoutFor(g);
    const s = this.sign(this.roundId, this.ring(), i, g.member.secret, message);
    const out = this.apply(this.submitClaim(this.state, s.key_image, s.signature, message));
    if (out.ok) {
      g.claimed = true;
      g.tag = s.key_image;
      g.output = output;
      this.feesCharged += CHARGED;
      this.payouts.push({ tag: s.key_image, output, message });
    }
    return out;
  }

  /** Tries to open every payout with ghost `i`'s wallet: only its own gift opens. */
  openAll(i: number): (number | null)[] {
    const g = this.ghosts[i];
    return this.payouts.map(
      (p) =>
        call<Reply & { amount: number | null }>({
          op: "open",
          view_secret: g.view.secret,
          spend_public: g.spend.public,
          output: p.output,
        }).amount,
    );
  }

  keyImageOf(i: number): string {
    return call<Reply & { key_image: string }>({
      op: "key_image",
      round_id: this.roundId,
      secret: this.ghosts[i].member.secret,
    }).key_image;
  }

  // -------------------------------------------------------------------------------------------
  // Attack lab: each attempt runs against a copy of the round, so nothing here changes the game.
  // -------------------------------------------------------------------------------------------

  private rejectOf(r: Reply): Outcome {
    return r.ok ? { ok: true, message: "accepted (this should never happen)" } : { ok: false, message: r.error ?? "rejected" };
  }

  attackDoubleClaim(): Outcome {
    let state = this.state;
    let idx = this.ghosts.findIndex((g) => g.claimed);
    if (idx < 0) {
      idx = 0;
      const g = this.ghosts[0];
      const { message } = this.payoutFor(g);
      const s = this.sign(this.roundId, this.ring(), 0, g.member.secret, message);
      const first = this.submitClaim(this.sealedState, s.key_image, s.signature, message);
      state = first.state;
    }
    const g = this.ghosts[idx];
    const { message } = this.payoutFor(g);
    const s = this.sign(this.roundId, this.ring(), idx, g.member.secret, message);
    return this.rejectOf(this.submitClaim(state, s.key_image, s.signature, message));
  }

  attackOutsider(): Outcome {
    const outsider = keygen();
    const fake = this.ring();
    fake[0] = outsider.public;
    const { message } = this.payoutFor(this.ghosts[0]);
    const s = this.sign(this.roundId, fake, 0, outsider.secret, message);
    return this.rejectOf(this.submitClaim(this.sealedState, s.key_image, s.signature, message));
  }

  attackRedirect(): Outcome {
    const g = this.ghosts[0];
    const honest = this.payoutFor(g);
    const thief = this.payoutFor({ ...g, view: keygen(), spend: keygen() });
    const s = this.sign(this.roundId, this.ring(), 0, g.member.secret, honest.message);
    return this.rejectOf(this.submitClaim(this.sealedState, s.key_image, s.signature, thief.message));
  }

  attackReplay(): Outcome {
    const g = this.ghosts[1];
    const { message } = this.payoutFor(g);
    const s = this.sign(seed(), this.ring(), 1, g.member.secret, message);
    return this.rejectOf(this.submitClaim(this.sealedState, s.key_image, s.signature, message));
  }

  attackWrongGift(): Outcome {
    const k = keygen();
    return this.rejectOf(
      call({ op: "join", state: this.emptyState, now: this.now, member: k.public, pop_secret: k.secret, gift: GIFT - 100_000, seed: seed() }),
    );
  }

  attackKeyTheft(): Outcome {
    const victim = this.ghosts[0].member;
    const thief = keygen();
    return this.rejectOf(
      call({ op: "join", state: this.emptyState, now: this.now, member: victim.public, pop_secret: thief.secret, gift: GIFT, seed: seed() }),
    );
  }

  attackEarlyRefund(): Outcome {
    const g = this.ghosts[2];
    const { message } = this.payoutFor(g);
    const s = call<Reply & { key_image: string; proof: string }>({
      op: "sign_refund",
      round_id: this.roundId,
      secret: g.member.secret,
      message,
      seed: seed(),
    });
    return this.rejectOf(
      call({ op: "refund", state: this.sealedState, now: this.now, member: g.member.public, key_image: s.key_image, proof: s.proof, message, fee_charged: 0 }),
    );
  }
}
