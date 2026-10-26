# Poltergift design notes (Phase 0)

Status: recon done 2026-10-25. Numbers marked *estimate* are replaced by measured values in
"Measured costs" once the template tests run.

## 1. What the platform gives us (verified in the official sources)

Pinned crates (crates.io, published 2026-10-19):

| crate | version | used by |
|---|---|---|
| `tari_template_lib` | 0.35 | template |
| `tari_template_test_tooling` | 0.47 | template tests |
| `tari_template_lib_types` | 0.35 | client |
| `tari_ootle_transaction` | 0.47 | client |
| `ootle-rs` | 0.29 | client / CLI |
| `tari_bor` | 0.16 | client + template (CBOR encoding of statements) |

Template crypto (`tari_template_lib::intrinsics`, native, metered in "native points"):

* Ristretto: `add`, `sub`, `negate`, `mul`, `mul_base`, `msm`, `is_identity`, `is_canonical`.
* Scalars: `add`, `sub`, `mul`, `negate`, `invert`, `from_uniform_bytes` (64-byte wide reduction),
  `is_canonical`.
* Hashes: Blake2b-256, SHA-256, Keccak-256, SHA-512 (multi-part, one engine call).
* `schnorr_verify_with_domain` (Tari Schnorr).
* No hash-to-point intrinsic. A pure-Rust curve crate would compile to WASM, but every group
  operation would then be metered as WASM instructions; intrinsics are far cheaper, so the
  template uses intrinsics only and never links a curve library.

Prices (`tari_engine_types::limits::NativeExecutionPoints`): MSM 100k + 250k per term, `mul`
550k, `mul_base` 300k, point op 50k, scalar op 3k, hash 10k + 30/byte, engine call 10k.
Fee intent runs on a free compute grace of 32M points before `pay_fee`.

Stealth funds in templates:

* A transaction turns stealth UTXOs into a revealed `Bucket` with a `StealthTransfer` instruction
  (revealed output, receiver = a signer of the transaction). That bucket can be passed to any
  component method. The signer can be the stealth input's one-time key, so no account is involved.
* A template pays out to a fresh stealth output with
  `ResourceManager::stealth_transfer_with_opt_input_bucket(statement, Some(bucket))`, where the
  statement's revealed input equals the bucket amount and its single output is a Pedersen
  commitment with hidden amount, a one-time key, and encrypted data only the recipient opens.
* A component vault holding TARI can pay the transaction fee: `Vault::pay_fee(amount)`. It is only
  allowed inside the **fee intent** (`FeePaymentInMainIntent` otherwise). If anything in the fee
  intent panics, the whole transaction is rejected and nothing is charged or written. Unused fee
  is refunded to the paying vault. The fee intent may contain at most one stealth transfer.

Testnet (Esmeralda): indexer `https://esme-indexer-a.ootle.tari.com/` (REST, reachable), explorer
`https://explorer.tari.mw`. Ootle epoch = 80 L1 blocks, L1 block ≈ 30 s, so an epoch ≈ 40 min.
The built-in faucet is dry: `take()` hands out a fixed 1000 tTARI and the vault holds 999.65, so
every claim fails with `InsufficientFunds` (checked with a dry run). Fallback in use: CPU-mine
Esmeralda L1 (RandomXT, `minotari_miner`) to a console wallet, burn to the Ootle claim key, claim
on the Ootle. Node, wallet and miner live under `./.chain/l1/` (gitignored); keys under `./.secrets/`.

## 2. Chosen design

### Roles and flow

```
 create(params)          join x N                     seal (automatic, N-th join)
 ───────────────►  [ open ] ─────────────────────────►  [ sealed ]
                     │  member key P_i + PoP              │ claim: LSAG over ring {P_1..P_N}
                     │  + gift bucket (exactly g)         │        + key image I (one-time tag)
                     │                                    │        + payout statement (1 stealth out)
                     ▼ epoch >= join_deadline             ▼ epoch >= claim_deadline
                  refund (DLEQ: I = x·H, P = x·G,     refund for members whose I is unspent
                          bound to payout)
```

* `create(gift_amount, size, join_deadline, claim_deadline, claim_fee)`: anyone. The component has
  `OwnerRule::None`, so nobody can change its rules or take funds out except through the methods.
* `join(member_key, pop, gift)`: `gift` must be exactly `gift_amount` revealed TARI. `member_key`
  must be canonical, not the identity and not already in the ring. `pop` is a Schnorr proof of
  possession of `member_key`, bound to the round id, so nobody can register a key they do not own
  or replay a key from another round. The N-th join seals the round and stores the ring hash.
* `claim(key_image, signature, payout)`: only while sealed and before `claim_deadline`. Runs entirely
  in the fee intent: pays `claim_fee` from the round vault, verifies the LSAG, checks and records
  the key image, then sends `gift_amount - claim_fee` to the single stealth output in `payout`.
  The transaction is signed by a throwaway key, so no account or member key ever appears.
* `refund(member_key, key_image, proof, payout)`: after `join_deadline` if the round never filled,
  or after `claim_deadline` if it did. `proof` is a DLEQ proof (a ring signature with a ring of one)
  that `member_key = x·G` and `key_image = x·H`, so a member who already claimed (their key image
  is spent) cannot also refund. It records the key image and marks the member refunded.

### Crypto

* Group: Ristretto255, base point `G`.
* Per-round tag base `H = HashToPoint("poltergift/v1/tag-base", round_id)` by try-and-increment:
  `b = Blake2b-256(dst ‖ round_id ‖ ctr_le32)`, take the first `b` that is a canonical Ristretto
  encoding of a non-identity point. Each group element has exactly one canonical encoding, so the
  result is a uniformly random point with unknown discrete log. The template computes it once in
  `create` with `ristretto_is_canonical`, and the client computes the identical value with
  curve25519-dalek (the engine decodes points with the same library). `round_id` is the
  component address, allocated up front in `create`.
* Claim signature: linkable ring signature of Liu–Wei–Wong (2004) with the per-round generator `H`
  (their `h = H2(L)`), in the bLSAG layout: `σ = (c_0, s_0..s_{N-1})`, key image `I = x_π·H`.
  `c_{i+1} = Hs(prefix ‖ s_i·G + c_i·P_i ‖ s_i·H + c_i·I)` with
  `prefix = dst_claim ‖ round_id ‖ ring_hash ‖ I ‖ msg`, `Hs = scalar_from_uniform(SHA-512(...))`.
  Accept iff the chain closes (`c_N = c_0`), all scalars are canonical and `I` is canonical and
  not the identity. `msg = Blake2b-256(dst_msg ‖ cbor(payout statement))`, so the signature
  commits to the exact payout output, its range proof and balance proof: a relayer or front-runner
  cannot redirect the gift.
* Linkability: the same key always gives the same `I` in a round, so double claims hit the spent
  set. Anonymity: deciding whether `I` belongs to `P_i` is a DDH instance in `(G, H, P_i, I)`.
  Key images from different rounds use different `H`, so they cannot be linked across rounds and
  a signature from one round never verifies in another (round id is also in the prefix).
* Verification cost in the template: per ring member, two 2-term MSMs and one SHA-512.
  Measured: ≈1.36M native points per member on top of a fixed ≈8.7M (see "Measured costs").
  Maximum ring size: 16.

Alternatives considered:

* Blind-signature tickets: they need an online issuer that must not collude with the chain
  observer, which weakens "not even the chain knows". Rejected.
* Hash-set membership plus nullifier (a zk-SNARK, Semaphore style): needs a proving system that is
  not available as an intrinsic. Rejected.
* bLSAG with `Hp(P_i)` per member: needs N hash-to-point operations per verification (no
  intrinsic); the per-round `H` gives the same guarantees at a fraction of the cost.

### Protocol messages (all CBOR via the transaction args)

| call | args | checked |
|---|---|---|
| `create` | `gift_amount: Amount, size: u32, join_deadline: u64, claim_deadline: u64, claim_fee: Amount` | `2 <= size <= 16`, `0 < claim_fee < gift_amount`, `now < join_deadline < claim_deadline`, no overflow in `size·gift_amount` |
| `join` | `member: RistrettoPublicKeyBytes, pop: SchnorrProof, gift: Bucket` | open, before deadline, TARI, exact amount, no confidential part, canonical/non-identity, unique, PoP valid |
| `claim` | `key_image, sig: RingSignature, payout: StealthTransferStatement` | sealed, before claim deadline, image unspent, payout shape (no stealth inputs, no revealed output, exactly 1 output, revealed input = g − fee), LSAG valid |
| `refund` | `member, key_image, proof: RingSignature (ring of 1), payout` | deadline passed for the state, member present and not refunded, image unspent, proof valid |

Events carry no amounts and no identities: `Joined {count}`, `Sealed`, `Claimed {count}`,
`Refunded {count}`.

## 3. What leaks (honest threat model, summarised; full version in THREAT_MODEL.md)

Hidden: which member received which payout; the payout owner (one-time stealth key); the payout
amount in the output commitment (though it is implied, see below); the link between a payout and
the member's account.

Still visible:

* **Membership**: the N member keys are public. If a member pays the gift from an account (not a
  stealth coin), the join transaction links that account to the round. Use stealth inputs.
* **Amounts**: gifts are equal and the vault is a revealed vault, so `gift_amount` and
  `claim_fee` are public, and every payout's revealed input equals `g − fee`. Equal amounts are
  the point: they make payouts indistinguishable.
* **Timing**: claims are ordered in time. A member who claims right after joining, or the only
  member online at some hour, narrows the set. Clients should wait and claim at random times.
* **Graph**: the payout UTXO is fresh, but whatever the recipient does next with it (merging with
  other coins) is outside this protocol.
* **Fees**: every claim pays the same fixed `claim_fee` from the vault, so fees do not fingerprint
  claimants. A claim transaction's signer is a throwaway key.
* **Self-gift**: gifts are fungible (same amount from one vault), so there is no "own gift"; a
  member always receives exactly one gift of the same size. The probability of getting your own
  coins is meaningless here because the vault mixes them; in a slot-assignment model it would
  be 1/N.
* **Refunds**: a refund reveals the refunder's key image, telling the world that this member did
  not claim, so the claims were made by the remaining members (smaller anonymity set,
  retroactively).
* **Sybil / n−1**: an attacker who controls N−1 of the keys learns the honest member's payout.
  The anonymity set only counts honest, distinct members.
* **Dust**: unused fee is refunded into the vault, so a finished round can keep a few µT of dust.

## 4. Whispers (sealed notes): dropped

A whisper must be readable only by whoever claims that gift. But the claimant is anonymous and
unknown when the gift is deposited, and the only data available at claim time is public chain data.
So the depositor would have to encrypt to a key that does not exist yet. The sound options are:
(a) the giver comes back after the claim and re-encrypts to a key the claimant put in the claim,
which needs a second, also anonymous, transaction from every giver and a liveness assumption;
(b) a trusted re-encryption party, which breaks the "not even the chain knows" story; or
(c) witness encryption, which is not practical. The payout's encrypted memo field is written by
the claimant (who builds the output), so it cannot carry the giver's note either. Poltergift
ships without whispers rather than with a weak version.

## 5. Auditor view

TARI on Esmeralda has no resource view key, and the round vault is a revealed vault. Totals are
therefore public to everyone, and the "auditor" view needs no special key: deposits = N·g, vault
balance + claims·g + refunds·g = N·g. The optional auditor key from the brief is dropped (it would
add a parameter that grants nothing). The web demo's Auditor panel shows exactly these totals,
derived from public state.

## 6. Plan (deadline: code complete 2026-10-30 12:00 UTC)

* **Oct 25**: recon (done), L1 node sync and wallet set up, ring crate with property tests,
  template skeleton.
* **Oct 26**: template complete; happy paths N=3/5/8; 30+ named attack tests; conservation
  property test; measured fees for N=4/8/16. Start mining as soon as the node is synced.
* **Oct 27**: client crate and CLI; burn and claim tTARI; publish the template on Esmeralda; play
  the N=5 bot round and a second round; `deployments/esmeralda.json`; `examples/live_esmeralda`.
* **Oct 28**: WASM build of client crypto + round model; web demo (Summon 5 Ghosts, three views,
  live screen with recorded fallback); model-vs-template equivalence test.
* **Oct 29**: README, THREAT_MODEL.md, SUBMISSION.md, SVG card, CI workflow, polish.
* **Oct 30 (morning)**: buffer, final test run, PROGRESS.md summary.

## Measured costs

From `template/tests/fees.rs` (official engine, Esmeralda fee table, one claim with fees on):

| ring size | fee charged | native points | WASM points |
|---|---|---|---|
| 4 | 17,651 µT (0.018 tTARI) | 14.18M | 0.27M |
| 8 | 23,480 µT (0.023 tTARI) | 19.61M | 0.44M |
| 16 | 35,135 µT (0.035 tTARI) | 30.46M | 0.77M |

Fixed part ≈ 8.7M points (verifying the payout's stealth output and statement), plus ≈1.36M per
ring member (two 2-term MSMs and one SHA-512 each). The claim pays its fee before verifying, so
the free fee-intent grace (32M) is not the binding limit. Measured with `claim_fee = 1 tTARI`, the
vault paid out exactly `payout + fee charged` and got the rest back. The CLI therefore defaults
`claim_fee` to 0.05 tTARI for rings up to 16.

## Lessons from the live run (2026-10-26)

* **Funding without a faucet.** CPU RandomXT mining runs in light mode (~40 H/s here), so SHA3x did
  most of the work; Esmeralda is multi-algorithm with a separate difficulty per algorithm, so mining
  both at once adds blocks rather than competing. Coinbase maturity is 6 blocks.
* **Burn claims wait for epochs.** The Ootle reads L1 about 100 blocks behind tip (80 blocks per
  epoch), and a burn is claimable only once the Ootle epoch is past the burn's L1 epoch. On a quiet
  testnet that means mining roughly 150–200 L1 blocks after the burn.
* **Burn proof format.** The console wallet writes the L1 view of the burn (hash preimage with borsh
  output features); `crates/client/src/burn_proof.rs` converts it the way the official wallet daemon
  does.
* **Fees.** Dry runs can under-report execution points for intrinsic-heavy calls, and the compute
  allowance is bought by the fee carried, so the client carries twice the measured need on
  account-paid transactions (the unused part is refunded).
* **Light client.** Verified reads work on Esmeralda; right after an epoch change the indexer may
  briefly lack the handover checkpoint, which the client retries.
