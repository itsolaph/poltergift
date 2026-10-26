<p align="center"><img src="assets/card.svg" alt="Poltergift: a secret gift exchange on the Tari Ootle" width="100%"/></p>

# Poltergift

**A secret gift exchange on the Tari Ootle where nobody, not even the chain, knows who gave what to
whom.** A group joins a *haunted round*: each ghost drops one equal gift of tTARI under a fresh
member key, ideally paid from a stealth coin. When the round is full the gifts are *possessed*. Each
member then claims one gift into a brand-new stealth output, proving on chain only "I am one of
the members of this round" with a linkable ring signature, plus a one-time tag that stops a
second claim. The claim is sealed by a throwaway key and its fee is paid by the round itself. An
observer sees N equal deposits in and N unlinkable stealth payouts out, and each recipient can open
only their own gift. If a round never fills, or a ghost vanishes, deadlines let depositors take
their gift back.

**▶ Browser demo (no wallet, under 2 minutes):** <https://itsolaph.github.io/poltergift/>
(or run it locally, see [Quick start](#quick-start)) · **Live rounds:** [deployment table](#live-on-esmeralda) ·
**Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md) · **Design notes:** [NOTES.md](NOTES.md)

## Two-minute tour

1. Open the [browser demo](https://itsolaph.github.io/poltergift/) and press **Summon 5 Ghosts**
   (about 15 seconds). Five ghosts open a round, drop gifts, seal it and claim in random order.
2. Look at the three panels: the **Observer** list of deposits and claims has nothing that pairs
   them, the **Recipient** panel opens only the selected ghost's own gift, and the **Auditor**
   totals balance.
3. Click every button in the **Attack lab**: double claim, outsider, redirected payout, replay from
   another round, early refund, wrong gift, key theft. Each is refused with the template's own
   message.
4. Open **Live on Esmeralda**: the same thing on the real testnet, read straight from the public
   indexer, with every transaction linked to the explorer.

<p align="center"><img src="assets/demo.png" alt="The browser demo after a full round: ghosts, observer/recipient/auditor views and the attack lab" width="90%"/></p>

## How it works (30 seconds)

<p align="center"><img src="web/public/how-it-works.svg" alt="Equal gifts in under N member keys, one sealed ring, one-time tags, unlinkable stealth payouts out" width="90%"/></p>

```
 join ×N          P_i + PoP + exactly g TARI ─┐
 (public)                                    ▼
                         ┌────────────── round component ──────────────┐
                         │ vault (revealed)   ring {P_1..P_N}  tag base H │
                         │ spent tags {I}     deadlines (epochs)          │
                         └───────────────────────┬──────────────────────┘
 claim ×N   LSAG over the ring + tag I = x·H     │  fee intent, throwaway signer,
 (anonymous)  signs the exact payout statement   ▼  fee paid by the vault
                         one fresh stealth output: one-time owner key, amount hidden
```

1. **Join**: a fresh member key `P = x·G` per round, a Schnorr proof of possession bound to the
   round, and exactly the gift amount in TARI. The `N`-th join seals the ring.
2. **Claim**: an LSAG ring signature (Liu–Wei–Wong, per-round generator `H`, bLSAG layout) over
   Ristretto255, verified inside the template with the engine's native intrinsics. The key image
   `I = x·H` is the one-time tag. The signature also signs the CBOR of the payout statement, so the
   payout cannot be redirected.
3. **Payout**: exactly `gift − claim_fee` into a single new stealth output. The claim runs in the
   fee intent, the round vault pays the fee, and a throwaway key seals the transaction: nothing in
   it points at a member or an account.
4. **Refund**: after the join deadline (round never filled) or the claim deadline (round sealed), a
   DLEQ proof (a ring signature with a ring of one) shows `P = x·G` and `I = x·H`. A member whose tag
   is already spent cannot also refund.

## Quick start

Requirements: Rust (stable, with `rustup target add wasm32-unknown-unknown`) and Node 20+.

**Browser demo**

```bash
cd web
npm ci
npm run build        # compiles poltergift.wasm from crates/wasm and bundles the site into web/dist
npm run serve        # http://127.0.0.1:8000  (any static file server works)
```

Press **Summon 5 Ghosts**: five ghosts create, join, seal and claim a round in your browser in about
15 seconds, using the same Rust ring-signature code and the same round rules as the template (the
model is replayed against the real template in CI). Then try the three views, the attack lab and the
**Live on Esmeralda** tab, which reads the real rounds from the public indexer.

**Tests**

```bash
cargo test --workspace                      # ring crate, model, client, CLI, WASM engine
cd template && cargo test --release         # template in the official Tari engine (attacks, fees, equivalence)
cd web && npm test                          # browser engine smoke test (after npm run build)
```

**Reproduce the live check**

```bash
cargo run -p poltergift-cli --example live_esmeralda -- deployments/esmeralda.json
```

It reads every recorded round from the public Esmeralda indexer through the ootle-rs light client
and checks that the ring and tags match, that no payout transaction is signed by a member key, a
join signer or another payout's signer, and that payout outputs carry no amount.

## CLI

```bash
cargo build --release -p poltergift-cli        # → target/release/poltergift
P=target/release/poltergift

$P init                                         # wallet in ./.poltergift (secret: keep it out of git)
$P balance
$P publish --wasm template.min.wasm             # once per network (see "Build the template")
$P round create --template template_… --gift 5 --size 5 --join-epochs 3 --claim-epochs 8
$P round join component_… --from-utxo COMMITMENT:VALUE   # gift from a stealth coin: no account in the tx
$P round join component_…                       # or from the account (links the account to the round)
$P round status component_…
$P round claim component_…                      # anonymous claim to a fresh stealth output of this wallet
$P round refund component_…                     # after the relevant deadline
$P inspect component_… --as-member DIR …        # observer view, plus which payout each member key opens
$P scan                                          # find and open this wallet's stealth outputs
$P bots --template template_… --size 5          # a whole round with freshly generated bot wallets
```

Global flags: `--network esmeralda|localnet`, `--indexer URL`, `--data-dir DIR`, `--record FILE`
(appends public facts such as addresses, transaction ids and tags to a JSON record, never secrets) and
`--trust-indexer` (skip proof verification; for a quiet local network only).

**Build the template**

```bash
cd template
cargo build --target wasm32-unknown-unknown --release
npx -p binaryen wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int \
  --enable-mutable-globals --strip-debug --strip-producers --strip-target-features \
  target/wasm32-unknown-unknown/release/poltergift_template.wasm -o template.min.wasm
```

## Live on Esmeralda

LIVE_TABLE_PLACEHOLDER

## Threat model: what is hidden, what still leaks

Hidden: which member received which payout (deciding it is a DDH problem in `(G, H, P_i, I)`); who
signed a claim (a throwaway key, fee paid by the vault); who owns a payout and its value (a Tari
stealth output); and, with `--from-utxo`, which account paid a gift.

Still visible, by design or as a limit:

* **membership**: the N member keys are public (fresh per round; paying from an account links it);
* **amounts**: equal by design, so every payout spends the same public `gift − fee`;
* **timing**: claims are ordered in time, so claim at a random moment;
* **refunds**: a refund shows that this member did not claim;
* **Sybil / n−1**: the anonymity set only counts honest, distinct members;
* **funding graph**: what you do with the payout afterwards is up to you.

The full list, with 41 money-safety threats each mapped to a named test, is in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Tests

TESTS_PLACEHOLDER

## Costs

Measured in the official engine on the Esmeralda fee table (`template/tests/fees.rs`):

| ring size | claim fee charged | native points |
|---|---|---|
| 4 | 17,651 µT (0.018 tTARI) | 14.2M |
| 8 | 23,480 µT (0.023 tTARI) | 19.6M |
| 16 | 35,135 µT (0.035 tTARI) | 30.5M |

About 1.36M points per ring member (two 2-term multi-scalar multiplications and one SHA-512) on top
of the stealth-output verification. The template binary is 204 KB after `wasm-opt -Oz`; publishing
it on localnet cost 2.2 tTARI.

## Repository layout

| path | what |
|---|---|
| `template/` | the on-chain round template (Rust → WASM) and its engine tests |
| `crates/ring` | LSAG ring signatures, proof of possession, per-round tag base (curve25519-dalek) |
| `crates/model` | the template's rules as plain Rust, used by the browser and checked against the template |
| `crates/client` | wallet store, round state decoding, all round transactions (ootle-rs), output scanning |
| `crates/cli` | the `poltergift` CLI and `examples/live_esmeralda.rs` |
| `crates/wasm` | browser engine: ring + model compiled to WASM with a JSON C ABI |
| `web/` | the static browser demo (vanilla TypeScript, esbuild) |
| `deployments/` | public record of the live Esmeralda deployment |

## Credits

Built only from official Tari material, credited here with licenses:

* [tari-project/tari-ootle](https://github.com/tari-project/tari-ootle) (BSD-3-Clause): crates
  `tari_template_lib`, `tari_template_lib_types`, `tari_template_test_tooling`, `tari_ootle_transaction`,
  `tari_ootle_common_types`, `tari_engine` (via the test tooling), `tari_bor`, `ootle-rs`,
  `tari_ootle_wallet_crypto`, `ootle_byte_type`; the release binaries (`tari_swarm_daemon`,
  validator node, indexer, wallet daemon) used for local rehearsal; the developer docs at
  [ootle.tari.com](https://ootle.tari.com) (stealth resources, privacy, templates, testing, fees).
* [tari-project/tari-crypto](https://github.com/tari-project/tari-crypto) (BSD-3-Clause).
* [tari-project/tari](https://github.com/tari-project/tari) (BSD-3-Clause): the Esmeralda base node,
  console wallet and miner used to obtain tTARI through burn-and-claim, and the gRPC protos.
* The Esmeralda public indexers and the Veil explorer at <https://explorer.tari.mw>.

Third-party libraries: curve25519-dalek (BSD-3-Clause), RustCrypto `sha2` and `blake2` (MIT/Apache-2.0),
`rand_chacha`/`rand_core` (MIT/Apache-2.0), serde/serde_json (MIT/Apache-2.0), clap (MIT/Apache-2.0),
tokio (MIT), proptest (MIT/Apache-2.0), esbuild (MIT), TypeScript (Apache-2.0), binaryen (Apache-2.0).

The linkable ring signature follows J. K. Liu, V. K. Wei and D. S. Wong, *Linkable Spontaneous
Anonymous Group Signature for Ad Hoc Groups* (ACISP 2004).

## License

MIT. See [LICENSE](LICENSE).
