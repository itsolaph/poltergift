# Poltergift: forum submission draft

**1. Code:** https://github.com/itsolaph/poltergift

**2. Description**

> **Poltergift: a secret gift exchange on the Tari Ootle where nobody, not even the chain, knows who
> gave what to whom.**
>
> A group joins a *haunted round*. Each ghost drops one equal gift of tTARI under a fresh member key,
> ideally paid from a stealth coin so no account appears. When the round is full it is sealed, and
> each member claims one gift into a brand-new stealth output. The claim proves only "I am one of the
> members" with a linkable ring signature (LSAG over Ristretto255, verified on chain with the
> engine's native intrinsics), plus a one-time tag that stops a second claim. The signature commits to
> the exact payout, the claim is sealed by a throwaway key, and its fee is paid by the round vault, so
> the claim transaction points at nobody. On the explorer you see N equal deposits in and N unlinkable
> stealth payouts out; each recipient can open only their own gift. Deadlines let depositors take
> their gift back if a round never fills or a member vanishes, and a DLEQ proof stops anyone from
> both claiming and refunding.
>
> * **Live on Esmeralda:** the template and four real rounds: a 5-ghost round played by bot wallets
>   with stealth-funded joins and anonymous claims, a 3-ghost round, a round that never filled (both
>   members refunded after the join deadline), and a round where one member vanished and refunded
>   after the claim deadline, while the deployed template refused the early refund, the refund by the
>   member who had already claimed, and the late claim. Every address and transaction is linked in the
>   README, and `examples/live_esmeralda.rs` re-checks the privacy claims against the public indexer
>   (all checks pass). The faucet was empty, so the tTARI came from CPU-mining Esmeralda L1 and
>   burning to the Ootle.
> * **Browser demo, no wallet, under 2 minutes:** https://itsolaph.github.io/poltergift/ :
>   "Summon 5 Ghosts" plays a full round in your browser with the same Rust code compiled to WASM.
>   It has Observer / Recipient / Auditor views, an attack lab, and a live view of the Esmeralda rounds.
> * **Tested hard:** 56 named attack tests in the official Tari engine (double claims, forgeries,
>   scalar malleability, cross-round replay, redirected payouts, ring tampering, refund theft, fake
>   tokens, key theft, deadline abuse, …). There is also a property test that replays random operation
>   sequences against the template and the browser model and checks equivalence, solvency and
>   conservation after every step.
> * **Honest threat model:** THREAT_MODEL.md maps every threat to its test and lists what still leaks
>   (membership, timing, refunds, Sybil/n−1, equal amounts by design).
>
> Built only on official Tari crates (tari_template_lib 0.35, test tooling 0.47, ootle-rs 0.29). MIT
> licensed.

**3. Tari address for the prize:** `12LTDpm29efd7BANafTLWfuHWujrVw4nnuhAPVJcnwEh3GBqC7rxFMsbKYxSg5wo6ozPWHusDcnxyjFqFsf7q4RPuB9`

**4. Social post:** SOCIAL_POST_PLACEHOLDER
