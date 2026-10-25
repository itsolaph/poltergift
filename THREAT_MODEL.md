# Poltergift threat model

Poltergift promises two things:

1. **Money safety.** Each member puts in exactly one gift and can take out exactly one gift (by
   claim, or by refund after a deadline). Nobody else can take anything out. The vault can always
   pay every gift still owed.
2. **Unlinkability.** Nobody (an observer, the indexer, validators, other members, or the round
   creator) can tell which member received which payout, beyond what the anonymity set and the
   leaks listed below allow.

Everything below refers to `template/src/lib.rs` (the on-chain rules), `template/src/crypto.rs`
(on-chain verification) and `crates/ring` (the signing side). Test names are in
`template/tests/attacks.rs` unless another file is named. Every attack test asserts the exact reason
the template gives, so a test cannot pass by failing for an unrelated reason.

## Participants and trust

| Party | Trusted for | Not trusted for |
|---|---|---|
| Tari Ootle validators | executing the template correctly and finalizing state | privacy: they see everything an observer sees |
| Indexer | nothing; the client verifies substate proofs with the ootle-rs light client (`IndexerTrust::Verify`) | |
| Round creator | nothing; the component is created with `OwnerRule::None` and allow-all method rules, so the creator has no extra power after `create` | |
| Members | their own funds only | everyone else's |

## Money safety: attacks and the tests that cover them

| # | Attack | Defence | Test(s) |
|---|---|---|---|
| 1 | Claim twice with the same signature | spent-tag set | `claim_rejects_double_claim_with_the_same_tag` |
| 2 | Claim twice with a fresh signature and fresh payout | the key image `x·H` is deterministic per key and round | `claim_rejects_second_claim_with_fresh_signature_and_payout` |
| 3 | Outsider claims by putting their own key into the ring they sign over | verification uses the ring stored at seal time | `claim_rejects_outsider_who_substitutes_own_key_into_ring` |
| 4 | Forge a signature from random scalars | LSAG unforgeability | `claim_rejects_forged_signature_of_random_scalars`, ring crate `prop_any_single_bit_flip_breaks_signature` |
| 5 | Malleate a valid signature (`s + ℓ`, same value, new bytes) | every scalar must be canonical | `claim_rejects_malleated_signature_with_non_canonical_scalar`, ring crate `rejects_non_canonical_scalar_malleation` |
| 6 | Swap in another member's key image to burn their claim | the key image is inside every challenge hash | `claim_rejects_signature_with_another_members_key_image` |
| 7 | Identity or non-canonical key image | canonical, non-identity check | `claim_rejects_identity_key_image`, `claim_rejects_non_canonical_key_image` |
| 8 | Replay a claim from round A in round B with the **same** ring | round id in every challenge; per-round tag base `H` | `claim_rejects_replay_into_round_with_identical_ring` |
| 9 | Front-run or relay a claim and redirect the payout | the signature signs `Blake2b(cbor(payout statement))` | `claim_rejects_redirected_payout`, `refund_rejects_redirected_payout` |
| 10 | Take more than one gift in a payout | payout must spend exactly `gift − claim_fee` | `claim_rejects_payout_larger_than_gift_minus_fee` |
| 11 | Under-claim (strand funds, skew accounting) | exact amount required | `claim_rejects_payout_smaller_than_gift_minus_fee` |
| 12 | Leak value back out as a revealed bucket | no revealed output allowed | `claim_rejects_payout_with_revealed_output_bucket` |
| 13 | Split the payout into several outputs (fingerprinting) | exactly one stealth output | `claim_rejects_payout_split_into_two_outputs` |
| 14 | Mix extra stealth inputs into the payout statement | no stealth inputs allowed | `claim_rejects_payout_that_spends_extra_stealth_inputs` |
| 15 | Claim before the round is sealed (small anonymity set) | claims need the seal | `claim_rejects_claim_before_round_is_sealed` |
| 16 | Claim after the claim deadline | deadline check | `claim_rejects_claim_after_claim_deadline` |
| 17 | Run the claim outside the fee intent so some other source pays, or so a failing claim still burns vault fees | `Vault::pay_fee` only works in the fee intent; a fee-intent panic rejects the whole transaction and charges nothing | `claim_rejects_call_from_main_intent` |
| 18 | Ring tampering: sign over a shorter ring | signature length must match the stored ring | `claim_rejects_signature_over_a_shorter_ring` |
| 19 | Ring tampering: sign over a reordered ring | ring hash in every challenge | `claim_rejects_signature_over_a_reordered_ring` |
| 20 | Pad the signature with extra scalars | exact length | `claim_rejects_signature_padded_with_extra_scalars` |
| 21 | Use a refund proof as a claim (domain confusion) | separate domain tags | `claim_rejects_refund_proof_presented_as_claim`, ring crate `rejects_wrong_message_round_purpose` |
| 22 | Use a claim signature as a refund proof | separate domain tags | `refund_rejects_claim_domain_signature_as_refund_proof` |
| 23 | Refund before the join deadline of an open round | deadline check | `refund_rejects_open_round_before_join_deadline` |
| 24 | Refund before the claim deadline of a sealed round | deadline check | `refund_rejects_sealed_round_before_claim_deadline` |
| 25 | Claim **and** refund (take two gifts) | refund reveals and spends the member's tag via a DLEQ proof | `refund_rejects_member_who_already_claimed`, `claim_rejects_member_after_their_refund` |
| 26 | Claimed member refunds with a made-up tag | DLEQ pins the tag to `x·H` | `refund_rejects_claimed_member_using_a_made_up_key_image` |
| 27 | Outsider steals a member's refund | DLEQ proof must be by the member key | `refund_rejects_outsider_stealing_a_members_gift` |
| 28 | Non-member asks for a refund | membership check | `refund_rejects_non_member_key` |
| 29 | Member refunds another member's gift | DLEQ proof is for the named key only | `refund_rejects_member_signing_for_another_member` |
| 30 | Double refund | refunded set + spent tag | `refund_rejects_double_refund` |
| 31 | Pay the gift with a different token that calls itself "TARI" | resource address must be TARI | `join_rejects_fake_token_named_tari` |
| 32 | Pay less or more than the gift | exact amount | `join_rejects_gift_below_round_amount`, `join_rejects_gift_above_round_amount` |
| 33 | Join after the deadline | deadline check | `join_rejects_late_join_after_deadline` |
| 34 | Join a sealed round | seal check | `join_rejects_extra_member_after_seal` |
| 35 | Join twice with the same key (ring confusion) | duplicate check | `join_rejects_same_key_twice` |
| 36 | Register the identity or a garbage point as a member key | canonical, non-identity check | `join_rejects_identity_point_as_member_key`, `join_rejects_non_canonical_member_key` |
| 37 | Register someone else's public key (a "donation" that skews the ring) | Schnorr proof of possession bound to the round | `join_rejects_registering_someone_elses_key`, `join_rejects_missing_proof_of_possession` |
| 38 | Replay a proof of possession into another round | round id in the PoP challenge | `join_rejects_proof_of_possession_replayed_from_another_round` |
| 39 | Zero, oversized or overflowing parameters | `create` validation | `create_rejects_round_of_one`, `create_rejects_round_of_zero`, `create_rejects_ring_larger_than_verifier_limit`, `create_rejects_zero_claim_fee`, `create_rejects_fee_that_eats_the_whole_gift`, `create_rejects_zero_gift`, `create_rejects_gift_too_large_for_a_stealth_output`, `create_rejects_join_deadline_in_the_past`, `create_rejects_claim_deadline_not_after_join_deadline` |
| 40 | Any sequence of the above leaves the vault unable to pay, or creates or destroys value | invariants checked after every step of random operation sequences | `equivalence.rs::template_matches_model_and_conserves_value` (128 random sequences), `equivalence.rs::scripted_sequence_covers_every_path` |
| 41 | Creator keeps powers over the round | `OwnerRule::None`; no admin methods exist | by construction; `happy_path.rs` rounds run with no owner proofs |

The browser demo's attack lab replays seven of these against the WASM round model, which
`equivalence.rs` keeps identical to the template.

## Privacy: what is hidden

* **Which member received which payout.** A claim shows a key image `I = x·H` and a ring
  signature over all `N` member keys. Matching `I` to a member `P_i = x_i·G` means deciding whether
  `(G, H, P_i, I)` is a DDH tuple, which is hard in Ristretto255. `H` is fresh per round
  (try-and-increment hash-to-group from the round id), so tags from different rounds are unrelated.
* **Who signed the claim.** The claim transaction is sealed by a throwaway key, and its fee is paid
  by the round vault inside the fee intent, so no account and no member key signs it.
  (`live_esmeralda` checks this on the real network: no payout transaction is signed by a member key,
  a join signer or another payout's signer.)
* **Who owns the payout.** It is a Tari stealth output: a one-time owner key derived by
  Diffie-Hellman with the recipient's view key, the value in a Pedersen commitment, and the value and
  mask encrypted so that only the recipient opens them (`tari_ootle_wallet_crypto`).
* **Join funding (when stealth-funded).** `poltergift round join --from-utxo` turns one of the
  member's stealth outputs into the gift in a transaction sealed by that output's one-time key: an
  observer sees "some stealth coin became a gift", not an account.

## Privacy: what still leaks

* **Membership.** The `N` member keys are public. They are fresh per round, but if a member pays the
  gift from an account (`round join` without `--from-utxo`), that account is linked to the round.
* **Amounts.** Gifts are equal and the vault is revealed, so `gift_amount` and `claim_fee` are
  public, and every payout's revealed input is `gift − fee`. Equal amounts are what make payouts
  indistinguishable from each other; they are not a link.
* **Timing.** Claims are ordered in time. A member who claims right after the seal, or the only one
  awake at that hour, narrows the anonymity set. The bot driver claims in a random order with random
  pauses; real users should wait a random time.
* **Funding graph.** Whatever the member does with the payout afterwards (merging it with a
  long-lived coin, spending it in the same transaction as identifying funds) is outside the protocol.
  For the recorded bot rounds the five bots were funded by one wallet in one transaction, which
  links the bots to that wallet (but not any bot to any payout).
* **Refunds.** A refund reveals the refunder's key image, which shows that this member did not
  claim. The remaining claims were then made by the other members: a smaller anonymity set,
  retroactively.
* **Sybil / n−1.** Anyone who controls `N−1` of the member keys learns the last member's payout.
  The anonymity set only counts honest, distinct members. The proof of possession stops someone
  registering a key they do not own, but not someone creating many keys of their own.
* **Self-gift.** All gifts go into one vault and come out as equal amounts, so there is no "own
  gift" to receive back; the question of self-gift probability does not arise. In a model that
  assigned deposit slots to claims, a member would draw their own slot with probability `1/N`.
* **Fee dust.** Claims and refunds carry a fixed `claim_fee`; whatever the network does not charge
  goes back into the vault, where it stays after the last payout. The amount is the same for
  everyone and reveals nothing.
* **Denial of service.** Anyone can submit invalid claims. They are rejected in the fee intent and
  cost the vault nothing, but validators do the verification work for free; this is a network-level
  concern that applies to every fee-intent template call.

## Things that are deliberately not in scope

* **Whispers (sealed notes)**: dropped, because there is no sound one-shot way for a giver to encrypt
  to a claimant who is anonymous and unknown at deposit time (see NOTES.md §4).
* **Auditor keys**: TARI has no resource view key, and the round vault is revealed, so totals are
  already public; the auditor view needs no special key (NOTES.md §5).
