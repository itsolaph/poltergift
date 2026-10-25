//! Poltergift: a secret gift exchange on the Tari Ootle.
//!
//! A round collects one equal gift of TARI from each of `size` members. Once full it is sealed and
//! every member can claim one gift into a fresh stealth output, proving only "I am one of the
//! members" with a linkable ring signature. The key image of that signature is a one-time tag that
//! stops a second claim without revealing which member claimed. Deadlines let members take their
//! gift back if the round never fills or if they never claimed.
//!
//! Claims and refunds pay their fee from the round vault, so they must be called from the
//! transaction's fee intent and can be signed by a throwaway key: no account or member key ever
//! appears in a claim transaction.

use tari_template_lib::{
    prelude::*,
    types::{Hash32, constants::TARI_TOKEN},
};

mod crypto;

pub use crypto::MAX_RING_SIZE;

#[template]
mod poltergift {
    use super::*;
    use crate::crypto::{self, RingCheck};

    pub struct Round {
        vault: Vault,
        gift_amount: Amount,
        claim_fee: Amount,
        size: u32,
        join_deadline: u64,
        claim_deadline: u64,
        round_id: Hash32,
        tag_base: RistrettoPublicKeyBytes,
        members: Vec<RistrettoPublicKeyBytes>,
        ring_hash: Option<Hash32>,
        spent_tags: Vec<RistrettoPublicKeyBytes>,
        refunded: Vec<u32>,
        claims: u32,
        refunds: u32,
    }

    impl Round {
        /// Opens a round of `size` members, each giving exactly `gift_amount` µT. Claims and refunds
        /// pay out `gift_amount - claim_fee` and spend `claim_fee` on their own transaction fee.
        /// Deadlines are epochs: joins are accepted while `epoch < join_deadline`, claims while
        /// `epoch < claim_deadline`.
        pub fn create(
            gift_amount: Amount,
            size: u32,
            join_deadline: u64,
            claim_deadline: u64,
            claim_fee: Amount,
        ) -> Component<Self> {
            assert!(
                size >= 2 && size as usize <= MAX_RING_SIZE,
                "round size must be between 2 and {MAX_RING_SIZE}"
            );
            assert!(claim_fee.is_positive(), "claim fee must be positive");
            assert!(claim_fee < gift_amount, "claim fee must be smaller than the gift");
            // Payouts are stealth outputs, whose values are range-proven below 2^64.
            assert!(gift_amount.to_u128() <= u64::MAX as u128, "gift amount too large");
            assert!(
                gift_amount.checked_mul(Amount::from(size)).is_some(),
                "gift amount times size overflows"
            );
            let now = Consensus::current_epoch();
            assert!(join_deadline > now, "join deadline must be in the future");
            assert!(claim_deadline > join_deadline, "claim deadline must be after the join deadline");

            let allocation = CallerContext::allocate_component_address(None);
            let round_id = allocation.get_address().as_object_key().into_array();
            let tag_base = crypto::tag_base(&round_id);

            emit_event("Created", metadata!["size" => size.to_string()]);

            Component::new(Self {
                vault: Vault::new_empty(TARI_TOKEN),
                gift_amount,
                claim_fee,
                size,
                join_deadline,
                claim_deadline,
                round_id: Hash32::from(round_id),
                tag_base,
                members: Vec::new(),
                ring_hash: None,
                spent_tags: Vec::new(),
                refunded: Vec::new(),
                claims: 0,
                refunds: 0,
            })
            .with_address_allocation(allocation)
            .with_owner_rule(OwnerRule::None)
            .with_access_rules(ComponentAccessRules::allow_all())
            .create()
        }

        /// Adds a member with their gift. `pop` is a proof of possession of `member` bound to this
        /// round. The join that fills the round seals it.
        pub fn join(&mut self, member: RistrettoPublicKeyBytes, pop: Vec<u8>, gift: Bucket) {
            assert!(self.ring_hash.is_none(), "round is sealed");
            assert!(Consensus::current_epoch() < self.join_deadline, "join deadline has passed");
            assert!(gift.resource_address() == TARI_TOKEN, "gift must be TARI");
            assert!(gift.count_confidential_commitments() == 0, "gift must be revealed funds");
            assert!(gift.amount() == self.gift_amount, "gift must be exactly the round's gift amount");
            assert!(crypto::is_valid_point(&member), "member key must be a canonical non-identity point");
            assert!(!self.members.contains(&member), "member key already joined");
            assert!(
                crypto::verify_pop(&self.round_id.into_array(), &member, &pop),
                "invalid proof of possession"
            );

            self.vault.deposit(gift);
            self.members.push(member);
            emit_event("Joined", metadata!["count" => self.members.len().to_string()]);

            if self.members.len() == self.size as usize {
                self.ring_hash = Some(crypto::ring_hash(&self.round_id.into_array(), &self.members));
                emit_event("Sealed", metadata!["size" => self.size.to_string()]);
            }
        }

        /// Claims one gift anonymously. `signature` is a ring signature over all members that signs
        /// the exact `payout` statement; `key_image` is its one-time tag. Must run in the fee
        /// intent: the round vault pays `claim_fee` for this transaction.
        pub fn claim(&mut self, key_image: RistrettoPublicKeyBytes, signature: Vec<u8>, payout: StealthTransferStatement) {
            let ring_hash = self.ring_hash.expect("round is not sealed");
            assert!(Consensus::current_epoch() < self.claim_deadline, "claim deadline has passed");
            assert!(!self.spent_tags.contains(&key_image), "gift already claimed with this tag");
            self.check_payout(&payout);

            self.vault.pay_fee(self.claim_fee);

            let message = crypto::payout_message(&tari_bor::encode(&payout).expect("payout encodes"));
            let round_id = self.round_id.into_array();
            let result = crypto::verify_ring(&RingCheck {
                purpose_dst: crypto::dst::CLAIM,
                round_id: &round_id,
                ring: &self.members,
                ring_hash: &ring_hash,
                tag_base: &self.tag_base,
                key_image: &key_image,
                message: &message,
                signature: &signature,
            });
            if let Err(err) = result {
                panic!("{}", err.as_str());
            }

            self.spent_tags.push(key_image);
            self.claims += 1;
            self.pay_out(payout);
            emit_event("Claimed", metadata!["count" => self.claims.to_string()]);
        }

        /// Returns a member's gift after a deadline: the join deadline if the round never filled,
        /// the claim deadline if it did. `proof` shows `member = x·G` and `key_image = x·H`, so a
        /// member whose tag was already spent by a claim cannot also take a refund. Must run in the
        /// fee intent, like `claim`.
        pub fn refund(
            &mut self,
            member: RistrettoPublicKeyBytes,
            key_image: RistrettoPublicKeyBytes,
            proof: Vec<u8>,
            payout: StealthTransferStatement,
        ) {
            let epoch = Consensus::current_epoch();
            if self.ring_hash.is_some() {
                assert!(epoch >= self.claim_deadline, "round is sealed and the claim deadline has not passed");
            } else {
                assert!(epoch >= self.join_deadline, "round is open and the join deadline has not passed");
            }
            let index = self
                .members
                .iter()
                .position(|m| *m == member)
                .expect("not a member of this round") as u32;
            assert!(!self.refunded.contains(&index), "member already refunded");
            assert!(!self.spent_tags.contains(&key_image), "gift already claimed with this tag");
            self.check_payout(&payout);

            self.vault.pay_fee(self.claim_fee);

            let message = crypto::payout_message(&tari_bor::encode(&payout).expect("payout encodes"));
            let round_id = self.round_id.into_array();
            let ring = [member];
            let ring_hash = crypto::ring_hash(&round_id, &ring);
            let result = crypto::verify_ring(&RingCheck {
                purpose_dst: crypto::dst::REFUND,
                round_id: &round_id,
                ring: &ring,
                ring_hash: &ring_hash,
                tag_base: &self.tag_base,
                key_image: &key_image,
                message: &message,
                signature: &proof,
            });
            if let Err(err) = result {
                panic!("{}", err.as_str());
            }

            self.spent_tags.push(key_image);
            self.refunded.push(index);
            self.refunds += 1;
            self.pay_out(payout);
            emit_event("Refunded", metadata!["count" => self.refunds.to_string()]);
        }

        /// Read-only summary: `(joined, size, claims, refunds, sealed)`.
        pub fn status(&self) -> (u32, u32, u32, u32, bool) {
            (
                self.members.len() as u32,
                self.size,
                self.claims,
                self.refunds,
                self.ring_hash.is_some(),
            )
        }

        /// The round id (component address key) that every signature in this round is bound to.
        pub fn round_id(&self) -> Hash32 {
            self.round_id
        }

        /// The per-round tag base `H`; key images are `x·H`.
        pub fn tag_base(&self) -> RistrettoPublicKeyBytes {
            self.tag_base
        }

        /// The revealed TARI held by the round (deposits not yet paid out, plus any fee dust).
        pub fn balance(&self) -> Amount {
            self.vault.balance()
        }

        fn payout_amount(&self) -> Amount {
            self.gift_amount
                .checked_sub(self.claim_fee)
                .expect("claim fee is smaller than the gift")
        }

        /// A payout is exactly one fresh stealth output funded only by the revealed gift: no stealth
        /// inputs (nothing else can be mixed in), no revealed output (nothing leaks back out as a
        /// bucket), and the full payout amount.
        fn check_payout(&self, payout: &StealthTransferStatement) {
            assert!(payout.stealth_inputs().is_empty(), "payout must not spend stealth inputs");
            assert!(payout.covenant_claims.is_empty(), "payout must not carry covenant claims");
            assert!(payout.revealed_output_amount().is_zero(), "payout must not have a revealed output");
            assert!(payout.stealth_outputs().len() == 1, "payout must have exactly one stealth output");
            assert!(
                payout.revealed_input_amount() == self.payout_amount(),
                "payout must spend exactly the gift minus the claim fee"
            );
        }

        fn pay_out(&mut self, payout: StealthTransferStatement) {
            let gift = self.vault.withdraw(self.payout_amount());
            let leftover = ResourceManager::get(TARI_TOKEN).stealth_transfer_with_opt_input_bucket(payout, Some(gift));
            assert!(leftover.is_none(), "payout must not return a bucket");
        }
    }
}
