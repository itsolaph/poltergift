//! An executable model of the Poltergift round template.
//!
//! `RoundModel` applies exactly the rules of `template/src/lib.rs`, in the same order and with the
//! same rejection messages, using `poltergift-ring` for the cryptography. The browser demo runs
//! rounds against this model, and `template/tests/equivalence.rs` replays random operation sequences
//! against both the model and the real template in the official engine and requires identical
//! outcomes, so the model cannot drift from the contract without CI failing.
//!
//! What the model does not reproduce is the engine itself: stealth transfers and fee metering. A
//! payout is described by its [`PayoutShape`] (what the template checks) and its signed message;
//! the fee actually charged is passed in by the caller.

use poltergift_ring::{self as ring, Purpose, RingSignature};
use serde::{Deserialize, Serialize};

pub use ring::{MAX_RING_SIZE, PointBytes, RoundId};

/// Round parameters, as passed to the template's `create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub gift_amount: u128,
    pub size: u32,
    pub join_deadline: u64,
    pub claim_deadline: u64,
    pub claim_fee: u128,
}

/// The parts of a payout `StealthTransferStatement` that the template checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutShape {
    pub stealth_inputs: usize,
    pub covenant_claims: usize,
    pub revealed_output: u128,
    pub stealth_outputs: usize,
    pub revealed_input: u128,
}

impl PayoutShape {
    /// The only shape the template accepts for a round: one output funded by exactly `amount`.
    pub fn valid(amount: u128) -> Self {
        Self {
            stealth_inputs: 0,
            covenant_claims: 0,
            revealed_output: 0,
            stealth_outputs: 1,
            revealed_input: amount,
        }
    }
}

/// A rejection, carrying the template's panic message verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejected(pub &'static str);

impl core::fmt::Display for Rejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

pub type Outcome = Result<(), Rejected>;

macro_rules! ensure {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return Err(Rejected($msg));
        }
    };
}

/// Template messages, shared so the equivalence test can name them.
pub mod msg {
    pub const SIZE: &str = "round size must be between 2 and 16";
    pub const FEE_POSITIVE: &str = "claim fee must be positive";
    pub const FEE_BELOW_GIFT: &str = "claim fee must be smaller than the gift";
    pub const GIFT_TOO_LARGE: &str = "gift amount too large";
    pub const GIFT_OVERFLOW: &str = "gift amount times size overflows";
    pub const JOIN_DEADLINE_FUTURE: &str = "join deadline must be in the future";
    pub const CLAIM_AFTER_JOIN: &str = "claim deadline must be after the join deadline";
    pub const SEALED: &str = "round is sealed";
    pub const JOIN_DEADLINE_PASSED: &str = "join deadline has passed";
    pub const NOT_TARI: &str = "gift must be TARI";
    pub const NOT_REVEALED: &str = "gift must be revealed funds";
    pub const WRONG_GIFT: &str = "gift must be exactly the round's gift amount";
    pub const BAD_MEMBER: &str = "member key must be a canonical non-identity point";
    pub const DUPLICATE: &str = "member key already joined";
    pub const BAD_POP: &str = "invalid proof of possession";
    pub const NOT_SEALED: &str = "round is not sealed";
    pub const CLAIM_DEADLINE_PASSED: &str = "claim deadline has passed";
    pub const TAG_SPENT: &str = "gift already claimed with this tag";
    pub const SEALED_BEFORE_CLAIM_DEADLINE: &str = "round is sealed and the claim deadline has not passed";
    pub const OPEN_BEFORE_JOIN_DEADLINE: &str = "round is open and the join deadline has not passed";
    pub const NOT_MEMBER: &str = "not a member of this round";
    pub const ALREADY_REFUNDED: &str = "member already refunded";
    pub const PAYOUT_INPUTS: &str = "payout must not spend stealth inputs";
    pub const PAYOUT_COVENANT: &str = "payout must not carry covenant claims";
    pub const PAYOUT_REVEALED: &str = "payout must not have a revealed output";
    pub const PAYOUT_OUTPUTS: &str = "payout must have exactly one stealth output";
    pub const PAYOUT_AMOUNT: &str = "payout must spend exactly the gift minus the claim fee";
    pub const RING_SIZE: &str = "ring size out of range";
    pub const SIG_LENGTH: &str = "signature length does not match the ring";
    pub const BAD_KEY_IMAGE: &str = "key image must be a canonical non-identity point";
    pub const SCALAR: &str = "signature scalar is not canonical";
    pub const INVALID_SIG: &str = "ring signature does not verify";
}

/// The state of one round, field for field the template's component state (the vault is its
/// revealed balance).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundModel {
    pub params: Params,
    pub round_id: RoundId,
    pub tag_base: PointBytes,
    pub members: Vec<PointBytes>,
    pub ring_hash: Option<[u8; 32]>,
    pub spent_tags: Vec<PointBytes>,
    pub refunded: Vec<u32>,
    pub claims: u32,
    pub refunds: u32,
    pub vault: u128,
}

/// `(joined, size, claims, refunds, sealed)`, as the template's `status()` returns it.
pub type Status = (u32, u32, u32, u32, bool);

fn is_valid_point(p: &PointBytes) -> bool {
    ring::decode_nonidentity_point(p).is_ok()
}

fn ring_error_message(err: ring::Error, image_checked: bool) -> &'static str {
    match err {
        ring::Error::RingSize => msg::RING_SIZE,
        ring::Error::Length => msg::SIG_LENGTH,
        ring::Error::NonCanonicalPoint | ring::Error::IdentityPoint if image_checked => msg::BAD_KEY_IMAGE,
        ring::Error::NonCanonicalScalar => msg::SCALAR,
        _ => msg::INVALID_SIG,
    }
}

/// Verifies a claim/refund signature with the template's check order and messages.
fn verify_with_template_semantics(
    purpose: Purpose,
    round_id: &RoundId,
    ring_keys: &[PointBytes],
    key_image: &PointBytes,
    message: &[u8; 32],
    signature: &[u8],
) -> Outcome {
    let n = ring_keys.len();
    ensure!((1..=MAX_RING_SIZE).contains(&n), msg::RING_SIZE);
    ensure!(signature.len() == 32 * (n + 1), msg::SIG_LENGTH);
    ensure!(is_valid_point(key_image), msg::BAD_KEY_IMAGE);
    let sig = RingSignature::from_bytes(signature).map_err(|_| Rejected(msg::SIG_LENGTH))?;
    ensure!(
        core::iter::once(&sig.c0).chain(&sig.s).all(|s| ring::decode_scalar(s).is_ok()),
        msg::SCALAR
    );
    ring::verify(purpose, round_id, ring_keys, key_image, message, &sig).map_err(|e| Rejected(ring_error_message(e, true)))
}

impl RoundModel {
    /// The template's `create`. `round_id` is the component address the engine allocates.
    pub fn create(params: Params, round_id: RoundId, now: u64) -> Result<Self, Rejected> {
        ensure!(params.size >= 2 && params.size as usize <= MAX_RING_SIZE, msg::SIZE);
        ensure!(params.claim_fee > 0, msg::FEE_POSITIVE);
        ensure!(params.claim_fee < params.gift_amount, msg::FEE_BELOW_GIFT);
        ensure!(params.gift_amount <= u64::MAX as u128, msg::GIFT_TOO_LARGE);
        ensure!(params.gift_amount.checked_mul(params.size as u128).is_some(), msg::GIFT_OVERFLOW);
        ensure!(params.join_deadline > now, msg::JOIN_DEADLINE_FUTURE);
        ensure!(params.claim_deadline > params.join_deadline, msg::CLAIM_AFTER_JOIN);
        let (_, tag_base) = ring::tag_base(&round_id).expect("tag base exists");
        Ok(Self {
            params,
            round_id,
            tag_base,
            members: Vec::new(),
            ring_hash: None,
            spent_tags: Vec::new(),
            refunded: Vec::new(),
            claims: 0,
            refunds: 0,
            vault: 0,
        })
    }

    pub fn status(&self) -> Status {
        (
            self.members.len() as u32,
            self.params.size,
            self.claims,
            self.refunds,
            self.ring_hash.is_some(),
        )
    }

    pub fn is_sealed(&self) -> bool {
        self.ring_hash.is_some()
    }

    pub fn payout_amount(&self) -> u128 {
        self.params.gift_amount - self.params.claim_fee
    }

    /// The template's `join`. `gift_is_tari` and `gift_confidential` describe the bucket.
    pub fn join(
        &mut self,
        now: u64,
        member: PointBytes,
        pop: &[u8],
        gift_amount: u128,
        gift_is_tari: bool,
        gift_confidential: bool,
    ) -> Outcome {
        ensure!(self.ring_hash.is_none(), msg::SEALED);
        ensure!(now < self.params.join_deadline, msg::JOIN_DEADLINE_PASSED);
        ensure!(gift_is_tari, msg::NOT_TARI);
        ensure!(!gift_confidential, msg::NOT_REVEALED);
        ensure!(gift_amount == self.params.gift_amount, msg::WRONG_GIFT);
        ensure!(is_valid_point(&member), msg::BAD_MEMBER);
        ensure!(!self.members.contains(&member), msg::DUPLICATE);
        ensure!(ring::verify_pop(&self.round_id, &member, pop).is_ok(), msg::BAD_POP);

        self.vault += gift_amount;
        self.members.push(member);
        if self.members.len() == self.params.size as usize {
            self.ring_hash = Some(ring::ring_hash(&self.round_id, &self.members));
        }
        Ok(())
    }

    fn check_payout(&self, payout: &PayoutShape) -> Outcome {
        ensure!(payout.stealth_inputs == 0, msg::PAYOUT_INPUTS);
        ensure!(payout.covenant_claims == 0, msg::PAYOUT_COVENANT);
        ensure!(payout.revealed_output == 0, msg::PAYOUT_REVEALED);
        ensure!(payout.stealth_outputs == 1, msg::PAYOUT_OUTPUTS);
        ensure!(payout.revealed_input == self.payout_amount(), msg::PAYOUT_AMOUNT);
        Ok(())
    }

    /// The template's `claim`. `message` is `payout_message(cbor(statement))`; `fee_charged` is what
    /// the network charged for the transaction (the rest of `claim_fee` is refunded to the vault).
    pub fn claim(
        &mut self,
        now: u64,
        key_image: PointBytes,
        signature: &[u8],
        payout: &PayoutShape,
        message: &[u8; 32],
        fee_charged: u128,
    ) -> Outcome {
        ensure!(self.ring_hash.is_some(), msg::NOT_SEALED);
        ensure!(now < self.params.claim_deadline, msg::CLAIM_DEADLINE_PASSED);
        ensure!(!self.spent_tags.contains(&key_image), msg::TAG_SPENT);
        self.check_payout(payout)?;
        verify_with_template_semantics(Purpose::Claim, &self.round_id, &self.members, &key_image, message, signature)?;

        self.spent_tags.push(key_image);
        self.claims += 1;
        self.vault -= self.payout_amount() + fee_charged.min(self.params.claim_fee);
        Ok(())
    }

    /// The template's `refund`.
    #[allow(clippy::too_many_arguments)]
    pub fn refund(
        &mut self,
        now: u64,
        member: PointBytes,
        key_image: PointBytes,
        proof: &[u8],
        payout: &PayoutShape,
        message: &[u8; 32],
        fee_charged: u128,
    ) -> Outcome {
        if self.ring_hash.is_some() {
            ensure!(now >= self.params.claim_deadline, msg::SEALED_BEFORE_CLAIM_DEADLINE);
        } else {
            ensure!(now >= self.params.join_deadline, msg::OPEN_BEFORE_JOIN_DEADLINE);
        }
        let index = self
            .members
            .iter()
            .position(|m| *m == member)
            .ok_or(Rejected(msg::NOT_MEMBER))? as u32;
        ensure!(!self.refunded.contains(&index), msg::ALREADY_REFUNDED);
        ensure!(!self.spent_tags.contains(&key_image), msg::TAG_SPENT);
        self.check_payout(payout)?;
        verify_with_template_semantics(Purpose::Refund, &self.round_id, &[member], &key_image, message, proof)?;

        self.spent_tags.push(key_image);
        self.refunded.push(index);
        self.refunds += 1;
        self.vault -= self.payout_amount() + fee_charged.min(self.params.claim_fee);
        Ok(())
    }

    /// Gifts still owed: members who neither claimed nor were refunded.
    pub fn outstanding(&self) -> u32 {
        self.members.len() as u32 - self.claims - self.refunds
    }

    /// The solvency invariant: the vault can always pay every outstanding gift.
    pub fn is_solvent(&self) -> bool {
        self.vault >= self.outstanding() as u128 * self.payout_amount()
    }
}

#[cfg(test)]
mod tests;
