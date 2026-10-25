//! Decoding a round component's state as published by the indexer.
//!
//! The template's `Round` struct is CBOR-encoded by the engine as a positional array (the template
//! macro derives minicbor with field indices in declaration order). `RoundState` mirrors it field
//! for field; a field added to the template must be added here at the same index.

use anyhow::{Result, anyhow};
use tari_template_lib_types::{Amount, Hash32, VaultId, crypto::RistrettoPublicKeyBytes};

#[derive(Debug, Clone, minicbor::Decode)]
pub struct RoundState {
    #[n(0)]
    pub vault: VaultId,
    #[n(1)]
    pub gift_amount: Amount,
    #[n(2)]
    pub claim_fee: Amount,
    #[n(3)]
    pub size: u32,
    #[n(4)]
    pub join_deadline: u64,
    #[n(5)]
    pub claim_deadline: u64,
    #[n(6)]
    pub round_id: Hash32,
    #[n(7)]
    pub tag_base: RistrettoPublicKeyBytes,
    #[n(8)]
    pub members: Vec<RistrettoPublicKeyBytes>,
    #[n(9)]
    pub ring_hash: Option<Hash32>,
    #[n(10)]
    pub spent_tags: Vec<RistrettoPublicKeyBytes>,
    #[n(11)]
    pub refunded: Vec<u32>,
    #[n(12)]
    pub claims: u32,
    #[n(13)]
    pub refunds: u32,
}

impl RoundState {
    pub fn from_value(value: &tari_bor::Value) -> Result<Self> {
        tari_bor::from_value(value).map_err(|e| anyhow!("component state is not a Poltergift round: {e}"))
    }

    pub fn is_sealed(&self) -> bool {
        self.ring_hash.is_some()
    }

    pub fn round_id_bytes(&self) -> [u8; 32] {
        self.round_id.into_array()
    }

    pub fn ring(&self) -> Vec<[u8; 32]> {
        self.members.iter().map(|m| m.into_array()).collect()
    }

    pub fn payout_amount(&self) -> Amount {
        self.gift_amount.checked_sub(self.claim_fee).unwrap_or_default()
    }

    pub fn member_index(&self, public: &[u8; 32]) -> Option<usize> {
        self.members.iter().position(|m| m.into_array() == *public)
    }

    /// The lifecycle phase at `epoch`, in words.
    pub fn phase(&self, epoch: u64) -> &'static str {
        match (self.is_sealed(), epoch) {
            (false, e) if e < self.join_deadline => "open",
            (false, _) => "expired (refunds open)",
            (true, e) if e < self.claim_deadline => "sealed (claims open)",
            (true, _) => "closed (refunds for unclaimed gifts)",
        }
    }
}

#[cfg(test)]
mod tests {
    use tari_template_lib_types::ObjectKey;

    use super::*;

    /// The template's `Round` field layout, encoded the way the template macro derives it.
    #[derive(minicbor::Encode)]
    struct TemplateLayout {
        #[n(0)]
        vault: VaultId,
        #[n(1)]
        gift_amount: Amount,
        #[n(2)]
        claim_fee: Amount,
        #[n(3)]
        size: u32,
        #[n(4)]
        join_deadline: u64,
        #[n(5)]
        claim_deadline: u64,
        #[n(6)]
        round_id: Hash32,
        #[n(7)]
        tag_base: RistrettoPublicKeyBytes,
        #[n(8)]
        members: Vec<RistrettoPublicKeyBytes>,
        #[n(9)]
        ring_hash: Option<Hash32>,
        #[n(10)]
        spent_tags: Vec<RistrettoPublicKeyBytes>,
        #[n(11)]
        refunded: Vec<u32>,
        #[n(12)]
        claims: u32,
        #[n(13)]
        refunds: u32,
    }

    fn layout(sealed: bool) -> TemplateLayout {
        TemplateLayout {
            vault: VaultId::new(ObjectKey::from_array([9; 32])),
            gift_amount: Amount::from(5_000_000u64),
            claim_fee: Amount::from(50_000u64),
            size: 3,
            join_deadline: 10,
            claim_deadline: 20,
            round_id: Hash32::from([1; 32]),
            tag_base: RistrettoPublicKeyBytes::from([2; 32]),
            members: vec![RistrettoPublicKeyBytes::from([3; 32]), RistrettoPublicKeyBytes::from([4; 32])],
            ring_hash: sealed.then(|| Hash32::from([5; 32])),
            spent_tags: vec![RistrettoPublicKeyBytes::from([6; 32])],
            refunded: vec![1],
            claims: 1,
            refunds: 1,
        }
    }

    #[test]
    fn decodes_the_template_layout() {
        for sealed in [false, true] {
            let value = tari_bor::to_value(&layout(sealed)).unwrap();
            let state = RoundState::from_value(&value).unwrap();
            assert_eq!(state.is_sealed(), sealed);
            assert_eq!(state.payout_amount(), Amount::from(4_950_000u64));
            assert_eq!(state.ring(), vec![[3; 32], [4; 32]]);
            assert_eq!(state.member_index(&[4; 32]), Some(1));
            assert_eq!(state.round_id_bytes(), [1; 32]);
            assert_eq!((state.claims, state.refunds, state.refunded.clone()), (1, 1, vec![1]));
        }
    }

    #[test]
    fn phases_follow_deadlines() {
        let open = RoundState::from_value(&tari_bor::to_value(&layout(false)).unwrap()).unwrap();
        assert_eq!(open.phase(5), "open");
        assert_eq!(open.phase(10), "expired (refunds open)");
        let sealed = RoundState::from_value(&tari_bor::to_value(&layout(true)).unwrap()).unwrap();
        assert_eq!(sealed.phase(15), "sealed (claims open)");
        assert_eq!(sealed.phase(20), "closed (refunds for unclaimed gifts)");
    }

    #[test]
    fn rejects_other_components() {
        let value = tari_bor::to_value(&(1u32, 2u32)).unwrap();
        assert!(RoundState::from_value(&value).is_err());
    }
}
