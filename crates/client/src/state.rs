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
