//! Finding and opening this wallet's stealth outputs.
//!
//! An output's owner is hidden; only the holder of the destination's view key can recognise it.
//! Each output carries a 32-bit tag `H(view·R ‖ resource)` (a fast filter) and a public nonce `R`;
//! the value and mask are encrypted under a key derived from `view·R`. Scanning streams every
//! unspent TARI output's `(tag, R)` from the indexer, keeps the ones whose tag matches, fetches them
//! and decrypts them. Nothing about the scan is revealed to the indexer beyond "this client
//! downloaded the public tag list".

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use futures::StreamExt;
use ootle_byte_type::FromByteType;
use ootle_rs::{
    crypto::{encrypted_data::decrypt_data, kdfs},
    provider::{ShardCursor, StealthUtxoFrame, StealthUtxoWatchRequest},
};
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_ootle_common_types::{
    Epoch,
    engine_types::substate::SubstateValue,
    shard::Shard,
    StateVersion,
};
use tari_template_lib_types::{
    UtxoAddress,
    constants::TARI_TOKEN,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, UtxoTag},
};
use tari_ootle_common_types::engine_types::crypto::OutputBody;

use crate::client::PoltergiftClient;

/// One of this wallet's outputs, opened.
#[derive(Debug, Clone)]
pub struct OwnedOutput {
    pub commitment: PedersenCommitmentBytes,
    pub value: u64,
    pub memo: Option<String>,
}

impl PoltergiftClient {
    fn open_body(&self, commitment: PedersenCommitmentBytes, body: &OutputBody) -> Option<OwnedOutput> {
        let nonce: RistrettoPublicKey = body.public_nonce.try_from_byte_type().ok()?;
        let key = kdfs::encrypted_data_dh_kdf_aead(self.secret().view_only_secret(), &nonce);
        let opened = decrypt_data(&key, &commitment, &body.encrypted_data, false).ok()?;
        Some(OwnedOutput {
            commitment,
            value: opened.mask_and_value.value,
            memo: opened.memo.map(|m| format!("{m:?}")),
        })
    }

    /// Opens the output at `commitment` with this wallet's view key. `Ok(None)` means the output
    /// exists but is not ours (it does not decrypt); an error means it is gone (spent) or unknown.
    pub async fn open_output(&self, commitment: PedersenCommitmentBytes) -> Result<Option<OwnedOutput>> {
        let substate = self
            .provider()
            .fetch_substate(UtxoAddress::new(TARI_TOKEN, commitment.into()))
            .await?;
        match substate.into_substate_value() {
            SubstateValue::Utxo(utxo) => {
                let output = utxo.output.ok_or_else(|| anyhow!("output was burnt"))?;
                Ok(self.open_body(commitment, output.output()))
            },
            other => Err(anyhow!("not a UTXO: {other:?}")),
        }
    }

    fn tag_for(&self, public_nonce: &RistrettoPublicKeyBytes) -> Option<UtxoTag> {
        let nonce: RistrettoPublicKey = public_nonce.try_from_byte_type().ok()?;
        Some(kdfs::utxo_tag_stealth_dh(
            self.network(),
            &nonce,
            self.secret().view_only_secret(),
            &TARI_TOKEN,
        ))
    }

    /// Scans every unspent TARI output for ones this wallet owns.
    pub async fn scan_owned(&self) -> Result<Vec<OwnedOutput>> {
        let preshards = self.provider().get_num_preshards().await?;
        let mut cursors: BTreeMap<Shard, StateVersion> = ShardCursor::genesis(preshards).to_pairs().into_iter().collect();
        let mut candidates = Vec::new();
        loop {
            let request = StealthUtxoWatchRequest {
                resource_address: TARI_TOKEN,
                from_epoch: Epoch(0),
                shard_state_versions: cursors.iter().map(|(s, v)| (*s, *v)).collect(),
                unspent_only: true,
                per_shard_limit: 1_000,
            };
            let mut more = false;
            let mut stream = Box::pin(self.provider().watch_stealth_utxos(request).into_stream());
            while let Some(frame) = stream.next().await {
                match frame.map_err(|e| anyhow!("UTXO stream: {e}"))? {
                    StealthUtxoFrame::StartOfShard { has_more, .. } => more |= has_more,
                    StealthUtxoFrame::Unspent { tag, public_nonce } => {
                        if self.tag_for(&public_nonce) == Some(tag) {
                            candidates.push((tag, public_nonce));
                        }
                    },
                    StealthUtxoFrame::EndOfShard { shard, max_state_version } => {
                        cursors.insert(shard, max_state_version);
                    },
                    StealthUtxoFrame::Spent { .. } | StealthUtxoFrame::Burnt { .. } => {},
                }
            }
            if !more {
                break;
            }
        }
        let fetched = self.provider().fetch_unspent_utxos(TARI_TOKEN, &candidates).await?;
        Ok(fetched
            .into_iter()
            .filter_map(|(id, utxo)| utxo.output.and_then(|o| self.open_body(id.into_commitment_bytes(), o.output())))
            .collect())
    }
}
