//! Reading the burn proof file the L1 console wallet writes (`--burn-proof-out`).
//!
//! The file carries the L1 view of the burn: the output's hash preimage (with the output features
//! as L1 borsh bytes) and its MMR inclusion proofs. The Ootle engine takes a `MinotariBurnClaimProof`
//! with the features decoded. This is the same conversion the official wallet daemon performs
//! (`tari_ootle_app_utilities::burn_claim_proof::claim_proof_from_l1`), written against the public
//! types so the client does not need the L1 crates.

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine;
use bounded_vec::BoundedVec;
use ootle_rs::claim_burn::MinotariBurnClaimProof;
use serde::Deserialize;
use tari_ootle_common_types::engine_types::confidential::{
    BurnOutput, BurnOutputFeatures, BurnOutputInclusionProof, MmrInclusionProof,
};
use tari_template_lib_types::{
    EncryptedData, Hash32,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, Scalar32Bytes, SchnorrSignatureBytes},
};

#[derive(Deserialize)]
struct File {
    claim_proof: L1ClaimProof,
    /// Base64 of the burn output's encrypted data.
    encrypted_data: String,
}

#[derive(Deserialize)]
struct L1ClaimProof {
    ownership_proof: L1Schnorr,
    output_proof: L1OutputProof,
    value: u64,
}

#[derive(Deserialize)]
struct L1Schnorr {
    public_nonce: String,
    signature: String,
}

#[derive(Deserialize)]
struct L1OutputProof {
    block_hash: String,
    output: L1Output,
    normal_output_proof: L1Mmr,
    normal_output_mr: String,
    block_output_proof: L1Mmr,
}

#[derive(Deserialize)]
struct L1Output {
    version: u8,
    features: String,
    commitment: String,
    rangeproof_hash: String,
    script: String,
    sender_offset_public_key: String,
    metadata_signature: L1MetadataSignature,
    covenant: String,
    encrypted_data: String,
    minimum_value_promise: u64,
}

#[derive(Deserialize)]
struct L1MetadataSignature {
    ephemeral_commitment: String,
    ephemeral_pubkey: String,
    u_a: String,
    u_x: String,
    u_y: String,
}

#[derive(Deserialize)]
struct L1Mmr {
    leaf_index: u64,
    mmr_size: u64,
    path: Vec<String>,
    peaks: Vec<String>,
}

fn h32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)?.try_into().map_err(|_| anyhow!("expected 32 bytes: {s}"))
}

fn hash(s: &str) -> Result<Hash32> {
    Ok(Hash32::from(h32(s)?))
}

fn bounded<const N: usize>(field: &str, bytes: Vec<u8>) -> Result<BoundedVec<u8, 1, N>> {
    let len = bytes.len();
    BoundedVec::<u8, 1, N>::try_from(bytes).map_err(|_| anyhow!("burn output {field} length {len} is out of range"))
}

fn mmr(p: &L1Mmr) -> Result<MmrInclusionProof> {
    Ok(MmrInclusionProof {
        leaf_index: p.leaf_index,
        mmr_size: p.mmr_size,
        path: p.path.iter().map(|h| hash(h)).collect::<Result<_>>()?,
        peaks: p.peaks.iter().map(|h| hash(h)).collect::<Result<_>>()?,
    })
}

/// A minimal reader for the L1 borsh encoding of `OutputFeatures`.
struct Borsh<'a>(&'a [u8]);

impl Borsh<'_> {
    fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self.0.split_first().context("features truncated")?;
        self.0 = rest;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(self.0.len() >= n, "features truncated");
        let (a, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(a)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

const OUTPUT_TYPE_BURN: u8 = 2;
const SIDECHAIN_DATA_CONFIDENTIAL_OUTPUT: u8 = 2;

/// Decodes L1 `OutputFeatures` (version, output type, maturity, coinbase extra, optional sidechain
/// feature with a confidential-output claim key, range proof type) for a burn to the Ootle.
fn decode_features(raw: &[u8]) -> Result<BurnOutputFeatures> {
    let mut r = Borsh(raw);
    let version = r.u8()?;
    let output_type = r.u8()?;
    ensure!(output_type == OUTPUT_TYPE_BURN, "output type {output_type} is not a burn");
    let maturity = r.u64()?;
    let _coinbase_extra = r.bytes()?;
    ensure!(r.u8()? == 1, "the burn output has no sidechain feature, so it names no claimant");
    ensure!(r.u8()? == SIDECHAIN_DATA_CONFIDENTIAL_OUTPUT, "the sidechain feature is not a confidential output");
    let claim_key: [u8; 32] = r.bytes()?.try_into().map_err(|_| anyhow!("claim key must be 32 bytes"))?;
    if r.u8()? != 0 {
        bail!("burns to a keyed sidechain are not supported (Ootle burns carry no sidechain id)");
    }
    let range_proof_type = r.u8()?;
    ensure!(r.0.is_empty(), "unexpected trailing bytes in output features");
    let features = BurnOutputFeatures {
        version,
        maturity,
        claim_public_key: RistrettoPublicKeyBytes::from(claim_key),
        sidechain_id: None,
        range_proof_type,
    };
    ensure!(encode_features(&features) == raw, "output features do not round-trip");
    Ok(features)
}

fn encode_features(f: &BurnOutputFeatures) -> Vec<u8> {
    let mut out = vec![f.version, OUTPUT_TYPE_BURN];
    out.extend_from_slice(&f.maturity.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[1, SIDECHAIN_DATA_CONFIDENTIAL_OUTPUT]);
    out.extend_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(f.claim_public_key.as_ref());
    out.extend_from_slice(&[0, f.range_proof_type]);
    out
}

/// Borsh of the L1 commitment-and-public-key signature: five 32-byte values, each length-prefixed.
fn metadata_signature_bytes(s: &L1MetadataSignature) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(5 * 36);
    for part in [&s.ephemeral_commitment, &s.ephemeral_pubkey, &s.u_a, &s.u_x, &s.u_y] {
        out.extend_from_slice(&32u32.to_le_bytes());
        out.extend_from_slice(&h32(part)?);
    }
    Ok(out)
}

/// Parses a console-wallet burn proof file into the claim proof and encrypted data the Ootle needs.
pub fn parse_l1_burn_proof(json: &str) -> Result<(MinotariBurnClaimProof, EncryptedData)> {
    let file: File = serde_json::from_str(json).context("not a burn proof file")?;
    let p = &file.claim_proof;
    let o = &p.output_proof.output;
    let proof = MinotariBurnClaimProof {
        commitment: PedersenCommitmentBytes::from(h32(&o.commitment)?),
        ownership_proof: SchnorrSignatureBytes::new(
            RistrettoPublicKeyBytes::from(h32(&p.ownership_proof.public_nonce)?),
            Scalar32Bytes::from(h32(&p.ownership_proof.signature)?),
        ),
        value: p.value,
        output: BurnOutput {
            version: o.version,
            features: decode_features(&hex::decode(&o.features)?)?,
            rangeproof_hash: hash(&o.rangeproof_hash)?,
            script: bounded("script", hex::decode(&o.script)?)?,
            sender_offset_public_key: RistrettoPublicKeyBytes::from(h32(&o.sender_offset_public_key)?),
            metadata_signature: bounded("metadata signature", metadata_signature_bytes(&o.metadata_signature)?)?,
            covenant: bounded("covenant", hex::decode(&o.covenant)?)?,
            encrypted_data: bounded("encrypted data", hex::decode(&o.encrypted_data)?)?,
            minimum_value_promise: o.minimum_value_promise,
        },
        inclusion_proof: BurnOutputInclusionProof {
            block_hash: hash(&p.output_proof.block_hash)?,
            normal_output_proof: mmr(&p.output_proof.normal_output_proof)?,
            normal_output_mr: hash(&p.output_proof.normal_output_mr)?,
            block_output_proof: mmr(&p.output_proof.block_output_proof)?,
        },
    };
    let encrypted = base64::engine::general_purpose::STANDARD.decode(&file.encrypted_data)?;
    let encrypted = EncryptedData::try_from(encrypted).map_err(|e| anyhow!("bad encrypted data: {e:?}"))?;
    Ok((proof, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ootle_burn_features() {
        let raw = hex::decode(
            "00020000000000000000000000000102200000001ad8b2954561f508241d7191a95abe718510dae0e0cd27a15a01de6f5640fa080000",
        )
        .unwrap();
        let f = decode_features(&raw).unwrap();
        assert_eq!((f.version, f.maturity, f.range_proof_type), (0, 0, 0));
        assert_eq!(
            hex::encode(f.claim_public_key.as_ref()),
            "1ad8b2954561f508241d7191a95abe718510dae0e0cd27a15a01de6f5640fa08"
        );
        assert!(f.sidechain_id.is_none());
    }

    #[test]
    fn rejects_non_burn_outputs() {
        let mut raw = hex::decode(
            "00020000000000000000000000000102200000001ad8b2954561f508241d7191a95abe718510dae0e0cd27a15a01de6f5640fa080000",
        )
        .unwrap();
        raw[1] = 0;
        assert!(decode_features(&raw).is_err());
        assert!(decode_features(&raw[..20]).is_err());
    }
}
