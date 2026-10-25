//! On-disk state for the CLI: the wallet's keys and the member key for every round joined.
//!
//! Everything here is secret material. Files are created with mode 0600 inside a 0700 directory.
//! Point `--data-dir` at a location covered by your backups and never commit it.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use ootle_rs::{Network, keys::OotleSecretKey};
use poltergift_ring::SecretKey;
use serde::{Deserialize, Serialize};
use tari_crypto::{ristretto::RistrettoSecretKey, tari_utilities::ByteArray};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletFile {
    network: String,
    account_secret: String,
    view_secret: String,
}

/// What a member remembers about one round.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The member's ring secret for this round (hex). Fresh per round.
    pub member_secret: String,
    pub member_public: String,
    pub join_tx: Option<String>,
    pub claim_tx: Option<String>,
    pub refund_tx: Option<String>,
    /// Commitment of the stealth output the gift was paid to.
    pub payout_commitment: Option<String>,
}

impl MemberRecord {
    pub fn secret(&self) -> Result<SecretKey> {
        let bytes: [u8; 32] =
            hex::decode(&self.member_secret)?.try_into().map_err(|_| anyhow!("member secret must be 32 bytes"))?;
        SecretKey::from_bytes(&bytes).map_err(|e| anyhow!("invalid member secret: {e}"))
    }
}

pub struct Store {
    dir: PathBuf,
}

fn network_name(n: Network) -> String {
    format!("{n:?}").to_lowercase()
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("opening {}", tmp.display()))?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Store {
    pub fn open<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn wallet_path(&self) -> PathBuf {
        self.dir.join("wallet.json")
    }

    fn rounds_path(&self) -> PathBuf {
        self.dir.join("rounds.json")
    }

    pub fn has_wallet(&self) -> bool {
        self.wallet_path().exists()
    }

    /// Loads the wallet, creating a fresh random one on first use.
    pub fn load_or_create_wallet(&self, network: Network) -> Result<(OotleSecretKey, bool)> {
        if self.has_wallet() {
            return Ok((self.load_wallet(network)?, false));
        }
        let secret = OotleSecretKey::random(network);
        let file = WalletFile {
            network: network_name(network),
            account_secret: hex::encode(secret.account_secret().as_bytes()),
            view_secret: hex::encode(secret.view_only_secret().as_bytes()),
        };
        write_private(&self.wallet_path(), serde_json::to_string_pretty(&file)?.as_bytes())?;
        Ok((secret, true))
    }

    pub fn load_wallet(&self, network: Network) -> Result<OotleSecretKey> {
        let raw = fs::read_to_string(self.wallet_path()).context("no wallet; run `poltergift init` first")?;
        let file: WalletFile = serde_json::from_str(&raw)?;
        if file.network != network_name(network) {
            return Err(anyhow!(
                "wallet in {} is for network {}, not {}",
                self.dir.display(),
                file.network,
                network_name(network)
            ));
        }
        let account = RistrettoSecretKey::from_canonical_bytes(&hex::decode(&file.account_secret)?)
            .map_err(|e| anyhow!("bad account secret: {e}"))?;
        let view = RistrettoSecretKey::from_canonical_bytes(&hex::decode(&file.view_secret)?)
            .map_err(|e| anyhow!("bad view secret: {e}"))?;
        Ok(OotleSecretKey::new(network, account, view))
    }

    pub fn rounds(&self) -> Result<BTreeMap<String, MemberRecord>> {
        match fs::read_to_string(self.rounds_path()) {
            Ok(raw) => Ok(serde_json::from_str(&raw)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn round(&self, component: &str) -> Result<Option<MemberRecord>> {
        Ok(self.rounds()?.remove(component))
    }

    pub fn save_round(&self, component: &str, record: &MemberRecord) -> Result<()> {
        let mut all = self.rounds()?;
        all.insert(component.to_string(), record.clone());
        write_private(&self.rounds_path(), serde_json::to_string_pretty(&all)?.as_bytes())
    }
}
