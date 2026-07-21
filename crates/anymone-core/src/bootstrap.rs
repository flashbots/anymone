//! Static bootstrap configuration loaded from `anymone.toml` at startup:
//! the node's identity path, its network listen/peers, and the governance
//! committee it trusts.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::committee::CommitteeParams;
use crate::governance::GovernanceConfig;
use crate::identity::Pubkey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    pub identity_path: PathBuf,
    pub network: NetworkConfig,
    pub governance: GovernanceConfig,
    /// Committee scheduler tunables (shared across all nodes). Optional — an
    /// absent `[committee]` section uses [`CommitteeParams`] defaults.
    #[serde(default)]
    pub committee: CommitteeParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen: String,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
}

impl BootstrapConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, BootstrapError> {
        let cfg: BootstrapConfig = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self, BootstrapError> {
        let s = fs::read_to_string(path)?;
        Self::from_toml_str(&s)
    }

    pub fn write_to(&self, path: &Path) -> Result<(), BootstrapError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(BootstrapError::Encode)?;
        fs::write(path, s)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), BootstrapError> {
        if self.governance.committee.is_empty() {
            return Err(BootstrapError::EmptyCommittee);
        }
        let n = self.governance.committee.len() as u32;
        if self.governance.threshold == 0 || self.governance.threshold > n {
            return Err(BootstrapError::BadThreshold {
                threshold: self.governance.threshold,
                committee: n,
            });
        }
        let mut sorted: Vec<Pubkey> = self.governance.committee.iter().map(|m| m.pubkey).collect();
        sorted.sort();
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(BootstrapError::DuplicateCommitteeMember(w[0]));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("toml decode: {0}")]
    Decode(#[from] toml::de::Error),
    #[error("toml encode: {0}")]
    Encode(toml::ser::Error),
    #[error("committee is empty")]
    EmptyCommittee,
    #[error("threshold {threshold} not in 1..={committee}")]
    BadThreshold { threshold: u32, committee: u32 },
    #[error("duplicate committee member: {0}")]
    DuplicateCommitteeMember(Pubkey),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// A `[[governance.committee]]` table for a fresh identity.
    fn member_table(id: &Identity) -> String {
        let xpub = crate::config::ExchangePublicKeyWire::from_key(&id.exchange_pubkey());
        format!(
            "[[governance.committee]]\npubkey = \"{}\"\nexchange_pubkey = \"{}\"\n",
            id.pubkey(),
            hex::encode(&xpub.0),
        )
    }

    #[test]
    fn bootstrap_parses_valid_toml() {
        let members: String = (0..3).map(|_| member_table(&Identity::generate())).collect();
        let toml = format!(
            r#"
identity_path = "/tmp/identity"

[network]
listen = "/ip4/0.0.0.0/tcp/7100"
bootstrap_peers = ["/dns4/seed/tcp/7100/p2p/12D3KooW..."]

[governance]
threshold = 2
{members}
[committee]
public_round_ms = 2000
protocol = "panetiere"
aggregation = false"#
        );
        let cfg = BootstrapConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.governance.committee.len(), 3);
        assert_eq!(cfg.governance.threshold, 2);
        assert_eq!(cfg.network.bootstrap_peers.len(), 1);
        assert!(cfg.governance.committee[0].exchange_pubkey.to_key().is_ok());
        // Present fields parse; omitted committee fields fall back to defaults.
        assert_eq!(cfg.committee.public_round_ms, 2000);
        assert_eq!(cfg.committee.committee_round_ms, 10_000);
        assert_eq!(cfg.committee.protocol.as_deref(), Some("panetiere"));
        assert!(!cfg.committee.aggregation);
        // A config with no `[committee]` section at all uses all defaults.
        let no_committee = BootstrapConfig::from_toml_str(&toml.replace("[committee]\npublic_round_ms = 2000\nprotocol = \"panetiere\"\naggregation = false", "")).unwrap();
        assert_eq!(no_committee.committee.public_round_ms, 4000);
        assert_eq!(no_committee.committee.protocol, None);
        assert!(no_committee.committee.aggregation);
    }

    #[test]
    fn bootstrap_rejects_threshold_too_high() {
        let member = member_table(&Identity::generate());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 2
{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::BadThreshold { .. }));
    }

    #[test]
    fn bootstrap_rejects_zero_threshold() {
        let member = member_table(&Identity::generate());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 0
{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::BadThreshold { .. }));
    }

    #[test]
    fn bootstrap_rejects_duplicate_committee() {
        let id = Identity::generate();
        let member = member_table(&id);
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 1
{member}{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::DuplicateCommitteeMember(_)));
    }

    #[test]
    fn bootstrap_rejects_malformed_pubkey() {
        let xpub =
            crate::config::ExchangePublicKeyWire::from_key(&Identity::generate().exchange_pubkey());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 1
[[governance.committee]]
pubkey = "not-a-key"
exchange_pubkey = "{}"
"#,
            hex::encode(&xpub.0),
        );
        assert!(BootstrapConfig::from_toml_str(&toml).is_err());
    }
}
