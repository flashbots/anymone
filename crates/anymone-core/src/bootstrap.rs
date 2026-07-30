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
    /// `host:port` this node accepts backbone connections on.
    #[serde(default)]
    pub listen_addr: Option<String>,
    /// Address peers dial us on; `listen_addr` unless behind a NAT.
    #[serde(default)]
    pub dialable_addr: Option<String>,
    /// `ed25519:<hex>@host:port`.
    #[serde(default)]
    pub bootstrappers: Vec<String>,
    /// Backbone peers reachable before the first signed config, beyond the committee.
    #[serde(default)]
    pub genesis_peers: Vec<Pubkey>,
    /// `host:port` clients dial to reach this node; absent serves no clients.
    #[serde(default)]
    pub stream_listen: Option<String>,
    /// `ed25519:<hex>@host:port` of nodes a client dials.
    #[serde(default)]
    pub stream_bootstrappers: Vec<String>,
    /// Loopback deployment: allow private IPs and discover faster.
    #[serde(default)]
    pub local: bool,
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

    /// Build the backbone listen/bootstrapper config. The genesis peer set is
    /// the committee plus `network.genesis_peers`.
    pub fn commonware_config(
        &self,
        good_clients: crate::session::GoodClients,
    ) -> Result<crate::cw::CommonwareConfig, BootstrapError> {
        let listen_str = self
            .network
            .listen_addr
            .as_deref()
            .ok_or(BootstrapError::MissingListenAddr)?;
        let listen = listen_str
            .parse()
            .map_err(|_| BootstrapError::BadSocketAddr(listen_str.to_string()))?;
        let dialable = match self.network.dialable_addr.as_deref() {
            Some(s) => s
                .parse()
                .map_err(|_| BootstrapError::BadSocketAddr(s.to_string()))?,
            None => listen,
        };
        let bootstrappers = self
            .network
            .bootstrappers
            .iter()
            .map(|s| parse_peer_addr(s))
            .collect::<Result<_, BootstrapError>>()?;
        let stream_listen = match self.network.stream_listen.as_deref() {
            Some(s) => Some(
                s.parse()
                    .map_err(|_| BootstrapError::BadSocketAddr(s.to_string()))?,
            ),
            None => None,
        };
        let mut genesis_peers: Vec<Pubkey> =
            self.governance.committee.iter().map(|m| m.pubkey).collect();
        genesis_peers.extend(self.network.genesis_peers.iter().copied());
        Ok(crate::cw::CommonwareConfig {
            listen,
            dialable,
            bootstrappers,
            genesis_peers,
            local: self.network.local,
            stream_listen,
            good_clients,
        })
    }

    /// Servers a client-plane process dials.
    pub fn stream_client_config(&self) -> Result<crate::cw::StreamClientConfig, BootstrapError> {
        let servers = self
            .network
            .stream_bootstrappers
            .iter()
            .map(|s| parse_peer_addr(s))
            .collect::<Result<Vec<_>, _>>()?;
        if servers.is_empty() {
            return Err(BootstrapError::NoStreamServers);
        }
        Ok(crate::cw::StreamClientConfig { servers })
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

/// `ed25519:<hex>@host:port`.
fn parse_peer_addr(s: &str) -> Result<(Pubkey, std::net::SocketAddr), BootstrapError> {
    let (pk, addr) = s
        .rsplit_once('@')
        .ok_or_else(|| BootstrapError::BadBootstrapper(s.to_string()))?;
    let pk: Pubkey = pk
        .parse()
        .map_err(|_| BootstrapError::BadBootstrapper(s.to_string()))?;
    let addr = addr
        .parse()
        .map_err(|_| BootstrapError::BadSocketAddr(addr.to_string()))?;
    Ok((pk, addr))
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
    #[error("bad socket address: {0}")]
    BadSocketAddr(String),
    #[error("bad bootstrapper, expected `ed25519:<hex>@host:port`: {0}")]
    BadBootstrapper(String),
    #[error("network.listen_addr is required by a backbone node")]
    MissingListenAddr,
    #[error("network.stream_bootstrappers is required by a client-plane process")]
    NoStreamServers,
    #[error("transport start: {0}")]
    TransportStart(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// A `[[governance.committee]]` table for a fresh identity.
    fn member_table(id: &Identity) -> String {
        format!(
            "[[governance.committee]]\npubkey = \"{}\"\nexchange_pubkey = {}\n",
            id.pubkey(),
            exchange_keys_inline(id),
        )
    }

    /// The `exchange_pubkey` value as a TOML inline table.
    fn exchange_keys_inline(id: &Identity) -> String {
        let xk = id.exchange_keys();
        format!(
            "{{ ecdh = \"{}\", kem = \"{}\" }}",
            hex::encode(&xk.ecdh),
            hex::encode(&xk.kem),
        )
    }

    #[test]
    fn bootstrap_parses_valid_toml() {
        let members: String = (0..3)
            .map(|_| member_table(&Identity::generate()))
            .collect();
        let seed = Identity::generate();
        let seed_pubkey = seed.pubkey();
        let toml = format!(
            r#"
identity_path = "/tmp/identity"

[network]
listen_addr = "0.0.0.0:7100"
bootstrappers = ["{seed_pubkey}@10.0.0.1:7100"]
genesis_peers = ["{seed_pubkey}"]

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
        assert!(cfg.governance.committee[0].exchange_pubkey.to_key().is_ok());
        let cw = cfg
            .commonware_config(crate::session::GoodClients::all())
            .unwrap();
        assert_eq!(cw.listen.to_string(), "0.0.0.0:7100");
        // Absent `dialable_addr` falls back to the listen address.
        assert_eq!(cw.dialable, cw.listen);
        assert_eq!(
            cw.bootstrappers,
            vec![(seed_pubkey, "10.0.0.1:7100".parse().unwrap())]
        );
        assert_eq!(
            cw.genesis_peers.len(),
            4,
            "genesis = the committee plus network.genesis_peers"
        );
        assert!(cw.genesis_peers.contains(&seed_pubkey));
        // Present fields parse; omitted committee fields fall back to defaults.
        assert_eq!(cfg.committee.public_round_ms, 2000);
        assert_eq!(cfg.committee.committee_round_ms, 10_000);
        assert_eq!(cfg.committee.protocol.as_deref(), Some("panetiere"));
        assert!(!cfg.committee.aggregation);
        // The client plane a deployment renders for a bot/forwarder: streams to
        // dial and nothing else, so it joins no peer set.
        let client = BootstrapConfig::from_toml_str(&format!(
            r#"
identity_path = "/tmp/identity"

[network]
stream_bootstrappers = ["{seed_pubkey}@10.0.0.1:7600"]

[governance]
threshold = 2
{members}"#
        ))
        .unwrap();
        assert_eq!(client.stream_client_config().unwrap().servers.len(), 1);
        assert!(matches!(
            client.commonware_config(crate::session::GoodClients::all()),
            Err(BootstrapError::MissingListenAddr)
        ));
        // A config with no `[committee]` section at all uses all defaults.
        let no_committee = BootstrapConfig::from_toml_str(&toml.replace(
            "[committee]\npublic_round_ms = 2000\nprotocol = \"panetiere\"\naggregation = false",
            "",
        ))
        .unwrap();
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
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 1
[[governance.committee]]
pubkey = "not-a-key"
exchange_pubkey = {}
"#,
            exchange_keys_inline(&Identity::generate()),
        );
        assert!(BootstrapConfig::from_toml_str(&toml).is_err());
    }
}
