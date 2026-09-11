use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnymoneRoundConfiguration, GovernanceConfig, Pubkey, ServiceTag};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub version: u16,
    pub governance: GovernanceConfig,
}

impl Genesis {
    pub fn new(mut governance: GovernanceConfig) -> Self {
        governance.committee.sort_by_key(|member| member.pubkey);
        Self { version: 1, governance }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let committee = &self.governance.committee;
        if self.version != 1 || committee.is_empty() || committee.len() > 256
            || self.governance.threshold == 0
            || self.governance.threshold as usize > committee.len()
            || committee.windows(2).any(|members| members[0].pubkey >= members[1].pubkey)
        {
            return Err(Error::Invalid("invalid genesis"));
        }
        Ok(())
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(bincode::serialize(&(b"anymone/genesis/v1", self)).expect("genesis serializes")).into()
    }

    pub fn verify_config(&self, config: &AnymoneRoundConfiguration) -> Result<(), Error> {
        self.validate()?;
        config.verify_multisig(
            &self.governance.committee.iter().map(|member| member.pubkey).collect::<Vec<_>>(),
            self.governance.threshold,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoints {
    pub nodes: Vec<(Pubkey, String)>,
    pub services: Vec<(ServiceTag, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub genesis: Genesis,
    pub config: AnymoneRoundConfiguration,
}

pub fn check_config(genesis: &Genesis, config: &AnymoneRoundConfiguration,
                    previous: Option<&AnymoneRoundConfiguration>) -> Result<(), Error> {
    genesis.verify_config(config)?;
    if previous.is_some_and(|previous| config.body.round < previous.body.round
        || (config.body.round == previous.body.round && config.body != previous.body)) {
        return Err(Error::Invalid("configuration rollback or equivocation"));
    }
    Ok(())
}

pub fn valid_endpoint(endpoint: Option<&str>) -> bool {
    endpoint.is_none_or(|url| url.len() <= 2048 && (url.starts_with("https://") || url.starts_with("http://")))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Config(#[from] crate::ConfigError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitteeMember, Identity, NoopConfig, ProtocolConfig, Registration};

    #[test]
    fn configuration_authentication_and_rollback() {
        let identity = Identity::generate();
        let genesis = Genesis::new(GovernanceConfig { threshold: 1, committee: vec![CommitteeMember {
            pubkey: identity.pubkey(), exchange_pubkey: identity.exchange_keys(),
        }] });
        let mut config = AnymoneRoundConfiguration::singleton_subnet(5,
            ProtocolConfig::Noop(NoopConfig { round_duration_ms: 1000, message_size: 256,
                client_set_min: 0, client_set_max: 8 }), vec![], vec![], vec![]);
        config.body.endpoints.nodes.push((identity.pubkey(), "https://node.example".into()));
        config = config.sign_with(&[&identity]);
        check_config(&genesis, &config, None).unwrap();
        let decoded = AnymoneRoundConfiguration::decode(&bincode::serialize(&config).unwrap()).unwrap();
        assert_eq!(decoded, config);
        let mut changed = config.clone();
        changed.body.endpoints.nodes[0].1 = "https://other.example".into();
        assert!(check_config(&genesis, &changed, None).is_err());
        changed.signatures.clear();
        changed = changed.sign_with(&[&identity]);
        assert!(check_config(&genesis, &changed, Some(&config)).is_err());
        changed.body.round = 4;
        changed.signatures.clear();
        changed = changed.sign_with(&[&identity]);
        assert!(check_config(&genesis, &changed, Some(&config)).is_err());
        let mut invalid = genesis.clone();
        invalid.governance.threshold = 0;
        assert!(invalid.validate().is_err());
        assert_ne!(invalid.hash(), genesis.hash());
        invalid = genesis.clone();
        invalid.governance.committee.push(invalid.governance.committee[0].clone());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn registrations_sign_endpoint_fields() {
        let identity = Identity::generate();
        let mut relay = Registration::relay_endpoints(&identity, identity.exchange_keys(),
            Some("127.0.0.1:7600".into()), Some("https://node.example".into()));
        assert!(relay.verify());
        if let Registration::Relay { rpc_url, .. } = &mut relay { *rpc_url = Some("https://other.example".into()); }
        assert!(!relay.verify());
        let mut service = Registration::service_at(&identity, ServiceTag::from_label("ethereum"),
            identity.exchange_keys(), Some("https://service.example/descriptor".into()));
        assert!(service.verify());
        if let Registration::Service { descriptor_url, .. } = &mut service { *descriptor_url = None; }
        assert!(!service.verify());
    }
}
