//! Governance topic plumbing.
//!
//! Anymone configs are gossiped on `anymone/config` and signed by the
//! committee. Every node verifies the multisig before acting on a config.
//! Registration goes on `anymone/registration`; faults on `anymone/faults`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{AnymoneRoundConfigurationBody, ExchangePublicKeyWire, Round, SubnetId};
use crate::faults::Fault;
use crate::identity::Pubkey;
use crate::transport::TopicPolicy;

/// The committee + threshold a deployment configures (the `[governance]` section
/// of the bootstrap TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub committee: Vec<CommitteeMember>,
    pub threshold: u32,
}

/// A committee member as configured: its identity pubkey plus the exchange
/// pubkey the internal committee Panetiere needs to seal openings to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub pubkey: Pubkey,
    pub exchange_pubkey: ExchangePublicKeyWire,
}

impl GovernanceConfig {
    /// The committee roster (pubkey + exchange pubkey) the committee scheduler
    /// takes — so callers don't re-assemble it field-by-field.
    pub fn roster(&self) -> Vec<(Pubkey, ExchangePublicKeyWire)> {
        self.committee
            .iter()
            .map(|m| (m.pubkey, m.exchange_pubkey.clone()))
            .collect()
    }
}

pub const TOPIC_CONFIG: &str = "anymone/config";
pub const TOPIC_REGISTRATION: &str = "anymone/registration";
pub const TOPIC_FAULTS: &str = "anymone/faults";

/// A fault a node observed on a subnet, gossiped on `anymone/faults` for the
/// committee and any auditor. `reporter` is the observing node; the embedded
/// [`Fault`] carries kind, attribution, and opaque re-verifiable evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultReport {
    pub round: Round,
    pub subnet: SubnetId,
    pub reporter: Pubkey,
    pub fault: Fault,
}

impl FaultReport {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("fault report serialises")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// What each node needs to know up front to verify configs gossiped on the
/// network: the committee pubkeys and the signature threshold.
#[derive(Debug, Clone)]
pub struct GovernanceBootstrap {
    pub committee: Vec<Pubkey>,
    pub threshold: u32,
}

impl GovernanceBootstrap {
    pub fn from_bootstrap_config(cfg: &crate::bootstrap::BootstrapConfig) -> Self {
        GovernanceBootstrap {
            committee: cfg.governance.committee.iter().map(|m| m.pubkey).collect(),
            threshold: cfg.governance.threshold,
        }
    }
}

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("config topic closed before any valid configuration arrived")]
    TopicClosed,
    #[error("no valid configuration arrived within the startup deadline")]
    Timeout,
}

/// Topic admission for an adopted config: subnet shares/broadcast topics bound
/// to that subnet's relays (+ aggregators), faults to the union of all relays,
/// config to the committee. Ingress and per-group aggregator topics stay open
/// — clients are permissionless and can't be bound to a fixed roster. Noop
/// subnets run their whole protocol (client contributions included) over the
/// broadcast topic, so theirs stays open too.
pub fn topic_policy(body: &AnymoneRoundConfigurationBody, committee: &[Pubkey]) -> TopicPolicy {
    use std::collections::HashSet;
    let mut policy = TopicPolicy::new();
    let mut all_relays: HashSet<Pubkey> = HashSet::new();
    for subnet in &body.subnets {
        let mut shares: HashSet<Pubkey> = subnet.relays.iter().copied().collect();
        if let Some(agg) = crate::runtime::subnet_aggregation(subnet) {
            shares.extend(
                agg.groups
                    .iter()
                    .flat_map(|g| g.aggregators.iter().copied()),
            );
        }
        policy.insert(crate::runtime::subnet_shares_topic(subnet.id), shares);
        if !matches!(subnet.protocol, crate::config::ProtocolConfig::Noop(_)) {
            policy.insert(
                crate::runtime::subnet_broadcast_topic(subnet.id),
                subnet.relays.iter().copied().collect(),
            );
        }
        all_relays.extend(subnet.relays.iter().copied());
    }
    policy.insert(TOPIC_FAULTS.to_string(), all_relays);
    policy.insert(
        TOPIC_CONFIG.to_string(),
        committee.iter().copied().collect(),
    );
    policy
}
