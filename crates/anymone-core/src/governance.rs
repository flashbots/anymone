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
use crate::transport::{NetView, Topic};

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

pub const TOPIC_CONFIG: Topic = Topic::Config;
pub const TOPIC_REGISTRATION: Topic = Topic::Registration;
pub const TOPIC_FAULTS: Topic = Topic::Faults;

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

/// A config's network view, applied to the transport whole on every adoption.
///
/// Topic admission: subnet shares/broadcast topics bound to that subnet's
/// relays (+ aggregators), faults to the union of all relays, config to the
/// committee. A Noop subnet's broadcast stays open — its whole protocol
/// (client contributions included) rides that topic. Peer sets: primary =
/// committee + relays + aggregators (dialed outbound), secondary = watchers
/// (inbound only); services live on the client plane and are not peers.
pub fn net_view(body: &AnymoneRoundConfigurationBody, committee: &[Pubkey]) -> NetView {
    use std::collections::{HashMap, HashSet};
    let mut senders: HashMap<Topic, HashSet<Pubkey>> = HashMap::new();
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
        senders.insert(Topic::Shares(subnet.id), shares);
        if !matches!(subnet.protocol, crate::config::ProtocolConfig::Noop(_)) {
            senders.insert(
                Topic::Broadcast(subnet.id),
                subnet.relays.iter().copied().collect(),
            );
        }
        all_relays.extend(subnet.relays.iter().copied());
    }
    senders.insert(Topic::Faults, all_relays);
    senders.insert(Topic::Config, committee.iter().copied().collect());

    let mut primary: Vec<Pubkey> = committee.to_vec();
    for subnet in &body.subnets {
        primary.extend(subnet.relays.iter().copied());
        if let Some(agg) = crate::runtime::subnet_aggregation(subnet) {
            primary.extend(
                agg.groups
                    .iter()
                    .flat_map(|g| g.aggregators.iter().copied()),
            );
        }
    }
    primary.sort();
    primary.dedup();
    let mut secondary: Vec<Pubkey> = body
        .watchers
        .iter()
        .copied()
        .filter(|pk| primary.binary_search(pk).is_err())
        .collect();
    secondary.sort();
    secondary.dedup();

    let mut registration_recipients: Vec<Pubkey> = committee
        .iter()
        .chain(body.watchers.iter())
        .copied()
        .collect();
    registration_recipients.sort();
    registration_recipients.dedup();

    NetView {
        index: body.round,
        senders,
        primary,
        secondary,
        registration_recipients,
        relay_client_addrs: body.relay_client_addrs.clone(),
        subnets: body.subnets.iter().map(|s| s.id).collect(),
    }
}
