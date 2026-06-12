//! Governance topic plumbing.
//!
//! Anymone configs are gossiped on `anymone/config` and signed by the
//! committee. Every node verifies the multisig before acting on a config.
//! Registration goes on `anymone/registration`; faults on `anymone/faults`.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::sleep;

use crate::config::{AnymoneRoundConfiguration, Round, SubnetId};
use crate::identity::Pubkey;
use crate::session::Fault;
use crate::transport::Transport;

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
    pub fn from_bootstrap_config(cfg: &crate::identity::BootstrapConfig) -> Self {
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
}
