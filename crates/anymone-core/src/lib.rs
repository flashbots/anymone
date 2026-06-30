//! anymone — anonymous broadcast channel meta-protocol.
//!
//! See `IMPLEMENTATION.md` at the repo root for design and milestones.
//! This crate is the entire library; binaries (`anymone-node`, `anymone-masque`)
//! are thin shells over it.

pub mod adcnet;
pub mod bootstrap;
pub mod committee;
pub mod config;
pub mod faults;
pub mod governance;
pub mod identity;
pub mod keys;
pub mod noop;
pub mod p2p;
pub mod panetiere;
pub mod pipe;
pub mod runtime;
pub mod scheduler_core;
pub mod scheduling;
pub mod session;
pub mod tee;
pub mod transport;
pub mod wire;
pub mod wire_debug;

#[cfg(feature = "test-util")]
pub mod test_util;

pub use adcnet::AdcnetObserverSession;
pub use committee::{
    committee_roster, spawn_panetiere_committee_scheduler, PanetiereCommitteeConfig,
};
pub use config::{
    AdcnetConfig, AnymoneRoundConfiguration, AnymoneRoundConfigurationBody, ConfigError,
    NoopConfig, NymConfig, PanetiereConfig, ProtocolConfig, Round, ScheduledAdcnetConfig,
    ServiceEntry, Signature, Subnet, SubnetId,
};
pub use bootstrap::{BootstrapConfig, NetworkConfig};
pub use governance::{
    CommitteeMember, FaultReport, GovernanceBootstrap, GovernanceConfig, GovernanceError,
    TOPIC_CONFIG, TOPIC_FAULTS, TOPIC_REGISTRATION,
};
pub use identity::{Identity, Pubkey};
pub use panetiere::{
    PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, PanetiereWatchSession,
};
pub use pipe::{Pipe, PipeIncoming, SendError};
pub use runtime::{Anymone, AnymonePrep, Event, OpenError};
pub use scheduler_core::{SchedulerAction, SchedulerCore, SchedulerParams, SignedProposal};
pub use scheduling::{
    announce_relay_registration, announce_service_registration, Registration,
};
pub use faults::{Attribution, Fault, FaultKind, OutputFaultTracker};
pub use session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
pub use tee::{NoopProver, TeeProver, TeeVerifier};
pub use transport::{InMemoryHandle, InMemoryNetwork, Inbound, Subscription, Transport};
pub use wire::{Frame, ServiceTag, WireError};
