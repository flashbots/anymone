//! anymone — anonymous broadcast channel meta-protocol.
//!
//! See `IMPLEMENTATION.md` at the repo root for design and milestones.
//! This crate is the entire library; binaries (`anymone-node`, `anymone-masque`)
//! are thin shells over it.

pub mod adcnet;
pub mod backend;
pub mod bootstrap;
pub mod client_pool;
pub mod client_set;
pub mod committee;
pub mod config;
pub mod cw;
pub mod faults;
pub mod governance;
pub mod identity;
pub mod keys;
pub mod log_target;
pub mod noop;
pub mod panetiere;
pub mod panetiere_scheduled;
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
pub use bootstrap::{BootstrapConfig, NetworkConfig};
pub use client_pool::{ClientPool, PoolError, SpawnClient};
pub use committee::{
    committee_roster, spawn_panetiere_committee_scheduler, CommitteeParams,
    PanetiereCommitteeConfig,
};
pub use config::{
    AdcnetConfig, AnymoneRoundConfiguration, AnymoneRoundConfigurationBody, ConfigError,
    NoopConfig, NymConfig, PanetiereConfig, ProtocolConfig, Round, ScheduledAdcnetConfig,
    ServiceEntry, Signature, Subnet, SubnetId,
};
pub use faults::{Attribution, Fault, FaultKind, OutputFaultTracker};
pub use governance::{
    CommitteeMember, FaultReport, GovernanceBootstrap, GovernanceConfig, GovernanceError,
    TOPIC_CONFIG, TOPIC_FAULTS, TOPIC_REGISTRATION,
};
pub use identity::{Identity, Pubkey};
pub use panetiere::{
    PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, PanetiereWatchSession,
};
pub use pipe::{max_message_payload, Pipe, PipeIncoming, SendError};
pub use runtime::{leader_of, subnet_leader_pk, Anymone, AnymonePrep, Event, OpenError};
pub use scheduler_core::{SchedulerAction, SchedulerCore, SchedulerParams, SignedProposal};
pub use scheduling::{
    announce_relay_registration, announce_relay_registration_at, announce_service_registration,
    announce_watcher_registration, Registration, SchedulerProtocol,
};
pub use session::{GoodClients, LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
pub use tee::{
    Attestation, AttestationScheme, AttestedClients, MultiVerifier, TeeError, TeeProver,
    TeeVerifier,
};
#[cfg(feature = "tdx-attest")]
pub use tee::{TdxProver, TdxVerifier};
pub use transport::{
    Dest, InMemoryHandle, InMemoryNetwork, Inbound, NetView, Subscription, Topic, Transport,
};
pub use wire::{Frame, RouteTag, ServiceTag, WireError};
