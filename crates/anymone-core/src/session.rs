//! Per-(node, subnet, role) state machine driving one subnet's rounds.
//!
//! The runtime owns the clock and tells a session when a round starts and ends.
//! Between those calls, the runtime feeds it peer-authenticated inbound bytes
//! as they arrive. The session itself is otherwise inert — no transport, no
//! async, no internal time.
//!
//! Anymone always broadcasts session outputs on the subnet's p2p topic; there
//! is no unicast in the trait. Every member receives every message and filters
//! locally.

use std::collections::HashMap;
use std::time::Instant;

use crate::config::{Aggregation, Round};
use crate::faults::Fault;
use crate::identity::Pubkey;

/// An ADCNet leader's view of the aggregator layer: which pubkeys may sign each
/// group's aggregate.
pub struct LeaderAggregation {
    pub roster: HashMap<u32, Vec<Pubkey>>,
}

impl LeaderAggregation {
    pub fn from_config(a: &Aggregation) -> Self {
        let roster = a
            .groups
            .iter()
            .enumerate()
            .map(|(i, g)| (i as u32, g.aggregators.clone()))
            .collect();
        LeaderAggregation { roster }
    }
}

/// Identifier for the peer a message arrived from: a node's long-lived
/// `Pubkey`, which is also what the transport authenticates the link against.
pub type PeerId = Pubkey;

/// Which client keys a relay accepts contributions from. The demo admits
/// everyone; a deployment restricts it to attested clients.
#[derive(Clone)]
pub struct GoodClients(std::sync::Arc<dyn Fn(&Pubkey) -> bool + Send + Sync>);

impl GoodClients {
    pub fn all() -> Self {
        GoodClients(std::sync::Arc::new(|_| true))
    }

    pub fn new(f: impl Fn(&Pubkey) -> bool + Send + Sync + 'static) -> Self {
        GoodClients(std::sync::Arc::new(f))
    }

    pub fn allows(&self, client: &Pubkey) -> bool {
        (self.0)(client)
    }
}

impl Default for GoodClients {
    fn default() -> Self {
        GoodClients::all()
    }
}

pub trait Session: Send {
    /// Set up state for `round`. Returns messages to broadcast at round start.
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>>;

    /// Hand a peer-authenticated inbound message to the session.
    /// May produce more outbound (e.g. share exchanges, acks).
    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>>;

    /// Close `round`. Produces decoded payloads, faults, and any last-gasp
    /// outbound (e.g. final decryption shares).
    fn end_round(&mut self, round: Round, now: Instant) -> RoundOutcome;

    /// Emit at intra-round checkpoint `k` (1-based, protocol-defined). Default: nothing.
    fn checkpoint(&mut self, _round: Round, _k: u8, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Stage a payload for transmission on the next round.
    /// Default impl: no-op (server / watch sessions ignore this).
    fn stage(&mut self, _payload: Vec<u8>) {}

    /// Adopt a new cover rate from a config change. Client sessions that
    /// originate cover honor it; others ignore it.
    fn set_cover_rate(&mut self, _rate: f32) {}

    /// Byzantine misbehavior policy (demo/testing). `None` is honest. A server
    /// session honors it; clients/watchers ignore it. Default: honest.
    fn set_misbehavior(&mut self, _mode: Option<Misbehavior>) {}
}

/// A relay's deliberate misbehavior, for fault-injection demos and tests.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Misbehavior {
    /// Withhold the decryption share entirely
    Withhold,
    /// Contribute a signed share computed over tampered key material
    CorruptShare,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RoundOutcome {
    pub outbound: Vec<Vec<u8>>,
    /// Wire-format `Message`s decoded this round. The runtime parses headers,
    /// reassembles fragments, and routes by service tag.
    pub decoded: Vec<Vec<u8>>,
    pub faults: Vec<Fault>,
}
