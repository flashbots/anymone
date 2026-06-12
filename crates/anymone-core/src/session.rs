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

use serde::{Deserialize, Serialize};

use crate::config::Round;
use crate::identity::Pubkey;

/// A leader's view of an aggregator layer: which pubkeys may sign each group's
/// aggregate. Shared by both protocols' leaders.
pub struct LeaderAggregation {
    pub roster: HashMap<u32, Vec<Pubkey>>,
}

/// Identifier for the peer a message arrived from. Same shape as a node's
/// long-lived `Pubkey` — libp2p PeerIds are derived from it.
pub type PeerId = Pubkey;

pub trait Session: Send {
    /// Set up state for `round`. Returns messages to broadcast at round start.
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>>;

    /// Hand a peer-authenticated inbound message to the session.
    /// May produce more outbound (e.g. share exchanges, acks).
    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>>;

    /// Close `round`. Produces decoded payloads, faults, and any last-gasp
    /// outbound (e.g. final decryption shares).
    fn end_round(&mut self, round: Round, now: Instant) -> RoundOutcome;

    /// Emit partway through `round`, before it closes (e.g. an aggregator
    /// forwarding its batch early). Default: nothing.
    fn mid_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Stage a payload for transmission on the next round.
    /// Default impl: no-op (server / watch sessions ignore this).
    fn stage(&mut self, _payload: Vec<u8>) {}

    /// Runtime cover-traffic policy for the upcoming round. When `false`, an
    /// idle client session sits the round out instead of contributing its zero
    /// message; a real staged payload is always sent regardless. Sessions that
    /// don't originate cover ignore this. Default: cover.
    fn set_cover(&mut self, _cover: bool) {}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    pub kind: FaultKind,
    pub attribution: Attribution,
    /// Protocol-specific evidence
    #[serde(with = "serde_bytes")]
    pub evidence: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    Decryption,
    Integrity,
    Liveness,
    Censorship,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attribution {
    None,
    Peers(Vec<PeerId>),
}

/// Per-round subnet observation that detects liveness faults the way the
/// committee does (see the ADCNet fault-model memory): **missing decoded
/// output is the trigger**, and attribution is only possible when output is
/// missing *and* only some relays' aggregate decryption shares were seen.
///
/// A protocol observer session feeds it three things — a relay published a
/// share for round R ([`Self::observe_share`]), an output appeared for round R
/// ([`Self::observe_output`]), and "evaluate every round below this frontier"
/// ([`Self::evaluate`]). It emits a single `Liveness` fault once `threshold`
/// consecutive superseded rounds have produced no output. The wire-specific
/// recognition of share / output messages lives in the protocol session;
/// this is the shared, protocol-agnostic bookkeeping.
pub struct OutputFaultTracker {
    /// Sorted relay roster; index = the protocol's server index.
    roster: Vec<PeerId>,
    /// Consecutive failed (output-less) rounds needed to fault.
    threshold: u64,
    /// How many share-rounds output may fail to advance before we call it
    /// *frozen* (stalled) rather than merely lagging. Larger than the protocol's
    /// share→output latency so jitter never trips it.
    stall_margin: u64,
    shares: std::collections::HashMap<u64, std::collections::HashSet<usize>>,
    outputs: std::collections::HashSet<u64>,
    /// Highest round we've seen any share for (the subnet's liveness frontier).
    max_share_round: Option<u64>,
    /// Highest round we've seen an output for.
    max_output_round: Option<u64>,
    /// `max_share_round` at the moment output last advanced (or at the first
    /// share if output has never appeared). The gap between this and the
    /// current `max_share_round` tells lag (output still advancing → small
    /// gap) from a stall (output frozen → gap grows without bound).
    share_at_last_output: Option<u64>,
    /// Highest round we've already evaluated.
    evaluated_through: Option<u64>,
    /// Missing-relay sets for the current run of consecutive failed rounds.
    fail_run: Vec<std::collections::HashSet<usize>>,
    emitted: bool,
}

const DEFAULT_STALL_MARGIN: u64 = 4;

impl OutputFaultTracker {
    pub fn new(roster: Vec<PeerId>, threshold: u64) -> Self {
        OutputFaultTracker {
            roster,
            threshold: threshold.max(1),
            stall_margin: DEFAULT_STALL_MARGIN,
            shares: std::collections::HashMap::new(),
            outputs: std::collections::HashSet::new(),
            max_share_round: None,
            max_output_round: None,
            share_at_last_output: None,
            evaluated_through: None,
            fail_run: Vec::new(),
            emitted: false,
        }
    }

    pub fn observe_share(&mut self, round: u64, idx: usize) {
        if idx < self.roster.len() {
            self.shares.entry(round).or_default().insert(idx);
            self.max_share_round = Some(self.max_share_round.map_or(round, |m| m.max(round)));
            // Anchor the lag baseline at the first share, so the gap starts at
            // zero rather than counting from round 0 for a late-joining observer.
            self.share_at_last_output.get_or_insert(round);
        }
    }

    pub fn observe_output(&mut self, round: u64) {
        self.outputs.insert(round);
        let advanced = self.max_output_round.map_or(true, |m| round > m);
        if advanced {
            self.max_output_round = Some(self.max_output_round.map_or(round, |m| m.max(round)));
            // Output just advanced → reset the lag baseline to "now".
            self.share_at_last_output = self.max_share_round.or(Some(round));
        }
    }

    /// True when output has stopped advancing while shares have moved on by
    /// more than `stall_margin` rounds — a stall, not transient lag.
    fn output_frozen(&self) -> bool {
        match (self.max_share_round, self.share_at_last_output) {
            (Some(s), Some(base)) => s.saturating_sub(base) > self.stall_margin,
            _ => false,
        }
    }

    /// Process superseded rounds in order. A round with output succeeds (and
    /// resets the failure run). A round without output is **deferred** while
    /// output is merely lagging (still advancing), and only judged **failed**
    /// once output is frozen. `threshold` consecutive failed rounds emit one
    /// `Liveness` fault: attributed to the relays missing in every round of the
    /// run if that's a proper non-empty subset, else unattributable.
    pub fn evaluate(&mut self) -> Vec<Fault> {
        let mut faults = Vec::new();
        if self.emitted {
            return faults;
        }
        let Some(frontier) = self.max_share_round else {
            return faults;
        };
        let start = self.evaluated_through.map_or_else(
            || self.shares.keys().min().copied().unwrap_or(frontier),
            |r| r + 1,
        );
        // Only judge rounds the subnet has moved past (a later share exists).
        for r in start..frontier {
            if self.outputs.contains(&r) {
                self.evaluated_through = Some(r);
                self.fail_run.clear();
                continue;
            }
            // A round nobody published a share for never *ran* — no relay
            // announced or contributed to a canonical set (e.g. a quiet round
            // with no client traffic, or a label skipped by round-counter
            // drift between the client and the leader). That is not a relay
            // liveness failure: there was no output to expect. Skip it
            // transparently — don't reset the failure run, don't count it —
            // so spurious all-missing rounds can't masquerade as an
            // unattributable stall.
            let shared = self.shares.get(&r).cloned().unwrap_or_default();
            if shared.is_empty() {
                self.evaluated_through = Some(r);
                continue;
            }
            // No output for r, but it did run. It's a failure only if either
            // output has moved *past* r (outputs are in order, so a later
            // output means r was skipped — fast, no margin) or output is frozen
            // (stalled). If neither, output may simply be lagging and still
            // coming — defer.
            let skipped = self.max_output_round.map_or(false, |m| m > r);
            if !(skipped || self.output_frozen()) {
                break;
            }
            let missing: std::collections::HashSet<usize> = (0..self.roster.len())
                .filter(|i| !shared.contains(i))
                .collect();
            self.evaluated_through = Some(r);
            self.fail_run.push(missing);
            if self.fail_run.len() as u64 >= self.threshold {
                let mut culprits = self.fail_run[0].clone();
                for s in &self.fail_run[1..] {
                    culprits = culprits.intersection(s).copied().collect();
                }
                let attribution = if !culprits.is_empty() && culprits.len() < self.roster.len() {
                    let mut pks: Vec<PeerId> = culprits.iter().map(|i| self.roster[*i]).collect();
                    pks.sort();
                    Attribution::Peers(pks)
                } else {
                    Attribution::None
                };
                faults.push(Fault {
                    kind: FaultKind::Liveness,
                    attribution,
                    evidence: Vec::new(),
                });
                self.emitted = true;
                break;
            }
        }
        faults
    }

    /// Highest round any relay has published a share for (the liveness
    /// frontier). `None` before the first share is seen.
    pub fn share_frontier(&self) -> Option<u64> {
        self.max_share_round
    }

    /// Highest round that has produced decoded output. `None` before the first
    /// output is seen.
    pub fn output_frontier(&self) -> Option<u64> {
        self.max_output_round
    }

    /// Roster indices of relays that published a share within `window` rounds of
    /// the share frontier — the relays observably alive right now. Empty before
    /// any share is seen. Used to surface per-relay liveness on the dashboard.
    pub fn relays_shared_recent(&self, window: u64) -> Vec<usize> {
        let Some(frontier) = self.max_share_round else {
            return Vec::new();
        };
        let oldest = frontier.saturating_sub(window);
        let mut idxs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for (round, set) in &self.shares {
            if *round >= oldest {
                idxs.extend(set.iter().copied());
            }
        }
        let mut v: Vec<usize> = idxs.into_iter().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn roster(n: usize) -> Vec<PeerId> {
        (0..n).map(|_| Identity::generate().pubkey()).collect()
    }

    #[test]
    fn healthy_rounds_no_fault() {
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        for round in 0..5u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
            t.observe_output(round);
        }
        assert!(t.evaluate().is_empty());
    }

    #[test]
    fn two_failed_rounds_attribute_to_missing_relay() {
        let r = roster(3);
        let victim = r[1];
        let mut t = OutputFaultTracker::new(r, 2);
        // Rounds 0,1 healthy.
        for round in 0..2u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
            t.observe_output(round);
        }
        // Rounds 2.. : relay #1 silent, no output. Run long enough for the
        // share frontier to outrun the (frozen) output past the stall margin.
        for round in 2..12u64 {
            t.observe_share(round, 0);
            t.observe_share(round, 2);
        }
        let faults = t.evaluate();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].kind, FaultKind::Liveness);
        assert_eq!(faults[0].attribution, Attribution::Peers(vec![victim]));
    }

    #[test]
    fn single_failed_round_below_threshold_is_silent() {
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        t.observe_share(0, 0);
        t.observe_share(0, 2); // round 0 fails (no output, #1 missing)
                               // round 1 healthy → output advances past round 0, so round 0 is a
                               // detected (skipped) failure, but it's only one — below threshold.
        for idx in 0..3 {
            t.observe_share(1, idx);
        }
        t.observe_output(1);
        assert!(
            t.evaluate().is_empty(),
            "one failure resets on the next success"
        );
    }

    #[test]
    fn late_start_does_not_fault_unseen_rounds() {
        // An observer that joins mid-stream (its first observations are for
        // round 10) must NOT retroactively judge rounds 0..9 — which it never
        // saw — as failed. This is the spurious-`None` bug that broke the full
        // committee e2e, where the observer is built only after the committee
        // decodes the config (well after the subnet started).
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        for round in 10..16u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
            t.observe_output(round);
        }
        assert!(
            t.evaluate().is_empty(),
            "must not fault rounds before the observer started seeing traffic"
        );
    }

    #[test]
    fn lagging_but_advancing_output_does_not_fault() {
        // Healthy subnet under jitter: every relay shares every round and the
        // decoded output arrives in order but lags the share frontier by more
        // than any fixed margin. As long as output keeps *advancing*, no round
        // may be faulted. (This is the real committee-e2e false positive: a
        // margin-based observer judged lagging rounds output-less.)
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        // Shares race ahead to round 20.
        for round in 0..20u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
        }
        // Outputs lag far behind (only up to 6) but are still coming.
        for round in 0..7u64 {
            t.observe_output(round);
        }
        assert!(
            t.evaluate().is_empty(),
            "rounds with output still in flight must be deferred, not faulted"
        );
        // Output catches up.
        for round in 7..20u64 {
            t.observe_output(round);
        }
        assert!(t.evaluate().is_empty(), "all rounds eventually had output");
    }

    #[test]
    fn all_shares_but_no_output_is_unattributable() {
        // Every relay publishes its share but the leader never produces an
        // output (an aggregation/leader fault, not a relay liveness fault).
        // Nothing is missing, so this is a general — unattributable — fault.
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        // Long enough for the share frontier to outrun the (never-advancing)
        // output past the stall margin.
        for round in 0..12u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
            // deliberately no observe_output
        }
        let faults = t.evaluate();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].attribution, Attribution::None);
    }
}
