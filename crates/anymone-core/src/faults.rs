//! Fault types and the protocol-agnostic liveness observer.

use serde::{Deserialize, Serialize};

use crate::session::PeerId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    pub kind: FaultKind,
    pub attribution: Attribution,
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

/// Detects liveness faults from the share/output frontiers a protocol observer
/// feeds it: missing decoded output is the trigger, attributable only when some
/// relays' shares were also missing. Wire recognition lives in the protocol
/// session; this is the shared bookkeeping.
pub struct OutputFaultTracker {
    /// Sorted relay roster; index = the protocol's server index.
    roster: Vec<PeerId>,
    /// Consecutive failed (output-less) rounds needed to fault.
    threshold: u64,
    /// Share-rounds output may lag before we call it frozen rather than lagging.
    stall_margin: u64,
    shares: std::collections::HashMap<u64, std::collections::HashSet<usize>>,
    outputs: std::collections::HashSet<u64>,
    max_share_round: Option<u64>,
    max_output_round: Option<u64>,
    /// Share frontier when output last advanced; the gap to `max_share_round`
    /// separates lag (small) from stall (grows without bound).
    share_at_last_output: Option<u64>,
    evaluated_through: Option<u64>,
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
            self.share_at_last_output.get_or_insert(round);
        }
    }

    pub fn observe_output(&mut self, round: u64) {
        self.outputs.insert(round);
        let advanced = self.max_output_round.map_or(true, |m| round > m);
        if advanced {
            self.max_output_round = Some(self.max_output_round.map_or(round, |m| m.max(round)));
            self.share_at_last_output = self.max_share_round.or(Some(round));
        }
    }

    fn output_frozen(&self) -> bool {
        match (self.max_share_round, self.share_at_last_output) {
            (Some(s), Some(base)) => s.saturating_sub(base) > self.stall_margin,
            _ => false,
        }
    }

    /// Process superseded rounds in order. A round with output succeeds and
    /// resets the run; a round without is deferred while output is still
    /// advancing and judged failed only once output is frozen or skipped past.
    /// `threshold` consecutive failures emit one `Liveness` fault, attributed to
    /// the relays missing in every failed round if that's a proper subset.
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
        for r in start..frontier {
            if self.outputs.contains(&r) {
                self.evaluated_through = Some(r);
                self.fail_run.clear();
                continue;
            }
            // A round with no shares never ran (no traffic / round-label drift),
            // so there was no output to expect — skip without counting it.
            let shared = self.shares.get(&r).cloned().unwrap_or_default();
            if shared.is_empty() {
                self.evaluated_through = Some(r);
                continue;
            }
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

    /// Highest round any relay has published a share for. `None` before the
    /// first share.
    pub fn share_frontier(&self) -> Option<u64> {
        self.max_share_round
    }

    /// Highest round that has produced decoded output. `None` before the first.
    pub fn output_frontier(&self) -> Option<u64> {
        self.max_output_round
    }

    /// Roster indices of relays that shared within `window` rounds of the
    /// frontier — observably alive now. Empty before any share.
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
        for round in 0..2u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
            t.observe_output(round);
        }
        // Relay #1 silent, no output; run long enough to outrun the stall margin.
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
        // An observer joining mid-stream (first round 10) must not retroactively
        // judge rounds 0..9 it never saw.
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
        // Output lags the share frontier by more than any fixed margin but keeps
        // advancing — no round may be faulted.
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        for round in 0..20u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
        }
        for round in 0..7u64 {
            t.observe_output(round);
        }
        assert!(
            t.evaluate().is_empty(),
            "rounds with output still in flight must be deferred, not faulted"
        );
        for round in 7..20u64 {
            t.observe_output(round);
        }
        assert!(t.evaluate().is_empty(), "all rounds eventually had output");
    }

    #[test]
    fn all_shares_but_no_output_is_unattributable() {
        // Every relay shares but the leader never outputs (a leader/aggregation
        // fault): nothing missing, so unattributable.
        let r = roster(3);
        let mut t = OutputFaultTracker::new(r, 2);
        for round in 0..12u64 {
            for idx in 0..3 {
                t.observe_share(round, idx);
            }
        }
        let faults = t.evaluate();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].attribution, Attribution::None);
    }
}
