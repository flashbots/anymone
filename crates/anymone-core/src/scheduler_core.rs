//! Sans-IO scheduling decision core.
//!
//! This is the committee's brain with the I/O and the clock removed — the same
//! discipline the protocol [`Session`](crate::session::Session)s follow, pushed
//! up one level. It owns the scheduling *decisions* (who's a live relay, which
//! protocol the public subnet should run, when to publish a new config) and
//! returns [`SchedulerAction`]s describing the I/O to perform. It never touches
//! a transport or a clock.
//!
//! The async committee daemon ([`crate::committee`]) is one composition: it
//! pumps transport messages into the core, runs the committee-anonymisation
//! Panetiere, and executes the returned actions. A test is another composition:
//! it feeds synthetic registrations + faults and asserts the actions, with no
//! tokio and no timers. See the "libraries over frameworks" refactor.
//!
//! Fault handling follows the ADCNet fault model: a `Liveness` fault with
//! `Attribution::Peers` sidelines exactly those relays (drop + escalate to
//! Panetiere); an unattributable `Attribution::None` fault escalates to Panetiere
//! without dropping a specific relay. A sidelined relay heals — and the subnet
//! drops back to the optimistic ADCNet — when it re-registers; the culprit-less
//! general fault heals only after [`ESCALATION_GRACE`] fault-free rounds.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::adcnet::AdcnetObserverSession;
use crate::config::{
    AdcnetConfig, Aggregation, AggregatorGroup, AnymoneRoundConfiguration,
    AnymoneRoundConfigurationBody, ExchangePublicKeyWire, PanetiereConfig, ProtocolConfig, Round,
    ServiceEntry, Signature, Subnet, SubnetId,
};
use crate::faults::{Attribution, Fault, FaultKind};
use crate::governance::{FaultReport, TOPIC_CONFIG};
use crate::identity::{Identity, Pubkey};
use crate::panetiere::PanetiereObserverSession;
use crate::scheduling::{Registration, SchedulerProtocol};
use crate::session::Session;
use crate::wire::ServiceTag;

/// The public subnet the committee schedules + observes (singleton, id 0).
pub const SUBNET_ID: SubnetId = 0;

/// Add a subnet once the per-subnet load (total ÷ subnet count) reaches this.
/// Growth is immediate; removal waits [`SUBNET_SHRINK_GRACE`] consecutive ticks so
/// the re-home transient — where clients have left a subnet but the newly-scheduled
/// one hasn't announced its set yet, momentarily undercounting the total — can't
/// flap a subnet straight back off.
pub(crate) const SUBNET_GROW_AT: u32 = 63;
/// Consecutive ticks the shrink condition must hold before a subnet is removed.
const SUBNET_SHRINK_GRACE: u32 = 3;
/// Most public subnets the committee will schedule (matches the committee's
/// observability subscriptions; a safety cap, not an expected count).
pub const MAX_SUBNETS: usize = 16;

/// Subnet capacity before any client population has been observed, and the
/// default [`SchedulerParams::min_capacity`].
pub const INITIAL_CAPACITY: u32 = 8;
/// Smallest capacity we'll size down to (keeps a little headroom for churn).
const MIN_CAPACITY: u32 = 8;
/// Default bar on an integrity offender's re-registration. Overridable via
/// [`SchedulerParams::integrity_backoff_ms`].
pub const INTEGRITY_BACKOFF_MS: u64 = 6 * 60 * 1000;
/// Default fault-free rounds before a general (unattributable) escalation
/// de-escalates. Overridable via [`SchedulerParams::escalation_grace`]; keep it
/// above the observer's `fault_threshold` so a recurring cause re-trips first.
pub const ESCALATION_GRACE: u32 = 5;
/// Predicted client set above which Panetiere routes public ciphertexts+commitments
/// through an aggregator layer (lessening the leader/broadcast fan-in).
const AGGREGATION_THRESHOLD: u32 = 16;
/// Max distance between a `FaultReport.round` and its subnet's `share_frontier`.
const FAULT_REPORT_ROUND_WINDOW: Round = 32;
/// Aggregators per group. One, deliberately: replicas were meant to agree
/// byte-for-byte, but on a real lossy/async network they receive different
/// client subsets and diverge, and the leader keeps only the first it sees
/// (`adcnet.rs` `or_insert`) — collapsing the canonical client set and stalling
/// decode. A single authoritative aggregator per group avoids the divergence.
const AGGREGATOR_REPLICATION: u32 = 1;
/// Reconfigure capacity only once the desired size differs from the current by
/// at least `max(MIN_CAPACITY, 10%)` of the current, in either direction —
/// capacity is signed governance, so a re-proposal must be worth a re-sign, not
/// round-to-round cover jitter. The 10% ratio keeps the hysteresis proportional
/// as the subnet scales; the floor keeps it meaningful when capacity is small.
fn capacity_resize_margin(current: u32) -> u32 {
    (current / 10).max(MIN_CAPACITY)
}

/// Capacity that fits `clients` with room to grow: `max(clients+10,
/// ceil(clients*1.2))`, floored at [`MIN_CAPACITY`].
fn size_capacity(clients: usize) -> u32 {
    let plus = clients.saturating_add(10);
    let mult = (clients as f64 * 1.2).ceil() as usize;
    (plus.max(mult) as u32).max(MIN_CAPACITY)
}

/// IBLT/MSE decode capacity for an anonymity set of `set`: ~half its members
/// send real messages, the rest cover — and cover vanishes from the IBLT/sum.
pub(crate) fn expected_active(set: u32) -> u32 {
    set.div_ceil(2).max(MIN_CAPACITY / 2)
}

/// Per-subnet wire budget: a subnet's largest per-round message must stay under this,
/// with headroom below the gossipsub ceiling.
const MAX_SUBNET_WIRE: usize = crate::p2p::MAX_TRANSMIT_SIZE * 3 / 4;

/// Capacity ceiling. Subnets split well before this; at this many clients the biggest
/// message (the ciphertext) is still a few hundred KB, far under [`MAX_SUBNET_WIRE`],
/// so a fixed cap avoids sizing a subnet whose message would blow the p2p limit.
const MAX_SUBNET_CLIENTS: u32 = 300;

/// Largest per-round wire message the given subnet protocol broadcasts, via each
/// protocol's own packing-accurate estimator. Never-proposed protocols report 0
/// (validate_body rejects them by variant).
fn subnet_max_wire(p: &ProtocolConfig, n_relays: usize) -> usize {
    match p {
        ProtocolConfig::Adcnet(c) => crate::adcnet::max_wire_estimate(
            c.max_payload_bytes,
            c.estimated_messages,
            c.client_set_max,
            n_relays,
        ),
        ProtocolConfig::Panetiere(c) => crate::panetiere::max_wire_estimate(
            c.message_size,
            c.estimated_messages,
            c.client_set_max,
            n_relays,
        ),
        ProtocolConfig::ScheduledPanetiere(c) => crate::panetiere_scheduled::max_wire_estimate(
            c.vector_bytes,
            c.estimated_messages,
            c.client_set_max,
            n_relays,
        ),
        ProtocolConfig::Noop(c) => crate::noop::max_wire_estimate(
            c.message_size,
            c.client_set_max,
            c.client_set_max,
            n_relays,
        ),
        ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => 0,
    }
}

/// Shape checks independent of local state; an empty `groups`/zero `replication`
/// would otherwise reach `agg.roster.len() % group_count` downstream and panic.
fn aggregation_structural_ok(agg: &Option<Aggregation>) -> bool {
    let Some(a) = agg else { return true };
    a.replication > 0
        && !a.groups.is_empty()
        && a.groups
            .iter()
            .all(|g| g.aggregators.len() == a.replication as usize)
}

/// Checks independent of local state — safe to run before `registered`/`services`
/// are populated, e.g. on a just-verified published config ahead of `learn_config`.
fn validate_structure(body: &AnymoneRoundConfigurationBody) -> bool {
    if body.subnets.is_empty() || body.subnets.len() > MAX_SUBNETS {
        return false;
    }
    for s in &body.subnets {
        if s.relays.is_empty() {
            return false;
        }
        if subnet_max_wire(&s.protocol, s.relays.len()) > MAX_SUBNET_WIRE {
            return false;
        }
        match &s.protocol {
            ProtocolConfig::Noop(c) => {
                if c.client_set_max < MIN_CAPACITY {
                    return false;
                }
            }
            ProtocolConfig::Adcnet(c) => {
                if c.client_set_max < MIN_CAPACITY || !aggregation_structural_ok(&c.aggregation) {
                    return false;
                }
            }
            ProtocolConfig::Panetiere(c) => {
                let n = s.relays.len() as u32;
                let threshold_ok = c.threshold >= n / 2 + 1 && c.threshold <= n.max(1);
                if c.client_set_max < MIN_CAPACITY
                    || !threshold_ok
                    || !aggregation_structural_ok(&c.aggregation)
                {
                    return false;
                }
            }
            ProtocolConfig::ScheduledPanetiere(c) => {
                let n = s.relays.len() as u32;
                let threshold_ok = c.threshold >= n / 2 + 1 && c.threshold <= n.max(1);
                if c.client_set_max < MIN_CAPACITY
                    || !threshold_ok
                    || !aggregation_structural_ok(&c.aggregation)
                    || c.message_size == 0
                    || c.message_size > u16::MAX as usize
                    || c.vector_bytes == 0
                {
                    return false;
                }
            }
            // The scheduler only ever proposes Noop / Adcnet / Panetiere / ScheduledPanetiere.
            ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod sizing_tests {
    use super::*;

    #[test]
    fn reference_capacity_fits_budget() {
        // At the capacity ceiling the biggest message stays well under the wire budget.
        let msg = 256usize;
        let est = expected_active(MAX_SUBNET_CLIENTS);
        for n_relays in [5usize, 8] {
            let worst =
                crate::adcnet::max_wire_estimate(msg, est, MAX_SUBNET_CLIENTS, n_relays).max(
                    crate::panetiere::max_wire_estimate(msg, est, MAX_SUBNET_CLIENTS, n_relays),
                );
            assert!(
                worst <= MAX_SUBNET_WIRE,
                "reference message {worst} at {n_relays} relays exceeds budget"
            );
        }
    }

    #[test]
    fn pathological_client_set_exceeds_budget() {
        let over = subnet_max_wire(
            &ProtocolConfig::Adcnet(crate::config::AdcnetConfig {
                round_duration_ms: 1000,
                max_payload_bytes: 256,
                estimated_messages: expected_active(50_000),
                client_set_min: 0,
                client_set_max: 50_000,
                relay_exchange_keys: vec![],
                aggregation: None,
            }),
            5,
        );
        assert!(over > MAX_SUBNET_WIRE, "validate_body must reject this");

        // A subnet with no relays is rejected outright (would otherwise panic the
        // runtime's leader election).
        let id = Identity::generate();
        let core = SchedulerCore::new(
            id.clone(),
            vec![id.pubkey()],
            1,
            SchedulerParams {
                public_round_duration: Duration::from_secs(1),
                min_relays: 1,
                min_services: 1,
                fault_threshold: 2,
                escalation_grace: ESCALATION_GRACE,
                grow_at: SUBNET_GROW_AT,
                message_size: 256,
                integrity_backoff_ms: 6 * 60 * 1000,
                sideline: true,
                min_capacity: 8,
                pin: None,
                aggregation: true,
            },
        );
        let body = AnymoneRoundConfigurationBody {
            round: 0,
            epoch_unix_ms: 0,
            services: vec![],
            subnets: vec![Subnet {
                id: 0,
                relays: vec![],
                protocol: ProtocolConfig::Noop(crate::config::NoopConfig {
                    round_duration_ms: 1000,
                    message_size: 256,
                    client_set_min: 0,
                    client_set_max: MIN_CAPACITY,
                }),
                cover_rate: 1.0,
            }],
        };
        assert!(
            !core.validate_body(&body),
            "empty relay set must be rejected"
        );
    }
}

/// Effects the core wants performed. The daemon executes them; a test inspects
/// them. (Mirrors `Session::begin_round -> Vec<Vec<u8>>`: return the bytes,
/// don't perform the I/O.)
#[derive(Debug, Clone)]
pub enum SchedulerAction {
    /// Anonymise + broadcast this config body via the committee's internal
    /// Panetiere (the lead proposer's job).
    StageProposal(Vec<u8>),
    /// Publish bytes directly on a governance topic (signatures, configs).
    Publish { topic: String, bytes: Vec<u8> },
}

/// Wire form for committee signature gossip — one per body a member signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeSig {
    pub body_bytes: Vec<u8>,
    pub signer: Pubkey,
    pub signature: Vec<u8>,
}

/// A config body proposed by the committee lead, carried over the committee's
/// internal Panetiere. The lead's signature over `body.propose_bytes()` — a
/// domain distinct from the `approve_bytes()` multisig signs — lets every
/// member confirm the proposal genuinely came from the current lead
/// (`sorted(committee)[0]`) before signing it — without this, any peer that
/// reconstructs the public-roster-derived Panetiere params could inject an
/// arbitrary body and have the committee multisig-sign it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedProposal {
    pub body: AnymoneRoundConfigurationBody,
    pub proposer: Pubkey,
    pub signature: Vec<u8>,
}

/// Tunables shared with the daemon.
#[derive(Debug, Clone)]
pub struct SchedulerParams {
    pub public_round_duration: Duration,
    pub min_relays: usize,
    pub min_services: usize,
    /// Consecutive output-less rounds before the observer faults (demo: 2).
    pub fault_threshold: u64,
    /// Fault-free rounds before a general escalation de-escalates (default
    /// [`ESCALATION_GRACE`]); keep above `fault_threshold`.
    pub escalation_grace: u32,
    /// Per-subnet load at which a new subnet is scheduled.
    pub grow_at: u32,
    /// Per-message payload bound the scheduled subnets carry — the dominant
    /// per-round crypto cost, so tests shrink it to stay cheap.
    pub message_size: usize,
    /// How long an integrity offender stays barred from re-registration
    /// (default [`INTEGRITY_BACKOFF_MS`]).
    pub integrity_backoff_ms: u64,
    /// Hard floor and initial value for subnet capacity. Setting it above the
    /// expected client load holds capacity constant, so the subnet never
    /// respawns its workers to resize mid-demo (default [`INITIAL_CAPACITY`]).
    pub min_capacity: u32,
    /// Whether attributed faults drop the culprit from the roster. `false`
    /// keeps the fault feed (reports, escalation state, dashboard attribution)
    /// but leaves the roster intact — for showcases where a corrupted relay
    /// should be *seen*, not removed.
    pub sideline: bool,
    /// Force every subnet onto one protocol, bypassing the escalation ladder.
    /// `Panetiere` still traffic-upgrades to `ScheduledPanetiere`; pinning
    /// `ScheduledPanetiere` fixes it outright.
    pub pin: Option<SchedulerProtocol>,
    /// Whether the committee may route large Panetiere subnets through an
    /// aggregator layer above [`AGGREGATION_THRESHOLD`].
    pub aggregation: bool,
}

/// One public subnet's escalation state: `general` (unattributable fault, heals
/// on a clean streak) and `relays` attributed-faulted here (escalated while any
/// is still sidelined; heals on re-registration).
#[derive(Default)]
struct SubnetEscalation {
    general: bool,
    clean_streak: u32,
    /// Share frontier the streak last advanced at; a frozen frontier holds it.
    streak_frontier: Option<u64>,
    relays: HashSet<Pubkey>,
}

const SCHED_WINDOW: u64 = 8;
const SCHED_DOWNGRADE_GRACE: u32 = 5;
/// Vector resize hysteresis: re-propose only past this fractional change.
const SCHED_VECTOR_RESIZE_MARGIN: f64 = 0.25;
const MAX_VECTOR_BYTES: usize = 128 * 1024;

fn round_up_to(x: usize, to: usize) -> usize {
    x.div_ceil(to) * to
}

#[derive(Default)]
struct SchedModeState {
    scheduled: bool,
    downgrade_streak: u32,
    vector_bytes: usize,
}

pub struct SchedulerCore {
    identity: Identity,
    committee: Vec<Pubkey>,
    threshold: u32,
    is_lead: bool,
    /// The only member whose proposals members will sign: `sorted(committee)[0]`.
    lead: Pubkey,
    /// Highest proposal round accepted so far. A proposal with a strictly lower
    /// round is a stale-rollback replay and is rejected.
    last_accepted_round: Option<Round>,
    /// Highest committee round seen via `tick`.
    cur_round: Round,
    /// `(subnet, report.round, culprit)` already applied, to reject replays.
    seen_integrity_faults: HashSet<(SubnetId, Round, Pubkey)>,
    /// Network genesis epoch; learned from an adopted config or self-stamped
    /// once if we're the first proposer.
    epoch_unix_ms: Option<u64>,
    params: SchedulerParams,

    // Relay liveness: registered minus sidelined is the live set. A sidelined
    // relay returns only on re-registration.
    registered: HashSet<Pubkey>,
    sidelined: HashSet<Pubkey>,
    /// Relays sidelined for a *proven* integrity fault, mapped to the time of
    /// the offense. Re-registration is refused until `INTEGRITY_BACKOFF_MS` has
    /// elapsed (longer than a liveness sideline, which heals immediately).
    integrity_offenders: HashMap<Pubkey, u64>,
    /// Per-subnet escalation state, keyed by subnet id. Replaces a single global
    /// flag so a fault on one subnet escalates only that subnet (and a clean
    /// streak on one doesn't de-escalate another).
    escalation: std::collections::BTreeMap<SubnetId, SubnetEscalation>,
    /// Per-subnet scheduled-Panetiere mode state (see `apply_sched_mode`).
    sched_mode: std::collections::BTreeMap<SubnetId, SchedModeState>,

    services: HashMap<ServiceTag, Pubkey>,
    relay_xpubs: HashMap<Pubkey, ExchangePublicKeyWire>,

    // Liveness observer for the current public subnet (protocol-specific).
    /// Per-subnet liveness observers (one per public subnet), keyed by id. They
    /// drive both fault detection (every subnet) and the total client tally.
    observers: std::collections::BTreeMap<SubnetId, PublicObserver>,
    /// Signature of the current public-subnet set (id + sorted roster + proto);
    /// observers are rebuilt only when this changes, so fault state survives the
    /// committee's periodic config re-broadcasts.
    current_subnets_sig: Vec<(SubnetId, Vec<Pubkey>, Option<SchedulerProtocol>)>,
    /// Number of public ADCNet subnets the committee currently schedules.
    subnet_count: usize,
    /// Consecutive ticks the shrink condition has held — gates subnet removal
    /// so a re-home transient can't immediately undo a just-added subnet.
    shrink_streak: u32,
    /// Subnet capacity (`client_set_max` / IBLT sizing). Starts medium and is
    /// resized to fit the observed client population, keeping per-round CPU
    /// proportional to actual usage rather than a fixed worst case.
    capacity: u32,
    /// Cover rate stamped onto every scheduled subnet; folded into the content
    /// key so a change re-proposes.
    cover_rate: f32,

    // Lead-proposer state: bump `public_round` only when the round-independent
    // content (protocol + roster + services) changes, then re-stage every round
    // until `published_round` catches up — a lone early lead's first attempt
    // can't reach threshold, so one stage isn't enough.
    last_content: Option<Vec<u8>>,
    public_round: Round,
    published_round: Option<Round>,

    // Multisig assembly.
    sigs: HashMap<Vec<u8>, HashMap<Pubkey, Vec<u8>>>,
    published: HashSet<Vec<u8>>,
}

impl SchedulerCore {
    pub fn new(
        identity: Identity,
        committee: Vec<Pubkey>,
        threshold: u32,
        params: SchedulerParams,
    ) -> Self {
        let our_pk = identity.pubkey();
        let mut sorted = committee.clone();
        sorted.sort();
        let lead = sorted.first().copied().unwrap_or(our_pk);
        let is_lead = lead == our_pk;
        let capacity = params.min_capacity.max(INITIAL_CAPACITY);
        SchedulerCore {
            identity,
            committee,
            threshold,
            is_lead,
            lead,
            last_accepted_round: None,
            cur_round: 0,
            seen_integrity_faults: HashSet::new(),
            epoch_unix_ms: None,
            params,
            registered: HashSet::new(),
            sidelined: HashSet::new(),
            integrity_offenders: HashMap::new(),
            escalation: std::collections::BTreeMap::new(),
            sched_mode: std::collections::BTreeMap::new(),
            services: HashMap::new(),
            relay_xpubs: HashMap::new(),
            observers: std::collections::BTreeMap::new(),
            current_subnets_sig: Vec::new(),
            subnet_count: 1,
            shrink_streak: 0,
            capacity,
            cover_rate: 1.0,
            last_content: None,
            public_round: 0,
            published_round: None,
            sigs: HashMap::new(),
            published: HashSet::new(),
        }
    }

    pub fn is_lead(&self) -> bool {
        self.is_lead
    }

    pub fn set_cover_rate(&mut self, rate: f32) {
        self.cover_rate = rate.clamp(0.0, 1.0);
    }

    /// Ingest a registration. (Re-)registration of a relay heals a sideline,
    /// but a general fault clears only on a clean-round streak (see `tick`).
    pub fn on_registration(&mut self, reg: Registration) {
        match reg {
            Registration::Relay {
                pubkey,
                exchange_pubkey,
                ..
            } => {
                if !self.integrity_offenders.contains_key(&pubkey) {
                    self.sidelined.remove(&pubkey);
                    self.registered.insert(pubkey);
                    self.relay_xpubs.insert(pubkey, exchange_pubkey);
                }
            }
            Registration::Service {
                tag,
                pubkey,
                exchange_pubkey: _,
                ..
            } => {
                self.services.insert(tag, pubkey);
            }
        }
    }

    /// Feed a message from public subnet `subnet` to that subnet's own liveness
    /// observer (daemon path). Every subnet is observed independently — each has
    /// its own anonymity set and its own faults.
    pub fn on_subnet_message(&mut self, subnet: SubnetId, from: Pubkey, bytes: Vec<u8>) {
        if let Some(obs) = self.observers.get_mut(&subnet) {
            obs.on_inbound(from, bytes);
        }
    }

    /// Apply faults observed on `subnet`: sideline attributed relays (globally —
    /// relays are shared across subnets; skipped when `params.sideline` is off)
    /// and escalate this subnet. Public so tests can inject faults without
    /// crafting wire bytes.
    pub fn apply_observed_faults(
        &mut self,
        subnet: SubnetId,
        faults: Vec<Fault>,
        now_unix_ms: u64,
    ) {
        if faults.is_empty() {
            return;
        }
        self.escalation.entry(subnet).or_default().clean_streak = 0;
        for fault in faults {
            let integrity = fault.kind == FaultKind::Integrity;
            match fault.attribution {
                Attribution::Peers(pks) => {
                    for pk in pks {
                        self.escalation.entry(subnet).or_default().relays.insert(pk);
                        if !self.params.sideline {
                            continue;
                        }
                        self.registered.remove(&pk);
                        self.sidelined.insert(pk);
                        if integrity {
                            self.integrity_offenders.insert(pk, now_unix_ms);
                        }
                    }
                }
                Attribution::None => {
                    self.escalation.entry(subnet).or_default().general = true;
                }
            }
        }
    }

    /// Ingest an integrity `FaultReport` gossiped on `TOPIC_FAULTS`. Accepted only
    /// from the subnet's leader and only when we can re-verify the evidence
    /// ourselves — it must be signed by the very relay it attributes — so a lying
    /// leader can't frame an honest one. Liveness stays the observer's job.
    ///
    /// `report.round` is a subnet round on a different clock than the
    /// committee's `tick` round, so freshness is checked against the subnet's
    /// own `share_frontier`, not `self.cur_round`.
    pub fn on_fault_report(&mut self, from: Pubkey, report: FaultReport, now_unix_ms: u64) {
        if report.fault.kind != FaultKind::Integrity {
            return;
        }
        let roster = match self
            .current_subnets_sig
            .iter()
            .find(|(id, _, _)| *id == report.subnet)
        {
            Some((_, roster, _)) if !roster.is_empty() => roster.clone(),
            _ => return,
        };
        if from != roster[(report.subnet as usize) % roster.len()] {
            return;
        }
        if let Some(frontier) = self
            .observers
            .get(&report.subnet)
            .and_then(|o| o.share_frontier())
        {
            let in_window = report.round.saturating_add(FAULT_REPORT_ROUND_WINDOW) >= frontier
                && report.round <= frontier.saturating_add(FAULT_REPORT_ROUND_WINDOW);
            if !in_window {
                tracing::debug!(
                    subnet = report.subnet,
                    report_round = report.round,
                    frontier,
                    "scheduler: rejecting fault report outside the subnet's round window"
                );
                return;
            }
        }
        let Some(culprit) =
            crate::panetiere::integrity_culprit_from_evidence(&report.fault.evidence, &roster)
        else {
            return;
        };
        if report.fault.attribution != Attribution::Peers(vec![culprit]) {
            return;
        }
        if !self
            .seen_integrity_faults
            .insert((report.subnet, report.round, culprit))
        {
            return;
        }
        self.apply_observed_faults(report.subnet, vec![report.fault], now_unix_ms);
    }

    /// Advance one committee round: tick the observer, apply any faults, and —
    /// if we're the lead and the proposal content changed — stage a new config.
    pub fn tick(&mut self, round: Round, now_unix_ms: u64) -> Vec<SchedulerAction> {
        self.cur_round = round;
        for obs in self.observers.values_mut() {
            obs.refresh_clock();
        }
        // Bound seen_integrity_faults: drop entries far behind their subnet's frontier.
        let frontiers: HashMap<SubnetId, Round> = self
            .observers
            .iter()
            .filter_map(|(id, o)| o.share_frontier().map(|f| (*id, f)))
            .collect();
        self.seen_integrity_faults.retain(|(subnet, r, _)| {
            frontiers
                .get(subnet)
                .is_none_or(|f| r.saturating_add(2 * FAULT_REPORT_ROUND_WINDOW) >= *f)
        });
        // Evaluate each subnet's own liveness observer and route its faults to
        // that subnet's escalation state — each subnet has its own anonymity set,
        // faults, and escalation.
        let ids: Vec<SubnetId> = self.observers.keys().copied().collect();
        let mut faulted: HashSet<SubnetId> = HashSet::new();
        for id in ids {
            let faults = self
                .observers
                .get_mut(&id)
                .map(|o| o.end_round_faults(round))
                .unwrap_or_default();
            if !faults.is_empty() {
                faulted.insert(id);
            }
            self.apply_observed_faults(id, faults, now_unix_ms);
        }
        // A subnet's clean streak only advances on real progress — a stalled
        // subnet also emits no fault and must not read as healthy.
        let grace = self.params.escalation_grace;
        let observers = &self.observers;
        for (id, esc) in self.escalation.iter_mut() {
            let frontier = observers.get(id).and_then(|o| o.share_frontier());
            let advanced = match (frontier, esc.streak_frontier) {
                (Some(f), Some(prev)) => f > prev,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if !faulted.contains(id) && advanced {
                esc.clean_streak = esc.clean_streak.saturating_add(1);
                esc.streak_frontier = frontier;
            }
            if esc.general && esc.clean_streak >= grace {
                esc.general = false;
            }
        }
        self.integrity_offenders
            .retain(|_, t| now_unix_ms.saturating_sub(*t) < self.params.integrity_backoff_ms);

        // Busiest subnet's own anon set (each subnet sizes its IBLT to its load).
        // Clients hash across all current subnets, so the per-subnet load is
        // ~total/subnet_count; add a subnet when any nears the grow mark, drop one
        // when all sit well below. One step per tick.
        // Total observed submitters across all subnets. Each client appears in
        // exactly one subnet's canonical set, so this is conserved as clients
        // re-home — unlike `busiest`, which only drops once a freshly-scheduled
        // subnet is adopted and clients move onto it.
        let total: usize = self
            .observers
            .values()
            .filter_map(|o| o.anonymity_set())
            .sum();
        let busiest = self
            .observers
            .values()
            .filter_map(|o| o.anonymity_set())
            .max()
            .unwrap_or(0) as u32;
        tracing::debug!(
            is_lead = self.is_lead,
            observers = self.observers.len(),
            registered = self.registered.len(),
            services = self.services.len(),
            sidelined = self.sidelined.len(),
            total,
            per_subnet = total / self.subnet_count.max(1),
            subnet_count = self.subnet_count,
            "scheduler tick: subnet sizing"
        );
        // Size the subnet count to the load each subnet WOULD carry once clients
        // spread evenly across the current count, not the busiest single subnet.
        // Using `busiest` makes the committee add a subnet every tick (the
        // adopted config lags, so `busiest` stays high), overshoot to
        // MAX_SUBNETS, and — because the proposal body then changes every round
        // — never converge on a config to publish. `total / subnet_count`
        // converges: at total=63 it grows 1→2 (63≥63) then holds (31<63).
        let per_subnet = (total / self.subnet_count.max(1)) as u32;
        // Shrink only when merging back to one fewer subnet would still leave the
        // load below grow_at (10% hysteresis), so a shrink never immediately re-grows.
        let merged_per_subnet = (total / (self.subnet_count.max(2) - 1)) as u32;
        let shrink_floor = self.params.grow_at.saturating_sub(self.params.grow_at / 10);
        if per_subnet >= self.params.grow_at && self.subnet_count < MAX_SUBNETS {
            // Grow immediately.
            self.subnet_count += 1;
            self.shrink_streak = 0;
        } else if self.subnet_count > 1 && merged_per_subnet <= shrink_floor {
            // Shrink only after the condition holds for a few ticks, so the
            // re-home transient (total briefly undercounted) can't flap a
            // freshly-added subnet straight back off.
            self.shrink_streak += 1;
            if self.shrink_streak >= SUBNET_SHRINK_GRACE {
                self.subnet_count -= 1;
                self.shrink_streak = 0;
            }
        } else {
            self.shrink_streak = 0;
        }
        // Size capacity to the busiest observed set (every subnet's IBLT uses it),
        // with hysteresis so cover-traffic jitter doesn't churn. `min_capacity`
        // is a hard floor — set it above the expected load to keep the subnet
        // from resizing (and respawning workers) at all during a demo.
        let desired = size_capacity(busiest as usize).max(self.params.min_capacity);
        if desired.abs_diff(self.capacity) >= capacity_resize_margin(self.capacity) {
            self.capacity = desired;
        }
        // Cap clients per subnet so the biggest message stays under the p2p limit.
        self.capacity = self.capacity.min(MAX_SUBNET_CLIENTS);
        // Drop escalation for subnets that no longer exist, so a reused id starts clean.
        let count = self.subnet_count;
        self.escalation.retain(|id, _| (*id as usize) < count);
        self.sched_mode.retain(|id, _| (*id as usize) < count);

        let mut actions = Vec::new();
        let faulted = !self.sidelined.is_empty() || self.escalation.values().any(|e| e.general);
        // `min_relays` gates bootstrap, not fault response: sidelining a relay
        // drops it from `registered`, and holding the full floor would wedge
        // governance — it must still escalate with the relays that remain.
        let enough_relays = self.registered.len() >= self.params.min_relays
            || (faulted && !self.registered.is_empty());
        if self.is_lead && enough_relays && self.services.len() >= self.params.min_services {
            // Per-subnet protocol, so a fault escalates only its own subnet.
            let mut protos = self.subnet_protocols();
            self.apply_sched_mode(&mut protos);
            let vector_bytes: Vec<usize> = (0..protos.len())
                .map(|i| {
                    self.sched_mode
                        .get(&(i as SubnetId))
                        .map(|s| s.vector_bytes)
                        .unwrap_or(0)
                })
                .collect();
            let content = content_key(
                &protos,
                &vector_bytes,
                self.params.pin,
                &self.registered,
                &self.services,
                self.capacity,
                self.cover_rate,
            );
            if self.last_content.as_ref() != Some(&content) {
                self.public_round = self.public_round.wrapping_add(1);
                self.last_content = Some(content);
            }
            if self.published_round != Some(self.public_round) {
                self.epoch_unix_ms
                    .get_or_insert_with(crate::config::now_unix_ms);
                let body = self.build_body(&protos);
                let signature = self.identity.sign(&body.propose_bytes());
                let proposal = SignedProposal {
                    body,
                    proposer: self.identity.pubkey(),
                    signature,
                };
                let bytes = bincode::serialize(&proposal).expect("proposal serialises");
                actions.push(SchedulerAction::StageProposal(bytes));
            }
        }
        actions
    }

    /// Raise the round counters to a network-adopted config, so a restarted
    /// member proposes above the network instead of wedging on stale-round rejections.
    pub fn on_published_config(&mut self, cfg: &AnymoneRoundConfiguration) -> bool {
        if cfg
            .verify_multisig(&self.committee, self.threshold)
            .is_err()
        {
            return false;
        }
        if !validate_structure(&cfg.body) {
            return false;
        }
        let r = cfg.body.round;
        self.last_accepted_round = Some(self.last_accepted_round.map_or(r, |l| l.max(r)));
        self.public_round = self.public_round.max(r);
        self.published_round = Some(self.published_round.map_or(r, |p| p.max(r)));
        self.published.insert(cfg.body.canonical_bytes());
        self.learn_config(&cfg.body);
        true
    }

    /// A committee-Panetiere round decoded a proposed body. Before signing,
    /// confirm it genuinely came from the lead, is not a stale replay, and is
    /// consistent with our own observed registrations — so a forged config takes
    /// `threshold` genuinely malicious members, not one peer or one bad lead.
    /// Then learn its roster/protocol (rebuilding the observer on change) and try
    /// to assemble + publish if we already hold a threshold of signatures.
    pub fn on_decoded_body(&mut self, proposal: SignedProposal) -> Vec<SchedulerAction> {
        // 1. Proposer authentication: only the lead may propose, and the
        //    signature must cover the body.
        if proposal.proposer != self.lead {
            return Vec::new();
        }
        let canonical = proposal.body.canonical_bytes();
        if !proposal
            .proposer
            .verify(&proposal.body.propose_bytes(), &proposal.signature)
        {
            return Vec::new();
        }
        // 2. Replay freshness: reject a strictly older proposal (rollback). The
        //    current round is re-signed idempotently (the sig set dedups).
        if self
            .last_accepted_round
            .is_some_and(|last| proposal.body.round < last)
        {
            return Vec::new();
        }
        // 3. Independent validation: a malicious lead can't insert relays or
        //    services we never saw registered.
        if !self.validate_body(&proposal.body) {
            tracing::debug!(
                registered = self.registered.len(),
                services = self.services.len(),
                "scheduler: rejecting proposal in validate_body"
            );
            return Vec::new();
        }
        self.last_accepted_round = Some(
            self.last_accepted_round
                .map_or(proposal.body.round, |l| l.max(proposal.body.round)),
        );

        let body = proposal.body;
        let sig = self.identity.sign(&body.approve_bytes());
        self.sigs
            .entry(canonical.clone())
            .or_default()
            .insert(self.identity.pubkey(), sig.clone());

        let mut actions = vec![SchedulerAction::Publish {
            topic: crate::committee::TOPIC_COMMITTEE_SIGS.to_string(),
            bytes: bincode::serialize(&CommitteeSig {
                body_bytes: canonical.clone(),
                signer: self.identity.pubkey(),
                signature: sig,
            })
            .expect("CommitteeSig serialises"),
        }];

        self.learn_config(&body);
        if let Some(a) = self.try_assemble(&body) {
            actions.push(a);
        }
        actions
    }

    /// Ingest a peer committee member's signature; assemble + publish if it
    /// crosses the threshold.
    pub fn on_committee_sig(&mut self, sig_msg: CommitteeSig) -> Vec<SchedulerAction> {
        if !self.committee.contains(&sig_msg.signer) {
            return Vec::new();
        }
        // `body_bytes` is canonical (fixint/big-endian) — decode it the same
        // way, not with default bincode, or the re-derived canonical key won't
        // match the stored one and assembly never fires.
        let Ok(body) = AnymoneRoundConfigurationBody::from_canonical_bytes(&sig_msg.body_bytes)
        else {
            return Vec::new();
        };
        if !sig_msg
            .signer
            .verify(&body.approve_bytes(), &sig_msg.signature)
        {
            return Vec::new();
        }
        self.sigs
            .entry(sig_msg.body_bytes.clone())
            .or_default()
            .insert(sig_msg.signer, sig_msg.signature);
        if let Some(a) = self.try_assemble(&body) {
            return vec![a];
        }
        Vec::new()
    }

    fn learn_config(&mut self, body: &AnymoneRoundConfigurationBody) {
        self.epoch_unix_ms = Some(body.epoch_unix_ms);
        // One observer per public subnet, rebuilt only when the subnet set
        // (ids + rosters + protocols) actually changes — so fault-tracking state
        // survives the committee's periodic re-broadcasts of the same config.
        let sig: Vec<(SubnetId, Vec<Pubkey>, Option<SchedulerProtocol>)> = body
            .subnets
            .iter()
            .map(|s| {
                let mut roster = s.relays.clone();
                roster.sort();
                (s.id, roster, proto_kind(&s.protocol))
            })
            .collect();
        if sig != self.current_subnets_sig {
            self.observers = sig
                .iter()
                .filter_map(|(id, roster, proto)| {
                    let leader = crate::runtime::leader_of(roster, *id);
                    build_observer(*proto, roster.clone(), leader, self.params.fault_threshold)
                        .map(|o| (*id, o))
                })
                .collect();
            self.current_subnets_sig = sig;
        }
    }

    fn try_assemble(&mut self, body: &AnymoneRoundConfigurationBody) -> Option<SchedulerAction> {
        let canonical = body.canonical_bytes();
        if self.published.contains(&canonical) {
            return None;
        }
        let entry = self.sigs.get(&canonical)?;
        if (entry.len() as u32) < self.threshold {
            return None;
        }
        let signatures: Vec<Signature> = entry
            .iter()
            .map(|(signer, bytes)| Signature {
                signer: *signer,
                bytes: bytes.clone(),
            })
            .collect();
        let cfg = AnymoneRoundConfiguration {
            body: body.clone(),
            signatures,
        };
        if let Err(e) = cfg.verify_multisig(&self.committee, self.threshold) {
            tracing::debug!(?e, "scheduler: assembled config failed verify_multisig");
            return None;
        }
        self.published.insert(canonical);
        self.published_round = Some(
            self.published_round
                .map_or(body.round, |r| r.max(body.round)),
        );
        Some(SchedulerAction::Publish {
            topic: TOPIC_CONFIG.to_string(),
            bytes: bincode::serialize(&cfg).expect("config encodes"),
        })
    }

    /// Validate a lead-authenticated proposal against our own observed
    /// registrations and the scheduler's structural bounds before signing it.
    /// Tolerant of cross-member view divergence (subset checks, so a member that
    /// hasn't yet seen a registration simply abstains rather than blocking
    /// quorum), strict on forgery signals: a relay or service we never saw
    /// register, an exchange key that doesn't match what its owner registered, an
    /// out-of-bounds size, or a protocol the scheduler never emits all reject it.
    fn validate_body(&self, body: &AnymoneRoundConfigurationBody) -> bool {
        if !validate_structure(body) {
            return false;
        }
        if !body
            .services
            .iter()
            .all(|svc| self.services.get(&svc.tag) == Some(&svc.pubkey))
        {
            return false;
        }
        for s in &body.subnets {
            if !s.relays.iter().all(|pk| self.registered.contains(pk)) {
                return false;
            }
            let keys_ok = match &s.protocol {
                ProtocolConfig::Noop(_) => true,
                ProtocolConfig::Adcnet(c) => {
                    self.exchange_keys_match(&c.relay_exchange_keys)
                        && self.aggregation_valid(&c.aggregation)
                }
                ProtocolConfig::Panetiere(c) => {
                    self.exchange_keys_match(&c.relay_exchange_keys)
                        && self.aggregation_valid(&c.aggregation)
                }
                ProtocolConfig::ScheduledPanetiere(c) => {
                    self.exchange_keys_match(&c.relay_exchange_keys)
                        && self.aggregation_valid(&c.aggregation)
                }
                // Rejected by validate_structure already.
                ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => false,
            };
            if !keys_ok {
                return false;
            }
        }
        true
    }

    /// Every `(relay, exchange_key)` pair in a proposed protocol config must
    /// match what that relay actually registered.
    fn exchange_keys_match(&self, keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        keys.iter()
            .all(|(pk, xk)| self.relay_xpubs.get(pk) == Some(xk))
    }

    /// Each aggregator group must be a `replication`-sized committee of
    /// registered relays whose exchange keys match registration.
    fn aggregation_valid(&self, agg: &Option<Aggregation>) -> bool {
        if !aggregation_structural_ok(agg) {
            return false;
        }
        let Some(a) = agg else { return true };
        a.groups.iter().all(|g| {
            g.aggregators.iter().all(|pk| self.registered.contains(pk))
                && self.exchange_keys_match(&g.aggregator_exchange_keys)
        })
    }

    fn subnet_escalated(&self, id: SubnetId) -> bool {
        self.escalation
            .get(&id)
            .is_some_and(|e| e.general || e.relays.iter().any(|pk| self.sidelined.contains(pk)))
    }

    /// Per-subnet protocol: escalated subnets run Panetiere, the rest ADCNet —
    /// unless `params.pin` fixes every subnet to one protocol (escalation
    /// state is still tracked underneath; only the protocol choice is fixed).
    fn subnet_protocols(&self) -> Vec<SchedulerProtocol> {
        (0..self.subnet_count.max(1))
            .map(|i| {
                self.params.pin.unwrap_or_else(|| {
                    if self.subnet_escalated(i as SubnetId) {
                        SchedulerProtocol::Panetiere
                    } else {
                        SchedulerProtocol::Adcnet
                    }
                })
            })
            .collect()
    }

    /// Upgrades a `Panetiere` entry to `ScheduledPanetiere` on sustained traffic,
    /// downgrades after `SCHED_DOWNGRADE_GRACE` low ticks. An `Adcnet` entry
    /// drops its state, so escalation always starts one-round. A `pin` of
    /// `ScheduledPanetiere` forces `scheduled` permanently but still runs the
    /// sizing below, so vector_bytes tracks real traffic even when pinned.
    fn apply_sched_mode(&mut self, protos: &mut [SchedulerProtocol]) {
        let upgrade_bytes = 2 * self.params.message_size;
        let downgrade_bytes = self.params.message_size / 2;
        for (i, proto) in protos.iter_mut().enumerate() {
            let id = i as SubnetId;
            if *proto == SchedulerProtocol::Adcnet {
                self.sched_mode.remove(&id);
                continue;
            }
            let pinned_scheduled = *proto == SchedulerProtocol::ScheduledPanetiere;
            let bytes = self
                .observers
                .get(&id)
                .and_then(|o| o.decoded_bytes_recent(SCHED_WINDOW))
                .unwrap_or(0);
            let state = self.sched_mode.entry(id).or_default();
            if pinned_scheduled {
                state.scheduled = true;
            } else if !state.scheduled && bytes >= upgrade_bytes {
                state.scheduled = true;
                state.downgrade_streak = 0;
            } else if state.scheduled && bytes <= downgrade_bytes {
                state.downgrade_streak += 1;
                if state.downgrade_streak >= SCHED_DOWNGRADE_GRACE {
                    state.scheduled = false;
                    state.downgrade_streak = 0;
                }
            } else {
                state.downgrade_streak = 0;
            }
            if state.scheduled {
                let min_vector = round_up_to(
                    expected_active(self.capacity) as usize * self.params.message_size / 2,
                    8192,
                );
                let desired = round_up_to(bytes.saturating_mul(3) / 2, 8192)
                    .max(min_vector)
                    .min(MAX_VECTOR_BYTES);
                if state.vector_bytes == 0
                    || desired.abs_diff(state.vector_bytes) as f64
                        >= state.vector_bytes as f64 * SCHED_VECTOR_RESIZE_MARGIN
                {
                    state.vector_bytes = desired;
                }
                *proto = SchedulerProtocol::ScheduledPanetiere;
            }
        }
    }

    fn build_body(&self, protos: &[SchedulerProtocol]) -> AnymoneRoundConfigurationBody {
        let mut relay_vec: Vec<Pubkey> = self.registered.iter().copied().collect();
        relay_vec.sort();
        let mut service_vec: Vec<ServiceEntry> = self
            .services
            .iter()
            .map(|(tag, pk)| ServiceEntry {
                tag: *tag,
                pubkey: *pk,
            })
            .collect();
        service_vec.sort_by_key(|s| s.tag.0);

        let dur_ms = self.params.public_round_duration.as_millis() as u64;
        let relay_xk: Vec<(Pubkey, ExchangePublicKeyWire)> = relay_vec
            .iter()
            .filter_map(|pk| self.relay_xpubs.get(pk).map(|xk| (*pk, xk.clone())))
            .collect();
        let aggregation = self
            .params
            .aggregation
            .then(|| build_subnet_aggregation(self.capacity, &relay_vec, &relay_xk))
            .flatten();
        let n = relay_vec.len() as u32;
        let subnets = protos
            .iter()
            .enumerate()
            .map(|(i, proto)| {
                let protocol = match proto {
                    SchedulerProtocol::Panetiere => ProtocolConfig::Panetiere(PanetiereConfig {
                        round_duration_ms: dur_ms,
                        message_size: self.params.message_size,
                        estimated_messages: expected_active(self.capacity),
                        client_set_min: 0,
                        client_set_max: self.capacity,
                        threshold: (n / 2 + 1).max(n.saturating_sub(2)),
                        setup_seed: crate::keys::derive_seed(b"anymone/subnet-seed", &relay_vec),
                        relay_exchange_keys: relay_xk.clone(),
                        aggregation: aggregation.clone(),
                    }),
                    SchedulerProtocol::ScheduledPanetiere => {
                        let vector_bytes = self
                            .sched_mode
                            .get(&(i as SubnetId))
                            .map(|s| s.vector_bytes)
                            .filter(|&v| v > 0)
                            .unwrap_or_else(|| {
                                round_up_to(
                                    expected_active(self.capacity) as usize
                                        * self.params.message_size
                                        / 2,
                                    8192,
                                )
                                .min(MAX_VECTOR_BYTES)
                            });
                        ProtocolConfig::ScheduledPanetiere(
                            crate::config::ScheduledPanetiereConfig {
                                round_duration_ms: dur_ms,
                                message_size: self.params.message_size,
                                vector_bytes,
                                estimated_messages: self.capacity,
                                client_set_min: 0,
                                client_set_max: self.capacity,
                                threshold: (n / 2 + 1).max(n.saturating_sub(2)),
                                setup_seed: crate::keys::derive_seed(
                                    b"anymone/subnet-seed",
                                    &relay_vec,
                                ),
                                relay_exchange_keys: relay_xk.clone(),
                                aggregation: aggregation.clone(),
                            },
                        )
                    }
                    // ADCNet for `Adcnet` (and the never-scheduled `Noop`).
                    _ => ProtocolConfig::Adcnet(AdcnetConfig {
                        round_duration_ms: dur_ms,
                        max_payload_bytes: self.params.message_size,
                        estimated_messages: expected_active(self.capacity),
                        client_set_min: 0,
                        client_set_max: self.capacity,
                        relay_exchange_keys: relay_xk.clone(),
                        aggregation: aggregation.clone(),
                    }),
                };
                Subnet {
                    id: i as SubnetId,
                    relays: relay_vec.clone(),
                    protocol,
                    cover_rate: self.cover_rate,
                }
            })
            .collect();
        AnymoneRoundConfigurationBody {
            round: self.public_round,
            epoch_unix_ms: self
                .epoch_unix_ms
                .unwrap_or_else(crate::config::now_unix_ms),
            services: service_vec,
            subnets,
        }
    }
}

/// Round-independent fingerprint of a proposal: protocol + sorted relay set +
/// sorted service tags. The lead stages a new config only when this changes.
/// Clients aren't part of the fingerprint — they're permissionless and never
/// appear in the config (they key-exchange directly with relays on the subnet).
fn content_key(
    protos: &[SchedulerProtocol],
    vector_bytes: &[usize],
    pin: Option<SchedulerProtocol>,
    relays: &HashSet<Pubkey>,
    services: &HashMap<ServiceTag, Pubkey>,
    capacity: u32,
    cover_rate: f32,
) -> Vec<u8> {
    let mut key = Vec::new();
    // Subnet count + each subnet's protocol, so one subnet escalating re-proposes.
    key.extend_from_slice(&(protos.len() as u32).to_le_bytes());
    for (i, p) in protos.iter().enumerate() {
        key.push(match p {
            SchedulerProtocol::Adcnet => 1,
            SchedulerProtocol::Panetiere => 2,
            SchedulerProtocol::ScheduledPanetiere => 3,
        });
        if *p == SchedulerProtocol::ScheduledPanetiere {
            key.extend_from_slice(&(vector_bytes[i] as u32).to_le_bytes());
        }
    }
    // Toggling the pin must re-propose even if it doesn't (yet) change `protos`.
    key.push(match pin {
        None => 0,
        Some(SchedulerProtocol::Adcnet) => 1,
        Some(SchedulerProtocol::Panetiere) => 2,
        Some(SchedulerProtocol::ScheduledPanetiere) => 3,
    });
    key.extend_from_slice(&capacity.to_le_bytes());
    // Quantize so a change in the committee's cover target re-proposes a config.
    key.push((cover_rate.clamp(0.0, 1.0) * 100.0).round() as u8);
    let mut relay_vec: Vec<Pubkey> = relays.iter().copied().collect();
    relay_vec.sort();
    for pk in &relay_vec {
        key.extend_from_slice(&pk.0);
    }
    key.push(0xff);
    let mut tags: Vec<[u8; 20]> = services.keys().map(|t| t.0).collect();
    tags.sort();
    for t in &tags {
        key.extend_from_slice(t);
    }
    key
}

/// Aggregator layer for a Panetiere subnet of `capacity` clients, or `None`
/// below the threshold. Group count is `min(1 + capacity/16, √capacity/2)`,
/// clamped to at least one and at most one distinct `replication`-sized committee
/// per group (a node runs one aggregator session, so a relay can't staff two).
fn build_subnet_aggregation(
    capacity: u32,
    relay_vec: &[Pubkey],
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
) -> Option<Aggregation> {
    let replication = AGGREGATOR_REPLICATION.min(relay_vec.len() as u32);
    if capacity <= AGGREGATION_THRESHOLD || replication == 0 {
        return None;
    }
    let max_groups = relay_vec.len() as u32 / replication;
    let group_count = ((1.0 + capacity as f64 / 16.0)
        .min((capacity as f64).sqrt() / 2.0)
        .floor() as u32)
        .min(max_groups)
        .max(1);
    let xk: HashMap<Pubkey, ExchangePublicKeyWire> = relay_xk.iter().cloned().collect();
    let groups = (0..group_count)
        .map(|g| {
            let aggregators: Vec<Pubkey> = (0..replication)
                .map(|r| relay_vec[((g * replication + r) as usize) % relay_vec.len()])
                .collect();
            let aggregator_exchange_keys = aggregators
                .iter()
                .filter_map(|pk| xk.get(pk).map(|x| (*pk, x.clone())))
                .collect();
            AggregatorGroup {
                aggregators,
                aggregator_exchange_keys,
            }
        })
        .collect();
    Some(Aggregation {
        replication,
        groups,
    })
}

fn proto_kind(p: &ProtocolConfig) -> Option<SchedulerProtocol> {
    match p {
        ProtocolConfig::Adcnet(_) => Some(SchedulerProtocol::Adcnet),
        ProtocolConfig::Panetiere(_) => Some(SchedulerProtocol::Panetiere),
        ProtocolConfig::ScheduledPanetiere(_) => Some(SchedulerProtocol::ScheduledPanetiere),
        ProtocolConfig::Noop(_) | ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => {
            None
        }
    }
}

/// The public subnet's liveness observer, kept as a concrete type (not a
/// `Box<dyn Session>`) so the core can read the observed anonymity set — the
/// per-round canonical client-set size each observer already tracks — and size
/// the next config's capacity to it.
enum PublicObserver {
    Adcnet(AdcnetObserverSession),
    Panetiere(PanetiereObserverSession),
}

impl PublicObserver {
    fn on_inbound(&mut self, from: Pubkey, bytes: Vec<u8>) {
        match self {
            PublicObserver::Adcnet(o) => {
                o.on_inbound(from, bytes);
            }
            PublicObserver::Panetiere(o) => {
                o.on_inbound(from, bytes);
            }
        }
    }

    fn end_round_faults(&mut self, round: Round) -> Vec<Fault> {
        let now = std::time::Instant::now();
        match self {
            PublicObserver::Adcnet(o) => o.end_round(round, now).faults,
            PublicObserver::Panetiere(o) => o.end_round(round, now).faults,
        }
    }

    /// Advance the observer's round clamp to the highest subnet round observed
    /// so far, since nothing else here ever calls its `begin_round`.
    fn refresh_clock(&mut self) {
        let now = std::time::Instant::now();
        match self {
            PublicObserver::Adcnet(o) => {
                if let Some(r) = o.observed_round() {
                    o.begin_round(r, now);
                }
            }
            PublicObserver::Panetiere(o) => {
                if let Some(r) = o.round() {
                    o.begin_round(r, now);
                }
            }
        }
    }

    /// Observed anonymity set (canonical client-set size), or `None` if no set
    /// has been announced yet.
    fn anonymity_set(&self) -> Option<usize> {
        match self {
            PublicObserver::Adcnet(o) => o.anonymity_set(),
            PublicObserver::Panetiere(o) => o.anonymity_set(),
        }
    }

    fn share_frontier(&self) -> Option<u64> {
        match self {
            PublicObserver::Adcnet(o) => o.share_frontier(),
            PublicObserver::Panetiere(o) => o.share_frontier(),
        }
    }

    /// Mean decoded bytes/round over `window` — the scheduled-mode upgrade
    /// signal. `None` for ADCNet (not part of the Panetiere family).
    fn decoded_bytes_recent(&self, window: u64) -> Option<usize> {
        match self {
            PublicObserver::Adcnet(_) => None,
            PublicObserver::Panetiere(o) => Some(o.decoded_bytes_recent(window)),
        }
    }
}

fn build_observer(
    proto: Option<SchedulerProtocol>,
    roster: Vec<Pubkey>,
    leader: Pubkey,
    fault_threshold: u64,
) -> Option<PublicObserver> {
    match proto {
        Some(SchedulerProtocol::Adcnet) => Some(PublicObserver::Adcnet(
            AdcnetObserverSession::new(roster, leader, fault_threshold),
        )),
        Some(SchedulerProtocol::Panetiere) | Some(SchedulerProtocol::ScheduledPanetiere) => {
            Some(PublicObserver::Panetiere(PanetiereObserverSession::new(
                roster,
                Some(leader),
                fault_threshold,
            )))
        }
        _ => None,
    }
}
