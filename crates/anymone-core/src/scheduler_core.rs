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
use crate::log_target::{GOV, SCHED};
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

/// Most relays the committee will place. Every proposal carries each placed
/// relay's exchange keys — the ML-KEM encapsulation key alone is 1184 bytes — so
/// the roster is what sizes [`crate::panetiere::COMMITTEE_MSG_BYTES`]. Placing
/// more than that channel can carry would wedge the committee, which rejects an
/// oversize proposal rather than truncating it.
pub const MAX_COMMITTEE_RELAYS: usize = 16;

/// Subnet capacity before any client population has been observed, and the
/// default [`SchedulerParams::min_capacity`].
pub const INITIAL_CAPACITY: u32 = 8;
/// Smallest capacity we'll size down to (keeps a little headroom for churn).
const MIN_CAPACITY: u32 = 8;
/// Default bar on an integrity offender's re-registration. Overridable via
/// [`SchedulerParams::integrity_backoff_ms`].
pub const INTEGRITY_BACKOFF_MS: u64 = 6 * 60 * 1000;
/// Predicted client set above which ADCNet routes clients' blinded contributions
/// through an aggregator layer (lessening the leader/broadcast fan-in).
const AGGREGATION_THRESHOLD: u32 = 16;
/// Rounds above the established one a proposal may claim.
const MAX_ROUND_ADVANCE: Round = 8;
/// Max distance between a `FaultReport.round` and its subnet's `share_frontier`.
const FAULT_REPORT_ROUND_WINDOW: Round = 32;
/// How far a subnet's last canonical set may lag the freshest one and still
/// count toward sizing (tolerates per-subnet decode latency, not dead subnets).
const ANON_SET_FRESHNESS: Round = 4;
/// Committee ticks after an observer is rebuilt (roster/protocol change) during
/// which its faults are ignored — a cutover gap or forming mesh is not a fault.
const OBSERVER_FAULT_GRACE: u32 = 3;
/// Consecutive ticks the capacity-resize condition must hold before acting.
const CAPACITY_RESIZE_GRACE: u32 = 3;
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
/// with headroom below the transport ceiling.
const MAX_SUBNET_WIRE: usize = crate::transport::MAX_TRANSMIT_SIZE * 3 / 4;

/// Capacity ceiling. Subnets split well before this; at this many clients the biggest
/// message (the ciphertext) is still a few hundred KB, far under [`MAX_SUBNET_WIRE`],
/// so a fixed cap avoids sizing a subnet whose message would blow the p2p limit.
const MAX_SUBNET_CLIENTS: u32 = 300;

/// Largest per-round wire message the given subnet protocol broadcasts, via each
/// protocol's wire-size estimator.
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
            c.threshold,
            c.encoding,
            c.set_formation,
        ),
        ProtocolConfig::ScheduledPanetiere(c) => crate::panetiere_scheduled::max_wire_estimate(
            c.vector_bytes,
            c.estimated_messages,
            c.client_set_max,
            n_relays,
            c.threshold,
            c.set_formation,
        ),
        ProtocolConfig::Noop(c) => crate::noop::max_wire_estimate(
            c.message_size,
            c.client_set_max,
            c.client_set_max,
            n_relays,
        ),
        ProtocolConfig::ScheduledAdcnet(c) => {
            crate::adcnet::scheduled_max_wire_estimate(c, n_relays)
        }
    }
}

/// Consensus set formation spends the round on `CONSENSUS_PHASES` plus one
/// Dolev–Strong round per tolerated relay, each needing a gossip hop to land.
/// A round too short for the grid would cut the relay rounds off mid-agreement,
/// so the config is rejected instead.
const CONSENSUS_PHASE_MS: u64 = 150;

fn consensus_cadence_fits(
    round_duration_ms: u64,
    set_formation: crate::config::SetFormation,
    n_relays: usize,
    threshold: u32,
) -> bool {
    if set_formation != crate::config::SetFormation::Consensus {
        return true;
    }
    let n = n_relays.max(1);
    let phases = crate::panetiere::CONSENSUS_PHASES + (n - threshold as usize + 1);
    round_duration_ms >= (phases as u64 + 1) * CONSENSUS_PHASE_MS
}

fn aggregation_structural_ok(agg: &Option<Aggregation>) -> bool {
    let Some(a) = agg else { return true };
    !a.groups.is_empty() && unique(a.groups.iter().map(|g| g.aggregator))
}

fn unique<T: Ord>(items: impl Iterator<Item = T>) -> bool {
    let mut seen: Vec<T> = items.collect();
    let len = seen.len();
    seen.sort_unstable();
    seen.dedup();
    seen.len() == len
}

/// Checks independent of local state — safe to run before `registered`/`services`
/// are populated, e.g. on a just-verified published config ahead of `learn_config`.
fn validate_structure(body: &AnymoneRoundConfigurationBody) -> bool {
    if body.subnets.is_empty() || body.subnets.len() > MAX_SUBNETS {
        return false;
    }
    // Duplicates would have `apply_config` start two workers and detach one.
    if !unique(body.subnets.iter().map(|s| s.id)) {
        return false;
    }
    if !unique(body.services.iter().map(|s| s.tag.0)) {
        return false;
    }
    if !unique(body.relay_exchange_keys.iter().map(|(pk, _)| *pk)) {
        return false;
    }
    for s in &body.subnets {
        if s.relays.is_empty() || s.relays.len() > MAX_COMMITTEE_RELAYS {
            return false;
        }
        if !unique(s.relays.iter().copied()) {
            return false;
        }
        if !(0.0..=1.0).contains(&s.cover_rate) {
            return false;
        }
        if s.protocol.round_duration() == Duration::ZERO
            || s.protocol.message_size() == 0
            || s.protocol.client_set_min() > s.protocol.client_set_max()
        {
            return false;
        }
        match &s.protocol {
            ProtocolConfig::Noop(c) => {
                if c.client_set_max < MIN_CAPACITY {
                    return false;
                }
            }
            ProtocolConfig::Adcnet(c) => {
                if c.client_set_max < MIN_CAPACITY
                    || c.estimated_messages == 0
                    || !aggregation_structural_ok(&c.aggregation)
                {
                    return false;
                }
            }
            ProtocolConfig::Panetiere(c) => {
                let n = s.relays.len() as u32;
                let threshold_ok = c.threshold >= n / 2 + 1 && c.threshold <= n.max(1);
                if c.client_set_max < MIN_CAPACITY
                    || c.estimated_messages == 0
                    || !threshold_ok
                    || !consensus_cadence_fits(
                        c.round_duration_ms,
                        c.set_formation,
                        s.relays.len(),
                        c.threshold,
                    )
                {
                    return false;
                }
            }
            ProtocolConfig::ScheduledPanetiere(c) => {
                let n = s.relays.len() as u32;
                let threshold_ok = c.threshold >= n / 2 + 1 && c.threshold <= n.max(1);
                if c.client_set_max < MIN_CAPACITY
                    || c.estimated_messages == 0
                    || !threshold_ok
                    || c.message_size > u16::MAX as usize
                    || c.vector_bytes == 0
                    || !consensus_cadence_fits(
                        c.round_duration_ms,
                        c.set_formation,
                        s.relays.len(),
                        c.threshold,
                    )
                {
                    return false;
                }
            }
            ProtocolConfig::ScheduledAdcnet(c) => {
                if c.client_set_max < MIN_CAPACITY
                    || c.auction_slots == 0
                    || c.auction_slots > MAX_SUBNET_CLIENTS
                    || c.message_length < 1024
                    || c.message_length % 1024 != 0
                    || c.message_length > MAX_VECTOR_BYTES
                    || c.min_message_size == 0
                    || c.min_message_size as usize > c.message_length
                {
                    return false;
                }
            }
        }
        if subnet_max_wire(&s.protocol, s.relays.len()) > MAX_SUBNET_WIRE {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod sizing_tests {
    use super::*;

    #[test]
    fn configured_threshold_controls_consensus_cadence() {
        use crate::config::{PanetiereConfig, ScheduledPanetiereConfig, SetFormation};
        let relays: Vec<_> = (0..5).map(|_| Identity::generate().pubkey()).collect();
        let phase_ms = CONSENSUS_PHASE_MS;
        let duration = (crate::panetiere::CONSENSUS_PHASES as u64 + 2) * phase_ms;
        for threshold in [0, 2, 3, 4, 5, 6] {
            for protocol in [
                ProtocolConfig::Panetiere(PanetiereConfig {
                    threshold,
                    round_duration_ms: duration,
                    set_formation: SetFormation::Consensus,
                    client_set_max: MIN_CAPACITY,
                    estimated_messages: 1,
                    ..Default::default()
                }),
                ProtocolConfig::ScheduledPanetiere(ScheduledPanetiereConfig {
                    threshold,
                    round_duration_ms: duration,
                    set_formation: SetFormation::Consensus,
                    client_set_max: MIN_CAPACITY,
                    estimated_messages: 1,
                    ..Default::default()
                }),
            ] {
                let cfg = AnymoneRoundConfiguration::singleton_subnet(
                    0,
                    protocol,
                    relays.clone(),
                    vec![],
                    vec![],
                );
                assert_eq!(validate_structure(&cfg.body), threshold == 5);
            }
        }
    }

    #[test]
    fn reference_capacity_fits_budget() {
        // At the capacity ceiling the biggest message stays well under the wire budget.
        let msg = 256usize;
        let est = expected_active(MAX_SUBNET_CLIENTS);
        for n_relays in [5usize, 8] {
            let worst = crate::adcnet::max_wire_estimate(msg, est, MAX_SUBNET_CLIENTS, n_relays)
                .max(crate::panetiere::max_wire_estimate(
                    msg,
                    est,
                    MAX_SUBNET_CLIENTS,
                    n_relays,
                    crate::panetiere::rs_k(n_relays) as u32,
                    crate::config::Encoding::Mse,
                    crate::config::SetFormation::Consensus,
                ));
            assert!(
                worst <= MAX_SUBNET_WIRE,
                "reference message {worst} at {n_relays} relays exceeds budget"
            );
        }

        // The worst-case proposal (MAX_SUBNETS, largest protocol config, max
        // aggregator groups) must fit the committee channel, or the committee
        // wedges: it stages the config every round and never decodes it back. A
        // body carries every placed relay's exchange keys, so it grows with the
        // roster — measured at the largest roster the cap is sized for.
        let mut worst = 0;
        for n_relays in [4usize, 8, MAX_COMMITTEE_RELAYS] {
            let id = Identity::generate();
            let mut core = SchedulerCore::new(
                id.clone(),
                vec![id.pubkey()],
                1,
                SchedulerParams {
                    public_round_duration: Duration::from_secs(8),
                    min_relays: 4,
                    min_services: 1,
                    fault_threshold: 2,
                    grow_at: SUBNET_GROW_AT,
                    message_size: 1024,
                    integrity_backoff_ms: 6 * 60 * 1000,
                    sideline: false,
                    renegotiate_on_fault: true,
                    min_capacity: 8,
                    vector_bytes: 0,
                    pin: None,
                    aggregation: true,
                    encoding: crate::config::Encoding::default(),
                    set_formation: crate::config::SetFormation::Leader,
                    attested_subnets: Vec::new(),
                    attestation: crate::config::AttestationPolicy::default(),
                },
            );
            for _ in 0..n_relays {
                let rid = Identity::generate();
                core.registered.insert(rid.pubkey());
                core.relay_xpubs.insert(rid.pubkey(), rid.exchange_keys());
            }
            core.services
                .insert(ServiceTag([1u8; 20]), Identity::generate().pubkey());
            core.capacity = MAX_SUBNET_CLIENTS;
            let body = core.build_body(&vec![SchedulerProtocol::ScheduledPanetiere; MAX_SUBNETS]);
            let proposal = SignedProposal {
                body,
                proposer: id.pubkey(),
                signature: vec![0u8; 64],
            };
            let len = bincode::serialize(&proposal).unwrap().len();
            println!("{MAX_SUBNETS} subnets, {n_relays} relays: {len} bytes");
            worst = worst.max(len);
        }
        assert!(
            worst <= crate::panetiere::COMMITTEE_MSG_BYTES,
            "{MAX_SUBNETS}-subnet proposal at {MAX_COMMITTEE_RELAYS} relays ({worst} bytes) \
             exceeds COMMITTEE_MSG_BYTES"
        );
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
                grow_at: SUBNET_GROW_AT,
                message_size: 256,
                integrity_backoff_ms: 6 * 60 * 1000,
                sideline: true,
                renegotiate_on_fault: true,
                min_capacity: 8,
                vector_bytes: 0,
                pin: None,
                aggregation: true,
                encoding: crate::config::Encoding::default(),
                set_formation: crate::config::SetFormation::Leader,
                attested_subnets: Vec::new(),
                attestation: crate::config::AttestationPolicy::default(),
            },
        );
        let body = AnymoneRoundConfigurationBody {
            round: 0,
            epoch_unix_ms: 0,
            services: vec![],
            relay_exchange_keys: vec![],
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
                attested: false,
            }],
            relay_client_addrs: vec![],
            watchers: vec![],
            attestation: crate::config::AttestationPolicy::default(),
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
    Publish {
        topic: crate::transport::Topic,
        bytes: Vec<u8>,
    },
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
    /// keeps the fault feed (reports and dashboard attribution)
    /// but leaves the roster intact — for showcases where a corrupted relay
    /// should be *seen*, not removed.
    pub sideline: bool,
    /// Whether observed faults change the roster (sidelining and re-registration). `false` logs faults and otherwise ignores them —
    /// a fault-triggered reconfiguration is itself a round-losing cutover, so a
    /// stabilizing deployment turns the reaction off rather than tuning graces.
    pub renegotiate_on_fault: bool,
    /// Fixed scheduled-Panetiere message-vector width; `0` derives it from
    /// capacity and observed traffic.
    pub vector_bytes: usize,
    /// Protocol for every subnet; `None` selects ADCNet.
    pub pin: Option<SchedulerProtocol>,
    /// Whether the committee may route large ADCNet subnets through an
    /// aggregator layer above [`AGGREGATION_THRESHOLD`].
    pub aggregation: bool,
    /// Payload encoding every proposed Panetiere subnet carries.
    pub encoding: crate::config::Encoding,
    /// How proposed Panetiere subnets fix their canonical client set.
    pub set_formation: crate::config::SetFormation,
    /// Subnet ids that accept only attested clients. Ids the network has not
    /// grown to yet are simply inert.
    pub attested_subnets: Vec<SubnetId>,
    /// What those subnets' relays accept as proof.
    pub attestation: crate::config::AttestationPolicy,
}

impl Default for SchedulerParams {
    fn default() -> Self {
        Self {
            public_round_duration: Duration::from_secs(1),
            min_relays: 1,
            min_services: 1,
            fault_threshold: 2,
            grow_at: SUBNET_GROW_AT,
            message_size: 256,
            integrity_backoff_ms: INTEGRITY_BACKOFF_MS,
            min_capacity: INITIAL_CAPACITY,
            sideline: true,
            renegotiate_on_fault: true,
            vector_bytes: 0,
            pin: None,
            aggregation: true,
            encoding: crate::config::Encoding::default(),
            set_formation: crate::config::SetFormation::Leader,
            attested_subnets: Vec::new(),
            attestation: crate::config::AttestationPolicy::default(),
        }
    }
}

const SCHED_WINDOW: u64 = 8;
/// Vector resize hysteresis: re-propose only past this fractional change.
const SCHED_VECTOR_RESIZE_MARGIN: f64 = 0.25;
const MAX_VECTOR_BYTES: usize = 128 * 1024;

fn round_up_to(x: usize, to: usize) -> usize {
    x.div_ceil(to) * to
}

#[derive(Default)]
struct ScheduledVector {
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
    /// Per-subnet scheduled-Panetiere vector sizing.
    scheduled_vectors: std::collections::BTreeMap<SubnetId, ScheduledVector>,

    services: HashMap<ServiceTag, Pubkey>,
    relay_xpubs: HashMap<Pubkey, ExchangePublicKeyWire>,
    /// Client-facing address per relay that advertised one.
    relay_client_addrs: HashMap<Pubkey, String>,
    /// Registered follow-only nodes; secondary peers, never in a subnet roster.
    watchers: HashSet<Pubkey>,

    // Liveness observer for the current public subnet (protocol-specific).
    /// Per-subnet liveness observers (one per public subnet), keyed by id. They
    /// drive both fault detection (every subnet) and the total client tally.
    observers: std::collections::BTreeMap<SubnetId, PublicObserver>,
    /// Remaining grace ticks per freshly rebuilt observer ([`OBSERVER_FAULT_GRACE`]).
    observer_grace: HashMap<SubnetId, u32>,
    /// Per-subnet round duration from the adopted body, for deriving each
    /// subnet's wall-clock round at tick.
    subnet_round_ms: std::collections::BTreeMap<SubnetId, u64>,
    /// Signature of the current public-subnet set (id + sorted roster + proto);
    /// observers are rebuilt only when this changes, so fault state survives the
    /// committee's periodic config re-broadcasts.
    current_subnets_sig: Vec<(SubnetId, Vec<Pubkey>, Option<SchedulerProtocol>)>,
    /// Number of public ADCNet subnets the committee currently schedules.
    subnet_count: usize,
    /// Consecutive ticks the shrink condition has held — gates subnet removal
    /// so a re-home transient can't immediately undo a just-added subnet.
    shrink_streak: u32,
    /// Consecutive ticks the capacity-resize condition has held.
    capacity_streak: u32,
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
            scheduled_vectors: std::collections::BTreeMap::new(),
            services: HashMap::new(),
            relay_client_addrs: HashMap::new(),
            watchers: HashSet::new(),
            relay_xpubs: HashMap::new(),
            observers: std::collections::BTreeMap::new(),
            observer_grace: HashMap::new(),
            subnet_round_ms: std::collections::BTreeMap::new(),
            current_subnets_sig: Vec::new(),
            subnet_count: 1,
            shrink_streak: 0,
            capacity_streak: 0,
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
            Registration::Watcher { pubkey, .. } => {
                if self.watchers.insert(pubkey) {
                    tracing::debug!(
                        target: GOV,
                        watcher = %pubkey,
                        watchers = self.watchers.len(),
                        "registration: first announcement from a watcher"
                    );
                }
            }
            Registration::Relay {
                pubkey,
                exchange_pubkey,
                client_addr,
                ..
            } => {
                if self.integrity_offenders.contains_key(&pubkey) {
                    // Held out until `integrity_backoff_ms` expires; the relay
                    // re-announces the whole time with no visible effect.
                    tracing::debug!(
                        target: GOV,
                        relay = %pubkey,
                        "registration ignored: relay is serving an integrity backoff"
                    );
                } else {
                    self.sidelined.remove(&pubkey);
                    // Re-announced every few seconds; the first arrival is the
                    // one that measures delivery latency.
                    if self.registered.insert(pubkey) {
                        tracing::debug!(
                            target: GOV,
                            relay = %pubkey,
                            registered = self.registered.len(),
                            "registration: first announcement from a relay"
                        );
                    }
                    self.relay_xpubs.insert(pubkey, exchange_pubkey);
                    match client_addr {
                        Some(addr) => self.relay_client_addrs.insert(pubkey, addr),
                        None => self.relay_client_addrs.remove(&pubkey),
                    };
                }
            }
            Registration::Service {
                tag,
                pubkey,
                exchange_pubkey: _,
                ..
            } => {
                if self.services.insert(tag, pubkey).is_none() {
                    tracing::debug!(
                        target: GOV,
                        service = %pubkey,
                        services = self.services.len(),
                        "registration: first announcement for a service tag"
                    );
                }
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
    /// Public so tests can inject faults without
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
        if !self.params.renegotiate_on_fault {
            for fault in &faults {
                tracing::info!(
                    target: GOV,
                    subnet,
                    kind = ?fault.kind,
                    attribution = ?fault.attribution,
                    "observed fault ignored: renegotiate_on_fault is off"
                );
            }
            return;
        }
        for fault in faults {
            let integrity = fault.kind == FaultKind::Integrity;
            match fault.attribution {
                Attribution::Peers(pks) => {
                    for pk in pks {
                        tracing::warn!(
                            target: GOV,
                            subnet,
                            relay = %pk,
                            kind = ?fault.kind,
                            sidelined = self.params.sideline,
                            "observed attributed fault"
                        );
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
                    tracing::warn!(
                        target: GOV,
                        subnet,
                        kind = ?fault.kind,
                        "observed unattributable fault"
                    );
                }
            }
        }
    }

    /// Ingest an integrity `FaultReport` gossiped on `TOPIC_FAULTS`. Every relay
    /// on the subnet decodes, so any of them may report; the evidence must be
    /// signed by the very relay it attributes, so a lying reporter can't frame an
    /// honest one, and `seen_integrity_faults` applies the first report per
    /// (subnet, round, culprit). Liveness stays the observer's job.
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
            _ => {
                tracing::debug!(
                    target: GOV,
                    subnet = report.subnet,
                    "fault report for a subnet we don't track, ignored"
                );
                return;
            }
        };
        if !roster.contains(&from) {
            tracing::debug!(
                target: GOV,
                subnet = report.subnet,
                reporter = %from,
                "fault report from outside the subnet's roster, ignored"
            );
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
                    target: GOV,
                    subnet = report.subnet,
                    report_round = report.round,
                    frontier,
                    "scheduler: rejecting fault report outside the subnet's round window"
                );
                return;
            }
        }
        // An integrity fault we can't re-derive from the reporter's own evidence:
        // either the evidence is malformed or the reporter is lying.
        let Some(culprit) =
            crate::panetiere::integrity_culprit_from_evidence(&report.fault.evidence, &roster)
        else {
            tracing::warn!(
                target: GOV,
                subnet = report.subnet,
                report_round = report.round,
                reporter = %from,
                "fault report evidence does not attribute a culprit, ignored"
            );
            return;
        };
        if report.fault.attribution != Attribution::Peers(vec![culprit]) {
            tracing::warn!(
                target: GOV,
                subnet = report.subnet,
                report_round = report.round,
                reporter = %from,
                derived = %culprit,
                "fault report attributes a relay its evidence does not, ignored"
            );
            return;
        }
        if !self
            .seen_integrity_faults
            .insert((report.subnet, report.round, culprit))
        {
            tracing::trace!(
                target: GOV,
                subnet = report.subnet,
                report_round = report.round,
                "fault report already applied, ignored"
            );
            return;
        }
        self.apply_observed_faults(report.subnet, vec![report.fault], now_unix_ms);
    }

    /// Advance one committee round: tick the observer, apply any faults, and —
    /// if we're the lead and the proposal content changed — stage a new config.
    pub fn tick(&mut self, round: Round, now_unix_ms: u64) -> Vec<SchedulerAction> {
        self.cur_round = round;
        for (id, obs) in self.observers.iter_mut() {
            // The subnet's wall-clock round (global genesis clock, unforgeable):
            // traffic can only move an observer's clock by its acceptance window
            // per tick, so a committee ticking slower than window×round_duration
            // would wedge behind a live subnet for good.
            let wall = self
                .epoch_unix_ms
                .zip(self.subnet_round_ms.get(id).copied())
                .filter(|(_, d)| *d > 0)
                .map(|(e, d)| crate::runtime::round_at(0, e, d, now_unix_ms));
            obs.refresh_clock(wall);
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
        // Each subnet has its own liveness observer.
        let ids: Vec<SubnetId> = self.observers.keys().copied().collect();
        for id in ids {
            let faults = self
                .observers
                .get_mut(&id)
                .map(|o| o.end_round_faults(round))
                .unwrap_or_default();
            // A rebuilt observer watching a subnet mid-cutover sees a gap, not
            // a fault; reacting would renegotiate and cause the next gap.
            if let Some(g) = self.observer_grace.get_mut(&id) {
                *g -= 1;
                if *g == 0 {
                    self.observer_grace.remove(&id);
                }
                continue;
            }
            self.apply_observed_faults(id, faults, now_unix_ms);
        }
        self.integrity_offenders
            .retain(|_, t| now_unix_ms.saturating_sub(*t) < self.params.integrity_backoff_ms);

        // Total observed submitters across all subnets. Each client appears in
        // exactly one subnet's canonical set per round, so a round-aligned sum
        // is conserved. A set whose round lags the freshest frontier is a ghost
        // (a quiet or dead subnet's last announcement) — counting it inflates
        // `total` cumulatively and drives runaway subnet growth.
        let freshest = self
            .observers
            .values()
            .filter_map(|o| o.anon_set_round())
            .max();
        let fresh_set = |o: &PublicObserver| -> Option<usize> {
            let r = o.anon_set_round()?;
            (r + ANON_SET_FRESHNESS >= freshest?).then(|| o.anonymity_set())?
        };
        // Union ids: a scheduled-flow client sits in two subnets' sets in one
        // round (reservation + grant delivery), so summing sizes double-counts.
        let mut ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut sized = 0usize;
        for o in self.observers.values() {
            let fresh = o
                .anon_set_round()
                .zip(freshest)
                .is_some_and(|(r, f)| r + ANON_SET_FRESHNESS >= f);
            if !fresh {
                continue;
            }
            match o.latest_clients() {
                Some(c) => ids.extend(c.iter().copied()),
                None => sized += o.anonymity_set().unwrap_or(0),
            }
        }
        let total = ids.len() + sized;
        let busiest = self
            .observers
            .values()
            .filter_map(&fresh_set)
            .max()
            .unwrap_or(0) as u32;
        // Leader-announced demand is not censored at `client_set_max`, so
        // capacity converges in one resize instead of ratcheting.
        let demand = self
            .observers
            .values()
            .filter_map(|o| {
                let r = o.anon_set_round()?;
                (r + ANON_SET_FRESHNESS >= freshest?).then(|| o.demand())?
            })
            .max()
            .unwrap_or(0)
            .min(MAX_SUBNET_CLIENTS);
        tracing::debug!(
            target: SCHED,
            is_lead = self.is_lead,
            observers = self.observers.len(),
            registered = self.registered.len(),
            services = self.services.len(),
            sidelined = self.sidelined.len(),
            total,
            demand,
            per_subnet = total / self.subnet_count.max(1),
            subnet_count = self.subnet_count,
            freshest = ?freshest,
            "scheduler tick: subnet sizing"
        );
        // Size the subnet count to the load each subnet WOULD carry once clients
        // spread evenly across the current count, not the busiest single subnet.
        // Using `busiest` makes the committee add a subnet every tick (the
        // adopted config lags, so `busiest` stays high), overshoot to
        // MAX_SUBNETS, and — because the proposal body then changes every round
        // — never converge on a config to publish. `total / subnet_count`
        // converges: at total=63 it grows 1→2 (63≥63) then holds (31<63).
        // `total` (union of announced sets) is capped at the current capacity,
        // so demand — uncensored — must feed the count too, or the count can
        // never grow while capacity is the bottleneck.
        let load = (total as u32).max(demand);
        let per_subnet = load / self.subnet_count.max(1) as u32;
        // Shrink only when merging back to one fewer subnet would still leave the
        // load below grow_at (10% hysteresis), so a shrink never immediately re-grows.
        let merged_per_subnet = load / (self.subnet_count.max(2) - 1) as u32;
        let shrink_floor = self.params.grow_at.saturating_sub(self.params.grow_at / 10);
        if per_subnet >= self.params.grow_at && self.subnet_count < MAX_SUBNETS {
            // Grow immediately, straight to the count that absorbs the load.
            let absorbing = (load / self.params.grow_at.max(1)) as usize + 1;
            self.subnet_count = absorbing.clamp(self.subnet_count, MAX_SUBNETS);
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
        // Per-subnet share AFTER count growth: splitting absorbs load first,
        // so capacity never inflates to a pre-split concentration spike.
        // `min_capacity` is a hard floor — set it above the expected load to
        // keep the subnet from resizing at all during a demo.
        let observed = busiest.max(load.div_ceil(self.subnet_count.max(1) as u32));
        let desired = size_capacity(observed as usize)
            .max(self.params.min_capacity)
            .min(MAX_SUBNET_CLIENTS);
        if observed >= self.capacity {
            // Overflowing right now (clients being rejected): grow immediately.
            self.capacity = desired.max(self.capacity);
            self.capacity_streak = 0;
        } else if desired.abs_diff(self.capacity) >= capacity_resize_margin(self.capacity) {
            // Drift within headroom, either direction: damped, so demand
            // jitter neither creeps capacity up nor flaps it down.
            self.capacity_streak += 1;
            if self.capacity_streak >= CAPACITY_RESIZE_GRACE {
                self.capacity = desired;
                self.capacity_streak = 0;
            }
        } else {
            self.capacity_streak = 0;
        }
        // Cap clients per subnet so the biggest message stays under the p2p limit.
        self.capacity = self.capacity.min(MAX_SUBNET_CLIENTS);
        // Retire sizing state for subnets that no longer exist.
        let count = self.subnet_count;
        self.scheduled_vectors
            .retain(|id, _| (*id as usize) < count);

        let mut actions = Vec::new();
        let faulted = !self.sidelined.is_empty();
        // `min_relays` gates bootstrap, not fault response: sidelining a relay
        // drops it from `registered`, and holding the full floor would wedge
        // governance — it must still reconfigure with the relays that remain.
        let enough_relays = self.registered.len() >= self.params.min_relays
            || (faulted && !self.registered.is_empty());
        // The lead holding back is how the network wedges with no config at all:
        // the floors are never met, so nothing is ever proposed.
        if self.is_lead && !(enough_relays && self.services.len() >= self.params.min_services) {
            tracing::debug!(
                target: GOV,
                round,
                registered = self.registered.len(),
                min_relays = self.params.min_relays,
                services = self.services.len(),
                min_services = self.params.min_services,
                sidelined = self.sidelined.len(),
                "scheduler: lead is below the registration floors; no proposal this round"
            );
        }
        if self.is_lead && enough_relays && self.services.len() >= self.params.min_services {
            let protos = self.subnet_protocols();
            self.resize_scheduled_vectors(&protos);
            self.epoch_unix_ms
                .get_or_insert_with(crate::config::now_unix_ms);
            let mut body = self.build_body(&protos);
            body.round = 0;
            let content = body.canonical_bytes();
            if self.last_content.as_ref() != Some(&content) {
                self.public_round = self.public_round.wrapping_add(1);
                self.last_content = Some(content);
            }
            if self.published_round != Some(self.public_round) {
                body.round = self.public_round;
                let signature = self.identity.sign(&body.propose_bytes());
                let proposal = SignedProposal {
                    body,
                    proposer: self.identity.pubkey(),
                    signature,
                };
                let bytes = bincode::serialize(&proposal).expect("proposal serialises");
                tracing::debug!(
                    target: GOV,
                    round,
                    version = self.public_round,
                    published = ?self.published_round,
                    subnets = protos.len(),
                    capacity = self.capacity,
                    len = bytes.len(),
                    "scheduler: lead staging a proposal"
                );
                actions.push(SchedulerAction::StageProposal(bytes));
            }
        }
        actions
    }

    /// Raise the round counters to a network-adopted config, so a restarted
    /// member proposes above the network instead of wedging on stale-round rejections.
    pub fn on_published_config(&mut self, cfg: &AnymoneRoundConfiguration) -> bool {
        if let Err(e) = cfg.verify_multisig(&self.committee, self.threshold) {
            tracing::debug!(
                target: GOV,
                version = cfg.body.round,
                sigs = cfg.signatures.len(),
                threshold = self.threshold,
                ?e,
                "scheduler: published config failed multisig verification"
            );
            return false;
        }
        if !validate_structure(&cfg.body) {
            // We stay pinned to a stale round and keep proposing below the
            // network, which every current member rejects.
            tracing::warn!(
                target: GOV,
                version = cfg.body.round,
                subnets = cfg.body.subnets.len(),
                "scheduler: published config failed structural validation"
            );
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
            tracing::debug!(
                target: GOV,
                round = proposal.body.round,
                proposer = %proposal.proposer,
                lead = %self.lead,
                "scheduler: rejecting proposal from a non-lead member"
            );
            return Vec::new();
        }
        let canonical = proposal.body.canonical_bytes();
        if !proposal
            .proposer
            .verify(&proposal.body.propose_bytes(), &proposal.signature)
        {
            tracing::warn!(
                target: GOV,
                round = proposal.body.round,
                proposer = %proposal.proposer,
                "scheduler: rejecting proposal whose signature does not cover the body"
            );
            return Vec::new();
        }
        // 2. Replay freshness: reject a strictly older proposal (rollback). The
        //    current round is re-signed idempotently (the sig set dedups).
        if self
            .last_accepted_round
            .is_some_and(|last| proposal.body.round < last)
        {
            tracing::debug!(
                target: GOV,
                round = proposal.body.round,
                last_accepted = ?self.last_accepted_round,
                "scheduler: rejecting stale proposal"
            );
            return Vec::new();
        }
        // 3. Reachability: a lead bumps the version by one per content change, so
        //    a far-future round is one pinning the committee where no later config
        //    can ever be newer.
        let established = self
            .last_accepted_round
            .unwrap_or(0)
            .max(self.public_round)
            .max(self.published_round.unwrap_or(0));
        if proposal.body.round > established.saturating_add(MAX_ROUND_ADVANCE) {
            tracing::warn!(
                target: GOV,
                round = proposal.body.round,
                established,
                "scheduler: rejecting proposal too far above the established round"
            );
            return Vec::new();
        }
        // 4. Independent validation: a malicious lead can't insert relays or
        //    services we never saw registered. `validate_body` logs the reason.
        if !self.validate_body(&proposal.body) {
            tracing::debug!(
                target: GOV,
                round = proposal.body.round,
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
            topic: crate::committee::TOPIC_COMMITTEE_SIGS,
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
            tracing::debug!(
                target: GOV,
                signer = %sig_msg.signer,
                "scheduler: signature from outside the committee, ignored"
            );
            return Vec::new();
        }
        // `body_bytes` is canonical (fixint/big-endian) — decode it the same
        // way, not with default bincode, or the re-derived canonical key won't
        // match the stored one and assembly never fires.
        let Ok(body) = AnymoneRoundConfigurationBody::from_canonical_bytes(&sig_msg.body_bytes)
        else {
            tracing::debug!(
                target: GOV,
                signer = %sig_msg.signer,
                len = sig_msg.body_bytes.len(),
                "scheduler: signature over an undecodable body, ignored"
            );
            return Vec::new();
        };
        if !sig_msg
            .signer
            .verify(&body.approve_bytes(), &sig_msg.signature)
        {
            tracing::warn!(
                target: GOV,
                round = body.round,
                signer = %sig_msg.signer,
                "scheduler: committee signature does not verify, ignored"
            );
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
        self.subnet_round_ms = body
            .subnets
            .iter()
            .map(|s| (s.id, s.protocol.round_duration().as_millis() as u64))
            .collect();
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
            // Diff per subnet id — growing/shrinking the subnet count changes
            // the overall `sig`, but must not reset every other subnet's
            // observer (anonymity set, fault streak) along with it.
            let prev: HashMap<SubnetId, (Vec<Pubkey>, Option<SchedulerProtocol>)> = self
                .current_subnets_sig
                .iter()
                .map(|(id, roster, proto)| (*id, (roster.clone(), *proto)))
                .collect();
            let mut observers = std::collections::BTreeMap::new();
            for (id, roster, proto) in &sig {
                if prev.get(id) == Some(&(roster.clone(), *proto)) {
                    if let Some(o) = self.observers.remove(id) {
                        observers.insert(*id, o);
                        continue;
                    }
                }
                let leader = crate::runtime::leader_of(roster, *id);
                if let Some(o) =
                    build_observer(*proto, roster.clone(), leader, self.params.fault_threshold)
                {
                    observers.insert(*id, o);
                    self.observer_grace.insert(*id, OBSERVER_FAULT_GRACE);
                }
            }
            self.observers = observers;
            self.observer_grace
                .retain(|id, _| sig.iter().any(|(s, _, _)| s == id));
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
            // Threshold signatures collected but the assembly won't verify, so
            // this config can never publish and governance stalls here.
            tracing::warn!(
                target: GOV,
                round = body.round,
                sigs = cfg.signatures.len(),
                threshold = self.threshold,
                ?e,
                "scheduler: assembled config failed verify_multisig"
            );
            return None;
        }
        tracing::debug!(
            target: GOV,
            round = body.round,
            sigs = cfg.signatures.len(),
            "scheduler: assembled a threshold-signed config; publishing"
        );
        self.published.insert(canonical);
        self.published_round = Some(
            self.published_round
                .map_or(body.round, |r| r.max(body.round)),
        );
        Some(SchedulerAction::Publish {
            topic: TOPIC_CONFIG,
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
            tracing::debug!(
                target: GOV,
                round = body.round,
                subnets = body.subnets.len(),
                "validate_body: structural bounds"
            );
            return false;
        }
        // The epoch is the round clock's genesis; moving it re-times every subnet.
        if self
            .epoch_unix_ms
            .is_some_and(|known| known != body.epoch_unix_ms)
        {
            tracing::debug!(
                target: GOV,
                round = body.round,
                proposed = body.epoch_unix_ms,
                known = ?self.epoch_unix_ms,
                "validate_body: proposed epoch is not the one we established"
            );
            return false;
        }
        if !body
            .services
            .iter()
            .all(|svc| self.services.get(&svc.tag) == Some(&svc.pubkey))
        {
            tracing::debug!(
                target: GOV,
                round = body.round,
                proposed = body.services.len(),
                known = self.services.len(),
                "validate_body: a proposed service is not one we saw register"
            );
            return false;
        }
        if !self.exchange_keys_match(&body.relay_exchange_keys) {
            tracing::debug!(
                target: GOV,
                round = body.round,
                proposed = body.relay_exchange_keys.len(),
                known = self.relay_xpubs.len(),
                "validate_body: a relay exchange key differs from what its owner registered"
            );
            return false;
        }
        // Relays screen clients against this, so a member that signed a policy
        // it doesn't hold would admit a different client set than it enforces.
        if body.attestation != self.params.attestation {
            tracing::debug!(
                target: GOV,
                round = body.round,
                "validate_body: proposed attestation policy is not ours"
            );
            return false;
        }
        for s in &body.subnets {
            if s.attested != self.params.attested_subnets.contains(&s.id) {
                tracing::debug!(
                    target: GOV,
                    round = body.round,
                    subnet = s.id,
                    proposed = s.attested,
                    "validate_body: subnet's attestation requirement is not ours"
                );
                return false;
            }
            if !s.relays.iter().all(|pk| self.registered.contains(pk)) {
                tracing::debug!(
                    target: GOV,
                    round = body.round,
                    subnet = s.id,
                    relays = s.relays.len(),
                    registered = self.registered.len(),
                    "validate_body: a proposed relay is not one we saw register"
                );
                return false;
            }
            let keys_ok = match &s.protocol {
                ProtocolConfig::Noop(_) => true,
                ProtocolConfig::Adcnet(c) => self.aggregation_valid(&c.aggregation),
                ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => true,
                ProtocolConfig::ScheduledAdcnet(_) => true,
            };
            if !keys_ok {
                tracing::debug!(
                    target: GOV,
                    round = body.round,
                    subnet = s.id,
                    "validate_body: subnet aggregation groups are not valid"
                );
                return false;
            }
        }
        true
    }

    /// Every `(relay, exchange_key)` pair in a proposed config must match what
    /// that relay actually registered.
    fn exchange_keys_match(&self, keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        keys.iter()
            .all(|(pk, xk)| self.relay_xpubs.get(pk) == Some(xk))
    }

    /// Every aggregator must be a registered relay.
    fn aggregation_valid(&self, agg: &Option<Aggregation>) -> bool {
        if !aggregation_structural_ok(agg) {
            return false;
        }
        let Some(a) = agg else { return true };
        a.groups
            .iter()
            .all(|g| self.registered.contains(&g.aggregator))
    }

    fn subnet_protocols(&self) -> Vec<SchedulerProtocol> {
        vec![self.params.pin.unwrap_or(SchedulerProtocol::Adcnet); self.subnet_count.max(1)]
    }

    fn resize_scheduled_vectors(&mut self, protos: &[SchedulerProtocol]) {
        for (i, proto) in protos.iter().enumerate() {
            let id = i as SubnetId;
            if *proto != SchedulerProtocol::ScheduledPanetiere {
                self.scheduled_vectors.remove(&id);
                continue;
            }
            let bytes = self
                .observers
                .get(&id)
                .and_then(|o| o.decoded_bytes_recent(SCHED_WINDOW))
                .unwrap_or(0);
            let state = self.scheduled_vectors.entry(id).or_default();
            let min_vector = round_up_to(
                expected_active(self.capacity) as usize * self.params.message_size / 2,
                8192,
            );
            let desired = if self.params.vector_bytes > 0 {
                self.params.vector_bytes
            } else {
                round_up_to(bytes.saturating_mul(3) / 2, 8192)
                    .max(min_vector)
                    .min(MAX_VECTOR_BYTES)
            };
            if state.vector_bytes == 0
                || desired.abs_diff(state.vector_bytes) as f64
                    >= state.vector_bytes as f64 * SCHED_VECTOR_RESIZE_MARGIN
            {
                state.vector_bytes = desired;
            }
        }
    }

    fn build_body(&self, protos: &[SchedulerProtocol]) -> AnymoneRoundConfigurationBody {
        let mut relay_vec: Vec<Pubkey> = self.registered.iter().copied().collect();
        relay_vec.sort();
        if relay_vec.len() > MAX_COMMITTEE_RELAYS {
            tracing::warn!(
                target: GOV,
                registered = relay_vec.len(),
                cap = MAX_COMMITTEE_RELAYS,
                "more relays registered than a proposal can carry; placing the lowest pubkeys"
            );
            relay_vec.truncate(MAX_COMMITTEE_RELAYS);
        }
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
            .then(|| build_subnet_aggregation(self.capacity, &relay_vec))
            .flatten();
        let n = relay_vec.len() as u32;
        let subnets: Vec<Subnet> = protos
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
                        encoding: self.params.encoding,
                        set_formation: self.params.set_formation,
                    }),
                    SchedulerProtocol::ScheduledPanetiere => {
                        let vector_bytes = Some(self.params.vector_bytes)
                            .filter(|&v| v > 0)
                            .or_else(|| {
                                self.scheduled_vectors
                                    .get(&(i as SubnetId))
                                    .map(|s| s.vector_bytes)
                                    .filter(|&v| v > 0)
                            })
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
                                set_formation: self.params.set_formation,
                            },
                        )
                    }
                    SchedulerProtocol::ScheduledAdcnet => {
                        ProtocolConfig::ScheduledAdcnet(crate::config::ScheduledAdcnetConfig {
                            round_duration_ms: dur_ms,
                            message_length: round_up_to(self.params.message_size, 1024),
                            auction_slots: expected_active(self.capacity),
                            min_message_size: 1,
                            client_set_min: 0,
                            client_set_max: self.capacity,
                        })
                    }
                    SchedulerProtocol::Noop => ProtocolConfig::Noop(crate::config::NoopConfig {
                        round_duration_ms: dur_ms,
                        message_size: self.params.message_size,
                        client_set_min: 0,
                        client_set_max: self.capacity,
                    }),
                    SchedulerProtocol::Adcnet => ProtocolConfig::Adcnet(AdcnetConfig {
                        round_duration_ms: dur_ms,
                        max_payload_bytes: self.params.message_size,
                        estimated_messages: expected_active(self.capacity),
                        client_set_min: 0,
                        client_set_max: self.capacity,
                        aggregation: aggregation.clone(),
                    }),
                };
                Subnet {
                    id: i as SubnetId,
                    relays: relay_vec.clone(),
                    protocol,
                    cover_rate: self.cover_rate,
                    attested: self.params.attested_subnets.contains(&(i as SubnetId)),
                }
            })
            .collect();
        // Only placed relays, so a flood of registrations can't inflate the body.
        let placed: HashSet<Pubkey> = subnets
            .iter()
            .flat_map(|s| s.relays.iter().copied())
            .collect();
        let mut relay_client_addrs: Vec<(Pubkey, String)> = self
            .relay_client_addrs
            .iter()
            .filter(|(pk, _)| placed.contains(pk))
            .map(|(pk, addr)| (*pk, addr.clone()))
            .collect();
        relay_client_addrs.sort();
        let mut watchers: Vec<Pubkey> = self.watchers.iter().copied().collect();
        watchers.sort();
        AnymoneRoundConfigurationBody {
            round: self.public_round,
            epoch_unix_ms: self
                .epoch_unix_ms
                .unwrap_or_else(crate::config::now_unix_ms),
            services: service_vec,
            relay_exchange_keys: relay_xk,
            subnets,
            relay_client_addrs,
            watchers,
            attestation: self.params.attestation.clone(),
        }
    }
}

/// Aggregator group count for a subnet of `capacity` clients over `n_relays`,
/// or `None` when the subnet is below the aggregation threshold and clients
/// reach relays directly. `min(1 + capacity/16, √capacity/2)`, clamped to at
/// least one and at most one group per relay.
fn aggregator_group_count(capacity: u32, n_relays: usize) -> Option<u32> {
    if capacity <= AGGREGATION_THRESHOLD || n_relays == 0 {
        return None;
    }
    let max_groups = n_relays as u32;
    Some(
        ((1.0 + capacity as f64 / 16.0)
            .min((capacity as f64).sqrt() / 2.0)
            .floor() as u32)
            .min(max_groups)
            .max(1),
    )
}

/// Aggregator layer for an ADCNet subnet of `capacity` clients, or `None`
/// below the threshold.
fn build_subnet_aggregation(capacity: u32, relay_vec: &[Pubkey]) -> Option<Aggregation> {
    let group_count = aggregator_group_count(capacity, relay_vec.len())?;
    let groups = relay_vec
        .iter()
        .take(group_count as usize)
        .map(|&aggregator| AggregatorGroup { aggregator })
        .collect();
    Some(Aggregation { groups })
}

fn proto_kind(p: &ProtocolConfig) -> Option<SchedulerProtocol> {
    match p {
        ProtocolConfig::Adcnet(_) => Some(SchedulerProtocol::Adcnet),
        ProtocolConfig::Panetiere(_) => Some(SchedulerProtocol::Panetiere),
        ProtocolConfig::ScheduledPanetiere(_) => Some(SchedulerProtocol::ScheduledPanetiere),
        ProtocolConfig::Noop(_) => Some(SchedulerProtocol::Noop),
        ProtocolConfig::ScheduledAdcnet(_) => Some(SchedulerProtocol::ScheduledAdcnet),
    }
}

/// The public subnet's liveness observer, kept as a concrete type (not a
/// `Box<dyn Session>`) so the core can read the observed anonymity set — the
/// per-round canonical client-set size each observer already tracks — and size
/// the next config's capacity to it.
enum PublicObserver {
    Adcnet(AdcnetObserverSession),
    Panetiere(PanetiereObserverSession),
    Noop(NoopWireCount),
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
            PublicObserver::Noop(o) => {
                o.current.insert(from);
            }
        }
    }

    fn end_round_faults(&mut self, round: Round) -> Vec<Fault> {
        let now = std::time::Instant::now();
        match self {
            PublicObserver::Adcnet(o) => o.end_round(round, now).faults,
            PublicObserver::Panetiere(o) => o.end_round(round, now).faults,
            PublicObserver::Noop(o) => {
                if !o.current.is_empty() {
                    o.last = Some((round, o.current.len()));
                    o.current.clear();
                }
                Vec::new()
            }
        }
    }

    /// Advance the observer's round clamp to the subnet's wall-clock round —
    /// never behind the highest wire round already accepted — since nothing
    /// else here ever calls its `begin_round`.
    fn refresh_clock(&mut self, wall_round: Option<Round>) {
        let now = std::time::Instant::now();
        match self {
            PublicObserver::Adcnet(o) => {
                if let Some(r) = o.observed_round().into_iter().chain(wall_round).max() {
                    o.begin_round(r, now);
                }
            }
            PublicObserver::Panetiere(o) => {
                if let Some(r) = o.round().into_iter().chain(wall_round).max() {
                    o.begin_round(r, now);
                }
            }
            PublicObserver::Noop(_) => {}
        }
    }

    /// Observed anonymity set (canonical client-set size), or `None` if no set
    /// has been announced yet.
    fn anonymity_set(&self) -> Option<usize> {
        match self {
            PublicObserver::Adcnet(o) => o.anonymity_set(),
            PublicObserver::Panetiere(o) => o.anonymity_set(),
            PublicObserver::Noop(o) => o.last.map(|(_, n)| n),
        }
    }

    /// Round of the most recent canonical set, for freshness gating.
    fn anon_set_round(&self) -> Option<Round> {
        match self {
            PublicObserver::Adcnet(o) => o.anon_set_round(),
            PublicObserver::Panetiere(o) => o.anon_set_round(),
            PublicObserver::Noop(o) => o.last.map(|(r, _)| r),
        }
    }

    /// Leader-announced per-round demand (admitted + capacity-rejected clients).
    /// Only Panetiere announces it; the others fall back to censored sizing.
    fn demand(&self) -> Option<u32> {
        match self {
            PublicObserver::Panetiere(o) => o.demand(),
            PublicObserver::Adcnet(_) | PublicObserver::Noop(_) => None,
        }
    }

    /// Members of the most recent canonical set, where the wire carries them.
    fn latest_clients(&self) -> Option<&[u32]> {
        match self {
            PublicObserver::Panetiere(o) => o.latest_clients().map(|(_, c)| c),
            PublicObserver::Adcnet(_) | PublicObserver::Noop(_) => None,
        }
    }

    fn share_frontier(&self) -> Option<u64> {
        match self {
            PublicObserver::Adcnet(o) => o.share_frontier(),
            PublicObserver::Panetiere(o) => o.share_frontier(),
            PublicObserver::Noop(o) => o.last.map(|(r, _)| r),
        }
    }

    /// Mean decoded bytes/round over `window` — the scheduled-mode upgrade
    /// signal. `None` for ADCNet (not part of the Panetiere family).
    fn decoded_bytes_recent(&self, window: u64) -> Option<usize> {
        match self {
            PublicObserver::Adcnet(_) | PublicObserver::Noop(_) => None,
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
        Some(SchedulerProtocol::Adcnet) | Some(SchedulerProtocol::ScheduledAdcnet) => {
            Some(PublicObserver::Adcnet(AdcnetObserverSession::for_protocol(
                proto == Some(SchedulerProtocol::ScheduledAdcnet),
                roster,
                leader,
                fault_threshold,
            )))
        }
        Some(SchedulerProtocol::Panetiere) | Some(SchedulerProtocol::ScheduledPanetiere) => {
            Some(PublicObserver::Panetiere(PanetiereObserverSession::new(
                roster,
                Some(leader),
                fault_threshold,
            )))
        }
        Some(SchedulerProtocol::Noop) => Some(PublicObserver::Noop(NoopWireCount::default())),
        _ => None,
    }
}

/// Noop has no protocol-level canonical set; the anonymity set is the count of
/// distinct senders seen on the subnet's topics between committee ticks.
#[derive(Default)]
struct NoopWireCount {
    current: HashSet<Pubkey>,
    last: Option<(Round, usize)>,
}
