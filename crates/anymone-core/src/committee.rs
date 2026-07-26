//! Panetiere-coordinated committee scheduling daemon.
//!
//! Committee members run an internal Panetiere subnet among themselves to anonymously
//! deliberate the next public-network configuration, then multisig-sign and publish.
//!
//! This module is the **async shell** — it owns the transport, the clock, and
//! the committee-anonymisation Panetiere. All scheduling *decisions* live in the
//! sans-IO [`SchedulerCore`](crate::scheduler_core::SchedulerCore)

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::governance::{FaultReport, TOPIC_FAULTS, TOPIC_REGISTRATION};
use crate::identity::{Identity, Pubkey};
use crate::panetiere::{
    channel_mse_params, setup_pp, PanetiereClientSession, PanetiereServerSession, SetMode,
    COMMITTEE_MSG_BYTES,
};
use crate::scheduler_core::{SchedulerAction, SchedulerCore, SchedulerParams};
use crate::scheduling::Registration;
use crate::session::Session;
use crate::transport::Transport;

use panetiere::protocol::ServerId;

pub const TOPIC_COMMITTEE_PANETIERE: &str = "anymone/committee/0";
pub const TOPIC_COMMITTEE_SIGS: &str = "anymone/committee/sigs";

/// The committee roster as configured: each member's identity pubkey with its
/// exchange pubkey. For callers holding the member `Identity`s (tests, the
/// in-process demo); a deployment reads the same pairs from its config file.
pub fn committee_roster(ids: &[Identity]) -> Vec<(Pubkey, crate::config::ExchangePublicKeyWire)> {
    ids.iter()
        .map(|i| {
            (
                i.pubkey(),
                crate::config::ExchangePublicKeyWire::from_key(&i.exchange_pubkey()),
            )
        })
        .collect()
}

/// Await the next message from any public-subnet subscription, returning it
/// tagged with that subnet's id (recovered from the subscription that fired).
async fn poll_subnets(
    subs: &mut [(crate::config::SubnetId, crate::transport::Subscription)],
) -> (crate::config::SubnetId, Option<crate::transport::Inbound>) {
    let futures: Vec<_> = subs
        .iter_mut()
        .map(|(id, sub)| {
            let id = *id;
            Box::pin(async move { (id, sub.recv().await) })
        })
        .collect();
    let ((id, msg), _, _) = futures_util::future::select_all(futures).await;
    (id, msg)
}

/// Tunables for the Panetiere-coordinated committee scheduler.
#[derive(Debug, Clone)]
pub struct PanetiereCommitteeConfig {
    /// Round duration for the committee's internal Panetiere subnet.
    pub committee_round_duration: Duration,
    /// Round duration the committee uses for the public subnet it schedules.
    pub public_round_duration: Duration,
    /// Minimum relays observed before the first proposal is staged.
    pub min_relays: usize,
    /// Minimum services observed before the first proposal is staged.
    pub min_services: usize,
    /// Consecutive output-less public-subnet rounds before the committee
    /// faults + renegotiates (demo: 2 — "fault on the second round").
    pub fault_grace: u64,
    /// Fault-free rounds before a general escalation de-escalates; keep above
    /// `fault_grace` so a recurring cause re-trips first.
    pub escalation_grace: u32,
    /// Per-subnet load at which the committee schedules another subnet.
    pub subnet_grow_at: u32,
    /// Per-message payload bound the scheduled subnets carry.
    pub message_size: usize,
    /// How long an integrity offender stays barred from re-registration.
    pub integrity_backoff_ms: u64,
    /// Whether attributed faults drop the culprit from the roster; `false`
    /// reports faults without removing relays.
    pub sideline: bool,
    /// Whether observed faults change the network at all (escalation ladder,
    /// sidelining, re-roster); `false` logs them and never reconfigures.
    pub renegotiate_on_fault: bool,
    /// Hard floor / initial subnet capacity; set above expected load to hold
    /// capacity constant and avoid resize-driven worker respawns.
    pub min_capacity: u32,
    /// Fixed scheduled-Panetiere message-vector width; `0` derives it from
    /// capacity and observed traffic.
    pub vector_bytes: usize,
    /// Cover rate (f32 bits) shared so a caller can retune it live.
    pub cover_rate: Arc<AtomicU32>,
    /// Freeze every subnet onto one protocol ("adcnet" | "panetiere" |
    /// "scheduled-panetiere"), bypassing the escalation ladder and the
    /// traffic-driven scheduled upgrade. `None` keeps the default
    /// ADCNet-unless-escalated behavior with the upgrade live.
    pub protocol: Option<String>,
    /// Whether large Panetiere subnets may route through an aggregator layer.
    pub aggregation: bool,
    /// Per-message byte bound of the committee's config-anonymising channel;
    /// must fit the largest proposal it will carry and MATCH across members.
    pub committee_msg_bytes: usize,
}

impl Default for PanetiereCommitteeConfig {
    fn default() -> Self {
        PanetiereCommitteeConfig {
            committee_round_duration: Duration::from_secs(1),
            public_round_duration: Duration::from_secs(1),
            min_relays: 1,
            min_services: 1,
            fault_grace: 2,
            escalation_grace: crate::scheduler_core::ESCALATION_GRACE,
            subnet_grow_at: crate::scheduler_core::SUBNET_GROW_AT,
            message_size: 256,
            integrity_backoff_ms: crate::scheduler_core::INTEGRITY_BACKOFF_MS,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: crate::scheduler_core::INITIAL_CAPACITY,
            cover_rate: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            protocol: None,
            aggregation: true,
            committee_msg_bytes: COMMITTEE_MSG_BYTES,
            vector_bytes: 0,
        }
    }
}

/// Committee scheduler tunables as they live in the shared bootstrap TOML
/// (`[committee]`), so every committee node agrees — it's critical they match.
/// `cover_rate` is intentionally absent: it's a runtime knob, not a file setting.
/// An absent `[committee]` section yields these deployment defaults.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CommitteeParams {
    pub committee_round_ms: u64,
    pub public_round_ms: u64,
    pub min_relays: usize,
    pub min_services: usize,
    pub fault_grace: u64,
    pub escalation_grace: u32,
    pub subnet_grow_at: u32,
    pub message_size: usize,
    pub integrity_backoff_ms: u64,
    /// Whether attributed faults drop the culprit from the roster.
    pub sideline: bool,
    /// Whether observed faults change the network at all (escalation ladder,
    /// sidelining, re-roster); `false` logs them and never reconfigures.
    pub renegotiate_on_fault: bool,
    /// Hard floor / initial subnet capacity.
    pub min_capacity: u32,
    /// Force every subnet onto one protocol ("adcnet" | "panetiere" |
    /// "scheduled-panetiere"); absent or unrecognized keeps the default
    /// ADCNet-unless-escalated ladder. See [`PanetiereCommitteeConfig::protocol`].
    pub protocol: Option<String>,
    /// Whether large Panetiere subnets may route through an aggregator layer.
    pub aggregation: bool,
    /// See [`PanetiereCommitteeConfig::committee_msg_bytes`].
    pub committee_msg_bytes: usize,
    /// See [`PanetiereCommitteeConfig::vector_bytes`].
    pub vector_bytes: usize,
}

impl Default for CommitteeParams {
    fn default() -> Self {
        CommitteeParams {
            committee_round_ms: 10_000,
            public_round_ms: 4_000,
            min_relays: 1,
            min_services: 1,
            fault_grace: 2,
            escalation_grace: crate::scheduler_core::ESCALATION_GRACE,
            subnet_grow_at: crate::scheduler_core::SUBNET_GROW_AT,
            message_size: 256,
            integrity_backoff_ms: crate::scheduler_core::INTEGRITY_BACKOFF_MS,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: crate::scheduler_core::INITIAL_CAPACITY,
            protocol: None,
            aggregation: true,
            committee_msg_bytes: COMMITTEE_MSG_BYTES,
            vector_bytes: 0,
        }
    }
}

impl CommitteeParams {
    pub fn into_config(self) -> PanetiereCommitteeConfig {
        PanetiereCommitteeConfig {
            committee_round_duration: Duration::from_millis(self.committee_round_ms),
            public_round_duration: Duration::from_millis(self.public_round_ms),
            min_relays: self.min_relays,
            min_services: self.min_services,
            fault_grace: self.fault_grace,
            escalation_grace: self.escalation_grace,
            subnet_grow_at: self.subnet_grow_at,
            message_size: self.message_size,
            integrity_backoff_ms: self.integrity_backoff_ms,
            sideline: self.sideline,
            renegotiate_on_fault: self.renegotiate_on_fault,
            min_capacity: self.min_capacity,
            cover_rate: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            protocol: self.protocol,
            aggregation: self.aggregation,
            committee_msg_bytes: self.committee_msg_bytes,
            vector_bytes: self.vector_bytes,
        }
    }
}

/// Spawn the committee scheduler. `committee` carries each member's exchange
/// pubkey alongside its identity (from the committee's shared configuration) so
/// the internal Panetiere's openings are sealed member-to-member. Returns the
/// `JoinHandle` once every relevant topic is subscribed, so callers can publish
/// straight after without a sub/publish race.
pub async fn spawn_panetiere_committee_scheduler(
    transport: Arc<dyn Transport>,
    identity: Identity,
    committee: Vec<(Pubkey, crate::config::ExchangePublicKeyWire)>,
    threshold: u32,
    config: PanetiereCommitteeConfig,
) -> JoinHandle<()> {
    // Subscribe-before-spawn for every consumed topic.
    let mut reg_sub = transport.subscribe(TOPIC_REGISTRATION).await;
    let mut faults_sub = transport.subscribe(TOPIC_FAULTS).await;
    let mut panetiere_sub = transport.subscribe(TOPIC_COMMITTEE_PANETIERE).await;
    let mut sigs_sub = transport.subscribe(TOPIC_COMMITTEE_SIGS).await;
    let mut config_sub = transport.subscribe(crate::governance::TOPIC_CONFIG).await;
    let committee_xpubs: std::collections::HashMap<Pubkey, crate::config::ExchangePublicKeyWire> =
        committee.iter().cloned().collect();
    let committee: Vec<Pubkey> = committee.into_iter().map(|(pk, _)| pk).collect();

    // One subscription per possible public subnet (the committee may schedule
    // several). Each subnet is observed independently (its own anonymity set, its own faults).
    let mut subnet_subs: Vec<(crate::config::SubnetId, crate::transport::Subscription)> =
        Vec::new();
    for id in 0..crate::scheduler_core::MAX_SUBNETS as crate::config::SubnetId {
        // Broadcast topic carries the leader's `ClientSet` (anonymity set) and
        // `Decoded` (round output); the shares topic carries each relay's share
        // (liveness / share frontier). Both feed the same per-subnet observer.
        subnet_subs.push((
            id,
            transport
                .subscribe(&crate::runtime::subnet_broadcast_topic(id))
                .await,
        ));
        subnet_subs.push((
            id,
            transport
                .subscribe(&crate::runtime::subnet_shares_topic(id))
                .await,
        ));
    }

    // Committee-anonymisation Panetiere parameters, derived deterministically.
    // ρ=3: a malicious member can't overwrite the lead's config in the IBLT.
    let setup_seed = crate::keys::derive_seed(b"anymone/committee-seed", &committee);
    let committee_mse = channel_mse_params(3, config.committee_msg_bytes, setup_seed);
    let pp = setup_pp(&committee_mse, committee.len(), setup_seed);
    let mut sorted_committee = committee.clone();
    sorted_committee.sort();
    let our_pk = identity.pubkey();
    let my_server_id = ServerId(
        sorted_committee
            .iter()
            .position(|p| *p == our_pk)
            .expect("identity in committee") as u32,
    );
    let seal_roster: Vec<(ServerId, panetiere::pke::PublicKey)> = sorted_committee
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| {
            let xk = committee_xpubs.get(pk)?;
            let pk256 = panetiere::pke::PublicKey::from_sec1_bytes(&xk.0).ok()?;
            Some((ServerId(i as u32), pk256))
        })
        .collect();

    let pin = match config.protocol.as_deref() {
        Some("adcnet") => Some(crate::scheduling::SchedulerProtocol::Adcnet),
        Some("panetiere") => Some(crate::scheduling::SchedulerProtocol::Panetiere),
        Some("scheduled-panetiere") => {
            Some(crate::scheduling::SchedulerProtocol::ScheduledPanetiere)
        }
        Some("noop") => Some(crate::scheduling::SchedulerProtocol::Noop),
        Some(other) => {
            tracing::warn!(
                protocol = other,
                "unrecognized committee protocol pin, ignoring"
            );
            None
        }
        None => None,
    };
    let params = SchedulerParams {
        public_round_duration: config.public_round_duration,
        min_relays: config.min_relays,
        min_services: config.min_services,
        fault_threshold: config.fault_grace,
        escalation_grace: config.escalation_grace,
        grow_at: config.subnet_grow_at,
        message_size: config.message_size,
        integrity_backoff_ms: config.integrity_backoff_ms,
        sideline: config.sideline,
        renegotiate_on_fault: config.renegotiate_on_fault,
        min_capacity: config.min_capacity,
        pin,
        aggregation: config.aggregation,
        vector_bytes: config.vector_bytes,
    };

    tokio::spawn(async move {
        let topic = TOPIC_COMMITTEE_PANETIERE.to_string();
        let round_duration = config.committee_round_duration;

        let mut core = SchedulerCore::new(identity.clone(), committee.clone(), threshold, params);
        let mut seeded = match pull_config(&transport).await {
            Some(cfg) if core.on_published_config(&cfg) => {
                transport.set_topic_policy(crate::governance::topic_policy(&cfg.body, &committee));
                true
            }
            _ => false,
        };
        let committee_server_pubkeys = sorted_committee
            .iter()
            .enumerate()
            .map(|(i, pk)| (ServerId(i as u32), *pk))
            .collect();
        let mut server_session_inner = PanetiereServerSession::new(
            pp.clone(),
            committee_mse.clone(),
            my_server_id,
            identity.clone(),
            // Leaderless, all-to-all: every member derives its own set and decodes
            // locally; no announcer, no Decoded on the committee topic.
            SetMode::SelfDerived,
            0,
            committee_server_pubkeys,
            None, // committee runs the direct flow, never aggregated
        );
        // Clients here are committee members themselves — bounded by committee size.
        server_session_inner.set_client_set_max(committee.len());
        let mut server_session: Box<dyn Session> = Box::new(server_session_inner);
        let mut client_session: Option<Box<dyn Session>> = None;

        // Round from the shared wall clock (epoch 0), so staggered members agree
        // on it and their Panetiere shares land in the same round bucket.
        let dur_ms = (round_duration.as_millis() as u64).max(1);
        let mut anymone_round =
            crate::runtime::round_at(0, 0, dur_ms, crate::config::now_unix_ms());
        let mut deadline =
            crate::runtime::deadline_for(anymone_round, 0, 0, dur_ms, crate::config::now_unix_ms());

        // Helper to execute a scheduler action: stage on the committee Panetiere
        // client (anonymise + broadcast), or publish directly.
        macro_rules! execute {
            ($action:expr) => {{
                match $action {
                    SchedulerAction::StageProposal(bytes) => {
                        let cs = client_session.get_or_insert_with(|| {
                            // Secret entropy — a pubkey-derived seed would let
                            // anyone replay the member's client rounds.
                            let mut seed = [0u8; 32];
                            rand::rngs::OsRng.fill_bytes(&mut seed);
                            Box::new(PanetiereClientSession::new(
                                pp.clone(),
                                committee_mse.clone(),
                                crate::panetiere::client_id_from_pubkey(our_pk),
                                seal_roster.clone(),
                                seed,
                            ))
                        });
                        cs.stage(bytes);
                        debug!("committee: lead staged proposal");
                    }
                    SchedulerAction::Publish { topic, bytes } => {
                        if topic == crate::governance::TOPIC_CONFIG {
                            debug!("committee: publishing config");
                            // Serve it so a joining node can pull rather than await a push.
                            transport.serve_config(bytes.clone());
                            if let Ok(cfg) = bincode::deserialize::<
                                crate::config::AnymoneRoundConfiguration,
                            >(&bytes)
                            {
                                transport.set_topic_policy(crate::governance::topic_policy(
                                    &cfg.body, &committee,
                                ));
                            }
                        }
                        transport.publish(&topic, bytes).await;
                    }
                }
            }};
        }

        let init = server_session.begin_round(anymone_round, Instant::now());
        emit(
            &transport,
            &topic,
            our_pk,
            &mut server_session,
            &mut client_session,
            init,
        )
        .await;

        loop {
            tokio::select! {
                biased;

                _ = tokio::time::sleep_until(deadline) => {
                    let outcome = server_session.end_round(anymone_round, Instant::now());
                    emit(&transport, &topic, our_pk, &mut server_session, &mut client_session, outcome.outbound).await;
                    for decoded in outcome.decoded {
                        if let Ok(proposal) =
                            bincode::deserialize::<crate::scheduler_core::SignedProposal>(&decoded)
                        {
                            for action in core.on_decoded_body(proposal) {
                                execute!(action);
                            }
                        } else {
                            debug!("committee: decoded payload was not a valid proposal");
                        }
                    }
                    if let Some(cs) = client_session.as_mut() {
                        let _ = cs.end_round(anymone_round, Instant::now());
                    }

                    let now_ms = crate::config::now_unix_ms();
                    anymone_round = crate::runtime::round_at(0, 0, dur_ms, now_ms).max(anymone_round + 1);
                    deadline = crate::runtime::deadline_for(anymone_round, 0, 0, dur_ms, now_ms);

                    if !seeded {
                        if let Some(cfg) = pull_config(&transport).await {
                            if core.on_published_config(&cfg) {
                                transport.set_topic_policy(crate::governance::topic_policy(&cfg.body, &committee));
                                seeded = true;
                            }
                        }
                    }
                    core.set_cover_rate(f32::from_bits(config.cover_rate.load(Ordering::Relaxed)));
                    for action in core.tick(anymone_round, now_ms) {
                        execute!(action);
                    }

                    let server_out = server_session.begin_round(anymone_round, Instant::now());
                    emit(&transport, &topic, our_pk, &mut server_session, &mut client_session, server_out).await;
                    let client_out = client_session
                        .as_mut()
                        .map(|cs| cs.begin_round(anymone_round, Instant::now()))
                        .unwrap_or_default();
                    emit(&transport, &topic, our_pk, &mut server_session, &mut client_session, client_out).await;
                }

                Some(msg) = panetiere_sub.recv() => {
                    let crate::transport::Inbound { from, payload } = msg;
                    let mut outs = server_session.on_inbound(from, payload.clone());
                    if let Some(cs) = client_session.as_mut() {
                        outs.extend(cs.on_inbound(from, payload));
                    }
                    emit(&transport, &topic, our_pk, &mut server_session, &mut client_session, outs).await;
                }

                Some(msg) = reg_sub.recv() => {
                    if let Ok(reg) = bincode::deserialize::<Registration>(&msg.payload) {
                        if reg.verify() {
                            core.on_registration(reg);
                        }
                    }
                }

                Some(msg) = faults_sub.recv() => {
                    if let Some(report) = FaultReport::decode(&msg.payload) {
                        core.on_fault_report(msg.from, report, crate::config::now_unix_ms());
                    }
                }

                (subnet_id, inbound) = poll_subnets(&mut subnet_subs) => {
                    if let Some(crate::transport::Inbound { from, payload }) = inbound {
                        core.on_subnet_message(subnet_id, from, payload);
                    }
                }

                Some(msg) = config_sub.recv() => {
                    if let Ok(cfg) = bincode::deserialize::<crate::config::AnymoneRoundConfiguration>(&msg.payload) {
                        if core.on_published_config(&cfg) {
                            transport.set_topic_policy(crate::governance::topic_policy(&cfg.body, &committee));
                            seeded = true;
                        }
                    }
                }

                Some(msg) = sigs_sub.recv() => {
                    if let Ok(sig) = bincode::deserialize::<crate::scheduler_core::CommitteeSig>(&msg.payload) {
                        for action in core.on_committee_sig(sig) {
                            execute!(action);
                        }
                    }
                }
            }
        }
    })
}

async fn pull_config(
    transport: &Arc<dyn Transport>,
) -> Option<crate::config::AnymoneRoundConfiguration> {
    let bytes = transport.fetch_config().await?;
    bincode::deserialize(&bytes).ok()
}

/// Send a member's own committee-Panetiere output to peers and feed it back into
/// the member's own sessions. The transport doesn't loop a publish back to the
/// publisher, so this in-process feed is the only way a member counts its own
/// shares. Drains the cascade each `on_inbound` produces (finite per round).
async fn emit(
    transport: &Arc<dyn Transport>,
    topic: &str,
    our_pk: Pubkey,
    server_session: &mut Box<dyn Session>,
    client_session: &mut Option<Box<dyn Session>>,
    init: Vec<Vec<u8>>,
) {
    let mut queue: std::collections::VecDeque<Vec<u8>> = init.into_iter().collect();
    while let Some(out) = queue.pop_front() {
        transport.publish(topic, out.clone()).await;
        queue.extend(server_session.on_inbound(our_pk, out.clone()));
        if let Some(cs) = client_session.as_mut() {
            queue.extend(cs.on_inbound(our_pk, out));
        }
    }
}
