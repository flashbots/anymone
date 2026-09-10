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
use tracing::{debug, trace, warn};

use crate::governance::{FaultReport, TOPIC_FAULTS, TOPIC_REGISTRATION};
use crate::identity::{Identity, Pubkey};
use crate::log_target::GOV;
use crate::panetiere::{
    params_for, PanetiereClientSession, PanetiereServerSession, SetMode, COMMITTEE_MSG_BYTES,
};
use crate::scheduler_core::{SchedulerAction, SchedulerCore, SchedulerParams};
use crate::scheduling::Registration;
use crate::session::Session;
use crate::transport::{Topic, Transport};

use panetiere::protocol::ServerId;

pub const TOPIC_COMMITTEE_PANETIERE: Topic = Topic::CommitteeBody;
pub const TOPIC_COMMITTEE_SIGS: Topic = Topic::CommitteeSigs;

/// The committee roster as configured: each member's identity pubkey with its
/// exchange pubkey. For callers holding the member `Identity`s (tests, the
/// in-process demo); a deployment reads the same pairs from its config file.
pub fn committee_roster(ids: &[Identity]) -> Vec<(Pubkey, crate::config::ExchangePublicKeyWire)> {
    ids.iter()
        .map(|i| (i.pubkey(), i.exchange_keys()))
        .collect()
}

/// Which topic a committee inbound message arrived on.
#[derive(Clone, Copy)]
enum Source {
    Panetiere,
    Registration,
    Faults,
    Subnet(crate::config::SubnetId),
    Config,
    Sigs,
}

/// Await the next message from any subscribed topic, tagged with its source.
/// Rotating keeps it fair: the committee Panetiere out-volumes the governance
/// topics and starves everything behind it under a fixed poll order.
async fn recv_any(
    subs: &mut [(Source, crate::transport::Subscription)],
) -> (Source, Option<crate::transport::Inbound>) {
    subs.rotate_left(1);
    let futures: Vec<_> = subs
        .iter_mut()
        .map(|(src, sub)| {
            let src = *src;
            Box::pin(async move { (src, sub.recv().await) })
        })
        .collect();
    let ((src, msg), _, _) = futures_util::future::select_all(futures).await;
    (src, msg)
}

/// Runtime settings for the committee's own channel and public-subnet scheduler.
#[derive(Debug, Clone)]
pub struct PanetiereCommitteeConfig {
    pub committee_round_duration: Duration,
    pub committee_msg_bytes: usize,
    pub scheduler: SchedulerParams,
    pub cover_rate: Arc<AtomicU32>,
}

impl Default for PanetiereCommitteeConfig {
    fn default() -> Self {
        Self {
            committee_round_duration: Duration::from_secs(1),
            committee_msg_bytes: COMMITTEE_MSG_BYTES,
            scheduler: SchedulerParams::default(),
            cover_rate: Arc::new(AtomicU32::new(1.0f32.to_bits())),
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
    pub subnet_grow_at: u32,
    pub message_size: usize,
    pub integrity_backoff_ms: u64,
    /// Whether attributed faults drop the culprit from the roster.
    pub sideline: bool,
    /// Whether observed faults change the roster (sidelining and re-registration); `false` logs them and never reconfigures.
    pub renegotiate_on_fault: bool,
    /// Hard floor / initial subnet capacity.
    pub min_capacity: u32,
    /// Protocol for every subnet; `None` selects ordinary Panetiere.
    pub protocol: Option<crate::scheduling::SchedulerProtocol>,
    /// Whether large ADCNet subnets may route through an aggregator layer.
    pub aggregation: bool,
    /// See [`SchedulerParams::encoding`].
    pub encoding: crate::config::Encoding,
    /// See [`PanetiereCommitteeConfig::committee_msg_bytes`].
    pub committee_msg_bytes: usize,
    /// See [`SchedulerParams::vector_bytes`].
    pub vector_bytes: usize,
    /// Use consensus client-set formation for public Panetiere subnets.
    pub consensus_set: bool,
    /// See [`SchedulerParams::attested_subnets`].
    pub attested_subnets: Vec<crate::config::SubnetId>,
    pub tdx_images: Vec<crate::config::TdxImage>,
    /// Committee rounds a client's enrolment holds for.
    pub attestation_validity_rounds: crate::config::Round,
    pub play_integrity: Option<crate::config::PlayIntegrityPolicy>,
    pub app_attest: Option<crate::config::AppAttestPolicy>,
    pub android_key: Option<crate::config::AndroidKeyPolicy>,
}

impl Default for CommitteeParams {
    fn default() -> Self {
        let scheduler = SchedulerParams::default();
        CommitteeParams {
            committee_round_ms: 10_000,
            public_round_ms: 4_000,
            min_relays: scheduler.min_relays,
            min_services: scheduler.min_services,
            fault_grace: scheduler.fault_threshold,
            subnet_grow_at: scheduler.grow_at,
            message_size: scheduler.message_size,
            integrity_backoff_ms: scheduler.integrity_backoff_ms,
            sideline: scheduler.sideline,
            renegotiate_on_fault: scheduler.renegotiate_on_fault,
            min_capacity: scheduler.min_capacity,
            protocol: scheduler.pin,
            aggregation: scheduler.aggregation,
            encoding: scheduler.encoding,
            committee_msg_bytes: COMMITTEE_MSG_BYTES,
            vector_bytes: scheduler.vector_bytes,
            consensus_set: false,
            attested_subnets: scheduler.attested_subnets,
            tdx_images: Vec::new(),
            attestation_validity_rounds: crate::tee::DEFAULT_VALIDITY_ROUNDS,
            play_integrity: None,
            app_attest: None,
            android_key: None,
        }
    }
}

impl CommitteeParams {
    pub fn into_config(self) -> PanetiereCommitteeConfig {
        PanetiereCommitteeConfig {
            committee_round_duration: Duration::from_millis(self.committee_round_ms),
            committee_msg_bytes: self.committee_msg_bytes,
            cover_rate: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            scheduler: SchedulerParams {
                public_round_duration: Duration::from_millis(self.public_round_ms),
                min_relays: self.min_relays,
                min_services: self.min_services,
                fault_threshold: self.fault_grace,
                grow_at: self.subnet_grow_at,
                message_size: self.message_size,
                integrity_backoff_ms: self.integrity_backoff_ms,
                sideline: self.sideline,
                renegotiate_on_fault: self.renegotiate_on_fault,
                min_capacity: self.min_capacity,
                pin: self.protocol,
                aggregation: self.aggregation,
                encoding: self.encoding,
                vector_bytes: self.vector_bytes,
                set_formation: if self.consensus_set {
                    crate::config::SetFormation::Consensus
                } else {
                    crate::config::SetFormation::Leader
                },
                attested_subnets: self.attested_subnets,
                attestation: crate::config::AttestationPolicy {
                    tdx_images: self.tdx_images,
                    validity_rounds: self.attestation_validity_rounds,
                    play_integrity: self.play_integrity,
                    app_attest: self.app_attest,
                    android_key: self.android_key,
                },
            },
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
    let mut inbound: Vec<(Source, crate::transport::Subscription)> = vec![
        (
            Source::Registration,
            transport.subscribe(TOPIC_REGISTRATION).await,
        ),
        (Source::Faults, transport.subscribe(TOPIC_FAULTS).await),
        (
            Source::Panetiere,
            transport.subscribe(TOPIC_COMMITTEE_PANETIERE).await,
        ),
        (
            Source::Sigs,
            transport.subscribe(TOPIC_COMMITTEE_SIGS).await,
        ),
        (
            Source::Config,
            transport.subscribe(crate::governance::TOPIC_CONFIG).await,
        ),
    ];
    let committee_xpubs: std::collections::HashMap<Pubkey, crate::config::ExchangePublicKeyWire> =
        committee.iter().cloned().collect();
    let committee: Vec<Pubkey> = committee.into_iter().map(|(pk, _)| pk).collect();

    // One subscription per possible public subnet (the committee may schedule
    // several). Each subnet is observed independently (its own anonymity set, its own faults).
    for id in 0..crate::scheduler_core::MAX_SUBNETS as crate::config::SubnetId {
        // Broadcast topic carries the leader's `ClientSet` (anonymity set) and
        // `Decoded` (round output); the shares topic carries each relay's share
        // (liveness / share frontier). Both feed the same per-subnet observer.
        inbound.push((
            Source::Subnet(id),
            transport.subscribe(Topic::Broadcast(id)).await,
        ));
        inbound.push((
            Source::Subnet(id),
            transport.subscribe(Topic::Shares(id)).await,
        ));
    }

    // Committee-anonymisation Panetiere parameters, derived deterministically.
    let n = committee.len();
    let committee_cfg = crate::config::PanetiereConfig {
        round_duration_ms: config.committee_round_duration.as_millis() as u64,
        message_size: config.committee_msg_bytes,
        estimated_messages: n as u32,
        client_set_min: 1,
        // Clients here are the members themselves.
        client_set_max: n as u32,
        threshold: (n as u32) / 2 + 1,
        setup_seed: crate::keys::derive_seed(b"anymone/committee-seed", &committee),
        encoding: config.scheduler.encoding,
        // The committee's own channel is leaderless already, and its client set
        // is the membership — there is nothing for consensus formation to add.
        set_formation: crate::config::SetFormation::Leader,
    };
    let (committee_mse, pp) = params_for(&committee_cfg, n);
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
            let seal_key = committee_xpubs.get(pk)?.to_seal_key().ok()?;
            Some((ServerId(i as u32), seal_key))
        })
        .collect();

    tokio::spawn(async move {
        let topic = TOPIC_COMMITTEE_PANETIERE;
        let round_duration = config.committee_round_duration;

        let mut core = SchedulerCore::new(
            identity.clone(),
            committee.clone(),
            threshold,
            config.scheduler,
        );
        let mut seeded = match pull_config(&transport).await {
            Some(cfg) if core.on_published_config(&cfg) => {
                adopt_transport_policy(&transport, &committee, &cfg);
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
            committee_server_pubkeys,
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
                                identity.clone(),
                                seal_roster.clone(),
                                seed,
                            ))
                        });
                        cs.stage(bytes);
                        trace!(target: GOV, "committee: lead staged proposal");
                    }
                    SchedulerAction::Publish { topic, bytes } => {
                        if topic == crate::governance::TOPIC_CONFIG {
                            debug!(target: GOV, len = bytes.len(), "committee: publishing config");
                            // Serve it so a joining node can pull rather than await a push.
                            transport.serve_config(bytes.clone());
                            match bincode::deserialize::<crate::config::AnymoneRoundConfiguration>(
                                &bytes,
                            ) {
                                Ok(cfg) => adopt_transport_policy(&transport, &committee, &cfg),
                                // The policy keeps the previous config's rosters,
                                // so the new subnets' topics reject their publishers.
                                Err(e) => warn!(
                                    target: GOV,
                                    error = %e,
                                    "committee: published config did not round-trip; topic policy not updated"
                                ),
                            }
                        }
                        transport.publish(topic, bytes).await;
                    }
                }
            }};
        }

        let init = server_session.begin_round(anymone_round, Instant::now());
        emit(
            &transport,
            topic,
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
                    emit(&transport, topic, our_pk, &mut server_session, &mut client_session, outcome.outbound).await;
                    for decoded in outcome.decoded {
                        if let Ok(proposal) =
                            bincode::deserialize::<crate::scheduler_core::SignedProposal>(&decoded)
                        {
                            for action in core.on_decoded_body(proposal) {
                                execute!(action);
                            }
                        } else {
                            // Kept permanently: a decode that isn't a proposal is
                            // how a governance stall looks from the inside.
                            warn!(
                                target: GOV,
                                round = anymone_round,
                                len = decoded.len(),
                                "committee: decoded payload was not a valid proposal"
                            );
                        }
                    }
                    if let Some(cs) = client_session.as_mut() {
                        let _ = cs.end_round(anymone_round, Instant::now());
                    }

                    let now_ms = crate::config::now_unix_ms();
                    // A member emits nothing for rounds it skips, so they can never
                    // reach the share threshold; silent otherwise.
                    let wall_round = crate::runtime::round_at(0, 0, dur_ms, now_ms);
                    if wall_round > anymone_round + 1 {
                        warn!(
                            target: GOV,
                            from_round = anymone_round,
                            to_round = wall_round,
                            skipped = wall_round - (anymone_round + 1),
                            round_ms = dur_ms,
                            "committee: round work outran its duration; skipped rounds cannot decode"
                        );
                    }
                    anymone_round = wall_round.max(anymone_round + 1);
                    deadline = crate::runtime::deadline_for(anymone_round, 0, 0, dur_ms, now_ms);

                    if !seeded {
                        if let Some(cfg) = pull_config(&transport).await {
                            if core.on_published_config(&cfg) {
                                adopt_transport_policy(&transport, &committee, &cfg);
                                seeded = true;
                            }
                        }
                    }
                    core.set_cover_rate(f32::from_bits(config.cover_rate.load(Ordering::Relaxed)));
                    for action in core.tick(anymone_round, now_ms) {
                        execute!(action);
                    }

                    let server_out = server_session.begin_round(anymone_round, Instant::now());
                    emit(&transport, topic, our_pk, &mut server_session, &mut client_session, server_out).await;
                    let client_out = client_session
                        .as_mut()
                        .map(|cs| cs.begin_round(anymone_round, Instant::now()))
                        .unwrap_or_default();
                    emit(&transport, topic, our_pk, &mut server_session, &mut client_session, client_out).await;
                }

                (src, Some(msg)) = recv_any(&mut inbound) => match src {
                    Source::Panetiere => {
                        let crate::transport::Inbound { from, payload } = msg;
                        let mut outs = server_session.on_inbound(from, payload.clone());
                        if let Some(cs) = client_session.as_mut() {
                            outs.extend(cs.on_inbound(from, payload));
                        }
                        emit(&transport, topic, our_pk, &mut server_session, &mut client_session, outs).await;
                    }

                    Source::Registration => {
                        match bincode::deserialize::<Registration>(&msg.payload) {
                            // An unverifiable registration keeps the relay/service out
                            // of every proposal, so the config never includes it.
                            Ok(reg) if !reg.verify() => debug!(
                                target: GOV,
                                from = %msg.from,
                                "committee: registration failed signature verification, ignored"
                            ),
                            Ok(reg) => core.on_registration(reg),
                            Err(e) => debug!(
                                target: GOV,
                                from = %msg.from,
                                error = %e,
                                "committee: undecodable registration, ignored"
                            ),
                        }
                    }

                    Source::Faults => {
                        match FaultReport::decode(&msg.payload) {
                            Some(report) => core.on_fault_report(msg.from, report, crate::config::now_unix_ms()),
                            None => debug!(
                                target: GOV,
                                from = %msg.from,
                                len = msg.payload.len(),
                                "committee: undecodable fault report, ignored"
                            ),
                        }
                    }

                    Source::Subnet(subnet_id) => {
                        core.on_subnet_message(subnet_id, msg.from, msg.payload);
                    }

                    Source::Config => {
                        match bincode::deserialize::<crate::config::AnymoneRoundConfiguration>(&msg.payload) {
                            Ok(cfg) => {
                                if core.on_published_config(&cfg) {
                                    adopt_transport_policy(&transport, &committee, &cfg);
                                    seeded = true;
                                }
                            }
                            Err(e) => debug!(
                                target: GOV,
                                from = %msg.from,
                                error = %e,
                                "committee: undecodable config on the governance topic, ignored"
                            ),
                        }
                    }

                    Source::Sigs => {
                        match bincode::deserialize::<crate::scheduler_core::CommitteeSig>(&msg.payload) {
                            Ok(sig) => {
                                for action in core.on_committee_sig(sig) {
                                    execute!(action);
                                }
                            }
                            // A signature we can't read never counts towards the
                            // threshold, so assembly silently never fires.
                            Err(e) => debug!(
                                target: GOV,
                                from = %msg.from,
                                error = %e,
                                "committee: undecodable committee signature, ignored"
                            ),
                        }
                    }
                },
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

/// Transport admission for a config the committee adopted or published. Every
/// adoption path funnels through here so policy and peer sets never diverge.
fn adopt_transport_policy(
    transport: &Arc<dyn Transport>,
    committee: &[Pubkey],
    cfg: &crate::config::AnymoneRoundConfiguration,
) {
    transport.apply(crate::governance::net_view(&cfg.body, committee));
}

/// Send a member's own committee-Panetiere output to peers and feed it back into
/// the member's own sessions. The transport doesn't loop a publish back to the
/// publisher, so this in-process feed is the only way a member counts its own
/// shares. Drains the cascade each `on_inbound` produces (finite per round).
async fn emit(
    transport: &Arc<dyn Transport>,
    topic: Topic,
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
