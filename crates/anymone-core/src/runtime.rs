//! Per-subnet driver and the `Anymone` facade.
//!
//! The runtime owns the clock and the transport-side I/O. Each subnet runs
//! in its own task; sessions live inside the task and never see async.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use rand::{Rng, RngCore};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use crate::adcnet::AdcnetWatchSession;
use crate::config::{AnymoneRoundConfiguration, ProtocolConfig, Round, Subnet, SubnetId};
use crate::faults::{Attribution, Fault, FaultKind};
use crate::governance::{FaultReport, GovernanceBootstrap, GovernanceError, TOPIC_FAULTS};
use crate::identity::{Identity, Pubkey};
use crate::log_target::{GOV, SCHED, WIRE};
use crate::noop;
use crate::panetiere::PanetiereWatchSession;
use crate::pipe::{Pipe, PipeIncoming, PipeMessage};
use crate::session::{GoodClients, Misbehavior, Session};
use crate::transport::{Dest, Inbound, Subscription, Topic, Transport};
use crate::wire::{Frame, RouteTag, ServiceTag, SERVICE_TAG_LEN};

/// Consecutive output-less rounds before a subnet's leader-side monitor reports
/// a `Liveness` fault — the established "fault on the second round" threshold
/// (matches the committee + dashboard observers).
pub(crate) const FAULT_THRESHOLD: u64 = 2;

/// Rounds after a worker (re)spawn during which observed faults are not
/// published: a cutover gap or still-connecting peers read as a Liveness fault
/// and would trigger a renegotiation — which causes another cutover, sustaining
/// a storm.
pub(crate) const RECONFIG_FAULT_GRACE: Round = 3;

/// Capacity of the [`Anymone::events`] broadcast. Slow consumers lag and lose
/// the oldest events rather than blocking the subnet workers.
const EVENTS_CAPACITY: usize = 256;

/// Subnet- and round-level events for relayers, services, and the scheduling
/// committee. Apps that only use [`Pipe`] can ignore this.
#[derive(Debug, Clone)]
pub enum Event {
    /// A round's decoded payloads were routed to pipes.
    RoundDecoded {
        round: Round,
        subnet: SubnetId,
        n_messages: usize,
    },
    /// A fault this node observed (also gossiped on `anymone/faults`).
    Fault {
        round: Round,
        subnet: SubnetId,
        fault: Fault,
    },
    /// A new `AnymoneRoundConfiguration` took effect.
    ConfigUpdated { round: Round },
}

/// Runtime for one node, driving every subnet it participates in. Clones share
/// the same node; the last clone dropped aborts every per-subnet task (the tasks
/// hold only an `Arc<AnymoneInner>`, never the [`SubnetTasks`] guard).
#[derive(Clone)]
pub struct Anymone {
    pub(crate) inner: Arc<AnymoneInner>,
    _tasks: Arc<SubnetTasks>,
}

/// Per-subnet worker: task handle + subnet signature, so reconfig can tell a
/// roster/protocol change (respawn) from an unchanged subnet (leave running).
struct SubnetWorker {
    sig: Vec<u8>,
    handle: JoinHandle<()>,
}

/// Owns per-subnet worker tasks (keyed by id for live add/replace/drop) plus
/// auxiliary tasks (the governance-config watcher). Aborts everything on drop.
struct SubnetTasks {
    workers: Mutex<HashMap<SubnetId, SubnetWorker>>,
    aux: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for SubnetTasks {
    fn drop(&mut self) {
        for (_, w) in self.workers.lock().unwrap().drain() {
            w.handle.abort();
        }
        for h in self.aux.lock().unwrap().drain(..) {
            h.abort();
        }
    }
}

pub(crate) struct AnymoneInner {
    pub(crate) identity: Identity,
    pub(crate) transport: Arc<dyn Transport>,
    /// Current signed config. Swapped in place on live reconfiguration; the
    /// per-round participation draw sees the latest subnet set immediately.
    pub(crate) config: RwLock<AnymoneRoundConfiguration>,
    /// `service_tag` → inbox for the matching `Pipe` (service tags and return tags).
    pub(crate) pipes: Mutex<HashMap<RouteTag, mpsc::UnboundedSender<PipeIncoming>>>,
    /// Joined client pipes (`open`/`subscribe`), by client tag, to their carrier
    /// service. While non-empty, the node participates (cover or real) in one
    /// randomly drawn subnet per round.
    pub(crate) joined: Mutex<HashMap<RouteTag, ServiceTag>>,
    pub(crate) subnets: Mutex<HashMap<SubnetId, mpsc::UnboundedSender<StageMsg>>>,
    /// Framed payloads awaiting a round: drained one per round by the subnet
    /// worker holding this round's participation draw. Node-level, so queued
    /// messages survive worker respawns on reconfiguration.
    pub(crate) outbox: Mutex<VecDeque<Vec<u8>>>,
    /// Scheduled-Panetiere reservation entries per subnet. Node-level like the
    /// outbox: a message vector unpacks `RESERVATION_TO_MSG_GAP` rounds after
    /// its reservations, so a respawned worker reads what its predecessor decoded.
    sched_entries: Mutex<HashMap<SubnetId, crate::panetiere_scheduled::ReservationEntries>>,
    /// Private seed for the per-round subnet draw: deterministic across this
    /// node's workers (exactly one claims each round), unpredictable outside it.
    participation_seed: [u8; 32],
    /// Set only under governance; `None` for `start_with_config` (fixed-config
    /// tests). Drives topic admission on every adopted config.
    pub(crate) committee: Option<Vec<Pubkey>>,
    /// Fan-out of subnet/round events ([`Event`]). Workers publish; callers
    /// subscribe via [`Anymone::events`].
    pub(crate) events: broadcast::Sender<Event>,
    /// Byzantine misbehavior this node's relay sessions adopt (demo/testing):
    /// 0 = honest, 1 = withhold shares, 2 = corrupt shares.
    misbehavior: AtomicU8,
    /// Which client keys this node's relay sessions accept contributions from.
    pub(crate) good_clients: GoodClients,
}

impl AnymoneInner {
    /// The subnet's shared reservation-entries store, created on first use.
    pub(crate) fn sched_reservation_entries(
        &self,
        subnet: SubnetId,
    ) -> crate::panetiere_scheduled::ReservationEntries {
        self.sched_entries
            .lock()
            .unwrap()
            .entry(subnet)
            .or_default()
            .clone()
    }

    pub(crate) fn misbehavior(&self) -> Option<Misbehavior> {
        match self.misbehavior.load(Ordering::Relaxed) {
            1 => Some(Misbehavior::Withhold),
            2 => Some(Misbehavior::CorruptShare),
            _ => None,
        }
    }
}

fn misbehavior_code(mode: Option<Misbehavior>) -> u8 {
    match mode {
        None => 0,
        Some(Misbehavior::Withhold) => 1,
        Some(Misbehavior::CorruptShare) => 2,
    }
}

/// Control message to a subnet worker. Client staging goes through the
/// node-level outbox + per-round participation draw, not this channel.
pub(crate) enum StageMsg {
    /// Adopt a new cover rate from a config change, without rebuilding the worker.
    SetCoverRate(f32),
    /// Graceful cutover: finish the round in progress plus one more (routing
    /// their decodes), then exit. The replacement worker arms to start at that
    /// same boundary — see [`arm_until_cutover`].
    Shutdown,
}

impl Anymone {
    /// Phase 1 of startup: subscribe to the governance config topic before
    /// returning, so a config published right after isn't missed. Drive the
    /// returned handle forward with [`AnymonePrep::start`].
    pub async fn prepare(
        identity: Identity,
        transport: Arc<dyn Transport>,
        bootstrap: GovernanceBootstrap,
    ) -> AnymonePrep {
        let config_sub = transport.subscribe(crate::governance::TOPIC_CONFIG).await;
        AnymonePrep {
            identity,
            transport,
            bootstrap,
            config_sub,
            good_clients: GoodClients::all(),
        }
    }

    pub async fn start(
        identity: Identity,
        transport: Arc<dyn Transport>,
        bootstrap: GovernanceBootstrap,
    ) -> Result<Self, GovernanceError> {
        Anymone::prepare(identity, transport, bootstrap)
            .await
            .start()
            .await
    }

    /// Start from a fixed signed config, bypassing governance. The config is
    /// static — no live reconfiguration. Used by runtime unit tests.
    pub async fn start_with_config(
        identity: Identity,
        transport: Arc<dyn Transport>,
        config: AnymoneRoundConfiguration,
    ) -> Self {
        Self::build_from_config(identity, transport, config, None, GoodClients::all()).await
    }

    /// Build the node from `config`. When `governance` is set (the
    /// `prepare`/`start` path), a watcher task adopts later config versions so
    /// the live network can scale subnets up/down.
    async fn build_from_config(
        identity: Identity,
        transport: Arc<dyn Transport>,
        config: AnymoneRoundConfiguration,
        governance: Option<(Subscription, GovernanceBootstrap)>,
        good_clients: GoodClients,
    ) -> Self {
        let committee = governance.as_ref().map(|(_, gb)| gb.committee.clone());
        let mut participation_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut participation_seed);
        let inner = Arc::new(AnymoneInner {
            identity,
            transport: transport.clone(),
            config: RwLock::new(config.clone()),
            pipes: Mutex::new(HashMap::new()),
            joined: Mutex::new(HashMap::new()),
            subnets: Mutex::new(HashMap::new()),
            outbox: Mutex::new(VecDeque::new()),
            sched_entries: Mutex::new(HashMap::new()),
            participation_seed,
            committee,
            events: broadcast::channel(EVENTS_CAPACITY).0,
            misbehavior: AtomicU8::new(0),
            good_clients,
        });
        let tasks = Arc::new(SubnetTasks {
            workers: Mutex::new(HashMap::new()),
            aux: Mutex::new(Vec::new()),
        });
        let served = bincode::serialize(&config).unwrap_or_default();
        apply_config(&inner, &tasks, config).await;
        // Answer config-pull requests from joining peers with what we adopted.
        transport.serve_config(served);

        if let Some((sub, bootstrap)) = governance {
            let inner_w = Arc::downgrade(&inner);
            let tasks_w = Arc::downgrade(&tasks);
            let watcher = tokio::spawn(reconfig_watch(sub, bootstrap, inner_w, tasks_w));
            tasks.aux.lock().unwrap().push(watcher);
        }

        Anymone {
            inner,
            _tasks: tasks,
        }
    }

    /// Open a pipe to a service: allocates a fresh return tag, registers an
    /// inbox. While the pipe lives, the node contributes (cover or real) to one
    /// randomly drawn subnet per round.
    pub async fn open(&self, tag: ServiceTag) -> Result<Pipe, OpenError> {
        let has_carrier = self
            .inner
            .config
            .read()
            .unwrap()
            .body
            .services
            .iter()
            .any(|svc| svc.tag == tag);
        if !has_carrier {
            return Err(OpenError::TagNotInConfig);
        }

        let mut return_bytes = [0u8; SERVICE_TAG_LEN];
        rand::thread_rng().fill_bytes(&mut return_bytes);
        let return_tag = RouteTag(return_bytes);

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner
            .pipes
            .lock()
            .unwrap()
            .insert(return_tag, in_tx.clone());
        self.inner.joined.lock().unwrap().insert(return_tag, tag);

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            Some(tag),
            return_tag,
            in_rx,
            in_tx,
        ))
    }

    /// Bind to a service tag. Caller's pubkey must match the config entry for `tag`.
    pub async fn bind(&self, tag: ServiceTag) -> Result<Pipe, OpenError> {
        let our_service = self
            .inner
            .config
            .read()
            .unwrap()
            .body
            .services
            .iter()
            .find(|svc| svc.tag == tag)
            .map(|svc| svc.pubkey);

        match our_service {
            None => return Err(OpenError::TagNotInConfig),
            Some(pk) if pk != self.inner.identity.pubkey() => return Err(OpenError::NotOurService),
            Some(_) => {}
        }

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner
            .pipes
            .lock()
            .unwrap()
            .insert(tag.into(), in_tx.clone());

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            None,
            tag.into(),
            in_rx,
            in_tx,
        ))
    }

    /// Join a broadcast room on `tag`: receive every message addressed to `tag`
    /// and send to it. Unlike [`bind`](Self::bind), requires no ownership of the
    /// tag — the anonymous-broadcast receive path. `recv` yields every
    /// participant's message (including our own sends).
    pub async fn subscribe(&self, tag: ServiceTag) -> Result<Pipe, OpenError> {
        let has_carrier = self
            .inner
            .config
            .read()
            .unwrap()
            .body
            .services
            .iter()
            .any(|svc| svc.tag == tag);
        if !has_carrier {
            return Err(OpenError::TagNotInConfig);
        }

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner
            .pipes
            .lock()
            .unwrap()
            .insert(tag.into(), in_tx.clone());
        self.inner.joined.lock().unwrap().insert(tag.into(), tag);

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            Some(tag),
            tag.into(),
            in_rx,
            in_tx,
        ))
    }

    /// Read a broadcast room without joining it: receive every message, send
    /// none, contribute no cover, never appear in a round's anonymity set. For a
    /// party that structurally cannot originate traffic — counting it would
    /// overstate the set, since it hides nobody. Anyone who might send must
    /// [`subscribe`](Self::subscribe): joining on first send would make the join
    /// itself the signal.
    pub async fn listen(&self, tag: ServiceTag) -> Result<Pipe, OpenError> {
        let has_carrier = self
            .inner
            .config
            .read()
            .unwrap()
            .body
            .services
            .iter()
            .any(|svc| svc.tag == tag);
        if !has_carrier {
            return Err(OpenError::TagNotInConfig);
        }

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner
            .pipes
            .lock()
            .unwrap()
            .insert(tag.into(), in_tx.clone());

        // No peer tag, so a send fails instead of silently making this node a
        // client the moment it transmits.
        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            None,
            tag.into(),
            in_rx,
            in_tx,
        ))
    }

    /// Subscribe to subnet/round [`Event`]s; pure `Pipe` apps can ignore it. A slow
    /// consumer lags and drops the oldest events rather than blocking the runtime.
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Round duration of the adopted config (all public subnets share it). Read
    /// live so a caller's cadence tracks reconfiguration.
    pub fn round_duration(&self) -> std::time::Duration {
        let cfg = self.inner.config.read().unwrap();
        cfg.body
            .subnets
            .first()
            .map(|s| s.protocol.round_duration())
            .unwrap_or(std::time::Duration::from_secs(1))
    }

    /// Framed payloads accepted from this node's pipes but not yet on the wire.
    /// At most one leaves per round (the round's participation draw stages it),
    /// so a non-zero depth is how many rounds the next send waits — what
    /// [`crate::client_pool::ClientPool`] balances over.
    pub fn queued_outbound(&self) -> usize {
        self.inner.outbox.lock().unwrap().len()
    }

    /// Make this node's relay sessions misbehave (`None` = honest). For demos
    /// and fault-injection tests: a `Withhold`ing relay triggers an attributed
    /// `Liveness` fault; a `CorruptShare` relay is unattributable under ADCNet
    /// but an attributed `Integrity` fault under Panetiere. Applied from the next
    /// round and across reconfiguration.
    pub fn set_misbehavior(&self, mode: Option<Misbehavior>) {
        self.inner
            .misbehavior
            .store(misbehavior_code(mode), Ordering::Relaxed);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("service tag not present in current AnymoneRoundConfiguration")]
    TagNotInConfig,
    #[error("local identity is not registered for this service tag")]
    NotOurService,
}

/// Prepared (not yet running) instance with its governance subscription set up.
/// Advance with [`AnymonePrep::start`]. Relays/services publish their registration
/// separately via [`crate::scheduling::announce_relay_registration`] /
/// [`announce_service_registration`](crate::scheduling::announce_service_registration).
pub struct AnymonePrep {
    identity: Identity,
    transport: Arc<dyn Transport>,
    bootstrap: GovernanceBootstrap,
    config_sub: Subscription,
    good_clients: GoodClients,
}

impl AnymonePrep {
    /// Restrict which client keys this node's relays accept contributions from;
    /// every client is accepted otherwise.
    pub fn set_good_clients(&mut self, good_clients: GoodClients) {
        self.good_clients = good_clients;
    }
}

/// Overall bound on waiting for a first valid config at startup, so an
/// unreachable committee fails loudly instead of looping forever.
const STARTUP_CONFIG_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

impl AnymonePrep {
    /// Await the first valid signed config, bring up its subnets, and hand the
    /// subscription to the reconfig watcher for later versions.
    pub async fn start(mut self) -> Result<Anymone, GovernanceError> {
        let committee = self.bootstrap.committee.clone();
        let threshold = self.bootstrap.threshold;
        let verify =
            |c: &AnymoneRoundConfiguration| c.verify_multisig(&committee, threshold).is_ok();
        let fetch_loop = async {
            loop {
                // Prefer pulling the current config from a connected peer.
                match self.transport.fetch_config().await {
                    Some(b) => match bincode::deserialize::<AnymoneRoundConfiguration>(&b) {
                        Ok(c) if verify(&c) => break Ok(c),
                        Ok(_) => {
                            tracing::debug!(target: GOV, "anymone: fetched config failed multisig verification")
                        }
                        Err(e) => {
                            tracing::debug!(target: GOV, error = %e, "anymone: fetched config failed to deserialize")
                        }
                    },
                    None => {}
                }
                // No peer answered yet — briefly await a pushed config, then retry the pull.
                tokio::select! {
                    msg = self.config_sub.recv() => {
                        let msg = msg.ok_or(GovernanceError::TopicClosed)?;
                        match bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) {
                            Ok(c) if verify(&c) => break Ok(c),
                            Ok(_) => tracing::debug!(target: GOV, "anymone: pushed config failed multisig verification"),
                            Err(e) => tracing::debug!(target: GOV, error = %e, "anymone: pushed config failed to deserialize"),
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                }
            }
        };
        let cfg = match tokio::time::timeout(STARTUP_CONFIG_DEADLINE, fetch_loop).await {
            Ok(result) => result?,
            Err(_) => return Err(GovernanceError::Timeout),
        };
        Ok(Anymone::build_from_config(
            self.identity,
            self.transport,
            cfg,
            Some((self.config_sub, self.bootstrap)),
            self.good_clients,
        )
        .await)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SessionKey {
    Server,
    Watch,
    Client,
    Aggregator,
}

/// Serialized (id, sorted roster, protocol). Respawn a worker only when this
/// changes — leadership/role derive from the roster, so it covers them too.
fn subnet_sig(subnet: &Subnet) -> Vec<u8> {
    let mut roster = subnet.relays.clone();
    roster.sort();
    bincode::serialize(&(subnet.id, &roster, &subnet.protocol)).unwrap_or_default()
}

/// Reconcile running workers to `config`: spawn new/changed, drop removed, leave
/// unchanged ones running. Subscriptions are set up before taking the task lock
/// (subscribe is async), then the worker + stage-channel maps swap together.
async fn apply_config(
    inner: &Arc<AnymoneInner>,
    tasks: &Arc<SubnetTasks>,
    config: AnymoneRoundConfiguration,
) {
    let me = inner.identity.pubkey();
    info!(
        target: GOV,
        version = config.body.round,
        subnets = config.body.subnets.len(),
        "applying config"
    );
    // Global round clock (genesis epoch), so every node agrees regardless of which
    // config version it holds. `config.body.round` is the version, not the clock.
    let base_round = 0;
    let epoch_unix_ms = config.body.epoch_unix_ms;

    // Applied before any worker spawns, so its first sends already resolve
    // against this config's peers and rosters.
    inner.transport.apply(crate::governance::net_view(
        &config.body,
        inner.committee.as_deref().unwrap_or_default(),
    ));

    let current: HashMap<SubnetId, Vec<u8>> = {
        let g = tasks.workers.lock().unwrap();
        g.iter().map(|(id, w)| (*id, w.sig.clone())).collect()
    };
    let present: std::collections::HashSet<SubnetId> =
        config.body.subnets.iter().map(|s| s.id).collect();
    // Live reconfiguration arms new workers to start at the cutover boundary
    // while outgoing ones finish their in-flight round; at startup there is
    // nothing to hand over from, so workers join the current round directly.
    let armed = !current.is_empty();

    let mut built: Vec<(
        SubnetId,
        Vec<u8>,
        mpsc::UnboundedSender<StageMsg>,
        JoinHandle<()>,
    )> = Vec::new();
    for subnet in config.body.subnets.iter().cloned() {
        let id = subnet.id;
        let sig = subnet_sig(&subnet);
        if current.get(&id) == Some(&sig) {
            continue; // unchanged — leave the running worker in place
        }
        // Skip (don't panic on) a subnet we can't run in a signed config.
        if !subnet_runnable(&subnet) {
            warn!(target: SCHED, id, "skipping unrunnable subnet in config");
            continue;
        }
        let (topics, wants_inbox) = subnet_subscriptions(&subnet, me);
        let mut subscriptions = Vec::with_capacity(topics.len() + 1);
        for t in topics {
            subscriptions.push(inner.transport.subscribe(t).await);
        }
        if wants_inbox {
            subscriptions.push(inner.transport.inbox(id).await);
        }
        let (stage_tx, stage_rx) = mpsc::unbounded_channel();
        let inner_for_task = inner.clone();
        // The one place that dispatches on protocol: each runs its own self-contained
        // subnet driver. Unsupported protocols were filtered by subnet_runnable above.
        let handle = match &subnet.protocol {
            ProtocolConfig::Adcnet(_) => tokio::spawn(crate::adcnet::run_subnet(
                subnet,
                config.body.relay_exchange_keys.clone(),
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
                armed,
            )),
            ProtocolConfig::Panetiere(_) => tokio::spawn(crate::panetiere::run_subnet(
                subnet,
                config.body.relay_exchange_keys.clone(),
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
                armed,
            )),
            ProtocolConfig::ScheduledPanetiere(_) => {
                tokio::spawn(crate::panetiere_scheduled::run_subnet(
                    subnet,
                    config.body.relay_exchange_keys.clone(),
                    inner_for_task,
                    stage_rx,
                    subscriptions,
                    base_round,
                    epoch_unix_ms,
                    armed,
                ))
            }
            ProtocolConfig::Noop(_) => tokio::spawn(crate::noop::run_subnet(
                subnet,
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
                armed,
            )),
            ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => {
                unreachable!("filtered by subnet_runnable")
            }
        };
        built.push((id, sig, stage_tx, handle));
    }

    {
        let mut workers = tasks.workers.lock().unwrap();
        let mut stage_map = inner.subnets.lock().unwrap();
        let removed: Vec<SubnetId> = workers
            .keys()
            .copied()
            .filter(|id| !present.contains(id))
            .collect();
        // Outgoing workers (removed or replaced) finish their in-flight round
        // plus one more, then exit — the armed replacement starts at that
        // boundary, so reconfiguration loses no round. A finished worker's
        // `Subscription`s drop with it; nothing else to tear down.
        for id in removed {
            if workers.remove(&id).is_some() {
                if let Some(tx) = stage_map.remove(&id) {
                    let _ = tx.send(StageMsg::Shutdown);
                }
            }
        }
        for (id, sig, stage_tx, handle) in built {
            if let Some(old_tx) = stage_map.get(&id) {
                let _ = old_tx.send(StageMsg::Shutdown);
            }
            workers.insert(id, SubnetWorker { sig, handle });
            stage_map.insert(id, stage_tx);
        }
    }
    // Deliver each subnet's cover rate to its (surviving) worker; a cover-only
    // change isn't in `subnet_sig`, so the worker isn't rebuilt for it.
    {
        let stage_map = inner.subnets.lock().unwrap();
        for subnet in &config.body.subnets {
            if let Some(tx) = stage_map.get(&subnet.id) {
                let _ = tx.send(StageMsg::SetCoverRate(subnet.cover_rate));
            }
        }
    }
    let _ = inner.events.send(Event::ConfigUpdated {
        round: config.body.round,
    });
}

/// How often a node re-pulls the config from peers to catch a version it
/// missed on the push topic. A stale node keeps contributing with the old
/// geometry, which every current-config relay must reject — catch-up bounds
/// how long that divergence lasts.
const CONFIG_CATCHUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Watch the governance config topic and adopt every newer signed version, for
/// the node's lifetime — with a periodic pull fallback for missed pushes.
/// Exits when the `Anymone` is dropped (weak refs fail).
async fn reconfig_watch(
    mut sub: Subscription,
    bootstrap: GovernanceBootstrap,
    inner: Weak<AnymoneInner>,
    tasks: Weak<SubnetTasks>,
) {
    let mut catchup = tokio::time::interval(CONFIG_CATCHUP_INTERVAL);
    catchup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let payload = tokio::select! {
            msg = sub.recv() => match msg {
                Some(m) => m.payload,
                None => return,
            },
            _ = catchup.tick() => {
                let Some(inner) = inner.upgrade() else { return };
                match inner.transport.fetch_config().await {
                    Some(bytes) => bytes,
                    None => continue,
                }
            }
        };
        let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&payload) else {
            debug!(target: GOV, len = payload.len(), "reconfig: undecodable config, ignored");
            continue;
        };
        if let Err(e) = cfg.verify_multisig(&bootstrap.committee, bootstrap.threshold) {
            debug!(
                target: GOV,
                version = cfg.body.round,
                sigs = cfg.signatures.len(),
                threshold = bootstrap.threshold,
                ?e,
                "reconfig: config failed multisig verification, ignored"
            );
            continue;
        }
        let (Some(inner), Some(tasks)) = (inner.upgrade(), tasks.upgrade()) else {
            return; // the node was dropped
        };
        // Adopt strictly newer versions only; a re-publish of the same config is
        // a no-op.
        {
            let cur = inner.config.read().unwrap();
            if cfg.body.round <= cur.body.round {
                trace!(
                    target: GOV,
                    version = cfg.body.round,
                    current = cur.body.round,
                    "reconfig: not newer than the adopted config, ignored"
                );
                continue;
            }
        }
        *inner.config.write().unwrap() = cfg.clone();
        // Serve the new version to peers that pull instead of waiting for a push.
        inner.transport.serve_config(payload);
        apply_config(&inner, &tasks, cfg).await;
    }
}

/// Put one outbound message where its `Dest` says: a topic publish, or a
/// direct send to each addressee. A self-addressed send is skipped — the local
/// loop-back in [`publish_and_loop_back`] already fed it to this node's sessions.
pub(crate) async fn deliver(inner: &AnymoneInner, me: Pubkey, dest: Dest, bytes: Vec<u8>) {
    match dest {
        Dest::Topic(topic) => inner.transport.publish(topic, bytes).await,
        Dest::Peer(_, pk) if pk == me => {}
        Dest::Peer(subnet, pk) => inner.transport.send(pk, subnet, bytes).await,
        Dest::Each(subnet, pks) => {
            for pk in pks {
                if pk != me {
                    inner.transport.send(pk, subnet, bytes.clone()).await;
                }
            }
        }
    }
}

/// Publish `out` and also feed it to this node's other local sessions — the
/// transport drops a node's own messages, so a node with two roles on the same
/// subnet (e.g. leader + aggregator) would otherwise never see the other's output.
pub(crate) async fn publish_and_loop_back(
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> Dest,
    identity_pk: Pubkey,
    producer: SessionKey,
    out: Vec<u8>,
) {
    if let Some(m) = fault_monitor.as_mut() {
        m.on_inbound(identity_pk, out.clone());
    }
    for (key, s) in sessions.iter_mut() {
        if *key == producer {
            continue;
        }
        for followup in s.on_inbound(identity_pk, out.clone()) {
            let dest = egress(key, &followup);
            deliver(inner, identity_pk, dest, followup).await;
        }
    }
    let dest = egress(&producer, &out);
    deliver(inner, identity_pk, dest, out).await;
}

/// Feed one inbound message to every session, publishing whatever they produce.
pub(crate) async fn handle_inbound(
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> Dest,
    identity_pk: Pubkey,
    msg: Inbound,
) {
    let Inbound { from, payload } = msg;
    if let Some(m) = fault_monitor.as_mut() {
        m.on_inbound(from, payload.clone());
    }
    let outs: Vec<(SessionKey, Vec<u8>)> = sessions
        .iter_mut()
        .flat_map(|(key, s)| {
            let key = *key;
            s.on_inbound(from, payload.clone())
                .into_iter()
                .map(move |out| (key, out))
        })
        .collect();
    for (key, out) in outs {
        publish_and_loop_back(
            sessions,
            fault_monitor,
            inner,
            egress,
            identity_pk,
            key,
            out,
        )
        .await;
    }
}

/// Deliver already-arrived messages before a timer action: a round cutoff must
/// never outrun inbound delivered before it fired (a one-shot payload would be lost).
pub(crate) async fn drain_inbound(
    subscriptions: &mut [Subscription],
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> Dest,
    identity_pk: Pubkey,
) {
    for i in 0..subscriptions.len() {
        while let Some(msg) = subscriptions[i].try_recv() {
            handle_inbound(sessions, fault_monitor, inner, egress, identity_pk, msg).await;
        }
    }
}

/// A leader detects a misbehaving relay twice — its session names the lane, its
/// fault monitor names the inconsistent share — and the committee counts reports
/// against `fault_grace`, so one node reports a fault once.
#[derive(Default)]
pub(crate) struct ReportedFaults(std::collections::HashSet<(Round, FaultKind, Attribution)>);

const FAULT_REPORT_HISTORY: Round = 16;

impl ReportedFaults {
    fn first_time(&mut self, round: Round, fault: &Fault) -> bool {
        self.0
            .retain(|(seen, _, _)| *seen + FAULT_REPORT_HISTORY >= round);
        self.0
            .insert((round, fault.kind, fault.attribution.clone()))
    }
}

/// Gossip every observed fault for the committee/auditors and surface it locally
/// on the events stream. Shared by every protocol's subnet driver; each fault
/// carries its own round since one tick can span faults from different rounds.
pub(crate) async fn gossip_faults(
    inner: &AnymoneInner,
    subnet_id: SubnetId,
    reporter: Pubkey,
    reported: &mut ReportedFaults,
    faults: Vec<(Round, Fault)>,
) {
    for (round, fault) in faults {
        if !reported.first_time(round, &fault) {
            continue;
        }
        let report = FaultReport {
            round,
            subnet: subnet_id,
            reporter,
            fault: fault.clone(),
        };
        inner.transport.publish(TOPIC_FAULTS, report.encode()).await;
        let _ = inner.events.send(Event::Fault {
            round,
            subnet: subnet_id,
            fault,
        });
    }
}

pub(crate) fn round_at(base_round: Round, epoch_unix_ms: u64, dur_ms: u64, now_ms: u64) -> Round {
    if now_ms <= epoch_unix_ms {
        return base_round;
    }
    base_round + (now_ms - epoch_unix_ms) / dur_ms
}

pub(crate) fn deadline_for(
    round: Round,
    base_round: Round,
    epoch_unix_ms: u64,
    dur_ms: u64,
    now_ms: u64,
) -> tokio::time::Instant {
    let boundary_ms = epoch_unix_ms + (round - base_round + 1) * dur_ms;
    let wait = boundary_ms.saturating_sub(now_ms);
    tokio::time::Instant::now() + std::time::Duration::from_millis(wait)
}

/// Armed spawn: sleep until the end of the round after the current one — the
/// boundary where the outgoing worker (told to [`StageMsg::Shutdown`] at the
/// same instant) exits. Round boundaries are epoch-aligned, so every node that
/// adopts the config within the same round picks the same boundary, and the
/// wait gives fresh peer connections time to establish. Absorbs
/// cover-rate updates while waiting; returns `false` on `Shutdown` (or channel
/// close), meaning this worker was itself replaced before ever running and must
/// exit — its successor arms to its own boundary, and the round or two of gap a
/// double reconfiguration leaves is accepted rather than bridged.
pub(crate) async fn arm_until_cutover(
    base_round: Round,
    epoch_unix_ms: u64,
    dur_ms: u64,
    stage_rx: &mut mpsc::UnboundedReceiver<StageMsg>,
    cover_rate: &mut f32,
) -> bool {
    let now_ms = crate::config::now_unix_ms();
    let cur = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let arm = tokio::time::sleep_until(deadline_for(
        cur + 1,
        base_round,
        epoch_unix_ms,
        dur_ms,
        now_ms,
    ));
    tokio::pin!(arm);
    loop {
        tokio::select! {
            _ = &mut arm => return true,
            msg = stage_rx.recv() => match msg {
                Some(StageMsg::SetCoverRate(r)) => *cover_rate = r,
                Some(StageMsg::Shutdown) | None => {
                    debug!(target: SCHED, "armed worker replaced before running; exiting");
                    return false;
                }
            },
        }
    }
}

/// A non-empty roster and a protocol with runtime wiring.
pub fn subnet_runnable(subnet: &Subnet) -> bool {
    !subnet.relays.is_empty()
        && matches!(
            subnet.protocol,
            ProtocolConfig::Adcnet(_)
                | ProtocolConfig::Panetiere(_)
                | ProtocolConfig::ScheduledPanetiere(_)
                | ProtocolConfig::Noop(_)
        )
}

/// Subnet leader (ADCNet canonical-set announcer / Panetiere `Decoded`
/// publisher), indexed by subnet id so each subnet gets a distinct leader.
pub fn subnet_leader_pk(subnet: &Subnet) -> Pubkey {
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    leader_of(&sorted, subnet.id)
}

/// The leader index into an already-sorted roster, shared by `subnet_leader_pk`
/// and the committee's per-subnet observers so the two never disagree.
pub fn leader_of(sorted_roster: &[Pubkey], subnet_id: SubnetId) -> Pubkey {
    let n = sorted_roster.len();
    assert!(n > 0, "subnet has at least one relay");
    sorted_roster[(subnet_id as usize) % n]
}

/// What this node reads for `subnet`: topics, plus whether it wants the
/// subnet's direct inbox. Combining relays (ADCNet: only the leader; Panetiere:
/// every relay) read the inbox — client posts, their lane's coded shares, the
/// openings sealed to them — plus the shares topic; everyone else only the
/// broadcast topic. Aggregators read the inbox (their group's client
/// contributions) and the shares topic.
fn subnet_subscriptions(subnet: &Subnet, me: Pubkey) -> (Vec<Topic>, bool) {
    let combines = match &subnet.protocol {
        ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => {
            subnet.relays.contains(&me)
        }
        ProtocolConfig::Adcnet(_) => subnet_leader_pk(subnet) == me,
        _ => false,
    };
    let mut wants_inbox = combines;
    let mut topics = if combines {
        vec![Topic::Shares(subnet.id)]
    } else {
        vec![Topic::Broadcast(subnet.id)]
    };
    // Scheduled Panetiere relays combine over inbox+shares like the one-round
    // flow, but also need the leader's `Reservations` broadcast — for their own
    // (possibly co-located) client session and as a follower fallback. Under
    // consensus set formation a co-located client needs the receipts, which
    // ride broadcast for the same reason.
    let broadcast_too = matches!(subnet.protocol, ProtocolConfig::ScheduledPanetiere(_))
        || subnet.protocol.set_formation() == crate::config::SetFormation::Consensus;
    if combines && broadcast_too {
        topics.push(Topic::Broadcast(subnet.id));
    }
    if let Some(a) = subnet_aggregation(subnet) {
        if aggregator_group_of(a, me).is_some() {
            wants_inbox = true;
            let shares = Topic::Shares(subnet.id);
            if !topics.contains(&shares) {
                topics.push(shares);
            }
        }
    }
    (topics, wants_inbox)
}

/// Aggregation config for a subnet — ADCNet only; Panetiere shards its ingress
/// across the relay set instead of aggregating it.
pub(crate) fn subnet_aggregation(subnet: &Subnet) -> Option<&crate::config::Aggregation> {
    match &subnet.protocol {
        ProtocolConfig::Adcnet(c) => c.aggregation.as_ref(),
        _ => None,
    }
}

/// Group index whose aggregator committee includes `me`, if any.
pub(crate) fn aggregator_group_of(a: &crate::config::Aggregation, me: Pubkey) -> Option<u32> {
    a.groups
        .iter()
        .position(|g| g.aggregators.contains(&me))
        .map(|i| i as u32)
}

/// The aggregator committee a client routes its contribution to in an
/// aggregated subnet.
pub(crate) fn client_aggregators(subnet: &Subnet, me: Pubkey) -> Option<Vec<Pubkey>> {
    let a = subnet_aggregation(subnet)?;
    let group = u32::from_be_bytes([me.0[0], me.0[1], me.0[2], me.0[3]]) % a.groups.len() as u32;
    Some(a.groups[group as usize].aggregators.clone())
}

/// Await the next message on any of `subs`, dropping closed ones. Parks forever
/// once all are closed, so it never fires spuriously in a `tokio::select!`.
pub(crate) async fn recv_any(subs: &mut Vec<Subscription>) -> Inbound {
    loop {
        if subs.is_empty() {
            std::future::pending::<()>().await;
        }
        // Rotate first: `select_all` returns the lowest-index ready future, so a
        // fixed order lets the high-volume inbox starve the low-volume shares
        // topic (relays would never see each other's decryption shares).
        subs.rotate_left(1);
        let futures: Vec<_> = subs.iter_mut().map(|s| Box::pin(s.recv())).collect();
        let (res, idx, _) = futures_util::future::select_all(futures).await;
        match res {
            Some(msg) => return msg,
            None => {
                subs.remove(idx);
            }
        }
    }
}

pub fn subnet_uses_ingress(subnet: &Subnet) -> bool {
    matches!(
        subnet.protocol,
        ProtocolConfig::Adcnet(_)
            | ProtocolConfig::Panetiere(_)
            | ProtocolConfig::ScheduledPanetiere(_)
    )
}

/// Build a non-participating watch session for `subnet`: reads the leader's
/// `Decoded` broadcasts (Noop: a plain server session), no crypto state.
pub fn watch_session_for(subnet: &Subnet) -> Box<dyn Session> {
    match &subnet.protocol {
        ProtocolConfig::Noop(c) => noop::server_session(c),
        ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => {
            Box::new(PanetiereWatchSession::new(subnet_leader_pk(subnet)))
        }
        ProtocolConfig::Adcnet(_) => Box::new(AdcnetWatchSession::new(subnet_leader_pk(subnet))),
        ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => {
            unimplemented!("ScheduledAdcnet / Nym runtime wiring is not yet implemented")
        }
    }
}

pub(crate) fn route_to_pipe(inner: &AnymoneInner, round: Round, bytes: &[u8]) {
    let frame = match Frame::decode(bytes) {
        Ok(f) => f,
        Err(e) => {
            warn!(target: WIRE, len = bytes.len(), "dropped malformed frame: {e}");
            return;
        }
    };
    let outer_tag = frame.dst();
    let data = match frame {
        Frame::Raw { data, .. } => data,
        Frame::Fragment {
            n_chunks,
            chunk_index,
            ..
        } => {
            // The payload is lost, not deferred — reassembly is unimplemented.
            warn!(
                target: WIRE,
                dst = ?outer_tag,
                chunk_index,
                n_chunks,
                "dropped fragment: reassembly is not implemented"
            );
            return;
        }
    };
    let pipe_msg: PipeMessage = match bincode::deserialize(data) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                target: WIRE,
                dst = ?outer_tag,
                len = data.len(),
                error = %e,
                "dropped decoded frame: payload is not a PipeMessage"
            );
            return;
        }
    };
    let sender = inner.pipes.lock().unwrap().get(&outer_tag).cloned();
    match sender {
        Some(tx) => {
            trace!(target: WIRE, dst = ?outer_tag, "route to pipe");
            let _ = tx.send(PipeIncoming {
                return_tag: pipe_msg.return_tag,
                payload: pipe_msg.payload,
                round,
            });
        }
        // Every node decodes every subnet payload, so most are for other
        // people's pipes — but this is also how a message to a pipe that has
        // since closed disappears.
        None => trace!(target: WIRE, dst = ?outer_tag, "no pipe for dst, dropped"),
    }
}

/// The one subnet this node participates in (cover or real) at `round`, drawn
/// uniformly over the current config's runnable subnets. Deterministic across
/// this node's workers — exactly one claims each round — and independent of
/// subnet configuration, so all randomly-participating clients form a single
/// anonymity set (whitepaper: anonymity superset).
pub(crate) fn participation_subnet(inner: &AnymoneInner, round: Round) -> Option<SubnetId> {
    let cfg = inner.config.read().unwrap();
    let mut candidates: Vec<SubnetId> = cfg
        .body
        .subnets
        .iter()
        .filter(|s| subnet_runnable(s))
        .map(|s| s.id)
        .collect();
    drop(cfg);
    if candidates.is_empty() {
        return None;
    }
    candidates.sort();
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    inner.participation_seed.hash(&mut h);
    round.hash(&mut h);
    Some(candidates[(h.finish() % candidates.len() as u64) as usize])
}

/// Reconcile a worker's client session with the node's plan for `round`:
/// create/drop the session, and when this subnet holds the round's
/// participation draw, roll the messaging-rate coin — on a hit the session
/// submits, carrying a queued frame if there is one and a zero-message
/// otherwise. The rate coin gates the submission event itself, so P(submit)
/// is independent of real traffic and send patterns can't distinguish users.
pub(crate) fn sync_client_round(
    inner: &AnymoneInner,
    subnet: SubnetId,
    round: Round,
    messaging_rate: f32,
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    make: impl FnOnce() -> Box<dyn Session>,
) {
    let joined = !inner.joined.lock().unwrap().is_empty();
    if !joined && inner.outbox.lock().unwrap().is_empty() {
        // Dropping the session strands anything queued after this check but
        // before the next round's — worth seeing when a send goes missing.
        if sessions.remove(&SessionKey::Client).is_some() {
            debug!(
                target: SCHED,
                subnet, round, "sync: no pipe joined and nothing queued; client session dropped"
            );
        }
        return;
    }
    let drawn = participation_subnet(inner, round) == Some(subnet);
    let submit = drawn && rand::thread_rng().gen::<f32>() < messaging_rate;
    let queued = inner.outbox.lock().unwrap().len();
    // Not being drawn is the normal case on every other subnet; only a coin
    // skip (messaging_rate < 1) is worth a line.
    if drawn && !submit {
        debug!(
            target: SCHED,
            subnet, round, messaging_rate, queued, "sync: drawn but not submitting"
        );
    }
    // A payload queued while this subnet keeps losing the draw waits, silently,
    // for however many rounds that takes.
    if !drawn && queued > 0 {
        trace!(
            target: SCHED,
            subnet, round, queued, "sync: payload queued but this subnet was not drawn"
        );
    }
    let sess = sessions.entry(SessionKey::Client).or_insert_with(make);
    sess.set_cover_rate(if submit { 1.0 } else { 0.0 });
    if submit {
        let frame = inner.outbox.lock().unwrap().pop_front();
        if let Some(frame) = frame {
            trace!(
                target: SCHED,
                subnet,
                round,
                len = frame.len(),
                "sync: staging a queued payload"
            );
            sess.stage(frame);
        }
    }
}

/// One line per round per subnet worker: the round's whole outcome, so a stalled
/// subnet is visible as an absence of decodes rather than an absence of logs.
/// `debug` — a round that carried nothing leaves no other trace, and every
/// failure path here is silent by construction.
pub(crate) fn log_round_outcome(
    protocol: &'static str,
    subnet: SubnetId,
    round: Round,
    n_decoded: usize,
    n_faults: usize,
) {
    debug!(
        target: SCHED,
        protocol,
        subnet,
        round,
        decoded = n_decoded,
        faults = n_faults,
        "round complete"
    );
}

/// Queue a framed payload for the next participating round (any subnet).
pub(crate) fn queue_outbound(
    inner: &Weak<AnymoneInner>,
    payload: Vec<u8>,
) -> Result<(), crate::pipe::SendError> {
    let inner = inner.upgrade().ok_or(crate::pipe::SendError::Closed)?;
    inner.outbox.lock().unwrap().push_back(payload);
    Ok(())
}

#[cfg(test)]
mod outbox_tests {
    use super::*;
    use crate::config::{AnymoneRoundConfiguration, NoopConfig, ProtocolConfig};
    use crate::config::ScheduledPanetiereConfig;
    use crate::panetiere_scheduled::{
        params_for, ReservationEntries, ScheduledPanetiereClientSession,
    };

    fn test_inner(relays: Vec<Pubkey>) -> Arc<AnymoneInner> {
        let protocol = ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        });
        let cfg = AnymoneRoundConfiguration::singleton_subnet(
            0,
            protocol,
            relays.clone(),
            vec![],
            vec![],
        );
        let transport: Arc<dyn Transport> =
            Arc::new(crate::transport::InMemoryNetwork::new().handle(relays[0]));
        Arc::new(AnymoneInner {
            identity: crate::Identity::generate(),
            transport,
            config: RwLock::new(cfg),
            pipes: Mutex::new(HashMap::new()),
            joined: Mutex::new(HashMap::new()),
            subnets: Mutex::new(HashMap::new()),
            outbox: Mutex::new(VecDeque::new()),
            sched_entries: Mutex::new(HashMap::new()),
            participation_seed: [42u8; 32],
            committee: None,
            events: broadcast::channel(1).0,
            misbehavior: AtomicU8::new(0),
            good_clients: GoodClients::all(),
        })
    }

    /// A reconfig cutover drops the client session mid-flight; its payloads came
    /// off the outbox, so they have to go back or the send is silently lost.
    #[test]
    fn dropped_client_session_requeues_unsent_payloads() {
        let identity = crate::Identity::generate();
        let inner = test_inner(vec![identity.pubkey()]);
        let cfg = ScheduledPanetiereConfig {
            vector_bytes: 128,
            estimated_messages: 2,
            ..Default::default()
        };
        let (mse, pp) = params_for(&cfg, 1);

        let mut session = ScheduledPanetiereClientSession::new(
            pp,
            mse,
            128,
            identity.clone(),
            Vec::new(),
            identity.pubkey(),
            [7u8; 32],
            ReservationEntries::default(),
        );
        session.set_node(Arc::downgrade(&inner));
        session.stage(b"first".to_vec());
        session.stage(b"second".to_vec());
        // Cover carries no payload and must not be resurrected as a real send.
        session.stage(Vec::new());
        assert!(inner.outbox.lock().unwrap().is_empty());

        drop(session);

        let outbox = inner.outbox.lock().unwrap();
        assert_eq!(
            outbox.iter().cloned().collect::<Vec<_>>(),
            vec![b"first".to_vec(), b"second".to_vec()],
            "unsent payloads must return to the outbox, in order, without cover"
        );
    }
}

#[cfg(test)]
mod participation_tests {
    use super::*;
    use crate::config::{AnymoneRoundConfiguration, NoopConfig, ProtocolConfig};

    #[test]
    fn participation_draw_is_uniform_and_deterministic() {
        let protocol = ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        });
        let relays = vec![crate::Identity::generate().pubkey()];
        let cfg = AnymoneRoundConfiguration::singleton_subnet(
            0,
            protocol.clone(),
            relays.clone(),
            vec![],
            vec![],
        );
        let mut cfg = cfg;
        for id in 1..4u32 {
            let mut s = cfg.body.subnets[0].clone();
            s.id = id;
            cfg.body.subnets.push(s);
        }
        let transport: Arc<dyn Transport> =
            Arc::new(crate::transport::InMemoryNetwork::new().handle(relays[0]));
        let inner = AnymoneInner {
            identity: crate::Identity::generate(),
            transport,
            config: RwLock::new(cfg),
            pipes: Mutex::new(HashMap::new()),
            joined: Mutex::new(HashMap::new()),
            subnets: Mutex::new(HashMap::new()),
            outbox: Mutex::new(VecDeque::new()),
            sched_entries: Mutex::new(HashMap::new()),
            participation_seed: [42u8; 32],
            committee: None,
            events: broadcast::channel(1).0,
            misbehavior: AtomicU8::new(0),
            good_clients: GoodClients::all(),
        };
        let mut counts = [0usize; 4];
        for round in 0..4000u64 {
            let a = participation_subnet(&inner, round).unwrap();
            // Deterministic: every worker computing the draw agrees.
            assert_eq!(participation_subnet(&inner, round), Some(a));
            counts[a as usize] += 1;
        }
        for c in counts {
            assert!((800..1200).contains(&c), "skewed draw: {counts:?}");
        }
    }
}
