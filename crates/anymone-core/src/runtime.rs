//! Per-subnet driver and the `Anymone` facade.
//!
//! The runtime owns the clock and the transport-side I/O. Each subnet runs
//! in its own task; sessions live inside the task and never see async.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Instant;

use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::adcnet::{
    AdcnetClientSession, AdcnetObserverSession, AdcnetServerSession, AdcnetWatchSession,
};
use crate::config::{
    AdcnetConfig, AnymoneRoundConfiguration, PanetiereConfig, ProtocolConfig, Round, Subnet,
    SubnetId,
};
use crate::governance::{FaultReport, GovernanceBootstrap, GovernanceError, TOPIC_FAULTS};
use crate::identity::{Identity, Pubkey};
use crate::noop;
use crate::panetiere::{
    PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, PanetiereWatchSession,
};
use crate::pipe::{Pipe, PipeIncoming, PipeMessage};
use crate::session::{Fault, Misbehavior, Session};
use crate::transport::{Inbound, Subscription, Transport};
use crate::wire::{Frame, ServiceTag, SERVICE_TAG_LEN};

/// Consecutive output-less rounds before a subnet's leader-side monitor reports
/// a `Liveness` fault — the established "fault on the second round" threshold
/// (matches the committee + dashboard observers).
const FAULT_THRESHOLD: u64 = 2;

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

use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};
use panetiere::protocol::{ClientId, ProtocolParams, ServerId};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

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
    /// Current signed config. Swapped in place on live reconfiguration; `open`/`bind`/`Pipe`
    /// send-time resolution sees the latest subnet set and re-homes clients automatically.
    pub(crate) config: RwLock<AnymoneRoundConfiguration>,
    /// `service_tag` → inbox for the matching `Pipe` (service tags and return tags).
    pub(crate) pipes: Mutex<HashMap<ServiceTag, mpsc::UnboundedSender<PipeIncoming>>>,
    pub(crate) subnets: Mutex<HashMap<SubnetId, mpsc::UnboundedSender<StageMsg>>>,
    /// Fan-out of subnet/round events ([`Event`]). Workers publish; callers
    /// subscribe via [`Anymone::events`].
    pub(crate) events: broadcast::Sender<Event>,
    /// Byzantine misbehavior this node's relay sessions adopt (demo/testing):
    /// 0 = honest, 1 = withhold shares, 2 = corrupt shares.
    misbehavior: AtomicU8,
}

impl AnymoneInner {
    fn misbehavior(&self) -> Option<Misbehavior> {
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

/// Message to a subnet worker about a client session (keyed by the pipe's `return_tag`).
pub(crate) enum StageMsg {
    /// Build the client session for an open `Pipe` so it ticks (and so emits
    /// cover) every round, even with no `send`.
    Join { client_tag: ServiceTag },
    /// Stage a payload on the client session (building it if needed).
    Stage {
        client_tag: ServiceTag,
        payload: Vec<u8>,
    },
    /// Drop the client session. Sent to a client's *old* subnet on re-home so it
    /// leaves that anonymity set — otherwise the population is double-counted.
    Retire { client_tag: ServiceTag },
    /// Adopt a new cover rate from a config change, without rebuilding the worker
    /// (which would drop idle pipes from the anonymity set).
    SetCoverRate(f32),
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
        Self::build_from_config(identity, transport, config, None).await
    }

    /// Build the node from `config`. When `governance` is set (the
    /// `prepare`/`start` path), a watcher task adopts later config versions so
    /// the live network can scale subnets up/down.
    async fn build_from_config(
        identity: Identity,
        transport: Arc<dyn Transport>,
        config: AnymoneRoundConfiguration,
        governance: Option<(Subscription, GovernanceBootstrap)>,
    ) -> Self {
        let inner = Arc::new(AnymoneInner {
            identity,
            transport: transport.clone(),
            config: RwLock::new(config.clone()),
            pipes: Mutex::new(HashMap::new()),
            subnets: Mutex::new(HashMap::new()),
            events: broadcast::channel(EVENTS_CAPACITY).0,
            misbehavior: AtomicU8::new(0),
        });
        let tasks = Arc::new(SubnetTasks {
            workers: Mutex::new(HashMap::new()),
            aux: Mutex::new(Vec::new()),
        });
        apply_config(&inner, &tasks, config).await;

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

    /// Open a pipe to a service. Spreads across all subnets carrying `tag`,
    /// allocates a fresh return tag, registers an inbox.
    pub async fn open(&self, tag: ServiceTag) -> Result<Pipe, OpenError> {
        let has_carrier = self
            .inner
            .config
            .read()
            .unwrap()
            .body
            .subnets
            .iter()
            .any(|s| s.services.iter().any(|svc| svc.tag == tag));
        if !has_carrier {
            return Err(OpenError::TagNotInConfig);
        }

        let mut return_bytes = [0u8; SERVICE_TAG_LEN];
        rand::thread_rng().fill_bytes(&mut return_bytes);
        let return_tag = ServiceTag(return_bytes);

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner.pipes.lock().unwrap().insert(return_tag, in_tx);

        // Join the home subnet so the pipe contributes cover before any send.
        if let Some(subnet) = resolve_send_subnet(&self.inner, Some(tag), return_tag, tag) {
            let tx = self.inner.subnets.lock().unwrap().get(&subnet).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(StageMsg::Join {
                    client_tag: return_tag,
                });
            }
        }

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            Some(tag),
            return_tag,
            in_rx,
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
            .subnets
            .iter()
            .flat_map(|s| s.services.iter())
            .find(|svc| svc.tag == tag)
            .map(|svc| svc.pubkey);

        match our_service {
            None => return Err(OpenError::TagNotInConfig),
            Some(pk) if pk != self.inner.identity.pubkey() => return Err(OpenError::NotOurService),
            Some(_) => {}
        }

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner.pipes.lock().unwrap().insert(tag, in_tx);

        Ok(Pipe::new(Arc::downgrade(&self.inner), None, tag, in_rx))
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
            .subnets
            .iter()
            .any(|s| s.services.iter().any(|svc| svc.tag == tag));
        if !has_carrier {
            return Err(OpenError::TagNotInConfig);
        }

        let (in_tx, in_rx) = mpsc::unbounded_channel();
        self.inner.pipes.lock().unwrap().insert(tag, in_tx);

        // Join one carrier for cover; receiving is route-by-tag on every subnet.
        if let Some(subnet) = resolve_send_subnet(&self.inner, Some(tag), tag, tag) {
            let tx = self.inner.subnets.lock().unwrap().get(&subnet).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(StageMsg::Join { client_tag: tag });
            }
        }

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            Some(tag),
            tag,
            in_rx,
        ))
    }

    /// Subscribe to subnet/round [`Event`]s; pure `Pipe` apps can ignore it. A slow
    /// consumer lags and drops the oldest events rather than blocking the runtime.
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
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
/// Advance with [`AnymonePrep::start`].
pub struct AnymonePrep {
    identity: Identity,
    transport: Arc<dyn Transport>,
    bootstrap: GovernanceBootstrap,
    config_sub: Subscription,
}

impl AnymonePrep {
    /// Await the first valid signed config, bring up its subnets, and hand the
    /// subscription to the reconfig watcher for later versions.
    pub async fn start(mut self) -> Result<Anymone, GovernanceError> {
        let cfg = loop {
            let msg = self
                .config_sub
                .recv()
                .await
                .ok_or(GovernanceError::TopicClosed)?;
            let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) else {
                continue;
            };
            if cfg
                .verify_multisig(&self.bootstrap.committee, self.bootstrap.threshold)
                .is_ok()
            {
                break cfg;
            }
        };
        Ok(Anymone::build_from_config(
            self.identity,
            self.transport,
            cfg,
            Some((self.config_sub, self.bootstrap)),
        )
        .await)
    }

    /// Like [`start`](Self::start) but re-publishes `registration` on the
    /// registration topic every `interval` — first until the node is placed, then
    /// for the node's lifetime so a relay/service later dropped from the roster
    /// (sidelined) re-registers and is healed back in once its backoff lapses.
    pub async fn start_announcing(
        self,
        registration: Vec<u8>,
        interval: std::time::Duration,
    ) -> Result<Anymone, GovernanceError> {
        let transport = self.transport.clone();
        let started = self.start();
        tokio::pin!(started);
        let anymone = loop {
            transport
                .publish(crate::governance::TOPIC_REGISTRATION, registration.clone())
                .await;
            tokio::select! {
                res = &mut started => break res?,
                _ = tokio::time::sleep(interval) => {}
            }
        };
        // Keep re-announcing for as long as the node is alive (weak handle, so the
        // task ends when the node is dropped).
        let weak = std::sync::Arc::downgrade(&transport);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(t) = weak.upgrade() else { break };
                t.publish(crate::governance::TOPIC_REGISTRATION, registration.clone())
                    .await;
            }
        });
        Ok(anymone)
    }
}

#[derive(PartialEq, Eq, Hash)]
enum SessionKey {
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
    // Global round clock (genesis epoch), so every node agrees regardless of which
    // config version it holds. `config.body.round` is the version, not the clock.
    let base_round = 0;
    let epoch_unix_ms = 0;

    let current: HashMap<SubnetId, Vec<u8>> = {
        let g = tasks.workers.lock().unwrap();
        g.iter().map(|(id, w)| (*id, w.sig.clone())).collect()
    };
    let present: std::collections::HashSet<SubnetId> =
        config.body.subnets.iter().map(|s| s.id).collect();

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
        let topics = subnet_subscription_topics(&subnet, me);
        let mut subscriptions = Vec::with_capacity(topics.len());
        for t in &topics {
            subscriptions.push(inner.transport.subscribe(t).await);
        }
        let (stage_tx, stage_rx) = mpsc::unbounded_channel();
        let inner_for_task = inner.clone();
        let handle = tokio::spawn(async move {
            run_subnet(
                subnet,
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
            )
            .await;
        });
        built.push((id, sig, stage_tx, handle));
    }

    let mut workers = tasks.workers.lock().unwrap();
    let mut stage_map = inner.subnets.lock().unwrap();
    workers.retain(|id, w| {
        if present.contains(id) {
            true
        } else {
            w.handle.abort();
            stage_map.remove(id);
            false
        }
    });
    for (id, sig, stage_tx, handle) in built {
        if let Some(old) = workers.insert(id, SubnetWorker { sig, handle }) {
            old.handle.abort();
        }
        stage_map.insert(id, stage_tx);
    }
    drop(workers);
    drop(stage_map);
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

/// Watch the governance config topic and adopt every newer signed version, for
/// the node's lifetime. Exits when the `Anymone` is dropped (weak refs fail).
async fn reconfig_watch(
    mut sub: Subscription,
    bootstrap: GovernanceBootstrap,
    inner: Weak<AnymoneInner>,
    tasks: Weak<SubnetTasks>,
) {
    while let Some(msg) = sub.recv().await {
        let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) else {
            continue;
        };
        if cfg
            .verify_multisig(&bootstrap.committee, bootstrap.threshold)
            .is_err()
        {
            continue;
        }
        let (Some(inner), Some(tasks)) = (inner.upgrade(), tasks.upgrade()) else {
            return; // the node was dropped
        };
        // Adopt strictly newer versions only; re-broadcasts of the same config
        // (the committee resends every round for late joiners) are a no-op.
        {
            let cur = inner.config.read().unwrap();
            if cfg.body.round <= cur.body.round {
                continue;
            }
        }
        *inner.config.write().unwrap() = cfg.clone();
        apply_config(&inner, &tasks, cfg).await;
    }
}

async fn run_subnet(
    subnet: Subnet,
    inner: Arc<AnymoneInner>,
    mut stage_rx: mpsc::UnboundedReceiver<StageMsg>,
    mut subscriptions: Vec<Subscription>,
    base_round: Round,
    epoch_unix_ms: u64,
) {
    let identity_pk = inner.identity.pubkey();
    let broadcast_topic = subnet_broadcast_topic(subnet.id);
    let ingress_topic = subnet_ingress_topic(subnet.id);
    let shares_topic = subnet_shares_topic(subnet.id);
    let uses_ingress = subnet_uses_ingress(&subnet);

    let round_duration = subnet.protocol.round_duration();

    let shared = SubnetShared::from_subnet(&subnet);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut client_homes: HashSet<ServiceTag> = HashSet::new();
    let mut cover_rate = subnet.cover_rate;
    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            build_server_session(&subnet, &shared, &inner.identity),
        );
    } else {
        sessions.insert(SessionKey::Watch, watch_session_for(&subnet));
    }
    // Aggregator role: a node in some aggregator group sums that group's client
    // contributions. Coexists with any relay role.
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            let n_groups = a.groups.len() as u32;
            let session: Box<dyn Session> = match &subnet.protocol {
                ProtocolConfig::Panetiere(_) => {
                    Box::new(crate::panetiere::PanetiereAggregatorSession::new(
                        group,
                        n_groups,
                        inner.identity.clone(),
                    ))
                }
                ProtocolConfig::Adcnet(_) => Box::new(crate::adcnet::AdcnetAggregatorSession::new(
                    group,
                    n_groups,
                    inner.identity.clone(),
                )),
                _ => unreachable!("aggregation only on Panetiere/Adcnet"),
            };
            sessions.insert(SessionKey::Aggregator, session);
        }
    }

    // Leader-side liveness monitor: it sees every relay's share (shares topic)
    // and its own decoded output, so feeding it all inbound + local outbound
    // reconstructs the wire view the observer needs. One reporter per subnet.
    let mut fault_monitor: Option<Box<dyn Session>> = if subnet_leader_pk(&subnet) == identity_pk {
        let mut roster = subnet.relays.clone();
        roster.sort();
        match &subnet.protocol {
            ProtocolConfig::Panetiere(_) => Some(Box::new(PanetiereObserverSession::new(
                roster,
                FAULT_THRESHOLD,
            ))),
            ProtocolConfig::Adcnet(_) => Some(Box::new(AdcnetObserverSession::new(
                roster,
                FAULT_THRESHOLD,
            ))),
            _ => None,
        }
    } else {
        None
    };

    // Round labels are derived from the signed wall-clock epoch (passed in from
    // the config that scheduled this subnet), not counted locally, so every node
    // agrees on the current round regardless of when it joined or how long it
    // was blocked. `deadline` aligns to absolute round boundaries; a node that
    // falls behind re-derives and skips ahead.
    let dur_ms = (round_duration.as_millis() as u64).max(1);

    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
    // Fire `mid_round` halfway through each round (aggregators emit their batch).
    let mut mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
    let mut mid_done = false;

    let is_share: fn(&[u8]) -> bool = match &subnet.protocol {
        ProtocolConfig::Adcnet(_) => crate::adcnet::is_server_share,
        ProtocolConfig::Panetiere(_) => crate::panetiere::is_server_share,
        _ => |_| false,
    };
    // In an aggregated subnet a client's contribution goes to its aggregator
    // group's topic instead of ingress (Panetiere openings still go to ingress).
    let client_agg_topic: Option<String> = client_aggregator_topic(&subnet, identity_pk);
    let is_agg_client: fn(&[u8]) -> bool = match &subnet.protocol {
        ProtocolConfig::Adcnet(_) => crate::adcnet::is_client_message,
        ProtocolConfig::Panetiere(_) => crate::panetiere::is_client_public,
        _ => |_| false,
    };
    let egress = |key: &SessionKey, bytes: &[u8]| -> &str {
        if !uses_ingress {
            return &broadcast_topic;
        }
        match key {
            SessionKey::Server => {
                if is_share(bytes) {
                    &shares_topic
                } else {
                    &broadcast_topic
                }
            }
            SessionKey::Client => match &client_agg_topic {
                Some(t) if is_agg_client(bytes) => t,
                _ => &ingress_topic,
            },
            // Aggregators publish their signed group aggregate on the shares
            // topic, where the leader already listens.
            SessionKey::Aggregator => &shares_topic,
            SessionKey::Watch => &broadcast_topic,
        }
    };

    if let Some(m) = fault_monitor.as_mut() {
        m.begin_round(round, Instant::now());
    }
    let misbehavior = inner.misbehavior();
    for (key, s) in sessions.iter_mut() {
        if let SessionKey::Server = key {
            s.set_misbehavior(misbehavior);
        }
        for out in s.begin_round(round, Instant::now()) {
            if let Some(m) = fault_monitor.as_mut() {
                m.on_inbound(identity_pk, out.clone());
            }
            let dest = egress(key, &out);
            inner.transport.publish(dest, out).await;
        }
    }

    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep_until(mid_deadline), if !mid_done => {
                mid_done = true;
                for (key, s) in sessions.iter_mut() {
                    for out in s.mid_round(round, Instant::now()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(dest, out).await;
                    }
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults: Vec<Fault> = Vec::new();
                for (key, s) in sessions.iter_mut() {
                    let outcome = s.end_round(round, Instant::now());
                    for out in outcome.outbound {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(dest, out).await;
                    }
                    decoded_all.extend(outcome.decoded);
                    faults.extend(outcome.faults);
                }
                if let Some(m) = fault_monitor.as_mut() {
                    faults.extend(m.end_round(round, Instant::now()).faults);
                }
                let n_decoded = decoded_all.len();
                for bytes in decoded_all {
                    route_to_pipe(&inner, &bytes);
                }
                if n_decoded > 0 {
                    let _ = inner.events.send(Event::RoundDecoded {
                        round,
                        subnet: subnet.id,
                        n_messages: n_decoded,
                    });
                }
                // Gossip every observed fault for the committee/auditors and
                // surface it locally on the events stream.
                for fault in faults {
                    let report = FaultReport {
                        round,
                        subnet: subnet.id,
                        reporter: identity_pk,
                        fault: fault.clone(),
                    };
                    inner.transport.publish(TOPIC_FAULTS, report.encode()).await;
                    let _ = inner.events.send(Event::Fault { round, subnet: subnet.id, fault });
                }
                // Re-derive the round from the clock (self-correcting), but
                // always advance at least one round so a sub-millisecond skew
                // between the tokio timer and the wall clock can't replay the
                // round we just ended.
                let now_ms = crate::config::now_unix_ms();
                round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
                mid_done = false;
                if let Some(m) = fault_monitor.as_mut() {
                    m.begin_round(round, Instant::now());
                }
                let misbehavior = inner.misbehavior();
                for (key, s) in sessions.iter_mut() {
                    if let SessionKey::Server = key {
                        s.set_misbehavior(misbehavior);
                    }
                    for out in s.begin_round(round, Instant::now()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(dest, out).await;
                    }
                }
            }

            msg = recv_any(&mut subscriptions) => {
                let Inbound { from, payload } = msg;
                // Sessions self-include their own output; don't ingest the loopback.
                if from == identity_pk {
                    continue;
                }
                if let Some(m) = fault_monitor.as_mut() {
                    m.on_inbound(from, payload.clone());
                }
                for (key, s) in sessions.iter_mut() {
                    for out in s.on_inbound(from, payload.clone()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(dest, out).await;
                    }
                }
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::Join { client_tag } => {
                        client_homes.insert(client_tag);
                        sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| build_client_session(&subnet, &shared, &inner.identity))
                            .set_cover_rate(cover_rate);
                    }
                    StageMsg::Stage { client_tag, payload } => {
                        client_homes.insert(client_tag);
                        let sess = sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| build_client_session(&subnet, &shared, &inner.identity));
                        sess.set_cover_rate(cover_rate);
                        sess.stage(payload);
                    }
                    StageMsg::Retire { client_tag } => {
                        client_homes.remove(&client_tag);
                        if client_homes.is_empty() {
                            sessions.remove(&SessionKey::Client);
                        }
                    }
                    StageMsg::SetCoverRate(rate) => {
                        cover_rate = rate;
                        if let Some(c) = sessions.get_mut(&SessionKey::Client) {
                            c.set_cover_rate(rate);
                        }
                    }
                }
            }
        }
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

/// Per-subnet state shared across sessions, built once so `ProtocolParams::setup`
/// (CS / KAHE keygen) isn't re-run for every client stage.
enum SubnetShared {
    Trivial,
    Panetiere { pp: Arc<ProtocolParams> },
    Adcnet { one_round: OneRoundConfig },
}

impl SubnetShared {
    fn from_subnet(subnet: &Subnet) -> Self {
        match &subnet.protocol {
            ProtocolConfig::Panetiere(cfg) => {
                let mut rng = ChaCha20Rng::from_seed(cfg.setup_seed);
                let pp = Arc::new(ProtocolParams::setup(&mut rng, subnet.relays.len()));
                SubnetShared::Panetiere { pp }
            }
            ProtocolConfig::Adcnet(cfg) => {
                let one_round = OneRoundConfig {
                    iblt: IbltMsgParamsOwned {
                        estimated_messages: cfg.estimated_messages,
                        max_payload_bytes: cfg.max_payload_bytes,
                    },
                };
                SubnetShared::Adcnet { one_round }
            }
            _ => SubnetShared::Trivial,
        }
    }
}

fn adcnet_relay_index(subnet: &Subnet, pk: Pubkey) -> Option<u32> {
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    sorted.iter().position(|p| *p == pk).map(|i| i as u32)
}

/// Subnet leader (ADCNet canonical-set announcer / Panetiere `Decoded`
/// publisher), indexed by subnet id so each subnet gets a distinct leader.
pub fn subnet_leader_pk(subnet: &Subnet) -> Pubkey {
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    let n = sorted.len();
    assert!(n > 0, "subnet has at least one relay");
    sorted[(subnet.id as usize) % n]
}

/// Topics this node subscribes to for `subnet`. The combining relays read
/// ingress + shares (ADCNet: only the leader combines; Panetiere: every relay
/// does); everyone else only the broadcast topic.
fn subnet_subscription_topics(subnet: &Subnet, me: Pubkey) -> Vec<String> {
    let combines = match &subnet.protocol {
        ProtocolConfig::Panetiere(_) => subnet.relays.contains(&me),
        ProtocolConfig::Adcnet(_) => subnet_leader_pk(subnet) == me,
        _ => false,
    };
    let mut topics = if combines {
        vec![
            subnet_ingress_topic(subnet.id),
            subnet_shares_topic(subnet.id),
        ]
    } else {
        vec![subnet_broadcast_topic(subnet.id)]
    };
    // An aggregator listens on its group topic for client messages, and joins the
    // shares mesh to publish its group aggregate there.
    if let Some(a) = subnet_aggregation(subnet) {
        if let Some(group) = aggregator_group_of(a, me) {
            topics.push(subnet_aggregator_topic(subnet.id, group));
            let shares = subnet_shares_topic(subnet.id);
            if !topics.contains(&shares) {
                topics.push(shares);
            }
        }
    }
    topics
}

/// Aggregation config for a subnet, if either protocol enabled it.
fn subnet_aggregation(subnet: &Subnet) -> Option<&crate::config::Aggregation> {
    match &subnet.protocol {
        ProtocolConfig::Panetiere(c) => c.aggregation.as_ref(),
        ProtocolConfig::Adcnet(c) => c.aggregation.as_ref(),
        _ => None,
    }
}

/// Group index whose aggregator committee includes `me`, if any.
fn aggregator_group_of(a: &crate::config::Aggregation, me: Pubkey) -> Option<u32> {
    a.groups
        .iter()
        .position(|g| g.aggregators.contains(&me))
        .map(|i| i as u32)
}

/// The group topic a client routes its contribution to in an aggregated subnet.
fn client_aggregator_topic(subnet: &Subnet, me: Pubkey) -> Option<String> {
    let a = subnet_aggregation(subnet)?;
    let group = u32::from_be_bytes([me.0[0], me.0[1], me.0[2], me.0[3]]) % a.groups.len() as u32;
    Some(subnet_aggregator_topic(subnet.id, group))
}

/// Await the next message on any of `subs`, dropping closed ones. Parks forever
/// once all are closed, so it never fires spuriously in a `tokio::select!`.
async fn recv_any(subs: &mut Vec<Subscription>) -> Inbound {
    loop {
        if subs.is_empty() {
            std::future::pending::<()>().await;
        }
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

pub fn subnet_broadcast_topic(id: SubnetId) -> String {
    format!("anymone/subnet/{id}")
}

/// Leader-ingress topic: high-volume client contributions go here, only the
/// leader subscribes, so that traffic is never gossiped to everyone else.
pub fn subnet_ingress_topic(id: SubnetId) -> String {
    format!("anymone/subnet/{id}/ingress")
}

/// Shares topic: every relay broadcasts its decryption share here (low volume).
/// The leader combines from it; observers track liveness; broadcasting (rather
/// than a leader-only channel) keeps shares available for verifiability.
pub fn subnet_shares_topic(id: SubnetId) -> String {
    format!("anymone/subnet/{id}/shares")
}

pub fn subnet_uses_ingress(subnet: &Subnet) -> bool {
    matches!(
        subnet.protocol,
        ProtocolConfig::Adcnet(_) | ProtocolConfig::Panetiere(_)
    )
}

/// Per-group topic: an aggregator group's clients post their public
/// ciphertext+commitment here; the group's aggregators subscribe.
pub fn subnet_aggregator_topic(id: SubnetId, group: u32) -> String {
    format!("anymone/subnet/{id}/agg/{group}")
}

/// ADCNet client shared secrets: ECDH the node's exchange privkey against each
/// relay's exchange pubkey from the subnet config.
fn adcnet_client_shared_secrets(
    cfg: &AdcnetConfig,
    identity: &Identity,
    subnet: &Subnet,
) -> std::collections::HashMap<adcnet::crypto::ServerId, adcnet::crypto::SharedKey> {
    use std::collections::HashMap as Map;
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    let mut out = Map::new();
    let xkey_by_pk: Map<Pubkey, &crate::config::ExchangePublicKeyWire> = cfg
        .relay_exchange_keys
        .iter()
        .map(|(p, x)| (*p, x))
        .collect();
    for (i, pk) in sorted.iter().enumerate() {
        if let Some(xkw) = xkey_by_pk.get(pk) {
            if let Ok(xk) = xkw.to_key() {
                let sid = adcnet::crypto::ServerId((i + 1) as u32);
                out.insert(sid, identity.exchange().ecdh(&xk));
            }
        }
    }
    out
}

/// Panetiere `ServerId` → relay exchange pubkey, for sealing client openings.
fn panetiere_server_xpubs(
    cfg: &PanetiereConfig,
    subnet: &Subnet,
) -> HashMap<ServerId, adcnet::crypto::ExchangePublicKey> {
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    let xkey_by_pk: HashMap<Pubkey, &crate::config::ExchangePublicKeyWire> = cfg
        .relay_exchange_keys
        .iter()
        .map(|(p, x)| (*p, x))
        .collect();
    sorted
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| {
            let xk = xkey_by_pk.get(pk)?.to_key().ok()?;
            Some((ServerId(i as u32), xk))
        })
        .collect()
}

/// Position of `pk` in the sorted relay list — the Panetiere `ServerId`.
fn server_index(relays: &[Pubkey], pk: Pubkey) -> Option<u32> {
    let mut sorted = relays.to_vec();
    sorted.sort();
    sorted.iter().position(|p| *p == pk).map(|i| i as u32)
}

/// Deterministic `ClientId` from the pipe's return tag — first 4 bytes as
/// big-endian u32. Same node + same pipe yields the same id, which is what
/// the Panetiere decoder uses to merge round publics with openings.
fn client_id_from_pubkey(pk: Pubkey) -> ClientId {
    ClientId(u32::from_be_bytes([pk.0[0], pk.0[1], pk.0[2], pk.0[3]]))
}

fn leader_aggregation_from_config(
    a: &crate::config::Aggregation,
) -> crate::session::LeaderAggregation {
    let roster = a
        .groups
        .iter()
        .enumerate()
        .map(|(i, g)| (i as u32, g.aggregators.clone()))
        .collect();
    crate::session::LeaderAggregation { roster }
}

fn build_server_session(
    subnet: &Subnet,
    shared: &SubnetShared,
    identity: &Identity,
) -> Box<dyn Session> {
    let identity_pk = identity.pubkey();
    match (&subnet.protocol, shared) {
        (ProtocolConfig::Noop(c), _) => noop::server_session(c),
        (ProtocolConfig::Panetiere(cfg), SubnetShared::Panetiere { pp }) => {
            let server_id = ServerId(
                server_index(&subnet.relays, identity_pk)
                    .expect("build_server_session called on non-relay"),
            );
            let mut sorted = subnet.relays.clone();
            sorted.sort();
            let server_pubkeys = sorted
                .into_iter()
                .enumerate()
                .map(|(i, pk)| (ServerId(i as u32), pk))
                .collect();
            // Every relay needs the aggregator roster (canonical mode + verifying
            // group-aggregate signatures); only the leader emits the decode.
            let aggregation = cfg.aggregation.as_ref().map(leader_aggregation_from_config);
            Box::new(PanetiereServerSession::new(
                pp.clone(),
                server_id,
                crate::scheduler_core::expected_active(cfg.client_set_max),
                identity.exchange().clone(),
                subnet_leader_pk(subnet) == identity_pk,
                server_pubkeys,
                aggregation,
            ))
        }
        (ProtocolConfig::Adcnet(cfg), SubnetShared::Adcnet { one_round }) => {
            let idx = adcnet_relay_index(subnet, identity_pk)
                .expect("build_server_session called on non-relay");
            let server_id = adcnet::crypto::ServerId(idx + 1);
            let leader_pk = subnet_leader_pk(subnet);
            let leader_idx = (subnet.id as usize) % subnet.relays.len();
            let is_leader = idx as usize == leader_idx;
            // Only the leader combines, so only it needs the aggregator roster.
            let aggregation = if is_leader {
                cfg.aggregation.as_ref().map(leader_aggregation_from_config)
            } else {
                None
            };
            Box::new(AdcnetServerSession::new(
                one_round.clone(),
                server_id,
                identity.to_adcnet_signing_key(),
                identity.exchange().clone(),
                subnet.relays.len(),
                is_leader, // sorted_relays[id % n] leads this subnet
                leader_pk,
                aggregation,
            ))
        }
        (ProtocolConfig::ScheduledAdcnet(_), _) | (ProtocolConfig::Nym(_), _) => {
            unimplemented!("ScheduledAdcnet / Nym runtime wiring is not yet implemented")
        }
        (ProtocolConfig::Panetiere(_), _) => {
            unreachable!("Panetiere requires SubnetShared::Panetiere")
        }
        (ProtocolConfig::Adcnet(_), _) => unreachable!("Adcnet requires SubnetShared::Adcnet"),
    }
}

fn build_client_session(
    subnet: &Subnet,
    shared: &SubnetShared,
    identity: &Identity,
) -> Box<dyn Session> {
    match (&subnet.protocol, shared) {
        (ProtocolConfig::Noop(c), _) => noop::client_session(c),
        (ProtocolConfig::Panetiere(cfg), SubnetShared::Panetiere { pp }) => {
            let client_id = client_id_from_pubkey(identity.pubkey());
            let mut sorted = subnet.relays.clone();
            sorted.sort();
            let server_ids: Vec<ServerId> = (0..sorted.len() as u32).map(ServerId).collect();
            // Secret entropy: a seed derived from the return tag (public, rides
            // in routing headers) would let anyone replay the client's round.
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            Box::new(PanetiereClientSession::new(
                pp.clone(),
                client_id,
                server_ids,
                panetiere_server_xpubs(cfg, subnet),
                seed,
            ))
        }
        (ProtocolConfig::Adcnet(cfg), SubnetShared::Adcnet { one_round }) => {
            let shared_secrets = adcnet_client_shared_secrets(cfg, identity, subnet);
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            Box::new(AdcnetClientSession::new(
                one_round.clone(),
                identity.to_adcnet_signing_key(),
                shared_secrets,
                identity.exchange_pubkey(),
                seed,
            ))
        }
        (ProtocolConfig::ScheduledAdcnet(_), _) | (ProtocolConfig::Nym(_), _) => {
            unimplemented!("ScheduledAdcnet / Nym runtime wiring is not yet implemented")
        }
        (ProtocolConfig::Panetiere(_), _) => {
            unreachable!("Panetiere requires SubnetShared::Panetiere")
        }
        (ProtocolConfig::Adcnet(_), _) => unreachable!("Adcnet requires SubnetShared::Adcnet"),
    }
}

/// Build a non-participating watch session for `subnet`: reads the leader's
/// `Decoded` broadcasts (Noop: a plain server session), no crypto state.
pub fn watch_session_for(subnet: &Subnet) -> Box<dyn Session> {
    match &subnet.protocol {
        ProtocolConfig::Noop(c) => noop::server_session(c),
        ProtocolConfig::Panetiere(_) => {
            Box::new(PanetiereWatchSession::new(subnet_leader_pk(subnet)))
        }
        ProtocolConfig::Adcnet(_) => Box::new(AdcnetWatchSession::new(subnet_leader_pk(subnet))),
        ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => {
            unimplemented!("ScheduledAdcnet / Nym runtime wiring is not yet implemented")
        }
    }
}

fn route_to_pipe(inner: &AnymoneInner, bytes: &[u8]) {
    let frame = match Frame::decode(bytes) {
        Ok(f) => f,
        Err(e) => {
            warn!("dropped malformed frame: {e}");
            return;
        }
    };
    let outer_tag = frame.service_tag();
    let data = match frame {
        Frame::Raw { data, .. } => data,
        Frame::Fragment { .. } => return, // reassembly is M6
    };
    let pipe_msg: PipeMessage = match bincode::deserialize(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    let sender = inner.pipes.lock().unwrap().get(&outer_tag).cloned();
    if let Some(tx) = sender {
        let _ = tx.send(PipeIncoming {
            return_tag: pipe_msg.return_tag,
            payload: pipe_msg.payload,
        });
    }
}

/// Resolve which subnet a send goes on, from the *current* config (so a pipe
/// re-homes across reconfigs). Client pipes (`peer_tag = Some`) hash their
/// return tag over the service's carriers; service replies (`None`) hash `dst`.
pub(crate) fn resolve_send_subnet(
    inner: &AnymoneInner,
    peer_tag: Option<ServiceTag>,
    return_tag: ServiceTag,
    dst: ServiceTag,
) -> Option<SubnetId> {
    let cfg = inner.config.read().unwrap();
    let (candidates, key): (Vec<SubnetId>, ServiceTag) = match peer_tag {
        Some(service) => (
            cfg.body
                .subnets
                .iter()
                .filter(|s| s.services.iter().any(|svc| svc.tag == service))
                .map(|s| s.id)
                .collect(),
            return_tag,
        ),
        None => (cfg.body.subnets.iter().map(|s| s.id).collect(), dst),
    };
    if candidates.is_empty() {
        return None;
    }
    let h = key
        .0
        .iter()
        .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(*b as usize));
    Some(candidates[h % candidates.len()])
}

pub(crate) fn stage_outbound(
    inner: &Weak<AnymoneInner>,
    subnet: SubnetId,
    client_tag: ServiceTag,
    payload: Vec<u8>,
) -> Result<(), crate::pipe::SendError> {
    let inner = inner.upgrade().ok_or(crate::pipe::SendError::Closed)?;
    let stage_tx = inner
        .subnets
        .lock()
        .unwrap()
        .get(&subnet)
        .cloned()
        .ok_or(crate::pipe::SendError::SubnetGone)?;
    stage_tx
        .send(StageMsg::Stage {
            client_tag,
            payload,
        })
        .map_err(|_| crate::pipe::SendError::SubnetGone)
}

/// Best-effort: drop this pipe's client session on `subnet` after a re-home. A
/// subnet that's already gone needs no retirement.
pub(crate) fn retire_outbound(
    inner: &Weak<AnymoneInner>,
    subnet: SubnetId,
    client_tag: ServiceTag,
) {
    let Some(inner) = inner.upgrade() else { return };
    let tx = inner.subnets.lock().unwrap().get(&subnet).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(StageMsg::Retire { client_tag });
    }
}
