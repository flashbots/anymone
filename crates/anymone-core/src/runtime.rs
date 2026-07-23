//! Per-subnet driver and the `Anymone` facade.
//!
//! The runtime owns the clock and the transport-side I/O. Each subnet runs
//! in its own task; sessions live inside the task and never see async.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use rand::RngCore;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::adcnet::AdcnetWatchSession;
use crate::config::{AnymoneRoundConfiguration, ProtocolConfig, Round, Subnet, SubnetId};
use crate::faults::Fault;
use crate::governance::{FaultReport, GovernanceBootstrap, GovernanceError, TOPIC_FAULTS};
use crate::identity::{Identity, Pubkey};
use crate::noop;
use crate::panetiere::PanetiereWatchSession;
use crate::pipe::{Pipe, PipeIncoming, PipeMessage};
use crate::session::{Misbehavior, Session};
use crate::transport::{Inbound, Subscription, Transport};
use crate::wire::{Frame, RouteTag, ServiceTag, SERVICE_TAG_LEN};

/// Consecutive output-less rounds before a subnet's leader-side monitor reports
/// a `Liveness` fault — the established "fault on the second round" threshold
/// (matches the committee + dashboard observers).
pub(crate) const FAULT_THRESHOLD: u64 = 2;

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
    /// Topics this worker subscribed to, so tearing it down can also leave
    /// them (gossipsub subscription outlives a dropped local `Subscription`).
    topics: Vec<String>,
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
    pub(crate) pipes: Mutex<HashMap<RouteTag, mpsc::UnboundedSender<PipeIncoming>>>,
    /// Joined client pipes (`open`/`subscribe`), by client tag, to their carrier
    /// service — reconfig uses this to re-Join a respawned/re-homed worker.
    pub(crate) joined: Mutex<HashMap<RouteTag, ServiceTag>>,
    pub(crate) subnets: Mutex<HashMap<SubnetId, mpsc::UnboundedSender<StageMsg>>>,
    /// Set only under governance; `None` for `start_with_config` (fixed-config
    /// tests). Drives topic admission on every adopted config.
    pub(crate) committee: Option<Vec<Pubkey>>,
    /// Fan-out of subnet/round events ([`Event`]). Workers publish; callers
    /// subscribe via [`Anymone::events`].
    pub(crate) events: broadcast::Sender<Event>,
    /// Byzantine misbehavior this node's relay sessions adopt (demo/testing):
    /// 0 = honest, 1 = withhold shares, 2 = corrupt shares.
    misbehavior: AtomicU8,
}

impl AnymoneInner {
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

/// Message to a subnet worker about a client session (keyed by the pipe's `return_tag`).
pub(crate) enum StageMsg {
    /// Build the client session for an open `Pipe` so it ticks (and so emits
    /// cover) every round, even with no `send`.
    Join { client_tag: RouteTag },
    /// Stage a payload on the client session (building it if needed).
    Stage {
        client_tag: RouteTag,
        payload: Vec<u8>,
    },
    /// Drop the client session. Sent to a client's *old* subnet on re-home so it
    /// leaves that anonymity set — otherwise the population is double-counted.
    Retire { client_tag: RouteTag },
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
        let committee = governance.as_ref().map(|(_, gb)| gb.committee.clone());
        let inner = Arc::new(AnymoneInner {
            identity,
            transport: transport.clone(),
            config: RwLock::new(config.clone()),
            pipes: Mutex::new(HashMap::new()),
            joined: Mutex::new(HashMap::new()),
            subnets: Mutex::new(HashMap::new()),
            committee,
            events: broadcast::channel(EVENTS_CAPACITY).0,
            misbehavior: AtomicU8::new(0),
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

    /// Open a pipe to a service. Spreads across all subnets carrying `tag`,
    /// allocates a fresh return tag, registers an inbox.
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

        // Join the home subnet so the pipe contributes cover before any send.
        let subnet = resolve_send_subnet(&self.inner, Some(tag), return_tag, tag.into());
        if let Some(subnet) = subnet {
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
            subnet,
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
            None,
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

        // Join one carrier for cover; receiving is route-by-tag on every subnet.
        let subnet = resolve_send_subnet(&self.inner, Some(tag), tag.into(), tag.into());
        if let Some(subnet) = subnet {
            let tx = self.inner.subnets.lock().unwrap().get(&subnet).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(StageMsg::Join {
                    client_tag: tag.into(),
                });
            }
        }

        Ok(Pipe::new(
            Arc::downgrade(&self.inner),
            Some(tag),
            tag.into(),
            subnet,
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
                            tracing::debug!("anymone: fetched config failed multisig verification")
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "anymone: fetched config failed to deserialize")
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
                            Ok(_) => tracing::debug!("anymone: pushed config failed multisig verification"),
                            Err(e) => tracing::debug!(error = %e, "anymone: pushed config failed to deserialize"),
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
    // Global round clock (genesis epoch), so every node agrees regardless of which
    // config version it holds. `config.body.round` is the version, not the clock.
    let base_round = 0;
    let epoch_unix_ms = config.body.epoch_unix_ms;

    // gossipsub meshes form only over existing connections, so dial the full
    // roster rather than relying on kademlia adjacency.
    let mut roster: Vec<Pubkey> = config
        .body
        .subnets
        .iter()
        .flat_map(|s| {
            s.relays.iter().copied().chain(
                s.protocol
                    .aggregation()
                    .into_iter()
                    .flat_map(|a| a.groups.iter().flat_map(|g| g.aggregators.iter().copied())),
            )
        })
        .collect();
    roster.sort();
    roster.dedup();
    inner.transport.ensure_peers(roster).await;

    let current: HashMap<SubnetId, Vec<u8>> = {
        let g = tasks.workers.lock().unwrap();
        g.iter().map(|(id, w)| (*id, w.sig.clone())).collect()
    };
    let present: std::collections::HashSet<SubnetId> =
        config.body.subnets.iter().map(|s| s.id).collect();

    let mut built: Vec<(
        SubnetId,
        Vec<u8>,
        Vec<String>,
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
            warn!(id, "skipping unrunnable subnet in config");
            continue;
        }
        let topics = subnet_subscription_topics(&subnet, me);
        let mut subscriptions = Vec::with_capacity(topics.len());
        for t in &topics {
            subscriptions.push(inner.transport.subscribe(t).await);
        }
        let (stage_tx, stage_rx) = mpsc::unbounded_channel();
        let inner_for_task = inner.clone();
        // The one place that dispatches on protocol: each runs its own self-contained
        // subnet driver. Unsupported protocols were filtered by subnet_runnable above.
        let handle = match &subnet.protocol {
            ProtocolConfig::Adcnet(_) => tokio::spawn(crate::adcnet::run_subnet(
                subnet,
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
            )),
            ProtocolConfig::Panetiere(_) => tokio::spawn(crate::panetiere::run_subnet(
                subnet,
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
            )),
            ProtocolConfig::ScheduledPanetiere(_) => {
                tokio::spawn(crate::panetiere_scheduled::run_subnet(
                    subnet,
                    inner_for_task,
                    stage_rx,
                    subscriptions,
                    base_round,
                    epoch_unix_ms,
                ))
            }
            ProtocolConfig::Noop(_) => tokio::spawn(crate::noop::run_subnet(
                subnet,
                inner_for_task,
                stage_rx,
                subscriptions,
                base_round,
                epoch_unix_ms,
            )),
            ProtocolConfig::ScheduledAdcnet(_) | ProtocolConfig::Nym(_) => {
                unreachable!("filtered by subnet_runnable")
            }
        };
        built.push((id, sig, topics, stage_tx, handle));
    }

    let mut stale: Vec<SubnetWorker> = Vec::new();
    let live_topics: std::collections::HashSet<String>;
    {
        let mut workers = tasks.workers.lock().unwrap();
        let mut stage_map = inner.subnets.lock().unwrap();
        let removed: Vec<SubnetId> = workers
            .keys()
            .copied()
            .filter(|id| !present.contains(id))
            .collect();
        for id in removed {
            if let Some(w) = workers.remove(&id) {
                w.handle.abort();
                stage_map.remove(&id);
                stale.push(w);
            }
        }
        for (id, sig, topics, stage_tx, handle) in built {
            if let Some(old) = workers.insert(
                id,
                SubnetWorker {
                    sig,
                    topics,
                    handle,
                },
            ) {
                old.handle.abort();
                stale.push(old);
            }
            stage_map.insert(id, stage_tx);
        }
        live_topics = workers
            .values()
            .flat_map(|w| w.topics.iter().cloned())
            .collect();
    }
    // Leave topics no current worker uses. A respawned subnet reuses its topic
    // names, so only topics outside the live set may be unsubscribed — and only
    // after the stale worker has actually terminated and dropped its
    // `Subscription`s, else the transport still counts it as a listener.
    for w in stale {
        let _ = w.handle.await;
        for topic in w.topics {
            if !live_topics.contains(&topic) {
                inner.transport.unsubscribe(&topic).await;
            }
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
    if let Some(committee) = &inner.committee {
        inner
            .transport
            .set_topic_policy(crate::governance::topic_policy(&config.body, committee));
    }
    // Re-home every joined pipe against the new config: a respawned worker
    // starts with no joined pipes, and a re-home moves a listen-only pipe's
    // home without it ever sending. Held across the whole loop so a
    // concurrent `Pipe::drop` (same lock) can't interleave a stale Join
    // after this drop's retire.
    {
        let joined = inner.joined.lock().unwrap();
        let stage_map = inner.subnets.lock().unwrap();
        for (&client_tag, &service) in joined.iter() {
            let home = resolve_send_subnet(inner, Some(service), client_tag, service.into());
            for (&id, tx) in stage_map.iter() {
                let msg = if Some(id) == home {
                    StageMsg::Join { client_tag }
                } else {
                    StageMsg::Retire { client_tag }
                };
                let _ = tx.send(msg);
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
        // Adopt strictly newer versions only; a re-publish of the same config is
        // a no-op.
        {
            let cur = inner.config.read().unwrap();
            if cfg.body.round <= cur.body.round {
                continue;
            }
        }
        *inner.config.write().unwrap() = cfg.clone();
        // Serve the new version to peers that pull instead of waiting for a push.
        inner.transport.serve_config(msg.payload.clone());
        apply_config(&inner, &tasks, cfg).await;
    }
}

/// Destination topic for one outbound message, given the role that produced it
/// and the protocol's wire predicates. Shared by every protocol's subnet driver.
pub(crate) fn egress_dest(
    subnet_id: SubnetId,
    uses_ingress: bool,
    is_share: fn(&[u8]) -> bool,
    is_client: fn(&[u8]) -> bool,
    client_agg_topic: Option<&str>,
    key: &SessionKey,
    bytes: &[u8],
) -> String {
    if !uses_ingress {
        return subnet_broadcast_topic(subnet_id);
    }
    match key {
        SessionKey::Server => {
            if is_share(bytes) {
                subnet_shares_topic(subnet_id)
            } else {
                subnet_broadcast_topic(subnet_id)
            }
        }
        // In an aggregated subnet a client's contribution goes to its aggregator
        // group's topic instead of ingress (Panetiere openings still go to ingress).
        SessionKey::Client => match client_agg_topic {
            Some(t) if is_client(bytes) => t.to_string(),
            _ => subnet_ingress_topic(subnet_id),
        },
        // Aggregators publish their signed group aggregate on the shares topic,
        // where the leader already listens.
        SessionKey::Aggregator => subnet_shares_topic(subnet_id),
        SessionKey::Watch => subnet_broadcast_topic(subnet_id),
    }
}

/// Publish `out` and also feed it to this node's other local sessions — the
/// transport drops a node's own messages, so a node with two roles on the same
/// subnet (e.g. leader + aggregator) would otherwise never see the other's output.
pub(crate) async fn publish_and_loop_back(
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> String,
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
            inner.transport.publish(&dest, followup).await;
        }
    }
    let dest = egress(&producer, &out);
    inner.transport.publish(&dest, out).await;
}

/// Feed one inbound message to every session, publishing whatever they produce.
pub(crate) async fn handle_inbound(
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> String,
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
    egress: &impl Fn(&SessionKey, &[u8]) -> String,
    identity_pk: Pubkey,
) {
    for i in 0..subscriptions.len() {
        while let Some(msg) = subscriptions[i].try_recv() {
            handle_inbound(sessions, fault_monitor, inner, egress, identity_pk, msg).await;
        }
    }
}

/// Gossip every observed fault for the committee/auditors and surface it locally
/// on the events stream. Shared by every protocol's subnet driver; each fault
/// carries its own round since one tick can span faults from different rounds.
pub(crate) async fn gossip_faults(
    inner: &AnymoneInner,
    subnet_id: SubnetId,
    reporter: Pubkey,
    faults: Vec<(Round, Fault)>,
) {
    for (round, fault) in faults {
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

/// Topics this node subscribes to for `subnet`. The combining relays read
/// ingress + shares (ADCNet: only the leader combines; Panetiere: every relay
/// does); everyone else only the broadcast topic.
fn subnet_subscription_topics(subnet: &Subnet, me: Pubkey) -> Vec<String> {
    let combines = match &subnet.protocol {
        ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => {
            subnet.relays.contains(&me)
        }
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
    // Scheduled Panetiere relays combine over ingress+shares like the one-round
    // flow, but also need the leader's `Reservations` broadcast — for their own
    // (possibly co-located) client session and as a follower fallback.
    if combines && matches!(subnet.protocol, ProtocolConfig::ScheduledPanetiere(_)) {
        let broadcast = subnet_broadcast_topic(subnet.id);
        if !topics.contains(&broadcast) {
            topics.push(broadcast);
        }
    }
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
pub(crate) fn subnet_aggregation(subnet: &Subnet) -> Option<&crate::config::Aggregation> {
    match &subnet.protocol {
        ProtocolConfig::Panetiere(c) => c.aggregation.as_ref(),
        ProtocolConfig::ScheduledPanetiere(c) => c.aggregation.as_ref(),
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

/// The group topic a client routes its contribution to in an aggregated subnet.
pub(crate) fn client_aggregator_topic(subnet: &Subnet, me: Pubkey) -> Option<String> {
    let a = subnet_aggregation(subnet)?;
    let group = u32::from_be_bytes([me.0[0], me.0[1], me.0[2], me.0[3]]) % a.groups.len() as u32;
    Some(subnet_aggregator_topic(subnet.id, group))
}

/// Await the next message on any of `subs`, dropping closed ones. Parks forever
/// once all are closed, so it never fires spuriously in a `tokio::select!`.
pub(crate) async fn recv_any(subs: &mut Vec<Subscription>) -> Inbound {
    loop {
        if subs.is_empty() {
            std::future::pending::<()>().await;
        }
        // Rotate first: `select_all` returns the lowest-index ready future, so a
        // fixed order lets the high-volume ingress topic starve the low-volume
        // shares topic (relays would never see each other's decryption shares).
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
        ProtocolConfig::Adcnet(_)
            | ProtocolConfig::Panetiere(_)
            | ProtocolConfig::ScheduledPanetiere(_)
    )
}

/// Per-group topic: an aggregator group's clients post their public
/// ciphertext+commitment here; the group's aggregators subscribe.
pub fn subnet_aggregator_topic(id: SubnetId, group: u32) -> String {
    format!("anymone/subnet/{id}/agg/{group}")
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

pub(crate) fn route_to_pipe(inner: &AnymoneInner, bytes: &[u8]) {
    let frame = match Frame::decode(bytes) {
        Ok(f) => f,
        Err(e) => {
            warn!("dropped malformed frame: {e}");
            return;
        }
    };
    let outer_tag = frame.dst();
    let data = match frame {
        Frame::Raw { data, .. } => data,
        Frame::Fragment { .. } => return, // reassembly not yet implemented
    };
    let pipe_msg: PipeMessage = match bincode::deserialize(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    let sender = inner.pipes.lock().unwrap().get(&outer_tag).cloned();
    tracing::debug!(dst = ?outer_tag, matched = sender.is_some(), "route to pipe");
    if let Some(tx) = sender {
        let _ = tx.send(PipeIncoming {
            return_tag: pipe_msg.return_tag,
            payload: pipe_msg.payload,
        });
    }
}

/// Resolve which subnet a send goes on, from the *current* config (so a pipe
/// re-homes across reconfigs). Every subnet carries every service, so the
/// candidate set is just the runnable subnets; client pipes hash their return
/// tag, service replies hash `dst`.
pub(crate) fn resolve_send_subnet(
    inner: &AnymoneInner,
    peer_tag: Option<ServiceTag>,
    return_tag: RouteTag,
    dst: RouteTag,
) -> Option<SubnetId> {
    let cfg = inner.config.read().unwrap();
    // Only runnable subnets carry workers — never route to one we skipped.
    let candidates: Vec<SubnetId> = cfg
        .body
        .subnets
        .iter()
        .filter(|s| subnet_runnable(s))
        .map(|s| s.id)
        .collect();
    let key = if peer_tag.is_some() { return_tag } else { dst };
    select_subnet(candidates, key)
}

/// Pick one subnet for `key`, sorting first so the choice is independent of the
/// config's subnet order — every node must resolve a tag to the same subnet.
fn select_subnet(mut candidates: Vec<SubnetId>, key: RouteTag) -> Option<SubnetId> {
    if candidates.is_empty() {
        return None;
    }
    candidates.sort();
    let h = key
        .0
        .iter()
        .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(*b as usize));
    Some(candidates[h % candidates.len()])
}

#[cfg(test)]
mod placement_tests {
    use super::*;

    #[test]
    fn select_subnet_is_order_independent() {
        let key = RouteTag([7u8; SERVICE_TAG_LEN]);
        let a = select_subnet(vec![0, 1, 2, 3], key);
        let b = select_subnet(vec![3, 1, 0, 2], key);
        assert_eq!(a, b, "placement must not depend on candidate order");
        assert!(a.is_some());
        assert_eq!(select_subnet(vec![], key), None);
    }
}

pub(crate) fn stage_outbound(
    inner: &Weak<AnymoneInner>,
    subnet: SubnetId,
    client_tag: RouteTag,
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
pub(crate) fn retire_outbound(inner: &Weak<AnymoneInner>, subnet: SubnetId, client_tag: RouteTag) {
    let Some(inner) = inner.upgrade() else { return };
    let tx = inner.subnets.lock().unwrap().get(&subnet).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(StageMsg::Retire { client_tag });
    }
}

/// Retire `client_tag` from every worker, not just its last known home — a
/// reconfig can move a listen-only pipe's home without it ever sending.
pub(crate) fn retire_outbound_everywhere(inner: &Weak<AnymoneInner>, client_tag: RouteTag) {
    let Some(inner) = inner.upgrade() else { return };
    for tx in inner.subnets.lock().unwrap().values() {
        let _ = tx.send(StageMsg::Retire { client_tag });
    }
}
