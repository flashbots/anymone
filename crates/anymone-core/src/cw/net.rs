//! [`Transport`] over commonware-p2p `authenticated::discovery`.
//!
//! Frames are self-describing (`NetFrame`): topic publishes and directly
//! addressed subnet sends, on two physical channels so subnet volume can't
//! rate-limit governance. commonware's runtime owns its own tokio reactor, so
//! the stack lives on a dedicated thread and talks to anymone over
//! `tokio::sync` channels.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use commonware_cryptography::ed25519;
use commonware_p2p::authenticated::discovery;
use commonware_p2p::{Manager, Receiver as _, Recipients, Sender as _, TrackedPeers};
use commonware_runtime::{tokio as cw_tokio, Quota, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::ordered::Set;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::config::SubnetId;
use crate::identity::{Identity, Pubkey};
use crate::log_target::P2P;
use crate::session::GoodClients;
use crate::transport::{Inbound, NetView, Subscription, Topic, Transport, MAX_TRANSMIT_SIZE};

use super::keys;
use super::stream_server::{self, Feeds, ServerHooks};

/// Governance topics; kept off the subnet channel so they can't queue behind it.
const CH_CONTROL: u64 = 0;
const CH_DATA: u64 = 1;
const CH_RR: u64 = 2;

/// Peer-set index holding the bootstrap peers. Config-derived sets are offset
/// past it, or a round-0 config collides and commonware discards it.
const GENESIS_PEER_SET: u64 = 0;

const MAILBOX: usize = 1024;
const TOPIC_CAPACITY: usize = 1024;
const CONFIG_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Bounds the unanswered-request map; a fetch whose peers never reply is
/// abandoned by the caller's timeout, not here.
const MAX_PENDING_FETCHES: usize = 64;
/// How long shutdown waits for tasks to release their contexts; overshooting it
/// drops the runtime while a task is still on it.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a peer counts as reachable after its last frame. Governance
/// re-announces every 5s, so a live peer refreshes well inside this.
const PEER_FRESHNESS: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone)]
pub struct CommonwareConfig {
    pub listen: SocketAddr,
    /// Address peers dial us on; `listen` unless behind a NAT.
    pub dialable: SocketAddr,
    pub bootstrappers: Vec<(Pubkey, SocketAddr)>,
    /// Tracked at index 0, so governance is reachable before any signed config.
    pub genesis_peers: Vec<Pubkey>,
    /// Registration recipients before any config names watchers.
    pub committee: Vec<Pubkey>,
    /// Loopback deployments need private IPs and faster discovery.
    pub local: bool,
    /// Where clients dial this node. `None` serves no clients.
    pub stream_listen: Option<SocketAddr>,
    /// Screens client keys at the stream handshake.
    pub good_clients: GoodClients,
}

/// Everything on the backbone wire outside the RR channel.
#[derive(Serialize, Deserialize)]
enum NetFrame {
    Topic(Topic, #[serde(with = "serde_bytes")] Vec<u8>),
    /// Addressed to the receiving peer's inbox for this subnet.
    Direct(SubnetId, #[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Serialize, Deserialize)]
enum ConfigRr {
    Request(u64),
    Response(u64, Option<Vec<u8>>),
}

enum Cmd {
    Publish {
        topic: Topic,
        bytes: Vec<u8>,
    },
    Send {
        to: Pubkey,
        subnet: SubnetId,
        bytes: Vec<u8>,
    },
    Track {
        index: u64,
        primary: Vec<Pubkey>,
        secondary: Vec<Pubkey>,
    },
    FetchConfig(oneshot::Sender<Option<Vec<u8>>>),
}

/// Whether `topic` rides the data channel (subnet volume) or control.
fn is_data_topic(topic: Topic) -> bool {
    matches!(topic, Topic::Broadcast(_) | Topic::Shares(_))
}

/// State both sides read: the front-end sets it, the thread and the stream
/// listener apply it.
pub(crate) struct Shared {
    /// Pubkeys allowed to publish on each bound topic.
    senders: Mutex<HashMap<Topic, HashSet<Pubkey>>>,
    served_config: Mutex<Option<Vec<u8>>>,
    /// Live per-topic fan-out to local subscribers.
    topics: Mutex<HashMap<Topic, broadcast::Sender<Inbound>>>,
    /// Frames addressed to this node, per subnet.
    inboxes: Mutex<HashMap<SubnetId, broadcast::Sender<Inbound>>>,
    /// Where a Registration publish or a forwarded stream `Register` goes.
    reg_recipients: Mutex<Vec<Pubkey>>,
    /// Subnets in the current config; gates client stream submissions.
    subnets: Mutex<HashSet<SubnetId>>,
    /// When each peer was last heard from. There is no connected-peers API, so
    /// observed traffic is the only honest reachability signal.
    last_seen: Mutex<HashMap<Pubkey, std::time::Instant>>,
}

impl Shared {
    /// Hand `payload` to this node's local subscribers of `topic`, if any.
    pub(crate) fn deliver_local(&self, topic: Topic, from: Pubkey, payload: Vec<u8>) {
        if let Some(tx) = self.topics.lock().unwrap().get(&topic) {
            let _ = tx.send(Inbound { from, payload });
        }
    }

    /// Hand `payload` to this node's inbox for `subnet`, if open.
    pub(crate) fn deliver_inbox(&self, subnet: SubnetId, from: Pubkey, payload: Vec<u8>) {
        if let Some(tx) = self.inboxes.lock().unwrap().get(&subnet) {
            let _ = tx.send(Inbound { from, payload });
        }
    }

    pub(crate) fn served_config(&self) -> Option<Vec<u8>> {
        self.served_config.lock().unwrap().clone()
    }

    pub(crate) fn subnet_known(&self, subnet: SubnetId) -> bool {
        self.subnets.lock().unwrap().contains(&subnet)
    }

    /// Sender admission on a bound topic; an unbound topic is open.
    fn admits(&self, topic: Topic, from: Pubkey) -> bool {
        match self.senders.lock().unwrap().get(&topic) {
            Some(roster) => roster.contains(&from),
            None => true,
        }
    }

    /// Whether `topic` admits only a fixed roster.
    pub(crate) fn topic_is_bound(&self, topic: Topic) -> bool {
        self.senders.lock().unwrap().contains_key(&topic)
    }

    fn note_seen(&self, peer: Pubkey) {
        self.last_seen
            .lock()
            .unwrap()
            .insert(peer, std::time::Instant::now());
    }
}

pub struct CommonwareNetwork {
    cmds: mpsc::UnboundedSender<Cmd>,
    shared: Arc<Shared>,
    identity: Pubkey,
    attested_clients: Arc<crate::tee::AttestedClients>,
}

impl CommonwareNetwork {
    pub fn start(identity: &Identity, cfg: CommonwareConfig) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let signer = identity.to_commonware_signer();
        let me = identity.pubkey();
        let shared = Arc::new(Shared {
            senders: Mutex::new(HashMap::new()),
            served_config: Mutex::new(None),
            topics: Mutex::new(HashMap::new()),
            inboxes: Mutex::new(HashMap::new()),
            reg_recipients: Mutex::new(cfg.committee.clone()),
            subnets: Mutex::new(HashSet::new()),
            last_seen: Mutex::new(HashMap::new()),
        });
        let attested_clients = Arc::new(crate::tee::AttestedClients::new());
        let thread_shared = shared.clone();
        let thread_attested = attested_clients.clone();
        std::thread::Builder::new()
            .name("commonware".into())
            .spawn(move || {
                let dir =
                    std::env::temp_dir().join(format!("anymone-cw-{}", hex::encode(&me.0[..8])));
                let rt = cw_tokio::Config::default().with_storage_directory(dir);
                cw_tokio::Runner::new(rt).start(|context| {
                    run(context, signer, cfg, cmd_rx, thread_shared, thread_attested)
                });
            })
            .expect("spawn commonware thread");
        Arc::new(CommonwareNetwork {
            cmds: cmd_tx,
            shared,
            identity: me,
            attested_clients,
        })
    }

    fn send_cmd(&self, cmd: Cmd) {
        if self.cmds.send(cmd).is_err() {
            tracing::warn!(target: P2P, "commonware thread is gone; command dropped");
        }
    }
}

#[async_trait]
impl Transport for CommonwareNetwork {
    async fn subscribe(&self, topic: Topic) -> Subscription {
        let mut topics = self.shared.topics.lock().unwrap();
        let tx = topics
            .entry(topic)
            .or_insert_with(|| broadcast::channel(TOPIC_CAPACITY).0);
        Subscription::from_broadcast_receiver(tx.subscribe(), topic.to_string())
    }

    async fn publish(&self, topic: Topic, bytes: Vec<u8>) {
        if !self.shared.admits(topic, self.identity) {
            tracing::warn!(target: P2P, %topic, from = %self.identity, "publish rejected: sender not in topic roster");
            return;
        }
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, %topic, len = bytes.len(), limit = MAX_TRANSMIT_SIZE, "publish dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(&topic.to_string(), &self.identity, &bytes);
        self.send_cmd(Cmd::Publish { topic, bytes });
    }

    async fn send(&self, to: Pubkey, subnet: SubnetId, bytes: Vec<u8>) {
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, subnet, len = bytes.len(), limit = MAX_TRANSMIT_SIZE, "send dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(&format!("subnet/{subnet}/inbox"), &self.identity, &bytes);
        self.send_cmd(Cmd::Send { to, subnet, bytes });
    }

    async fn inbox(&self, subnet: SubnetId) -> Subscription {
        let mut inboxes = self.shared.inboxes.lock().unwrap();
        let tx = inboxes
            .entry(subnet)
            .or_insert_with(|| broadcast::channel(TOPIC_CAPACITY).0);
        Subscription::from_broadcast_receiver(tx.subscribe(), format!("subnet/{subnet}/inbox"))
    }

    fn apply(&self, view: NetView) {
        *self.shared.senders.lock().unwrap() = view.senders;
        *self.shared.reg_recipients.lock().unwrap() = view.registration_recipients;
        *self.shared.subnets.lock().unwrap() = view.subnets.iter().copied().collect();
        self.send_cmd(Cmd::Track {
            index: view.index,
            primary: view.primary,
            secondary: view.secondary,
        });
    }

    fn serve_config(&self, bytes: Vec<u8>) {
        *self.shared.served_config.lock().unwrap() = Some(bytes);
    }

    fn cached_config(&self) -> Option<Vec<u8>> { self.shared.served_config() }

    async fn fetch_config(&self) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.send_cmd(Cmd::FetchConfig(tx));
        tokio::time::timeout(CONFIG_FETCH_TIMEOUT, rx)
            .await
            .ok()?
            .ok()
            .flatten()
    }

    fn peers(&self) -> Vec<Pubkey> {
        let now = std::time::Instant::now();
        let mut peers: Vec<Pubkey> = self
            .shared
            .last_seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) <= PEER_FRESHNESS)
            .map(|(pk, _)| *pk)
            .collect();
        peers.sort();
        peers
    }

    fn local_pubkey(&self) -> Pubkey {
        self.identity
    }

    fn attested_clients(&self) -> Option<Arc<crate::tee::AttestedClients>> {
        Some(self.attested_clients.clone())
    }
}

fn cw_set(peers: &[Pubkey]) -> Set<ed25519::PublicKey> {
    Set::from_iter_dedup(peers.iter().filter_map(keys::to_cw))
}

/// Everything below runs on the commonware thread.
async fn run(
    context: cw_tokio::Context,
    signer: ed25519::PrivateKey,
    cfg: CommonwareConfig,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    shared: Arc<Shared>,
    attested_clients: Arc<crate::tee::AttestedClients>,
) {
    let signer_for_stream = signer.clone();
    let me = keys::from_cw(&commonware_cryptography::Signer::public_key(&signer));
    let bootstrappers: Vec<_> = cfg
        .bootstrappers
        .iter()
        .filter_map(|(pk, addr)| keys::to_cw(pk).map(|k| (k, (*addr).into())))
        .collect();
    let namespace = b"anymone-p2p-v0";
    let max = MAX_TRANSMIT_SIZE as u32;
    let p2p_cfg = if cfg.local {
        discovery::Config::local(
            signer,
            namespace,
            cfg.listen,
            cfg.dialable,
            bootstrappers,
            max,
        )
    } else {
        discovery::Config::recommended(
            signer,
            namespace,
            cfg.listen,
            cfg.dialable,
            bootstrappers,
            max,
        )
    };

    let (mut network, mut oracle) = discovery::Network::new(context.child("net"), p2p_cfg);
    // Channels must all be registered before the network starts.
    let quota = Quota::per_second(std::num::NonZeroU32::new(20_000).expect("nonzero"));
    let (mut control_tx, control_rx) = network.register(CH_CONTROL, quota, MAILBOX);
    let (mut data_tx, data_rx) = network.register(CH_DATA, quota, MAILBOX);
    let (mut rr_tx, mut rr_rx) = network.register(CH_RR, quota, MAILBOX);

    let mut genesis: Vec<Pubkey> = cfg.genesis_peers.clone();
    genesis.extend(cfg.bootstrappers.iter().map(|(pk, _)| *pk));
    oracle.track(GENESIS_PEER_SET, cw_set(&genesis));
    network.start();

    // Config-pull candidates: no API exposes who is connected, so ask the peers
    // we know are meant to be reachable.
    let rr_candidates: Vec<ed25519::PublicKey> = genesis.iter().filter_map(keys::to_cw).collect();

    // Ordered so eviction drops the oldest request, not every in-flight one.
    let mut pending: std::collections::BTreeMap<u64, oneshot::Sender<Option<Vec<u8>>>> =
        std::collections::BTreeMap::new();
    let mut nonce = 0u64;

    // Client-facing plane. Frames forwarded on a client's behalf re-enter this
    // loop, so they go out exactly like a local publish (registrations
    // addressed to the committee, open-topic submissions to all).
    let feeds = Feeds::default();
    let (forward_tx, mut forward_rx) = mpsc::unbounded_channel::<(Topic, Vec<u8>)>();
    if let Some(stream_listen) = cfg.stream_listen {
        stream_server::spawn(
            context.child("stream"),
            signer_for_stream,
            stream_listen,
            Arc::new(ServerHooks {
                shared: shared.clone(),
                feeds: feeds.clone(),
                publish: forward_tx,
                good_clients: cfg.good_clients.clone(),
                attested_clients,
            }),
        );
    }

    // Inbound demux: both channels carry `NetFrame`s; a frame for a topic or
    // inbox nothing local reads is dropped after decode.
    for (name, rx) in [("recv_control", control_rx), ("recv_data", data_rx)] {
        let shared = shared.clone();
        let feeds = feeds.clone();
        context.child(name).spawn(move |_| async move {
            let mut rx = rx;
            while let Ok((peer, buf)) = rx.recv().await {
                let from = keys::from_cw(&peer);
                shared.note_seen(from);
                match bincode::deserialize::<NetFrame>(buf.as_ref()) {
                    Ok(NetFrame::Topic(topic, payload)) => {
                        // Links are authenticated, so this only adds roster
                        // admission on bound topics.
                        if !shared.admits(topic, from) {
                            tracing::debug!(target: P2P, %topic, %from, "inbound dropped: publisher not in topic roster");
                            continue;
                        }
                        feeds.fanout(topic, from, &payload);
                        shared.deliver_local(topic, from, payload);
                    }
                    Ok(NetFrame::Direct(subnet, payload)) => {
                        shared.deliver_inbox(subnet, from, payload);
                    }
                    Err(e) => {
                        tracing::debug!(target: P2P, %from, error = %e, "undecodable frame")
                    }
                }
            }
        });
    }

    // One transmit path for both frame kinds: a `Direct` frame goes to its
    // addressee on the data channel; a topic frame's recipients and channel
    // derive from the topic. Registrations go to the committee (and watchers),
    // not the whole network — the recipients are known, so nothing else needs
    // the bytes.
    let mut transmit = |frame: NetFrame, to: Option<ed25519::PublicKey>| {
        let bytes = bincode::serialize(&frame).expect("frame encodes");
        match frame {
            NetFrame::Direct(..) => {
                let Some(to) = to else { return };
                data_tx.send(Recipients::One(to), bytes, false);
            }
            NetFrame::Topic(topic, _) => {
                let recipients = if topic == Topic::Registration {
                    Recipients::Some(
                        shared
                            .reg_recipients
                            .lock()
                            .unwrap()
                            .iter()
                            .filter_map(keys::to_cw)
                            .collect(),
                    )
                } else {
                    Recipients::All
                };
                if is_data_topic(topic) {
                    data_tx.send(recipients, bytes, false);
                } else {
                    control_tx.send(recipients, bytes, true);
                }
            }
        }
    };

    loop {
        tokio::select! {
            cmd = cmds.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Publish { topic, bytes } => {
                        // Stream clients see this node's own output too; the
                        // backbone never loops a publish back to its publisher.
                        feeds.fanout(topic, me, &bytes);
                        transmit(NetFrame::Topic(topic, bytes), None);
                    }
                    Cmd::Send { to, subnet, bytes } => {
                        let Some(to) = keys::to_cw(&to) else { continue };
                        transmit(NetFrame::Direct(subnet, bytes), Some(to));
                    }
                    Cmd::Track { index, primary, secondary } => {
                        oracle.track(
                            index.saturating_add(GENESIS_PEER_SET + 1),
                            TrackedPeers::new(cw_set(&primary), cw_set(&secondary)),
                        );
                    }
                    Cmd::FetchConfig(responder) => {
                        if rr_candidates.is_empty() {
                            let _ = responder.send(None);
                            continue;
                        }
                        nonce += 1;
                        while pending.len() >= MAX_PENDING_FETCHES {
                            pending.pop_first();
                        }
                        pending.insert(nonce, responder);
                        let req = bincode::serialize(&ConfigRr::Request(nonce)).expect("encode");
                        rr_tx.send(Recipients::Some(rr_candidates.clone()), req, true);
                    }
                }
            }

            // A client's frame, republished on its behalf.
            forward = forward_rx.recv() => {
                let Some((topic, bytes)) = forward else { continue };
                transmit(NetFrame::Topic(topic, bytes), None);
            }

            inbound = rr_rx.recv() => {
                let Ok((peer, buf)) = inbound else { break };
                match bincode::deserialize::<ConfigRr>(buf.as_ref()) {
                    Ok(ConfigRr::Request(n)) => {
                        let served = shared.served_config.lock().unwrap().clone();
                        let resp = bincode::serialize(&ConfigRr::Response(n, served)).expect("encode");
                        rr_tx.send(Recipients::One(peer), resp, true);
                    }
                    // A peer with no config answers `None`; keep waiting for one
                    // that has it rather than resolving the fetch empty.
                    Ok(ConfigRr::Response(n, Some(bytes))) => {
                        if let Some(responder) = pending.remove(&n) {
                            let _ = responder.send(Some(bytes));
                        }
                    }
                    Ok(ConfigRr::Response(_, None)) => {}
                    Err(e) => tracing::debug!(target: P2P, error = %e, "undecodable config request/response"),
                }
            }
        }
    }
    // Let tasks release their contexts before this thread drops the runtime out
    // from under them.
    let _ = context
        .child("shutdown")
        .stop(0, Some(SHUTDOWN_GRACE))
        .await;
}
