//! [`Transport`] over commonware-p2p `authenticated::discovery`.
//!
//! Anymone publishes on named topics; commonware sends on numeric channels to
//! authenticated peers. Topics become mux subchannels over three physical
//! channels so subnet volume can't rate-limit governance. commonware's runtime
//! owns its own tokio reactor, so the stack lives on a dedicated thread and
//! talks to anymone over `tokio::sync` channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use commonware_cryptography::ed25519;
use commonware_p2p::authenticated::discovery;
use commonware_p2p::utils::mux::{self, Builder as _};
use commonware_p2p::{Manager, Receiver as _, Recipients, Sender as _, TrackedPeers};
use commonware_runtime::{tokio as cw_tokio, Quota, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::ordered::Set;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::identity::{Identity, Pubkey};
use crate::log_target::P2P;
use crate::session::GoodClients;
use crate::transport::{Inbound, Subscription, TopicPolicy, Transport, MAX_TRANSMIT_SIZE};

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
    /// Loopback deployments need private IPs and faster discovery.
    pub local: bool,
    /// Where clients dial this node. `None` serves no clients.
    pub stream_listen: Option<SocketAddr>,
    /// Screens client keys at the stream handshake.
    pub good_clients: GoodClients,
}

#[derive(Serialize, Deserialize)]
enum ConfigRr {
    Request(u64),
    Response(u64, Option<Vec<u8>>),
}

enum Cmd {
    Subscribe {
        topic: String,
        tx: broadcast::Sender<Inbound>,
    },
    Unsubscribe(String),
    Publish {
        topic: String,
        bytes: Vec<u8>,
    },
    Track {
        index: u64,
        primary: Vec<Pubkey>,
        secondary: Vec<Pubkey>,
    },
    FetchConfig(oneshot::Sender<Option<Vec<u8>>>),
}

/// State both sides read: the front-end sets it, the thread applies it.
pub(crate) struct Shared {
    policy: Mutex<TopicPolicy>,
    served_config: Mutex<Option<Vec<u8>>>,
    /// Live per-topic fan-out. A second `subscribe` reuses the running pump
    /// instead of re-registering a subchannel (which panics), and the stream
    /// server injects client submissions through it.
    topics: Mutex<HashMap<String, broadcast::Sender<Inbound>>>,
    /// When each peer was last heard from. There is no connected-peers API, so
    /// observed traffic is the only honest reachability signal.
    last_seen: Mutex<HashMap<Pubkey, std::time::Instant>>,
}

impl Shared {
    /// Hand `payload` to this node's local subscribers of `topic`, if any.
    pub(crate) fn deliver_local(&self, topic: &str, from: Pubkey, payload: Vec<u8>) {
        if let Some(tx) = self.topics.lock().unwrap().get(topic) {
            let _ = tx.send(Inbound { from, payload });
        }
    }

    pub(crate) fn served_config(&self) -> Option<Vec<u8>> {
        self.served_config.lock().unwrap().clone()
    }

    /// Whether `topic` admits only a fixed roster.
    pub(crate) fn topic_is_bound(&self, topic: &str) -> bool {
        self.policy.lock().unwrap().contains_key(topic)
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
}

fn subchannel(topic: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(topic.as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("32-byte digest"))
}

fn is_subnet_topic(topic: &str) -> bool {
    topic.starts_with("anymone/subnet/")
}

impl CommonwareNetwork {
    pub fn start(identity: &Identity, cfg: CommonwareConfig) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let signer = identity.to_commonware_signer();
        let me = identity.pubkey();
        let shared = Arc::new(Shared {
            policy: Mutex::new(TopicPolicy::new()),
            served_config: Mutex::new(None),
            topics: Mutex::new(HashMap::new()),
            last_seen: Mutex::new(HashMap::new()),
        });
        let thread_shared = shared.clone();
        std::thread::Builder::new()
            .name("commonware".into())
            .spawn(move || {
                let dir = std::env::temp_dir()
                    .join(format!("anymone-cw-{}", hex::encode(&me.0[..8])));
                let rt = cw_tokio::Config::default().with_storage_directory(dir);
                cw_tokio::Runner::new(rt)
                    .start(|context| run(context, signer, cfg, cmd_rx, thread_shared));
            })
            .expect("spawn commonware thread");
        Arc::new(CommonwareNetwork {
            cmds: cmd_tx,
            shared,
            identity: me,
        })
    }

    fn send(&self, cmd: Cmd) {
        if self.cmds.send(cmd).is_err() {
            tracing::warn!(target: P2P, "commonware thread is gone; command dropped");
        }
    }
}

#[async_trait]
impl Transport for CommonwareNetwork {
    async fn subscribe(&self, topic: &str) -> Subscription {
        let mut topics = self.shared.topics.lock().unwrap();
        if let Some(tx) = topics.get(topic) {
            return Subscription::from_broadcast_receiver(tx.subscribe(), topic.to_string());
        }
        let (tx, rx) = broadcast::channel(TOPIC_CAPACITY);
        topics.insert(topic.to_string(), tx.clone());
        self.send(Cmd::Subscribe {
            topic: topic.to_string(),
            tx,
        });
        Subscription::from_broadcast_receiver(rx, topic.to_string())
    }

    async fn unsubscribe(&self, topic: &str) {
        let mut topics = self.shared.topics.lock().unwrap();
        // A respawned worker re-subscribes the same topics, so only tear the
        // pump down once nothing local is listening.
        if topics.get(topic).is_some_and(|tx| tx.receiver_count() == 0) {
            topics.remove(topic);
            self.send(Cmd::Unsubscribe(topic.to_string()));
        }
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
        if let Some(roster) = self.shared.policy.lock().unwrap().get(topic) {
            if !roster.contains(&self.identity) {
                tracing::warn!(target: P2P, topic, from = %self.identity, "publish rejected: sender not in topic roster");
                return;
            }
        }
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, topic, len = bytes.len(), limit = MAX_TRANSMIT_SIZE, "publish dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(topic, &self.identity, &bytes);
        self.send(Cmd::Publish {
            topic: topic.to_string(),
            bytes,
        });
    }

    fn serve_config(&self, bytes: Vec<u8>) {
        *self.shared.served_config.lock().unwrap() = Some(bytes);
    }

    async fn fetch_config(&self) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.send(Cmd::FetchConfig(tx));
        tokio::time::timeout(CONFIG_FETCH_TIMEOUT, rx)
            .await
            .ok()?
            .ok()
            .flatten()
    }

    fn set_topic_policy(&self, policy: TopicPolicy) {
        *self.shared.policy.lock().unwrap() = policy;
    }

    fn track_peers(&self, index: u64, primary: Vec<Pubkey>, secondary: Vec<Pubkey>) {
        self.send(Cmd::Track {
            index,
            primary,
            secondary,
        });
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
    let (control_tx, control_rx) = network.register(CH_CONTROL, quota, MAILBOX);
    let (data_tx, data_rx) = network.register(CH_DATA, quota, MAILBOX);
    let (mut rr_tx, mut rr_rx) = network.register(CH_RR, quota, MAILBOX);

    let mut genesis: Vec<Pubkey> = cfg.genesis_peers.clone();
    genesis.extend(cfg.bootstrappers.iter().map(|(pk, _)| *pk));
    oracle.track(GENESIS_PEER_SET, cw_set(&genesis));

    let (control_mux, mut control_handle, mut control_global) = mux::Muxer::builder(
        context.child("mux_control"),
        control_tx,
        control_rx,
        MAILBOX,
    )
    .with_global_sender()
    .build();
    let (data_mux, mut data_handle, mut data_global) =
        mux::Muxer::builder(context.child("mux_data"), data_tx, data_rx, MAILBOX)
            .with_global_sender()
            .build();
    control_mux.start();
    data_mux.start();
    network.start();

    // Config-pull candidates: no API exposes who is connected, so ask the peers
    // we know are meant to be reachable.
    let rr_candidates: Vec<ed25519::PublicKey> =
        genesis.iter().filter_map(keys::to_cw).collect();

    let mut pumps: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    // Which topic owns each subchannel, so a hash collision is refused rather
    // than silently crossing two topics' traffic.
    let mut registry: HashMap<u64, String> = HashMap::new();
    // Ordered so eviction drops the oldest request, not every in-flight one.
    let mut pending: std::collections::BTreeMap<u64, oneshot::Sender<Option<Vec<u8>>>> =
        std::collections::BTreeMap::new();
    let mut nonce = 0u64;

    // Client-facing plane. Its republish channel re-enters this loop, so client
    // traffic reaches the backbone through the same path as anything else.
    let feeds = Feeds::default();
    let (stream_pub_tx, mut stream_pub_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
    if let Some(stream_listen) = cfg.stream_listen {
        stream_server::spawn(
            context.child("stream"),
            signer_for_stream,
            stream_listen,
            Arc::new(ServerHooks {
                shared: shared.clone(),
                feeds: feeds.clone(),
                publish: stream_pub_tx,
                good_clients: cfg.good_clients.clone(),
            }),
        );
    }

    loop {
        tokio::select! {
            cmd = cmds.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Subscribe { topic, tx } => {
                        if pumps.contains_key(&topic) {
                            continue;
                        }
                        let sub = subchannel(&topic);
                        if let Some(owner) = registry.get(&sub) {
                            tracing::error!(target: P2P, topic = %topic, %owner, sub, "subchannel collision; refusing to share it");
                            continue;
                        }
                        let registered = if is_subnet_topic(&topic) {
                            data_handle.register(sub).await
                        } else {
                            control_handle.register(sub).await
                        };
                        match registered {
                            Ok((_, mut rx)) => {
                                registry.insert(sub, topic.clone());
                                let shared = shared.clone();
                                let feeds = feeds.clone();
                                let name = topic.clone();
                                pumps.insert(topic, tokio::spawn(async move {
                                    while let Ok((peer, buf)) = rx.recv().await {
                                        let from = keys::from_cw(&peer);
                                        shared.note_seen(from);
                                        // Links are authenticated, so this only
                                        // adds roster admission on bound topics.
                                        if let Some(roster) = shared.policy.lock().unwrap().get(&name) {
                                            if !roster.contains(&from) {
                                                tracing::debug!(target: P2P, topic = %name, %from, "inbound dropped: publisher not in topic roster");
                                                continue;
                                            }
                                        }
                                        let payload = buf.as_ref().to_vec();
                                        feeds.fanout(&name, from, &payload);
                                        // Send failure just means no local
                                        // listener; keep the subchannel for a
                                        // later subscribe.
                                        let _ = tx.send(Inbound { from, payload });
                                    }
                                }));
                            }
                            Err(e) => tracing::warn!(target: P2P, topic = %topic, error = %e, "subchannel registration failed"),
                        }
                    }
                    Cmd::Unsubscribe(topic) => {
                        // Await the abort: deregistration only happens when the
                        // task is actually dropped, and re-registering a
                        // subchannel before that fails and leaves no pump.
                        if let Some(h) = pumps.remove(&topic) {
                            h.abort();
                            let _ = h.await;
                            registry.remove(&subchannel(&topic));
                        }
                    }
                    Cmd::Publish { topic, bytes } => {
                        // Stream clients see this node's own output too; the
                        // backbone never loops a publish back to its publisher.
                        feeds.fanout(&topic, me, &bytes);
                        let sub = subchannel(&topic);
                        if is_subnet_topic(&topic) {
                            data_global.send(sub, Recipients::All, bytes, false);
                        } else {
                            control_global.send(sub, Recipients::All, bytes, true);
                        }
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

            // A client's submission, relayed onto the backbone on its behalf.
            forward = stream_pub_rx.recv() => {
                let Some((topic, bytes)) = forward else { continue };
                let sub = subchannel(&topic);
                if is_subnet_topic(&topic) {
                    data_global.send(sub, Recipients::All, bytes, false);
                } else {
                    control_global.send(sub, Recipients::All, bytes, true);
                }
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
