//! [`Transport`] for a client that never joins the backbone.
//!
//! A client dials nodes over commonware-stream: submissions go up the
//! connection, subscribed topics come back down it. Publishing is best-effort in
//! the same way the backbone is — a dropped connection loses the frame, and the
//! caller's next round re-sends.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use commonware_cryptography::ed25519;
use commonware_runtime::{
    tokio as cw_tokio, Network as _, Runner as _, Spawner as _, Supervisor as _,
};
use commonware_stream::encrypted;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::identity::{Identity, Pubkey};
use crate::log_target::P2P;
use crate::transport::{Inbound, Subscription, Transport, MAX_TRANSMIT_SIZE};

use super::keys;
use super::stream_wire::StreamMsg;

const TOPIC_CAPACITY: usize = 1024;
const CONFIG_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Clone)]
pub struct StreamClientConfig {
    /// Nodes to dial. Every one is tried; the first to answer serves a request.
    pub servers: Vec<(Pubkey, SocketAddr)>,
}

enum Cmd {
    Subscribe(String),
    Publish { topic: String, bytes: Vec<u8> },
    FetchConfig(oneshot::Sender<Option<Vec<u8>>>),
}

pub struct StreamClientNetwork {
    cmds: mpsc::UnboundedSender<Cmd>,
    topics: Mutex<HashMap<String, broadcast::Sender<Inbound>>>,
    identity: Pubkey,
    targets: Arc<Mutex<crate::transport::PublishTargets>>,
}

impl StreamClientNetwork {
    pub fn start(identity: &Identity, cfg: StreamClientConfig) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let signer = identity.to_commonware_signer();
        let me = identity.pubkey();
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let targets: Arc<Mutex<crate::transport::PublishTargets>> = Arc::default();
        let net = Arc::new(StreamClientNetwork {
            cmds: cmd_tx,
            topics: Mutex::new(HashMap::new()),
            identity: me,
            targets: targets.clone(),
        });
        // Frames arrive on the commonware thread and fan out on this one.
        let sink = net.clone();
        tokio::spawn(async move {
            let mut frame_rx = frame_rx;
            while let Some((topic, from, payload)) = frame_rx.recv().await {
                if let Some(tx) = sink.topics.lock().unwrap().get(&topic) {
                    let _ = tx.send(Inbound { from, payload });
                }
            }
        });
        std::thread::Builder::new()
            .name("commonware-client".into())
            .spawn(move || {
                let dir = std::env::temp_dir()
                    .join(format!("anymone-cwc-{}", hex::encode(&me.0[..8])));
                let rt = cw_tokio::Config::default().with_storage_directory(dir);
                cw_tokio::Runner::new(rt)
                    .start(|context| run(context, signer, cfg, cmd_rx, frame_tx, targets));
            })
            .expect("spawn commonware client thread");
        net
    }

    fn send(&self, cmd: Cmd) {
        if self.cmds.send(cmd).is_err() {
            tracing::warn!(target: P2P, "stream client thread is gone; command dropped");
        }
    }
}

#[async_trait]
impl Transport for StreamClientNetwork {
    async fn subscribe(&self, topic: &str) -> Subscription {
        let mut topics = self.topics.lock().unwrap();
        if let Some(tx) = topics.get(topic) {
            return Subscription::from_broadcast_receiver(tx.subscribe(), topic.to_string());
        }
        let (tx, rx) = broadcast::channel(TOPIC_CAPACITY);
        topics.insert(topic.to_string(), tx);
        self.send(Cmd::Subscribe(topic.to_string()));
        Subscription::from_broadcast_receiver(rx, topic.to_string())
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, topic, len = bytes.len(), "publish dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(topic, &self.identity, &bytes);
        self.send(Cmd::Publish {
            topic: topic.to_string(),
            bytes,
        });
    }

    fn set_publish_targets(&self, targets: crate::transport::PublishTargets) {
        *self.targets.lock().unwrap() = targets;
    }

    /// A client serves no config; only nodes answer pulls.
    fn serve_config(&self, _bytes: Vec<u8>) {}

    fn local_pubkey(&self) -> Pubkey {
        self.identity
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
}

/// Mint virtual clients as fresh stream connections to the same servers. Each
/// gets an unpersisted identity, so nothing marks it as belonging to this
/// process — and it costs a connection, not a whole node.
pub fn stream_client_spawner(
    cfg: StreamClientConfig,
    governance: crate::governance::GovernanceBootstrap,
) -> crate::client_pool::SpawnClient {
    Arc::new(move || {
        let cfg = cfg.clone();
        let governance = governance.clone();
        Box::pin(async move {
            let identity = Identity::generate();
            let net = StreamClientNetwork::start(&identity, cfg);
            match crate::runtime::Anymone::start(identity, net, governance).await {
                Ok(anymone) => Some(anymone),
                Err(e) => {
                    tracing::warn!(target: P2P, error = %e, "virtual client: anymone start failed");
                    None
                }
            }
        })
    })
}

/// One server connection's outbound half, plus whether it is currently up —
/// queueing a submission onto a dead connection loses it silently.
struct Conn {
    peer: Pubkey,
    tx: mpsc::UnboundedSender<StreamMsg>,
    up: Arc<std::sync::atomic::AtomicBool>,
}

type Frames = mpsc::UnboundedSender<(String, Pubkey, Vec<u8>)>;
/// Fetches awaiting any server's config; all of them are satisfied by one reply.
type PendingFetches = Arc<Mutex<Vec<oneshot::Sender<Option<Vec<u8>>>>>>;

async fn run(
    context: cw_tokio::Context,
    signer: ed25519::PrivateKey,
    cfg: StreamClientConfig,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    frames: Frames,
    targets: Arc<Mutex<crate::transport::PublishTargets>>,
) {
    let mut conns: Vec<Conn> = Vec::new();
    let mut subscribed: Vec<String> = Vec::new();
    let pending: PendingFetches = Arc::new(Mutex::new(Vec::new()));

    for (pk, addr) in &cfg.servers {
        let Some(peer) = keys::to_cw(pk) else { continue };
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        conns.push(Conn {
            peer: *pk,
            tx: out_tx,
            up: up.clone(),
        });
        context.child("conn").spawn({
            let signer = signer.clone();
            let frames = frames.clone();
            let pending = pending.clone();
            let addr = *addr;
            move |ctx| async move {
                connection(ctx, signer, peer, addr, out_rx, frames, pending, up).await;
            }
        });
    }
    if conns.is_empty() {
        tracing::warn!(target: P2P, "stream client has no usable servers");
    }

    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Subscribe(topic) => {
                if subscribed.contains(&topic) {
                    continue;
                }
                subscribed.push(topic.clone());
                let msg = StreamMsg::FeedSubscribe {
                    topics: vec![topic],
                };
                for c in &conns {
                    let _ = c.tx.send(msg.clone());
                }
            }
            Cmd::Publish { topic, bytes } => {
                let named_topic = topic.clone();
                let msg = if topic == crate::governance::TOPIC_REGISTRATION {
                    StreamMsg::Register(bytes)
                } else {
                    StreamMsg::Submit {
                        topic,
                        payload: bytes,
                    }
                };
                let named = targets.lock().unwrap().get(&named_topic).cloned();
                if let Some(peers) = named {
                    for c in conns.iter().filter(|c| peers.contains(&c.peer)) {
                        let _ = c.tx.send(msg.clone());
                    }
                    continue;
                }
                // Unnamed topics ride one server and gossip. Prefer a connection
                // that is up, but queue on the first if none is yet — it drains
                // once the dial completes.
                let target = conns
                    .iter()
                    .find(|c| c.up.load(std::sync::atomic::Ordering::Relaxed))
                    .or_else(|| conns.first());
                if let Some(c) = target {
                    let _ = c.tx.send(msg);
                }
            }
            Cmd::FetchConfig(responder) => {
                if conns.is_empty() {
                    let _ = responder.send(None);
                    continue;
                }
                pending.lock().unwrap().push(responder);
                for c in &conns {
                    let _ = c.tx.send(StreamMsg::ConfigReq);
                }
            }
        }
    }
    // Let the connection tasks release their contexts before this thread drops
    // the runtime out from under them.
    drop(conns);
    let _ = context
        .child("shutdown")
        .stop(0, Some(std::time::Duration::from_secs(5)))
        .await;
}

/// Hold one server connection open, redialing on loss. Re-sends the current
/// feed subscriptions after every reconnect, since the server forgets them.
#[allow(clippy::too_many_arguments)]
async fn connection(
    context: cw_tokio::Context,
    signer: ed25519::PrivateKey,
    peer: ed25519::PublicKey,
    addr: SocketAddr,
    mut out_rx: mpsc::UnboundedReceiver<StreamMsg>,
    frames: Frames,
    pending: PendingFetches,
    up: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut subscriptions: Vec<String> = Vec::new();
    // Without this the redial loop outlives the runtime it dials on.
    let mut stop = context.stopped();
    loop {
        let cfg = encrypted::Config {
            signing_key: signer.clone(),
            namespace: b"anymone-stream-v0".to_vec(),
            max_message_size: MAX_TRANSMIT_SIZE as u32,
            synchrony_bound: std::time::Duration::from_secs(5),
            max_handshake_age: std::time::Duration::from_secs(10),
            handshake_timeout: std::time::Duration::from_secs(5),
        };
        let dialed = match context.dial(addr).await {
            // `dial` takes stream before sink, the reverse of the runtime's pair.
            Ok((sink, stream)) => {
                encrypted::dial(context.child("handshake"), cfg, peer.clone(), stream, sink)
                    .await
                    .ok()
            }
            Err(_) => None,
        };
        let Some((mut tx, mut rx)) = dialed else {
            tokio::time::sleep(RECONNECT_BACKOFF).await;
            continue;
        };
        up.store(true, std::sync::atomic::Ordering::Relaxed);
        // Reading gets its own task: a cancelled encrypted recv may have
        // half-consumed a frame, which poisons the stream, so it must never sit
        // in a `select!`.
        let (dead_tx, mut dead_rx) = oneshot::channel();
        let reader = tokio::spawn({
            let frames = frames.clone();
            let pending = pending.clone();
            async move {
                loop {
                    let bufs = match rx.recv().await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::debug!(target: P2P, error = ?e, "stream client recv ended");
                            break;
                        }
                    };
                    match StreamMsg::decode(bufs.coalesce().as_ref()) {
                        Some(StreamMsg::FeedFrame {
                            topic,
                            from,
                            payload,
                        }) => {
                            let _ = frames.send((topic, from, payload));
                        }
                        // Requests carry no id, so match by satisfying all of
                        // them: any served config answers every outstanding
                        // fetch, and popping one would answer the wrong caller.
                        Some(StreamMsg::ConfigResp(Some(bytes))) => {
                            for r in pending.lock().unwrap().drain(..) {
                                let _ = r.send(Some(bytes.clone()));
                            }
                        }
                        // A server without a config yet; another may have one.
                        Some(StreamMsg::ConfigResp(None)) => {}
                        _ => tracing::debug!(target: P2P, "unexpected stream message from a server"),
                    }
                }
                let _ = dead_tx.send(());
            }
        });

        // The server has no memory of a previous connection.
        let mut resent = true;
        for t in &subscriptions {
            let msg = StreamMsg::FeedSubscribe {
                topics: vec![t.clone()],
            };
            if tx.send(msg.encode()).await.is_err() {
                resent = false;
                break;
            }
        }
        if resent {
            loop {
                // Only the plain channels are cancelled here; the send below is
                // awaited to completion inside the arm.
                tokio::select! {
                    outbound = out_rx.recv() => {
                        let Some(msg) = outbound else {
                            reader.abort();
                            return;
                        };
                        if let StreamMsg::FeedSubscribe { topics } = &msg {
                            subscriptions.extend(topics.iter().cloned());
                        }
                        if tx.send(msg.encode()).await.is_err() {
                            break;
                        }
                    }
                    _ = &mut dead_rx => break,
                    _ = &mut stop => {
                        up.store(false, std::sync::atomic::Ordering::Relaxed);
                        reader.abort();
                        return;
                    }
                }
            }
        }
        up.store(false, std::sync::atomic::Ordering::Relaxed);
        reader.abort();
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}
