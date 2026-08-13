//! [`Transport`] for a client that never joins the backbone.
//!
//! A client dials nodes over commonware-stream. Bootstrap servers carry feeds,
//! config pulls, and registrations; subnet data goes on a direct connection to
//! the relay it is addressed to, dialed from the adopted config's
//! `relay_client_addrs`. Sending is best-effort in the same way the backbone
//! is — a dropped connection loses the frame, and the caller's next round
//! re-sends.

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

use crate::config::SubnetId;
use crate::identity::{Identity, Pubkey};
use crate::log_target::P2P;
use crate::transport::{Inbound, NetView, Subscription, Topic, Transport, MAX_TRANSMIT_SIZE};

use super::keys;
use super::stream_wire::StreamMsg;

const TOPIC_CAPACITY: usize = 1024;
const CONFIG_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Clone)]
pub struct StreamClientConfig {
    /// Bootstrap nodes to dial. Every one is tried; the first to answer serves
    /// a request.
    pub servers: Vec<(Pubkey, SocketAddr)>,
}

enum Cmd {
    Subscribe(Topic),
    Publish(Topic, Vec<u8>),
    Send {
        to: Pubkey,
        subnet: SubnetId,
        bytes: Vec<u8>,
    },
    /// Adopted config's relay dial addresses.
    Relays(Vec<(Pubkey, String)>),
    FetchConfig(oneshot::Sender<Option<Vec<u8>>>),
}

pub struct StreamClientNetwork {
    cmds: mpsc::UnboundedSender<Cmd>,
    topics: Mutex<HashMap<Topic, broadcast::Sender<Inbound>>>,
    /// A pure client is never a send addressee; inboxes exist so `inbox` has
    /// something to return, and stay silent.
    inboxes: Mutex<HashMap<SubnetId, broadcast::Sender<Inbound>>>,
    identity: Pubkey,
}

impl StreamClientNetwork {
    pub fn start(identity: &Identity, cfg: StreamClientConfig) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let signer = identity.to_commonware_signer();
        let me = identity.pubkey();
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let net = Arc::new(StreamClientNetwork {
            cmds: cmd_tx,
            topics: Mutex::new(HashMap::new()),
            inboxes: Mutex::new(HashMap::new()),
            identity: me,
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
                    .start(|context| run(context, signer, cfg, cmd_rx, frame_tx));
            })
            .expect("spawn commonware client thread");
        net
    }

    fn send_cmd(&self, cmd: Cmd) {
        if self.cmds.send(cmd).is_err() {
            tracing::warn!(target: P2P, "stream client thread is gone; command dropped");
        }
    }
}

#[async_trait]
impl Transport for StreamClientNetwork {
    async fn subscribe(&self, topic: Topic) -> Subscription {
        let mut topics = self.topics.lock().unwrap();
        if let Some(tx) = topics.get(&topic) {
            return Subscription::from_broadcast_receiver(tx.subscribe(), topic.to_string());
        }
        let (tx, rx) = broadcast::channel(TOPIC_CAPACITY);
        topics.insert(topic, tx);
        self.send_cmd(Cmd::Subscribe(topic));
        Subscription::from_broadcast_receiver(rx, topic.to_string())
    }

    async fn publish(&self, topic: Topic, bytes: Vec<u8>) {
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, %topic, len = bytes.len(), "publish dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(&topic.to_string(), &self.identity, &bytes);
        match topic {
            // Registrations, and a Noop subnet's broadcast (its whole protocol
            // rides the open topic); the node refuses anything bound.
            Topic::Registration | Topic::Broadcast(_) => {
                self.send_cmd(Cmd::Publish(topic, bytes))
            }
            // Every other topic originates on the backbone; a client has
            // nothing to say on them.
            _ => {
                tracing::warn!(target: P2P, %topic, "client-plane publish on a backbone topic, dropped")
            }
        }
    }

    async fn send(&self, to: Pubkey, subnet: SubnetId, bytes: Vec<u8>) {
        if bytes.len() > MAX_TRANSMIT_SIZE {
            tracing::warn!(target: P2P, subnet, len = bytes.len(), "send dropped: over the transmit limit");
            return;
        }
        crate::wire_debug::trace(&format!("subnet/{subnet}/inbox"), &self.identity, &bytes);
        self.send_cmd(Cmd::Send { to, subnet, bytes });
    }

    async fn inbox(&self, subnet: SubnetId) -> Subscription {
        let mut inboxes = self.inboxes.lock().unwrap();
        let tx = inboxes
            .entry(subnet)
            .or_insert_with(|| broadcast::channel(1).0);
        Subscription::from_broadcast_receiver(tx.subscribe(), format!("subnet/{subnet}/inbox"))
    }

    fn apply(&self, view: NetView) {
        self.send_cmd(Cmd::Relays(view.relay_client_addrs));
    }

    /// A client serves no config; only nodes answer pulls.
    fn serve_config(&self, _bytes: Vec<u8>) {}

    fn local_pubkey(&self) -> Pubkey {
        self.identity
    }

    async fn fetch_config(&self) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.send_cmd(Cmd::FetchConfig(tx));
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

/// One connection's outbound half, plus whether it is currently up — queueing
/// a submission onto a dead connection loses it silently.
struct Conn {
    peer: Pubkey,
    tx: mpsc::UnboundedSender<StreamMsg>,
    up: Arc<std::sync::atomic::AtomicBool>,
}

type Frames = mpsc::UnboundedSender<(Topic, Pubkey, Vec<u8>)>;
/// Fetches awaiting any server's config; all of them are satisfied by one reply.
type PendingFetches = Arc<Mutex<Vec<oneshot::Sender<Option<Vec<u8>>>>>>;

fn spawn_conn(
    context: &cw_tokio::Context,
    signer: &ed25519::PrivateKey,
    pk: Pubkey,
    addr: SocketAddr,
    frames: &Frames,
    pending: &PendingFetches,
) -> Option<Conn> {
    let peer = keys::to_cw(&pk)?;
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    context.child("conn").spawn({
        let signer = signer.clone();
        let frames = frames.clone();
        let pending = pending.clone();
        let up = up.clone();
        move |ctx| async move {
            connection(ctx, signer, peer, addr, out_rx, frames, pending, up).await;
        }
    });
    Some(Conn {
        peer: pk,
        tx: out_tx,
        up,
    })
}

async fn run(
    context: cw_tokio::Context,
    signer: ed25519::PrivateKey,
    cfg: StreamClientConfig,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    frames: Frames,
) {
    let pending: PendingFetches = Arc::new(Mutex::new(Vec::new()));
    let mut servers: Vec<Conn> = Vec::new();
    // Relay data connections, keyed by relay; re-dialed from every adopted config.
    let mut relays: HashMap<Pubkey, Conn> = HashMap::new();
    let mut subscribed: Vec<Topic> = Vec::new();

    for (pk, addr) in &cfg.servers {
        if let Some(conn) = spawn_conn(&context, &signer, *pk, *addr, &frames, &pending) {
            servers.push(conn);
        }
    }
    if servers.is_empty() {
        tracing::warn!(target: P2P, "stream client has no usable servers");
    }

    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Subscribe(topic) => {
                if subscribed.contains(&topic) {
                    continue;
                }
                subscribed.push(topic);
                let msg = StreamMsg::FeedSubscribe {
                    topics: vec![topic],
                };
                for c in &servers {
                    let _ = c.tx.send(msg.clone());
                }
            }
            Cmd::Publish(topic, bytes) => {
                // One server suffices: a registration is forwarded to every
                // committee member and re-announced anyway; an open-topic
                // submission is republished network-wide. Prefer a connection
                // that is up, but queue on the first if none is yet — it
                // drains once the dial completes.
                let msg = if topic == Topic::Registration {
                    StreamMsg::Register(bytes)
                } else {
                    StreamMsg::Submit {
                        topic,
                        payload: bytes,
                    }
                };
                let target = servers
                    .iter()
                    .find(|c| c.up.load(std::sync::atomic::Ordering::Relaxed))
                    .or_else(|| servers.first());
                if let Some(c) = target {
                    let _ = c.tx.send(msg);
                }
            }
            Cmd::Send { to, subnet, bytes } => {
                // The addressee, on its data connection or as a bootstrap server.
                let conn = relays
                    .get(&to)
                    .or_else(|| servers.iter().find(|c| c.peer == to));
                match conn {
                    Some(c) => {
                        let _ = c.tx.send(StreamMsg::Data {
                            subnet,
                            payload: bytes,
                        });
                    }
                    None => {
                        tracing::warn!(target: P2P, to = %to, subnet, "no connection to the addressed relay; frame dropped")
                    }
                }
            }
            Cmd::Relays(addrs) => {
                let named: HashMap<Pubkey, String> = addrs.into_iter().collect();
                relays.retain(|pk, _| named.contains_key(pk));
                for (pk, addr) in named {
                    if relays.contains_key(&pk) || servers.iter().any(|c| c.peer == pk) {
                        continue;
                    }
                    let Ok(addr) = addr.parse::<SocketAddr>() else {
                        tracing::warn!(target: P2P, relay = %pk, %addr, "unparseable relay client address");
                        continue;
                    };
                    if let Some(conn) = spawn_conn(&context, &signer, pk, addr, &frames, &pending)
                    {
                        relays.insert(pk, conn);
                    }
                }
            }
            Cmd::FetchConfig(responder) => {
                if servers.is_empty() {
                    let _ = responder.send(None);
                    continue;
                }
                pending.lock().unwrap().push(responder);
                for c in &servers {
                    let _ = c.tx.send(StreamMsg::ConfigReq);
                }
            }
        }
    }
    // Let the connection tasks release their contexts before this thread drops
    // the runtime out from under them.
    drop(servers);
    drop(relays);
    let _ = context
        .child("shutdown")
        .stop(0, Some(std::time::Duration::from_secs(5)))
        .await;
}

/// Hold one connection open, redialing on loss. Re-sends the current feed
/// subscriptions after every reconnect, since the server forgets them.
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
    let mut subscriptions: Vec<Topic> = Vec::new();
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
            let msg = StreamMsg::FeedSubscribe { topics: vec![*t] };
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
                            subscriptions.extend(topics.iter().copied());
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
