//! Client-facing stream listener.
//!
//! Clients are permissionless and dynamic, so they never enter a tracked peer
//! set. They dial here instead: the handshake authenticates the client key and
//! screens it, then the node forwards what the client submits onto the backbone
//! and feeds subscribed topics back down the same connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use commonware_cryptography::ed25519;
use commonware_runtime::{tokio as cw_tokio, Listener as _, Network as _, Spawner as _, Supervisor as _};
use commonware_stream::encrypted;
use tokio::sync::mpsc;

use crate::identity::Pubkey;
use crate::log_target::P2P;
use crate::session::GoodClients;

use super::keys;
use super::net::Shared;
use super::stream_wire::StreamMsg;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Frames a client can fall behind by before its feed is dropped.
const FEED_BACKLOG: usize = 512;

/// Per-topic stream subscribers. Cloned into the network loop so published and
/// relayed frames both reach clients.
#[derive(Clone, Default)]
pub(crate) struct Feeds {
    inner: Arc<Mutex<HashMap<String, Vec<mpsc::Sender<StreamMsg>>>>>,
}

impl Feeds {
    fn add(&self, topics: Vec<String>, tx: mpsc::Sender<StreamMsg>) {
        let mut map = self.inner.lock().unwrap();
        for t in topics {
            map.entry(t).or_default().push(tx.clone());
        }
    }

    /// Offer a frame to every client subscribed to `topic`, dropping closed and
    /// lagging feeds.
    pub(crate) fn fanout(&self, topic: &str, from: Pubkey, payload: &[u8]) {
        let mut map = self.inner.lock().unwrap();
        let Some(subs) = map.get_mut(topic) else {
            return;
        };
        subs.retain(|tx| {
            let frame = StreamMsg::FeedFrame {
                topic: topic.to_string(),
                from,
                payload: payload.to_vec(),
            };
            !matches!(tx.try_send(frame), Err(mpsc::error::TrySendError::Closed(_)))
        });
        if subs.is_empty() {
            map.remove(topic);
        }
    }
}

/// What the listener may do on a client's behalf.
pub(crate) struct ServerHooks {
    pub(crate) shared: Arc<Shared>,
    pub(crate) feeds: Feeds,
    /// Republish onto the backbone: `(topic, bytes)`.
    pub(crate) publish: mpsc::UnboundedSender<(String, Vec<u8>)>,
    pub(crate) good_clients: GoodClients,
}

/// Topics a client may submit on.
///
/// A roster-bound topic is closed to clients: forwarding puts the frame on the
/// wire under this node's key, which is in the roster, so the receiving relays'
/// admission check would pass and the roster would mean nothing. The policy
/// already marks exactly the topics clients are meant to reach (subnet ingress,
/// aggregator groups, and a Noop subnet's broadcast) by leaving them unbound.
fn submit_allowed(topic: &str, shared: &Shared) -> bool {
    if topic == crate::governance::TOPIC_REGISTRATION {
        return true;
    }
    topic.starts_with("anymone/subnet/")
        && !topic.ends_with("/shares")
        && !shared.topic_is_bound(topic)
}

pub(crate) fn spawn(
    context: cw_tokio::Context,
    signer: ed25519::PrivateKey,
    listen: SocketAddr,
    hooks: Arc<ServerHooks>,
) {
    context.spawn(move |context| async move {
        let mut listener = match context.bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(target: P2P, %listen, error = ?e, "stream listener failed to bind");
                return;
            }
        };
        tracing::info!(target: P2P, %listen, "stream listener up");
        // Without this the accept loop outlives the runtime and the thread tears
        // down with the reactor still under it.
        let mut stop = context.stopped();
        loop {
            let accepted = tokio::select! {
                _ = &mut stop => break,
                conn = listener.accept() => conn,
            };
            let (peer_addr, sink, stream) = match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!(target: P2P, error = ?e, "stream accept failed");
                    continue;
                }
            };
            let cfg = encrypted::Config {
                signing_key: signer.clone(),
                namespace: b"anymone-stream-v0".to_vec(),
                max_message_size: crate::transport::MAX_TRANSMIT_SIZE as u32,
                synchrony_bound: std::time::Duration::from_secs(5),
                max_handshake_age: std::time::Duration::from_secs(10),
                handshake_timeout: HANDSHAKE_TIMEOUT,
            };
            let hooks = hooks.clone();
            context.child("session").spawn(move |ctx| async move {
                let good = hooks.good_clients.clone();
                let accepted = encrypted::listen(
                    ctx,
                    move |pk: ed25519::PublicKey| async move { good.allows(&keys::from_cw(&pk)) },
                    cfg,
                    stream,
                    sink,
                )
                .await;
                match accepted {
                    Ok((peer, tx, rx)) => {
                        let client = keys::from_cw(&peer);
                        tracing::debug!(target: P2P, %client, %peer_addr, "stream client accepted");
                        session(hooks, client, tx, rx).await;
                        tracing::debug!(target: P2P, %client, "stream client gone");
                    }
                    // A refused client is the good-clients screen working.
                    Err(e) => tracing::debug!(target: P2P, %peer_addr, error = ?e, "stream handshake refused"),
                }
            });
        }
    });
}

async fn session<S, R>(
    hooks: Arc<ServerHooks>,
    client: Pubkey,
    mut tx: encrypted::Sender<S>,
    mut rx: encrypted::Receiver<R>,
) where
    S: commonware_runtime::Sink,
    R: commonware_runtime::Stream,
{
    let (feed_tx, mut feed_rx) = mpsc::channel::<StreamMsg>(FEED_BACKLOG);
    // Encrypted sends and receives must never be cancelled — a dropped future
    // may have half-written a frame, which poisons the stream — so writing gets
    // its own task and neither side is ever polled inside a `select!`.
    let writer = tokio::spawn(async move {
        while let Some(frame) = feed_rx.recv().await {
            if tx.send(frame.encode()).await.is_err() {
                break;
            }
        }
    });

    loop {
        let bufs = match rx.recv().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(target: P2P, %client, error = ?e, "stream session recv ended");
                break;
            }
        };
        let Some(msg) = StreamMsg::decode(bufs.coalesce().as_ref()) else {
            tracing::debug!(target: P2P, %client, "undecodable stream message");
            continue;
        };
        match msg {
            StreamMsg::ConfigReq => {
                let resp = StreamMsg::ConfigResp(hooks.shared.served_config());
                if feed_tx.send(resp).await.is_err() {
                    break;
                }
            }
            StreamMsg::Register(bytes) => {
                match bincode::deserialize::<crate::scheduling::Registration>(&bytes) {
                    Ok(reg) if reg.verify() => {
                        let topic = crate::governance::TOPIC_REGISTRATION.to_string();
                        hooks.shared.deliver_local(&topic, client, bytes.clone());
                        let _ = hooks.publish.send((topic, bytes));
                    }
                    _ => tracing::debug!(target: P2P, %client, "unverifiable registration over stream, ignored"),
                }
            }
            StreamMsg::Submit { topic, payload } => {
                if !submit_allowed(&topic, &hooks.shared) {
                    tracing::debug!(target: P2P, %client, %topic, "client may not submit on this topic");
                    continue;
                }
                // `from` is the authenticated stream peer, so the local relay
                // session sees the real client, not this node.
                hooks.shared.deliver_local(&topic, client, payload.clone());
                let _ = hooks.publish.send((topic, payload));
            }
            StreamMsg::FeedSubscribe { topics } => {
                hooks.feeds.add(topics, feed_tx.clone());
            }
            // Server-to-client only.
            StreamMsg::ConfigResp(_) | StreamMsg::FeedFrame { .. } => {
                tracing::debug!(target: P2P, %client, "client sent a server-only message");
            }
        }
    }
    writer.abort();
}
