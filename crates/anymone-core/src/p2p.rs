//! libp2p-backed [`Transport`].
//!
//! Layout: a background swarm task owns the libp2p `Swarm` and pumps events.
//! [`Libp2pNetwork`] is the front-end: it holds a command channel and a
//! per-topic `broadcast::Sender`. `subscribe` returns a fresh receiver from
//! that sender; `publish` only forwards to the swarm task to broadcast on the
//! network — gossipsub never loops a publish back to its own publisher,
//! matching [`Transport`](crate::transport::Transport)'s documented contract.
//! Components that must observe their own output feed it back in-process at
//! emit time (see `committee.rs::emit`, `runtime.rs::publish_and_loop_back`).
//!
//! Authentication: we run gossipsub with `MessageAuthenticity::Signed`, so
//! every message carries the publisher's libp2p key. We reverse that into
//! our `Pubkey` newtype using `PeerId::extract_public_key`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{
    self, IdentTopic, MessageAcceptance, MessageAuthenticity, PeerScoreParams, PeerScoreThresholds,
    TopicScoreParams,
};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, kad, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use libp2p_identity as libp2p_id;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

/// Config-pull request/response (`/anymone/config/1`): a joining node asks a
/// connected peer for the latest signed config instead of waiting for a push.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigRequest;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigResponse(Option<Vec<u8>>);

use crate::identity::{Identity, Pubkey};
use crate::transport::{Inbound, Subscription, Transport};

/// gossipsub per-message ceiling; the committee sizes subnets under it (`scheduler_core::MAX_SUBNET_WIRE`).
pub const MAX_TRANSMIT_SIZE: usize = 16 * 1024 * 1024;

/// Cap on buffered publishes per topic while its mesh hasn't grafted yet; a
/// stalled topic drops its oldest buffered publish rather than growing forever.
const MAX_PENDING_PER_TOPIC: usize = 256;

/// Bounds the command channel so a fast publisher backpressures instead of growing memory unboundedly.
const CMD_CHANNEL_CAPACITY: usize = 1024;

/// Bootstrap parameters for [`Libp2pNetwork::start`].
#[derive(Debug, Clone)]
pub struct Libp2pConfig {
    pub listen: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
}

#[derive(Debug, Error)]
pub enum Libp2pError {
    #[error("swarm build: {0}")]
    Build(String),
    #[error("listen: {0}")]
    Listen(#[from] libp2p::TransportError<std::io::Error>),
    #[error("dial: {0}")]
    Dial(#[from] libp2p::swarm::DialError),
}

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    config_rr: request_response::cbor::Behaviour<ConfigRequest, ConfigResponse>,
}

enum Cmd {
    Subscribe(String),
    Unsubscribe(String),
    Publish(String, Vec<u8>),
    /// Dial and mark as gossipsub explicit peers, independent of kademlia adjacency.
    EnsurePeers(Vec<PeerId>),
    /// Pull the served config from `peer`; reply carries its answer (or `None`).
    FetchConfig {
        peer: PeerId,
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// Debug observability: snapshot gossipsub's per-topic subscriber + mesh sets.
    GossipSnapshot(tokio::sync::oneshot::Sender<Vec<TopicGossip>>),
    Shutdown,
}

/// Per-topic gossipsub view for debug observability (peer ids as strings).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TopicGossip {
    pub topic: String,
    pub subscribers: Vec<String>,
    pub mesh: Vec<String>,
}

pub struct Libp2pNetwork {
    cmd_tx: mpsc::Sender<Cmd>,
    topics: Arc<Mutex<HashMap<String, broadcast::Sender<Inbound>>>>,
    peers: Arc<Mutex<HashSet<PeerId>>>,
    /// Signed config this node answers config-pull requests with.
    served_config: Arc<Mutex<Option<Vec<u8>>>>,
    policy: Arc<Mutex<crate::transport::TopicPolicy>>,
    local_pubkey: Pubkey,
    local_peer_id: PeerId,
    _task: JoinHandle<()>,
}

impl Libp2pNetwork {
    /// Bring up a libp2p swarm bound to `identity`, listen on the given
    /// multiaddr, and dial each bootstrap peer.
    pub async fn start(
        identity: &Identity,
        config: Libp2pConfig,
    ) -> Result<Arc<Libp2pNetwork>, Libp2pError> {
        let kp = identity.to_libp2p_keypair();
        let local_peer_id = PeerId::from(kp.public());
        let local_pubkey = identity.pubkey();

        let mut swarm: Swarm<Behaviour> = libp2p::SwarmBuilder::with_existing_identity(kp.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| Libp2pError::Build(format!("tcp: {e}")))?
            .with_dns()
            .map_err(|e| Libp2pError::Build(format!("dns: {e}")))?
            .with_behaviour(build_behaviour)
            .map_err(|e| Libp2pError::Build(format!("behaviour: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm.listen_on(config.listen.clone())?;
        for peer in &config.bootstrap_peers {
            // Seed Kademlia with the bootnode so routing queries have somewhere
            // to start; the address is the same one we dial.
            if let Some((peer_id, addr)) = split_peer_addr(peer) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
            // dial errors here aren't fatal — peer may not be up yet.
            let _ = swarm.dial(peer.clone());
        }
        if !config.bootstrap_peers.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let topics: Arc<Mutex<HashMap<String, broadcast::Sender<Inbound>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let peers: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));
        let served_config: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let policy: Arc<Mutex<crate::transport::TopicPolicy>> =
            Arc::new(Mutex::new(HashMap::new()));

        let task = tokio::spawn(swarm_loop(
            swarm,
            cmd_rx,
            topics.clone(),
            peers.clone(),
            served_config.clone(),
            policy.clone(),
        ));

        Ok(Arc::new(Libp2pNetwork {
            cmd_tx,
            topics,
            peers,
            served_config,
            policy,
            local_pubkey,
            local_peer_id,
            _task: task,
        }))
    }

    pub fn local_pubkey(&self) -> Pubkey {
        self.local_pubkey
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Pubkeys of currently-connected peers
    pub fn peer_snapshot(&self) -> Vec<Pubkey> {
        self.peers
            .lock()
            .unwrap()
            .iter()
            .filter_map(peer_id_to_pubkey)
            .collect()
    }

    /// Debug observability: gossipsub's current per-topic subscriber + mesh sets.
    pub async fn gossip_snapshot(&self) -> Vec<TopicGossip> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.cmd_tx.send(Cmd::GossipSnapshot(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }
}

#[async_trait]
impl Transport for Libp2pNetwork {
    async fn subscribe(&self, topic: &str) -> Subscription {
        let rx = {
            let mut topics = self.topics.lock().unwrap();
            topics
                .entry(topic.to_string())
                .or_insert_with(|| broadcast::channel(1024).0)
                .subscribe()
        };
        let _ = self.cmd_tx.send(Cmd::Subscribe(topic.to_string())).await;
        Subscription::from_broadcast_receiver(rx, topic.to_string())
    }

    async fn unsubscribe(&self, topic: &str) {
        // Other components (e.g. the committee's subnet observers) may hold
        // their own `Subscription`s on this topic via the same transport —
        // only actually leave once no local receiver remains.
        let no_listeners = {
            let mut topics = self.topics.lock().unwrap();
            match topics.get(topic) {
                Some(tx) if tx.receiver_count() > 0 => false,
                _ => {
                    topics.remove(topic);
                    true
                }
            }
        };
        if no_listeners {
            let _ = self.cmd_tx.send(Cmd::Unsubscribe(topic.to_string())).await;
        }
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
        crate::wire_debug::trace(topic, &self.local_pubkey, &bytes);
        let _ = self
            .cmd_tx
            .send(Cmd::Publish(topic.to_string(), bytes))
            .await;
    }

    fn serve_config(&self, bytes: Vec<u8>) {
        *self.served_config.lock().unwrap() = Some(bytes);
    }

    async fn fetch_config(&self) -> Option<Vec<u8>> {
        let peer = self.peers.lock().unwrap().iter().next().copied()?;
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::FetchConfig { peer, reply: tx })
            .await
            .ok()?;
        match tokio::time::timeout(Duration::from_secs(3), rx).await {
            Ok(Ok(resp)) => resp,
            _ => None,
        }
    }

    fn set_topic_policy(&self, policy: crate::transport::TopicPolicy) {
        *self.policy.lock().unwrap() = policy;
    }

    async fn ensure_peers(&self, peers: Vec<Pubkey>) {
        let pids: Vec<PeerId> = peers
            .iter()
            .filter(|pk| **pk != self.local_pubkey)
            .filter_map(pubkey_to_peer_id)
            .collect();
        if !pids.is_empty() {
            let _ = self.cmd_tx.send(Cmd::EnsurePeers(pids)).await;
        }
    }
}

impl Drop for Libp2pNetwork {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(Cmd::Shutdown);
    }
}

/// P3/mesh-delivery-timing disabled (low-fanout topics would penalize honest
/// slow-mesh peers); P4 (invalid messages) strongly negative.
fn gossip_topic_score_params() -> TopicScoreParams {
    TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.01,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: -20.0,
        ..Default::default()
    }
}

/// The default IP-colocation penalty (>10 peers sharing an address, an
/// anti-sybil heuristic) treats every node in a single-host deployment as
/// suspicious, since they all share one IP. `ANYMONE_IP_COLOCATION_THRESHOLD`
/// raises the cliff for such deployments; production leaves it unset.
fn peer_score_params() -> PeerScoreParams {
    let mut params = PeerScoreParams::default();
    if let Ok(v) = std::env::var("ANYMONE_IP_COLOCATION_THRESHOLD") {
        match v.parse::<f64>() {
            Ok(threshold) => params.ip_colocation_factor_threshold = threshold,
            Err(e) => tracing::warn!(value = %v, error = %e, "invalid ANYMONE_IP_COLOCATION_THRESHOLD"),
        }
    }
    params
}

fn build_behaviour(
    kp: &libp2p_id::Keypair,
) -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
    let cfg = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(200))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(MAX_TRANSMIT_SIZE)
        .validate_messages()
        .build()?;
    let mut gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(kp.clone()), cfg)?;
    gossipsub
        .with_peer_score(peer_score_params(), PeerScoreThresholds::default())
        .map_err(|e| format!("peer score params: {e}"))?;

    let peer_id = PeerId::from(kp.public());
    let mut kad_cfg = kad::Config::default();
    // Re-bootstrap often: a joining node must find peers that registered with
    // the bootnode after its first query (default is 5 min).
    kad_cfg.set_periodic_bootstrap_interval(Some(Duration::from_secs(10)));
    let mut kademlia =
        kad::Behaviour::with_config(peer_id, kad::store::MemoryStore::new(peer_id), kad_cfg);
    // Server mode so leaf nodes answer routing queries and become discoverable.
    kademlia.set_mode(Some(kad::Mode::Server));

    let identify = identify::Behaviour::new(identify::Config::new(
        "/anymone/id/1".to_string(),
        kp.public(),
    ));

    let config_rr = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new("/anymone/config/1"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    Ok(Behaviour {
        gossipsub,
        identify,
        kademlia,
        config_rr,
    })
}

/// Split a `/…/p2p/<peer-id>` multiaddr into its peer id and address prefix.
fn split_peer_addr(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut prefix = addr.clone();
    match prefix.pop() {
        Some(Protocol::P2p(peer_id)) => Some((peer_id, prefix)),
        _ => None,
    }
}

async fn swarm_loop(
    mut swarm: Swarm<Behaviour>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    topics: Arc<Mutex<HashMap<String, broadcast::Sender<Inbound>>>>,
    peers: Arc<Mutex<HashSet<PeerId>>>,
    served_config: Arc<Mutex<Option<Vec<u8>>>>,
    policy: Arc<Mutex<crate::transport::TopicPolicy>>,
) {
    use std::collections::VecDeque;
    let mut pending_fetch: HashMap<OutboundRequestId, oneshot::Sender<Option<Vec<u8>>>> =
        HashMap::new();
    // Publishes that hit `InsufficientPeers` (the mesh hasn't grafted yet) are
    // buffered and retried — on a peer subscribing and on a short timer — until
    // they go out once. Drains to empty after delivery; no traffic when idle.
    let mut pending: HashMap<String, VecDeque<Vec<u8>>> = HashMap::new();
    let mut retry = tokio::time::interval(Duration::from_millis(500));
    let mut wanted: HashSet<PeerId> = HashSet::new();
    let mut redial = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = retry.tick() => flush_pending(&mut swarm, &mut pending),
            _ = redial.tick() => {
                let connected = peers.lock().unwrap().clone();
                for pid in wanted.difference(&connected) {
                    // dial() only uses addresses kademlia already has cached;
                    // query for the peer so a later redial has something to dial.
                    swarm.behaviour_mut().kademlia.get_closest_peers(*pid);
                    let _ = swarm.dial(*pid);
                }
            }
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::EnsurePeers(pids)) => {
                    let connected = peers.lock().unwrap().clone();
                    for pid in pids {
                        if wanted.insert(pid) {
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                        }
                        if !connected.contains(&pid) {
                            swarm.behaviour_mut().kademlia.get_closest_peers(pid);
                            let _ = swarm.dial(pid);
                        }
                    }
                }
                Some(Cmd::Subscribe(name)) => {
                    let topic = IdentTopic::new(name);
                    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
                    let _ = swarm.behaviour_mut().gossipsub.set_topic_params(topic, gossip_topic_score_params());
                }
                Some(Cmd::Unsubscribe(name)) => {
                    let topic = IdentTopic::new(name.clone());
                    let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                    pending.remove(&name);
                }
                Some(Cmd::Publish(name, bytes)) => {
                    // Observability: who does gossipsub think is subscribed to this
                    // topic right now (the set flood_publish targets)?
                    let th = gossipsub::TopicHash::from_raw(name.clone());
                    let subs: Vec<String> = swarm
                        .behaviour()
                        .gossipsub
                        .all_peers()
                        .filter(|(_, ts)| ts.iter().any(|t| **t == th))
                        .map(|(p, _)| p.to_string())
                        .collect();
                    let len = bytes.len();
                    tracing::trace!(topic = %name, recipients = ?subs, "publish recipients");
                    let topic = IdentTopic::new(name.clone());
                    match swarm.behaviour_mut().gossipsub.publish(topic, bytes.clone()) {
                        Ok(id) => tracing::debug!(topic = %name, len, n_subs = subs.len(), msg = %id, "publish ok"),
                        Err(gossipsub::PublishError::InsufficientPeers) => {
                            tracing::debug!(topic = %name, len, n_subs = subs.len(), "publish buffered (InsufficientPeers)");
                            let queue = pending.entry(name.clone()).or_default();
                            if queue.len() >= MAX_PENDING_PER_TOPIC {
                                queue.pop_front();
                                tracing::warn!(topic = %name, cap = MAX_PENDING_PER_TOPIC, "pending publish queue full; dropping oldest");
                            }
                            queue.push_back(bytes);
                        }
                        Err(e) => tracing::warn!(topic = %name, len, limit = MAX_TRANSMIT_SIZE, error = %e, "publish dropped"),
                    }
                }
                Some(Cmd::FetchConfig { peer, reply }) => {
                    let id = swarm.behaviour_mut().config_rr.send_request(&peer, ConfigRequest);
                    pending_fetch.insert(id, reply);
                }
                Some(Cmd::GossipSnapshot(reply)) => {
                    let gs = &swarm.behaviour().gossipsub;
                    let mut by_topic: HashMap<String, Vec<String>> = HashMap::new();
                    for (peer, ts) in gs.all_peers() {
                        for t in ts {
                            by_topic.entry(t.as_str().to_string()).or_default().push(peer.to_string());
                        }
                    }
                    let snap: Vec<TopicGossip> = by_topic
                        .into_iter()
                        .map(|(topic, subscribers)| {
                            let th = gossipsub::TopicHash::from_raw(topic.clone());
                            let mesh = gs.mesh_peers(&th).map(|p| p.to_string()).collect();
                            TopicGossip { topic, subscribers, mesh }
                        })
                        .collect();
                    let _ = reply.send(snap);
                }
                Some(Cmd::Shutdown) | None => break,
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { propagation_source, message_id, message }
                )) => {
                    let topic_name = message.topic.as_str().to_string();
                    let from = message
                        .source
                        .and_then(|pid| peer_id_to_pubkey(&pid))
                        .unwrap_or(Pubkey([0u8; 32]));
                    let admitted = policy
                        .lock()
                        .unwrap()
                        .get(&topic_name)
                        .is_none_or(|roster| roster.contains(&from));
                    if !admitted {
                        // Ignore avoids penalizing an honest forwarder during reconfig skew.
                        tracing::warn!(topic = %topic_name, from = %from, "publish ignored: sender not in topic roster");
                        swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id, &propagation_source, MessageAcceptance::Ignore,
                        );
                        continue;
                    }
                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, &propagation_source, MessageAcceptance::Accept,
                    );
                    crate::wire_debug::trace_in(&topic_name, &from, &message.data);
                    tracing::debug!(topic = %topic_name, from = %from, len = message.data.len(), "recv");
                    let topics = topics.lock().unwrap();
                    if let Some(s) = topics.get(&topic_name) {
                        let _ = s.send(Inbound { from, payload: message.data });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                    gossipsub::Event::Subscribed { .. }
                )) => flush_pending(&mut swarm, &mut pending),
                SwarmEvent::Behaviour(BehaviourEvent::ConfigRr(
                    request_response::Event::Message { message, .. }
                )) => match message {
                    request_response::Message::Request { channel, .. } => {
                        let served = served_config.lock().unwrap().clone();
                        let _ = swarm
                            .behaviour_mut()
                            .config_rr
                            .send_response(channel, ConfigResponse(served));
                    }
                    request_response::Message::Response { request_id, response } => {
                        if let Some(tx) = pending_fetch.remove(&request_id) {
                            let _ = tx.send(response.0);
                        }
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::ConfigRr(
                    request_response::Event::OutboundFailure { request_id, .. }
                )) => {
                    if let Some(tx) = pending_fetch.remove(&request_id) {
                        let _ = tx.send(None);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. }
                )) => {
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    }
                }
                // GetClosestPeers results carry real addresses but aren't cached
                // into the routing table automatically — without this, dialing a
                // peer discovered only through this query still has nothing to dial.
                SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                    kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)), ..
                    }
                )) => {
                    for peer in ok.peers {
                        for addr in peer.addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer.peer_id, addr);
                        }
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
                    tracing::debug!(peer = %peer_id, %error, "dial failed");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    peers.lock().unwrap().insert(peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    if num_established == 0 {
                        peers.lock().unwrap().remove(&peer_id);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Retry every buffered topic publish; keep only what still can't go out.
fn flush_pending(
    swarm: &mut Swarm<Behaviour>,
    pending: &mut HashMap<String, std::collections::VecDeque<Vec<u8>>>,
) {
    for (name, queue) in pending.iter_mut() {
        let topic = IdentTopic::new(name.clone());
        let before = queue.len();
        while let Some(bytes) = queue.pop_front() {
            match swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), bytes.clone())
            {
                Ok(_) => {}
                Err(gossipsub::PublishError::InsufficientPeers) => {
                    queue.push_front(bytes);
                    break;
                }
                Err(_) => {}
            }
        }
        if before != queue.len() {
            tracing::debug!(topic = %name, drained = before - queue.len(), remaining = queue.len(), "flush_pending");
        }
    }
    pending.retain(|_, q| !q.is_empty());
}

fn pubkey_to_peer_id(pk: &Pubkey) -> Option<PeerId> {
    let ed = libp2p_id::ed25519::PublicKey::try_from_bytes(&pk.0).ok()?;
    Some(PeerId::from_public_key(&libp2p_id::PublicKey::from(ed)))
}

fn peer_id_to_pubkey(peer_id: &PeerId) -> Option<Pubkey> {
    let mh = peer_id.as_ref();
    // libp2p uses the "identity" multihash (code 0x00) for keys whose
    // protobuf encoding is short enough — ed25519 keys qualify.
    if mh.code() != 0x00 {
        return None;
    }
    let pubkey = libp2p_id::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    let ed = pubkey.try_into_ed25519().ok()?;
    Some(Pubkey(ed.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_to_peer_id_matches_known_deployment_value() {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(
            "327070c91dc166160fd2315631c6058fcae0febc25db4a6b3f734e2feda049f3",
            &mut bytes,
        )
        .unwrap();
        let pid = pubkey_to_peer_id(&Pubkey(bytes)).unwrap();
        assert_eq!(
            pid.to_string(),
            "12D3KooWDDFzmBEys1wktvB5pumHWenBi3kx9dFKdoMqjjvuhLhQ"
        );
        assert_eq!(peer_id_to_pubkey(&pid).unwrap(), Pubkey(bytes));
    }
}
