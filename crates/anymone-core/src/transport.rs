//! Transport abstraction: subscribe/publish over named topics with
//! peer-authenticated delivery.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::identity::Pubkey;

/// Pubkeys allowed to publish on each bound topic; a topic absent from the map is open.
pub type TopicPolicy = HashMap<String, HashSet<Pubkey>>;

/// A message arriving on a topic, tagged with its publisher.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub from: Pubkey,
    pub payload: Vec<u8>,
}

/// Receiver of inbound messages on a single topic subscription.
///
/// A transport never delivers a message back to its publisher (matching libp2p
/// gossipsub). The in-memory backend shares one broadcast channel among all
/// subscribers, so it carries the publisher's own messages too — `owner` filters
/// those out in `recv`. Components that must consume their own output feed it to
/// their local state in-process at emit time (see `committee.rs`, `run_subnet`).
pub struct Subscription {
    rx: broadcast::Receiver<Inbound>,
    owner: Option<Pubkey>,
    topic: String,
}

impl Subscription {
    /// Construct a `Subscription` from an existing broadcast receiver. Used by
    /// the libp2p backend, where gossipsub already excludes the publisher.
    pub fn from_broadcast_receiver(rx: broadcast::Receiver<Inbound>, topic: String) -> Self {
        Subscription { rx, owner: None, topic }
    }
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<Inbound> {
        loop {
            match self.rx.recv().await {
                Ok(msg) if Some(msg.from) == self.owner => continue,
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(topic = %self.topic, skipped = n, "subscription lagged; oldest messages dropped");
                    continue;
                }
            }
        }
    }

    /// Non-blocking `recv`: the next already-delivered message, or `None`.
    pub fn try_recv(&mut self) -> Option<Inbound> {
        loop {
            match self.rx.try_recv() {
                Ok(msg) if Some(msg.from) == self.owner => continue,
                Ok(msg) => return Some(msg),
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!(topic = %self.topic, skipped = n, "subscription lagged; oldest messages dropped");
                    continue;
                }
                Err(_) => return None,
            }
        }
    }
}

#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Subscribe to `topic`. Returns a receiver that yields every subsequent
    /// publish from other peers (publisher's own messages are filtered).
    async fn subscribe(&self, topic: &str) -> Subscription;

    /// Leave `topic`: for gossipsub backends, actually leaves the mesh (a
    /// dropped `Subscription` alone doesn't — gossipsub subscription lives at
    /// the swarm level, independent of local listeners). Default no-op for
    /// backends without that distinction (e.g. the in-memory test transport).
    async fn unsubscribe(&self, _topic: &str) {}

    /// Publish `bytes` on `topic` to all current subscribers.
    async fn publish(&self, topic: &str, bytes: Vec<u8>);

    /// Store the signed config this node serves to config-pull requests.
    fn serve_config(&self, bytes: Vec<u8>);

    /// Pull the latest signed config from a peer; `None` if none answers yet.
    async fn fetch_config(&self) -> Option<Vec<u8>>;

    /// Adopt a roster-bound topic policy; default no-op for backends that don't enforce admission.
    fn set_topic_policy(&self, _policy: TopicPolicy) {}

    /// Maintain connections to these peers; default no-op.
    async fn ensure_peers(&self, _peers: Vec<Pubkey>) {}
}

/// In-memory broadcast network shared by multiple `Anymone` instances in a
/// single process. Tests construct one and hand each node a `handle`.
pub struct InMemoryNetwork {
    topics: Mutex<HashMap<String, broadcast::Sender<Inbound>>>,
    /// Signed config each node serves, keyed by node pubkey — backs `fetch_config`.
    configs: Mutex<HashMap<Pubkey, Vec<u8>>>,
    /// Kept on the network, not the publishing handle, so a rogue handle can't bypass it.
    policy: Mutex<TopicPolicy>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(InMemoryNetwork {
            topics: Mutex::new(HashMap::new()),
            configs: Mutex::new(HashMap::new()),
            policy: Mutex::new(TopicPolicy::new()),
        })
    }

    pub fn handle(self: &Arc<Self>, identity: Pubkey) -> InMemoryHandle {
        InMemoryHandle {
            net: self.clone(),
            identity,
        }
    }

    fn topic_sender(&self, topic: &str) -> broadcast::Sender<Inbound> {
        let mut topics = self.topics.lock().unwrap();
        topics
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(1024).0)
            .clone()
    }
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        InMemoryNetwork {
            topics: Mutex::new(HashMap::new()),
            configs: Mutex::new(HashMap::new()),
            policy: Mutex::new(TopicPolicy::new()),
        }
    }
}

#[derive(Clone)]
pub struct InMemoryHandle {
    net: Arc<InMemoryNetwork>,
    identity: Pubkey,
}

#[async_trait]
impl Transport for InMemoryHandle {
    async fn subscribe(&self, topic: &str) -> Subscription {
        let tx = self.net.topic_sender(topic);
        Subscription {
            rx: tx.subscribe(),
            owner: Some(self.identity),
            topic: topic.to_string(),
        }
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
        if let Some(roster) = self.net.policy.lock().unwrap().get(topic) {
            if !roster.contains(&self.identity) {
                tracing::warn!(topic, from = %self.identity, "publish rejected: sender not in topic roster");
                return;
            }
        }
        crate::wire_debug::trace(topic, &self.identity, &bytes);
        let tx = self.net.topic_sender(topic);
        let _ = tx.send(Inbound {
            from: self.identity,
            payload: bytes,
        });
    }

    fn serve_config(&self, bytes: Vec<u8>) {
        self.net
            .configs
            .lock()
            .unwrap()
            .insert(self.identity, bytes);
    }

    async fn fetch_config(&self) -> Option<Vec<u8>> {
        // Any peer that's served a config; prefer another node's over our own.
        let configs = self.net.configs.lock().unwrap();
        configs
            .iter()
            .find(|(pk, _)| **pk != self.identity)
            .or_else(|| configs.iter().next())
            .map(|(_, bytes)| bytes.clone())
    }

    fn set_topic_policy(&self, policy: TopicPolicy) {
        *self.net.policy.lock().unwrap() = policy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[tokio::test]
    async fn publish_reaches_peers_but_not_publisher() {
        let net = InMemoryNetwork::new();
        let a = Identity::generate();
        let b = Identity::generate();
        let handle_a = net.handle(a.pubkey());
        let handle_b = net.handle(b.pubkey());

        let mut sub_a = handle_a.subscribe("t").await;
        let mut sub_b = handle_b.subscribe("t").await;

        handle_a.publish("t", b"hi".to_vec()).await;

        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), sub_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.from, a.pubkey());
        assert_eq!(msg.payload, b"hi");

        // The publisher does not receive its own publish.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), sub_a.recv())
                .await
                .is_err(),
            "publisher must not receive its own message"
        );

        // A topic policy binding "t" to `a` rejects a publish from `b`.
        let mut policy = TopicPolicy::new();
        policy.insert("t".to_string(), HashSet::from([a.pubkey()]));
        handle_a.set_topic_policy(policy);
        handle_b.publish("t", b"forged".to_vec()).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), sub_a.recv())
                .await
                .is_err(),
            "publish from outside the topic roster must be rejected"
        );
        handle_a.publish("t", b"authorized".to_vec()).await;
        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), sub_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.payload, b"authorized");
    }
}
