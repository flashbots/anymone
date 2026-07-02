//! Transport abstraction: subscribe/publish over named topics with
//! peer-authenticated delivery.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::identity::Pubkey;

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
}

impl Subscription {
    /// Construct a `Subscription` from an existing broadcast receiver. Used by
    /// the libp2p backend, where gossipsub already excludes the publisher.
    pub fn from_broadcast_receiver(rx: broadcast::Receiver<Inbound>) -> Self {
        Subscription { rx, owner: None }
    }
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<Inbound> {
        loop {
            match self.rx.recv().await {
                Ok(msg) if Some(msg.from) == self.owner => continue,
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    }

    /// Non-blocking `recv`: the next already-delivered message, or `None`.
    pub fn try_recv(&mut self) -> Option<Inbound> {
        loop {
            match self.rx.try_recv() {
                Ok(msg) if Some(msg.from) == self.owner => continue,
                Ok(msg) => return Some(msg),
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
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

    /// Publish `bytes` on `topic` to all current subscribers.
    async fn publish(&self, topic: &str, bytes: Vec<u8>);

    /// Store the signed config this node serves to config-pull requests.
    fn serve_config(&self, bytes: Vec<u8>);

    /// Pull the latest signed config from a peer; `None` if none answers yet.
    async fn fetch_config(&self) -> Option<Vec<u8>>;
}

/// In-memory broadcast network shared by multiple `Anymone` instances in a
/// single process. Tests construct one and hand each node a `handle`.
pub struct InMemoryNetwork {
    topics: Mutex<HashMap<String, broadcast::Sender<Inbound>>>,
    /// Signed config each node serves, keyed by node pubkey — backs `fetch_config`.
    configs: Mutex<HashMap<Pubkey, Vec<u8>>>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(InMemoryNetwork {
            topics: Mutex::new(HashMap::new()),
            configs: Mutex::new(HashMap::new()),
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
        }
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
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
    }
}
