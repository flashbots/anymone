//! Transport abstraction: subscribe/publish over named topics with
//! peer-authenticated delivery.
//!
//! The real libp2p impl lands in M3. For now there's an in-memory impl that
//! lets tests run multiple `Anymone` instances inside one process over a
//! shared `InMemoryNetwork`.

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
/// Unlike libp2p gossipsub, this subscription **does** deliver
/// publisher-to-self messages. The committee scheduler publishes configs
/// on `anymone/config` and the same node's Anymone has to react — under
/// gossipsub semantics the committee would never see its own publish.
/// libp2p deployments will need a side-channel from the scheduler to the
/// local Anymone; the in-memory transport sidesteps that with looser
/// delivery here.
pub struct Subscription {
    rx: broadcast::Receiver<Inbound>,
}

impl Subscription {
    /// Construct a `Subscription` from an existing broadcast receiver.
    /// Used by transport backends other than the in-memory impl.
    pub fn from_broadcast_receiver(rx: broadcast::Receiver<Inbound>) -> Self {
        Subscription { rx }
    }
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<Inbound> {
        loop {
            match self.rx.recv().await {
                Ok(msg) => return Some(msg),
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
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
}

/// In-memory broadcast network shared by multiple `Anymone` instances in a
/// single process. Tests construct one and hand each node a `handle`.
pub struct InMemoryNetwork {
    topics: Mutex<HashMap<String, broadcast::Sender<Inbound>>>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(InMemoryNetwork { topics: Mutex::new(HashMap::new()) })
    }

    pub fn handle(self: &Arc<Self>, identity: Pubkey) -> InMemoryHandle {
        InMemoryHandle { net: self.clone(), identity }
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
        InMemoryNetwork { topics: Mutex::new(HashMap::new()) }
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
        Subscription { rx: tx.subscribe() }
    }

    async fn publish(&self, topic: &str, bytes: Vec<u8>) {
        crate::wire_debug::trace(topic, &self.identity, &bytes);
        let tx = self.net.topic_sender(topic);
        let _ = tx.send(Inbound { from: self.identity, payload: bytes });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[tokio::test]
    async fn publish_reaches_all_subscribers_including_publisher() {
        let net = InMemoryNetwork::new();
        let a = Identity::generate();
        let b = Identity::generate();
        let handle_a = net.handle(a.pubkey());
        let handle_b = net.handle(b.pubkey());

        let mut sub_a = handle_a.subscribe("t").await;
        let mut sub_b = handle_b.subscribe("t").await;

        handle_a.publish("t", b"hi".to_vec()).await;

        for sub in [&mut sub_a, &mut sub_b] {
            let msg = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(msg.from, a.pubkey());
            assert_eq!(msg.payload, b"hi");
        }
    }
}
