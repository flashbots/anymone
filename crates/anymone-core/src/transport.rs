//! Transport abstraction: a small closed set of broadcast topics plus
//! directly-addressed per-subnet sends, with peer-authenticated delivery.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::config::SubnetId;
use crate::identity::Pubkey;
use crate::log_target::P2P;

/// Largest message any backend carries; the committee sizes subnets under it
/// (`scheduler_core::MAX_SUBNET_WIRE`).
pub const MAX_TRANSMIT_SIZE: usize = 16 * 1024 * 1024;

/// A broadcast channel: one of the closed set of one-to-many flows. Traffic
/// that has a definite recipient (client data to a relay, registrations to the
/// committee) is addressed via [`Transport::send`], not a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Topic {
    /// Signed round configurations, committee → everyone.
    Config,
    /// Signed registrations. Not a broadcast: a publish is delivered to
    /// [`NetView::registration_recipients`] only. Kept a topic so registrants
    /// and the committee share the subscribe/publish surface.
    Registration,
    /// Observed subnet faults, relays → committee and auditors.
    Faults,
    /// The committee's internal anonymised proposal channel.
    CommitteeBody,
    /// Config signatures between committee members.
    CommitteeSigs,
    /// A subnet's round output: the leader's `Decoded`/`Reservations`, read by
    /// clients, watchers, and observers.
    Broadcast(SubnetId),
    /// Each relay's decryption share; public for verifiability.
    Shares(SubnetId),
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Topic::Config => write!(f, "config"),
            Topic::Registration => write!(f, "registration"),
            Topic::Faults => write!(f, "faults"),
            Topic::CommitteeBody => write!(f, "committee/body"),
            Topic::CommitteeSigs => write!(f, "committee/sigs"),
            Topic::Broadcast(id) => write!(f, "subnet/{id}"),
            Topic::Shares(id) => write!(f, "subnet/{id}/shares"),
        }
    }
}

/// Where one outbound protocol message goes: a topic, or straight to the
/// peer(s) it is for. Produced by each protocol's egress function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    Topic(Topic),
    /// One addressee's subnet inbox (a lane's coded share, a sealed opening).
    Peer(SubnetId, Pubkey),
    /// The same frame to each addressee's subnet inbox (a client's ingress
    /// post to every relay).
    Each(SubnetId, Vec<Pubkey>),
}

/// A config's network view, derived once per adoption by
/// [`crate::governance::net_view`] and handed to the transport whole.
#[derive(Debug, Clone, Default)]
pub struct NetView {
    /// Config version. Peer-set tracking index: must be monotonic and
    /// identical across peers.
    pub index: u64,
    /// Pubkeys allowed to publish on each topic; a topic absent from the map
    /// is open.
    pub senders: HashMap<Topic, HashSet<Pubkey>>,
    /// Peers dialed outbound: committee + relays + aggregators.
    pub primary: Vec<Pubkey>,
    /// Peers accepted inbound only: watchers.
    pub secondary: Vec<Pubkey>,
    /// Who a `Registration` publish is delivered to: committee ∪ watchers.
    /// Registrants are outside the authorized p2p, so registrations ride a
    /// stream connection to any node, which forwards to these.
    pub registration_recipients: Vec<Pubkey>,
    /// Client-facing dial address per relay, for backends whose clients don't
    /// join the p2p network.
    pub relay_client_addrs: Vec<(Pubkey, String)>,
    /// Subnets a client may submit data on.
    pub subnets: Vec<SubnetId>,
}

/// A message arriving on a topic or inbox, tagged with its publisher.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub from: Pubkey,
    pub payload: Vec<u8>,
}

/// Receiver of inbound messages on a single topic or inbox subscription.
///
/// A transport never delivers a message back to its publisher. The in-memory
/// backend shares one broadcast channel among all
/// subscribers, so it carries the publisher's own messages too — `owner` filters
/// those out in `recv`. Components that must consume their own output feed it to
/// their local state in-process at emit time (see `committee.rs`, `run_subnet`).
pub struct Subscription {
    rx: broadcast::Receiver<Inbound>,
    owner: Option<Pubkey>,
    label: String,
}

impl Subscription {
    /// Construct a `Subscription` from an existing broadcast receiver. Used by
    /// the network backends, which never route a message back to its publisher.
    pub fn from_broadcast_receiver(rx: broadcast::Receiver<Inbound>, label: String) -> Self {
        Subscription {
            rx,
            owner: None,
            label,
        }
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
                    tracing::warn!(target: P2P, label = %self.label, skipped = n, "subscription lagged; oldest messages dropped");
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
                    tracing::warn!(target: P2P, label = %self.label, skipped = n, "subscription lagged; oldest messages dropped");
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
    async fn subscribe(&self, topic: Topic) -> Subscription;

    /// Publish `bytes` on `topic` to all current subscribers (`Registration`:
    /// to the named recipients).
    async fn publish(&self, topic: Topic, bytes: Vec<u8>);

    /// Deliver `bytes` to `to`'s inbox for `subnet`. Best-effort like
    /// `publish`: a dropped connection loses the frame, the next round re-sends.
    async fn send(&self, to: Pubkey, subnet: SubnetId, bytes: Vec<u8>);

    /// Frames addressed to this node for `subnet`.
    async fn inbox(&self, subnet: SubnetId) -> Subscription;

    /// Adopt a config's network view: topic admission, peer sets, addressing.
    fn apply(&self, _view: NetView) {}

    /// Present this node's platform attestation on every relay connection,
    /// including ones dialed later.
    fn attest(&self, _attestation: crate::tee::Attestation) {}

    /// Clients this backend saw attest. `None` where none enrol over the wire.
    fn attested_clients(&self) -> Option<Arc<crate::tee::AttestedClients>> {
        None
    }

    /// Store the signed config this node serves to config-pull requests.
    fn serve_config(&self, bytes: Vec<u8>);

    /// The locally adopted config, when this transport serves config pulls.
    fn cached_config(&self) -> Option<Vec<u8>> { None }

    /// Pull the latest signed config from a peer; `None` if none answers yet.
    async fn fetch_config(&self) -> Option<Vec<u8>>;

    /// Peers this node has actually exchanged traffic with, for operator
    /// endpoints. Observed, never the configured roster — a peer listed here is
    /// one the transport has really heard from.
    fn peers(&self) -> Vec<Pubkey> {
        Vec::new()
    }

    /// This node's own key, so an endpoint can label itself without the caller
    /// threading the identity separately.
    fn local_pubkey(&self) -> Pubkey;
}

/// In-memory network shared by multiple `Anymone` instances in a single
/// process. Tests construct one and hand each node a `handle`. Topics are
/// broadcast to every subscriber; `send` reaches only the addressee's inbox,
/// so tests are faithful to the unicast plane.
pub struct InMemoryNetwork {
    topics: Mutex<HashMap<Topic, broadcast::Sender<Inbound>>>,
    inboxes: Mutex<HashMap<(Pubkey, SubnetId), broadcast::Sender<Inbound>>>,
    /// Signed config each node serves, keyed by node pubkey — backs `fetch_config`.
    configs: Mutex<HashMap<Pubkey, Vec<u8>>>,
    /// Kept on the network, not the publishing handle, so a rogue handle can't bypass it.
    senders: Mutex<HashMap<Topic, HashSet<Pubkey>>>,
}

impl InMemoryNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn handle(self: &Arc<Self>, identity: Pubkey) -> InMemoryHandle {
        InMemoryHandle {
            net: self.clone(),
            identity,
        }
    }

    fn topic_sender(&self, topic: Topic) -> broadcast::Sender<Inbound> {
        let mut topics = self.topics.lock().unwrap();
        topics
            .entry(topic)
            .or_insert_with(|| broadcast::channel(1024).0)
            .clone()
    }

    fn inbox_sender(&self, owner: Pubkey, subnet: SubnetId) -> broadcast::Sender<Inbound> {
        let mut inboxes = self.inboxes.lock().unwrap();
        inboxes
            .entry((owner, subnet))
            .or_insert_with(|| broadcast::channel(1024).0)
            .clone()
    }
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        InMemoryNetwork {
            topics: Mutex::new(HashMap::new()),
            inboxes: Mutex::new(HashMap::new()),
            configs: Mutex::new(HashMap::new()),
            senders: Mutex::new(HashMap::new()),
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
    async fn subscribe(&self, topic: Topic) -> Subscription {
        let tx = self.net.topic_sender(topic);
        Subscription {
            rx: tx.subscribe(),
            owner: Some(self.identity),
            label: topic.to_string(),
        }
    }

    async fn publish(&self, topic: Topic, bytes: Vec<u8>) {
        if let Some(roster) = self.net.senders.lock().unwrap().get(&topic) {
            if !roster.contains(&self.identity) {
                tracing::warn!(target: P2P, %topic, from = %self.identity, "publish rejected: sender not in topic roster");
                return;
            }
        }
        crate::wire_debug::trace(&topic.to_string(), &self.identity, &bytes);
        let tx = self.net.topic_sender(topic);
        let _ = tx.send(Inbound {
            from: self.identity,
            payload: bytes,
        });
    }

    async fn send(&self, to: Pubkey, subnet: SubnetId, bytes: Vec<u8>) {
        crate::wire_debug::trace(&format!("subnet/{subnet}/inbox"), &self.identity, &bytes);
        let tx = self.net.inbox_sender(to, subnet);
        let _ = tx.send(Inbound {
            from: self.identity,
            payload: bytes,
        });
    }

    async fn inbox(&self, subnet: SubnetId) -> Subscription {
        let tx = self.net.inbox_sender(self.identity, subnet);
        Subscription {
            rx: tx.subscribe(),
            owner: None,
            label: format!("subnet/{subnet}/inbox"),
        }
    }

    fn apply(&self, view: NetView) {
        *self.net.senders.lock().unwrap() = view.senders;
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

    fn cached_config(&self) -> Option<Vec<u8>> {
        self.net.configs.lock().unwrap().get(&self.identity).cloned()
    }

    fn local_pubkey(&self) -> Pubkey {
        self.identity
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

        let t = Topic::Broadcast(0);
        let mut sub_a = handle_a.subscribe(t).await;
        let mut sub_b = handle_b.subscribe(t).await;

        handle_a.publish(t, b"hi".to_vec()).await;

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

        // A sender roster binding the topic to `a` rejects a publish from `b`.
        let mut view = NetView::default();
        view.senders.insert(t, HashSet::from([a.pubkey()]));
        handle_a.apply(view);
        handle_b.publish(t, b"forged".to_vec()).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), sub_a.recv())
                .await
                .is_err(),
            "publish from outside the topic roster must be rejected"
        );
        handle_a.publish(t, b"authorized".to_vec()).await;
        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), sub_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.payload, b"authorized");

        // A send reaches only the addressee's inbox.
        let mut inbox_a = handle_a.inbox(0).await;
        let mut inbox_b = handle_b.inbox(0).await;
        handle_a.send(b.pubkey(), 0, b"direct".to_vec()).await;
        let msg = tokio::time::timeout(std::time::Duration::from_millis(100), inbox_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.from, a.pubkey());
        assert_eq!(msg.payload, b"direct");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), inbox_a.recv())
                .await
                .is_err(),
            "a send must reach only the addressee"
        );
    }
}
