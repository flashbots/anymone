//! Protocol between a client and the node it dials over commonware-stream.
//!
//! Clients never join the p2p backbone: they authenticate once at the stream
//! handshake, then submit through and receive from the node they dialed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum StreamMsg {
    ConfigReq,
    ConfigResp(Option<Vec<u8>>),
    /// A bincode `Registration`; the node verifies it before republishing, so a
    /// node still outside every tracked peer set can still be registered.
    Register(Vec<u8>),
    /// Client-origin traffic for a topic the node serves. Its payload carries
    /// the client's own signature, so forwarding doesn't launder its origin.
    Submit { topic: String, payload: Vec<u8> },
    FeedSubscribe { topics: Vec<String> },
    /// A frame on a subscribed topic. `from` is the node's own key: the stream
    /// peer is authenticated, so a client can trust it named itself honestly.
    FeedFrame {
        topic: String,
        from: crate::identity::Pubkey,
        payload: Vec<u8>,
    },
}

impl StreamMsg {
    pub(crate) fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("StreamMsg serialises")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}
