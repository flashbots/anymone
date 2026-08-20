//! Protocol between a client and the node it dials over commonware-stream.
//!
//! Clients never join the p2p backbone: they authenticate once at the stream
//! handshake, then submit through and receive from the node they dialed.

use serde::{Deserialize, Serialize};

use crate::config::SubnetId;
use crate::transport::Topic;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum StreamMsg {
    ConfigReq,
    ConfigResp(Option<Vec<u8>>),
    /// A bincode `Registration`; the node verifies it and forwards it to the
    /// committee, so a process outside every tracked peer set can still be
    /// registered.
    Register(Vec<u8>),
    /// The client's platform proof. Screened against the handshake-authenticated
    /// key, so it can't be replayed on another client's behalf.
    Attest(crate::tee::Attestation),
    /// Client data addressed to the receiving node for `subnet`. Its payload
    /// carries the client's own signature, so delivery doesn't launder its
    /// origin.
    Data { subnet: SubnetId, payload: Vec<u8> },
    /// A client's publish on a client-open topic (a Noop subnet's broadcast,
    /// where the whole protocol rides the topic). The node republishes it on
    /// the backbone; bound topics are refused.
    Submit { topic: Topic, payload: Vec<u8> },
    FeedSubscribe { topics: Vec<Topic> },
    /// A frame on a subscribed topic. `from` is the frame's publisher on the
    /// backbone (the serving node itself, for its own publishes); the stream
    /// peer is authenticated, so a client can trust it named the origin honestly.
    FeedFrame {
        topic: Topic,
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
