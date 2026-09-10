use serde::{Deserialize, Serialize};

use anymone_core::{ProtocolAction, RemoteSessionError, RemoteSessionStatus};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairingInfo {
    pub interface_version: u16,
    pub address: String,
    #[serde(with = "serde_bytes")]
    pub certificate_der: Vec<u8>,
    pub certificate_sha256: [u8; 32],
    pub pairing_token: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PairRequest {
    First {
        token: [u8; 32],
        controller_secret: [u8; 32],
    },
    Resume {
        controller_secret: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionInput {
    Pair(PairRequest),
    Action {
        sequence: u64,
        action: ProtocolAction,
    },
    Status,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionReply {
    Paired(RemoteSessionStatus),
    Action {
        sequence: u64,
        result: Result<Vec<Vec<u8>>, RemoteSessionError>,
    },
    Status(RemoteSessionStatus),
    Closed,
    Error(String),
}
