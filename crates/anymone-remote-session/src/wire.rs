use serde::{Deserialize, Serialize};

use anymone_core::{ProtocolAction, RemoteSessionError, RemoteSessionStatus};
use crate::HostConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostStatus {
    pub session_id: [u8; 32],
    pub next_request: u64,
    pub closed: bool,
    pub paired: bool,
    pub pairing_attempts_remaining: u8,
    pub client: Option<RemoteSessionStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionCommand {
    Configure(HostConfig),
    Action(ProtocolAction),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CommandResult {
    Configured { status: RemoteSessionStatus, returned_payloads: Vec<Vec<u8>> },
    Messages(Vec<Vec<u8>>),
}

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
    Code { message: Vec<u8> },
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
    CodeProof { controller_secret: [u8; 32], proof: [u8; 32] },
    Request {
        sequence: u64,
        command: SessionCommand,
    },
    Status,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionReply {
    CodeChallenge { message: Vec<u8> },
    CodeAccepted { proof: [u8; 32], status: HostStatus },
    Paired(HostStatus),
    Executed {
        sequence: u64,
        result: Result<CommandResult, RemoteSessionError>,
    },
    Status(HostStatus),
    Closed,
    Error(String),
}
