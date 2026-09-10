pub mod backend;
pub mod client;
pub mod host;
pub mod wire;

pub use backend::RemoteClientBackend;
pub use client::RemoteSessionClient;
pub use host::{RemoteSessionHost, RemoteSessionHostHandle};
pub use wire::{PairingInfo, SessionInput, SessionReply};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostConfig {
    pub subnet: anymone_core::Subnet,
    pub relay_exchange_keys: Vec<(
        anymone_core::Pubkey,
        anymone_core::config::ExchangePublicKeyWire,
    )>,
    pub starting_round: u64,
}

impl HostConfig {
    pub fn developer_session(
        &self,
    ) -> Result<anymone_core::RemoteAttestedSession, anymone_core::RemoteSessionError> {
        anymone_core::RemoteAttestedSession::developer(
            &self.subnet,
            &self.relay_exchange_keys,
            self.starting_round,
        )
    }
}

use thiserror::Error;

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const INTERFACE_VERSION: u16 = 3;

#[derive(Debug, Error)]
pub enum RemoteTransportError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate generation: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("wire encoding: {0}")]
    Encode(String),
    #[error("wire frame is {0} bytes")]
    FrameTooLarge(usize),
    #[error("pairing failed")]
    PairingFailed,
    #[error("host rejected the request: {0}")]
    Rejected(String),
    #[error(transparent)]
    Protocol(#[from] anymone_core::RemoteSessionError),
    #[error("operation timed out")]
    Timeout,
    #[error("unexpected host reply")]
    UnexpectedReply,
    #[error("retry the pending request before sending another action")]
    PendingRequest,
    #[error("there is no pending request")]
    NoPendingRequest,
    #[error("reconnect before retrying the request")]
    Disconnected,
}
