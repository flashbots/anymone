//! Mobile FFI for the anymone client: one client object, one pipe object, and
//! one attestation-token hook.
//!
//! Threading contract for the shells:
//! - `AnymoneClient::start*` waits for a committee-signed config (up to ~65 s).
//! - `recv`, `next_event` and the `subscribe`/`listen`/`open` retries suspend.
//! - `send*` and the getters return immediately.

mod attest;
mod client;
mod remote_session;
#[cfg(test)]
mod remote_host_tests;
mod secrets;

pub use attest::{AttestationStatus, AttestationTokenFetcher, FetchError, MobileScheme};
pub use client::{AnymoneClient, AnymoneEvent, AnymonePipe, IncomingMessage};
pub use remote_session::{RemoteHostError, RemoteProtocolHost};
pub use secrets::{SecretStore, SecretStoreError};

uniffi::setup_scaffolding!();

/// Every exported async fn runs its work here, so the futures the bindings
/// drive are runtime-agnostic and the anymone internals that call
/// `tokio::spawn` always find a runtime.
pub(crate) static RUNTIME: once_cell::sync::Lazy<tokio::runtime::Runtime> =
    once_cell::sync::Lazy::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("anymone")
            .enable_all()
            .build()
            .expect("build anymone tokio runtime")
    });

pub(crate) async fn on_runtime<T, F>(fut: F) -> T
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    RUNTIME.spawn(fut).await.expect("anymone task panicked")
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AnymoneError {
    #[error("config: {0}")]
    Config(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("governance: {0}")]
    Governance(String),
    #[error("service tag absent from the signed config")]
    TagNotInConfig,
    #[error("a pipe for this tag is already open")]
    TagAlreadyOpen,
    #[error("not this node's service tag")]
    NotOurService,
    #[error("send: {0}")]
    Send(String),
    #[error("pipe closed")]
    PipeClosed,
    #[error("client stopped")]
    Stopped,
    #[error("secret store: {0}")]
    SecretStore(String),
}

impl From<anymone_core::bootstrap::BootstrapError> for AnymoneError {
    fn from(e: anymone_core::bootstrap::BootstrapError) -> Self {
        AnymoneError::Config(e.to_string())
    }
}

impl From<anymone_core::identity::IdentityError> for AnymoneError {
    fn from(e: anymone_core::identity::IdentityError) -> Self {
        AnymoneError::Identity(e.to_string())
    }
}

impl From<anymone_core::GovernanceError> for AnymoneError {
    fn from(e: anymone_core::GovernanceError) -> Self {
        AnymoneError::Governance(e.to_string())
    }
}

impl From<anymone_core::OpenError> for AnymoneError {
    fn from(e: anymone_core::OpenError) -> Self {
        match e {
            anymone_core::OpenError::TagNotInConfig => AnymoneError::TagNotInConfig,
            anymone_core::OpenError::NotOurService => AnymoneError::NotOurService,
            anymone_core::OpenError::TagAlreadyOpen => AnymoneError::TagAlreadyOpen,
        }
    }
}

impl From<anymone_core::SendError> for AnymoneError {
    fn from(e: anymone_core::SendError) -> Self {
        match e {
            anymone_core::SendError::Closed => AnymoneError::PipeClosed,
            other => AnymoneError::Send(other.to_string()),
        }
    }
}
