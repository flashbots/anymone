//! User-facing `Pipe`: open/bind a service tag, send and receive bytes.
//!
//! The Pipe layer hides round structure, subnet selection, and the inner
//! routing format. From the caller's point of view: bytes in, bytes out.

use std::sync::{Mutex, Weak};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::runtime::{resolve_send_subnet, retire_outbound, stage_outbound, AnymoneInner};
use crate::wire::{Frame, ServiceTag};
use crate::SubnetId;

/// What gets put on the wire between Pipes: the inner `PipeMessage` is
/// bincode-encoded, then wrapped in a v0 raw `Frame` whose `service_tag` is
/// the destination tag (the peer's return tag, or the service's bound tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PipeMessage {
    pub return_tag: ServiceTag,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// What a `Pipe` yields on `recv`: the originator's return tag plus their
/// bytes. The tag is what the recipient should pass to `send_to` for replies.
#[derive(Debug, Clone)]
pub struct PipeIncoming {
    pub return_tag: ServiceTag,
    pub payload: Vec<u8>,
}

pub struct Pipe {
    anymone: Weak<AnymoneInner>,
    /// For client-opened pipes: the bound service tag (so `send` knows where).
    /// For service-bound pipes: `None` (caller must use `send_to`).
    peer_tag: Option<ServiceTag>,
    /// Our local routing tag — for client pipes this is the random per-pipe
    /// return tag, for service pipes this is the service's bound tag.
    return_tag: ServiceTag,
    /// Subnet this pipe last staged on. When a send resolves a different subnet
    /// (the committee re-homed us across a reconfig), we retire the client
    /// session on the old one so we stop contributing there.
    last_subnet: Mutex<Option<SubnetId>>,
    inbound: mpsc::UnboundedReceiver<PipeIncoming>,
}

impl Pipe {
    pub(crate) fn new(
        anymone: Weak<AnymoneInner>,
        peer_tag: Option<ServiceTag>,
        return_tag: ServiceTag,
        inbound: mpsc::UnboundedReceiver<PipeIncoming>,
    ) -> Self {
        Pipe { anymone, peer_tag, return_tag, last_subnet: Mutex::new(None), inbound }
    }

    /// Our local routing tag.
    pub fn return_tag(&self) -> ServiceTag {
        self.return_tag
    }

    /// Send `payload` to the pipe's bound counterparty (client-side only).
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let dst = self.peer_tag.ok_or(SendError::NoPeerTag)?;
        self.send_to(dst, payload).await
    }

    /// Send `payload` addressed to `dst`. Service-side replies use this with
    /// the request's `return_tag`.
    pub async fn send_to(&self, dst: ServiceTag, payload: Vec<u8>) -> Result<(), SendError> {
        // Resolve the subnet from the current config every send, so the pipe
        // re-homes as the committee adds/removes subnets.
        let anymone = self.anymone.upgrade().ok_or(SendError::Closed)?;
        let subnet = resolve_send_subnet(&anymone, self.peer_tag, self.return_tag, dst)
            .ok_or(SendError::SubnetGone)?;
        // On re-home (client pipes), retire the client session on the subnet we
        // left so we stop contributing there — otherwise the old subnet keeps
        // counting us and the population is double-counted across subnets.
        // Service replies (no peer tag) are one-off, so they don't track a home.
        if self.peer_tag.is_some() {
            let prev = {
                let mut last = self.last_subnet.lock().unwrap();
                last.replace(subnet)
            };
            if let Some(prev) = prev {
                if prev != subnet {
                    retire_outbound(&self.anymone, prev, self.return_tag);
                }
            }
        }
        let msg = PipeMessage { return_tag: self.return_tag, payload };
        let data = bincode::serialize(&msg).map_err(|e| SendError::Encode(e.to_string()))?;
        let mut bytes = Vec::with_capacity(1 + 20 + data.len());
        Frame::Raw { service_tag: dst, data: &data }.encode(&mut bytes);
        stage_outbound(&self.anymone, subnet, self.return_tag, bytes)
    }

    /// Receive the next inbound message, or `None` once the pipe is closed.
    pub async fn recv(&mut self) -> Option<PipeIncoming> {
        self.inbound.recv().await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("pipe was opened without a peer tag; use send_to(dst, ...)")]
    NoPeerTag,
    #[error("anymone instance shut down")]
    Closed,
    #[error("subnet is no longer active")]
    SubnetGone,
    #[error("encode: {0}")]
    Encode(String),
}
