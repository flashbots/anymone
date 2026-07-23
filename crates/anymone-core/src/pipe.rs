//! User-facing `Pipe`: open/bind a service tag, send and receive bytes.
//!
//! The Pipe layer hides round structure, subnet selection, and the inner
//! routing format. From the caller's point of view: bytes in, bytes out.

use std::sync::{Mutex, Weak};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::runtime::{
    resolve_send_subnet, retire_outbound, retire_outbound_everywhere, stage_outbound, AnymoneInner,
};
use crate::wire::{Frame, RouteTag, ServiceTag, SERVICE_TAG_LEN};
use crate::SubnetId;

/// What gets put on the wire between Pipes: the inner `PipeMessage` is
/// bincode-encoded, then wrapped in a v0 raw `Frame` whose `dst` is the
/// destination delivery address (the peer's return path, or the service's tag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PipeMessage {
    pub return_tag: RouteTag,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// What a `Pipe` yields on `recv`: the originator's return path plus their
/// bytes. The tag is what the recipient should pass to `send_to` for replies.
#[derive(Debug, Clone)]
pub struct PipeIncoming {
    pub return_tag: RouteTag,
    pub payload: Vec<u8>,
}

pub struct Pipe {
    anymone: Weak<AnymoneInner>,
    /// For client-opened pipes: the bound service tag (so `send` knows where).
    /// For service-bound pipes: `None` (caller must use `send_to`).
    peer_tag: Option<ServiceTag>,
    /// Our own delivery address — for client pipes a random per-pipe return
    /// path, for service pipes the service tag as a delivery address.
    return_tag: RouteTag,
    /// Subnet this pipe last staged on, or joined at construction. When a send
    /// resolves a different subnet (the committee re-homed us across a
    /// reconfig), or when the pipe is dropped, we retire the client session on
    /// this subnet so we stop contributing there.
    last_subnet: Mutex<Option<SubnetId>>,
    inbound: mpsc::UnboundedReceiver<PipeIncoming>,
    /// Clone of the sender registered under `return_tag` in `AnymoneInner.pipes`,
    /// so `Drop` only removes that entry if a later `bind`/`subscribe` on the
    /// same tag hasn't since overwritten it.
    self_tx: mpsc::UnboundedSender<PipeIncoming>,
}

impl Pipe {
    pub(crate) fn new(
        anymone: Weak<AnymoneInner>,
        peer_tag: Option<ServiceTag>,
        return_tag: RouteTag,
        initial_subnet: Option<SubnetId>,
        inbound: mpsc::UnboundedReceiver<PipeIncoming>,
        self_tx: mpsc::UnboundedSender<PipeIncoming>,
    ) -> Self {
        Pipe {
            anymone,
            peer_tag,
            return_tag,
            last_subnet: Mutex::new(initial_subnet),
            inbound,
            self_tx,
        }
    }

    /// Our own delivery address.
    pub fn return_tag(&self) -> RouteTag {
        self.return_tag
    }

    /// Send `payload` to the pipe's bound counterparty (client-side only).
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let dst = self.peer_tag.ok_or(SendError::NoPeerTag)?;
        self.send_to(dst, payload).await
    }

    /// Send `payload` addressed to `dst` (a service tag, or a peer's return
    /// path). Service-side replies pass the request's `return_tag`.
    pub async fn send_to(
        &self,
        dst: impl Into<RouteTag>,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        let dst = dst.into();
        // Resolve the subnet from the current config every send, so the pipe
        // re-homes as the committee adds/removes subnets.
        let anymone = self.anymone.upgrade().ok_or(SendError::Closed)?;
        let subnet = resolve_send_subnet(&anymone, self.peer_tag, self.return_tag, dst)
            .ok_or(SendError::SubnetGone)?;
        let msg = PipeMessage {
            return_tag: self.return_tag,
            payload,
        };
        let data = bincode::serialize(&msg).map_err(|e| SendError::Encode(e.to_string()))?;
        // Reject payloads too big for one message rather than truncating/dropping them
        // downstream; fragmentation across rounds is a later batch.
        let framed = 1 + SERVICE_TAG_LEN + data.len();
        let max_payload = anymone
            .config
            .read()
            .unwrap()
            .body
            .subnets
            .iter()
            .find(|s| s.id == subnet)
            .map(|s| s.protocol.message_size());
        if let Some(max) = max_payload {
            if framed > max {
                return Err(SendError::PayloadTooLarge { size: framed, max });
            }
        }
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
        let mut bytes = Vec::with_capacity(framed);
        Frame::Raw { dst, data: &data }.encode(&mut bytes);
        stage_outbound(&self.anymone, subnet, self.return_tag, bytes)
    }

    /// Receive the next inbound message, or `None` once the pipe is closed.
    pub async fn recv(&mut self) -> Option<PipeIncoming> {
        self.inbound.recv().await
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let Some(inner) = self.anymone.upgrade() else {
            return;
        };
        let mut pipes = inner.pipes.lock().unwrap();
        let still_owner = pipes
            .get(&self.return_tag)
            .map_or(false, |tx| tx.same_channel(&self.self_tx));
        if still_owner {
            pipes.remove(&self.return_tag);
        }
        drop(pipes);
        if still_owner && self.peer_tag.is_some() {
            let mut joined = inner.joined.lock().unwrap();
            joined.remove(&self.return_tag);
            retire_outbound_everywhere(&self.anymone, self.return_tag);
        }
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
    #[error("payload too large: {size} bytes exceeds the subnet's {max}-byte message limit")]
    PayloadTooLarge { size: usize, max: usize },
}
