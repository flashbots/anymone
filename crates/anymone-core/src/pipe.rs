//! User-facing `Pipe`: open/bind a service tag, send and receive bytes.
//!
//! The Pipe layer hides round structure, subnet selection, and the inner
//! routing format. From the caller's point of view: bytes in, bytes out.

use std::sync::Weak;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::runtime::{queue_outbound, subnet_runnable, AnymoneInner};
use crate::wire::{Frame, RouteTag, ServiceTag, SERVICE_TAG_LEN};

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

/// The largest `send`/`send_to`/`send_unlinkable` payload that fits in one
/// message on a subnet whose carrier reports `message_size`, computed from
/// the real `Frame::Raw` + `PipeMessage` encoding (not an estimate), so a
/// caller can reject an oversized payload before attempting a send.
pub fn max_message_payload(message_size: usize) -> usize {
    let probe = PipeMessage {
        return_tag: RouteTag([0u8; SERVICE_TAG_LEN]),
        payload: Vec::new(),
    };
    let empty_encoded = bincode::serialize(&probe)
        .expect("PipeMessage serialises")
        .len();
    let frame_header = 1 + SERVICE_TAG_LEN; // Frame::Raw discriminant + dst
    message_size.saturating_sub(frame_header + empty_encoded)
}

pub struct Pipe {
    anymone: Weak<AnymoneInner>,
    /// For client-opened pipes: the bound service tag (so `send` knows where).
    /// For service-bound pipes: `None` (caller must use `send_to`).
    peer_tag: Option<ServiceTag>,
    /// Our own delivery address — for client pipes a random per-pipe return
    /// path, for service pipes the service tag as a delivery address.
    return_tag: RouteTag,
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
        inbound: mpsc::UnboundedReceiver<PipeIncoming>,
        self_tx: mpsc::UnboundedSender<PipeIncoming>,
    ) -> Self {
        Pipe {
            anymone,
            peer_tag,
            return_tag,
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
        self.send_inner(dst.into(), self.return_tag, payload).await
    }

    /// Send to the bound service with a one-off random return path instead of
    /// this pipe's own: the recipient cannot link this message to any other
    /// send from this pipe (or reply to it). For reply-less broadcast traffic
    /// where reusing `return_tag` across sends would deanonymize the sender
    /// as "the same submitter" even though individual messages stay unlinked
    /// from the pipe's identity otherwise.
    pub async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let dst = self.peer_tag.ok_or(SendError::NoPeerTag)?;
        let mut bytes = [0u8; SERVICE_TAG_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        self.send_inner(dst.into(), RouteTag(bytes), payload).await
    }

    async fn send_inner(
        &self,
        dst: RouteTag,
        return_tag: RouteTag,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        let anymone = self.anymone.upgrade().ok_or(SendError::Closed)?;
        let msg = PipeMessage {
            return_tag,
            payload,
        };
        let data = bincode::serialize(&msg).map_err(|e| SendError::Encode(e.to_string()))?;
        // Reject payloads too big for one message rather than truncating/dropping
        // them downstream; fragmentation across rounds is a later batch. The
        // per-round draw can land the frame on any runnable subnet, so it must
        // fit the smallest.
        let framed = 1 + SERVICE_TAG_LEN + data.len();
        let max = anymone
            .config
            .read()
            .unwrap()
            .body
            .subnets
            .iter()
            .filter(|s| subnet_runnable(s))
            .map(|s| s.protocol.message_size())
            .min()
            .ok_or(SendError::SubnetGone)?;
        if framed > max {
            return Err(SendError::PayloadTooLarge { size: framed, max });
        }
        let mut bytes = Vec::with_capacity(framed);
        Frame::Raw { dst, data: &data }.encode(&mut bytes);
        queue_outbound(&self.anymone, bytes)
    }

    /// Receive the next inbound message, or `None` once the pipe is closed.
    pub async fn recv(&mut self) -> Option<PipeIncoming> {
        self.inbound.recv().await
    }

    /// Non-blocking receive: `Some` if a message is already queued, `None` if
    /// the inbox is currently empty (whether or not the pipe is closed).
    pub fn try_recv(&mut self) -> Option<PipeIncoming> {
        self.inbound.try_recv().ok()
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
            inner.joined.lock().unwrap().remove(&self.return_tag);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("pipe was opened without a peer tag; use send_to(dst, ...)")]
    NoPeerTag,
    #[error("anymone instance shut down")]
    Closed,
    #[error("no runnable subnet in the current configuration")]
    SubnetGone,
    #[error("encode: {0}")]
    Encode(String),
    #[error("payload too large: {size} bytes exceeds the subnet's {max}-byte message limit")]
    PayloadTooLarge { size: usize, max: usize },
}
