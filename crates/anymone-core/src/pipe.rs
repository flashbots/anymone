//! User-facing `Pipe`: open/bind a service tag, send and receive bytes.
//!
//! The Pipe layer hides round structure, subnet selection, and the inner
//! routing format. From the caller's point of view: bytes in, bytes out.

use std::sync::{Arc, Weak};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::Round;
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

/// What a `Pipe` yields on `recv`: the originator's return path, their bytes,
/// and the round the payload was decoded in. The tag is what the recipient
/// should pass to `send_to` for replies.
#[derive(Debug, Clone)]
pub struct PipeIncoming {
    pub return_tag: RouteTag,
    pub payload: Vec<u8>,
    pub round: Round,
}

/// The largest `send`/`send_to`/`send_unlinkable` payload that fits in one
/// message on a subnet whose carrier reports `message_size`, computed from
/// the real `Frame::Raw` + `PipeMessage` encoding (not an estimate), so a
/// caller can reject an oversized payload before attempting a send.
pub fn max_message_payload(message_size: usize) -> usize {
    message_size.saturating_sub(framing_overhead())
}

/// `Frame::Raw` header plus the bincode `PipeMessage` envelope a payload rides
/// in. The `Vec` length prefix is fixed-width, so this is exact for any payload.
fn framing_overhead() -> usize {
    let probe = PipeMessage {
        return_tag: RouteTag([0u8; SERVICE_TAG_LEN]),
        payload: Vec::new(),
    };
    let empty_encoded = bincode::serialize(&probe)
        .expect("PipeMessage serialises")
        .len();
    1 + SERVICE_TAG_LEN + empty_encoded // discriminant + dst + envelope
}

pub struct Pipe {
    sender: PipeSender,
    receiver: PipeReceiver,
}

#[derive(Clone)]
pub struct PipeSender {
    state: Arc<PipeState>,
}

pub struct PipeReceiver {
    state: Arc<PipeState>,
    inbound: mpsc::UnboundedReceiver<PipeIncoming>,
}

struct PipeState {
    anymone: Weak<AnymoneInner>,
    peer_tag: Option<ServiceTag>,
    return_tag: RouteTag,
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
        let state = Arc::new(PipeState {
            anymone,
            peer_tag,
            return_tag,
            self_tx,
        });
        Pipe {
            sender: PipeSender {
                state: state.clone(),
            },
            receiver: PipeReceiver { state, inbound },
        }
    }

    /// Both halves retain the pipe registration until the last half is dropped.
    pub fn split(self) -> (PipeSender, PipeReceiver) {
        (self.sender, self.receiver)
    }

    pub fn return_tag(&self) -> RouteTag {
        self.sender.return_tag()
    }
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.sender.send(payload)
    }
    pub async fn send_to(
        &self,
        dst: impl Into<RouteTag>,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        self.sender.send_to(dst, payload)
    }
    pub async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), SendError> {
        self.sender.send_unlinkable(payload)
    }
    pub fn check_size(&self, payload_len: usize) -> Result<(), SendError> {
        self.sender.check_size(payload_len)
    }
    pub async fn recv(&mut self) -> Option<PipeIncoming> {
        self.receiver.recv().await
    }
    pub fn try_recv(&mut self) -> Option<PipeIncoming> {
        self.receiver.try_recv()
    }
}

impl PipeSender {
    /// Our own delivery address.
    pub fn return_tag(&self) -> RouteTag {
        self.state.return_tag
    }

    /// Send `payload` to the pipe's bound counterparty (client-side only).
    pub fn send(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let dst = self.state.peer_tag.ok_or(SendError::NoPeerTag)?;
        self.send_to(dst, payload)
    }

    /// Send `payload` addressed to `dst` (a service tag, or a peer's return
    /// path). Service-side replies pass the request's `return_tag`.
    pub fn send_to(&self, dst: impl Into<RouteTag>, payload: Vec<u8>) -> Result<(), SendError> {
        self.send_inner(dst.into(), self.state.return_tag, payload)
    }

    /// Send to the bound service with a one-off random return path instead of
    /// this pipe's own: the recipient cannot link this message to any other
    /// send from this pipe (or reply to it). For reply-less broadcast traffic
    /// where reusing `return_tag` across sends would deanonymize the sender
    /// as "the same submitter" even though individual messages stay unlinked
    /// from the pipe's identity otherwise.
    pub fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), SendError> {
        let dst = self.state.peer_tag.ok_or(SendError::NoPeerTag)?;
        let mut bytes = [0u8; SERVICE_TAG_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        self.send_inner(dst.into(), RouteTag(bytes), payload)
    }

    /// Whether a `payload_len`-byte payload fits one message, by the same
    /// encoding `send*` uses — so a caller can refuse an oversized payload
    /// before queueing it rather than at the head of a queue.
    pub fn check_size(&self, payload_len: usize) -> Result<(), SendError> {
        let anymone = self.state.anymone.upgrade().ok_or(SendError::Closed)?;
        Self::check_size_against(&anymone, payload_len)
    }

    /// Reject payloads too big for one message rather than truncating/dropping
    /// them downstream; fragmentation across rounds is a later batch. The
    /// per-round draw can land the frame on any runnable subnet, so it must fit
    /// the smallest.
    fn check_size_against(anymone: &AnymoneInner, payload_len: usize) -> Result<(), SendError> {
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
        let framed = framing_overhead() + payload_len;
        if framed > max {
            return Err(SendError::PayloadTooLarge { size: framed, max });
        }
        Ok(())
    }

    fn send_inner(
        &self,
        dst: RouteTag,
        return_tag: RouteTag,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        let anymone = self.state.anymone.upgrade().ok_or(SendError::Closed)?;
        Self::check_size_against(&anymone, payload.len())?;
        let msg = PipeMessage {
            return_tag,
            payload,
        };
        let data = bincode::serialize(&msg).map_err(|e| SendError::Encode(e.to_string()))?;
        let framed = 1 + SERVICE_TAG_LEN + data.len();
        let mut bytes = Vec::with_capacity(framed);
        Frame::Raw { dst, data: &data }.encode(&mut bytes);
        queue_outbound(&self.state.anymone, bytes)
    }
}

impl PipeReceiver {
    pub fn return_tag(&self) -> RouteTag {
        self.state.return_tag
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

impl Drop for PipeState {
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
