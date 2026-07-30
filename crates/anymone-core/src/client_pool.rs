//! The sending side of a channel: the caller's own client plus *virtual
//! clients* spawned when messages queue up.
//!
//! One client submits at most one message per round — the node-level outbox is
//! drained a single frame per round, by whichever subnet worker holds that
//! round's participation draw — so more clients is the only way to send
//! concurrently. A [`ClientPool`] therefore keeps the queue itself and hands a
//! message to a client only once that client can carry it, minting a virtual
//! client (fresh ephemeral identity, own transport, own draw) while messages are
//! still waiting. Committing a payload to one client up front would strand it
//! behind that client's rounds, which no later client could take over.
//!
//! The pool leaks this process's demand: it grows while the caller is busy and
//! the client count is public. It buys concurrency, not anonymity.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::log_target::SCHED;
use crate::pipe::{Pipe, SendError};
use crate::runtime::Anymone;
use crate::wire::ServiceTag;

/// Mints a started client node on the same network as the caller's own — which
/// transport that is stays the caller's business
/// ([`crate::cw::stream_client_spawner`], or in-memory handles in a demo).
/// `None` on failure; the spawner reports why.
pub type SpawnClient =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Anymone>> + Send>> + Send + Sync>;

/// Well past any protocol's reservation-to-message gap, so an idle client is
/// never retired while a payload it staged is still in flight in its session.
const VIRTUAL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const REAP_INTERVAL: Duration = Duration::from_secs(10);

const ATTACH_RETRY: Duration = Duration::from_millis(500);

const VIRTUAL_ATTACH_TRIES: u32 = 20;

/// Already minutes of backlog at one frame per round; past it, accepting more
/// only grows memory to hide a channel that cannot keep up.
const MAX_QUEUED: usize = 64;

/// Distribution ticks per round. The queue has to reach a client's outbox before
/// the round boundary that stages it, so this only has to beat a round.
const TICKS_PER_ROUND: u32 = 4;

/// A client contributes cover for this many rounds before it is handed a real
/// message: its first submission can miss that round's canonical client set,
/// which loses the message rather than delaying it.
const WARMUP_ROUNDS: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("channel is not placed on a subnet yet")]
    NotAttached,
    #[error("channel is saturated: {queued} messages already queued")]
    Saturated { queued: usize },
    #[error(transparent)]
    Send(#[from] SendError),
}

/// One client backing the channel; dropping it tears that client down. Its pipe
/// is never received on — the pool sends unlinkably, nothing comes back to it.
struct Member {
    anymone: Anymone,
    pipe: Pipe,
    joined: Instant,
    last_send: Mutex<Instant>,
    virtual_client: bool,
}

impl Member {
    fn new(anymone: Anymone, pipe: Pipe, virtual_client: bool) -> Arc<Self> {
        Arc::new(Member {
            anymone,
            pipe,
            joined: Instant::now(),
            last_send: Mutex::new(Instant::now()),
            virtual_client,
        })
    }

    /// Ready for another message: nothing of this client's is still waiting for a
    /// round, and it has been in the client set long enough to be decoded.
    fn free(&self) -> bool {
        self.anymone.queued_outbound() == 0
            && self.joined.elapsed() >= WARMUP_ROUNDS * self.anymone.round_duration()
    }

    fn idle_for(&self) -> Duration {
        self.last_send.lock().unwrap().elapsed()
    }
}

struct PoolInner {
    tag: ServiceTag,
    spawn: SpawnClient,
    max_clients: usize,
    /// The caller's own client first, virtual clients after it.
    members: Mutex<Vec<Arc<Member>>>,
    /// Accepted messages, oldest first, not yet handed to any client.
    queue: Mutex<VecDeque<Vec<u8>>>,
    /// One spawn at a time: a burst would otherwise mint a client per message.
    spawning: AtomicBool,
}

/// Clients backing one channel's sends. Cloning shares the pool.
#[derive(Clone)]
pub struct ClientPool(Arc<PoolInner>);

impl ClientPool {
    /// Back `tag`'s sends with `own`, up to `max_clients` in total (`1` disables
    /// growth). Returns before attaching: until the tag is placed on a subnet,
    /// [`send`](Self::send) reports [`PoolError::NotAttached`].
    pub fn new(own: Anymone, tag: ServiceTag, spawn: SpawnClient, max_clients: usize) -> Self {
        let inner = Arc::new(PoolInner {
            tag,
            spawn,
            max_clients: max_clients.max(1),
            members: Mutex::new(Vec::new()),
            queue: Mutex::new(VecDeque::new()),
            spawning: AtomicBool::new(false),
        });
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                if let Some(pipe) = open_when_placed(&own, inner.tag, None).await {
                    inner
                        .members
                        .lock()
                        .unwrap()
                        .push(Member::new(own, pipe, false));
                }
            });
        }
        tokio::spawn(distribute(Arc::downgrade(&inner)));
        tokio::spawn(reap(Arc::downgrade(&inner)));
        ClientPool(inner)
    }

    /// Queue `payload` as one message on the channel. Rejects a payload no
    /// carrier can hold up front, so the refusal reaches its submitter rather
    /// than the queue's head.
    pub fn send(&self, payload: Vec<u8>) -> Result<(), PoolError> {
        let member = self
            .0
            .members
            .lock()
            .unwrap()
            .first()
            .cloned()
            .ok_or(PoolError::NotAttached)?;
        member.pipe.check_size(payload.len())?;
        let mut queue = self.0.queue.lock().unwrap();
        if queue.len() >= MAX_QUEUED {
            return Err(PoolError::Saturated { queued: queue.len() });
        }
        queue.push_back(payload);
        Ok(())
    }

    /// `0` before the tag is placed, `1` once the caller's own client attached.
    pub fn clients(&self) -> usize {
        self.0.members.lock().unwrap().len()
    }

    /// Messages accepted but not yet on the wire: waiting for a client, or in
    /// one's outbox waiting for its round.
    pub fn queued(&self) -> usize {
        let waiting = self.0.queue.lock().unwrap().len();
        let staged: usize = self
            .0
            .members
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.anymone.queued_outbound())
            .sum();
        waiting + staged
    }
}

impl PoolInner {
    /// Hand the head of the queue to each client that can carry a message this
    /// round, and grow the pool if messages are still waiting after that.
    async fn dispatch(self: &Arc<Self>) {
        let members: Vec<Arc<Member>> = self.members.lock().unwrap().clone();
        for member in members {
            if !member.free() {
                continue;
            }
            let Some(payload) = self.queue.lock().unwrap().pop_front() else {
                return;
            };
            let len = payload.len();
            match member.pipe.send_unlinkable(payload.clone()).await {
                Ok(()) => *member.last_send.lock().unwrap() = Instant::now(),
                // A shrunk carrier can refuse what was accepted under the old
                // one; requeueing that forever would stall every message behind
                // it.
                Err(e @ SendError::PayloadTooLarge { .. }) => {
                    warn!(target: SCHED, len, error = %e, "client pool: message dropped")
                }
                Err(e) => {
                    debug!(target: SCHED, error = %e, "client pool: send failed, message requeued");
                    self.queue.lock().unwrap().push_front(payload);
                    return;
                }
            }
        }
        if !self.queue.lock().unwrap().is_empty() {
            self.grow();
        }
    }

    /// A round's worth of a member's cadence, or a default before one attached.
    fn tick(&self) -> Duration {
        self.members
            .lock()
            .unwrap()
            .first()
            .map(|m| m.anymone.round_duration() / TICKS_PER_ROUND)
            .unwrap_or(ATTACH_RETRY)
            .max(Duration::from_millis(10))
    }

    fn grow(self: &Arc<Self>) {
        if self.members.lock().unwrap().len() >= self.max_clients {
            return;
        }
        if self.spawning.swap(true, Ordering::SeqCst) {
            return;
        }
        let inner = self.clone();
        tokio::spawn(async move {
            match (inner.spawn)().await {
                Some(anymone) => {
                    match open_when_placed(&anymone, inner.tag, Some(VIRTUAL_ATTACH_TRIES)).await {
                        Some(pipe) => {
                            let mut members = inner.members.lock().unwrap();
                            members.push(Member::new(anymone, pipe, true));
                            info!(
                                target: SCHED,
                                clients = members.len(),
                                "client pool: virtual client joined"
                            );
                        }
                        None => warn!(
                            target: SCHED,
                            "client pool: virtual client never got a pipe; not added"
                        ),
                    }
                }
                None => warn!(target: SCHED, "client pool: virtual client failed to start"),
            }
            inner.spawning.store(false, Ordering::SeqCst);
        });
    }
}

/// Open a send-only pipe on `tag`, waiting for the committee to place it.
/// `tries` bounds the wait; `None` waits indefinitely.
async fn open_when_placed(anymone: &Anymone, tag: ServiceTag, tries: Option<u32>) -> Option<Pipe> {
    let mut waited = 0u32;
    loop {
        match anymone.open(tag).await {
            Ok(pipe) => return Some(pipe),
            Err(e) => {
                if tries.is_some_and(|t| waited >= t) {
                    debug!(target: SCHED, error = %e, "client pool: gave up opening a pipe");
                    return None;
                }
                if waited % 20 == 0 {
                    debug!(
                        target: SCHED,
                        waited_ms = waited * ATTACH_RETRY.as_millis() as u32,
                        error = %e,
                        "client pool: waiting for the channel to be placed"
                    );
                }
                waited += 1;
                tokio::time::sleep(ATTACH_RETRY).await;
            }
        }
    }
}

/// Move the queue onto clients as their rounds come up.
async fn distribute(pool: Weak<PoolInner>) {
    let mut tick = ATTACH_RETRY;
    loop {
        tokio::time::sleep(tick).await;
        let Some(inner) = pool.upgrade() else { return };
        tick = inner.tick();
        inner.dispatch().await;
    }
}

/// Retire idle virtual clients — never the caller's own.
async fn reap(pool: Weak<PoolInner>) {
    loop {
        tokio::time::sleep(REAP_INTERVAL).await;
        let Some(inner) = pool.upgrade() else { return };
        let mut members = inner.members.lock().unwrap();
        let before = members.len();
        members.retain(|m| {
            !m.virtual_client
                || m.anymone.queued_outbound() > 0
                || m.idle_for() < VIRTUAL_IDLE_TIMEOUT
        });
        if members.len() < before {
            info!(
                target: SCHED,
                retired = before - members.len(),
                clients = members.len(),
                "client pool: idle virtual clients retired"
            );
        }
    }
}
