//! Scheduled (staggered, two-phase) Panetiere `Session`s.
//!
//! Each round's ciphertext is one joint KAHE plaintext: a tiny MSE reserving
//! `(rand, size)` message-vector slots for this round, plus a `vector_bytes`
//! vector fulfilling an earlier round's reservations (`codec::encode_at`/
//! `decode_ranges`, [`RESERVATION_TO_MSG_GAP`] rounds back). The leader
//! broadcasts decoded reservations as `Reservations` so clients can compute
//! the slot allocation (`codec::beacon`/`allocate`).
//!
//! Reuses the one-round flow's bucket/signature/decode machinery
//! (`PanetiereServerSession`, `PanetiereWire`, `PanetiereAggregatorSession`,
//! `PanetiereWatchSession`) — only the plaintext layout and checkpoint
//! cadence differ.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use chipmunk_code::KahePoly;
use panetiere::bulletin::ClientBulletinEntry;
use panetiere::codec;
use panetiere::channel::ChannelParams;
use panetiere::mse::MseEncoding;
use panetiere::pke;
use panetiere::protocol::client::run_client_round;
use panetiere::protocol::{message_polys, ClientId, ProtocolParams, ServerId};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::mpsc;

use crate::config::{
    ExchangePublicKeyWire, ProtocolConfig, Round, ScheduledPanetiereConfig, Subnet, SubnetId,
};
use crate::identity::{Identity, Pubkey};
use crate::log_target::{PANETIERE, SCHED};
use crate::panetiere::{
    client_id_from_pubkey, drain_inbound_upto, server_index, wire_round_past,
    PanetiereAggregatorSession, PanetiereObserverSession, PanetiereServerSession,
    PanetiereWatchSession, PanetiereWire, SetMode, PANETIERE_ROUND_RETENTION,
};
use crate::runtime::{
    aggregator_group_of, client_aggregator_topic, deadline_for, egress_dest,
    gossip_faults, handle_inbound, publish_and_loop_back, recv_any, round_at, route_to_pipe,
    subnet_aggregation, subnet_leader_pk, AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::Subscription;

/// `(rand, size)` per reservation: two `Z_t` symbols carrying the `u16`s
/// directly, so this channel is symbol-oriented and not byte-packed.
const SCHED_TOKEN_SYMBOLS: usize = 2;

/// `Reservations{R}` is fulfilled at round `R + RESERVATION_TO_MSG_GAP`. Must
/// be a fixed constant, not derived from a session's local clock: the relay
/// decodes one combined plaintext per round and can't distinguish which grant
/// round each client used, so every participant needs to land on the same
/// round independently. `R+2` is the floor: `Reservations{R}` broadcasts at
/// `end_round(R+1)`, leaving until the k=1 submit of `R+2` to arrive. Raise it
/// if `grant window missed` becomes common.
pub(crate) const RESERVATION_TO_MSG_GAP: Round = 2;

/// Must outlive `RESERVATION_TO_MSG_GAP` plus the inner session's own retention.
const SCHED_ENTRIES_RETENTION: Round = PANETIERE_ROUND_RETENTION + RESERVATION_TO_MSG_GAP;

/// Decoded reservation entries per round. Node-scoped (held on `AnymoneInner`,
/// handed to each worker generation, like the outbox): entries are public,
/// deterministic per-round facts every relay derives itself, and a message
/// vector unpacks `RESERVATION_TO_MSG_GAP` rounds after its reservations — a
/// reconfig respawn in that window must not lose them.
pub type ReservationEntries = Arc<Mutex<BTreeMap<Round, Vec<(u16, u16)>>>>;

/// MSE parameters for a reservation channel sized for `rho` expected
/// reservations per round; `prf_key` is domain-separated from the one-round
/// channel's (`0x5C` in `panetiere::channel_params`).
pub(crate) fn sched_channel_params(rho: u32, setup_seed: [u8; 32]) -> ChannelParams {
    let mut prf_key = setup_seed;
    prf_key[0] ^= 0x77;
    ChannelParams::for_symbols(rho, SCHED_TOKEN_SYMBOLS, prf_key)
}

pub(crate) fn msg_polys(vector_bytes: usize) -> usize {
    vector_bytes.div_ceil(codec::BYTES_PER_POLY)
}

/// Slot offsets (index-aligned with `entries`) and the poly count their grants
/// need. Pure in `entries`, so every participant sizes a round from the
/// leader's one public `Reservations` without further agreement.
fn allocation(entries: &[(u16, u16)], cap: usize) -> (Vec<Option<usize>>, usize) {
    let rands: Vec<u16> = entries.iter().map(|&(r, _)| r).collect();
    let sized: Vec<(u16, usize)> = entries.iter().map(|&(r, s)| (r, s as usize)).collect();
    let offs = codec::allocate(&sized, codec::beacon(&rands), cap);
    let used = sized
        .iter()
        .zip(&offs)
        .filter_map(|(&(_, size), off)| off.map(|o| o + size))
        .max()
        .unwrap_or(0);
    (offs, msg_polys(used))
}

/// Joint params: `mu_kahe` covers the reservation MSE plus the message vector.
pub(crate) fn setup_joint_pp(
    sched_mse: &ChannelParams,
    vector_bytes: usize,
    n_servers: usize,
    setup_seed: [u8; 32],
) -> Arc<ProtocolParams> {
    let mut rng = ChaCha20Rng::from_seed(setup_seed);
    let mu_kahe = sched_mse.n_polys() + msg_polys(vector_bytes);
    Arc::new(ProtocolParams::setup_with_kahe_dims(&mut rng, n_servers, mu_kahe))
}

/// Conservative upper bound on the largest per-round wire message a scheduled
/// Panetiere subnet broadcasts, sized from the real bulletin packing (never
/// `estimated_messages * message_size`).
pub(crate) fn max_wire_estimate(
    vector_bytes: usize,
    estimated_messages: u32,
    client_set_max: u32,
    n_relays: usize,
) -> usize {
    const FRAMING: usize = 512;
    let sched_mse = sched_channel_params(estimated_messages, [0u8; 32]);
    let n_polys = sched_mse.n_polys() + msg_polys(vector_bytes);
    // CS params depend only on n_servers; a tiny KAHE width skips sampling the
    // (large, unused-for-sizing) KAHE CRS — same trick as `panetiere::setup_pp`.
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let pp = ProtocolParams::setup_with_kahe_dims(&mut rng, n_relays.max(1), 1);
    let client_public = ClientBulletinEntry::packed_len(n_polys) + FRAMING;
    let server_public =
        pp.cs.aggregated_server_crypto_len(client_set_max) + client_set_max as usize * 4 + FRAMING;
    let decoded = vector_bytes + FRAMING;
    let reservations = 4 * estimated_messages as usize + FRAMING;
    client_public
        .max(server_public)
        .max(decoded)
        .max(reservations)
}

/// Scheduled-Panetiere `(ServerId, pke::PublicKey)` roster for sealing client
/// openings — relays whose exchange key is missing or undecodable are skipped.
fn seal_roster(
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
) -> Vec<(ServerId, pke::PublicKey)> {
    crate::keys::roster_seal_pubkeys(&subnet.relays, relay_xk)
        .into_iter()
        .map(|(i, pk)| (ServerId(i as u32), pk))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn client_session(
    pp: &Arc<ProtocolParams>,
    sched_mse: &ChannelParams,
    vector_bytes: usize,
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
    entries_by_round: ReservationEntries,
    node: Weak<AnymoneInner>,
    setup_seed: [u8; 32],
) -> Box<dyn Session> {
    let servers = seal_roster(relay_xk, subnet);
    if servers.len() != subnet.relays.len() {
        tracing::warn!(
            target: PANETIERE,
            have = servers.len(),
            need = subnet.relays.len(),
            "scheduled panetiere client: relay exchange keys incomplete"
        );
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut session = ScheduledPanetiereClientSession::new(
        pp.clone(),
        sched_mse.clone(),
        vector_bytes,
        client_id_from_pubkey(identity.pubkey()),
        servers,
        leader_pk,
        seed,
        entries_by_round,
    );
    session.set_node(node);
    session.set_setup_seed(setup_seed);
    Box::new(session)
}

#[allow(clippy::too_many_arguments)]
fn server_session(
    pp: &Arc<ProtocolParams>,
    sched_mse: &ChannelParams,
    vector_bytes: usize,
    cfg: &ScheduledPanetiereConfig,
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
    entries: ReservationEntries,
) -> Box<dyn Session> {
    let identity_pk = identity.pubkey();
    let server_id = ServerId(
        server_index(&subnet.relays, identity_pk).expect("server_session called on non-relay"),
    );
    let mut sorted = subnet.relays.clone();
    sorted.sort();
    let server_pubkeys = sorted
        .into_iter()
        .enumerate()
        .map(|(i, pk)| (ServerId(i as u32), pk))
        .collect();
    let aggregation = cfg.aggregation.as_ref().map(LeaderAggregation::from_config);
    let mode = if identity_pk == leader_pk {
        SetMode::Leader
    } else {
        SetMode::Follower { leader: leader_pk }
    };
    let mut session = ScheduledPanetiereServerSession::new(
        pp.clone(),
        sched_mse.clone(),
        vector_bytes,
        server_id,
        identity.clone(),
        mode,
        leader_pk,
        cfg.client_set_min,
        server_pubkeys,
        aggregation,
        entries,
    );
    session.set_client_set_max(cfg.client_set_max as usize);
    session.set_subnet(subnet.id);
    session.set_setup_seed(cfg.setup_seed);
    Box::new(session)
}

pub struct ScheduledPanetiereClientSession {
    pp: Arc<ProtocolParams>,
    sched_mse: ChannelParams,
    vector_bytes: usize,
    client_id: ClientId,
    servers: Vec<(ServerId, pke::PublicKey)>,
    leader_pk: PeerId,
    staged: Vec<Vec<u8>>,
    /// Bounced payloads, re-reserved on a per-round coin flip so an
    /// overloaded round drains instead of everyone retrying at once.
    deferred: Vec<Vec<u8>>,
    reserved: BTreeMap<Round, Vec<(u16, Vec<u8>)>>,
    granted: Vec<(Round, usize, Vec<u8>)>,
    /// Shared with this node's relay session for the subnet, so a client
    /// recreated by `sync_client_round` still knows the round's width.
    entries_by_round: ReservationEntries,
    /// `None` in session-level tests, which have no node to requeue to.
    node: Option<Weak<AnymoneInner>>,
    cur_round: Option<Round>,
    rng_seed: [u8; 32],
    cover_rate: f32,
    cover_rng: ChaCha20Rng,
    rand_rng: ChaCha20Rng,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
}

impl ScheduledPanetiereClientSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        sched_mse: ChannelParams,
        vector_bytes: usize,
        client_id: ClientId,
        servers: Vec<(ServerId, pke::PublicKey)>,
        leader_pk: Pubkey,
        rng_seed: [u8; 32],
        entries_by_round: ReservationEntries,
    ) -> Self {
        let mut cover_seed = rng_seed;
        cover_seed[0] ^= 0xA5;
        let mut rand_seed = rng_seed;
        rand_seed[0] ^= 0x91;
        ScheduledPanetiereClientSession {
            pp,
            sched_mse,
            vector_bytes,
            client_id,
            servers,
            leader_pk,
            staged: Vec::new(),
            deferred: Vec::new(),
            reserved: BTreeMap::new(),
            granted: Vec::new(),
            entries_by_round,
            node: None,
            cur_round: None,
            rng_seed,
            cover_rate: 1.0,
            cover_rng: ChaCha20Rng::from_seed(cover_seed),
            rand_rng: ChaCha20Rng::from_seed(rand_seed),
            setup_seed: [0u8; 32],
        }
    }

    pub(crate) fn set_node(&mut self, node: Weak<AnymoneInner>) {
        self.node = Some(node);
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.setup_seed = setup_seed;
    }
}

/// Return in-flight payloads to the outbox they were staged from, so a worker
/// respawn re-sends them instead of losing them. A placed grant is already out
/// of `granted`, so this re-sends without duplicating.
impl Drop for ScheduledPanetiereClientSession {
    fn drop(&mut self) {
        let staged = std::mem::take(&mut self.staged);
        let deferred = std::mem::take(&mut self.deferred);
        let reserved = std::mem::take(&mut self.reserved);
        let granted = std::mem::take(&mut self.granted);
        // Oldest first: `granted` and `reserved` have already waited rounds.
        let unsent: Vec<Vec<u8>> = granted
            .into_iter()
            .map(|(_, _, p)| p)
            .chain(reserved.into_values().flatten().map(|(_, p)| p))
            .chain(deferred)
            .chain(staged)
            .filter(|p| !p.is_empty())
            .collect();
        if unsent.is_empty() {
            return;
        }
        let Some(inner) = self.node.as_ref().and_then(|n| n.upgrade()) else {
            tracing::warn!(
                target: PANETIERE,
                client_id = self.client_id.0,
                unsent = unsent.len(),
                "scheduled panetiere client: session dropped with no node to requeue to; payloads lost"
            );
            return;
        };
        let mut outbox = inner.outbox.lock().unwrap();
        for payload in unsent.into_iter().rev() {
            outbox.push_front(payload);
        }
        tracing::debug!(
            target: PANETIERE,
            client_id = self.client_id.0,
            queued = outbox.len(),
            "scheduled panetiere client: session dropped; unsent payloads requeued"
        );
    }
}

impl Session for ScheduledPanetiereClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        // On a non-relay node no server session shares this store, so nothing
        // else would ever prune it. Same cutoff, so the two are idempotent.
        self.entries_by_round
            .lock()
            .unwrap()
            .retain(|r, _| *r >= round.saturating_sub(SCHED_ENTRIES_RETENTION));
        // A reservation whose grant never arrived (leader silence, GC) goes
        // back to staged for a fresh attempt.
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        let stale: Vec<Round> = self
            .reserved
            .keys()
            .filter(|&&r| r < cutoff)
            .copied()
            .collect();
        for r in stale {
            if let Some(entries) = self.reserved.remove(&r) {
                let real: Vec<Vec<u8>> = entries
                    .into_iter()
                    .map(|(_, payload)| payload)
                    .filter(|p| !p.is_empty())
                    .collect();
                if !real.is_empty() {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        reservation_round = r,
                        payloads = real.len(),
                        "scheduled panetiere client: grant never arrived; re-reserving"
                    );
                }
                self.deferred.extend(real);
            }
        }
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if from != self.leader_pk {
            return Vec::new();
        }
        let Ok(PanetiereWire::Reservations { round, entries }) =
            bincode::deserialize::<PanetiereWire>(&payload)
        else {
            return Vec::new();
        };
        if !crate::panetiere::round_in_window(round, self.cur_round) {
            return Vec::new();
        }
        let (offs, _) = allocation(&entries, self.vector_bytes);
        // Fixed, round-number-only — see `RESERVATION_TO_MSG_GAP`.
        let target = round + RESERVATION_TO_MSG_GAP;
        // Recorded even when we reserved nothing: a client with no grant still
        // has to match this round's entry width or the relay drops it.
        self.entries_by_round
            .lock()
            .unwrap()
            .entry(round)
            .or_insert(entries.clone());
        let Some(mine) = self.reserved.remove(&round) else {
            tracing::trace!(
                target: PANETIERE,
                round,
                "scheduled panetiere client: reservations for a round we did not reserve in"
            );
            return Vec::new();
        };
        for (rand, data) in mine {
            let idx = entries
                .iter()
                .position(|&(r, s)| r == rand && s as usize == data.len());
            // Zero-length (cover) grants are fulfilled too: a message at R
            // hides among clients present at BOTH R-GAP and R on this subnet,
            // so cover must return exactly like a real sender or the
            // intersection collapses to the real senders.
            match idx.and_then(|i| offs[i]) {
                Some(offset) => self.granted.push((target, offset, data)),
                // Dropped: rand tie, vector overflow, or no match — real
                // payloads retry with a fresh rand; a dropped cover
                // reservation just ends that chain.
                None if !data.is_empty() => {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        rand,
                        len = data.len(),
                        entries = entries.len(),
                        matched = idx.is_some(),
                        "scheduled panetiere client: reservation not granted; deferring payload"
                    );
                    self.deferred.push(data);
                }
                None => tracing::trace!(
                    target: PANETIERE,
                    round,
                    rand,
                    "scheduled panetiere client: cover reservation not granted"
                ),
            }
        }
        Vec::new()
    }

    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k != 1 {
            return Vec::new();
        }
        if self.servers.len() != self.pp.cs.n_servers {
            tracing::debug!(
                target: PANETIERE,
                round,
                have = self.servers.len(),
                need = self.pp.cs.n_servers,
                staged = self.staged.len(),
                granted = self.granted.len(),
                "scheduled panetiere client: missing relay exchange keys; skipping round"
            );
            return Vec::new();
        }

        let msg_bytes = round
            .checked_sub(RESERVATION_TO_MSG_GAP)
            .and_then(|prev| {
                let entries = self.entries_by_round.lock().unwrap();
                entries.get(&prev).map(|e| allocation(e, self.vector_bytes).1)
            })
            .unwrap_or(0)
            * codec::BYTES_PER_POLY;
        let mut msg_buf = vec![0u8; msg_bytes];
        let mut has_grant = false;
        let mut remaining = Vec::new();
        for (target, offset, data) in std::mem::take(&mut self.granted) {
            if target == round {
                let start = offset.min(msg_bytes);
                let end = (offset + data.len()).min(msg_bytes);
                // A grant whose slot runs past the vector delivers a truncated
                // payload — the receiver gets corrupt bytes, not nothing.
                if end - start < data.len() {
                    tracing::warn!(
                        target: PANETIERE,
                        round,
                        offset,
                        len = data.len(),
                        msg_bytes,
                        kept = end - start,
                        "scheduled panetiere client: granted slot overruns the message vector; payload truncated"
                    );
                }
                msg_buf[start..end].copy_from_slice(&data[..end - start]);
                has_grant = true;
            } else if target < round {
                // Missed its window (boundary skew) — retry with a fresh rand.
                if !data.is_empty() {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        grant_round = target,
                        len = data.len(),
                        "scheduled panetiere client: grant window missed; re-reserving"
                    );
                }
                self.deferred.push(data);
            } else {
                remaining.push((target, offset, data));
            }
        }
        self.granted = remaining;

        // Coin-flip drain of bounced payloads (see `deferred`).
        for data in std::mem::take(&mut self.deferred) {
            if self.rand_rng.gen::<bool>() {
                self.staged.push(data);
            } else {
                self.deferred.push(data);
            }
        }
        // A backlog that never shrinks is a payload the client will keep failing
        // to place, round after round.
        if !self.deferred.is_empty() {
            tracing::debug!(
                target: PANETIERE,
                round,
                deferred = self.deferred.len(),
                retrying = self.staged.len(),
                "scheduled panetiere client: payloads still waiting for a reservation"
            );
        }

        // Cover enacts the full scheduled flow: a fresh zero-length
        // reservation every round on the drawn subnet, and its zero-delivery
        // at r+GAP back on this subnet (via the grant, like a real message) —
        // presence in both rounds is what hides a real sender.
        if self.staged.is_empty() && self.cover_rng.gen::<f32>() < self.cover_rate {
            self.staged.push(Vec::new());
        }

        let mut sched = MseEncoding::new(self.sched_mse.mse().clone());
        let mut reservations = Vec::new();
        for data in std::mem::take(&mut self.staged) {
            let len = data.len();
            debug_assert!(
                len <= u16::MAX as usize,
                "pipe gate should have bounded payload size"
            );
            let rand: u16 = loop {
                let candidate = self.rand_rng.gen();
                if !reservations
                    .iter()
                    .any(|(r, _): &(u16, Vec<u8>)| *r == candidate)
                {
                    break candidate;
                }
            };
            sched.insert(&mut self.rand_rng, &[rand as i64, len as i64]);
            reservations.push((rand, data));
        }
        let real_reservation = !reservations.is_empty();
        if !reservations.is_empty() {
            self.reserved.insert(round, reservations);
        }

        // Nothing to submit: no message due, no reservation (real or cover).
        if !has_grant && !real_reservation {
            tracing::trace!(
                target: PANETIERE,
                round,
                client_id = self.client_id.0,
                "scheduled panetiere client: no grant and no reservation; silent this round"
            );
            return Vec::new();
        }

        let mut plaintext = sched.pack();
        plaintext.extend(codec::encode_raw(&msg_buf));
        debug_assert!(
            plaintext.len() <= message_polys(&self.pp),
            "joint pp must cover sched + the widest message vector"
        );

        let mut seed = self.rng_seed;
        seed[24..32].copy_from_slice(&round.to_le_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sid = crate::panetiere::session_id(&self.setup_seed, round);
        let round_out =
            run_client_round(&mut rng, &self.pp, &sid, self.client_id, plaintext, &self.servers);

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1 + self.servers.len());
        out.push(
            bincode::serialize(&PanetiereWire::ClientPublic {
                round,
                client_id: round_out.client_id.0,
                entry: round_out.encrypted_message.to_bytes(),
            })
            .expect("serialise client public"),
        );
        for (server_id, sealed) in round_out.sealed_openings {
            out.push(
                bincode::serialize(&PanetiereWire::Opening {
                    round,
                    client_id: round_out.client_id.0,
                    target_server: server_id.0,
                    sealed,
                })
                .expect("serialise opening"),
            );
        }
        out
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        self.staged.push(payload);
    }

    fn set_cover_rate(&mut self, rate: f32) {
        self.cover_rate = rate;
    }
}

/// Wraps the one-round [`PanetiereServerSession`] for its bucket/signature/
/// decode machinery, adding the sched/msg plaintext split and reservation hand-off.
pub struct ScheduledPanetiereServerSession {
    inner: PanetiereServerSession,
    sched_mse: ChannelParams,
    sched_polys: usize,
    vector_bytes: usize,
    is_leader: bool,
    leader_pk: PeerId,
    /// Labels this session's logs; a node relays several subnets at once.
    subnet: SubnetId,
    entries_by_round: ReservationEntries,
    /// Msg sections awaiting their reservation round's entries.
    pending_msg: BTreeMap<Round, Vec<KahePoly>>,
    /// Own round clock, from `begin_round`; bounds accepted `Reservations` rounds.
    cur_round: Option<Round>,
    /// First round this session ticked; rounds before it belong to a
    /// predecessor worker, or to before this subnet existed.
    first_round: Option<Round>,
}

impl ScheduledPanetiereServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        sched_mse: ChannelParams,
        vector_bytes: usize,
        server_id: ServerId,
        identity: Identity,
        mode: SetMode,
        leader_pk: Pubkey,
        min_clients: u32,
        server_pubkeys: HashMap<ServerId, Pubkey>,
        aggregation: Option<LeaderAggregation>,
        entries_by_round: ReservationEntries,
    ) -> Self {
        let is_leader = mode == SetMode::Leader;
        let sched_polys = sched_mse.n_polys();
        // inner.mse is unused: this wrapper never calls inner's own end_round.
        let mut inner = PanetiereServerSession::new(
            pp,
            sched_mse.clone(),
            server_id,
            identity,
            mode,
            min_clients,
            server_pubkeys,
            aggregation,
        );
        inner.set_entry_len(ClientBulletinEntry::packed_len(sched_polys));
        let mut session = ScheduledPanetiereServerSession {
            inner,
            sched_mse,
            sched_polys,
            vector_bytes,
            is_leader,
            leader_pk,
            subnet: 0,
            entries_by_round,
            pending_msg: BTreeMap::new(),
            cur_round: None,
            first_round: None,
        };
        session.sync_entry_lens();
        session
    }

    /// See [`crate::panetiere::PanetiereServerSession::set_client_set_max`].
    pub(crate) fn set_client_set_max(&mut self, max: usize) {
        self.inner.set_client_set_max(max);
    }

    pub(crate) fn set_subnet(&mut self, subnet: SubnetId) {
        self.subnet = subnet;
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.inner.set_setup_seed(setup_seed);
    }

    /// Entry width for every round the store can place. Re-scanned rather than
    /// pushed on decode: a successor worker inherits entries its predecessor
    /// deposited and so never "learns" them.
    fn sync_entry_lens(&mut self) {
        let widths: Vec<(Round, usize)> = {
            let map = self.entries_by_round.lock().unwrap();
            map.iter()
                .map(|(rd, e)| {
                    (
                        rd + RESERVATION_TO_MSG_GAP,
                        ClientBulletinEntry::packed_len(
                            self.sched_polys + allocation(e, self.vector_bytes).1,
                        ),
                    )
                })
                .collect()
        };
        for (round, len) in widths {
            self.inner.set_round_entry_len(round, len);
        }
    }
}

impl Session for ScheduledPanetiereServerSession {
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        self.first_round.get_or_insert(round);
        self.sync_entry_lens();
        self.inner.begin_round(round, now)
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if from == self.leader_pk {
            if let Ok(PanetiereWire::Reservations { round, entries }) =
                bincode::deserialize::<PanetiereWire>(&payload)
            {
                if crate::panetiere::round_in_window(round, self.cur_round) {
                    self.entries_by_round
                        .lock()
                        .unwrap()
                        .entry(round)
                        .or_insert(entries);
                    self.sync_entry_lens();
                } else {
                    // Without this round's entries we can't place any message
                    // vector fulfilling it, so those payloads never surface.
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        cur = ?self.cur_round,
                        entries = entries.len(),
                        "scheduled panetiere: Reservations outside round window, dropped"
                    );
                }
            }
        }
        self.inner.on_inbound(from, payload)
    }

    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        // A leader never receives its own `Reservations` over the wire, so on a
        // cutover boundary this is its only re-read before the round's entries.
        self.sync_entry_lens();
        if k == 3 && self.is_leader {
            self.inner.announce_settled(round)
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let mut outbound = self.inner.emit_server_publics(round);
        let mut decoded = Vec::new();

        let mut entries_map = self.entries_by_round.lock().unwrap();
        for (rd, plain) in self.inner.decode_settled() {
            let n = self.sched_polys.min(plain.len());
            let entries: Vec<(u16, u16)> =
                match MseEncoding::unpack(self.sched_mse.mse(), &plain[..n]).decode() {
                    Ok(elements) => elements
                        .into_iter()
                        .filter_map(|symbols| match symbols.as_slice() {
                            [rand, size] if *rand != 0 || *size != 0 => {
                                Some((*rand as u16, *size as u16))
                            }
                            _ => None,
                        })
                        .collect(),
                    Err(e) => {
                        // Peel stall loses the whole round's reservations (retried by clients).
                        tracing::warn!(
                            target: PANETIERE,
                            round = rd,
                            ?e,
                            "scheduled panetiere: reservation MSE peel failed; round's reservations lost"
                        );
                        Vec::new()
                    }
                };
            if self.is_leader {
                let wire = PanetiereWire::Reservations {
                    round: rd,
                    entries: entries.clone(),
                };
                outbound.push(bincode::serialize(&wire).expect("serialise reservations"));
            }
            entries_map.insert(rd, entries);
            self.pending_msg.insert(rd, plain[n..].to_vec());
        }

        // `checked_sub`, not saturating: rounds below the gap fulfil nothing, and
        // mapping them onto round 0's own reservations decodes garbage.
        let ready: Vec<Round> = self
            .pending_msg
            .keys()
            .copied()
            .filter(|rd| {
                rd.checked_sub(RESERVATION_TO_MSG_GAP)
                    .is_some_and(|prev| entries_map.contains_key(&prev))
            })
            .collect();
        for rd in ready {
            let plain = self.pending_msg.remove(&rd).expect("checked above");
            let prev = &entries_map[&(rd - RESERVATION_TO_MSG_GAP)];
            let (offs, _) = allocation(prev, self.vector_bytes);
            let ranges: Vec<(usize, usize)> = prev
                .iter()
                .zip(offs)
                .filter_map(|(&(_, size), off)| off.map(|o| (o, size as usize)))
                .filter(|&(_, size)| size > 0)
                .collect();
            // An all-cover round reserves only zero-length slots, so there is no
            // message vector to decode and `decode_raw` would reject the empty one.
            if ranges.is_empty() {
                continue;
            }
            let msgs = match codec::decode_ranges(&plain, &ranges) {
                Ok(payloads) => payloads
                    .into_iter()
                    .filter(|b| b.iter().any(|x| *x != 0))
                    .collect::<Vec<_>>(),
                Err(e) => {
                    tracing::warn!(
                        target: PANETIERE,
                        round = rd,
                        ranges = ranges.len(),
                        ?e,
                        "scheduled panetiere: message-vector decode failed; round's messages lost"
                    );
                    Vec::new()
                }
            };
            if !msgs.is_empty() {
                if self.is_leader {
                    let wire = PanetiereWire::Decoded {
                        round: rd,
                        payloads: msgs.clone(),
                    };
                    outbound.push(bincode::serialize(&wire).expect("serialise decoded"));
                }
                decoded.extend(msgs);
            }
        }

        self.inner.gc(round);
        let cutoff = round.saturating_sub(SCHED_ENTRIES_RETENTION);
        // A message vector whose reservation round's entries never arrived can't
        // be unpacked, so its senders' payloads are lost here. `predates_subnet`
        // marks the benign case: a subnet's own first rounds reference rounds
        // from before it existed, and those vectors are empty.
        for r in self.pending_msg.range(..cutoff) {
            let reservation_round = r.0.saturating_sub(RESERVATION_TO_MSG_GAP);
            tracing::warn!(
                target: PANETIERE,
                subnet = self.subnet,
                round = r.0,
                reservation_round,
                predates_subnet = self.first_round.is_some_and(|f| reservation_round < f),
                "scheduled panetiere: message vector aged out without its reservations"
            );
        }
        entries_map.retain(|r, _| *r >= cutoff);
        self.pending_msg.retain(|r, _| *r >= cutoff);
        drop(entries_map);
        self.sync_entry_lens();

        RoundOutcome {
            outbound,
            decoded,
            faults: Vec::new(),
        }
    }

    fn set_misbehavior(&mut self, mode: Option<Misbehavior>) {
        self.inner.set_misbehavior(mode);
    }
}

/// Shifts [`PanetiereAggregatorSession`]'s hardcoded k==1 to k==2 (k==1 is
/// the scheduled cadence's client-submit checkpoint), and tracks each round's
/// message-vector width: `run_aggregator_round` sums its group's ciphertexts,
/// and summing ragged ones panics.
pub(crate) struct ScheduledAggregatorSession {
    inner: PanetiereAggregatorSession,
    sched_polys: usize,
    vector_bytes: usize,
    entries_by_round: ReservationEntries,
    leader_pk: PeerId,
    cur_round: Option<Round>,
}

impl ScheduledAggregatorSession {
    pub(crate) fn new(
        mut inner: PanetiereAggregatorSession,
        sched_polys: usize,
        vector_bytes: usize,
        entries_by_round: ReservationEntries,
        leader_pk: Pubkey,
    ) -> Self {
        inner.set_entry_len(ClientBulletinEntry::packed_len(sched_polys));
        let mut session = ScheduledAggregatorSession {
            inner,
            sched_polys,
            vector_bytes,
            entries_by_round,
            leader_pk,
            cur_round: None,
        };
        session.sync_entry_lens();
        session
    }

    /// See [`ScheduledPanetiereServerSession::sync_entry_lens`]; a ragged group
    /// panics `run_aggregator_round`'s ciphertext sum.
    fn sync_entry_lens(&mut self) {
        let widths: Vec<(Round, usize)> = {
            let map = self.entries_by_round.lock().unwrap();
            map.iter()
                .map(|(rd, e)| {
                    (
                        rd + RESERVATION_TO_MSG_GAP,
                        ClientBulletinEntry::packed_len(
                            self.sched_polys + allocation(e, self.vector_bytes).1,
                        ),
                    )
                })
                .collect()
        };
        for (round, len) in widths {
            self.inner.set_round_entry_len(round, len);
        }
    }
}

impl Session for ScheduledAggregatorSession {
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        self.sync_entry_lens();
        self.inner.begin_round(round, now)
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if from == self.leader_pk {
            if let Ok(PanetiereWire::Reservations { round, entries }) =
                bincode::deserialize::<PanetiereWire>(&payload)
            {
                if crate::panetiere::round_in_window(round, self.cur_round) {
                    self.entries_by_round
                        .lock()
                        .unwrap()
                        .entry(round)
                        .or_insert(entries);
                    self.sync_entry_lens();
                }
            }
        }
        self.inner.on_inbound(from, payload)
    }

    fn checkpoint(&mut self, round: Round, k: u8, now: Instant) -> Vec<Vec<u8>> {
        self.sync_entry_lens();
        if k == 2 {
            self.inner.checkpoint(round, 1, now)
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, round: Round, now: Instant) -> RoundOutcome {
        self.inner.end_round(round, now)
    }
}

/// Self-contained scheduled-Panetiere subnet driver, mirroring
/// `panetiere::run_subnet`'s structure with a quarter-round checkpoint
/// cadence: k=1 client submit, k=2 aggregate (aggregated only), k=3 leader
/// announce, end_round shares + decode + broadcast.
pub(crate) async fn run_subnet(
    subnet: Subnet,
    relay_xk: Vec<(Pubkey, ExchangePublicKeyWire)>,
    inner: Arc<AnymoneInner>,
    mut stage_rx: mpsc::UnboundedReceiver<StageMsg>,
    mut subscriptions: Vec<Subscription>,
    base_round: Round,
    epoch_unix_ms: u64,
    armed: bool,
) {
    let cfg = match &subnet.protocol {
        ProtocolConfig::ScheduledPanetiere(c) => c.clone(),
        _ => unreachable!("panetiere_scheduled::run_subnet on a non-ScheduledPanetiere subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let sched_mse = sched_channel_params(cfg.estimated_messages, cfg.setup_seed);
    let pp = setup_joint_pp(
        &sched_mse,
        cfg.vector_bytes,
        subnet.relays.len(),
        cfg.setup_seed,
    );
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg_topic = client_aggregator_topic(&subnet, identity_pk);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(
                &pp,
                &sched_mse,
                cfg.vector_bytes,
                &cfg,
                &subnet,
                &inner.identity,
                leader_pk,
                inner.sched_reservation_entries(subnet.id),
            ),
        );
    } else {
        sessions.insert(
            SessionKey::Watch,
            Box::new(PanetiereWatchSession::new(leader_pk)),
        );
    }
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            let mut agg_session = PanetiereAggregatorSession::new(
                group,
                a.groups.len() as u32,
                inner.identity.clone(),
            );
            agg_session.set_client_set_max(crate::panetiere::aggregator_group_allowance(
                cfg.client_set_max,
                a.groups.len() as u32,
            ));
            sessions.insert(
                SessionKey::Aggregator,
                Box::new(ScheduledAggregatorSession::new(
                    agg_session,
                    sched_mse.n_polys(),
                    cfg.vector_bytes,
                    inner.sched_reservation_entries(subnet.id),
                    leader_pk,
                )),
            );
        }
    }
    let mut fault_monitor: Option<Box<dyn Session>> = if leader_pk == identity_pk {
        let mut roster = subnet.relays.clone();
        roster.sort();
        Some(Box::new(PanetiereObserverSession::new(
            roster,
            Some(leader_pk),
            FAULT_THRESHOLD,
        )))
    } else {
        None
    };

    let egress = |key: &SessionKey, bytes: &[u8]| {
        egress_dest(
            subnet.id,
            true,
            crate::panetiere::is_shares_topic_msg,
            crate::panetiere::is_client_public,
            client_agg_topic.as_deref(),
            key,
            bytes,
        )
    };

    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(4);
    let (k1_ms, k2_ms, k3_ms) = (dur_ms / 4, dur_ms / 2, 3 * dur_ms / 4);

    if armed
        && !crate::runtime::arm_until_cutover(
            base_round,
            epoch_unix_ms,
            dur_ms,
            &mut stage_rx,
            &mut cover_rate,
        )
        .await
    {
        return;
    }
    let mut final_round: Option<Round> = None;
    // Set on entering the drain round: the last round this worker owns. Wire
    // for later rounds belongs to the successor and is not ingested.
    let mut drain_cap: Option<Round> = None;
    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let spawn_round = round;
    tracing::debug!(
        target: SCHED,
        subnet = subnet.id,
        round,
        relay = subnet.relays.contains(&identity_pk),
        leader = leader_pk == identity_pk,
        vector_bytes = cfg.vector_bytes,
        dur_ms,
        "scheduled panetiere worker: start"
    );
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut k1_deadline = deadline - std::time::Duration::from_millis(dur_ms - k1_ms);
    let mut k2_deadline = deadline - std::time::Duration::from_millis(dur_ms - k2_ms);
    let mut k3_deadline = deadline - std::time::Duration::from_millis(dur_ms - k3_ms);
    let mut k1_done = false;
    let mut k2_done = false;
    let mut k3_done = false;

    if let Some(m) = fault_monitor.as_mut() {
        m.begin_round(round, Instant::now());
    }
    crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
        client_session(
            &pp,
            &sched_mse,
            cfg.vector_bytes,
            &relay_xk,
            &subnet,
            &inner.identity,
            leader_pk,
            inner.sched_reservation_entries(subnet.id),
            Arc::downgrade(&inner),
            cfg.setup_seed,
        )
    });
    let misbehavior = inner.misbehavior();
    let outs: Vec<(SessionKey, Vec<u8>)> = sessions
        .iter_mut()
        .flat_map(|(key, s)| {
            if let SessionKey::Server = key {
                s.set_misbehavior(misbehavior);
            }
            let key = *key;
            s.begin_round(round, Instant::now())
                .into_iter()
                .map(move |out| (key, out))
        })
        .collect();
    for (key, out) in outs {
        publish_and_loop_back(
            &mut sessions,
            &mut fault_monitor,
            &inner,
            &egress,
            identity_pk,
            key,
            out,
        )
        .await;
    }

    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep_until(k1_deadline), if !k1_done => {
                k1_done = true;
                drain_inbound_upto(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, drain_cap).await;
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.checkpoint(round, 1, Instant::now()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            _ = tokio::time::sleep_until(k2_deadline), if !k2_done => {
                k2_done = true;
                drain_inbound_upto(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, drain_cap).await;
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.checkpoint(round, 2, Instant::now()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            _ = tokio::time::sleep_until(k3_deadline), if !k3_done => {
                k3_done = true;
                drain_inbound_upto(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, drain_cap).await;
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.checkpoint(round, 3, Instant::now()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                drain_inbound_upto(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, drain_cap).await;
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults = Vec::new();
                let mut outs: Vec<(SessionKey, Vec<u8>)> = Vec::new();
                for (key, s) in sessions.iter_mut() {
                    let outcome = s.end_round(round, Instant::now());
                    outs.extend(outcome.outbound.into_iter().map(|out| (*key, out)));
                    decoded_all.extend(outcome.decoded);
                    faults.extend(outcome.faults);
                }
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
                let n_decoded = decoded_all.len();
                for bytes in decoded_all {
                    route_to_pipe(&inner, round, &bytes);
                }
                if n_decoded > 0 {
                    let _ = inner.events.send(crate::runtime::Event::RoundDecoded {
                        round,
                        subnet: subnet.id,
                        n_messages: n_decoded,
                    });
                }
                if drain_cap.is_some() {
                    tracing::debug!(
                        target: SCHED,
                        subnet = subnet.id,
                        round,
                        decoded = n_decoded,
                        "scheduled panetiere worker: drain exit"
                    );
                    return;
                }
                if let Some(m) = fault_monitor.as_mut() {
                    faults.extend(m.end_round(round, Instant::now()).faults);
                }
                crate::runtime::log_round_outcome("scheduled-panetiere", subnet.id, round, n_decoded, faults.len());
                let faults = faults
                    .into_iter()
                    .map(|f| (crate::panetiere::evidence_round(&f.evidence).unwrap_or(round), f))
                    .collect();
                if round >= spawn_round + crate::runtime::RECONFIG_FAULT_GRACE {
                    gossip_faults(&inner, subnet.id, identity_pk, faults).await;
                }

                if final_round.is_some_and(|f| round >= f) {
                    // A round decodes from shares arriving the round after it,
                    // so a relay stays one drain round: sessions that only
                    // consume and revisit, no new submissions against the
                    // successor. Watch-only workers hold no crypto state — the
                    // successor's watcher routes the drained leader's late
                    // `Decoded` instead.
                    if !sessions.contains_key(&SessionKey::Server) {
                        tracing::debug!(
                            target: SCHED,
                            subnet = subnet.id,
                            round,
                            "scheduled panetiere worker: graceful exit"
                        );
                        return;
                    }
                    tracing::debug!(
                        target: SCHED,
                        subnet = subnet.id,
                        round,
                        "scheduled panetiere worker: graceful exit; draining one round"
                    );
                    drain_cap = Some(round);
                    sessions.remove(&SessionKey::Client);
                    sessions.remove(&SessionKey::Aggregator);
                }
                let now_ms = crate::config::now_unix_ms();
                let next = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                if next > round + 1 {
                    tracing::debug!(
                        target: SCHED,
                        from = round,
                        to = next,
                        "scheduled panetiere worker: lagged past a round boundary, skipping rounds"
                    );
                }
                round = next;
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                k1_deadline = deadline - std::time::Duration::from_millis(dur_ms - k1_ms);
                k2_deadline = deadline - std::time::Duration::from_millis(dur_ms - k2_ms);
                k3_deadline = deadline - std::time::Duration::from_millis(dur_ms - k3_ms);
                k1_done = false;
                k2_done = false;
                k3_done = false;
                if drain_cap.is_none() {
                    if let Some(m) = fault_monitor.as_mut() {
                        m.begin_round(round, Instant::now());
                    }
                    crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
                        client_session(
                            &pp,
                            &sched_mse,
                            cfg.vector_bytes,
                            &relay_xk,
                            &subnet,
                            &inner.identity,
                            leader_pk,
                            inner.sched_reservation_entries(subnet.id),
                            Arc::downgrade(&inner),
                            cfg.setup_seed,
                        )
                    });
                    let misbehavior = inner.misbehavior();
                    let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                        .iter_mut()
                        .flat_map(|(key, s)| {
                            if let SessionKey::Server = key {
                                s.set_misbehavior(misbehavior);
                            }
                            let key = *key;
                            s.begin_round(round, Instant::now()).into_iter().map(move |out| (key, out))
                        })
                        .collect();
                    for (key, out) in outs {
                        publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                            .await;
                    }
                }
            }

            msg = recv_any(&mut subscriptions) => {
                if !drain_cap.is_some_and(|c| wire_round_past(&msg.payload, c)) {
                    handle_inbound(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, msg).await;
                }
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::SetCoverRate(rate) => cover_rate = rate,
                    StageMsg::Shutdown => {
                        final_round.get_or_insert(round + 1);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod sizing_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn wire_estimate_covers_real_messages() {
        let (vector_bytes, rho, cset, n_relays) = (256usize, 4u32, 40u32, 3usize);
        let est = max_wire_estimate(vector_bytes, rho, cset, n_relays);

        let sched_mse = sched_channel_params(rho, [1u8; 32]);
        let pp = setup_joint_pp(&sched_mse, vector_bytes, n_relays, [1u8; 32]);
        let servers: Vec<(ServerId, pke::PublicKey)> = (0..n_relays as u32)
            .map(|i| {
                (
                    ServerId(i),
                    pke::PrivateKey::generate(&mut rand::rngs::OsRng).public(),
                )
            })
            .collect();
        let leader = Identity::generate().pubkey();
        let mut c = ScheduledPanetiereClientSession::new(
            pp.clone(),
            sched_mse,
            vector_bytes,
            ClientId(1),
            servers,
            leader,
            [2u8; 32],
            ReservationEntries::default(),
        );
        // A grant filling the cap: the estimate bounds the widest round, and a
        // client with no reservations to fulfil now sends no message vector.
        c.on_inbound(
            leader,
            bincode::serialize(&PanetiereWire::Reservations {
                round: 0,
                entries: vec![(1, vector_bytes as u16)],
            })
            .unwrap(),
        );
        c.stage(vec![0xABu8; 64]);
        let client_public = c
            .checkpoint(RESERVATION_TO_MSG_GAP, 1, Instant::now())
            .iter()
            .map(|m| m.len())
            .max()
            .unwrap();
        assert!(
            est >= client_public,
            "estimate {est} < real ClientPublic {client_public}"
        );
        assert!(
            est >= pp.cs.aggregated_server_crypto_len(cset),
            "estimate omits the ServerPublic crypto term"
        );
        assert!(est >= vector_bytes, "estimate omits the Decoded term");
    }
}
