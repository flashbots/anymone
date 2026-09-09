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
//! (`PanetiereServerSession`, `PanetiereWire`, `PanetiereWatchSession`) — only
//! the plaintext layout and checkpoint cadence differ.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use panetiere::channel::ChannelParams;
use panetiere::codec;
use panetiere::mse::MseEncoding;
use panetiere::pke;
use panetiere::protocol::client::RsClientRound;
use panetiere::protocol::{message_polys, ClientId, ProtocolParams, ServerId};
use panetiere::KahePoly;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::config::{
    ExchangePublicKeyWire, Round, ScheduledPanetiereConfig, SetFormation, Subnet, SubnetId,
};
use crate::identity::{Identity, Pubkey};
use crate::log_target::PANETIERE;
use crate::panetiere::{
    bundle_wire, client_round, client_slice_wire, derive_post_key, fragment_wire, server_index,
    set_roster, verify_batch, ClientSetState, PanetiereServerSession, PanetiereWire, SetMode,
    PANETIERE_ROUND_RETENTION,
};
use crate::runtime::AnymoneInner;
use crate::session::{GoodClients, Misbehavior, PeerId, RoundOutcome, Session};

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

/// Reservation channel and joint params: `mu_kahe` covers the reservation MSE
/// plus the message vector. No encoding knob — the reservation cells are sums
/// mod `T_MODULUS_DEFAULT`, which a smaller prime could not carry.
pub fn params_for(
    cfg: &ScheduledPanetiereConfig,
    n_servers: usize,
) -> (ChannelParams, Arc<ProtocolParams>) {
    let sched_mse = sched_channel_params(cfg.estimated_messages, cfg.setup_seed);
    let mut rng = ChaCha20Rng::from_seed(cfg.setup_seed);
    let mu_kahe = sched_mse.n_polys() + msg_polys(cfg.vector_bytes);
    let mut pp = ProtocolParams::setup_rs_mode(
        &mut rng,
        n_servers,
        mu_kahe,
        cfg.threshold as usize,
        n_servers,
        sched_mse.plaintext_modulus(),
        cfg.client_set_max.max(1) as usize,
        cfg.setup_seed,
    );
    pp.shamir = panetiere::sss::ShamirParams::new(cfg.threshold as usize, n_servers);
    pp.min_clients = cfg.client_set_min.max(1) as usize;
    (sched_mse, Arc::new(pp))
}

/// Conservative upper bound on the largest per-round wire message a scheduled
/// Panetiere subnet broadcasts, sized from the real bulletin packing (never
/// `estimated_messages * message_size`).
pub(crate) fn max_wire_estimate(
    vector_bytes: usize,
    estimated_messages: u32,
    client_set_max: u32,
    n_relays: usize,
    threshold: u32,
    set_formation: SetFormation,
) -> usize {
    const FRAMING: usize = 512;
    let sched_mse = sched_channel_params(estimated_messages, [0u8; 32]);
    let n_polys = sched_mse.n_polys() + msg_polys(vector_bytes);
    let reservations = 4 * estimated_messages as usize + FRAMING;
    crate::panetiere::rs_wire_estimate(n_polys, vector_bytes, client_set_max, n_relays, threshold)
        .max(reservations)
        .max(crate::panetiere::consensus_wire_estimate(
            n_polys,
            client_set_max,
            n_relays,
            threshold,
            set_formation,
        ))
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
pub(crate) fn client_session(
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
    consensus: bool,
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
        identity.clone(),
        servers,
        leader_pk,
        seed,
        entries_by_round,
    );
    session.set_node(node);
    session.set_setup_seed(setup_seed);
    if consensus {
        match set_roster(relay_xk, subnet) {
            Some(pks) => session.set_consensus(pks),
            None => tracing::error!(
                target: PANETIERE,
                subnet = subnet.id,
                "scheduled panetiere client: consensus set formation needs every relay's \
                 client-set key; this client cannot submit"
            ),
        }
    }
    Box::new(session)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn server_session(
    pp: &Arc<ProtocolParams>,
    sched_mse: &ChannelParams,
    vector_bytes: usize,
    cfg: &ScheduledPanetiereConfig,
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
    entries: ReservationEntries,
    good_clients: GoodClients,
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
    let consensus = cfg.set_formation == SetFormation::Consensus;
    let mode = if consensus {
        SetMode::Consensus {
            publisher: leader_pk,
        }
    } else if identity_pk == leader_pk {
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
        server_pubkeys,
        entries,
    );
    session.set_client_set_max(cfg.client_set_max as usize);
    session.set_subnet(subnet.id);
    session.set_setup_seed(cfg.setup_seed);
    session.set_good_clients(good_clients);
    if consensus {
        match set_roster(relay_xk, subnet) {
            Some(pks) => {
                session.set_consensus_keys(identity.exchange().set_signing_key().clone(), pks)
            }
            None => tracing::error!(
                target: PANETIERE,
                subnet = subnet.id,
                "scheduled panetiere server: consensus set formation needs every relay's \
                 client-set key; this relay forms no set"
            ),
        }
    }
    Box::new(session)
}

pub struct ScheduledPanetiereClientSession {
    pp: Arc<ProtocolParams>,
    sched_mse: ChannelParams,
    vector_bytes: usize,
    identity: Identity,
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
    /// Signs the RS bulletin post; see [`derive_post_key`].
    post_key: panetiere::sig::SigningKey,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
    client_round: Option<(Round, RsClientRound)>,
    /// Consensus set formation: the roster receipts verify under, and the
    /// rounds whose bundles are still collecting them.
    set_pks: Option<Vec<panetiere::sig::VerifyingKey>>,
    set_rounds: BTreeMap<Round, ClientSetState>,
}

impl ScheduledPanetiereClientSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        sched_mse: ChannelParams,
        vector_bytes: usize,
        identity: Identity,
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
            client_id: crate::panetiere::client_id_from_pubkey(identity.pubkey()),
            identity,
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
            post_key: derive_post_key(rng_seed),
            setup_seed: [0u8; 32],
            client_round: None,
            set_pks: None,
            set_rounds: BTreeMap::new(),
        }
    }

    pub(crate) fn set_node(&mut self, node: Weak<AnymoneInner>) {
        self.node = Some(node);
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.setup_seed = setup_seed;
        self.client_round = None;
    }

    /// See [`crate::panetiere::PanetiereClientSession::set_consensus`].
    pub fn set_consensus(&mut self, set_pks: Vec<panetiere::sig::VerifyingKey>) {
        self.set_pks = Some(set_pks);
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
        if let Some(set_pks) = self.set_pks.as_ref() {
            if let Ok(PanetiereWire::SetBatch { round, data }) =
                bincode::deserialize::<PanetiereWire>(&payload)
            {
                let sid = crate::panetiere::session_id(&self.setup_seed, round);
                if let (Some(state), Some(batch)) = (
                    self.set_rounds.get_mut(&round),
                    crate::client_set::ReceiptBatch::unpack(&data)
                        .filter(|b| verify_batch(&sid, b, set_pks)),
                ) {
                    state.note_batch(&batch, self.client_id);
                }
                return Vec::new();
            }
        }
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
        if k == 2 && self.servers.len() == self.pp.cs.n_servers {
            let next = round.saturating_add(1);
            if !self
                .client_round
                .as_ref()
                .is_some_and(|(prepared_round, _)| *prepared_round == next)
            {
                self.client_round = Some((
                    next,
                    client_round(
                        &self.pp,
                        &self.setup_seed,
                        next,
                        self.client_id,
                        &self.servers,
                        self.rng_seed,
                    ),
                ));
            }
            return Vec::new();
        }
        if self.set_pks.is_some() && k == crate::panetiere::K_REPAIR {
            let Some(state) = self.set_rounds.get_mut(&round) else {
                return Vec::new();
            };
            let sid = crate::panetiere::session_id(&self.setup_seed, round);
            return fragment_wire(&self.pp, &sid, round, state, &self.post_key, &self.identity);
        }
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
                entries
                    .get(&prev)
                    .map(|e| allocation(e, self.vector_bytes).1)
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

        let mut sched = MseEncoding::new(
            self.sched_mse
                .mse()
                .expect("scheduled channel is the peeling encoding")
                .clone(),
        );
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
        // Constant-size posts make a narrow ciphertext pointless, and the coded
        // shares are a fixed block width, so every round rides the full width.
        plaintext.resize(message_polys(&self.pp), KahePoly::default());

        let sid = crate::panetiere::session_id(&self.setup_seed, round);
        let client_round = match self.client_round.take() {
            Some((prepared_round, client_round)) if prepared_round == round => client_round,
            _ => client_round(
                &self.pp,
                &self.setup_seed,
                round,
                self.client_id,
                &self.servers,
                self.rng_seed,
            ),
        };
        let round_out = client_round.finalize(&self.pp, &sid, &plaintext, &self.post_key);
        if self.set_pks.is_some() {
            let round_out = crate::client_set::client_set_round_from_rs(
                &self.pp,
                &sid,
                round_out,
                &self.post_key,
            );
            let out = bundle_wire(&self.pp, round, &round_out, &self.identity);
            self.set_rounds
                .insert(round, ClientSetState::new(round_out));
            self.set_rounds
                .retain(|r, _| *r + PANETIERE_ROUND_RETENTION >= round);
            return out;
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1 + 2 * self.servers.len());
        let cid = round_out.client_id.0;
        let entry = round_out.bulletin.to_bytes();
        out.push(
            bincode::serialize(&PanetiereWire::ClientPublic {
                round,
                client_id: cid,
                signature: self
                    .identity
                    .sign(&crate::panetiere::client_public_signing_bytes(
                        round, cid, &entry,
                    )),
                entry,
                signer: self.identity.pubkey(),
            })
            .expect("serialise client public"),
        );
        for (lane, (share, path)) in round_out
            .rs_shares
            .iter()
            .zip(round_out.share_paths.iter())
            .enumerate()
        {
            out.push(
                bincode::serialize(&client_slice_wire(
                    round,
                    cid,
                    lane as u32,
                    share,
                    path,
                    &self.identity,
                ))
                .expect("serialise client slice"),
            );
        }
        for (server_id, sealed) in round_out.sealed_openings {
            out.push(
                bincode::serialize(&PanetiereWire::Opening {
                    round,
                    client_id: cid,
                    target_server: server_id.0,
                    signature: self
                        .identity
                        .sign(&crate::panetiere::client_opening_signing_bytes(
                            round,
                            cid,
                            server_id.0,
                            &sealed,
                        )),
                    sealed,
                    signer: self.identity.pubkey(),
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

    fn has_pending_transmissions(&self) -> bool {
        !self.staged.is_empty()
            || !self.deferred.is_empty()
            || !self.reserved.is_empty()
            || !self.granted.is_empty()
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
    /// Consensus set formation: the inner session owns the whole cadence, and
    /// `Reservations` come from the publisher, not a set-announcing leader.
    consensus: bool,
    publishes: bool,
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
        server_pubkeys: HashMap<ServerId, Pubkey>,
        entries_by_round: ReservationEntries,
    ) -> Self {
        let is_leader = mode == SetMode::Leader;
        let consensus = matches!(mode, SetMode::Consensus { .. });
        let publishes = match mode {
            SetMode::Leader => true,
            SetMode::Consensus { publisher } => publisher == identity.pubkey(),
            SetMode::Follower { .. } | SetMode::SelfDerived => false,
        };
        let sched_polys = sched_mse.n_polys();
        // inner.mse is unused: this wrapper never calls inner's own end_round.
        let inner = PanetiereServerSession::new(
            pp,
            sched_mse.clone(),
            server_id,
            identity,
            mode,
            server_pubkeys,
        );
        ScheduledPanetiereServerSession {
            inner,
            sched_mse,
            sched_polys,
            vector_bytes,
            is_leader,
            consensus,
            publishes,
            leader_pk,
            subnet: 0,
            entries_by_round,
            pending_msg: BTreeMap::new(),
            cur_round: None,
            first_round: None,
        }
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

    pub(crate) fn set_good_clients(&mut self, good_clients: GoodClients) {
        self.inner.set_good_clients(good_clients);
    }

    /// See [`crate::panetiere::PanetiereServerSession::set_consensus_keys`].
    pub fn set_consensus_keys(
        &mut self,
        signer: panetiere::sig::SigningKey,
        pks: Vec<panetiere::sig::VerifyingKey>,
    ) {
        self.inner.set_consensus_keys(signer, pks);
    }
}

impl Session for ScheduledPanetiereServerSession {
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        self.first_round.get_or_insert(round);
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

    fn checkpoint(&mut self, round: Round, k: u8, now: Instant) -> Vec<Vec<u8>> {
        // Consensus has no announcement to make: the whole cadence — receipts,
        // echo, then the Dolev–Strong rounds — belongs to the inner session.
        if self.consensus {
            return self.inner.checkpoint(round, k, now);
        }
        // A leader never receives its own `Reservations` over the wire, so on a
        // cutover boundary this is its only re-read before the round's entries.
        if k == 3 && self.is_leader {
            self.inner.announce_settled(round)
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        if self.consensus {
            self.inner.fix_consensus_sets(round);
        }
        let mut outbound = self.inner.emit_server_publics(round);
        let mut decoded = Vec::new();

        let mut entries_map = self.entries_by_round.lock().unwrap();
        let (settled, _) = self.inner.decode_settled();
        for (rd, plain) in settled {
            let n = self.sched_polys.min(plain.len());
            let entries: Vec<(u16, u16)> = match MseEncoding::unpack(
                self.sched_mse
                    .mse()
                    .expect("scheduled channel is the peeling encoding"),
                &plain[..n],
            )
            .decode()
            {
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
            if self.publishes {
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
                if self.publishes {
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

pub(crate) use crate::panetiere::run_subnet;

#[cfg(test)]
mod sizing_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn wire_estimate_covers_real_messages() {
        let (vector_bytes, rho, cset, n_relays) = (256usize, 4u32, 40u32, 3usize);
        let est = max_wire_estimate(
            vector_bytes,
            rho,
            cset,
            n_relays,
            2,
            SetFormation::Consensus,
        );

        let cfg = ScheduledPanetiereConfig {
            vector_bytes,
            estimated_messages: rho,
            client_set_max: cset,
            ..Default::default()
        };
        let (sched_mse, pp) = params_for(&cfg, n_relays);
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
            Identity::generate(),
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
