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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use chipmunk_code::{KahePoly, N};
use panetiere::bulletin::ClientBulletinEntry;
use panetiere::codec;
use panetiere::mse::{MseEncoding, MseParams};
use panetiere::pke;
use panetiere::protocol::client::run_client_round;
use panetiere::protocol::{message_polys, ClientId, ProtocolParams, ServerId};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::mpsc;

use crate::config::{ProtocolConfig, Round, ScheduledPanetiereConfig, Subnet};
use crate::identity::{Identity, Pubkey};
use crate::panetiere::{
    client_id_from_pubkey, server_index, PanetiereAggregatorSession, PanetiereObserverSession,
    PanetiereServerSession, PanetiereWatchSession, PanetiereWire, SetMode, PANETIERE_ROUND_RETENTION,
};
use crate::runtime::{
    aggregator_group_of, client_aggregator_topic, deadline_for, drain_inbound, egress_dest,
    gossip_faults, handle_inbound, publish_and_loop_back, recv_any, round_at, route_to_pipe,
    subnet_aggregation, subnet_leader_pk, AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::Subscription;
use crate::wire::RouteTag;

/// `(rand, size)` per reservation.
const SCHED_TOKEN_SYMBOLS: usize = 2;
const SCHED_GAMMA: usize = 4;
/// Bytes one `KahePoly` (`N` coefficients, 4 bytes each) holds via `codec::encode_raw`.
const BYTES_PER_POLY: usize = N * 4;

/// `Reservations{R}` is fulfilled at round `R + RESERVATION_TO_MSG_GAP`. Must
/// be a fixed constant, not derived from a session's local clock: the relay
/// decodes one combined plaintext per round and can't distinguish which grant
/// round each client used, so every participant needs to land on the same
/// round independently. `R+3` because `Reservations{R}` broadcasts as
/// `begin_round(R+2)` fires elsewhere, and delivery lands sometime during `R+2`.
const RESERVATION_TO_MSG_GAP: Round = 3;

/// Must outlive `RESERVATION_TO_MSG_GAP` plus the inner session's own retention.
const SCHED_ENTRIES_RETENTION: Round = PANETIERE_ROUND_RETENTION + RESERVATION_TO_MSG_GAP;

/// MSE parameters for a reservation channel sized for `rho` expected
/// reservations per round; `prf_key` is domain-separated from the one-round
/// channel's (`0x5C` in `panetiere::channel_mse_params`).
pub(crate) fn sched_mse_params(rho: u32, setup_seed: [u8; 32]) -> MseParams {
    let delta = (3 * rho.max(1) as usize).div_ceil(SCHED_GAMMA);
    let mut prf_key = setup_seed;
    prf_key[0] ^= 0x77;
    MseParams::new(SCHED_GAMMA, delta, SCHED_TOKEN_SYMBOLS, prf_key)
}

pub(crate) fn msg_polys(vector_bytes: usize) -> usize {
    vector_bytes.div_ceil(BYTES_PER_POLY)
}

/// Joint params: `mu_kahe` covers the reservation MSE plus the message vector.
pub(crate) fn setup_joint_pp(
    sched_mse: &MseParams,
    vector_bytes: usize,
    n_servers: usize,
    setup_seed: [u8; 32],
) -> Arc<ProtocolParams> {
    let mut rng = ChaCha20Rng::from_seed(setup_seed);
    let mu_kahe = MseEncoding::n_polys(sched_mse) + msg_polys(vector_bytes);
    Arc::new(ProtocolParams::setup_with_kahe_dims(&mut rng, n_servers, mu_kahe, 1))
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
    let sched_mse = sched_mse_params(estimated_messages, [0u8; 32]);
    let n_polys = MseEncoding::n_polys(&sched_mse) + msg_polys(vector_bytes);
    // CS params depend only on n_servers; a tiny KAHE width skips sampling the
    // (large, unused-for-sizing) KAHE CRS — same trick as `panetiere::setup_pp`.
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let pp = ProtocolParams::setup_with_kahe_dims(&mut rng, n_relays.max(1), 1, 1);
    let client_public = ClientBulletinEntry::packed_len(n_polys) + FRAMING;
    let server_public =
        pp.cs.aggregated_server_crypto_len(client_set_max) + client_set_max as usize * 4 + FRAMING;
    let decoded = vector_bytes + FRAMING;
    let reservations = 4 * estimated_messages as usize + FRAMING;
    client_public.max(server_public).max(decoded).max(reservations)
}

/// Scheduled-Panetiere `(ServerId, pke::PublicKey)` roster for sealing client
/// openings — relays whose exchange key is missing or undecodable are skipped.
fn seal_roster(cfg: &ScheduledPanetiereConfig, subnet: &Subnet) -> Vec<(ServerId, pke::PublicKey)> {
    crate::keys::roster_exchange_pubkeys(&subnet.relays, &cfg.relay_exchange_keys)
        .into_iter()
        .filter_map(|(i, xk)| {
            let pk = pke::PublicKey::from_sec1_bytes(&xk.to_sec1_bytes()).ok()?;
            Some((ServerId(i as u32), pk))
        })
        .collect()
}

fn client_session(
    pp: &Arc<ProtocolParams>,
    sched_mse: &MseParams,
    vector_bytes: usize,
    cfg: &ScheduledPanetiereConfig,
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
) -> Box<dyn Session> {
    let servers = seal_roster(cfg, subnet);
    if servers.len() != subnet.relays.len() {
        tracing::warn!(
            have = servers.len(),
            need = subnet.relays.len(),
            "scheduled panetiere client: relay exchange keys incomplete"
        );
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    Box::new(ScheduledPanetiereClientSession::new(
        pp.clone(),
        sched_mse.clone(),
        vector_bytes,
        client_id_from_pubkey(identity.pubkey()),
        servers,
        leader_pk,
        seed,
    ))
}

#[allow(clippy::too_many_arguments)]
fn server_session(
    pp: &Arc<ProtocolParams>,
    sched_mse: &MseParams,
    vector_bytes: usize,
    cfg: &ScheduledPanetiereConfig,
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
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
    );
    session.set_client_set_max(cfg.client_set_max as usize);
    Box::new(session)
}

pub struct ScheduledPanetiereClientSession {
    pp: Arc<ProtocolParams>,
    sched_mse: MseParams,
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
    rng_seed: [u8; 32],
    cover_rate: f32,
    cover_rng: ChaCha20Rng,
    rand_rng: ChaCha20Rng,
}

impl ScheduledPanetiereClientSession {
    pub fn new(
        pp: Arc<ProtocolParams>,
        sched_mse: MseParams,
        vector_bytes: usize,
        client_id: ClientId,
        servers: Vec<(ServerId, pke::PublicKey)>,
        leader_pk: Pubkey,
        rng_seed: [u8; 32],
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
            rng_seed,
            cover_rate: 1.0,
            cover_rng: ChaCha20Rng::from_seed(cover_seed),
            rand_rng: ChaCha20Rng::from_seed(rand_seed),
        }
    }
}

impl Session for ScheduledPanetiereClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        // A reservation whose grant never arrived (leader silence, GC) goes
        // back to staged for a fresh attempt.
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        let stale: Vec<Round> = self.reserved.keys().filter(|&&r| r < cutoff).copied().collect();
        for r in stale {
            if let Some(entries) = self.reserved.remove(&r) {
                self.deferred.extend(entries.into_iter().map(|(_, payload)| payload));
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
        let Some(mine) = self.reserved.remove(&round) else {
            return Vec::new();
        };
        let rands: Vec<u16> = entries.iter().map(|&(r, _)| r).collect();
        let beacon = codec::beacon(&rands);
        let sized: Vec<(u16, usize)> = entries.iter().map(|&(r, s)| (r, s as usize)).collect();
        let offs = codec::allocate(&sized, beacon, self.vector_bytes);
        // Fixed, round-number-only — see `RESERVATION_TO_MSG_GAP`.
        let target = round + RESERVATION_TO_MSG_GAP;
        for (rand, data) in mine {
            let idx = entries
                .iter()
                .position(|&(r, s)| r == rand && s as usize == data.len());
            match idx.and_then(|i| offs[i]) {
                Some(offset) => self.granted.push((target, offset, data)),
                // Dropped: rand tie, vector overflow, or no match — retry with a fresh rand.
                None => self.deferred.push(data),
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
                have = self.servers.len(),
                need = self.pp.cs.n_servers,
                "scheduled panetiere client: missing relay exchange keys; skipping round"
            );
            return Vec::new();
        }

        let mut msg_buf = vec![0u8; self.vector_bytes];
        let mut has_grant = false;
        let mut remaining = Vec::new();
        for (target, offset, data) in std::mem::take(&mut self.granted) {
            if target == round {
                let end = (offset + data.len()).min(self.vector_bytes);
                msg_buf[offset..end].copy_from_slice(&data[..end - offset]);
                has_grant = true;
            } else if target < round {
                // Missed its window (boundary skew) — retry with a fresh rand.
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

        let mut sched = MseEncoding::new(self.sched_mse.clone());
        let mut reservations = Vec::new();
        for data in std::mem::take(&mut self.staged) {
            let len = data.len();
            debug_assert!(len <= u16::MAX as usize, "pipe gate should have bounded payload size");
            let rand: u16 = loop {
                let candidate = self.rand_rng.gen();
                if !reservations.iter().any(|(r, _): &(u16, Vec<u8>)| *r == candidate) {
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

        // Nothing forcing a submit this round — only cover with probability `cover_rate`.
        if !has_grant && !real_reservation && self.cover_rng.gen::<f32>() >= self.cover_rate {
            return Vec::new();
        }

        let mut plaintext = sched.pack();
        plaintext.extend(codec::encode_raw(&msg_buf));
        debug_assert_eq!(plaintext.len(), message_polys(&self.pp), "joint pp must fit sched + msg exactly");

        let mut seed = self.rng_seed;
        seed[24..32].copy_from_slice(&round.to_le_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed);
        let round_out = run_client_round(&mut rng, &self.pp, self.client_id, plaintext, &self.servers);

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
    sched_mse: MseParams,
    sched_polys: usize,
    vector_bytes: usize,
    is_leader: bool,
    leader_pk: PeerId,
    entries_by_round: BTreeMap<Round, Vec<(u16, u16)>>,
    /// Msg sections awaiting their reservation round's entries.
    pending_msg: BTreeMap<Round, Vec<KahePoly>>,
    /// Own round clock, from `begin_round`; bounds accepted `Reservations` rounds.
    cur_round: Option<Round>,
}

impl ScheduledPanetiereServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        sched_mse: MseParams,
        vector_bytes: usize,
        server_id: ServerId,
        identity: Identity,
        mode: SetMode,
        leader_pk: Pubkey,
        min_clients: u32,
        server_pubkeys: HashMap<ServerId, Pubkey>,
        aggregation: Option<LeaderAggregation>,
    ) -> Self {
        let is_leader = mode == SetMode::Leader;
        let sched_polys = MseEncoding::n_polys(&sched_mse);
        // inner.mse is unused: this wrapper never calls inner's own end_round.
        let inner = PanetiereServerSession::new(
            pp,
            sched_mse.clone(),
            server_id,
            identity,
            mode,
            min_clients,
            server_pubkeys,
            aggregation,
        );
        ScheduledPanetiereServerSession {
            inner,
            sched_mse,
            sched_polys,
            vector_bytes,
            is_leader,
            leader_pk,
            entries_by_round: BTreeMap::new(),
            pending_msg: BTreeMap::new(),
            cur_round: None,
        }
    }

    /// See [`crate::panetiere::PanetiereServerSession::set_client_set_max`].
    pub(crate) fn set_client_set_max(&mut self, max: usize) {
        self.inner.set_client_set_max(max);
    }
}

impl Session for ScheduledPanetiereServerSession {
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        self.inner.begin_round(round, now)
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if from == self.leader_pk {
            if let Ok(PanetiereWire::Reservations { round, entries }) =
                bincode::deserialize::<PanetiereWire>(&payload)
            {
                if crate::panetiere::round_in_window(round, self.cur_round) {
                    self.entries_by_round.entry(round).or_insert(entries);
                }
            }
        }
        self.inner.on_inbound(from, payload)
    }

    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k == 3 && self.is_leader {
            self.inner.announce_settled(round)
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let mut outbound = self.inner.emit_server_publics(round);
        let mut decoded = Vec::new();

        for (rd, plain) in self.inner.decode_settled() {
            let n = self.sched_polys.min(plain.len());
            let entries: Vec<(u16, u16)> = match MseEncoding::unpack(&self.sched_mse, &plain[..n]).decode() {
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
                    tracing::debug!(round = rd, ?e, "scheduled panetiere: reservation MSE peel failed");
                    Vec::new()
                }
            };
            if self.is_leader {
                let wire = PanetiereWire::Reservations { round: rd, entries: entries.clone() };
                outbound.push(bincode::serialize(&wire).expect("serialise reservations"));
            }
            self.entries_by_round.insert(rd, entries);
            self.pending_msg.insert(rd, plain[n..].to_vec());
        }

        let ready: Vec<Round> = self
            .pending_msg
            .keys()
            .copied()
            .filter(|rd| {
                self.entries_by_round
                    .contains_key(&rd.saturating_sub(RESERVATION_TO_MSG_GAP))
            })
            .collect();
        for rd in ready {
            let plain = self.pending_msg.remove(&rd).expect("checked above");
            let prev = &self.entries_by_round[&(rd.saturating_sub(RESERVATION_TO_MSG_GAP))];
            let rands: Vec<u16> = prev.iter().map(|&(r, _)| r).collect();
            let beacon = codec::beacon(&rands);
            let sized: Vec<(u16, usize)> = prev.iter().map(|&(r, s)| (r, s as usize)).collect();
            let offs = codec::allocate(&sized, beacon, self.vector_bytes);
            let ranges: Vec<(usize, usize)> = prev
                .iter()
                .zip(offs)
                .filter_map(|(&(_, size), off)| off.map(|o| (o, size as usize)))
                .collect();
            let msgs = match codec::decode_ranges(&plain, &ranges) {
                Ok(payloads) => payloads
                    .into_iter()
                    .filter(|b| b.iter().any(|x| *x != 0))
                    .collect::<Vec<_>>(),
                Err(e) => {
                    tracing::debug!(round = rd, ?e, "scheduled panetiere: message-vector decode failed");
                    Vec::new()
                }
            };
            if !msgs.is_empty() {
                if self.is_leader {
                    let wire = PanetiereWire::Decoded { round: rd, payloads: msgs.clone() };
                    outbound.push(bincode::serialize(&wire).expect("serialise decoded"));
                }
                decoded.extend(msgs);
            }
        }

        self.inner.gc(round);
        let cutoff = round.saturating_sub(SCHED_ENTRIES_RETENTION);
        self.entries_by_round.retain(|r, _| *r >= cutoff);
        self.pending_msg.retain(|r, _| *r >= cutoff);

        RoundOutcome { outbound, decoded, faults: Vec::new() }
    }

    fn set_misbehavior(&mut self, mode: Option<Misbehavior>) {
        self.inner.set_misbehavior(mode);
    }
}

/// Shifts [`PanetiereAggregatorSession`]'s hardcoded k==1 to k==2 (k==1 is
/// the scheduled cadence's client-submit checkpoint).
struct ScheduledAggregatorSession(PanetiereAggregatorSession);

impl Session for ScheduledAggregatorSession {
    fn begin_round(&mut self, round: Round, now: Instant) -> Vec<Vec<u8>> {
        self.0.begin_round(round, now)
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        self.0.on_inbound(from, payload)
    }

    fn checkpoint(&mut self, round: Round, k: u8, now: Instant) -> Vec<Vec<u8>> {
        if k == 2 {
            self.0.checkpoint(round, 1, now)
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, round: Round, now: Instant) -> RoundOutcome {
        self.0.end_round(round, now)
    }
}

/// Self-contained scheduled-Panetiere subnet driver, mirroring
/// `panetiere::run_subnet`'s structure with a quarter-round checkpoint
/// cadence: k=1 client submit, k=2 aggregate (aggregated only), k=3 leader
/// announce, end_round shares + decode + broadcast.
pub(crate) async fn run_subnet(
    subnet: Subnet,
    inner: Arc<AnymoneInner>,
    mut stage_rx: mpsc::UnboundedReceiver<StageMsg>,
    mut subscriptions: Vec<Subscription>,
    base_round: Round,
    epoch_unix_ms: u64,
) {
    let cfg = match &subnet.protocol {
        ProtocolConfig::ScheduledPanetiere(c) => c.clone(),
        _ => unreachable!("panetiere_scheduled::run_subnet on a non-ScheduledPanetiere subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let sched_mse = sched_mse_params(cfg.estimated_messages, cfg.setup_seed);
    let pp = setup_joint_pp(&sched_mse, cfg.vector_bytes, subnet.relays.len(), cfg.setup_seed);
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg_topic = client_aggregator_topic(&subnet, identity_pk);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut client_homes: HashSet<RouteTag> = HashSet::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(&pp, &sched_mse, cfg.vector_bytes, &cfg, &subnet, &inner.identity, leader_pk),
        );
    } else {
        sessions.insert(SessionKey::Watch, Box::new(PanetiereWatchSession::new(leader_pk)));
    }
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            let mut agg_session =
                PanetiereAggregatorSession::new(group, a.groups.len() as u32, inner.identity.clone());
            agg_session.set_client_set_max(cfg.client_set_max as usize);
            sessions.insert(SessionKey::Aggregator, Box::new(ScheduledAggregatorSession(agg_session)));
        }
    }
    let mut fault_monitor: Option<Box<dyn Session>> = if leader_pk == identity_pk {
        let mut roster = subnet.relays.clone();
        roster.sort();
        Some(Box::new(PanetiereObserverSession::new(roster, Some(leader_pk), FAULT_THRESHOLD)))
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

    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
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

    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep_until(k1_deadline), if !k1_done => {
                k1_done = true;
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
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
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
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
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
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
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
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
                if let Some(m) = fault_monitor.as_mut() {
                    faults.extend(m.end_round(round, Instant::now()).faults);
                }
                let n_decoded = decoded_all.len();
                for bytes in decoded_all {
                    route_to_pipe(&inner, &bytes);
                }
                if n_decoded > 0 {
                    let _ = inner.events.send(crate::runtime::Event::RoundDecoded {
                        round,
                        subnet: subnet.id,
                        n_messages: n_decoded,
                    });
                }
                let faults = faults
                    .into_iter()
                    .map(|f| (crate::panetiere::evidence_round(&f.evidence).unwrap_or(round), f))
                    .collect();
                gossip_faults(&inner, subnet.id, identity_pk, faults).await;

                let now_ms = crate::config::now_unix_ms();
                round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                k1_deadline = deadline - std::time::Duration::from_millis(dur_ms - k1_ms);
                k2_deadline = deadline - std::time::Duration::from_millis(dur_ms - k2_ms);
                k3_deadline = deadline - std::time::Duration::from_millis(dur_ms - k3_ms);
                k1_done = false;
                k2_done = false;
                k3_done = false;
                if let Some(m) = fault_monitor.as_mut() {
                    m.begin_round(round, Instant::now());
                }
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

            msg = recv_any(&mut subscriptions) => {
                handle_inbound(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, msg).await;
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::Join { client_tag } => {
                        client_homes.insert(client_tag);
                        sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&pp, &sched_mse, cfg.vector_bytes, &cfg, &subnet, &inner.identity, leader_pk))
                            .set_cover_rate(cover_rate);
                    }
                    StageMsg::Stage { client_tag, payload } => {
                        client_homes.insert(client_tag);
                        let sess = sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&pp, &sched_mse, cfg.vector_bytes, &cfg, &subnet, &inner.identity, leader_pk));
                        sess.set_cover_rate(cover_rate);
                        sess.stage(payload);
                    }
                    StageMsg::Retire { client_tag } => {
                        client_homes.remove(&client_tag);
                        if client_homes.is_empty() {
                            sessions.remove(&SessionKey::Client);
                        }
                    }
                    StageMsg::SetCoverRate(rate) => {
                        cover_rate = rate;
                        if let Some(c) = sessions.get_mut(&SessionKey::Client) {
                            c.set_cover_rate(rate);
                        }
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

        let sched_mse = sched_mse_params(rho, [1u8; 32]);
        let pp = setup_joint_pp(&sched_mse, vector_bytes, n_relays, [1u8; 32]);
        let servers: Vec<(ServerId, pke::PublicKey)> = (0..n_relays as u32)
            .map(|i| (ServerId(i), pke::PrivateKey::generate(&mut rand::rngs::OsRng).public()))
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
        );
        c.stage(vec![0xABu8; 64]);
        let client_public = c
            .checkpoint(0, 1, Instant::now())
            .iter()
            .map(|m| m.len())
            .max()
            .unwrap();
        assert!(est >= client_public, "estimate {est} < real ClientPublic {client_public}");
        assert!(
            est >= pp.cs.aggregated_server_crypto_len(cset),
            "estimate omits the ServerPublic crypto term"
        );
        assert!(est >= vector_bytes, "estimate omits the Decoded term");
    }
}
