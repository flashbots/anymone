//! Panetiere `Session` wrappers.
//!
//! Topic layout matches ADCNet: client messages on ingress (every relay reads —
//! all of them combine), `ServerPublic`s on shares, the leader's `Decoded` on
//! broadcast. Openings are sealed to their target server: ≥t plaintext openings
//! reconstruct the client's message.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use adcnet::crypto::ExchangePublicKey;
use chipmunk_code::KahePoly;
use panetiere::bulletin::{ClientBulletinEntry, ServerBulletinEntry};
use panetiere::cs::{Cs, HidingMerkleCommitment, Opening, PackedOpening};
use panetiere::kahe::{Kahe, KaheScheme};
use panetiere::mse::{MseEncoding, MseParams};
use panetiere::protocol::aggregator::run_aggregator_round;
use panetiere::protocol::client::run_client_round;
use panetiere::protocol::server::{run_server_round, ServerInbox};
use panetiere::protocol::verify::{aggregate_and_decrypt, decrypt_aggregate, VerifyError};
use panetiere::protocol::{message_polys, ClientId, ProtocolParams, ServerId};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::{PanetiereConfig, ProtocolConfig, Round, Subnet};
use crate::identity::{ExchangeIdentity, Identity, Pubkey};
use crate::faults::{Attribution, Fault, FaultKind, OutputFaultTracker};
use crate::runtime::{
    aggregator_group_of, client_aggregator_topic, deadline_for, egress_dest, gossip_faults,
    recv_any, round_at, route_to_pipe, subnet_aggregation, subnet_leader_pk, AnymoneInner,
    SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::scheduler_core::expected_active;
use crate::session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::{Inbound, Subscription};
use crate::wire::RouteTag;

/// Two bytes per MSE symbol — safely below `t = 2^18`, so no value wraps and the
/// byte↔symbol map is a plain little-endian `u16`.
const BYTES_PER_SYMBOL: usize = 2;

/// MSE parameters for a Panetiere channel carrying up to `rho` real messages of
/// `message_bytes` each: γ=4, δ ≈ 3 buckets per insert (peeling margin), ξ symbols
/// to hold the bytes. `prf_key` is domain-separated from the shared `setup_seed`
/// so all participants agree.
pub(crate) fn channel_mse_params(rho: u32, message_bytes: usize, setup_seed: [u8; 32]) -> MseParams {
    const GAMMA: usize = 4;
    let delta = (3 * rho.max(1) as usize).div_ceil(GAMMA);
    let xi = message_bytes.div_ceil(BYTES_PER_SYMBOL).max(1);
    let mut prf_key = setup_seed;
    prf_key[0] ^= 0x5C;
    MseParams::new(GAMMA, delta, xi, prf_key)
}

/// Message-byte bound for the committee's config-anonymising channel (a
/// serialized `SignedProposal` fits well within this).
pub(crate) const COMMITTEE_MSG_BYTES: usize = 4096;

/// Per-subnet Panetiere parameters, with the KAHE message width sized to exactly
/// hold one MSE pack (`mu_kahe = n_polys`, `l = 1`).
pub(crate) fn setup_pp(params: &MseParams, n_servers: usize, setup_seed: [u8; 32]) -> Arc<ProtocolParams> {
    let mut rng = ChaCha20Rng::from_seed(setup_seed);
    let mu_kahe = MseEncoding::n_polys(params);
    Arc::new(ProtocolParams::setup_with_kahe_dims(&mut rng, n_servers, mu_kahe, 1))
}

/// Pack message bytes into `xi` little-endian `u16` MSE symbols (zero-padded).
fn bytes_to_symbols(payload: &[u8], xi: usize) -> Vec<i32> {
    debug_assert!(
        payload.len() <= xi * BYTES_PER_SYMBOL,
        "payload exceeds channel capacity; the pipe send gate should have rejected it"
    );
    let mut buf = payload.to_vec();
    buf.resize(xi * BYTES_PER_SYMBOL, 0);
    (0..xi)
        .map(|i| u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]) as i32)
        .collect()
}

/// Inverse of [`bytes_to_symbols`]; trailing zero padding is left for
/// `Frame::decode` to ignore (the frame is self-delimiting).
fn symbols_to_bytes(symbols: &[i32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(symbols.len() * BYTES_PER_SYMBOL);
    for &s in symbols {
        out.extend_from_slice(&(s as u16).to_le_bytes());
    }
    out
}

/// Conservative upper bound on the largest per-round wire message a Panetiere subnet
/// broadcasts, for the committee's p2p size-cap guard. Sizes the real bulletin entries
/// (`ClientBulletinEntry::packed_len`, `CsParams::aggregated_server_crypto_len`).
pub(crate) fn max_wire_estimate(
    message_size: usize,
    estimated_messages: u32,
    client_set_max: u32,
    n_relays: usize,
) -> usize {
    const FRAMING: usize = 512;
    // n_polys is pure; the CS params depend only on n_servers, so build `pp` with a
    // tiny KAHE width to skip sampling the (large, unused-for-sizing) KAHE CRS.
    let n_polys = MseEncoding::n_polys(&channel_mse_params(estimated_messages, message_size, [0u8; 32]));
    let pp = setup_pp(&channel_mse_params(1, 1, [0u8; 32]), n_relays.max(1), [0u8; 32]);
    let client_public = ClientBulletinEntry::packed_len(n_polys) + FRAMING;
    let server_public =
        pp.cs.aggregated_server_crypto_len(client_set_max) + client_set_max as usize * 4 + FRAMING;
    let decoded = estimated_messages as usize * message_size + FRAMING;
    client_public.max(server_public).max(decoded)
}

/// `pk`'s position in the sorted relay list — the Panetiere `ServerId`.
fn server_index(relays: &[Pubkey], pk: Pubkey) -> Option<u32> {
    let mut sorted = relays.to_vec();
    sorted.sort();
    sorted.iter().position(|p| *p == pk).map(|i| i as u32)
}

/// Deterministic `ClientId` from a pubkey's first 4 bytes; stable per node+pipe
/// so the decoder merges a round's publics with its openings.
fn client_id_from_pubkey(pk: Pubkey) -> ClientId {
    ClientId(u32::from_be_bytes([pk.0[0], pk.0[1], pk.0[2], pk.0[3]]))
}

/// Panetiere `ServerId` → relay exchange pubkey, for sealing client openings.
fn server_xpubs(cfg: &PanetiereConfig, subnet: &Subnet) -> HashMap<ServerId, ExchangePublicKey> {
    crate::keys::roster_exchange_pubkeys(&subnet.relays, &cfg.relay_exchange_keys)
        .into_iter()
        .map(|(i, xk)| (ServerId(i as u32), xk))
        .collect()
}

fn client_session(pp: &Arc<ProtocolParams>, mse: &MseParams, cfg: &PanetiereConfig, subnet: &Subnet, identity: &Identity) -> Box<dyn Session> {
    let mut sorted = subnet.relays.clone();
    sorted.sort();
    let server_ids: Vec<ServerId> = (0..sorted.len() as u32).map(ServerId).collect();
    // Secret entropy: a seed from the (public) return tag would let anyone
    // replay the client's round.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    Box::new(PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_id_from_pubkey(identity.pubkey()),
        server_ids,
        server_xpubs(cfg, subnet),
        seed,
    ))
}

fn server_session(
    pp: &Arc<ProtocolParams>,
    mse: &MseParams,
    cfg: &PanetiereConfig,
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
    // Every relay needs the aggregator roster; only the leader emits the decode.
    let aggregation = cfg.aggregation.as_ref().map(LeaderAggregation::from_config);
    let mode = if identity_pk == leader_pk {
        SetMode::Leader
    } else {
        SetMode::Follower { leader: leader_pk }
    };
    Box::new(PanetiereServerSession::new(
        pp.clone(),
        mse.clone(),
        server_id,
        expected_active(cfg.client_set_max),
        identity.exchange().clone(),
        mode,
        cfg.client_set_min,
        server_pubkeys,
        aggregation,
    ))
}

/// Self-contained Panetiere subnet driver: builds this node's sessions, then owns
/// the round loop. The runtime dispatches here for Panetiere subnets.
pub(crate) async fn run_subnet(
    subnet: Subnet,
    inner: Arc<AnymoneInner>,
    mut stage_rx: mpsc::UnboundedReceiver<StageMsg>,
    mut subscriptions: Vec<Subscription>,
    base_round: Round,
    epoch_unix_ms: u64,
) {
    let cfg = match &subnet.protocol {
        ProtocolConfig::Panetiere(c) => c.clone(),
        _ => unreachable!("panetiere::run_subnet on a non-Panetiere subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let mse = channel_mse_params(cfg.estimated_messages, cfg.message_size, cfg.setup_seed);
    let pp = setup_pp(&mse, subnet.relays.len(), cfg.setup_seed);
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg_topic = client_aggregator_topic(&subnet, identity_pk);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut client_homes: HashSet<RouteTag> = HashSet::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(&pp, &mse, &cfg, &subnet, &inner.identity, leader_pk),
        );
    } else {
        sessions.insert(SessionKey::Watch, Box::new(PanetiereWatchSession::new(leader_pk)));
    }
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            sessions.insert(
                SessionKey::Aggregator,
                Box::new(PanetiereAggregatorSession::new(
                    group,
                    a.groups.len() as u32,
                    inner.identity.clone(),
                )),
            );
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
            is_shares_topic_msg,
            is_client_public,
            client_agg_topic.as_deref(),
            key,
            bytes,
        )
    };

    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(1);
    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
    let mut mid_done = false;

    if let Some(m) = fault_monitor.as_mut() {
        m.begin_round(round, Instant::now());
    }
    let misbehavior = inner.misbehavior();
    for (key, s) in sessions.iter_mut() {
        if let SessionKey::Server = key {
            s.set_misbehavior(misbehavior);
        }
        for out in s.begin_round(round, Instant::now()) {
            if let Some(m) = fault_monitor.as_mut() {
                m.on_inbound(identity_pk, out.clone());
            }
            let dest = egress(key, &out);
            inner.transport.publish(&dest, out).await;
        }
    }

    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep_until(mid_deadline), if !mid_done => {
                mid_done = true;
                for (key, s) in sessions.iter_mut() {
                    for out in s.mid_round(round, Instant::now()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(&dest, out).await;
                    }
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults: Vec<Fault> = Vec::new();
                for (key, s) in sessions.iter_mut() {
                    let outcome = s.end_round(round, Instant::now());
                    for out in outcome.outbound {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(&dest, out).await;
                    }
                    decoded_all.extend(outcome.decoded);
                    faults.extend(outcome.faults);
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
                gossip_faults(&inner, subnet.id, round, identity_pk, faults).await;

                let now_ms = crate::config::now_unix_ms();
                round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
                mid_done = false;
                if let Some(m) = fault_monitor.as_mut() {
                    m.begin_round(round, Instant::now());
                }
                let misbehavior = inner.misbehavior();
                for (key, s) in sessions.iter_mut() {
                    if let SessionKey::Server = key {
                        s.set_misbehavior(misbehavior);
                    }
                    for out in s.begin_round(round, Instant::now()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(&dest, out).await;
                    }
                }
            }

            msg = recv_any(&mut subscriptions) => {
                let Inbound { from, payload } = msg;
                if let Some(m) = fault_monitor.as_mut() {
                    m.on_inbound(from, payload.clone());
                }
                for (key, s) in sessions.iter_mut() {
                    for out in s.on_inbound(from, payload.clone()) {
                        if let Some(m) = fault_monitor.as_mut() {
                            m.on_inbound(identity_pk, out.clone());
                        }
                        let dest = egress(key, &out);
                        inner.transport.publish(&dest, out).await;
                    }
                }
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::Join { client_tag } => {
                        client_homes.insert(client_tag);
                        sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&pp, &mse, &cfg, &subnet, &inner.identity))
                            .set_cover_rate(cover_rate);
                    }
                    StageMsg::Stage { client_tag, payload } => {
                        client_homes.insert(client_tag);
                        let sess = sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&pp, &mse, &cfg, &subnet, &inner.identity));
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

/// Tagged wire form for every Panetiere message published on a subnet topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PanetiereWire {
    ClientPublic {
        round: u64,
        client_id: u32,
        /// Bit-packed `ClientBulletinEntry` (ciphertext + commitment).
        #[serde(with = "serde_bytes")]
        entry: Vec<u8>,
    },
    Opening {
        round: u64,
        client_id: u32,
        target_server: u32,
        /// ECIES-sealed `PackedOpeningWire`, opened only by the target server.
        /// Never plaintext: ≥t openings reconstruct the client's message.
        #[serde(with = "serde_bytes")]
        sealed: Vec<u8>,
    },
    ServerPublic {
        round: u64,
        server_id: u32,
        clients: Vec<u32>,
        agg_open: PackedOpeningWire,
        /// Bit-packed κ_kahe CsPoly shares (count = `agg_open.mu_cs`).
        #[serde(with = "serde_bytes")]
        agg_share: Vec<u8>,
    },
    /// Decoded round result, published on broadcast by the subnet leader only
    /// (every relay decodes; one publishes).
    Decoded { round: u64, payloads: Vec<Vec<u8>> },
    /// One aggregator group's summed public ciphertext+commitment, signed.
    /// Replicas in a group emit identical bytes (1-of-n liveness).
    GroupAggregate {
        round: u64,
        group: u32,
        clients: Vec<u32>,
        /// Bit-packed `ClientBulletinEntry` (Σ ctxt + Σ comm over the group).
        #[serde(with = "serde_bytes")]
        entry: Vec<u8>,
        signer: Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    /// Leader-announced canonical client set for `round` (public subnets). Relays
    /// share over exactly this set; one authoritative set per round.
    ClientSet { round: u64, clients: Vec<u32> },
}

/// Bytes an aggregator signs over (and the leader verifies): the round, group,
/// sorted client ids, and the packed aggregate entry.
fn group_aggregate_signing_bytes(round: u64, group: u32, clients: &[u32], entry: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + clients.len() * 4 + entry.len());
    m.extend_from_slice(&round.to_le_bytes());
    m.extend_from_slice(&group.to_le_bytes());
    for c in clients {
        m.extend_from_slice(&c.to_le_bytes());
    }
    m.extend_from_slice(entry);
    m
}

/// Serde mirror of `panetiere::cs::PackedOpening`. Fields are identical;
/// kept here so we don't depend on upstream serde derives.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackedOpeningWire {
    server_index: u32,
    path_index: u32,
    kappa_cs: u32,
    mu_cs: u32,
    block_size: u32,
    stored_path_len: u32,
    r_bound: u32,
    s_bound: u32,
    tree_bound: u32,
    bytes: Vec<u8>,
}

impl From<&PackedOpening> for PackedOpeningWire {
    fn from(p: &PackedOpening) -> Self {
        PackedOpeningWire {
            server_index: p.server_index,
            path_index: p.path_index,
            kappa_cs: p.kappa_cs,
            mu_cs: p.mu_cs,
            block_size: p.block_size,
            stored_path_len: p.stored_path_len,
            r_bound: p.r_bound,
            s_bound: p.s_bound,
            tree_bound: p.tree_bound,
            bytes: p.bytes.clone(),
        }
    }
}

impl From<PackedOpeningWire> for PackedOpening {
    fn from(w: PackedOpeningWire) -> Self {
        PackedOpening {
            server_index: w.server_index,
            path_index: w.path_index,
            kappa_cs: w.kappa_cs,
            mu_cs: w.mu_cs,
            block_size: w.block_size,
            stored_path_len: w.stored_path_len,
            r_bound: w.r_bound,
            s_bound: w.s_bound,
            tree_bound: w.tree_bound,
            bytes: w.bytes,
        }
    }
}

pub(crate) fn describe(bytes: &[u8]) -> Option<String> {
    match bincode::deserialize::<PanetiereWire>(bytes).ok()? {
        PanetiereWire::ClientPublic { client_id, .. } => {
            Some(format!("Panetiere ClientPublic cid={client_id}"))
        }
        PanetiereWire::Opening {
            client_id,
            target_server,
            ..
        } => Some(format!(
            "Panetiere Opening cid={client_id} -> sid={target_server}"
        )),
        PanetiereWire::ServerPublic {
            server_id, clients, ..
        } => Some(format!(
            "Panetiere ServerPublic sid={server_id} clients={}",
            clients.len()
        )),
        PanetiereWire::Decoded { round, payloads } => Some(format!(
            "Panetiere Decoded round={round} payloads={}",
            payloads.len()
        )),
        PanetiereWire::GroupAggregate {
            round,
            group,
            clients,
            ..
        } => Some(format!(
            "Panetiere GroupAggregate round={round} group={group} clients={}",
            clients.len()
        )),
        PanetiereWire::ClientSet { round, clients } => Some(format!(
            "Panetiere ClientSet round={round} clients={}",
            clients.len()
        )),
    }
}

/// Egress routing only: both relay shares and the leader's `ClientSet` ride the
/// shares topic (every relay subscribes to it; none subscribe to broadcast).
pub(crate) fn is_shares_topic_msg(bytes: &[u8]) -> bool {
    matches!(
        bincode::deserialize::<PanetiereWire>(bytes),
        Ok(PanetiereWire::ServerPublic { .. } | PanetiereWire::ClientSet { .. })
    )
}

pub(crate) fn is_client_public(bytes: &[u8]) -> bool {
    matches!(
        bincode::deserialize::<PanetiereWire>(bytes),
        Ok(PanetiereWire::ClientPublic { .. })
    )
}

/// Non-participating liveness/anonymity observer for a Panetiere subnet. Feeds
/// an [`OutputFaultTracker`] from real wire messages: `ServerPublic`s are the
/// per-relay share signal, the leader's `Decoded` is the output signal.
/// The self-contained `ShareOpeningMismatch` check (no canonical set, no
/// decryption); `true` when the wire can't be reconstructed, so malformed bytes
/// never frame a relay.
fn server_public_consistent(agg_open: &PackedOpeningWire, agg_share: &[u8]) -> bool {
    let n_shares = agg_open.mu_cs as usize;
    let Ok(open) = Opening::from_packed(&PackedOpening::from(agg_open.clone())) else {
        return true;
    };
    match panetiere::cs::unpack_cs_shares(agg_share, n_shares) {
        Some(share) => share.as_slice() == open.s(),
        None => true,
    }
}

/// Culprit `ServerId` iff `evidence` is a `ServerPublic` with a mismatched share
/// — lets the committee re-verify a leader's report instead of trusting it.
pub(crate) fn integrity_culprit_from_evidence(evidence: &[u8]) -> Option<ServerId> {
    match bincode::deserialize::<PanetiereWire>(evidence).ok()? {
        PanetiereWire::ServerPublic { server_id, agg_open, agg_share, .. } => {
            (!server_public_consistent(&agg_open, &agg_share)).then_some(ServerId(server_id))
        }
        _ => None,
    }
}

pub struct PanetiereObserverSession {
    tracker: OutputFaultTracker,
    /// Sorted roster; index = wire `server_id`.
    roster: Vec<PeerId>,
    /// Public subnets: the leader, whose `ClientSet`/`Decoded` alone are trusted.
    /// `None` for the leaderless committee, which reads the set off `ServerPublic`s.
    leader: Option<PeerId>,
    max_round: Option<u64>,
    /// Canonical client set size per round — the per-round anonymity set.
    anon_set_by_round: std::collections::BTreeMap<u64, usize>,
    /// Integrity culprits caught from inconsistent shares, deduped, emitted at `end_round`.
    integrity_pending: Vec<Fault>,
    integrity_seen: HashSet<(u64, u32)>,
}

const ANON_SET_HISTORY: usize = 16;

impl PanetiereObserverSession {
    pub fn new(roster: Vec<PeerId>, leader: Option<PeerId>, fault_threshold: u64) -> Self {
        PanetiereObserverSession {
            tracker: OutputFaultTracker::new(roster.clone(), fault_threshold),
            roster,
            leader,
            max_round: None,
            anon_set_by_round: std::collections::BTreeMap::new(),
            integrity_pending: Vec::new(),
            integrity_seen: HashSet::new(),
        }
    }

    fn record_anon(&mut self, round: u64, size: usize) {
        self.anon_set_by_round.insert(round, size);
        while self.anon_set_by_round.len() > ANON_SET_HISTORY {
            let oldest = *self.anon_set_by_round.keys().next().unwrap();
            self.anon_set_by_round.remove(&oldest);
        }
    }

    /// Highest round seen in any Panetiere message. `None` before traffic.
    pub fn round(&self) -> Option<u64> {
        self.max_round
    }

    /// Size of the most recent round's canonical client set.
    pub fn anonymity_set(&self) -> Option<usize> {
        self.anon_set_by_round.values().next_back().copied()
    }

    /// Canonical client set size for `round`, falling back to the most recent
    /// earlier round when that exact round hasn't been observed yet.
    pub fn anonymity_set_for(&self, round: u64) -> Option<usize> {
        self.anon_set_by_round
            .range(..=round)
            .next_back()
            .map(|(_, &s)| s)
    }

    /// Highest round a relay published a share for. `None` before any share.
    pub fn share_frontier(&self) -> Option<u64> {
        self.tracker.share_frontier()
    }

    /// Highest round in which every roster relay published (the Panetiere
    /// success signal). `None` before the first such round.
    pub fn output_frontier(&self) -> Option<u64> {
        self.tracker.output_frontier()
    }

    /// Roster indices of relays that published a share within `window` rounds of
    /// the frontier — the relays observably alive now (for dashboard liveness).
    pub fn relays_shared_recent(&self, window: u64) -> Vec<usize> {
        self.tracker.relays_shared_recent(window)
    }
}

impl Session for PanetiereObserverSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(msg) = bincode::deserialize::<PanetiereWire>(&payload) {
            let round = match &msg {
                PanetiereWire::ClientPublic { round, .. }
                | PanetiereWire::Opening { round, .. }
                | PanetiereWire::ServerPublic { round, .. }
                | PanetiereWire::Decoded { round, .. }
                | PanetiereWire::GroupAggregate { round, .. }
                | PanetiereWire::ClientSet { round, .. } => *round,
            };
            self.max_round = Some(self.max_round.map_or(round, |m| m.max(round)));
            match &msg {
                PanetiereWire::ServerPublic {
                    round,
                    server_id,
                    clients,
                    agg_open,
                    agg_share,
                } => {
                    // Panetiere server ids are the 0-based sorted-roster index.
                    self.tracker.observe_share(*round, *server_id as usize);
                    // Leaderless committee has no ClientSet; read the set off shares.
                    if self.leader.is_none() {
                        self.record_anon(*round, clients.len());
                    }
                    // A corrupt share is an attributable integrity fault even though
                    // t-of-n decode tolerates it, so liveness alone would miss it.
                    self.integrity_seen.retain(|(r, _)| *r + ANON_SET_HISTORY as u64 >= *round);
                    if !server_public_consistent(agg_open, agg_share)
                        && self.integrity_seen.insert((*round, *server_id))
                    {
                        if let Some(pk) = self.roster.get(*server_id as usize).copied() {
                            self.integrity_pending.push(Fault {
                                kind: FaultKind::Integrity,
                                attribution: Attribution::Peers(vec![pk]),
                                evidence: payload.clone(),
                            });
                        }
                    }
                }
                PanetiereWire::ClientSet { round, clients } if self.leader == Some(from) => {
                    self.record_anon(*round, clients.len());
                }
                PanetiereWire::Decoded { round, .. }
                    if self.leader.map_or(true, |l| from == l) =>
                {
                    self.tracker.observe_output(*round);
                }
                _ => {}
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        let mut faults = std::mem::take(&mut self.integrity_pending);
        faults.extend(self.tracker.evaluate());
        RoundOutcome { outbound: Vec::new(), decoded: Vec::new(), faults }
    }
}

/// Client-side session: stages a payload, encrypts + Shamir-shares it at
/// `begin_round`, and emits one `ClientPublic` plus per-server `Opening`
/// messages. Ignores inbound.
pub struct PanetiereClientSession {
    pp: Arc<ProtocolParams>,
    mse: MseParams,
    client_id: ClientId,
    server_ids: Vec<ServerId>,
    server_xpubs: HashMap<ServerId, ExchangePublicKey>,
    pending: Option<Vec<KahePoly>>,
    rng_seed: [u8; 32],
    cover_rate: f32,
    /// Separate stream for the cover draw: the per-round protocol RNG is
    /// deterministic, so reusing it would make cover predictable.
    cover_rng: ChaCha20Rng,
    /// Unpredictable stream for per-insert MSE randomness `r` (a predictable `r`
    /// would let an adversary craft a colliding insert).
    r_rng: ChaCha20Rng,
}

impl PanetiereClientSession {
    pub fn new(
        pp: Arc<ProtocolParams>,
        mse: MseParams,
        client_id: ClientId,
        server_ids: Vec<ServerId>,
        server_xpubs: HashMap<ServerId, ExchangePublicKey>,
        rng_seed: [u8; 32],
    ) -> Self {
        // Domain-separate the cover and MSE-r streams from the protocol seed.
        let mut cover_seed = rng_seed;
        cover_seed[0] ^= 0xA5;
        let mut r_seed = rng_seed;
        r_seed[0] ^= 0x3C;
        PanetiereClientSession {
            pp,
            mse,
            client_id,
            server_ids,
            server_xpubs,
            pending: None,
            rng_seed,
            cover_rate: 1.0,
            cover_rng: ChaCha20Rng::from_seed(cover_seed),
            r_rng: ChaCha20Rng::from_seed(r_seed),
        }
    }
}

impl Session for PanetiereClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        let msg = match self.pending.take() {
            Some(m) => m,
            None if self.cover_rng.gen::<f32>() < self.cover_rate => {
                let mut cover = MseEncoding::cover(&self.mse);
                cover.resize(message_polys(&self.pp), KahePoly::default());
                cover
            }
            None => return Vec::new(),
        };
        // The RNG is rebuilt from the seed each round; folding the round into
        // the trailing bytes keeps per-round randomness distinct.
        let mut seed = self.rng_seed;
        seed[24..32].copy_from_slice(&round.to_le_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed);
        let round_out = run_client_round(&mut rng, &self.pp, self.client_id, msg, &self.server_ids);

        let (r_b, s_b, t_b) = panetiere::cs::fresh_opening_pack_bounds(&self.pp.cs);

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1 + self.server_ids.len());

        let pub_msg = PanetiereWire::ClientPublic {
            round,
            client_id: round_out.client_id.0,
            entry: round_out.encrypted_message.to_bytes(),
        };
        out.push(bincode::serialize(&pub_msg).expect("serialise client public"));

        for (server_id, opening) in round_out.encrypted_openings {
            let packed = PackedOpeningWire::from(&opening.pack(r_b, s_b, t_b));
            let Some(xpub) = self.server_xpubs.get(&server_id) else {
                continue;
            };
            let plain = bincode::serialize(&packed).expect("serialise packed opening");
            let Ok(sealed) = adcnet::crypto::encrypt(xpub, &plain) else {
                continue;
            };
            let opening_msg = PanetiereWire::Opening {
                round,
                client_id: round_out.client_id.0,
                target_server: server_id.0,
                sealed: sealed.to_bytes(),
            };
            out.push(bincode::serialize(&opening_msg).expect("serialise opening"));
        }
        out
    }

    fn on_inbound(&mut self, _from: PeerId, _payload: Vec<u8>) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        // One MSE insert per message: the leader peels every active client's
        // element out of the summed plaintext, so concurrent senders don't collide.
        let symbols = bytes_to_symbols(&payload, self.mse.payload_symbols);
        let mut enc = MseEncoding::new(self.mse.clone());
        enc.insert(&mut self.r_rng, &symbols);
        let mut polys = enc.pack();
        polys.resize(message_polys(&self.pp), KahePoly::default());
        self.pending = Some(polys);
    }

    fn set_cover_rate(&mut self, rate: f32) {
        self.cover_rate = rate;
    }
}

/// One Panetiere round's collected state on a server. A full Panetiere round
/// spans two anymone rounds (clients→servers, then servers→servers), and the
/// runtime ticks clients every round, so several rounds are in flight at once.
/// Everything is therefore bucketed by the round stamped on each wire message —
/// without this, back-to-back rounds overwrite ciphertexts (client ids are
/// stable across rounds) and mix openings, losing traffic.
#[derive(Default)]
struct PanetiereRoundState {
    publics: HashMap<ClientId, ClientBulletinEntry>,
    inbox_items: Vec<(ClientId, Opening)>,
    peer_server_publics: HashMap<ServerId, ServerBulletinEntry>,
    raw_server_publics: HashMap<ServerId, Vec<u8>>,
    reported_bad: HashSet<ServerId>,
    emitted_my_public: bool,
    decoded: bool,
    /// Leader-only (aggregated flow): the agreed summed entry per group.
    group_aggregates: HashMap<u32, GroupAgg>,
}

#[derive(Clone)]
struct GroupAgg {
    clients: Vec<ClientId>,
    entry: ClientBulletinEntry,
}

/// Server-side session across Panetiere rounds. Lifecycle, per round `r`:
/// 1. `on_inbound`: file each message into the bucket for *its* stamped round —
///    `ClientPublic`s and the openings addressed to us, plus peer `ServerPublic`s.
/// 2. `end_round(r)`: emit our `ServerPublic` for round `r` from that bucket,
///    then decode any bucket (incl. earlier rounds) that has ≥ `t` peer
///    `ServerPublic`s — peers' shares for round `r` only arrive during `r+1`,
///    so decode naturally lags one anymone round.
/// How a relay obtains the round's canonical client set.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SetMode {
    /// Public-subnet leader: derive the set, announce it, broadcast `Decoded`.
    Leader,
    /// Public-subnet non-leader: adopt the leader's announced set.
    Follower { leader: PeerId },
    /// Leaderless committee: derive own set; decode via ≥t agreement.
    SelfDerived,
}

pub struct PanetiereServerSession {
    pp: Arc<ProtocolParams>,
    mse: MseParams,
    server_id: ServerId,
    max_clients: u32,
    exchange: ExchangeIdentity,
    mode: SetMode,
    /// Anonymity floor: never decode a canonical set smaller than this.
    min_clients: usize,
    server_pubkeys: HashMap<ServerId, Pubkey>,
    /// Per-round buckets, ordered so decode and GC walk oldest-first.
    rounds: std::collections::BTreeMap<Round, PanetiereRoundState>,
    /// Leader/Follower: the one canonical set per round (announced by the leader).
    client_set_by_round: std::collections::BTreeMap<Round, Vec<ClientId>>,
    announced_rounds: HashSet<Round>,
    misbehavior: Option<Misbehavior>,
    /// Set on every relay of an aggregated subnet. Drives two things: canonical
    /// is the openings we hold (clients send `ClientPublic`s to aggregators, not
    /// relays), and decode re-sums the signed group aggregates instead of
    /// individual `ClientPublic`s.
    aggregation: Option<LeaderAggregation>,
}

/// Rounds kept after they go quiet. A bucket decodes at `end_round(r+1)`; one
/// that never reaches `t` (a stalled round) is dropped this many rounds later so
/// memory stays bounded.
const PANETIERE_ROUND_RETENTION: Round = 4;

impl PanetiereServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        mse: MseParams,
        server_id: ServerId,
        max_clients: u32,
        exchange: ExchangeIdentity,
        mode: SetMode,
        min_clients: u32,
        server_pubkeys: HashMap<ServerId, Pubkey>,
        aggregation: Option<LeaderAggregation>,
    ) -> Self {
        PanetiereServerSession {
            pp,
            mse,
            server_id,
            max_clients,
            exchange,
            mode,
            min_clients: min_clients as usize,
            server_pubkeys,
            rounds: std::collections::BTreeMap::new(),
            client_set_by_round: std::collections::BTreeMap::new(),
            announced_rounds: HashSet::new(),
            misbehavior: None,
            aggregation,
        }
    }
}

/// Decode `state`'s round, excluding any server whose share fails its opening.
/// Returns the decoded payload (if ≥ `t` honest shares remain) plus the
/// `ServerId`s whose shares were rejected — decode and fault detection are
/// independent under Shamir threshold. Free function (not a method) so it can
/// run while `rounds` is borrowed mutably for iteration.
fn try_decode_round(
    pp: &ProtocolParams,
    state: &PanetiereRoundState,
    anchor: Option<&[ClientId]>,
    min_clients: usize,
) -> (Option<Vec<KahePoly>>, Vec<ServerId>) {
    if state.peer_server_publics.len() < pp.shamir.t {
        return (None, Vec::new());
    }
    // Public subnets pass the leader's single announced set as `anchor` — decode
    // strictly over it. The leaderless committee passes `None`: it has no
    // announcer, so it falls back to the set ≥t relays agree on (largest first).
    let candidates: Vec<(Vec<ClientId>, Vec<ServerBulletinEntry>)> = match anchor {
        Some(set) => {
            let mut canonical = set.to_vec();
            canonical.sort();
            canonical.dedup();
            let outputs = state
                .peer_server_publics
                .values()
                .filter(|sp| {
                    let mut c = sp.clients.clone();
                    c.sort();
                    c.dedup();
                    c == canonical
                })
                .cloned()
                .collect();
            vec![(canonical, outputs)]
        }
        None => {
            let mut groups: std::collections::BTreeMap<Vec<ClientId>, Vec<ServerBulletinEntry>> =
                std::collections::BTreeMap::new();
            for sp in state.peer_server_publics.values() {
                let mut key = sp.clients.clone();
                key.sort();
                groups.entry(key).or_default().push(sp.clone());
            }
            let mut c: Vec<(Vec<ClientId>, Vec<ServerBulletinEntry>)> = groups.into_iter().collect();
            c.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
            c
        }
    };

    for (canonical, mut outputs) in candidates {
        if canonical.len() < min_clients {
            continue;
        }
        if outputs.len() < pp.shamir.t {
            continue;
        }
        let publics: Vec<(ClientId, ClientBulletinEntry)> = canonical
            .iter()
            .filter_map(|cid| state.publics.get(cid).map(|p| (*cid, p.clone())))
            .collect();
        if publics.len() != canonical.len() {
            continue;
        }
        let mut culprits = Vec::new();
        loop {
            if outputs.len() < pp.shamir.t {
                break;
            }
            match aggregate_and_decrypt(pp, &canonical, &publics, &outputs) {
                Ok(plain) => return (Some(plain), culprits),
                Err(VerifyError::InvalidServerOpening(i))
                | Err(VerifyError::ShareOpeningMismatch(i)) => {
                    culprits.push(outputs[i].server_id);
                    outputs.remove(i);
                }
                Err(_) => break,
            }
        }
    }
    (None, Vec::new())
}

/// Aggregated-flow decode (leader): re-sum the per-group aggregates instead of
/// the individual `ClientPublic`s, then verify+decrypt against the relays'
/// openings. Needs every group's aggregate, and their union must equal the
/// servers' canonical set (else the summed ctxt/comm cover a different set than
/// the openings — treat as not-yet-decodable).
fn try_decode_round_aggregated(
    pp: &ProtocolParams,
    _agg: &LeaderAggregation,
    state: &PanetiereRoundState,
    anchor: Option<&[ClientId]>,
    min_clients: usize,
) -> (Option<Vec<KahePoly>>, Vec<ServerId>) {
    let mut culprits = Vec::new();
    if state.peer_server_publics.len() < pp.shamir.t {
        return (None, culprits);
    }
    let canonical = match anchor {
        Some(set) => Some(set.to_vec()),
        None => state
            .peer_server_publics
            .values()
            .next()
            .map(|sp| sp.clients.clone()),
    };
    let Some(mut canonical) = canonical else {
        return (None, culprits);
    };
    canonical.sort();
    canonical.dedup();
    if canonical.len() < min_clients {
        return (None, culprits);
    }
    let mut union: Vec<ClientId> = state
        .group_aggregates
        .values()
        .flat_map(|g| g.clients.iter().copied())
        .collect();
    union.sort();
    union.dedup();
    if union != canonical {
        return (None, culprits);
    }

    let ctxts: Vec<Vec<KahePoly>> = state
        .group_aggregates
        .values()
        .map(|g| g.entry.ctxt.clone())
        .collect();
    let comms: Vec<_> = state
        .group_aggregates
        .values()
        .map(|g| g.entry.comm.clone())
        .collect();
    let total_ctxt = Kahe::agg_ctxt(&ctxts);
    let total_comm = HidingMerkleCommitment::sum_commitments(&comms);

    let mut outputs: Vec<ServerBulletinEntry> =
        state.peer_server_publics.values().cloned().collect();
    loop {
        if outputs.len() < pp.shamir.t {
            return (None, culprits);
        }
        match decrypt_aggregate(pp, &total_ctxt, &total_comm, &outputs) {
            Ok(plain) => return (Some(plain), culprits),
            Err(VerifyError::InvalidServerOpening(i))
            | Err(VerifyError::ShareOpeningMismatch(i)) => {
                culprits.push(outputs[i].server_id);
                outputs.remove(i);
            }
            Err(_) => return (None, culprits),
        }
    }
}

impl Session for PanetiereServerSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let Ok(msg) = bincode::deserialize::<PanetiereWire>(&payload) else {
            return Vec::new();
        };
        match msg {
            PanetiereWire::ClientPublic {
                round,
                client_id,
                entry,
            } => {
                if let Some(entry) = ClientBulletinEntry::from_bytes(&entry) {
                    self.rounds
                        .entry(round)
                        .or_default()
                        .publics
                        .insert(ClientId(client_id), entry);
                }
            }
            PanetiereWire::Opening {
                round,
                client_id,
                target_server,
                sealed,
            } => {
                if target_server == self.server_id.0 {
                    let Some(plain) = self.exchange.unseal(&sealed) else {
                        return Vec::new();
                    };
                    let Ok(packed) = bincode::deserialize::<PackedOpeningWire>(&plain) else {
                        return Vec::new();
                    };
                    let Ok(opening) = Opening::from_packed(&PackedOpening::from(packed)) else {
                        return Vec::new();
                    };
                    self.rounds
                        .entry(round)
                        .or_default()
                        .inbox_items
                        .push((ClientId(client_id), opening));
                }
            }
            PanetiereWire::ServerPublic {
                round,
                server_id,
                clients,
                agg_open,
                agg_share,
            } => {
                let n_shares = agg_open.mu_cs as usize;
                let Ok(agg_open) = Opening::from_packed(&PackedOpening::from(agg_open)) else {
                    return Vec::new();
                };
                if let Some(agg_share) = panetiere::cs::unpack_cs_shares(&agg_share, n_shares) {
                    let bucket = self.rounds.entry(round).or_default();
                    bucket
                        .raw_server_publics
                        .insert(ServerId(server_id), payload.clone());
                    bucket.peer_server_publics.insert(
                        ServerId(server_id),
                        ServerBulletinEntry {
                            server_id: ServerId(server_id),
                            clients: clients.into_iter().map(ClientId).collect(),
                            agg_open,
                            agg_share,
                        },
                    );
                }
            }
            // Servers decode themselves; `Decoded` is for watchers.
            PanetiereWire::Decoded { .. } => {}
            PanetiereWire::ClientSet { round, clients } => {
                if let SetMode::Follower { leader } = self.mode {
                    if from == leader {
                        self.client_set_by_round
                            .entry(round)
                            .or_insert_with(|| clients.into_iter().map(ClientId).collect());
                    }
                }
            }
            PanetiereWire::GroupAggregate {
                round,
                group,
                clients,
                entry,
                signer,
                signature,
            } => {
                let Some(agg) = self.aggregation.as_ref() else {
                    return Vec::new();
                };
                let Some(roster) = agg.roster.get(&group) else {
                    return Vec::new();
                };
                if !roster.contains(&signer)
                    || !signer.verify(
                        &group_aggregate_signing_bytes(round, group, &clients, &entry),
                        &signature,
                    )
                {
                    return Vec::new();
                }
                let Some(parsed) = ClientBulletinEntry::from_bytes(&entry) else {
                    return Vec::new();
                };
                // 1-of-n: replicas emit identical bytes, so the first valid
                // aggregate per group stands; later replicas are redundant.
                self.rounds
                    .entry(round)
                    .or_default()
                    .group_aggregates
                    .entry(group)
                    .or_insert(GroupAgg {
                        clients: clients.into_iter().map(ClientId).collect(),
                        entry: parsed,
                    });
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let mut outbound: Vec<Vec<u8>> = Vec::new();
        let mut decoded: Vec<Vec<u8>> = Vec::new();

        // Phase 1: emit our ServerPublic for every settled round (`r <= round`)
        // we've collected openings for and haven't emitted yet — not just the
        // just-ended round. A relay whose round timer fires before that round's
        // openings arrive (boundary skew) would otherwise strand them: Phase 1
        // never revisits the bucket, so the round falls below `t` ServerPublics
        // and never decodes — losing a client message that's sent only once.
        // Withhold drops us from the threshold set entirely; the others still
        // decode under t-of-n. CorruptShare instead emits a share that no longer
        // matches its (valid) opening, so the decoding leader attributes it.
        let withholding = self.misbehavior == Some(Misbehavior::Withhold);
        let corrupt_share = self.misbehavior == Some(Misbehavior::CorruptShare);
        let aggregated = self.aggregation.is_some();
        let is_leader = self.mode == SetMode::Leader;
        let self_derived = self.mode == SetMode::SelfDerived;
        let cs = &self.pp.cs;
        let sid = self.server_id;

        // Phase A (leader only): announce the one canonical set per settled round,
        // exactly once, seeding our own `client_set_by_round` from it.
        if is_leader && !withholding {
            let mut announce: Vec<(Round, Vec<ClientId>)> = Vec::new();
            for (&r, state) in self.rounds.iter() {
                if r > round || self.announced_rounds.contains(&r) || state.inbox_items.is_empty() {
                    continue;
                }
                let mut canonical: Vec<ClientId> = if aggregated {
                    state.inbox_items.iter().map(|(cid, _)| *cid).collect()
                } else {
                    state
                        .inbox_items
                        .iter()
                        .filter_map(|(cid, _)| state.publics.get(cid).map(|_| *cid))
                        .collect()
                };
                canonical.sort();
                canonical.dedup();
                if !canonical.is_empty() {
                    announce.push((r, canonical));
                }
            }
            for (r, canonical) in announce {
                outbound.push(
                    bincode::serialize(&PanetiereWire::ClientSet {
                        round: r,
                        clients: canonical.iter().map(|c| c.0).collect(),
                    })
                    .expect("serialise client set"),
                );
                self.client_set_by_round.insert(r, canonical);
                self.announced_rounds.insert(r);
            }
        }

        if !withholding {
            for (&r, state) in self.rounds.iter_mut() {
                if r > round || state.emitted_my_public || state.inbox_items.is_empty() {
                    continue;
                }
                // Public subnets share over the leader's announced set; the
                // leaderless committee derives its own (public + opening it holds,
                // or openings alone in the aggregated flow).
                let canonical: Vec<ClientId> = if self_derived {
                    let mut c: Vec<ClientId> = if aggregated {
                        state.inbox_items.iter().map(|(cid, _)| *cid).collect()
                    } else {
                        state
                            .inbox_items
                            .iter()
                            .filter_map(|(cid, _)| state.publics.get(cid).map(|_| *cid))
                            .collect()
                    };
                    c.sort();
                    c.dedup();
                    c
                } else {
                    match self.client_set_by_round.get(&r) {
                        Some(set) => set.clone(),
                        None => continue,
                    }
                };
                if canonical.is_empty() {
                    continue;
                }
                // run_server_round is all-or-nothing: skip a round we can't fully
                // cover rather than share over a different set than the leader's.
                if !self_derived {
                    let present: HashSet<ClientId> =
                        state.inbox_items.iter().map(|(cid, _)| *cid).collect();
                    if !canonical.iter().all(|c| present.contains(c)) {
                        continue;
                    }
                }
                let inbox = ServerInbox {
                    server_id: sid,
                    items: std::mem::take(&mut state.inbox_items),
                };
                if let Ok(sp) = run_server_round(&inbox, &canonical) {
                    let (r_b, s_b, t_b) =
                        panetiere::cs::aggregated_opening_pack_bounds(cs, sp.clients.len() as u32);
                    let packed = sp.agg_open.pack(r_b, s_b, t_b);
                    let mut agg_share = panetiere::cs::pack_cs_shares(&sp.agg_share);
                    if corrupt_share {
                        if let Some(b) = agg_share.first_mut() {
                            *b ^= 0x01;
                        }
                    }
                    let wire = PanetiereWire::ServerPublic {
                        round: r,
                        server_id: sp.server_id.0,
                        clients: sp.clients.iter().map(|c| c.0).collect(),
                        agg_open: PackedOpeningWire::from(&packed),
                        agg_share,
                    };
                    // Cache our own honest public so try_decode sees it as a peer entry.
                    state.peer_server_publics.insert(sp.server_id, sp);
                    outbound.push(bincode::serialize(&wire).expect("serialise server public"));
                    state.emitted_my_public = true;
                }
            }
        }

        // Phase 2: decode every bucket that now has enough peer ServerPublics —
        // earlier rounds first. A round's shares arrive during the next anymone
        // round, so the round just ended usually isn't decodable yet; an earlier
        // one is.
        let mut faults: Vec<Fault> = Vec::new();
        for (r, state) in self.rounds.iter_mut() {
            if state.decoded {
                continue;
            }
            let anchor: Option<Vec<ClientId>> = if self_derived {
                None
            } else {
                self.client_set_by_round.get(r).cloned()
            };
            let (decoded_round, bad) = match self.aggregation.as_ref() {
                Some(agg) => {
                    try_decode_round_aggregated(&self.pp, agg, state, anchor.as_deref(), self.min_clients)
                }
                None => try_decode_round(&self.pp, state, anchor.as_deref(), self.min_clients),
            };
            if is_leader {
                for sid in bad {
                    if !state.reported_bad.insert(sid) {
                        continue;
                    }
                    if let Some(pk) = self.server_pubkeys.get(&sid) {
                        faults.push(Fault {
                            kind: FaultKind::Integrity,
                            attribution: Attribution::Peers(vec![*pk]),
                            evidence: state
                                .raw_server_publics
                                .get(&sid)
                                .cloned()
                                .unwrap_or_default(),
                        });
                    }
                }
            }
            if let Some(plain) = decoded_round {
                // Peel every client's MSE element out of the summed plaintext —
                // each is one message, so concurrent senders don't collide. A
                // cover-only round peels to nothing; a peel stall yields nothing.
                let n = MseEncoding::n_polys(&self.mse).min(plain.len());
                let msgs: Vec<Vec<u8>> = MseEncoding::unpack(&self.mse, &plain[..n])
                    .decode()
                    .map(|elements| {
                        elements
                            .into_iter()
                            .map(|symbols| symbols_to_bytes(&symbols))
                            .filter(|b| b.iter().any(|x| *x != 0))
                            .collect()
                    })
                    .unwrap_or_default();
                if !msgs.is_empty() {
                    if is_leader {
                        let wire = PanetiereWire::Decoded { round: *r, payloads: msgs.clone() };
                        outbound.push(bincode::serialize(&wire).expect("serialise decoded"));
                    }
                    decoded.extend(msgs);
                }
                state.decoded = true;
                // Free the heavy crypto state; keep the (now-empty) bucket
                // marked `decoded` so a share that arrives a round late lands
                // here and is skipped rather than re-decoding into a duplicate.
                state.publics.clear();
                state.inbox_items.clear();
                state.peer_server_publics.clear();
                state.raw_server_publics.clear();
            }
        }

        // GC: age out buckets (decoded or stalled) past the retention window so
        // memory stays bounded; the window keeps a round alive long enough for
        // its shares (which arrive the next anymone round) to decode it.
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        self.rounds.retain(|r, _| *r >= cutoff);
        self.client_set_by_round.retain(|r, _| *r >= cutoff);
        self.announced_rounds.retain(|r| *r >= cutoff);

        RoundOutcome {
            outbound,
            decoded,
            faults,
        }
    }

    fn set_misbehavior(&mut self, mode: Option<Misbehavior>) {
        self.misbehavior = mode;
    }
}

/// Aggregator-side session: collects its group's `ClientPublic`s, sums their
/// ciphertexts+commitments at `end_round`, and emits one signed `GroupAggregate`.
/// Holds only public data — no openings.
pub struct PanetiereAggregatorSession {
    group: u32,
    group_count: u32,
    identity: Identity,
    rounds: std::collections::BTreeMap<Round, HashMap<ClientId, ClientBulletinEntry>>,
    emitted: HashSet<Round>,
}

impl PanetiereAggregatorSession {
    pub fn new(group: u32, group_count: u32, identity: Identity) -> Self {
        PanetiereAggregatorSession {
            group,
            group_count,
            identity,
            rounds: std::collections::BTreeMap::new(),
            emitted: HashSet::new(),
        }
    }
}

impl Session for PanetiereAggregatorSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(PanetiereWire::ClientPublic {
            round,
            client_id,
            entry,
        }) = bincode::deserialize::<PanetiereWire>(&payload)
        {
            if client_id % self.group_count == self.group {
                if let Some(entry) = ClientBulletinEntry::from_bytes(&entry) {
                    self.rounds
                        .entry(round)
                        .or_default()
                        .insert(ClientId(client_id), entry);
                }
            }
        }
        Vec::new()
    }

    /// Emit the group's batch mid-round, so the leader can announce the set and
    /// decode within the round rather than a round late.
    fn mid_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        let mut outbound = Vec::new();
        if !self.emitted.contains(&round) {
            if let Some(entries) = self.rounds.get(&round).filter(|e| !e.is_empty()) {
                let items: Vec<(ClientId, ClientBulletinEntry)> =
                    entries.iter().map(|(c, e)| (*c, e.clone())).collect();
                let agg = run_aggregator_round(&items);
                let clients: Vec<u32> = agg.clients.iter().map(|c| c.0).collect();
                let entry = ClientBulletinEntry {
                    ctxt: agg.summed_ctxt,
                    comm: agg.summed_comm,
                }
                .to_bytes();
                let signature = self.identity.sign(&group_aggregate_signing_bytes(
                    round, self.group, &clients, &entry,
                ));
                let wire = PanetiereWire::GroupAggregate {
                    round,
                    group: self.group,
                    clients,
                    entry,
                    signer: self.identity.pubkey(),
                    signature,
                };
                outbound.push(bincode::serialize(&wire).expect("serialise group aggregate"));
                self.emitted.insert(round);
            }
        }
        outbound
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        self.rounds.retain(|r, _| *r >= cutoff);
        self.emitted.retain(|r| *r >= cutoff);
        RoundOutcome::default()
    }
}

/// Non-relay watcher for a Panetiere subnet: surfaces the leader's `Decoded`
/// broadcasts for pipe routing, carrying zero crypto state.
pub struct PanetiereWatchSession {
    leader_pk: PeerId,
    routed_rounds: std::collections::HashSet<u64>,
    pending_decoded: Vec<Vec<u8>>,
}

impl PanetiereWatchSession {
    pub fn new(leader_pk: PeerId) -> Self {
        PanetiereWatchSession {
            leader_pk,
            routed_rounds: std::collections::HashSet::new(),
            pending_decoded: Vec::new(),
        }
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn anon_set_only_from_leader_client_set() {
        let leader = Identity::generate().pubkey();
        let other = Identity::generate().pubkey();
        let mut obs = PanetiereObserverSession::new(vec![leader, other], Some(leader), 2);
        let cs = bincode::serialize(&PanetiereWire::ClientSet {
            round: 1,
            clients: vec![10, 20, 30],
        })
        .unwrap();
        obs.on_inbound(other, cs.clone());
        assert_eq!(obs.anonymity_set(), None, "non-leader ClientSet must be ignored");
        obs.on_inbound(leader, cs);
        assert_eq!(obs.anonymity_set(), Some(3));

        let dec = bincode::serialize(&PanetiereWire::Decoded { round: 7, payloads: vec![] }).unwrap();
        obs.on_inbound(other, dec.clone());
        assert_eq!(obs.output_frontier(), None, "forged Decoded must not advance output");
        obs.on_inbound(leader, dec);
        assert_eq!(obs.output_frontier(), Some(7));
    }

    #[test]
    fn wire_estimate_covers_real_messages() {
        use std::collections::HashMap;
        let (msg_size, est_msgs, cset, n_relays) = (256usize, 4u32, 40u32, 3usize);
        let est = max_wire_estimate(msg_size, est_msgs, cset, n_relays);

        let mse = channel_mse_params(est_msgs, msg_size, [1u8; 32]);
        let pp = setup_pp(&mse, n_relays, [1u8; 32]);
        let server_ids: Vec<ServerId> = (0..n_relays as u32).map(ServerId).collect();
        let mut c =
            PanetiereClientSession::new(pp.clone(), mse, ClientId(1), server_ids, HashMap::new(), [2u8; 32]);
        let client_public = c
            .begin_round(0, Instant::now())
            .iter()
            .map(|m| m.len())
            .max()
            .unwrap();
        assert!(est >= client_public, "estimate {est} < real ClientPublic {client_public}");
        assert!(
            est >= pp.cs.aggregated_server_crypto_len(cset),
            "estimate omits the ServerPublic crypto term"
        );
    }
}

impl Session for PanetiereWatchSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(PanetiereWire::Decoded { round, payloads }) =
            bincode::deserialize::<PanetiereWire>(&payload)
        {
            if from == self.leader_pk && !self.routed_rounds.contains(&round) {
                self.routed_rounds.insert(round);
                self.pending_decoded.extend(payloads);
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        let decoded = std::mem::take(&mut self.pending_decoded);
        RoundOutcome {
            outbound: Vec::new(),
            decoded,
            faults: Vec::new(),
        }
    }
}
