//! Panetiere `Session` wrappers.
//!
//! Topic layout matches ADCNet: client messages on ingress (every relay reads —
//! all of them combine), `ServerPublic`s on shares, the leader's `Decoded` on
//! broadcast. Openings are sealed to their target server: ≥t plaintext openings
//! reconstruct the client's message.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use chipmunk_code::{CsPoly, KahePoly};
use panetiere::bulletin::{ClientBulletinEntry, ServerBulletinEntry};
use panetiere::cs::{Opening, PackedOpening};
use panetiere::channel::{self, ChannelParams};
use panetiere::pke;
use panetiere::protocol::aggregator::run_aggregator_round;
use panetiere::protocol::client::run_client_round;
use panetiere::protocol::recipient::{
    recover_aggregated, recover_direct, CandidateRejection, RecipientError, SetPolicy,
};
use panetiere::protocol::server::{run_server_round, unseal_opening, ServerInbox};

use panetiere::protocol::{
    message_polys, round_wire_sizes, ClientId, ProtocolParams, ServerId, SessionId,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::{ExchangePublicKeyWire, PanetiereConfig, ProtocolConfig, Round, Subnet};
use crate::faults::{Attribution, Fault, FaultKind, OutputFaultTracker};
use crate::identity::{Identity, Pubkey};
use crate::log_target::{PANETIERE, SCHED};
use crate::runtime::{
    aggregator_group_of, client_aggregator_topic, deadline_for, egress_dest,
    gossip_faults, handle_inbound, publish_and_loop_back, recv_any, round_at, route_to_pipe,
    subnet_aggregation, subnet_leader_pk, AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::Subscription;

/// Channel sizing for a subnet carrying up to `rho` real messages of
/// `message_bytes` each. `prf_key` is domain-separated from the shared
/// `setup_seed` so all participants agree.
pub(crate) fn channel_params(rho: u32, message_bytes: usize, setup_seed: [u8; 32]) -> ChannelParams {
    let mut prf_key = setup_seed;
    prf_key[0] ^= 0x5C;
    ChannelParams::for_messages(rho, message_bytes, prf_key)
}

/// Message-byte bound for the committee's config-anonymising channel. Must fit
/// a serialized `SignedProposal` at `MAX_SUBNETS` and `MAX_COMMITTEE_RELAYS` —
/// asserted against the real `build_body` packing in
/// `scheduler_core::sizing_tests`, which measured 35940 bytes there.
///
/// A proposal grows ~2 KB per placed relay: its 1184-byte ML-KEM encapsulation
/// key and 33-byte ECDH point, plus its pubkey in every subnet roster and
/// aggregator group. Raising `MAX_COMMITTEE_RELAYS` means raising this, and it
/// must match across members.
pub const COMMITTEE_MSG_BYTES: usize = 36864;

/// Per-subnet Panetiere parameters. The KAHE width is exactly one packed
/// encoding, which `ChannelParams` derives.
pub(crate) fn setup_pp(
    params: &ChannelParams,
    n_servers: usize,
    setup_seed: [u8; 32],
) -> Arc<ProtocolParams> {
    let mut rng = ChaCha20Rng::from_seed(setup_seed);
    Arc::new(params.protocol_params(&mut rng, n_servers))
}

/// `client_id % groups` is never re-drawn, so an even share turns the busiest
/// bin away every round for as long as that roster lasts.
pub(crate) const AGGREGATOR_GROUP_SLACK: u32 = 2;

pub(crate) fn aggregator_group_allowance(client_set_max: u32, groups: u32) -> usize {
    client_set_max
        .div_ceil(groups.max(1))
        .saturating_mul(AGGREGATOR_GROUP_SLACK)
        .max(1) as usize
}

/// Every group full: a frozen group sum can't be truncated, so this and not
/// `client_set_max` is what the announced set can reach.
pub(crate) fn aggregated_client_set_bound(client_set_max: u32, groups: u32) -> u32 {
    (aggregator_group_allowance(client_set_max, groups) as u32).saturating_mul(groups.max(1))
}

/// Conservative upper bound on the largest per-round wire message a Panetiere
/// subnet broadcasts, for the committee's p2p size-cap guard. Crypto sizes come
/// from `protocol::round_wire_sizes`; the framing allowance is ours.
pub(crate) fn max_wire_estimate(
    message_size: usize,
    estimated_messages: u32,
    client_set_max: u32,
    n_relays: usize,
) -> usize {
    const FRAMING: usize = 512;
    let ch = channel_params(estimated_messages, message_size, [0u8; 32]);
    let w = round_wire_sizes(n_relays.max(1), ch.n_polys(), client_set_max);
    let client_public = w.client_post + FRAMING;
    let server_public = w.server_entry + client_set_max as usize * 4 + FRAMING;
    let decoded = estimated_messages as usize * message_size + FRAMING;
    client_public.max(server_public).max(decoded)
}

/// Panetière `sid` for one round of one subnet. The round must stay in the
/// hash: openings are bound to the sid, so a constant one permits cross-round
/// replay.
pub(crate) fn session_id(setup_seed: &[u8; 32], round: Round) -> SessionId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"anymone/panetiere/sid");
    h.update(setup_seed);
    h.update(round.to_le_bytes());
    SessionId(h.finalize().into())
}

/// `pk`'s position in the sorted relay list — the Panetiere `ServerId`.
pub(crate) fn server_index(relays: &[Pubkey], pk: Pubkey) -> Option<u32> {
    let mut sorted = relays.to_vec();
    sorted.sort();
    sorted.iter().position(|p| *p == pk).map(|i| i as u32)
}

/// Deterministic `ClientId` from a pubkey's first 4 bytes; stable per node+pipe
/// so the decoder merges a round's publics with its openings.
pub fn client_id_from_pubkey(pk: Pubkey) -> ClientId {
    ClientId(u32::from_be_bytes([pk.0[0], pk.0[1], pk.0[2], pk.0[3]]))
}

/// Wire length of a `ClientBulletinEntry` under `pp`'s geometry.
pub(crate) fn entry_wire_len(pp: &Arc<ProtocolParams>) -> usize {
    ClientBulletinEntry::packed_len(message_polys(pp))
}

/// Panetiere `(ServerId, pke::PublicKey)` roster for sealing client openings —
/// relays whose exchange key is missing or undecodable are skipped.
pub(crate) fn seal_roster(
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
) -> Vec<(ServerId, pke::PublicKey)> {
    crate::keys::roster_seal_pubkeys(&subnet.relays, relay_xk)
        .into_iter()
        .map(|(i, pk)| (ServerId(i as u32), pk))
        .collect()
}

fn client_session(
    pp: &Arc<ProtocolParams>,
    mse: &ChannelParams,
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
    identity: &Identity,
    setup_seed: [u8; 32],
) -> Box<dyn Session> {
    let servers = seal_roster(relay_xk, subnet);
    if servers.len() != subnet.relays.len() {
        tracing::warn!(
            target: PANETIERE,
            have = servers.len(),
            need = subnet.relays.len(),
            "panetiere client: relay exchange keys incomplete"
        );
    }
    // Secret entropy: a seed from the (public) return tag would let anyone
    // replay the client's round.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut session = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_id_from_pubkey(identity.pubkey()),
        servers,
        seed,
    );
    session.set_setup_seed(setup_seed);
    Box::new(session)
}

fn server_session(
    pp: &Arc<ProtocolParams>,
    mse: &ChannelParams,
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
    let mut session = PanetiereServerSession::new(
        pp.clone(),
        mse.clone(),
        server_id,
        identity.clone(),
        mode,
        cfg.client_set_min,
        server_pubkeys,
        aggregation,
    );
    session.set_client_set_max(cfg.client_set_max as usize);
    session.set_setup_seed(cfg.setup_seed);
    Box::new(session)
}

/// Self-contained Panetiere subnet driver: builds this node's sessions, then owns
/// the round loop. The runtime dispatches here for Panetiere subnets.
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
        ProtocolConfig::Panetiere(c) => c.clone(),
        _ => unreachable!("panetiere::run_subnet on a non-Panetiere subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let mse = channel_params(cfg.estimated_messages, cfg.message_size, cfg.setup_seed);
    let pp = setup_pp(&mse, subnet.relays.len(), cfg.setup_seed);
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg_topic = client_aggregator_topic(&subnet, identity_pk);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(&pp, &mse, &cfg, &subnet, &inner.identity, leader_pk),
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
            agg_session.set_client_set_max(aggregator_group_allowance(
                cfg.client_set_max,
                a.groups.len() as u32,
            ));
            agg_session.set_entry_len(entry_wire_len(&pp));
            sessions.insert(SessionKey::Aggregator, Box::new(agg_session));
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
            is_shares_topic_msg,
            is_client_public,
            client_agg_topic.as_deref(),
            key,
            bytes,
        )
    };

    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(1);
    // Aggregated subnets get a third checkpoint between mid and end (2/3, 1/3);
    // direct subnets keep mid at 1/2 with commit coinciding with (a no-op at) end.
    let aggregated_subnet = subnet_aggregation(&subnet).is_some();
    let (mid_offset_ms, commit_offset_ms) = if aggregated_subnet {
        (2 * dur_ms / 3, dur_ms / 3)
    } else {
        (dur_ms / 2, 0)
    };

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
        aggregated = aggregated_subnet,
        dur_ms,
        "panetiere worker: start"
    );
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut mid_deadline = deadline - std::time::Duration::from_millis(mid_offset_ms);
    let mut commit_deadline = deadline - std::time::Duration::from_millis(commit_offset_ms);
    let mut mid_done = false;
    let mut commit_done = false;

    if let Some(m) = fault_monitor.as_mut() {
        m.begin_round(round, Instant::now());
    }
    crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
        client_session(&pp, &mse, &relay_xk, &subnet, &inner.identity, cfg.setup_seed)
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

            _ = tokio::time::sleep_until(mid_deadline), if !mid_done => {
                mid_done = true;
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

            _ = tokio::time::sleep_until(commit_deadline), if !commit_done => {
                commit_done = true;
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

            _ = tokio::time::sleep_until(deadline) => {
                drain_inbound_upto(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, drain_cap).await;
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults: Vec<Fault> = Vec::new();
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
                    route_to_pipe(&inner, &bytes);
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
                        "panetiere worker: drain exit"
                    );
                    return;
                }
                if let Some(m) = fault_monitor.as_mut() {
                    faults.extend(m.end_round(round, Instant::now()).faults);
                }
                crate::runtime::log_round_outcome("panetiere", subnet.id, round, n_decoded, faults.len());
                let faults = faults
                    .into_iter()
                    .map(|f| (evidence_round(&f.evidence).unwrap_or(round), f))
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
                            "panetiere worker: graceful exit"
                        );
                        return;
                    }
                    tracing::debug!(
                        target: SCHED,
                        subnet = subnet.id,
                        round,
                        "panetiere worker: graceful exit; draining one round"
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
                        "panetiere worker: lagged past a round boundary, skipping rounds"
                    );
                }
                round = next;
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                mid_deadline = deadline - std::time::Duration::from_millis(mid_offset_ms);
                commit_deadline = deadline - std::time::Duration::from_millis(commit_offset_ms);
                mid_done = false;
                commit_done = false;
                if drain_cap.is_none() {
                    if let Some(m) = fault_monitor.as_mut() {
                        m.begin_round(round, Instant::now());
                    }
                    crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
                        client_session(&pp, &mse, &relay_xk, &subnet, &inner.identity, cfg.setup_seed)
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

/// Tagged wire form for every Panetiere message published on a subnet topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum PanetiereWire {
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
        /// Sealed envelope (`panetiere::pke`) over the packed `Opening`, opened
        /// only by the target server. Never plaintext: ≥t openings reconstruct
        /// the client's message.
        #[serde(with = "serde_bytes")]
        sealed: Vec<u8>,
    },
    ServerPublic {
        round: u64,
        server_id: u32,
        clients: Vec<u32>,
        /// `PackedOpening::to_bytes` of the aggregated opening.
        #[serde(with = "serde_bytes")]
        agg_open: Vec<u8>,
        /// Bit-packed κ_kahe CsPoly shares (count = the packed `mu_cs`).
        #[serde(with = "serde_bytes")]
        agg_share: Vec<u8>,
        /// By `roster[server_id]` over [`server_public_signing_bytes`] —
        /// attribution binds to the key, not the self-declared slot.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
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
    ClientSet {
        round: u64,
        clients: Vec<u32>,
        /// Distinct clients seen incl. capacity-rejected — the sizing signal.
        demand: u32,
    },
    /// Scheduled Panetiere only: `round`'s decoded reservation list
    /// `(rand, size)`, leader-broadcast so clients derive `round+1`'s
    /// message-vector allocation via `codec::beacon` + `codec::allocate`.
    Reservations {
        round: u64,
        entries: Vec<(u16, u16)>,
    },
}

impl PanetiereWire {
    /// The `round` field carried by every variant.
    pub(crate) fn round(&self) -> u64 {
        match self {
            PanetiereWire::ClientPublic { round, .. }
            | PanetiereWire::Opening { round, .. }
            | PanetiereWire::ServerPublic { round, .. }
            | PanetiereWire::Decoded { round, .. }
            | PanetiereWire::GroupAggregate { round, .. }
            | PanetiereWire::ClientSet { round, .. }
            | PanetiereWire::Reservations { round, .. } => *round,
        }
    }
}

/// True if `round` falls within `PANETIERE_ROUND_WINDOW` of `cur`, in either
/// direction. `cur = None` (no round observed yet) always accepts.
pub(crate) fn round_in_window(round: u64, cur: Option<u64>) -> bool {
    match cur {
        Some(cur) => {
            round <= cur.saturating_add(PANETIERE_ROUND_WINDOW)
                && round.saturating_add(PANETIERE_ROUND_WINDOW) >= cur
        }
        None => true,
    }
}

/// True if `payload` is a Panetiere wire message for a round past `cap` —
/// successor traffic a draining worker must not ingest (it would validate it
/// under the outgoing config).
pub(crate) fn wire_round_past(payload: &[u8], cap: Round) -> bool {
    bincode::deserialize::<PanetiereWire>(payload).is_ok_and(|m| m.round() > cap)
}

/// [`crate::runtime::drain_inbound`] with an optional round cap for a draining
/// worker; `None` delivers everything (normal operation).
pub(crate) async fn drain_inbound_upto(
    subscriptions: &mut [Subscription],
    sessions: &mut HashMap<SessionKey, Box<dyn Session>>,
    fault_monitor: &mut Option<Box<dyn Session>>,
    inner: &Arc<AnymoneInner>,
    egress: &impl Fn(&SessionKey, &[u8]) -> String,
    identity_pk: Pubkey,
    cap: Option<Round>,
) {
    for i in 0..subscriptions.len() {
        while let Some(msg) = subscriptions[i].try_recv() {
            if cap.is_some_and(|c| wire_round_past(&msg.payload, c)) {
                continue;
            }
            handle_inbound(sessions, fault_monitor, inner, egress, identity_pk, msg).await;
        }
    }
}

/// Bytes a relay signs over its `ServerPublic` (and every consumer verifies
/// against `roster[server_id]`).
pub(crate) fn server_public_signing_bytes(
    round: u64,
    server_id: u32,
    clients: &[u32],
    agg_open: &[u8],
    agg_share: &[u8],
) -> Vec<u8> {
    let mut m = b"anymone/panetiere/server-public".to_vec();
    m.extend_from_slice(
        &bincode::serialize(&(round, server_id, clients, agg_open, agg_share))
            .expect("serialise signing bytes"),
    );
    m
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

#[cfg(feature = "wire-debug")]
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
        PanetiereWire::ClientSet {
            round,
            clients,
            demand,
        } => Some(format!(
            "Panetiere ClientSet round={round} clients={} demand={demand}",
            clients.len()
        )),
        PanetiereWire::Reservations { round, entries } => Some(format!(
            "Panetiere Reservations round={round} entries={}",
            entries.len()
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
fn server_public_consistent(agg_open: &[u8], agg_share: &[u8]) -> bool {
    let Some(packed) = PackedOpening::from_bytes(agg_open) else {
        return true;
    };
    let n_shares = packed.mu_cs as usize;
    let Ok(open) = Opening::from_packed(&packed) else {
        return true;
    };
    match panetiere::cs::unpack_cs_shares(agg_share, n_shares) {
        Some(share) => share.as_slice() == open.s(),
        None => true,
    }
}

/// Wire form of a relay's aggregate share: one CS poly.
fn pack_agg_share(share: &CsPoly) -> Vec<u8> {
    panetiere::cs::pack_cs_shares(std::slice::from_ref(share))
}

/// The wire round embedded in a fault's evidence, when decodable as a
/// `PanetiereWire` — distinct from the anymone tick that observed it.
pub(crate) fn evidence_round(evidence: &[u8]) -> Option<Round> {
    match bincode::deserialize::<PanetiereWire>(evidence).ok()? {
        PanetiereWire::ClientPublic { round, .. }
        | PanetiereWire::Opening { round, .. }
        | PanetiereWire::ServerPublic { round, .. }
        | PanetiereWire::Decoded { round, .. }
        | PanetiereWire::GroupAggregate { round, .. }
        | PanetiereWire::ClientSet { round, .. }
        | PanetiereWire::Reservations { round, .. } => Some(round),
    }
}

/// Culprit iff `evidence` is a `ServerPublic` with a mismatched share that the
/// claimed slot's owner actually signed — lets the committee re-verify a
/// leader's report instead of trusting it.
pub(crate) fn integrity_culprit_from_evidence(
    evidence: &[u8],
    roster: &[Pubkey],
) -> Option<Pubkey> {
    match bincode::deserialize::<PanetiereWire>(evidence).ok()? {
        PanetiereWire::ServerPublic {
            round,
            server_id,
            clients,
            agg_open,
            agg_share,
            signature,
        } => {
            let culprit = *roster.get(server_id as usize)?;
            if !culprit.verify(
                &server_public_signing_bytes(round, server_id, &clients, &agg_open, &agg_share),
                &signature,
            ) {
                return None;
            }
            (!server_public_consistent(&agg_open, &agg_share)).then_some(culprit)
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
    /// Own round clock, from `begin_round`; bounds accepted wire rounds.
    cur_round: Option<u64>,
    /// Canonical client set size per round — the per-round anonymity set.
    anon_set_by_round: std::collections::BTreeMap<u64, usize>,
    /// Leader-announced demand per round (distinct authenticated clients seen,
    /// including capacity rejections) — the committee's sizing signal.
    demand_by_round: std::collections::BTreeMap<u64, u32>,
    clients_by_round: std::collections::BTreeMap<u64, Vec<u32>>,
    /// Total decoded payload bytes per round — the scheduler's upgrade signal
    /// for scheduled mode.
    decoded_bytes_by_round: std::collections::BTreeMap<u64, usize>,
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
            cur_round: None,
            anon_set_by_round: std::collections::BTreeMap::new(),
            demand_by_round: std::collections::BTreeMap::new(),
            clients_by_round: std::collections::BTreeMap::new(),
            decoded_bytes_by_round: std::collections::BTreeMap::new(),
            integrity_pending: Vec::new(),
            integrity_seen: HashSet::new(),
        }
    }

    /// First announcement per round wins, matching the followers' rule.
    fn record_anon(&mut self, round: u64, size: usize) {
        self.anon_set_by_round.entry(round).or_insert(size);
        while self.anon_set_by_round.len() > ANON_SET_HISTORY {
            let oldest = *self.anon_set_by_round.keys().next().unwrap();
            self.anon_set_by_round.remove(&oldest);
        }
    }

    fn record_decoded_bytes(&mut self, round: u64, bytes: usize) {
        self.decoded_bytes_by_round.insert(round, bytes);
        while self.decoded_bytes_by_round.len() > ANON_SET_HISTORY {
            let oldest = *self.decoded_bytes_by_round.keys().next().unwrap();
            self.decoded_bytes_by_round.remove(&oldest);
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

    /// Round of the most recent canonical client set.
    pub fn anon_set_round(&self) -> Option<u64> {
        self.anon_set_by_round.keys().next_back().copied()
    }

    /// Most recent leader-announced demand (distinct authenticated clients
    /// seen that round, including those rejected at capacity).
    pub fn demand(&self) -> Option<u32> {
        self.demand_by_round.values().next_back().copied()
    }

    /// Members of the most recent canonical set.
    pub fn latest_clients(&self) -> Option<(u64, &[u32])> {
        self.clients_by_round
            .iter()
            .next_back()
            .map(|(r, c)| (*r, c.as_slice()))
    }

    /// Clients in ≥2 of the last GAP+1 canonical sets — the set a scheduled
    /// message actually hides in (its reservation and delivery rounds).
    pub fn returning_set(&self) -> Option<usize> {
        let window = crate::panetiere_scheduled::RESERVATION_TO_MSG_GAP as usize + 1;
        let recent: Vec<&Vec<u32>> = self
            .clients_by_round
            .values()
            .rev()
            .take(window)
            .collect();
        if recent.len() < 2 {
            return None;
        }
        let mut seen: HashMap<u32, u32> = HashMap::new();
        for set in &recent {
            for c in set.iter() {
                *seen.entry(*c).or_default() += 1;
            }
        }
        Some(seen.values().filter(|&&n| n >= 2).count())
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

    /// Mean decoded bytes/round over the last `window` rounds — the scheduler's
    /// real-traffic signal for switching a subnet to scheduled mode. Anchored
    /// on the share frontier, not the last `Decoded`, so a round without one
    /// counts as zero and the mean decays instead of freezing when traffic stops.
    pub fn decoded_bytes_recent(&self, window: u64) -> usize {
        let decoded_last = self.decoded_bytes_by_round.keys().next_back().copied();
        let frontier = match self.tracker.share_frontier().max(decoded_last) {
            Some(r) => r,
            None => return 0,
        };
        let cutoff = frontier.saturating_sub(window.saturating_sub(1));
        let total: usize = self
            .decoded_bytes_by_round
            .range(cutoff..=frontier)
            .map(|(_, &b)| b)
            .sum();
        total / (frontier - cutoff + 1).max(1) as usize
    }
}

impl Session for PanetiereObserverSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = Some(round);
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let msg = match bincode::deserialize::<PanetiereWire>(&payload) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    target: PANETIERE,
                    len = payload.len(),
                    error = %e,
                    "panetiere observer: undecodable wire message"
                );
                return Vec::new();
            }
        };
        {
            let round = msg.round();
            if !round_in_window(round, self.cur_round) {
                tracing::debug!(
                    target: PANETIERE,
                    msg_round = round,
                    cur_round = ?self.cur_round,
                    "panetiere observer: message outside round window, not counted"
                );
                return Vec::new();
            }
            self.max_round = Some(self.max_round.map_or(round, |m| m.max(round)));
            match &msg {
                PanetiereWire::ServerPublic {
                    round,
                    server_id,
                    clients,
                    agg_open,
                    agg_share,
                    signature,
                } => {
                    // Liveness credit and attribution bind to the slot owner's key.
                    let Some(&expected) = self.roster.get(*server_id as usize) else {
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            server_id,
                            roster = self.roster.len(),
                            "panetiere observer: share for a slot outside the roster, no liveness credit"
                        );
                        return Vec::new();
                    };
                    if from != expected
                        || !expected.verify(
                            &server_public_signing_bytes(
                                *round, *server_id, clients, agg_open, agg_share,
                            ),
                            signature,
                        )
                    {
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            server_id,
                            wrong_sender = from != expected,
                            "panetiere observer: share failed slot-owner authentication, no liveness credit"
                        );
                        return Vec::new();
                    }
                    // Panetiere server ids are the 0-based sorted-roster index.
                    self.tracker.observe_share(*round, *server_id as usize);
                    // Leaderless committee has no ClientSet; read the set off shares.
                    if self.leader.is_none() {
                        self.record_anon(*round, clients.len());
                    }
                    // A corrupt share is an attributable integrity fault even though
                    // t-of-n decode tolerates it, so liveness alone would miss it.
                    self.integrity_seen
                        .retain(|(r, _)| *r + ANON_SET_HISTORY as u64 >= *round);
                    if !server_public_consistent(agg_open, agg_share)
                        && self.integrity_seen.insert((*round, *server_id))
                    {
                        self.integrity_pending.push(Fault {
                            kind: FaultKind::Integrity,
                            attribution: Attribution::Peers(vec![expected]),
                            evidence: payload.clone(),
                        });
                    }
                }
                PanetiereWire::ClientSet {
                    round,
                    clients,
                    demand,
                } if self.leader == Some(from) => {
                    self.record_anon(*round, clients.len());
                    self.clients_by_round
                        .entry(*round)
                        .or_insert_with(|| clients.clone());
                    while self.clients_by_round.len() > ANON_SET_HISTORY {
                        let oldest = *self.clients_by_round.keys().next().unwrap();
                        self.clients_by_round.remove(&oldest);
                    }
                    self.demand_by_round.entry(*round).or_insert(*demand);
                    while self.demand_by_round.len() > ANON_SET_HISTORY {
                        let oldest = *self.demand_by_round.keys().next().unwrap();
                        self.demand_by_round.remove(&oldest);
                    }
                }
                PanetiereWire::Decoded { round, payloads }
                    if self.leader.map_or(true, |l| from == l) =>
                {
                    self.tracker.observe_output(*round);
                    let bytes = payloads.iter().map(Vec::len).sum();
                    self.record_decoded_bytes(*round, bytes);
                }
                // Scheduled-flow only: the leader emits this every decoded
                // round (even when empty), so it's the output-liveness signal
                // there — `Decoded` may legitimately be absent on payload-empty
                // rounds.
                PanetiereWire::Reservations { round, .. } if self.leader == Some(from) => {
                    self.tracker.observe_output(*round);
                }
                // A leader-only message from a non-leader: either a stale roster
                // (so the real leader's set is being ignored too, and the
                // anonymity set reads low) or a peer forging one.
                PanetiereWire::ClientSet { round, .. }
                | PanetiereWire::Decoded { round, .. }
                | PanetiereWire::Reservations { round, .. } => {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        expected_leader = ?self.leader,
                        "panetiere observer: leader-only message from a non-leader, ignored"
                    );
                }
                PanetiereWire::ClientPublic { .. } | PanetiereWire::Opening { .. } => {}
                PanetiereWire::GroupAggregate { .. } => {}
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        let mut faults = std::mem::take(&mut self.integrity_pending);
        faults.extend(self.tracker.evaluate());
        RoundOutcome {
            outbound: Vec::new(),
            decoded: Vec::new(),
            faults,
        }
    }
}

/// Client-side session: stages a payload, encrypts + Shamir-shares it at
/// `begin_round`, and emits one `ClientPublic` plus per-server `Opening`
/// messages. Ignores inbound.
pub struct PanetiereClientSession {
    pp: Arc<ProtocolParams>,
    mse: ChannelParams,
    client_id: ClientId,
    servers: Vec<(ServerId, pke::PublicKey)>,
    pending: Option<Vec<KahePoly>>,
    rng_seed: [u8; 32],
    cover_rate: f32,
    /// Separate stream for the cover draw: the per-round protocol RNG is
    /// deterministic, so reusing it would make cover predictable.
    cover_rng: ChaCha20Rng,
    /// Unpredictable stream for per-insert MSE randomness `r` (a predictable `r`
    /// would let an adversary craft a colliding insert).
    r_rng: ChaCha20Rng,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
}

impl PanetiereClientSession {
    pub fn new(
        pp: Arc<ProtocolParams>,
        mse: ChannelParams,
        client_id: ClientId,
        servers: Vec<(ServerId, pke::PublicKey)>,
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
            servers,
            pending: None,
            rng_seed,
            cover_rate: 1.0,
            cover_rng: ChaCha20Rng::from_seed(cover_seed),
            r_rng: ChaCha20Rng::from_seed(r_seed),
            setup_seed: [0u8; 32],
        }
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.setup_seed = setup_seed;
    }
}

impl Session for PanetiereClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        // Sealing (and Shamir sharing) needs every relay's exchange key; a
        // partial set would poison the servers' all-or-nothing rounds.
        if self.servers.len() != self.pp.cs.n_servers {
            tracing::debug!(
                target: PANETIERE,
                round,
                have = self.servers.len(),
                need = self.pp.cs.n_servers,
                staged = self.pending.is_some(),
                "panetiere client: missing relay exchange keys; skipping round"
            );
            return Vec::new();
        }
        let had_pending = self.pending.is_some();
        let msg = match self.pending.take() {
            Some(m) => m,
            None if self.cover_rng.gen::<f32>() < self.cover_rate => {
                let mut cover = channel::cover(&self.mse);
                cover.resize(message_polys(&self.pp), KahePoly::default());
                cover
            }
            None => {
                tracing::trace!(
                    target: PANETIERE,
                    round,
                    client_id = self.client_id.0,
                    "panetiere client: nothing staged and cover coin missed; silent this round"
                );
                return Vec::new();
            }
        };
        // The RNG is rebuilt from the seed each round; folding the round into
        // the trailing bytes keeps per-round randomness distinct.
        let mut seed = self.rng_seed;
        seed[24..32].copy_from_slice(&round.to_le_bytes());
        let mut rng = ChaCha20Rng::from_seed(seed);
        let sid = session_id(&self.setup_seed, round);
        let round_out =
            run_client_round(&mut rng, &self.pp, &sid, self.client_id, msg, &self.servers);
        tracing::trace!(
            target: PANETIERE,
            round,
            client_id = self.client_id.0,
            real = had_pending,
            "panetiere client: emitting"
        );

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1 + self.servers.len());

        let pub_msg = PanetiereWire::ClientPublic {
            round,
            client_id: round_out.client_id.0,
            entry: round_out.encrypted_message.to_bytes(),
        };
        out.push(bincode::serialize(&pub_msg).expect("serialise client public"));

        for (server_id, sealed) in round_out.sealed_openings {
            let opening_msg = PanetiereWire::Opening {
                round,
                client_id: round_out.client_id.0,
                target_server: server_id.0,
                sealed,
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
        // Callers outside the pipe send gate (committee StageProposal) reach
        // here unchecked; truncating would corrupt the payload silently.
        let cap = self.mse.max_payload_bytes();
        if payload.len() > cap {
            tracing::error!(
                target: PANETIERE,
                len = payload.len(),
                cap,
                "panetiere client: staged payload exceeds channel capacity, dropped"
            );
            return;
        }
        // Overwrites a payload staged but not yet emitted (the runtime stages at
        // most one per round, but the committee's StageProposal path can).
        if self.pending.is_some() {
            tracing::debug!(
                target: PANETIERE,
                client_id = self.client_id.0,
                "panetiere client: staged payload replaced one that had not been emitted"
            );
        }
        // One insert per message: the leader peels every active client's element
        // out of the summed plaintext, so concurrent senders don't collide.
        let mut polys = match channel::encode_message(&mut self.r_rng, &self.mse, &payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(target: PANETIERE, ?e, "panetiere client: encode failed, dropped");
                return;
            }
        };
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
    emitted_my_public: bool,
    decoded: bool,
    /// Leader-only (aggregated flow): the agreed summed entry per group.
    group_aggregates: HashMap<u32, GroupAgg>,
    /// First pubkey to claim each `ClientId` this round. Binds client input to
    /// its gossipsub-authenticated origin and blocks a second signer from
    /// grinding a colliding 4-byte id to clobber another client's slot.
    owners: HashMap<ClientId, Pubkey>,
    /// Authenticated clients turned away at `client_set_max` — demand the
    /// capped canonical set can't show. Bounded at 4× the cap.
    rejected: HashSet<ClientId>,
}

/// Capacity rejections count as demand; ownership failures (forged ids) don't.
#[derive(PartialEq)]
enum Admit {
    Admitted,
    AtCapacity,
    NotOwner,
}

/// Admits `from` as (or confirms it already is) the owner of `client_id` in
/// `owners`, subject to a cap on distinct clients per round. Rejects unless
/// `client_id` is actually derived from `from` — closing the unauthenticated
/// self-chosen `client_id` gap — and rejects a second distinct signer trying
/// to claim an id already owned by someone else.
fn admit_client(
    owners: &mut HashMap<ClientId, Pubkey>,
    client_id: ClientId,
    from: Pubkey,
    max: usize,
) -> Admit {
    if client_id_from_pubkey(from) != client_id {
        return Admit::NotOwner;
    }
    match owners.get(&client_id) {
        Some(&owner) if owner == from => Admit::Admitted,
        Some(_) => Admit::NotOwner,
        None => {
            if owners.len() >= max {
                return Admit::AtCapacity;
            }
            owners.insert(client_id, from);
            Admit::Admitted
        }
    }
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
    mse: ChannelParams,
    server_id: ServerId,
    identity: Identity,
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
    /// Own round clock, from `begin_round`; bounds accepted wire rounds.
    cur_round: Option<Round>,
    /// First round this session ticked; earlier rounds were only partially
    /// observed and must never be (re-)announced.
    first_round: Option<Round>,
    /// Upper bound on distinct clients admitted per round (also the canonical
    /// set size ceiling); unbounded until [`Self::set_client_set_max`] is called.
    client_set_max: usize,
    /// Exact wire length of a `ClientBulletinEntry` under this session's
    /// geometry. A stale-config client's entry has a different width and, once
    /// summed, panics the KAHE math — reject it at ingestion instead.
    entry_len: usize,
    /// Per-round override of `entry_len`. Scheduled subnets size each round's
    /// message vector to that round's granted reservations; empty otherwise.
    round_entry_len: std::collections::BTreeMap<Round, usize>,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
}

/// Rounds kept after they go quiet. A bucket decodes at `end_round(r+1)`; one
/// that never reaches `t` (a stalled round) is dropped this many rounds later so
/// memory stays bounded.
pub(crate) const PANETIERE_ROUND_RETENTION: Round = 4;

/// How far a wire `round` may sit ahead of (or behind) the session's own round
/// clock. Ties to retention: a stalled round legitimately emits shares/outputs
/// up to `PANETIERE_ROUND_RETENTION` rounds late.
pub(crate) const PANETIERE_ROUND_WINDOW: Round = PANETIERE_ROUND_RETENTION;

impl PanetiereServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pp: Arc<ProtocolParams>,
        mse: ChannelParams,
        server_id: ServerId,
        identity: Identity,
        mode: SetMode,
        min_clients: u32,
        server_pubkeys: HashMap<ServerId, Pubkey>,
        aggregation: Option<LeaderAggregation>,
    ) -> Self {
        let entry_len = entry_wire_len(&pp);
        PanetiereServerSession {
            pp,
            mse,
            server_id,
            identity,
            mode,
            min_clients: min_clients as usize,
            server_pubkeys,
            rounds: std::collections::BTreeMap::new(),
            client_set_by_round: std::collections::BTreeMap::new(),
            announced_rounds: HashSet::new(),
            misbehavior: None,
            aggregation,
            cur_round: None,
            first_round: None,
            client_set_max: usize::MAX,
            entry_len,
            round_entry_len: std::collections::BTreeMap::new(),
            setup_seed: [0u8; 32],
        }
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.setup_seed = setup_seed;
    }

    /// Caps distinct clients admitted per round and the accepted canonical set
    /// size. Call with the subnet's real `client_set_max` on public subnets,
    /// where the client set is attacker-influenced; the committee's own
    /// internal channel is naturally bounded by committee size and can skip this.
    pub fn set_client_set_max(&mut self, max: usize) {
        self.client_set_max = max;
    }

    /// Geometry default for rounds with no per-round width.
    pub(crate) fn set_entry_len(&mut self, len: usize) {
        self.entry_len = len;
    }

    pub(crate) fn set_round_entry_len(&mut self, round: Round, len: usize) {
        self.round_entry_len.insert(round, len);
    }

    fn entry_len_for(&self, round: Round) -> usize {
        self.round_entry_len
            .get(&round)
            .copied()
            .unwrap_or(self.entry_len)
    }

    /// Largest set this subnet can announce: an aggregated one is the union of
    /// group aggregates, which overshoots `client_set_max` by the group slack.
    fn canonical_bound(&self) -> usize {
        match &self.aggregation {
            Some(a) => {
                aggregated_client_set_bound(self.client_set_max as u32, a.roster.len() as u32)
                    as usize
            }
            None => self.client_set_max,
        }
    }

    /// Leader-only: announce the one canonical set per settled round, once.
    /// Called from `end_round` (direct flow) or checkpoint 2 (aggregated).
    pub(crate) fn announce_settled(&mut self, round: Round) -> Vec<Vec<u8>> {
        let aggregated = self.aggregation.is_some();
        let mut outbound = Vec::new();
        let mut announce: Vec<(Round, Vec<ClientId>, u32)> = Vec::new();
        for (&r, state) in self.rounds.iter() {
            let empty = if aggregated {
                state.group_aggregates.is_empty()
            } else {
                state.inbox_items.is_empty()
            };
            // The predecessor worker announced pre-spawn rounds from full state.
            let partial = self.first_round.is_some_and(|f| r < f);
            if r > round || partial || self.announced_rounds.contains(&r) || empty {
                continue;
            }
            let mut canonical: Vec<ClientId> = if aggregated {
                // Frozen sums can't be truncated here; each group is capped at
                // `client_set_max / group_count` by its aggregator instead.
                state
                    .group_aggregates
                    .values()
                    .flat_map(|g| g.clients.iter().copied())
                    .collect()
            } else {
                // Safe to truncate: every relay admits 2× the cap in openings,
                // so any cap-sized subset the leader picks is servable.
                state
                    .inbox_items
                    .iter()
                    .filter_map(|(cid, _)| state.publics.get(cid).map(|_| *cid))
                    .take(self.client_set_max)
                    .collect()
            };
            canonical.sort();
            canonical.dedup();
            // Admitted + capacity-rejected: uncensored, unlike the capped set.
            let demand = (state.owners.len() + state.rejected.len()).max(canonical.len()) as u32;
            tracing::trace!(
                target: PANETIERE,
                round = r,
                aggregated,
                publics = state.publics.len(),
                inbox = state.inbox_items.len(),
                groups = state.group_aggregates.len(),
                announced = canonical.len(),
                demand,
                "panetiere leader: canonical set"
            );
            // Openings without a matching public (or vice versa) are clients the
            // leader saw but can't announce, so they're excluded from the round.
            if !aggregated && canonical.len() < state.inbox_items.len() {
                tracing::debug!(
                    target: PANETIERE,
                    round = r,
                    announced = canonical.len(),
                    inbox = state.inbox_items.len(),
                    publics = state.publics.len(),
                    capped_at = self.client_set_max,
                    "panetiere leader: clients excluded from the canonical set"
                );
            }
            if canonical.is_empty() {
                tracing::debug!(
                    target: PANETIERE,
                    round = r,
                    aggregated,
                    publics = state.publics.len(),
                    inbox = state.inbox_items.len(),
                    groups = state.group_aggregates.len(),
                    "panetiere leader: nothing to announce for a non-empty round"
                );
            } else {
                announce.push((r, canonical, demand));
            }
        }
        for (r, canonical, demand) in announce {
            outbound.push(
                bincode::serialize(&PanetiereWire::ClientSet {
                    round: r,
                    clients: canonical.iter().map(|c| c.0).collect(),
                    demand,
                })
                .expect("serialise client set"),
            );
            self.client_set_by_round.insert(r, canonical);
            self.announced_rounds.insert(r);
        }
        outbound
    }
}

/// Render the recipient's rejection reasons at the level each deserves. A round
/// below the share threshold is the normal state for the round that just ended —
/// peers report during the next one — so that case is trace, not debug.
fn log_decode_failure(round: Round, aggregated: bool, e: &RecipientError) {
    match e {
        RecipientError::BelowShareThreshold { have, need } => tracing::trace!(
            target: PANETIERE,
            round,
            shares = have,
            need,
            "panetiere decode: below the share threshold, not yet decodable"
        ),
        RecipientError::NoCandidate(rs) => {
            for CandidateRejection {
                canonical_len,
                reason,
            } in rs
            {
                tracing::debug!(
                    target: PANETIERE,
                    round,
                    aggregated,
                    canonical = canonical_len,
                    ?reason,
                    "panetiere decode: candidate client set rejected"
                );
            }
        }
    }
}

fn collect_outputs(state: &PanetiereRoundState) -> Vec<ServerBulletinEntry> {
    state.peer_server_publics.values().cloned().collect()
}

/// Group aggregates for `canonical`, partitioned by `client_id % group_count` —
/// our aggregator topology, so the partition stays here. The recipient only
/// checks that the groups jointly cover the set.
fn group_aggregates_for(
    agg: &LeaderAggregation,
    state: &PanetiereRoundState,
    canonical: &[ClientId],
) -> Vec<(Vec<ClientId>, ClientBulletinEntry)> {
    let group_count = (agg.roster.len() as u32).max(1);
    let mut wanted: HashSet<u32> = HashSet::new();
    for c in canonical {
        wanted.insert(c.0 % group_count);
    }
    state
        .group_aggregates
        .iter()
        .filter(|(g, _)| wanted.contains(g))
        .map(|(_, g)| (g.clients.clone(), g.entry.clone()))
        .collect()
}


impl Session for PanetiereServerSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if self.first_round.is_none() {
            self.first_round = Some(round);
        }
        self.cur_round = Some(round);
        Vec::new()
    }

    /// k=2: freeze the canonical set for the aggregated flow, ahead of `end_round`.
    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k != 2 {
            return Vec::new();
        }
        let is_leader = self.mode == SetMode::Leader;
        let withholding = self.misbehavior == Some(Misbehavior::Withhold);
        if is_leader && !withholding && self.aggregation.is_some() {
            self.announce_settled(round)
        } else {
            Vec::new()
        }
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let msg = match bincode::deserialize::<PanetiereWire>(&payload) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    target: PANETIERE,
                    len = payload.len(),
                    error = %e,
                    "panetiere server: undecodable wire message"
                );
                return Vec::new();
            }
        };
        if !round_in_window(msg.round(), self.cur_round) {
            // A client whose round clock drifts past the window is silently
            // excluded from the canonical set — a prime cause of a small,
            // fluctuating set even at full participation.
            if matches!(
                msg,
                PanetiereWire::ClientPublic { .. } | PanetiereWire::Opening { .. }
            ) {
                tracing::debug!(
                    target: PANETIERE,
                    msg_round = msg.round(),
                    cur_round = ?self.cur_round,
                    kind = if matches!(msg, PanetiereWire::ClientPublic { .. }) { "public" } else { "opening" },
                    "panetiere server: client contribution outside round window, dropped"
                );
            }
            return Vec::new();
        }
        // Rounds before this session's first tick belong to the predecessor
        // worker, which drains and decodes them under its own config; wire
        // produced under a different config (e.g. another aggregator group
        // count) must never be validated against this one.
        if self.first_round.is_some_and(|f| msg.round() < f) {
            tracing::trace!(
                target: PANETIERE,
                msg_round = msg.round(),
                first_round = ?self.first_round,
                "panetiere server: pre-spawn round, dropped"
            );
            return Vec::new();
        }
        match msg {
            PanetiereWire::ClientPublic {
                round,
                client_id,
                entry,
            } => {
                let expected = self.entry_len_for(round);
                if entry.len() != expected {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        len = entry.len(),
                        expected,
                        "panetiere server: wrong-geometry public dropped"
                    );
                    return Vec::new();
                }
                let cid = ClientId(client_id);
                let max = self.client_set_max;
                let bucket = self.rounds.entry(round).or_default();
                match admit_client(&mut bucket.owners, cid, from, max) {
                    Admit::Admitted => {}
                    Admit::AtCapacity => {
                        if bucket.rejected.len() < max.saturating_mul(4) {
                            bucket.rejected.insert(cid);
                        }
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            client_id,
                            max,
                            "panetiere server: public admission rejected"
                        );
                        return Vec::new();
                    }
                    // Either an id not derived from the sender's key, or a second
                    // signer claiming an id someone else already owns.
                    Admit::NotOwner => {
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            client_id,
                            from = %from,
                            derived = client_id_from_pubkey(from).0,
                            "panetiere server: public rejected, client id not owned by the sender"
                        );
                        return Vec::new();
                    }
                }
                match ClientBulletinEntry::from_bytes(&entry) {
                    Some(entry) => {
                        bucket.publics.insert(cid, entry);
                    }
                    // Right length, wrong contents: the client holds this round's
                    // slot but has no usable public, so the round can't decode.
                    None => tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        len = entry.len(),
                        "panetiere server: unparseable client public dropped"
                    ),
                }
            }
            PanetiereWire::Opening {
                round,
                client_id,
                target_server,
                sealed,
            } => {
                // The leader needs each canonical client's opening addressed to
                // its OWN slot; a client sealing to a stale roster (wrong slot
                // count/order) lands its public but no opening here, so it's in
                // `publics` yet excluded from `inbox_items ∩ publics`.
                if target_server != self.server_id.0 {
                    tracing::trace!(
                        target: PANETIERE,
                        round,
                        client_id,
                        target_server,
                        me = self.server_id.0,
                        "panetiere server: opening for another slot"
                    );
                }
                if target_server == self.server_id.0 {
                    let cid = ClientId(client_id);
                    // Admission is arrival-ordered and differs per relay, while
                    // the canonical set is frozen elsewhere; 2× headroom keeps
                    // every canonical member's opening servable.
                    let max = self.canonical_bound().saturating_mul(2);
                    let bucket = self.rounds.entry(round).or_default();
                    match admit_client(&mut bucket.owners, cid, from, max) {
                        Admit::Admitted => {}
                        Admit::AtCapacity => {
                            if bucket.rejected.len() < max.saturating_mul(4) {
                                bucket.rejected.insert(cid);
                            }
                            tracing::debug!(
                                target: PANETIERE,
                                round,
                                client_id,
                                max,
                                "panetiere server: opening admission rejected"
                            );
                            return Vec::new();
                        }
                        Admit::NotOwner => {
                            tracing::debug!(
                                target: PANETIERE,
                                round,
                                client_id,
                                from = %from,
                                derived = client_id_from_pubkey(from).0,
                                "panetiere server: opening rejected, client id not owned by the sender"
                            );
                            return Vec::new();
                        }
                    }
                    let sid = session_id(&self.setup_seed, round);
                    let Some(opening) = unseal_opening(
                        self.identity.exchange().pke(),
                        &sid,
                        cid,
                        self.server_id,
                        &sealed,
                    ) else {
                        // Sealed to a stale exchange key: this relay holds the
                        // client's slot but can never open its share.
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            client_id,
                            "panetiere server: undecodable sealed opening"
                        );
                        return Vec::new();
                    };
                    let bucket = self.rounds.entry(round).or_default();
                    // First-writer-wins per client per round.
                    if bucket.inbox_items.iter().any(|(c, _)| *c == cid) {
                        tracing::trace!(
                            target: PANETIERE,
                            round,
                            client_id,
                            "panetiere server: duplicate opening ignored"
                        );
                        return Vec::new();
                    }
                    bucket.inbox_items.push((cid, opening));
                }
            }
            PanetiereWire::ServerPublic {
                round,
                server_id,
                clients,
                agg_open,
                agg_share,
                signature,
            } => {
                // Attribution binds to the slot owner's key. Every rejection here
                // costs the round one share towards the decode threshold.
                let Some(&expected) = self.server_pubkeys.get(&ServerId(server_id)) else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        roster = self.server_pubkeys.len(),
                        "panetiere server: share for a slot outside our roster, dropped"
                    );
                    return Vec::new();
                };
                if from != expected
                    || !expected.verify(
                        &server_public_signing_bytes(
                            round, server_id, &clients, &agg_open, &agg_share,
                        ),
                        &signature,
                    )
                {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        wrong_sender = from != expected,
                        "panetiere server: share failed slot-owner authentication, dropped"
                    );
                    return Vec::new();
                }
                let Some(packed) = PackedOpening::from_bytes(&agg_open) else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        len = agg_open.len(),
                        "panetiere server: unparseable packed opening in a share, dropped"
                    );
                    return Vec::new();
                };
                let n_shares = packed.mu_cs as usize;
                let Ok(agg_open) = Opening::from_packed(&packed) else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        n_shares,
                        "panetiere server: packed opening failed to unpack, share dropped"
                    );
                    return Vec::new();
                };
                match panetiere::cs::unpack_cs_shares(&agg_share, n_shares)
                    .filter(|s| s.len() == 1)
                    .map(|s| s[0])
                {
                    Some(agg_share) => {
                        let bucket = self.rounds.entry(round).or_default();
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
                    None => tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        len = agg_share.len(),
                        n_shares,
                        "panetiere server: share body failed to unpack, dropped"
                    ),
                }
            }
            // Servers decode themselves; `Decoded` is for watchers.
            PanetiereWire::Decoded { .. } => {}
            // Scheduled-flow only; the one-round server has no use for it.
            PanetiereWire::Reservations { .. } => {}
            PanetiereWire::ClientSet {
                round,
                clients,
                demand: _,
            } => {
                if let SetMode::Follower { leader } = self.mode {
                    if from != leader {
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            n = clients.len(),
                            "panetiere server: ClientSet from a non-leader, ignored"
                        );
                    } else if clients.len() > self.client_set_max {
                        // We never share over this round, so the leader can't
                        // reach the decode threshold either.
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            n = clients.len(),
                            max = self.client_set_max,
                            "panetiere server: leader announced a set above our cap, ignored"
                        );
                    } else {
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
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        "panetiere server: group aggregate on a non-aggregated subnet, dropped"
                    );
                    return Vec::new();
                };
                let Some(roster) = agg.roster.get(&group) else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        groups = agg.roster.len(),
                        "panetiere server: group aggregate for an unknown group, dropped"
                    );
                    return Vec::new();
                };
                if !roster.contains(&signer)
                    || !signer.verify(
                        &group_aggregate_signing_bytes(round, group, &clients, &entry),
                        &signature,
                    )
                {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        signer = %signer,
                        in_roster = roster.contains(&signer),
                        "panetiere server: group aggregate failed aggregator authentication, dropped"
                    );
                    return Vec::new();
                }
                // A client outside the group's partition would poison the frozen
                // canonical set: decode expects it in another group's aggregate,
                // which can never match, so the round would stay undecodable.
                let group_count = (agg.roster.len() as u32).max(1);
                if clients.iter().any(|c| c % group_count != group) {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        group_count,
                        "panetiere: aggregate with out-of-group client"
                    );
                    return Vec::new();
                }
                if clients.len() > self.client_set_max {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        n = clients.len(),
                        max = self.client_set_max,
                        "panetiere: oversized group aggregate"
                    );
                    return Vec::new();
                }
                let expected = self.entry_len_for(round);
                if entry.len() != expected {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        len = entry.len(),
                        expected,
                        "panetiere: wrong-geometry group aggregate dropped"
                    );
                    return Vec::new();
                }
                let Some(parsed) = ClientBulletinEntry::from_bytes(&entry) else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        group,
                        len = entry.len(),
                        "panetiere: unparseable group aggregate entry dropped"
                    );
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
        let aggregated = self.aggregation.is_some();
        let is_leader = self.mode == SetMode::Leader;
        let withholding = self.misbehavior == Some(Misbehavior::Withhold);

        let mut outbound: Vec<Vec<u8>> = Vec::new();
        // Aggregated flow announces at checkpoint 2 instead.
        if is_leader && !withholding && !aggregated {
            outbound.extend(self.announce_settled(round));
        }
        outbound.extend(self.emit_server_publics(round));

        let mut decoded: Vec<Vec<u8>> = Vec::new();
        for (r, plain) in self.decode_settled() {
            // Peel every client's element out of the summed plaintext. A
            // cover-only round peels to nothing; a stall means the structure was
            // over-subscribed and the round's payloads are gone, which must not
            // look the same as an empty round.
            let msgs: Vec<Vec<u8>> = match channel::decode_messages(&self.mse, &plain, None) {
                Ok(elements) => elements
                    .into_iter()
                    .filter(|b| b.iter().any(|x| *x != 0))
                    .collect(),
                Err(e) => {
                    tracing::warn!(
                        target: PANETIERE,
                        round = r,
                        ?e,
                        "panetiere: payload peel failed; this round's messages are lost"
                    );
                    Vec::new()
                }
            };
            if !msgs.is_empty() {
                if is_leader {
                    let wire = PanetiereWire::Decoded {
                        round: r,
                        payloads: msgs.clone(),
                    };
                    outbound.push(bincode::serialize(&wire).expect("serialise decoded"));
                }
                decoded.extend(msgs);
            }
        }

        self.gc(round);

        RoundOutcome {
            outbound,
            decoded,
            faults: Vec::new(),
        }
    }

    fn set_misbehavior(&mut self, mode: Option<Misbehavior>) {
        self.misbehavior = mode;
    }
}

impl PanetiereServerSession {
    /// Phase 1: emit our `ServerPublic` for every settled round (`r <= round`)
    /// we've collected openings for and haven't emitted yet — not just the
    /// just-ended round. A relay whose round timer fires before that round's
    /// openings arrive (boundary skew) would otherwise strand them: this never
    /// revisits the bucket, so the round falls below `t` ServerPublics and
    /// never decodes — losing a client message that's sent only once.
    /// Withhold drops us from the threshold set entirely; the others still
    /// decode under t-of-n. CorruptShare instead emits a share that no longer
    /// matches its (valid) opening, so the decoding leader attributes it.
    pub(crate) fn emit_server_publics(&mut self, round: Round) -> Vec<Vec<u8>> {
        let withholding = self.misbehavior == Some(Misbehavior::Withhold);
        let corrupt_share = self.misbehavior == Some(Misbehavior::CorruptShare);
        let aggregated = self.aggregation.is_some();
        let self_derived = self.mode == SetMode::SelfDerived;

        let mut outbound = Vec::new();
        if withholding {
            return outbound;
        }

        let cs = &self.pp.cs;
        let sid = self.server_id;
        let identity = self.identity.clone();

        for (&r, state) in self.rounds.iter_mut() {
            if r > round || state.emitted_my_public || state.inbox_items.is_empty() {
                continue;
            }
            // Public subnets share over the leader's announced set; the
            // leaderless committee derives its own (public + opening it holds,
            // or openings alone in the aggregated flow).
            let canonical: Vec<ClientId> = if self_derived {
                let mut c: Vec<ClientId> = if aggregated {
                    state
                        .group_aggregates
                        .values()
                        .flat_map(|g| g.clients.iter().copied())
                        .collect()
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
                    None => {
                        tracing::debug!(
                            target: PANETIERE,
                            round = r,
                            openings = state.inbox_items.len(),
                            "panetiere server: no leader ClientSet yet; share deferred"
                        );
                        continue;
                    }
                }
            };
            if canonical.is_empty() {
                tracing::debug!(
                    target: PANETIERE,
                    round = r,
                    openings = state.inbox_items.len(),
                    publics = state.publics.len(),
                    "panetiere server: empty canonical set with openings held; no share emitted"
                );
                continue;
            }
            // run_server_round is all-or-nothing: skip a round we can't fully
            // cover rather than share over a different set than the leader's.
            if !self_derived {
                let present: HashSet<ClientId> =
                    state.inbox_items.iter().map(|(cid, _)| *cid).collect();
                let missing = canonical.iter().filter(|c| !present.contains(c)).count();
                if missing > 0 {
                    tracing::debug!(
                        target: PANETIERE,
                        round = r,
                        missing,
                        canonical = canonical.len(),
                        held = present.len(),
                        "panetiere server: openings incomplete for canonical set; share deferred"
                    );
                    continue;
                }
            }
            let inbox = ServerInbox {
                server_id: sid,
                items: std::mem::take(&mut state.inbox_items),
            };
            let n_items = inbox.items.len();
            match run_server_round(&inbox, &canonical) {
                Ok(sp) => {
                    let (r_b, s_b, t_b) =
                        panetiere::cs::aggregated_opening_pack_bounds(cs, sp.clients.len() as u32);
                    let packed = sp.agg_open.pack(r_b, s_b, t_b);
                    let mut agg_share = pack_agg_share(&sp.agg_share);
                    if corrupt_share {
                        if let Some(b) = agg_share.first_mut() {
                            *b ^= 0x01;
                        }
                    }
                    let clients: Vec<u32> = sp.clients.iter().map(|c| c.0).collect();
                    let agg_open = packed.to_bytes();
                    // Sign what we publish — a corrupted share stays attributable.
                    let signature = identity.sign(&server_public_signing_bytes(
                        r,
                        sp.server_id.0,
                        &clients,
                        &agg_open,
                        &agg_share,
                    ));
                    let wire = PanetiereWire::ServerPublic {
                        round: r,
                        server_id: sp.server_id.0,
                        clients,
                        agg_open,
                        agg_share,
                        signature,
                    };
                    // Cache our own honest public so try_decode sees it as a peer entry.
                    tracing::trace!(
                        target: PANETIERE,
                        round = r,
                        server_id = sp.server_id.0,
                        clients = sp.clients.len(),
                        "panetiere server: emitting share"
                    );
                    state.peer_server_publics.insert(sp.server_id, sp);
                    outbound.push(bincode::serialize(&wire).expect("serialise server public"));
                    state.emitted_my_public = true;
                }
                // The openings were consumed by `take` above, so this round can
                // never produce a share now — it costs the whole round a relay.
                Err(e) => tracing::warn!(
                    target: PANETIERE,
                    round = r,
                    server_id = sid.0,
                    canonical = canonical.len(),
                    openings = n_items,
                    ?e,
                    "panetiere server: run_server_round failed; no share for this round"
                ),
            }
        }
        outbound
    }

    /// Phase 2: decode every bucket that now has enough peer `ServerPublic`s —
    /// earlier rounds first. A round's shares arrive during the next anymone
    /// round, so the round just ended usually isn't decodable yet; an earlier
    /// one is. Returns raw plaintext (pre-MSE-peel) per decoded round; marks
    /// buckets decoded and frees their crypto state.
    pub(crate) fn decode_settled(&mut self) -> Vec<(Round, Vec<KahePoly>)> {
        let self_derived = self.mode == SetMode::SelfDerived;
        // One number for the set bound, so the announced, accepted and served
        // sets cannot drift apart. Hoisted: `rounds` is borrowed below.
        let max_clients = self.canonical_bound();
        let min_clients = self.min_clients;
        let aggregated = self.aggregation.is_some();
        let mut out = Vec::new();
        for (r, state) in self.rounds.iter_mut() {
            if state.decoded {
                continue;
            }
            let anchor: Option<Vec<ClientId>> = if self_derived {
                None
            } else {
                self.client_set_by_round.get(r).cloned()
            };
            let policy = match anchor.as_deref() {
                Some(set) => SetPolicy::anchored(set, min_clients, max_clients),
                None => SetPolicy::majority(min_clients, max_clients),
            };
            // Culprits excluded to reach decode are reported by the leader's
            // fault monitor (from the same wire evidence), not duplicated here.
            let decoded_round = match self.aggregation.as_ref() {
                Some(agg) => {
                    // Needs a canonical set to know which groups to gather; with no
                    // anchor, fall back to what the shares agree on.
                    let set = anchor.clone().or_else(|| {
                        state
                            .peer_server_publics
                            .values()
                            .next()
                            .map(|sp| sp.clients.clone())
                    });
                    match set {
                        Some(set) => {
                            let groups = group_aggregates_for(agg, state, &set);
                            recover_aggregated(&self.pp, &policy, &groups, &collect_outputs(state))
                        }
                        None => Err(RecipientError::BelowShareThreshold {
                            have: 0,
                            need: self.pp.shamir.t,
                        }),
                    }
                }
                None => recover_direct(
                    &self.pp,
                    &policy,
                    |cid| state.publics.get(&cid).cloned(),
                    &collect_outputs(state),
                ),
            };
            let decoded_round = match decoded_round {
                Ok(rec) => Some(rec.plaintext),
                Err(e) => {
                    log_decode_failure(*r, aggregated, &e);
                    None
                }
            };
            if let Some(plain) = decoded_round {
                out.push((*r, plain));
                state.decoded = true;
                // Free the heavy crypto state; keep the (now-empty) bucket
                // marked `decoded` so a share that arrives a round late lands
                // here and is skipped rather than re-decoding into a duplicate.
                state.publics.clear();
                state.inbox_items.clear();
                state.peer_server_publics.clear();
            }
        }
        out
    }

    /// Age out buckets (decoded or stalled) past the retention window so
    /// memory stays bounded; the window keeps a round alive long enough for
    /// its shares (which arrive the next anymone round) to decode it.
    pub(crate) fn gc(&mut self, round: Round) {
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        let t = self.pp.shamir.t;
        for (r, state) in self.rounds.range(..cutoff) {
            if !state.decoded && !state.peer_server_publics.is_empty() {
                // The round's payloads are gone for good; clients sent them once.
                tracing::warn!(
                    target: PANETIERE,
                    round = r,
                    shares = state.peer_server_publics.len(),
                    need = t,
                    publics = state.publics.len(),
                    openings = state.inbox_items.len(),
                    "panetiere server: round aged out undecoded"
                );
            }
        }
        self.rounds.retain(|r, _| *r >= cutoff);
        self.client_set_by_round.retain(|r, _| *r >= cutoff);
        self.announced_rounds.retain(|r| *r >= cutoff);
        self.round_entry_len.retain(|r, _| *r >= cutoff);
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
    /// Per round: first pubkey to claim each `ClientId` (see [`admit_client`]).
    owners: std::collections::BTreeMap<Round, HashMap<ClientId, Pubkey>>,
    emitted: HashSet<Round>,
    /// Own round clock, from `begin_round`; bounds accepted wire rounds.
    cur_round: Option<Round>,
    /// First round this session ticked; earlier rounds were only partially
    /// observed and must never be emitted.
    first_round: Option<Round>,
    /// Upper bound on distinct clients admitted per round; unbounded until
    /// [`Self::set_client_set_max`] is called.
    client_set_max: usize,
    /// Expected `ClientBulletinEntry` wire length; wrong-geometry entries
    /// (stale-config clients) panic the KAHE sum if admitted.
    entry_len: usize,
    /// Per-round override of `entry_len`, as on [`PanetiereServerSession`].
    round_entry_len: std::collections::BTreeMap<Round, usize>,
}

impl PanetiereAggregatorSession {
    pub fn new(group: u32, group_count: u32, identity: Identity) -> Self {
        PanetiereAggregatorSession {
            group,
            group_count,
            identity,
            rounds: std::collections::BTreeMap::new(),
            owners: std::collections::BTreeMap::new(),
            emitted: HashSet::new(),
            cur_round: None,
            first_round: None,
            client_set_max: usize::MAX,
            entry_len: usize::MAX,
            round_entry_len: std::collections::BTreeMap::new(),
        }
    }

    /// See [`PanetiereServerSession::set_client_set_max`].
    pub(crate) fn set_client_set_max(&mut self, max: usize) {
        self.client_set_max = max;
    }

    /// Expected entry length under the subnet's geometry
    /// (`ClientBulletinEntry::packed_len(message_polys(&pp))`).
    pub(crate) fn set_entry_len(&mut self, len: usize) {
        self.entry_len = len;
    }

    pub(crate) fn set_round_entry_len(&mut self, round: Round, len: usize) {
        self.round_entry_len.insert(round, len);
    }

    fn entry_len_for(&self, round: Round) -> usize {
        self.round_entry_len
            .get(&round)
            .copied()
            .unwrap_or(self.entry_len)
    }
}

impl Session for PanetiereAggregatorSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if self.first_round.is_none() {
            self.first_round = Some(round);
        }
        self.cur_round = Some(round);
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(PanetiereWire::ClientPublic {
            round,
            client_id,
            entry,
        }) = bincode::deserialize::<PanetiereWire>(&payload)
        {
            if !round_in_window(round, self.cur_round) {
                tracing::debug!(
                    target: PANETIERE,
                    round,
                    client_id,
                    cur = ?self.cur_round,
                    "panetiere aggregator: public outside round window, dropped"
                );
                return Vec::new();
            }
            if client_id % self.group_count != self.group {
                tracing::trace!(
                    target: PANETIERE,
                    round,
                    client_id,
                    group = self.group,
                    "panetiere aggregator: public for another group, ignored"
                );
            } else {
                let expected = self.entry_len_for(round);
                if expected != usize::MAX && entry.len() != expected {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        len = entry.len(),
                        expected,
                        "panetiere aggregator: wrong-geometry public dropped"
                    );
                    return Vec::new();
                }
                let cid = ClientId(client_id);
                let max = self.client_set_max;
                let admit = admit_client(self.owners.entry(round).or_default(), cid, from, max);
                if admit != Admit::Admitted {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        max,
                        at_capacity = admit == Admit::AtCapacity,
                        "panetiere aggregator: public admission rejected"
                    );
                    return Vec::new();
                }
                match ClientBulletinEntry::from_bytes(&entry) {
                    Some(entry) => {
                        self.rounds.entry(round).or_default().insert(cid, entry);
                    }
                    // Holds the group slot but contributes nothing summable, so
                    // the group aggregate omits it and the leader's set won't match.
                    None => tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        len = entry.len(),
                        "panetiere aggregator: unparseable client public dropped"
                    ),
                }
            }
        }
        Vec::new()
    }

    /// k=1: emit the group's batch mid-round, so the leader can announce the
    /// set and decode within the round rather than a round late. Revisits every
    /// retained un-emitted round (like `emit_server_publics`) — a missed tick
    /// must not strand the group's publics; a round-late aggregate still decodes.
    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k != 1 {
            return Vec::new();
        }
        let mut outbound = Vec::new();
        let due: Vec<Round> = self
            .rounds
            .keys()
            .copied()
            .filter(|r| {
                *r <= round
                    && !self.emitted.contains(r)
                    && !self.first_round.is_some_and(|f| *r < f)
            })
            .collect();
        for r in due {
            let Some(entries) = self.rounds.get(&r).filter(|e| !e.is_empty()) else {
                continue;
            };
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
                r, self.group, &clients, &entry,
            ));
            tracing::trace!(
                target: PANETIERE,
                round = r,
                group = self.group,
                of = self.group_count,
                clients = clients.len(),
                "panetiere aggregator: emit group aggregate"
            );
            let wire = PanetiereWire::GroupAggregate {
                round: r,
                group: self.group,
                clients,
                entry,
                signer: self.identity.pubkey(),
                signature,
            };
            outbound.push(bincode::serialize(&wire).expect("serialise group aggregate"));
            self.emitted.insert(r);
        }
        outbound
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let cutoff = round.saturating_sub(PANETIERE_ROUND_RETENTION);
        self.rounds.retain(|r, _| *r >= cutoff);
        self.owners.retain(|r, _| *r >= cutoff);
        self.emitted.retain(|r| *r >= cutoff);
        self.round_entry_len.retain(|r, _| *r >= cutoff);
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
        let leader_id = Identity::generate();
        let other_id = Identity::generate();
        let leader = leader_id.pubkey();
        let other = other_id.pubkey();
        let mut obs = PanetiereObserverSession::new(vec![leader, other], Some(leader), 2);
        let cs = bincode::serialize(&PanetiereWire::ClientSet {
            round: 1,
            clients: vec![10, 20, 30],
            demand: 3,
        })
        .unwrap();
        obs.on_inbound(other, cs.clone());
        assert_eq!(
            obs.anonymity_set(),
            None,
            "non-leader ClientSet must be ignored"
        );
        obs.on_inbound(leader, cs);
        assert_eq!(obs.anonymity_set(), Some(3));

        let dec = bincode::serialize(&PanetiereWire::Decoded {
            round: 7,
            payloads: vec![],
        })
        .unwrap();
        obs.on_inbound(other, dec.clone());
        assert_eq!(
            obs.output_frontier(),
            None,
            "forged Decoded must not advance output"
        );
        obs.on_inbound(leader, dec);
        assert_eq!(obs.output_frontier(), Some(7));

        // ServerPublic liveness credit binds to the slot owner: wrong signer or
        // wrong sender must not count as that slot's share.
        let agg_open = PackedOpening {
            server_index: 1,
            path_index: 0,
            kappa_cs: 0,
            mu_cs: 0,
            stored_path_len: 0,
            r_bound: 0,
            s_bound: 0,
            tree_bound: 0,
            bytes: Vec::new(),
        }
        .to_bytes();
        let sp = |signature: Vec<u8>| {
            bincode::serialize(&PanetiereWire::ServerPublic {
                round: 9,
                server_id: 1,
                clients: vec![10],
                agg_open: agg_open.clone(),
                agg_share: Vec::new(),
                signature,
            })
            .unwrap()
        };
        let signing = server_public_signing_bytes(9, 1, &[10], &agg_open, &[]);
        obs.on_inbound(other, sp(leader_id.sign(&signing)));
        assert_eq!(
            obs.share_frontier(),
            None,
            "slot 1 share signed by another key must be dropped"
        );
        obs.on_inbound(leader, sp(other_id.sign(&signing)));
        assert_eq!(
            obs.share_frontier(),
            None,
            "valid signature replayed from another sender must be dropped"
        );
        obs.on_inbound(other, sp(other_id.sign(&signing)));
        assert_eq!(obs.share_frontier(), Some(9));

        // A far-future round must be dropped once the observer's clock advances.
        obs.begin_round(9, Instant::now());
        let far_signing = server_public_signing_bytes(u64::MAX, 1, &[10], &agg_open, &[]);
        let far = bincode::serialize(&PanetiereWire::ServerPublic {
            round: u64::MAX,
            server_id: 1,
            clients: vec![10],
            agg_open: agg_open.clone(),
            agg_share: Vec::new(),
            signature: other_id.sign(&far_signing),
        })
        .unwrap();
        obs.on_inbound(other, far);
        assert_eq!(
            obs.share_frontier(),
            Some(9),
            "far-future round must be dropped by the round-window clamp"
        );
    }

    #[test]
    fn wire_estimate_covers_real_messages() {
        let (msg_size, est_msgs, cset, n_relays) = (256usize, 4u32, 40u32, 3usize);
        let est = max_wire_estimate(msg_size, est_msgs, cset, n_relays);

        let mse = channel_params(est_msgs, msg_size, [1u8; 32]);
        let pp = setup_pp(&mse, n_relays, [1u8; 32]);
        let servers: Vec<(ServerId, pke::PublicKey)> = (0..n_relays as u32)
            .map(|i| {
                (
                    ServerId(i),
                    pke::PrivateKey::generate(&mut rand::rngs::OsRng).public(),
                )
            })
            .collect();
        let mut c = PanetiereClientSession::new(pp.clone(), mse, ClientId(1), servers, [2u8; 32]);
        let client_public = c
            .begin_round(0, Instant::now())
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
    }
}

/// Per-stage checks (ingest, canonical-set agreement, peer exchange, decode)
/// for concurrent multi-client decode, so a regression localizes to one stage.
#[cfg(test)]
mod concurrent_decode_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn concurrent_clients_decode_stage_by_stage() {
        let n_servers = 3usize;
        let active = 4usize;
        let cover = 2usize;
        let total = active + cover;

        let mut server_ids: Vec<Identity> = (0..n_servers).map(|_| Identity::generate()).collect();
        server_ids.sort_by_key(|i| i.pubkey());
        let server_pks: Vec<Pubkey> = server_ids.iter().map(|i| i.pubkey()).collect();
        let server_pubkeys: HashMap<ServerId, Pubkey> = server_pks
            .iter()
            .enumerate()
            .map(|(i, pk)| (ServerId(i as u32), *pk))
            .collect();
        let xpubs: Vec<(ServerId, pke::PublicKey)> = server_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (ServerId(i as u32), id.exchange().pke().public()))
            .collect();

        let mse = channel_params(active as u32, 64, [7u8; 32]);
        let n_polys = mse.n_polys();
        assert_eq!(
            n_polys, 1,
            "sanity: a 64-byte payload should pack into exactly one poly"
        );
        let pp = setup_pp(&mse, n_servers, [7u8; 32]);

        let client_pks: Vec<Pubkey> = (0..total).map(|_| Identity::generate().pubkey()).collect();
        let mut clients: Vec<PanetiereClientSession> = (0..total)
            .map(|i| {
                PanetiereClientSession::new(
                    pp.clone(),
                    mse.clone(),
                    client_id_from_pubkey(client_pks[i]),
                    xpubs.clone(),
                    [40 + i as u8; 32],
                )
            })
            .collect();
        let payloads: Vec<Vec<u8>> = (0..active)
            .map(|i| format!("client-{i}-says-hi").into_bytes())
            .collect();
        for (i, p) in payloads.iter().enumerate() {
            clients[i].stage(p.clone());
        }
        // Cover clients (indices `active..total`) send cover at the default rate.

        let mut servers: Vec<PanetiereServerSession> = (0..n_servers)
            .map(|i| {
                let mode = if i == 0 {
                    SetMode::Leader
                } else {
                    SetMode::SelfDerived
                };
                PanetiereServerSession::new(
                    pp.clone(),
                    mse.clone(),
                    ServerId(i as u32),
                    server_ids[i].clone(),
                    mode,
                    0,
                    server_pubkeys.clone(),
                    None,
                )
            })
            .collect();

        let now = Instant::now();

        // Stage 1: ingest.
        for (i, c) in clients.iter_mut().enumerate() {
            for m in c.begin_round(0, now) {
                for s in servers.iter_mut() {
                    s.on_inbound(client_pks[i], m.clone());
                }
            }
        }
        for (si, s) in servers.iter().enumerate() {
            let state = s
                .rounds
                .get(&0)
                .expect("round 0 bucket must exist after ingest");
            assert_eq!(
                state.publics.len(),
                total,
                "server {si}: expected {total} ClientPublics, got {}",
                state.publics.len()
            );
            assert_eq!(
                state.inbox_items.len(),
                total,
                "server {si}: expected {total} openings targeted at it, got {}",
                state.inbox_items.len()
            );
        }

        // Stage 2: share generation — canonical sets must agree with the leader's.
        let outs: Vec<Vec<Vec<u8>>> = servers
            .iter_mut()
            .map(|s| s.end_round(0, now).outbound)
            .collect();
        let mut announced: Option<Vec<u32>> = None;
        let mut server_publics: Vec<(u32, Vec<u32>)> = Vec::new();
        for (si, out) in outs.iter().enumerate() {
            for msg in out {
                match bincode::deserialize::<PanetiereWire>(msg).expect("decode wire message") {
                    PanetiereWire::ClientSet { clients, .. } => {
                        assert_eq!(
                            si, 0,
                            "only the leader (server 0) should announce a ClientSet"
                        );
                        announced = Some(clients);
                    }
                    PanetiereWire::ServerPublic {
                        server_id, clients, ..
                    } => {
                        assert_eq!(
                            server_id, si as u32,
                            "ServerPublic must self-attribute the right slot"
                        );
                        server_publics.push((server_id, clients));
                    }
                    other => panic!("unexpected wire message from server {si}: {other:?}"),
                }
            }
        }
        let announced = announced.expect("leader must announce a ClientSet for round 0");
        assert_eq!(
            announced.len(),
            total,
            "leader's announced set must cover all {total} clients, got {}",
            announced.len()
        );
        assert_eq!(
            server_publics.len(),
            n_servers,
            "every server must emit exactly one ServerPublic, got {}",
            server_publics.len()
        );
        for (sid, set) in &server_publics {
            let mut got = set.clone();
            got.sort();
            let mut want = announced.clone();
            want.sort();
            assert_eq!(
                got, want,
                "server {sid}'s ServerPublic canonical set disagrees with the leader's announced set \
                 (self-derived followers must independently reach the same set)"
            );
        }

        // Stage 3: exchange.
        for (i, out) in outs.iter().enumerate() {
            for (j, s) in servers.iter_mut().enumerate() {
                if i == j {
                    continue;
                }
                for msg in out {
                    s.on_inbound(server_pks[i], msg.clone());
                }
            }
        }
        for (si, s) in servers.iter().enumerate() {
            let state = s.rounds.get(&0).unwrap();
            assert_eq!(
                state.peer_server_publics.len(),
                n_servers,
                "server {si}: expected all {n_servers} ServerPublics (own + peers) cached, got {}",
                state.peer_server_publics.len()
            );
        }

        // Stage 4: decode — distinguishes a verify/anchor rejection from an MSE peel stall.
        let anchor: Vec<ClientId> = announced.iter().map(|&c| ClientId(c)).collect();
        for (si, s) in servers.iter().enumerate() {
            let state = s.rounds.get(&0).unwrap();
            let policy = SetPolicy::anchored(&anchor, 0, usize::MAX);
            let rec = recover_direct(
                &pp,
                &policy,
                |cid| state.publics.get(&cid).cloned(),
                &collect_outputs(state),
            )
            .unwrap_or_else(|e| panic!("server {si}: recover_direct rejected the round: {e:?}"));
            assert!(
                rec.culprits.is_empty(),
                "server {si}: unexpected culprits {:?}",
                rec.culprits
            );
            let recovered_msgs: Vec<Vec<u8>> = channel::decode_messages(&mse, &rec.plaintext, None)
                .unwrap_or_else(|e| panic!("server {si}: payload peel failed: {e:?}"))
                .into_iter()
                .filter(|b| b.iter().any(|x| *x != 0))
                .collect();
            for p in &payloads {
                assert!(
                    recovered_msgs
                        .iter()
                        .any(|d| d.windows(p.len()).any(|w| w == p.as_slice())),
                    "server {si}: message {:?} not recovered; got {} non-cover buffers",
                    String::from_utf8_lossy(p),
                    recovered_msgs.len()
                );
            }
        }

        // Cross-check against the production path.
        let finals: Vec<RoundOutcome> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
        for (si, outcome) in finals.iter().enumerate() {
            for p in &payloads {
                assert!(
                    outcome
                        .decoded
                        .iter()
                        .any(|d| d.windows(p.len()).any(|w| w == p.as_slice())),
                    "server {si}: end_round(1) did not decode message {:?}",
                    String::from_utf8_lossy(p)
                );
            }
        }
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
            if from != self.leader_pk {
                // A stale leader here means this watcher never surfaces any
                // output at all — every inbound payload disappears.
                tracing::debug!(
                    target: PANETIERE,
                    round,
                    expected_leader = %self.leader_pk,
                    "panetiere watch: Decoded from a non-leader, ignored"
                );
            } else if self.routed_rounds.insert(round) {
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
