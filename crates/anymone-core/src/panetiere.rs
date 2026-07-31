//! Panetiere `Session` wrappers, over RS-sharded ingress: the ciphertext never
//! reaches a shared topic. A client posts a constant-size bulletin entry and
//! sends relay `j` its own coded share of the ciphertext, so relays double as
//! erasure-coding lanes and any `k` lane sums reconstruct `Σ ct`.
//!
//! Topics: the post on ingress (every relay reads — all of them combine), the
//! coded share and the opening sealed to relay `j` on lane `j`, `ServerPublic`s
//! (key share + lane sum, one message) on shares, the leader's `Decoded` on
//! broadcast. ≥t openings reconstruct `Σ sk`, k lane sums reconstruct `Σ ct`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use chipmunk_code::{CsPoly, DgtNTTPoly, HVCPoly, KahePoly};
use panetiere::bulletin::{
    dgt_packed_len, RsClientBulletinEntry, RsNodeBulletinEntry, ServerBulletinEntry,
};
use panetiere::channel::{self, ChannelError, ChannelParams};
use panetiere::cs::{Opening, PackedOpening};
use panetiere::pke;
use panetiere::prony::PronyError;
use panetiere::protocol::client::run_client_round_rs;
use panetiere::protocol::server::{
    run_rs_node_round, run_server_round, unseal_opening, RsNodeInbox, ServerInbox,
};
use panetiere::protocol::verify::{aggregate_and_decrypt_rs, VerifyError};
use panetiere::share_commitment::{
    fresh_path_packed_len, lane_post_packed_len, ShareOpening, SharePath,
};
use panetiere::sig;

use panetiere::protocol::{
    message_polys, round_wire_sizes, ClientId, NodeId, ProtocolParams, ServerId, SessionId,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::{
    Encoding, ExchangePublicKeyWire, PanetiereConfig, ProtocolConfig, Round, Subnet,
};
use crate::faults::{Attribution, Fault, FaultKind, OutputFaultTracker};
use crate::identity::{Identity, Pubkey};
use crate::log_target::{PANETIERE, SCHED};
use crate::runtime::{
    deadline_for, gossip_faults, handle_inbound, publish_and_loop_back, recv_any,
    round_at, route_to_pipe, subnet_leader_pk, AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{GoodClients, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::Subscription;

/// Channel sizing for a subnet carrying up to `rho` real messages of
/// `message_bytes` each. The MSE prf key is domain-separated from the shared
/// `setup_seed` so all participants agree; Prony needs no key.
pub(crate) fn channel_params(
    rho: u32,
    message_bytes: usize,
    setup_seed: [u8; 32],
    encoding: Encoding,
) -> ChannelParams {
    match encoding {
        Encoding::Prony => ChannelParams::prony_for_messages(rho, message_bytes),
        Encoding::Mse => {
            let mut prf_key = setup_seed;
            prf_key[0] ^= 0x5C;
            ChannelParams::for_messages(rho, message_bytes, prf_key)
        }
    }
}

/// Message-byte bound for the committee's config-anonymising channel. Must fit
/// a serialized `SignedProposal` at `MAX_SUBNETS` and `MAX_COMMITTEE_RELAYS` —
/// asserted against the real `build_body` packing in
/// `scheduler_core::sizing_tests`, which measured 35940 bytes there.
///
/// A proposal grows ~2 KB per placed relay: its 1184-byte ML-KEM encapsulation
/// key and 33-byte ECDH point, plus its pubkey in every subnet roster. Raising
/// `MAX_COMMITTEE_RELAYS` means raising this, and it must match across members.
pub const COMMITTEE_MSG_BYTES: usize = 36864;

/// Lane code rate: `k = t`, the Shamir threshold, so the lanes and the key
/// shares tolerate the same failure count `f`. Fix `f`, not `k` — raising `n`
/// must raise `k` with it or the rate silently degrades.
pub fn rs_k(n: usize) -> usize {
    (n / 2 + 1).max(n.saturating_sub(2)).min(n).max(1)
}

/// Channel and RS protocol params together, so nothing can pair a channel with
/// params sized for a different one. `rho_max` bounds a lane's aggregate over the
/// whole client set, so it is `client_set_max` and not `estimated_messages`.
pub fn params_for(cfg: &PanetiereConfig, n_servers: usize) -> (ChannelParams, Arc<ProtocolParams>) {
    let ch = channel_params(
        cfg.estimated_messages,
        cfg.message_size,
        cfg.setup_seed,
        cfg.encoding,
    );
    let mut rng = ChaCha20Rng::from_seed(cfg.setup_seed);
    let mut pp = ProtocolParams::setup_rs_mode(
        &mut rng,
        n_servers,
        ch.n_polys(),
        rs_k(n_servers),
        n_servers,
        ch.plaintext_modulus(),
        cfg.client_set_max.max(1) as usize,
        cfg.setup_seed,
    );
    pp.min_clients = cfg.client_set_min.max(1) as usize;
    (ch, Arc::new(pp))
}

/// Wire length of one lane's `ClientSlice` payload halves, under `pp`'s geometry.
fn slice_wire_lens(pp: &ProtocolParams) -> (usize, usize) {
    let Some(scp) = pp.share_comm.as_ref() else {
        return (0, 0);
    };
    (
        scp.block_len * dgt_packed_len(),
        fresh_path_packed_len(scp.n_lanes),
    )
}

/// Conservative upper bound on the largest per-round wire message a Panetiere
/// subnet broadcasts, for the committee's p2p size-cap guard. Crypto sizes come
/// from `protocol::round_wire_sizes`; the framing allowance is ours.
pub(crate) fn max_wire_estimate(
    message_size: usize,
    estimated_messages: u32,
    client_set_max: u32,
    n_relays: usize,
    encoding: Encoding,
) -> usize {
    let ch = channel_params(estimated_messages, message_size, [0u8; 32], encoding);
    rs_wire_estimate(
        ch.n_polys(),
        estimated_messages as usize * message_size,
        client_set_max,
        n_relays,
    )
}

/// Largest per-round message under RS ingress. The client post is constant, so
/// the biggest client-side message is one lane's coded share; the biggest relay
/// message carries both halves of a `ServerPublic`.
pub(crate) fn rs_wire_estimate(
    n_polys: usize,
    decoded_bytes: usize,
    client_set_max: u32,
    n_relays: usize,
) -> usize {
    const FRAMING: usize = 512;
    let n = n_relays.max(1);
    let rho = client_set_max.max(1);
    let block = panetiere::rs::RsParams::new(rs_k(n), n).block_len(n_polys);
    let w = round_wire_sizes(n, n_polys, rho);
    let client_public = RsClientBulletinEntry::packed_len() + FRAMING;
    let slice = block * dgt_packed_len() + fresh_path_packed_len(n) + FRAMING;
    let server_public = w.server_entry
        + lane_post_packed_len(block, n, rho as usize)
        + rho as usize * 4
        + FRAMING;
    client_public
        .max(slice)
        .max(server_public)
        .max(decoded_bytes + FRAMING)
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
    let mut session =
        PanetiereClientSession::new(pp.clone(), mse.clone(), identity.clone(), servers, seed);
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
        server_pubkeys,
    );
    session.set_client_set_max(cfg.client_set_max as usize);
    session.set_setup_seed(cfg.setup_seed);
    session.set_good_clients(good_clients);
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
    let (mse, pp) = params_for(&cfg, subnet.relays.len());
    let leader_pk = subnet_leader_pk(&subnet);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(
                &pp,
                &mse,
                &cfg,
                &subnet,
                &inner.identity,
                leader_pk,
                inner.good_clients.clone(),
            ),
        );
    } else {
        sessions.insert(
            SessionKey::Watch,
            Box::new(PanetiereWatchSession::new(leader_pk)),
        );
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

    let egress = |_key: &SessionKey, bytes: &[u8]| crate::panetiere::egress(subnet.id, bytes);

    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(1);
    let (mid_offset_ms, commit_offset_ms) = (dur_ms / 2, 0);

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
        client_session(
            &pp,
            &mse,
            &relay_xk,
            &subnet,
            &inner.identity,
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

    let mut reported = crate::runtime::ReportedFaults::default();
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
                    gossip_faults(&inner, subnet.id, identity_pk, &mut reported, faults).await;
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
        /// Bit-packed `RsClientBulletinEntry`: the key-share commitment, the root
        /// over the `n` coded shares, and the client's P-256 signature over both.
        /// Constant size in the message length — the point of the mode.
        #[serde(with = "serde_bytes")]
        entry: Vec<u8>,
        /// `client_id` must derive from this. Carried in-message because a relay
        /// forwards client wire, so the transport peer isn't the origin.
        signer: Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    /// One coded ciphertext share for lane `lane`, with that lane's opening of
    /// the client's share-commitment root. Rides the lane's own topic.
    ClientSlice {
        round: u64,
        client_id: u32,
        lane: u32,
        #[serde(with = "serde_bytes")]
        share: Vec<u8>,
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        signer: Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
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
        signer: Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    /// Relay `server_id`'s whole contribution for the round, over exactly
    /// `clients`: the summed Shamir key share, and — since every relay is also
    /// lane `server_id` — that lane's summed ciphertext share. Both are
    /// all-or-nothing over the same set, so they travel and verify together.
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
        /// Positional sum of this lane's coded shares — what RS reconstruction
        /// consumes in place of a bulletin full of ciphertexts.
        #[serde(with = "serde_bytes")]
        share_sum: Vec<u8>,
        /// The summed share-commitment opening proving `share_sum` against
        /// `Σ share_root` at this lane's position.
        #[serde(with = "serde_bytes")]
        lane_open: Vec<u8>,
        /// By `roster[server_id]` over [`server_public_signing_bytes`] —
        /// attribution binds to the key, not the self-declared slot.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    /// Decoded round result, published on broadcast by the subnet leader only
    /// (every relay decodes; one publishes).
    Decoded { round: u64, payloads: Vec<Vec<u8>> },
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
            | PanetiereWire::ClientSlice { round, .. }
            | PanetiereWire::Decoded { round, .. }
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn server_public_signing_bytes(
    round: u64,
    server_id: u32,
    clients: &[u32],
    agg_open: &[u8],
    agg_share: &[u8],
    share_sum: &[u8],
    lane_open: &[u8],
) -> Vec<u8> {
    let mut m = b"anymone/panetiere/server-public".to_vec();
    m.extend_from_slice(
        &bincode::serialize(&(
            round, server_id, clients, agg_open, agg_share, share_sum, lane_open,
        ))
        .expect("serialise signing bytes"),
    );
    m
}

pub(crate) fn client_public_signing_bytes(round: u64, client_id: u32, entry: &[u8]) -> Vec<u8> {
    let mut m = b"anymone/panetiere/client-public".to_vec();
    m.extend_from_slice(
        &bincode::serialize(&(round, client_id, entry)).expect("serialise signing bytes"),
    );
    m
}

pub(crate) fn client_opening_signing_bytes(
    round: u64,
    client_id: u32,
    target_server: u32,
    sealed: &[u8],
) -> Vec<u8> {
    let mut m = b"anymone/panetiere/client-opening".to_vec();
    m.extend_from_slice(
        &bincode::serialize(&(round, client_id, target_server, sealed))
            .expect("serialise signing bytes"),
    );
    m
}

pub(crate) fn client_slice_signing_bytes(
    round: u64,
    client_id: u32,
    lane: u32,
    share: &[u8],
    path: &[u8],
) -> Vec<u8> {
    let mut m = b"anymone/panetiere/client-slice".to_vec();
    m.extend_from_slice(
        &bincode::serialize(&(round, client_id, lane, share, path))
            .expect("serialise signing bytes"),
    );
    m
}

/// One lane's slice message, signed by the client's node identity. Shared by
/// both flows: the RS emission is identical, only the plaintext layout differs.
pub(crate) fn client_slice_wire(
    round: Round,
    client_id: u32,
    lane: u32,
    share: &[DgtNTTPoly],
    path: &SharePath,
    identity: &Identity,
) -> PanetiereWire {
    let mut share_bytes = Vec::new();
    panetiere::rs::pack_share(share, &mut share_bytes);
    let share = share_bytes;
    // Straight from `commit_shares`, so the digits are ζ-bounded by construction.
    let path = path.to_bytes().expect("fresh path digits within ζ");
    PanetiereWire::ClientSlice {
        round,
        client_id,
        lane,
        signature: identity.sign(&client_slice_signing_bytes(
            round, client_id, lane, &share, &path,
        )),
        share,
        path,
        signer: identity.pubkey(),
    }
}

/// Per-session P-256 key for the RS bulletin post, domain-separated from the
/// protocol seed. Never persisted: the post binds `(sid, client_id)` and the
/// Ed25519 wire signature already ties it to this node's identity.
pub(crate) fn derive_post_key(rng_seed: [u8; 32]) -> sig::SigningKey {
    let mut post_seed = rng_seed;
    post_seed[0] ^= 0x2A;
    sig::SigningKey::generate(&mut ChaCha20Rng::from_seed(post_seed))
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
        PanetiereWire::ClientSlice {
            client_id, lane, ..
        } => Some(format!("Panetiere ClientSlice cid={client_id} -> lane={lane}")),
        PanetiereWire::Decoded { round, payloads } => Some(format!(
            "Panetiere Decoded round={round} payloads={}",
            payloads.len()
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

/// Topic for one outbound message, by its own content. Relay shares and the
/// leader's `ClientSet` ride shares; a client's constant-size post rides
/// ingress; its coded share and its sealed opening ride the one lane each is
/// addressed to, so neither is gossiped to all S relays.
pub(crate) fn egress(subnet_id: crate::config::SubnetId, bytes: &[u8]) -> String {
    use crate::runtime::{
        subnet_broadcast_topic, subnet_ingress_topic, subnet_lane_topic, subnet_shares_topic,
    };
    match bincode::deserialize::<PanetiereWire>(bytes) {
        Ok(PanetiereWire::ServerPublic { .. } | PanetiereWire::ClientSet { .. }) => {
            subnet_shares_topic(subnet_id)
        }
        Ok(PanetiereWire::ClientPublic { .. }) => subnet_ingress_topic(subnet_id),
        Ok(PanetiereWire::ClientSlice { lane, .. }) => subnet_lane_topic(subnet_id, lane),
        Ok(PanetiereWire::Opening { target_server, .. }) => {
            subnet_lane_topic(subnet_id, target_server)
        }
        // `Decoded`, `Reservations`, and anything undecodable.
        _ => subnet_broadcast_topic(subnet_id),
    }
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
        | PanetiereWire::ClientSlice { round, .. }
        | PanetiereWire::Decoded { round, .. }
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
            share_sum,
            lane_open,
            signature,
        } => {
            let culprit = *roster.get(server_id as usize)?;
            if !culprit.verify(
                &server_public_signing_bytes(
                    round,
                    server_id,
                    &clients,
                    &agg_open,
                    &agg_share,
                    &share_sum,
                    &lane_open,
                ),
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
        let recent: Vec<&Vec<u32>> = self.clients_by_round.values().rev().take(window).collect();
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
                    share_sum,
                    lane_open,
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
                                *round, *server_id, clients, agg_open, agg_share, share_sum,
                                lane_open,
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
                PanetiereWire::ClientPublic { .. }
                | PanetiereWire::Opening { .. }
                | PanetiereWire::ClientSlice { .. } => {}
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
    identity: Identity,
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
    /// Signs the RS bulletin post. Per-session and never persisted: the post
    /// binds `(sid, client_id)` and the Ed25519 wire signature already ties it
    /// to this node's identity, so no cross-round continuity is needed.
    post_key: sig::SigningKey,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
}

impl PanetiereClientSession {
    /// `client_id` derives from `identity`, so a session can only ever claim the
    /// slot its own key owns.
    pub fn new(
        pp: Arc<ProtocolParams>,
        mse: ChannelParams,
        identity: Identity,
        servers: Vec<(ServerId, pke::PublicKey)>,
        rng_seed: [u8; 32],
    ) -> Self {
        // Domain-separate the cover and MSE-r streams from the protocol seed.
        let mut cover_seed = rng_seed;
        cover_seed[0] ^= 0xA5;
        let mut r_seed = rng_seed;
        r_seed[0] ^= 0x3C;
        let post_key = derive_post_key(rng_seed);
        PanetiereClientSession {
            pp,
            mse,
            client_id: client_id_from_pubkey(identity.pubkey()),
            identity,
            servers,
            pending: None,
            rng_seed,
            cover_rate: 1.0,
            cover_rng: ChaCha20Rng::from_seed(cover_seed),
            r_rng: ChaCha20Rng::from_seed(r_seed),
            post_key,
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
        let round_out = run_client_round_rs(
            &mut rng,
            &self.pp,
            &sid,
            self.client_id,
            msg,
            &self.servers,
            &self.post_key,
        );
        tracing::trace!(
            target: PANETIERE,
            round,
            client_id = self.client_id.0,
            real = had_pending,
            "panetiere client: emitting"
        );

        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1 + 2 * self.servers.len());

        let cid = round_out.client_id.0;
        let entry = round_out.bulletin.to_bytes();
        let pub_msg = PanetiereWire::ClientPublic {
            round,
            client_id: cid,
            signature: self
                .identity
                .sign(&client_public_signing_bytes(round, cid, &entry)),
            entry,
            signer: self.identity.pubkey(),
        };
        out.push(bincode::serialize(&pub_msg).expect("serialise client public"));

        // Lane j's coded ciphertext share and its opening of the share root.
        for (lane, (share, path)) in round_out
            .rs_shares
            .iter()
            .zip(round_out.share_paths.iter())
            .enumerate()
        {
            let slice = client_slice_wire(round, cid, lane as u32, share, path, &self.identity);
            out.push(bincode::serialize(&slice).expect("serialise client slice"));
        }

        for (server_id, sealed) in round_out.sealed_openings {
            let opening_msg = PanetiereWire::Opening {
                round,
                client_id: cid,
                target_server: server_id.0,
                signature: self.identity.sign(&client_opening_signing_bytes(
                    round,
                    cid,
                    server_id.0,
                    &sealed,
                )),
                sealed,
                signer: self.identity.pubkey(),
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
    publics: HashMap<ClientId, RsClientBulletinEntry>,
    inbox_items: Vec<(ClientId, Opening)>,
    /// Our lane's coded share from each client, with that lane's opening.
    lane_items: Vec<(ClientId, Vec<DgtNTTPoly>, SharePath)>,
    peer_server_publics: HashMap<ServerId, ServerBulletinEntry>,
    /// Peer lane sums for the round, with the raw wire kept as fault evidence.
    peer_lane_sums: HashMap<NodeId, (RsNodeBulletinEntry, Vec<u8>)>,
    emitted_my_public: bool,
    decoded: bool,
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
    server_pubkeys: HashMap<ServerId, Pubkey>,
    /// Per-round buckets, ordered so decode and GC walk oldest-first.
    rounds: std::collections::BTreeMap<Round, PanetiereRoundState>,
    /// Leader/Follower: the one canonical set per round (announced by the leader).
    client_set_by_round: std::collections::BTreeMap<Round, Vec<ClientId>>,
    announced_rounds: HashSet<Round>,
    misbehavior: Option<Misbehavior>,
    /// Own round clock, from `begin_round`; bounds accepted wire rounds.
    cur_round: Option<Round>,
    /// First round this session ticked; earlier rounds were only partially
    /// observed and must never be (re-)announced.
    first_round: Option<Round>,
    /// Upper bound on distinct clients admitted per round (also the canonical
    /// set size ceiling); unbounded until [`Self::set_client_set_max`] is called.
    client_set_max: usize,
    /// Subnet's `setup_seed`; with the round it forms the `sid` openings bind to.
    setup_seed: [u8; 32],
    good_clients: GoodClients,
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
        server_pubkeys: HashMap<ServerId, Pubkey>,
    ) -> Self {
        PanetiereServerSession {
            pp,
            mse,
            server_id,
            identity,
            mode,
            server_pubkeys,
            rounds: std::collections::BTreeMap::new(),
            client_set_by_round: std::collections::BTreeMap::new(),
            announced_rounds: HashSet::new(),
            misbehavior: None,
            cur_round: None,
            first_round: None,
            client_set_max: usize::MAX,
            setup_seed: [0u8; 32],
            good_clients: GoodClients::all(),
        }
    }

    pub(crate) fn set_setup_seed(&mut self, setup_seed: [u8; 32]) {
        self.setup_seed = setup_seed;
    }

    pub fn set_good_clients(&mut self, good_clients: GoodClients) {
        self.good_clients = good_clients;
    }

    /// Signature-verifies a client contribution and screens its signer.
    fn accept_client(
        &self,
        round: Round,
        client_id: u32,
        signer: Pubkey,
        signature: &[u8],
        signing_bytes: &[u8],
        kind: &str,
    ) -> bool {
        if !signer.verify(signing_bytes, signature) {
            tracing::debug!(
                target: PANETIERE,
                round,
                client_id,
                signer = %signer,
                kind,
                "panetiere server: client signature invalid, dropped"
            );
            return false;
        }
        if !self.good_clients.allows(&signer) {
            tracing::debug!(
                target: PANETIERE,
                round,
                client_id,
                signer = %signer,
                kind,
                "panetiere server: signer not an accepted client, dropped"
            );
            return false;
        }
        true
    }

    /// Caps distinct clients admitted per round and the accepted canonical set
    /// size. Call with the subnet's real `client_set_max` on public subnets,
    /// where the client set is attacker-influenced; the committee's own
    /// internal channel is naturally bounded by committee size and can skip this.
    pub fn set_client_set_max(&mut self, max: usize) {
        self.client_set_max = max;
    }

    /// Leader-only: announce the one canonical set per settled round, once.
    pub(crate) fn announce_settled(&mut self, round: Round) -> Vec<Vec<u8>> {
        let mut outbound = Vec::new();
        let mut announce: Vec<(Round, Vec<ClientId>, u32)> = Vec::new();
        for (&r, state) in self.rounds.iter() {
            // The predecessor worker announced pre-spawn rounds from full state.
            let partial = self.first_round.is_some_and(|f| r < f);
            if r > round || partial || self.announced_rounds.contains(&r) || state.inbox_items.is_empty()
            {
                continue;
            }
            // Safe to truncate: every relay admits 2× the cap in openings,
            // so any cap-sized subset the leader picks is servable.
            let mut canonical: Vec<ClientId> = state
                .inbox_items
                .iter()
                .filter_map(|(cid, _)| state.publics.get(cid).map(|_| *cid))
                .take(self.client_set_max)
                .collect();
            canonical.sort();
            canonical.dedup();
            // Admitted + capacity-rejected: uncensored, unlike the capped set.
            let demand = (state.owners.len() + state.rejected.len()).max(canonical.len()) as u32;
            tracing::trace!(
                target: PANETIERE,
                round = r,
                publics = state.publics.len(),
                inbox = state.inbox_items.len(),
                announced = canonical.len(),
                demand,
                "panetiere leader: canonical set"
            );
            // Openings without a matching public (or vice versa) are clients the
            // leader saw but can't announce, so they're excluded from the round.
            if canonical.len() < state.inbox_items.len() {
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
                    publics = state.publics.len(),
                    inbox = state.inbox_items.len(),
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
fn log_decode_failure(round: Round, e: &VerifyError) {
    match e {
        // Expected early in a round: peers report during the next one.
        VerifyError::NoServers | VerifyError::NotEnoughNodes | VerifyError::BadServerCoverage => {
            tracing::trace!(
                target: PANETIERE,
                round,
                ?e,
                "panetiere decode: below the share threshold, not yet decodable"
            )
        }
        _ => tracing::debug!(target: PANETIERE, round, ?e, "panetiere decode: round rejected"),
    }
}

fn collect_outputs(state: &PanetiereRoundState) -> Vec<ServerBulletinEntry> {
    state.peer_server_publics.values().cloned().collect()
}

/// One RS decode attempt over `set`, excluding attributable culprits and
/// retrying until the thresholds can't be met. There is no recipient wrapper for
/// RS mode, so the exclusion loop that `recover_*` owns for the broadcast flow
/// lives here. Lane liars are named as faults; servers are left to the leader's
/// fault monitor, which sees the same wire.
fn recover_rs(
    pp: &Arc<ProtocolParams>,
    sid: &SessionId,
    round: Round,
    state: &PanetiereRoundState,
    set: &[ClientId],
    lane_culprits: &mut Vec<NodeId>,
) -> Option<Vec<KahePoly>> {
    let rs_k = pp.rs.as_ref().map(|rs| rs.k)?;
    // Posts made over a different set can't contribute: upstream hard-errors
    // rather than mixing sets, so they are filtered, not excluded as culprits.
    let mut servers: Vec<ServerBulletinEntry> = state
        .peer_server_publics
        .values()
        .filter(|sp| sp.clients == set)
        .cloned()
        .collect();
    let mut lanes: Vec<RsNodeBulletinEntry> = state
        .peer_lane_sums
        .values()
        .map(|(l, _)| l)
        .filter(|l| l.clients == set)
        .cloned()
        .collect();
    let entries: Vec<(ClientId, RsClientBulletinEntry)> = set
        .iter()
        .filter_map(|c| state.publics.get(c).map(|e| (*c, e.clone())))
        .collect();
    if entries.len() != set.len() {
        tracing::trace!(
            target: PANETIERE,
            round,
            have = entries.len(),
            need = set.len(),
            "panetiere decode: posts missing for the canonical set"
        );
        return None;
    }
    loop {
        if servers.len() < pp.shamir.t || lanes.len() < rs_k {
            tracing::trace!(
                target: PANETIERE,
                round,
                servers = servers.len(),
                need_servers = pp.shamir.t,
                lanes = lanes.len(),
                need_lanes = rs_k,
                "panetiere decode: below threshold, not yet decodable"
            );
            return None;
        }
        match aggregate_and_decrypt_rs(pp, sid, set, &entries, &servers, &lanes) {
            Ok((plain, _)) => return Some(plain),
            Err(VerifyError::InvalidServerOpening(i)) | Err(VerifyError::ShareOpeningMismatch(i)) => {
                tracing::debug!(
                    target: PANETIERE,
                    round,
                    server = servers.get(i).map(|s| s.server_id.0),
                    "panetiere decode: excluding a server that failed its opening"
                );
                servers.remove(i);
            }
            Err(VerifyError::LaneOpeningFailed(ids)) => {
                tracing::warn!(
                    target: PANETIERE,
                    round,
                    lanes = ?ids.iter().map(|n| n.0).collect::<Vec<_>>(),
                    "panetiere decode: lane sum did not open; excluding the lane"
                );
                lane_culprits.extend(ids.iter().copied());
                lanes.retain(|l| !ids.contains(&l.node_id));
            }
            Err(e) => {
                log_decode_failure(round, &e);
                return None;
            }
        }
    }
}

/// Candidate canonical sets for a leaderless decode: every distinct set the
/// server shares cover, largest first (ties broken by the set itself, so the
/// order is a function of the inputs).
fn candidate_sets(outputs: &[ServerBulletinEntry]) -> Vec<Vec<ClientId>> {
    let mut sets: Vec<Vec<ClientId>> = outputs
        .iter()
        .map(|sp| {
            let mut c = sp.clients.clone();
            c.sort();
            c.dedup();
            c
        })
        .collect();
    sets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    sets.dedup();
    sets
}


impl Session for PanetiereServerSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if self.first_round.is_none() {
            self.first_round = Some(round);
        }
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
        // produced under a different config (e.g. a different client-set cap)
        // must never be validated against this one.
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
                signer,
                signature,
            } => {
                let expected = RsClientBulletinEntry::packed_len();
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
                if !self.accept_client(
                    round,
                    client_id,
                    signer,
                    &signature,
                    &client_public_signing_bytes(round, client_id, &entry),
                    "public",
                ) {
                    return Vec::new();
                }
                let cid = ClientId(client_id);
                // 2×, like the openings: every lane needs the root of every
                // canonical member, whichever cap-sized set the leader picks.
                let max = self.client_set_max.saturating_mul(2);
                let bucket = self.rounds.entry(round).or_default();
                match admit_client(&mut bucket.owners, cid, signer, max) {
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
                            signer = %signer,
                            derived = client_id_from_pubkey(signer).0,
                            "panetiere server: public rejected, client id not owned by the signer"
                        );
                        return Vec::new();
                    }
                }
                match RsClientBulletinEntry::from_bytes(&entry) {
                    Some(parsed) => {
                        // Verify the client's own P-256 signature at ingest, so a
                        // forged post can never reach decode as a `BadSignature`.
                        let sid = session_id(&self.setup_seed, round);
                        let signed = RsClientBulletinEntry::signing_bytes(
                            &sid,
                            cid,
                            &parsed.comm,
                            &parsed.share_root,
                        );
                        let ok = sig::VerifyingKey::from_sec1_bytes(&parsed.pubkey)
                            .is_ok_and(|vk| vk.verify(&signed, &parsed.sig).is_ok());
                        if !ok {
                            tracing::debug!(
                                target: PANETIERE,
                                round,
                                client_id,
                                "panetiere server: RS post signature invalid, dropped"
                            );
                            return Vec::new();
                        }
                        bucket.publics.insert(cid, parsed);
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
                signer,
                signature,
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
                    if !self.accept_client(
                        round,
                        client_id,
                        signer,
                        &signature,
                        &client_opening_signing_bytes(round, client_id, target_server, &sealed),
                        "opening",
                    ) {
                        return Vec::new();
                    }
                    let cid = ClientId(client_id);
                    // Admission is arrival-ordered and differs per relay, while
                    // the canonical set is frozen elsewhere; 2× headroom keeps
                    // every canonical member's opening servable.
                    let max = self.client_set_max.saturating_mul(2);
                    let bucket = self.rounds.entry(round).or_default();
                    match admit_client(&mut bucket.owners, cid, signer, max) {
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
                                signer = %signer,
                                derived = client_id_from_pubkey(signer).0,
                                "panetiere server: opening rejected, client id not owned by the signer"
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
            PanetiereWire::ClientSlice {
                round,
                client_id,
                lane,
                share,
                path,
                signer,
                signature,
            } => {
                if lane != self.server_id.0 {
                    return Vec::new();
                }
                if !self.accept_client(
                    round,
                    client_id,
                    signer,
                    &signature,
                    &client_slice_signing_bytes(round, client_id, lane, &share, &path),
                    "slice",
                ) {
                    return Vec::new();
                }
                // A stale-geometry client's share can't sum with the rest, so it
                // is rejected here rather than poisoning the lane's sum.
                let (share_len, path_len) = slice_wire_lens(&self.pp);
                if share.len() != share_len || path.len() != path_len {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        client_id,
                        lane,
                        got = share.len(),
                        expected = share_len,
                        "panetiere server: wrong-geometry slice dropped"
                    );
                    return Vec::new();
                }
                let cid = ClientId(client_id);
                let max = self.client_set_max.saturating_mul(2);
                let bucket = self.rounds.entry(round).or_default();
                match admit_client(&mut bucket.owners, cid, signer, max) {
                    Admit::Admitted => {}
                    Admit::AtCapacity => {
                        if bucket.rejected.len() < max.saturating_mul(4) {
                            bucket.rejected.insert(cid);
                        }
                        return Vec::new();
                    }
                    Admit::NotOwner => {
                        tracing::debug!(
                            target: PANETIERE,
                            round,
                            client_id,
                            signer = %signer,
                            "panetiere server: slice rejected, client id not owned by the signer"
                        );
                        return Vec::new();
                    }
                }
                if bucket.lane_items.iter().any(|(c, _, _)| *c == cid) {
                    return Vec::new();
                }
                let Some(scp) = self.pp.share_comm.as_ref() else {
                    return Vec::new();
                };
                let Some(share) = panetiere::rs::unpack_share(&share, scp.block_len) else {
                    return Vec::new();
                };
                let Some(path) = SharePath::from_bytes(scp, lane as usize, &path) else {
                    return Vec::new();
                };
                bucket.lane_items.push((cid, share, path));
            }
            PanetiereWire::ServerPublic {
                round,
                server_id,
                clients,
                agg_open,
                agg_share,
                share_sum,
                lane_open,
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
                            round,
                            server_id,
                            &clients,
                            &agg_open,
                            &agg_share,
                            &share_sum,
                            &lane_open,
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
                let Some(cs_share) = panetiere::cs::unpack_cs_shares(&agg_share, n_shares)
                    .filter(|s| s.len() == 1)
                    .map(|s| s[0])
                else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        len = agg_share.len(),
                        n_shares,
                        "panetiere server: share body failed to unpack, dropped"
                    );
                    return Vec::new();
                };
                // The lane half of the same message: this relay's summed coded
                // share plus the opening that proves it.
                let scp = self.pp.share_comm.as_ref().expect("RS mode params");
                let lane = server_id as usize;
                let parsed_lane = panetiere::rs::unpack_share(&share_sum, scp.block_len)
                    .zip(ShareOpening::from_bytes(scp, lane, &lane_open));
                let Some((lane_share_sum, lane_opening)) = parsed_lane else {
                    tracing::debug!(
                        target: PANETIERE,
                        round,
                        server_id,
                        share_len = share_sum.len(),
                        open_len = lane_open.len(),
                        "panetiere server: lane sum failed to unpack, share dropped"
                    );
                    return Vec::new();
                };
                let client_ids: Vec<ClientId> = clients.into_iter().map(ClientId).collect();
                let bucket = self.rounds.entry(round).or_default();
                bucket.peer_server_publics.insert(
                    ServerId(server_id),
                    ServerBulletinEntry {
                        server_id: ServerId(server_id),
                        clients: client_ids.clone(),
                        agg_open,
                        agg_share: cs_share,
                    },
                );
                bucket.peer_lane_sums.insert(
                    NodeId(server_id),
                    (
                        RsNodeBulletinEntry {
                            node_id: NodeId(server_id),
                            clients: client_ids,
                            share_sum: lane_share_sum,
                            agg_open: lane_opening,
                        },
                        payload,
                    ),
                );
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
        }
        Vec::new()
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        let is_leader = self.mode == SetMode::Leader;
        let withholding = self.misbehavior == Some(Misbehavior::Withhold);

        let mut outbound: Vec<Vec<u8>> = Vec::new();
        if is_leader && !withholding {
            outbound.extend(self.announce_settled(round));
        }
        outbound.extend(self.emit_server_publics(round));

        let mut decoded: Vec<Vec<u8>> = Vec::new();
        let (settled, decode_faults) = self.decode_settled();
        for (r, plain) in settled {
            // Peel every client's element out of the summed plaintext. A
            // cover-only round peels to nothing; a stall means the structure was
            // over-subscribed and the round's payloads are gone, which must not
            // look the same as an empty round.
            let msgs: Vec<Vec<u8>> = match channel::decode_messages(&self.mse, &plain, None) {
                Ok(elements) => elements
                    .into_iter()
                    .filter(|b| b.iter().any(|x| *x != 0))
                    .collect(),
                // Oversubscription is the application outrunning its sizing, not
                // a relay fault; the sketch reports the true contributor count,
                // which is the demand figure the capacity should be sized to.
                Err(ChannelError::SketchFailed(PronyError::CapacityExceeded {
                    count,
                    capacity,
                })) => {
                    tracing::error!(
                        target: PANETIERE,
                        round = r,
                        contributors = count,
                        capacity,
                        "panetiere: channel oversubscribed; this round's messages are lost"
                    );
                    Vec::new()
                }
                Err(e) => {
                    tracing::warn!(
                        target: PANETIERE,
                        round = r,
                        ?e,
                        "panetiere: payload decode failed; this round's messages are lost"
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
            faults: decode_faults,
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
            // leaderless committee derives its own (public + opening it holds).
            let canonical: Vec<ClientId> = if self_derived {
                let mut c: Vec<ClientId> = state
                    .inbox_items
                    .iter()
                    .filter_map(|(cid, _)| state.publics.get(cid).map(|_| *cid))
                    .collect();
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
            // Both halves are all-or-nothing over the same set: skip a round we
            // can't fully cover rather than share over a different set than the
            // leader's. The lane needs every member's slice AND its signed root.
            let present: HashSet<ClientId> =
                state.inbox_items.iter().map(|(cid, _)| *cid).collect();
            if !self_derived {
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
            let have_slices: HashSet<ClientId> =
                state.lane_items.iter().map(|(cid, _, _)| *cid).collect();
            let missing_lane = canonical
                .iter()
                .filter(|c| !have_slices.contains(c) || !state.publics.contains_key(c))
                .count();
            if missing_lane > 0 {
                tracing::debug!(
                    target: PANETIERE,
                    round = r,
                    missing = missing_lane,
                    canonical = canonical.len(),
                    slices = have_slices.len(),
                    publics = state.publics.len(),
                    "panetiere server: lane slices incomplete for canonical set; share deferred"
                );
                continue;
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
                    // The lane half over the same canonical set. A client whose
                    // share disagrees with its own signed root is named here and
                    // costs this lane the round; `k = t` absorbs up to f of those.
                    let scp = self.pp.share_comm.as_ref().expect("RS mode params");
                    let roots: Vec<(ClientId, HVCPoly)> = sp
                        .clients
                        .iter()
                        .map(|c| (*c, state.publics[c].share_root))
                        .collect();
                    let lane_inbox = RsNodeInbox {
                        node_id: NodeId(sid.0),
                        items: std::mem::take(&mut state.lane_items),
                    };
                    let lane = match run_rs_node_round(scp, &lane_inbox, &sp.clients, &roots) {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::warn!(
                                target: PANETIERE,
                                round = r,
                                node_id = sid.0,
                                canonical = sp.clients.len(),
                                ?e,
                                "panetiere lane: run_rs_node_round failed; no share for this round"
                            );
                            continue;
                        }
                    };
                    let mut share_sum = Vec::new();
                    panetiere::rs::pack_share(&lane.share_sum, &mut share_sum);
                    if corrupt_share {
                        if let Some(b) = share_sum.first_mut() {
                            *b ^= 0x01;
                        }
                    }
                    // Packing gates on β_agg, the same bound the aggregated
                    // opening has to verify under: unpackable means unverifiable.
                    let Some(lane_open) = lane.agg_open.to_bytes(scp) else {
                        tracing::warn!(
                            target: PANETIERE,
                            round = r,
                            node_id = sid.0,
                            canonical = sp.clients.len(),
                            "panetiere lane: aggregated opening past the digit bound; no share for this round"
                        );
                        continue;
                    };
                    // Sign what we publish — a corrupted share stays attributable.
                    let signature = identity.sign(&server_public_signing_bytes(
                        r,
                        sp.server_id.0,
                        &clients,
                        &agg_open,
                        &agg_share,
                        &share_sum,
                        &lane_open,
                    ));
                    let wire = PanetiereWire::ServerPublic {
                        round: r,
                        server_id: sp.server_id.0,
                        clients,
                        agg_open,
                        agg_share,
                        share_sum,
                        lane_open,
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
                    state.peer_lane_sums.insert(NodeId(sid.0), (lane, Vec::new()));
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
    pub(crate) fn decode_settled(&mut self) -> (Vec<(Round, Vec<KahePoly>)>, Vec<Fault>) {
        let self_derived = self.mode == SetMode::SelfDerived;
        let max_clients = self.client_set_max;
        let mut out = Vec::new();
        let mut faults = Vec::new();
        for (r, state) in self.rounds.iter_mut() {
            if state.decoded {
                continue;
            }
            let anchor: Option<Vec<ClientId>> = if self_derived {
                None
            } else {
                self.client_set_by_round.get(r).cloned()
            };
            // No announced set (leaderless committee): try each set the posts
            // agree on, largest first.
            let candidates: Vec<Vec<ClientId>> = match anchor {
                Some(set) => vec![set],
                None => candidate_sets(&collect_outputs(state)),
            };
            let sid = session_id(&self.setup_seed, *r);
            let mut plain = None;
            let mut culprits: Vec<NodeId> = Vec::new();
            for set in candidates {
                if set.len() > max_clients {
                    continue;
                }
                if let Some(p) = recover_rs(&self.pp, &sid, *r, state, &set, &mut culprits) {
                    plain = Some(p);
                    break;
                }
            }
            // A lane that fails its own opening is named from the wire it signed.
            for id in culprits {
                if let Some((_, evidence)) = state.peer_lane_sums.get(&id) {
                    if let Some(pk) = self.server_pubkeys.get(&ServerId(id.0)) {
                        faults.push(Fault {
                            kind: FaultKind::Integrity,
                            attribution: Attribution::Peers(vec![*pk]),
                            evidence: evidence.clone(),
                        });
                    }
                }
            }
            if let Some(plain) = plain {
                out.push((*r, plain));
                state.decoded = true;
                // Free the heavy crypto state; keep the (now-empty) bucket
                // marked `decoded` so a share that arrives a round late lands
                // here and is skipped rather than re-decoding into a duplicate.
                state.publics.clear();
                state.inbox_items.clear();
                state.lane_items.clear();
                state.peer_server_publics.clear();
                state.peer_lane_sums.clear();
            }
        }
        (out, faults)
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
                share_sum: Vec::new(),
                lane_open: Vec::new(),
                signature,
            })
            .unwrap()
        };
        let signing = server_public_signing_bytes(9, 1, &[10], &agg_open, &[], &[], &[]);
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
        let far_signing =
            server_public_signing_bytes(u64::MAX, 1, &[10], &agg_open, &[], &[], &[]);
        let far = bincode::serialize(&PanetiereWire::ServerPublic {
            round: u64::MAX,
            server_id: 1,
            clients: vec![10],
            agg_open: agg_open.clone(),
            agg_share: Vec::new(),
            share_sum: Vec::new(),
            lane_open: Vec::new(),
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
        for encoding in [Encoding::Prony, Encoding::Mse] {
            let cfg = PanetiereConfig {
                message_size: msg_size,
                estimated_messages: est_msgs,
                client_set_max: cset,
                encoding,
                ..Default::default()
            };
            let est = max_wire_estimate(msg_size, est_msgs, cset, n_relays, encoding);

            let (mse, pp) = params_for(&cfg, n_relays);
            let servers: Vec<(ServerId, pke::PublicKey)> = (0..n_relays as u32)
                .map(|i| {
                    (
                        ServerId(i),
                        pke::PrivateKey::generate(&mut rand::rngs::OsRng).public(),
                    )
                })
                .collect();
            let mut c = PanetiereClientSession::new(
                pp.clone(),
                mse,
                Identity::generate(),
                servers,
                [2u8; 32],
            );
            let client_public = c
                .begin_round(0, Instant::now())
                .iter()
                .map(|m| m.len())
                .max()
                .unwrap();
            assert!(
                est >= client_public,
                "{encoding:?}: estimate {est} < real ClientPublic {client_public}"
            );
            assert!(
                est >= pp.cs.aggregated_server_crypto_len(cset),
                "{encoding:?}: estimate omits the ServerPublic crypto term"
            );
        }
    }

    /// The modulus mismatch this guards is silent: a Prony channel over a
    /// power-of-two plaintext modulus decodes to noise, not an error.
    #[test]
    fn protocol_params_match_encoding() {
        for (encoding, modulus) in [
            (Encoding::Prony, panetiere::prony::PRONY_PRIME),
            (Encoding::Mse, panetiere::kahe::T_MODULUS_DEFAULT),
        ] {
            let cfg = PanetiereConfig {
                message_size: 256,
                estimated_messages: 64,
                client_set_max: 64,
                encoding,
                ..Default::default()
            };
            let (ch, pp) = params_for(&cfg, 5);
            assert_eq!(
                message_polys(&pp),
                ch.n_polys(),
                "{encoding:?}: KAHE width must be exactly one packed encoding"
            );
            assert_eq!(
                pp.kahe.t_modulus, modulus,
                "{encoding:?}: plaintext modulus must come from the encoding"
            );
        }
        // The whole point of the sketch: ~3x narrower at the same capacity.
        let prony = channel_params(300, 4096, [3u8; 32], Encoding::Prony).n_polys();
        let mse = channel_params(300, 4096, [3u8; 32], Encoding::Mse).n_polys();
        assert!(prony * 2 < mse, "prony {prony} polys vs mse {mse}");
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

        let cfg = PanetiereConfig {
            message_size: 64,
            estimated_messages: active as u32,
            client_set_max: total as u32,
            ..Default::default()
        };
        let (mse, pp) = params_for(&cfg, n_servers);

        let client_ids: Vec<Identity> = (0..total).map(|_| Identity::generate()).collect();
        let client_pks: Vec<Pubkey> = client_ids.iter().map(|id| id.pubkey()).collect();
        let mut clients: Vec<PanetiereClientSession> = (0..total)
            .map(|i| {
                PanetiereClientSession::new(
                    pp.clone(),
                    mse.clone(),
                    client_ids[i].clone(),
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
                    server_pubkeys.clone(),
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

        // Stage 4: decode — distinguishes a verify/anchor rejection from a
        // payload decode failure.
        let anchor: Vec<ClientId> = announced.iter().map(|&c| ClientId(c)).collect();
        // No session sets a setup seed here, so every sid is the default's.
        let sid = session_id(&[0u8; 32], 0);
        for (si, s) in servers.iter().enumerate() {
            let state = s.rounds.get(&0).unwrap();
            let mut culprits = Vec::new();
            let plain = recover_rs(&pp, &sid, 0, state, &anchor, &mut culprits)
                .unwrap_or_else(|| panic!("server {si}: RS recovery rejected the round"));
            assert!(culprits.is_empty(), "server {si}: unexpected lane culprits");
            let recovered_msgs: Vec<Vec<u8>> = channel::decode_messages(&mse, &plain, None)
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
