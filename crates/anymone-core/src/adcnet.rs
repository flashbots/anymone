//! ADCNet `Session` wrappers. Two flows, picked per subnet via
//! [`crate::ProtocolConfig`]: a 1-round IBLT-message flow ([`AdcnetClientSession`]
//! / [`AdcnetServerSession`]) and a 2-round auction-then-broadcast flow
//! ([`ScheduledAdcnetClientSession`] / [`ScheduledAdcnetServerSession`], which
//! use the upstream auction, blinding, and share-combining primitives).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::identity::{ExchangeIdentity, Identity};
pub use adcnet::crypto::ServerId;
use adcnet::crypto::{ExchangePrivateKey, ExchangePublicKey, PrivateKey, PublicKey, SharedKey};
use adcnet::protocol::messages::Signed;
use adcnet::protocol::session::one_round::{
    client_contribute, combine_round, server_contribute, ClientContribution, ServerShare,
};
pub use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};
use adcnet::protocol::session::two_round::ServerService;
use adcnet::protocol::{
    AdcNetConfig as UpstreamAdcNetConfig, AggregationMode, ClientRoundMessage,
    Round as UpstreamRound, RoundBroadcast, RoundContext, ServerPartialDecryptionMessage,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use crate::config::{AdcnetConfig, ExchangePublicKeyWire, ProtocolConfig, Round, Subnet};
use crate::faults::Fault;
use crate::identity::Pubkey;
use crate::log_target::{ADCNET, SCHED};
use crate::runtime::{
    aggregator_group_of, client_aggregator, deadline_for, drain_inbound, gossip_faults,
    handle_inbound, publish_and_loop_back, recv_any, round_at, route_to_pipe, subnet_aggregation,
    subnet_leader_pk, AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{GoodClients, LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::{Dest, Subscription, Topic};

/// Per-subnet ADCNet parameters (IBLT sizing), built once at subnet start.
pub(crate) fn one_round_config(cfg: &AdcnetConfig) -> OneRoundConfig {
    OneRoundConfig {
        iblt: IbltMsgParamsOwned {
            estimated_messages: cfg.estimated_messages,
            max_payload_bytes: cfg.max_payload_bytes,
        },
    }
}

/// Conservative upper bound on the largest per-round wire message an ADCNet subnet
/// broadcasts, for the committee's p2p size-cap guard. Uses the real IBLT sizing
/// (`encoded_len`); the blinded/share `Vec<u64>` dominates.
pub(crate) fn max_wire_estimate(
    message_size: usize,
    estimated_messages: u32,
    client_set_max: u32,
    _n_relays: usize,
) -> usize {
    const SIGNED_FRAMING: usize = 256;
    const KEYSET_ENTRY: usize = 200;
    let iblt = IbltMsgParamsOwned {
        estimated_messages,
        max_payload_bytes: message_size,
    };
    let share = iblt.as_params().encoded_len() * 8 + SIGNED_FRAMING;
    let client_set = client_set_max as usize * KEYSET_ENTRY + SIGNED_FRAMING;
    let decoded = estimated_messages as usize * message_size + SIGNED_FRAMING;
    share.max(client_set).max(decoded)
}

/// `pk`'s 0-based position in the sorted relay list — the ADCNet `ServerId`.
/// 0-based to match Panetiere (whose base is fixed by its Shamir/Merkle index);
/// ADCNet treats the id as an opaque label, so either base works.
fn relay_index(subnet: &Subnet, pk: Pubkey) -> Option<u32> {
    let mut sorted = subnet.relays.to_vec();
    sorted.sort();
    sorted.iter().position(|p| *p == pk).map(|i| i as u32)
}

/// ECDH the node's exchange privkey against each relay's exchange pubkey,
/// keyed by 0-based `ServerId`.
pub(crate) fn client_shared_secrets(
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    identity: &Identity,
    subnet: &Subnet,
) -> HashMap<ServerId, SharedKey> {
    crate::keys::roster_exchange_pubkeys(&subnet.relays, relay_xk)
        .into_iter()
        .map(|(i, xk)| (ServerId(i as u32), identity.exchange().ecdh(&xk)))
        .collect()
}

fn client_session(
    round: Round,
    inner: &Arc<AnymoneInner>,
    relay_xk: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
    identity: &Identity,
) -> Box<dyn Session> {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    match &subnet.protocol {
        ProtocolConfig::Adcnet(cfg) => Box::new(AdcnetClientSession::new(
            one_round_config(cfg),
            identity.to_adcnet_signing_key(),
            client_shared_secrets(relay_xk, identity, subnet),
            identity.exchange_pubkey(),
            seed,
        )),
        ProtocolConfig::ScheduledAdcnet(cfg) => {
            let config = scheduled_config(cfg);
            let servers: Vec<_> = crate::keys::roster_exchange_pubkeys(&subnet.relays, relay_xk)
                .into_iter()
                .map(|(i, key)| (ServerId(i as u32), key))
                .collect();
            let initial = empty_scheduled_broadcast(&config, 0);
            let mut client = ScheduledAdcnetClientSession::new(
                config,
                identity.to_adcnet_signing_key(),
                ExchangePrivateKey::from_bytes(&identity.exchange().scalar_bytes())
                    .expect("valid exchange scalar"),
                &servers,
                initial,
                round as i64 + 1,
                subnet_leader_pk(subnet),
            );
            client.min_message_size = cfg.min_message_size as usize;
            client.node = Some(Arc::downgrade(inner));
            Box::new(client)
        }
        _ => unreachable!(),
    }
}


fn server_session(
    one_round: &OneRoundConfig,
    cfg: &AdcnetConfig,
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
    good_clients: GoodClients,
) -> Box<dyn Session> {
    let identity_pk = identity.pubkey();
    let idx = relay_index(subnet, identity_pk).expect("server_session called on non-relay");
    let is_leader = identity_pk == leader_pk;
    // Only the leader combines, so only it needs the aggregator roster.
    let aggregation = if is_leader {
        cfg.aggregation.as_ref().map(LeaderAggregation::from_config)
    } else {
        None
    };
    let mut roster = subnet.relays.clone();
    roster.sort();
    let mut session = AdcnetServerSession::new(
        one_round.clone(),
        ServerId(idx),
        identity.to_adcnet_signing_key(),
        identity.exchange().clone(),
        subnet.relays.len(),
        roster,
        cfg.client_set_min as usize,
        cfg.client_set_max as usize,
        is_leader,
        leader_pk,
        aggregation,
    );
    session.set_good_clients(good_clients);
    Box::new(session)
}

/// Self-contained ADCNet subnet driver: builds this node's sessions, then owns
/// the round loop. The runtime dispatches here for ADCNet subnets.
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
    let scheduled = matches!(subnet.protocol, ProtocolConfig::ScheduledAdcnet(_));
    let identity_pk = inner.identity.pubkey();
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg = client_aggregator(&subnet, identity_pk);
    let mut sorted_roster = subnet.relays.clone();
    sorted_roster.sort();

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        let session = match &subnet.protocol {
            ProtocolConfig::Adcnet(cfg) => server_session(
                &one_round_config(cfg),
                cfg,
                &subnet,
                &inner.identity,
                leader_pk,
                inner.subnet_clients(&subnet),
            ),
            ProtocolConfig::ScheduledAdcnet(cfg) => {
                let peers: Vec<_> = sorted_roster
                    .iter()
                    .enumerate()
                    .map(|(i, pk)| (ServerId(i as u32), PublicKey::from_bytes(&pk.0)))
                    .collect();
                let mut server = ScheduledAdcnetServerSession::new(
                    scheduled_config(cfg),
                    ServerId(relay_index(&subnet, identity_pk).unwrap()),
                    inner.identity.to_adcnet_signing_key(),
                    ExchangePrivateKey::from_bytes(&inner.identity.exchange().scalar_bytes())
                        .expect("valid exchange scalar"),
                    &[],
                    &peers,
                    1,
                    leader_pk,
                );
                server.client_set_max = cfg.client_set_max as usize;
                server.good_clients = inner.subnet_clients(&subnet);
                Box::new(server) as Box<dyn Session>
            }
            _ => unreachable!(),
        };
        sessions.insert(SessionKey::Server, session);
    }
    if scheduled || !subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Watch,
            crate::runtime::watch_session_for(&subnet),
        );
    }
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            let mut agg_session =
                AdcnetAggregatorSession::new(group, a.groups.len() as u32, inner.identity.clone());
            agg_session.set_client_set_max(
                (subnet.protocol.client_set_max() as usize / a.groups.len().max(1)).max(1),
            );
            agg_session.set_good_clients(inner.subnet_clients(&subnet));
            sessions.insert(SessionKey::Aggregator, Box::new(agg_session));
        }
    }
    // Leader-side liveness monitor: sees every relay's share and the local output,
    // reconstructing the observer's wire view. One reporter per subnet.
    let mut fault_monitor: Option<Box<dyn Session>> = if leader_pk == identity_pk {
        let mut roster = subnet.relays.clone();
        roster.sort();
        Some(Box::new(AdcnetObserverSession::for_protocol(
            scheduled,
            roster,
            leader_pk,
            FAULT_THRESHOLD,
        )))
    } else {
        None
    };

    // A client's contribution goes directly to its aggregator group (aggregated
    // flow) or to every relay (direct flow; only the leader combines, but naming
    // the whole roster keeps no single relay on the delivery path). Shares and
    // the aggregators' signed group aggregates ride the shares topic, where the
    // leader already listens.
    let egress = |key: &SessionKey, bytes: &[u8]| match key {
        SessionKey::Server
            if if scheduled {
                matches!(
                    bincode::deserialize::<ScheduledAdcnetWire>(bytes),
                    Ok(ScheduledAdcnetWire::Partial(_) | ScheduledAdcnetWire::ClientSet(_))
                )
            } else {
                is_server_share(bytes)
            } =>
        {
            Dest::Topic(Topic::Shares(subnet.id))
        }
        SessionKey::Server => Dest::Topic(Topic::Broadcast(subnet.id)),
        SessionKey::Client if scheduled => Dest::Each(subnet.id, vec![leader_pk]),
        SessionKey::Client => match &client_agg {
            Some(aggregator) if is_client_message(bytes) => {
                Dest::Each(subnet.id, vec![*aggregator])
            }
            _ => Dest::Each(subnet.id, sorted_roster.clone()),
        },
        SessionKey::Aggregator => Dest::Topic(Topic::Shares(subnet.id)),
        SessionKey::Watch => Dest::Topic(Topic::Broadcast(subnet.id)),
    };

    // Round labels derive from the signed wall-clock epoch, not a local counter,
    // so every node agrees regardless of when it joined; `deadline` aligns to
    // absolute boundaries and a node that falls behind re-derives and skips ahead.
    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(1);
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
    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let spawn_round = round;
    debug!(target: SCHED, id = subnet.id, armed, round, dur_ms, "adcnet worker: start");
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
    let mut mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
    let mut mid_done = false;

    if let Some(m) = fault_monitor.as_mut() {
        m.begin_round(round, Instant::now());
    }
    crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
        client_session(round, &inner, &relay_xk, &subnet, &inner.identity)
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
    for (key, out) in outs.into_iter().chain(crate::runtime::flush_sessions(&mut sessions).await) {
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
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.checkpoint(round, 1, Instant::now()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs.into_iter().chain(crate::runtime::flush_sessions(&mut sessions).await) {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
                drain_inbound(&mut subscriptions, &mut sessions, &mut fault_monitor, &inner, &egress, identity_pk).await;
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults: Vec<Fault> = Vec::new();
                let mut outs: Vec<(SessionKey, Vec<u8>)> = Vec::new();
                for (key, s) in sessions.iter_mut() {
                    let outcome = s.end_round(round, Instant::now());
                    outs.extend(outcome.outbound.into_iter().map(|out| (*key, out)));
                    decoded_all.extend(outcome.decoded);
                    faults.extend(outcome.faults);
                }
                for (key, out) in outs.into_iter().chain(crate::runtime::flush_sessions(&mut sessions).await) {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
                if let Some(m) = fault_monitor.as_mut() {
                    faults.extend(m.end_round(round, Instant::now()).faults);
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
                crate::runtime::log_round_outcome(if scheduled { "scheduled-adcnet" } else { "adcnet" }, subnet.id, round, n_decoded, faults.len());
                if round >= spawn_round + crate::runtime::RECONFIG_FAULT_GRACE {
                    gossip_faults(&inner, subnet.id, identity_pk, &mut reported, faults.into_iter().map(|f| (round, f)).collect()).await;
                }

                if final_round.is_some_and(|f| round >= f) {
                    debug!(target: SCHED, id = subnet.id, round, "adcnet worker: graceful exit");
                    return;
                }
                let now_ms = crate::config::now_unix_ms();
                round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                mid_deadline = deadline - std::time::Duration::from_millis(dur_ms / 2);
                mid_done = false;
                if let Some(m) = fault_monitor.as_mut() {
                    m.begin_round(round, Instant::now());
                }
                crate::runtime::sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
                    client_session(round, &inner, &relay_xk, &subnet, &inner.identity)
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
                for (key, out) in outs.into_iter().chain(crate::runtime::flush_sessions(&mut sessions).await) {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            msg = recv_any(&mut subscriptions) => {
                handle_inbound(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, msg).await;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AdcnetWire {
    Client {
        contribution: Signed<ClientContribution>,
        key: Signed<KeyExchange>, // NIKE pubkey
    },
    Server(Signed<ServerShare>),
    /// Leader-announced canonical client set for `round`.
    ///
    /// Because in adcnet the leader alone decides the canonical
    /// set, a malicious leader can *censor* a client by omitting it from the
    /// set. This is detectable after the
    /// fact: a client holds a receipt and can later prove it was dropped from a
    /// round
    ClientSet {
        round: u32,
        clients: Vec<Signed<KeyExchange>>,
    },
    /// Leader-broadcast decoded result for `round`.
    Decoded {
        round: u32,
        payloads: Vec<Vec<u8>>,
    },
    /// One aggregator group's signed summed contributions + members' signed keys,
    GroupAggregate {
        round: u32,
        group: u32,
        blinded: Vec<u64>,
        clients: Vec<Signed<KeyExchange>>,
        signer: crate::identity::Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
}

fn group_aggregate_signing_bytes(
    round: u32,
    group: u32,
    blinded: &[u64],
    clients: &[Signed<KeyExchange>],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&round.to_le_bytes());
    m.extend_from_slice(&group.to_le_bytes());
    for v in blinded {
        m.extend_from_slice(&v.to_le_bytes());
    }
    m.extend_from_slice(&bincode::serialize(clients).expect("serialise client keys"));
    m
}

fn adcnet_client_group(pubkey_bytes: &[u8], group_count: u32) -> u32 {
    u32::from_be_bytes([
        pubkey_bytes[0],
        pubkey_bytes[1],
        pubkey_bytes[2],
        pubkey_bytes[3],
    ]) % group_count.max(1)
}

/// The client's P-256 exchange pubkey (SEC1 bytes), signed by the client's
/// signing key so relays can trust the signing↔exchange binding. Travels on
/// every [`AdcnetWire::Client`] and in each [`AdcnetWire::ClientSet`] entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchange {
    #[serde(with = "serde_bytes")]
    pub xpub: Vec<u8>,
}

/// One-line summary of an ADCNet wire message, for transport tracing.
#[cfg(feature = "wire-debug")]
pub(crate) fn describe(bytes: &[u8]) -> Option<String> {
    match bincode::deserialize::<AdcnetWire>(bytes).ok()? {
        AdcnetWire::Client { contribution, .. } => match contribution.recover() {
            Ok((c, s)) => Some(format!(
                "ADCNet Client signer={} round={}",
                short(s.as_bytes()),
                c.round
            )),
            Err(_) => Some("ADCNet Client <bad sig>".into()),
        },
        AdcnetWire::Server(signed) => match signed.recover() {
            Ok((s, _)) => Some(format!(
                "ADCNet Server sid={} round={}",
                s.server_id.0, s.round
            )),
            Err(_) => Some("ADCNet Server <bad sig>".into()),
        },
        AdcnetWire::ClientSet { round, clients } => Some(format!(
            "ADCNet ClientSet round={round} clients={}",
            clients.len()
        )),
        AdcnetWire::Decoded { round, payloads } => Some(format!(
            "ADCNet Decoded round={round} payloads={}",
            payloads.len()
        )),
        AdcnetWire::GroupAggregate {
            round,
            group,
            clients,
            ..
        } => Some(format!(
            "ADCNet GroupAggregate round={round} group={group} clients={}",
            clients.len()
        )),
    }
}

pub(crate) fn is_client_message(bytes: &[u8]) -> bool {
    matches!(
        bincode::deserialize::<AdcnetWire>(bytes),
        Ok(AdcnetWire::Client { .. })
    )
}

#[cfg(feature = "wire-debug")]
fn short(b: &[u8]) -> String {
    hex::encode(&b[..b.len().min(4)])
}

/// True if `bytes` is a relay decryption share — the runtime routes these to
/// the shares topic, keeping client contributions on ingress.
pub(crate) fn is_server_share(bytes: &[u8]) -> bool {
    matches!(
        bincode::deserialize::<AdcnetWire>(bytes),
        Ok(AdcnetWire::Server(_))
    )
}

/// What an ADCNet subnet message tells the committee's liveness observer.
enum AdcnetObserved {
    /// A relay `signer` published a share for `round`. The slot is derived from
    /// the signer's roster position, never the self-claimed wire `server_id`.
    Share {
        round: u64,
        signer: PublicKey,
    },
    /// The leader broadcast the decoded output for `round`.
    Output {
        round: u64,
    },
    /// The leader announced the canonical client set for `round`: `size`
    /// clients are in it, so the anonymity set that round is `size`.
    ClientSet {
        size: usize,
        round: u64,
    },
    Other,
}

fn observe_adcnet(bytes: &[u8]) -> AdcnetObserved {
    match bincode::deserialize::<AdcnetWire>(bytes) {
        Ok(AdcnetWire::Server(signed)) => match signed.recover() {
            Ok((s, signer)) => AdcnetObserved::Share {
                round: s.round as u64,
                signer: signer.clone(),
            },
            Err(_) => AdcnetObserved::Other,
        },
        Ok(AdcnetWire::Decoded { round, .. }) => AdcnetObserved::Output {
            round: round as u64,
        },
        Ok(AdcnetWire::ClientSet { clients, round }) => AdcnetObserved::ClientSet {
            size: clients.len(),
            round: round as u64,
        },
        _ => AdcnetObserved::Other,
    }
}

fn observe_scheduled_adcnet(bytes: &[u8], leader: Pubkey) -> AdcnetObserved {
    let wire_round = |r: i64| (r > 0).then(|| (r - 1) as u64);
    match bincode::deserialize::<ScheduledAdcnetWire>(bytes) {
        Ok(ScheduledAdcnetWire::Partial(signed)) => {
            if let Ok((partial, signer)) = signed.recover() {
                if let Some(round) = wire_round(partial.original_aggregate.round_number) {
                    return AdcnetObserved::Share {
                        round,
                        signer: signer.clone(),
                    };
                }
            }
        }
        Ok(ScheduledAdcnetWire::ClientSet(signed)) => {
            if let Ok((set, signer)) = signed.recover() {
                if signer.as_bytes() == leader.0 {
                    if let Some(round) = wire_round(set.round) {
                        return AdcnetObserved::ClientSet {
                            round,
                            size: set.clients.len(),
                        };
                    }
                }
            }
        }
        Ok(ScheduledAdcnetWire::Broadcast(signed)) => {
            if let Ok((result, signer)) = signed.recover() {
                if result.completed && signer.as_bytes() == leader.0 {
                    if let Some(round) = wire_round(result.broadcast.round_number) {
                        return AdcnetObserved::Output { round };
                    }
                }
            }
        }
        _ => {}
    }
    AdcnetObserved::Other
}

/// Liveness observer for an ADCNet subnet — run by the committee/dashboard
/// without participating. Recognises ADCNet share/output messages and feeds a
/// protocol-agnostic [`OutputFaultTracker`].
pub struct AdcnetObserverSession {
    scheduled: bool,
    tracker: crate::faults::OutputFaultTracker,
    /// Sorted roster; a share is credited to its signer's slot here.
    roster: Vec<PeerId>,
    /// Canonical client set size per round — the per-round anonymity set.
    anon_set_by_round: std::collections::BTreeMap<u64, usize>,
    /// Only this peer's `ClientSet`/`Decoded` are trusted (forgery guard).
    leader: PeerId,
    /// Own round clock, from `begin_round`, truncated to the ADCNet u32 wire
    /// round — every wire round is `anymone_round as u32`, so the window
    /// comparison must happen in that same wrapped space.
    cur_round: Option<u32>,
}

const ANON_SET_HISTORY: usize = 16;

impl AdcnetObserverSession {
    pub fn new(roster: Vec<PeerId>, leader: PeerId, fault_threshold: u64) -> Self {
        Self::for_protocol(false, roster, leader, fault_threshold)
    }

    pub fn for_protocol(
        scheduled: bool,
        roster: Vec<PeerId>,
        leader: PeerId,
        fault_threshold: u64,
    ) -> Self {
        AdcnetObserverSession {
            scheduled,
            tracker: crate::faults::OutputFaultTracker::new(roster.clone(), fault_threshold),
            roster,
            anon_set_by_round: std::collections::BTreeMap::new(),
            leader,
            cur_round: None,
        }
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

    pub fn anon_set_round(&self) -> Option<u64> {
        self.anon_set_by_round.keys().next_back().copied()
    }

    pub fn share_frontier(&self) -> Option<u64> {
        self.tracker.share_frontier()
    }

    pub fn output_frontier(&self) -> Option<u64> {
        self.tracker.output_frontier()
    }

    pub fn relays_shared_recent(&self, window: u64) -> Vec<usize> {
        self.tracker.relays_shared_recent(window)
    }

    /// Highest round observed in any wire message. `None` before any traffic.
    pub fn observed_round(&self) -> Option<u64> {
        [
            self.share_frontier(),
            self.output_frontier(),
            self.anon_set_round(),
        ]
        .into_iter()
        .flatten()
        .max()
    }
}

impl AdcnetObserverSession {
    // The window clock tracks the highest accepted wire round; the committee
    // additionally lifts it to the wall-clock subnet round via `begin_round`,
    // since traffic acceptance alone can't advance it past the slack.
    fn advance_cur_round(&mut self, round: u64) {
        let round = round as u32;
        self.cur_round = Some(self.cur_round.map_or(round, |cur| cur.max(round)));
    }
}

impl Session for AdcnetObserverSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        // A jump past the acceptance slack means the gap was unobservable —
        // judging it would fault a subnet that was merely out of sight.
        if self
            .cur_round
            .is_some_and(|c| round as u32 > c.saturating_add(FUTURE_ROUND_SLACK))
        {
            self.tracker.fast_forward(round);
        }
        self.advance_cur_round(round);
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let observed = if self.scheduled {
            observe_scheduled_adcnet(&payload, self.leader)
        } else {
            observe_adcnet(&payload)
        };
        // Observed rounds are u32 wire values widened to u64; compare wrapped.
        let future = |round: u64| {
            self.cur_round
                .is_some_and(|cur| round as u32 > cur.saturating_add(FUTURE_ROUND_SLACK))
        };
        match observed {
            AdcnetObserved::Share { round, signer } => {
                if future(round)
                    || self
                        .cur_round
                        .is_some_and(|cur| (round as u32).saturating_add(ROUND_WINDOW) < cur)
                {
                    debug!(
                        target: ADCNET,
                        round,
                        cur = ?self.cur_round,
                        "adcnet observer: share outside round window, no liveness credit"
                    );
                    return Vec::new();
                }
                self.advance_cur_round(round);
                // Credit the signer's own roster slot — a relay can't vouch for another.
                match self
                    .roster
                    .iter()
                    .position(|p| PublicKey::from_bytes(&p.0) == signer)
                {
                    Some(idx) => self.tracker.observe_share(round, idx),
                    None => debug!(
                        target: ADCNET,
                        round,
                        roster = self.roster.len(),
                        "adcnet observer: share from a non-roster signer, no liveness credit"
                    ),
                }
            }
            // `round` names which past round this is for, not "now" — a decode/set
            // announcement can legitimately land late, so only a future claim rejects.
            AdcnetObserved::Output { round } if from == self.leader => {
                if future(round) {
                    debug!(
                        target: ADCNET,
                        round,
                        cur = ?self.cur_round,
                        "adcnet observer: rejected too-future Decoded"
                    );
                    return Vec::new();
                }
                self.advance_cur_round(round);
                self.tracker.observe_output(round);
            }
            AdcnetObserved::ClientSet { size, round } if from == self.leader => {
                if future(round) {
                    debug!(target: ADCNET, round, size, cur = ?self.cur_round, "adcnet observer: rejected too-future ClientSet");
                    return Vec::new();
                }
                self.advance_cur_round(round);
                self.anon_set_by_round.insert(round, size);
                while self.anon_set_by_round.len() > ANON_SET_HISTORY {
                    let oldest = *self.anon_set_by_round.keys().next().unwrap();
                    self.anon_set_by_round.remove(&oldest);
                }
            }
            // Leader-only messages from a non-leader: a stale roster here means
            // the real leader's set and output are being ignored too.
            AdcnetObserved::Output { round } | AdcnetObserved::ClientSet { round, .. } => {
                debug!(
                    target: ADCNET,
                    round,
                    expected_leader = %self.leader,
                    "adcnet observer: leader-only message from a non-leader, ignored"
                );
            }
            AdcnetObserved::Other => {}
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome {
            outbound: Vec::new(),
            decoded: Vec::new(),
            faults: self.tracker.evaluate(),
        }
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn anon_set_and_output_only_from_leader() {
        let leader = Identity::generate();
        let other = Identity::generate();
        let leader_pk = leader.pubkey();
        let mut obs = AdcnetObserverSession::new(vec![leader_pk, other.pubkey()], leader_pk, 2);
        let signed = Signed::new(
            &leader.to_adcnet_signing_key(),
            KeyExchange {
                xpub: leader.exchange_pubkey().to_sec1_bytes(),
            },
        )
        .unwrap();
        let cs = bincode::serialize(&AdcnetWire::ClientSet {
            round: 1,
            clients: vec![signed],
        })
        .unwrap();
        obs.on_inbound(other.pubkey(), cs.clone());
        assert_eq!(
            obs.anonymity_set(),
            None,
            "non-leader ClientSet must be ignored"
        );
        obs.on_inbound(leader_pk, cs);
        assert_eq!(obs.anonymity_set(), Some(1));

        let dec = bincode::serialize(&AdcnetWire::Decoded {
            round: 5,
            payloads: vec![],
        })
        .unwrap();
        obs.on_inbound(other.pubkey(), dec.clone());
        assert_eq!(
            obs.output_frontier(),
            None,
            "forged Decoded must not advance output"
        );
        obs.on_inbound(leader_pk, dec);
        assert_eq!(obs.output_frontier(), Some(5));

        // server_id is derived from the signer, not the wire: `other` is roster
        // index 1, so a share it signs is always credited to slot 1 — even when it
        // stamps the leader's slot 0. A relay can't occupy or vouch for another slot.
        let stamp_r = |sid: u32, round: u32| {
            let sh = Signed::new(
                &other.to_adcnet_signing_key(),
                ServerShare {
                    server_id: ServerId(sid),
                    round,
                    share: vec![],
                },
            )
            .unwrap();
            bincode::serialize(&AdcnetWire::Server(sh)).unwrap()
        };
        let stamp = |sid: u32| stamp_r(sid, 3);
        obs.on_inbound(other.pubkey(), stamp(0));
        assert_eq!(
            obs.relays_shared_recent(8),
            vec![1],
            "credited to the signer's slot, not the stamped one"
        );

        // A far-future round must be dropped once the observer's clock advances.
        obs.begin_round(3, Instant::now());
        obs.on_inbound(other.pubkey(), stamp_r(0, u32::MAX));
        assert_eq!(
            obs.share_frontier(),
            Some(3),
            "far-future round must be dropped by the round-window clamp"
        );

        // The leader likewise keys the share by the signer's slot, ignoring the stamp.
        let one_round = OneRoundConfig {
            iblt: IbltMsgParamsOwned {
                estimated_messages: 8,
                max_payload_bytes: 256,
            },
        };
        let mut leader_srv = AdcnetServerSession::new(
            one_round,
            ServerId(0),
            leader.to_adcnet_signing_key(),
            leader.exchange().clone(),
            2,
            vec![leader_pk, other.pubkey()],
            0,
            usize::MAX,
            true,
            leader_pk,
            None,
        );
        leader_srv.begin_round(3, Instant::now());
        leader_srv.on_inbound(other.pubkey(), stamp(0));
        let slots: Vec<u32> = leader_srv
            .shares_by_round
            .get(&3)
            .map(|m| m.keys().map(|s| s.0).collect())
            .unwrap_or_default();
        assert_eq!(
            slots,
            vec![1],
            "share keyed by the signer's slot, not the stamped id"
        );

        leader_srv.on_inbound(other.pubkey(), stamp_r(0, u32::MAX));
        assert!(
            !leader_srv.shares_by_round.contains_key(&u32::MAX),
            "far-future round must be dropped by the round-window clamp"
        );
    }

    #[test]
    fn wire_estimate_covers_real_messages() {
        let (msg_size, est_msgs, cset) = (256usize, 32u32, 40u32);
        let est = max_wire_estimate(msg_size, est_msgs, cset, 3);

        let iblt = IbltMsgParamsOwned {
            estimated_messages: est_msgs,
            max_payload_bytes: msg_size,
        };
        let n = iblt.as_params().encoded_len();
        let id = Identity::generate();
        let share = Signed::new(
            &id.to_adcnet_signing_key(),
            ServerShare {
                server_id: ServerId(0),
                round: 1,
                share: vec![0u64; n],
            },
        )
        .unwrap();
        let share_wire = bincode::serialize(&AdcnetWire::Server(share)).unwrap();
        assert!(
            est >= share_wire.len(),
            "estimate {est} < real share {}",
            share_wire.len()
        );

        let key = Signed::new(
            &id.to_adcnet_signing_key(),
            KeyExchange {
                xpub: id.exchange_pubkey().to_sec1_bytes(),
            },
        )
        .unwrap();
        let cs = bincode::serialize(&AdcnetWire::ClientSet {
            round: 1,
            clients: vec![key; cset as usize],
        })
        .unwrap();
        assert!(
            est >= cs.len(),
            "estimate {est} < real client set {}",
            cs.len()
        );
        assert!(
            est <= 4 * share_wire.len().max(cs.len()),
            "estimate {est} wildly loose"
        );
    }
}

pub struct AdcnetClientSession {
    config: OneRoundConfig,
    signing_key: PrivateKey,
    shared_secrets: HashMap<ServerId, SharedKey>,
    /// This client's exchange pubkey (SEC1), attached to every contribution as a
    /// signed `KeyExchange` so relays derive the shared secret without an announcement.
    client_xpub: Vec<u8>,
    signed_key: Option<Signed<KeyExchange>>,
    pending: Option<Vec<u8>>,
    rng: ChaCha20Rng,
    /// Idle-round cover probability, drawn against the private `rng`.
    cover_rate: f32,
}

impl AdcnetClientSession {
    pub fn new(
        config: OneRoundConfig,
        signing_key: PrivateKey,
        shared_secrets: HashMap<ServerId, SharedKey>,
        client_xpub: ExchangePublicKey,
        rng_seed: [u8; 32],
    ) -> Self {
        AdcnetClientSession {
            config,
            signing_key,
            shared_secrets,
            client_xpub: client_xpub.to_sec1_bytes(),
            signed_key: None,
            pending: None,
            rng: ChaCha20Rng::from_seed(rng_seed),
            cover_rate: 1.0,
        }
    }

    pub fn stage_message(&mut self, payload: Vec<u8>) {
        self.pending = Some(payload);
    }
}

impl AdcnetClientSession {
    pub fn contribute(&mut self, round: Round, payload: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let round = u32::try_from(round).map_err(|_| "ADCNet round exceeds u32")?;
        if payload.is_some_and(|p| p.len() > self.config.iblt.max_payload_bytes) {
            return Err("payload exceeds channel capacity".into());
        }
        if self.signed_key.is_none() {
            self.signed_key = Some(Signed::new(
                &self.signing_key,
                KeyExchange { xpub: self.client_xpub.clone() },
            ).map_err(|e| e.to_string())?);
        }
        let contribution = client_contribute(
            &self.config, round, &self.signing_key, &self.shared_secrets, payload, &mut self.rng,
        ).map_err(|e| e.to_string())?;
        bincode::serialize(&AdcnetWire::Client {
            contribution,
            key: self.signed_key.clone().expect("signed key present"),
        }).map_err(|e| e.to_string())
    }
}

impl Session for AdcnetClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        let payload = self.pending.take();
        if payload.is_none() && self.rng.gen::<f32>() >= self.cover_rate {
            return Vec::new();
        }
        match self.contribute(round, payload.as_deref()) {
            Ok(message) => vec![message],
            Err(error) => {
                debug!(target: ADCNET, round, %error, "adcnet client: contribute failed");
                Vec::new()
            }
        }
    }

    fn on_inbound(&mut self, _from: PeerId, _payload: Vec<u8>) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        self.stage_message(payload);
    }

    fn set_cover_rate(&mut self, rate: f32) {
        self.cover_rate = rate;
    }
}

/// Aggregator-side session: sums its group's client contributions and forwards
/// one signed `GroupAggregate` (with the members' signed keys) to the leader.
pub struct AdcnetAggregatorSession {
    group: u32,
    group_count: u32,
    identity: Identity,
    rounds: std::collections::BTreeMap<u32, HashMap<PublicKey, (Vec<u64>, Signed<KeyExchange>)>>,
    emitted: std::collections::HashSet<u32>,
    cur_round: u32,
    /// Per-group ceiling: the groups' union forms the canonical set, which
    /// servers reject above the subnet's `client_set_max`.
    client_set_max: usize,
    /// Screened here too: the leader sees an aggregate, not the clients behind
    /// it, so a client the leader would refuse must not reach the group sum.
    good_clients: GoodClients,
}

impl AdcnetAggregatorSession {
    pub fn new(group: u32, group_count: u32, identity: Identity) -> Self {
        AdcnetAggregatorSession {
            group,
            group_count,
            identity,
            rounds: std::collections::BTreeMap::new(),
            emitted: std::collections::HashSet::new(),
            cur_round: 0,
            client_set_max: usize::MAX,
            good_clients: GoodClients::all(),
        }
    }

    /// See [`AdcnetServerSession`]'s `client_set_max`; call with the subnet's
    /// `client_set_max / group_count`.
    pub(crate) fn set_client_set_max(&mut self, max: usize) {
        self.client_set_max = max;
    }

    pub(crate) fn set_good_clients(&mut self, good_clients: GoodClients) {
        self.good_clients = good_clients;
    }
}

impl Session for AdcnetAggregatorSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = round as u32;
        let keep = self.cur_round.saturating_sub(ROUND_WINDOW);
        self.rounds.retain(|r, _| *r >= keep);
        self.emitted.retain(|r| *r >= keep);
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(AdcnetWire::Client { contribution, key }) =
            bincode::deserialize::<AdcnetWire>(&payload)
        {
            let (Ok((c, signer)), Ok((_, key_signer))) = (contribution.recover(), key.recover())
            else {
                debug!(
                    target: ADCNET,
                    group = self.group,
                    "adcnet aggregator: contribution or key signature did not recover, dropped"
                );
                return Vec::new();
            };
            if adcnet_client_group(signer.as_bytes(), self.group_count) != self.group {
                trace!(
                    target: ADCNET,
                    c_round = c.round,
                    group = self.group,
                    "adcnet aggregator: contribution for another group, ignored"
                );
                return Vec::new();
            }
            if key_signer != signer {
                debug!(
                    target: ADCNET,
                    c_round = c.round,
                    group = self.group,
                    "adcnet aggregator: key and contribution signers differ, dropped"
                );
                return Vec::new();
            }
            let signer_pk = <[u8; 32]>::try_from(signer.as_bytes())
                .map(Pubkey::from_bytes)
                .ok();
            if !signer_pk.is_some_and(|pk| self.good_clients.allows(&pk)) {
                debug!(
                    target: ADCNET,
                    c_round = c.round,
                    group = self.group,
                    "adcnet aggregator: signer not an accepted client, dropped"
                );
                return Vec::new();
            }
            if c.round.saturating_add(ROUND_WINDOW) < self.cur_round
                || c.round > self.cur_round.saturating_add(FUTURE_ROUND_SLACK)
            {
                debug!(
                    target: ADCNET,
                    c_round = c.round,
                    cur = self.cur_round,
                    group = self.group,
                    "adcnet aggregator: contribution outside round window, dropped"
                );
                return Vec::new();
            }
            let bucket = self.rounds.entry(c.round).or_default();
            if !bucket.contains_key(&signer) && bucket.len() >= self.client_set_max {
                debug!(
                    target: ADCNET,
                    c_round = c.round,
                    group = self.group,
                    max = self.client_set_max,
                    "adcnet aggregator: dropped client contribution, group at capacity"
                );
                return Vec::new();
            }
            bucket.insert(signer.clone(), (c.blinded.clone(), key.clone()));
        }
        Vec::new()
    }

    /// k=1: emit the group's batch mid-round, so the leader announces the set
    /// and combines within the round rather than a round late.
    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k != 1 {
            return Vec::new();
        }
        let round = round as u32;
        let mut outbound = Vec::new();
        if !self.emitted.contains(&round) {
            if let Some(entries) = self.rounds.get(&round).filter(|e| !e.is_empty()) {
                let mut members: Vec<(&PublicKey, &(Vec<u64>, Signed<KeyExchange>))> =
                    entries.iter().collect();
                members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                let blinded_slices: Vec<&[u64]> =
                    members.iter().map(|(_, v)| v.0.as_slice()).collect();
                let blinded = adcnet::field_round::aggregate_clients(&blinded_slices);
                let clients: Vec<Signed<KeyExchange>> =
                    members.iter().map(|(_, v)| v.1.clone()).collect();
                let signature = self.identity.sign(&group_aggregate_signing_bytes(
                    round, self.group, &blinded, &clients,
                ));
                let wire = AdcnetWire::GroupAggregate {
                    round,
                    group: self.group,
                    blinded,
                    clients,
                    signer: self.identity.pubkey(),
                    signature,
                };
                trace!(
                    target: ADCNET,
                    round,
                    group = self.group,
                    members = members.len(),
                    "adcnet aggregator: emit group aggregate"
                );
                outbound.push(bincode::serialize(&wire).expect("serialise group aggregate"));
                self.emitted.insert(round);
            }
        }
        outbound
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }
}

pub struct AdcnetServerSession {
    config: OneRoundConfig,
    server_id: ServerId,
    signing_key: PrivateKey,
    /// This relay's exchange identity; shared secrets are derived on demand from
    /// each client's carried xpub, so no client pre-registration is needed.
    exchange: ExchangeIdentity,
    /// `ECDH(relay_priv, client_xpub)` keyed by client signing pubkey. Populated
    /// from `Client` messages (leader) or the leader's `ClientSet` (non-leaders).
    shared_secrets: HashMap<PublicKey, SharedKey>,
    /// Leader only: signed `KeyExchange` per seen client, to put in `ClientSet`.
    client_keys: HashMap<PublicKey, Signed<KeyExchange>>,
    expected_servers: usize,
    /// Sorted relay roster; a share's `server_id` must equal its signer's index here.
    roster: Vec<Pubkey>,
    /// Anonymity floor: the leader won't decode a canonical set smaller than this.
    min_clients: usize,
    /// Upper bound on the accepted per-round client set.
    client_set_max: usize,
    /// Which client keys this relay accepts contributions from. ADCNet client
    /// keys are the same ed25519 bytes as a [`Pubkey`], just adcnet-wrapped.
    good_clients: GoodClients,
    /// This server leads canonical-set announcement (sorted-first relay).
    is_leader: bool,
    /// The leader's anymone pubkey — `ClientSet` announcements are only
    /// accepted when they arrive from this peer.
    leader_pk: PeerId,

    /// Leader only: client ciphertexts by round (non-leaders work off the
    /// canonical set alone — the bandwidth note on `AdcnetWire`).
    clients_by_round: HashMap<u32, Vec<(ClientContribution, PublicKey)>>,
    /// Leader-announced canonical client set per round.
    client_set_by_round: HashMap<u32, Vec<PublicKey>>,
    /// Leader only: server shares to combine.
    shares_by_round: HashMap<u32, HashMap<ServerId, ServerShare>>,
    announced_rounds: std::collections::HashSet<u32>,
    shared_rounds: std::collections::HashSet<u32>,
    combined_rounds: std::collections::HashSet<u32>,
    /// Payloads from the leader's `Decoded` broadcast, not yet surfaced for routing.
    pending_decoded: Vec<Vec<u8>>,
    routed_rounds: std::collections::HashSet<u32>,
    /// Highest round started — drives late-message rejection and pruning.
    cur_round: u32,
    misbehavior: Option<Misbehavior>,
    /// Leader-only: when set, the client set + combine come from signed group
    /// aggregates rather than individual contributions.
    aggregation: Option<LeaderAggregation>,
    /// Leader aggregated mode: round → group → (summed blinded, member signers).
    agg_by_round: HashMap<u32, HashMap<u32, (Vec<u64>, Vec<PublicKey>)>>,
}

/// Rounds of per-round state to keep behind the current round — enough to cover
/// the share→combine pipeline's one-or-two-round lag; older state is pruned.
const ROUND_WINDOW: u32 = 3;

/// Upper bound on how far ahead a wire `round` may sit, wider than
/// [`ROUND_WINDOW`] since legitimate multi-hop delivery can lag a few rounds.
const FUTURE_ROUND_SLACK: u32 = 64;

impl AdcnetServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: OneRoundConfig,
        server_id: ServerId,
        signing_key: PrivateKey,
        exchange: ExchangeIdentity,
        expected_servers: usize,
        roster: Vec<Pubkey>,
        min_clients: usize,
        client_set_max: usize,
        is_leader: bool,
        leader_pk: PeerId,
        aggregation: Option<LeaderAggregation>,
    ) -> Self {
        AdcnetServerSession {
            config,
            server_id,
            signing_key,
            exchange,
            shared_secrets: HashMap::new(),
            client_keys: HashMap::new(),
            expected_servers,
            roster,
            min_clients,
            client_set_max,
            good_clients: GoodClients::all(),
            is_leader,
            leader_pk,
            clients_by_round: HashMap::new(),
            client_set_by_round: HashMap::new(),
            shares_by_round: HashMap::new(),
            announced_rounds: std::collections::HashSet::new(),
            shared_rounds: std::collections::HashSet::new(),
            combined_rounds: std::collections::HashSet::new(),
            pending_decoded: Vec::new(),
            routed_rounds: std::collections::HashSet::new(),
            cur_round: 0,
            misbehavior: None,
            aggregation,
            agg_by_round: HashMap::new(),
        }
    }

    pub fn set_good_clients(&mut self, good_clients: GoodClients) {
        self.good_clients = good_clients;
    }

    /// The `ServerId` bound to `signer` by the sorted roster, if it's a relay.
    fn server_id_of(&self, signer: &PublicKey) -> Option<u32> {
        self.roster
            .iter()
            .position(|p| PublicKey::from_bytes(&p.0) == *signer)
            .map(|i| i as u32)
    }

    fn prune_stale(&mut self) {
        let keep_from = self.cur_round.saturating_sub(ROUND_WINDOW);
        self.clients_by_round.retain(|r, _| *r >= keep_from);
        self.client_set_by_round.retain(|r, _| *r >= keep_from);
        self.shares_by_round.retain(|r, _| *r >= keep_from);
        self.announced_rounds.retain(|r| *r >= keep_from);
        self.shared_rounds.retain(|r| *r >= keep_from);
        self.combined_rounds.retain(|r| *r >= keep_from);
        self.routed_rounds.retain(|r| *r >= keep_from);
        self.agg_by_round.retain(|r, _| *r >= keep_from);
    }

    fn cache_client_key(
        &mut self,
        signer: &PublicKey,
        ke: &KeyExchange,
        signed: Signed<KeyExchange>,
    ) {
        if let Ok(xp) = ExchangePublicKey::from_sec1_bytes(&ke.xpub) {
            if !self.shared_secrets.contains_key(signer) {
                let secret = self.exchange.ecdh(&xp);
                self.shared_secrets.insert(signer.clone(), secret);
            }
            self.client_keys.entry(signer.clone()).or_insert(signed);
        }
    }

    fn leader_set_for_round(&self, round: u32) -> Vec<Signed<KeyExchange>> {
        let mut signers: Vec<PublicKey> = Vec::new();
        if let Some(items) = self.clients_by_round.get(&round) {
            for (_, signer) in items {
                if self.client_keys.contains_key(signer) && !signers.contains(signer) {
                    signers.push(signer.clone());
                }
            }
        }
        signers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        signers
            .into_iter()
            .filter_map(|s| self.client_keys.get(&s).cloned())
            .collect()
    }

    /// Aggregated client set for `round`: union of the members of every group
    /// that has reported (the leader decides the canonical set, as in the direct
    /// flow — empty/late groups simply aren't in this round).
    fn leader_agg_set_for_round(&self, round: u32) -> Option<Vec<Signed<KeyExchange>>> {
        let groups = self.agg_by_round.get(&round)?;
        let mut signers: Vec<PublicKey> = Vec::new();
        for (_, members) in groups.values() {
            for s in members {
                if self.client_keys.contains_key(s) && !signers.contains(s) {
                    signers.push(s.clone());
                }
            }
        }
        signers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Some(
            signers
                .into_iter()
                .filter_map(|s| self.client_keys.get(&s).cloned())
                .collect(),
        )
    }

    fn leader_combine(&mut self, target: u32) -> Option<Vec<Vec<u8>>> {
        if self.combined_rounds.contains(&target) {
            return None;
        }
        let set = self.client_set_by_round.get(&target)?;
        if set.len() < self.min_clients {
            debug!(
                target: ADCNET,
                round = target,
                set = set.len(),
                min_clients = self.min_clients,
                "adcnet leader: client set below the anonymity floor, refusing to combine"
            );
            return None;
        }
        let Some(shares) = self.shares_by_round.get(&target) else {
            debug!(
                target: ADCNET,
                round = target,
                set = set.len(),
                "adcnet leader: no shares held for an announced round"
            );
            return None;
        };
        let mut got_ids: Vec<u32> = shares.keys().map(|s| s.0).collect();
        got_ids.sort();
        trace!(
            target: ADCNET,
            round = target,
            shares = shares.len(),
            expected = self.expected_servers,
            set = set.len(),
            ?got_ids,
            "adcnet leader: combine check"
        );
        if shares.len() < self.expected_servers {
            return None;
        }
        // Aggregated: each group's summed blinded is one ClientContribution; the
        // leader re-sums them (combine_round's aggregate_clients is associative).
        let clients: Vec<ClientContribution> = if self.aggregation.is_some() {
            let Some(groups) = self.agg_by_round.get(&target) else {
                debug!(
                    target: ADCNET,
                    round = target,
                    "adcnet leader: no group aggregates held for an announced round"
                );
                return None;
            };
            groups
                .values()
                .map(|(blinded, _)| ClientContribution {
                    round: target,
                    blinded: blinded.clone(),
                })
                .collect()
        } else {
            let Some(items) = self.clients_by_round.get(&target) else {
                debug!(
                    target: ADCNET,
                    round = target,
                    set = set.len(),
                    "adcnet leader: no client ciphertexts held for an announced round"
                );
                return None;
            };
            let clients: Vec<ClientContribution> = set
                .iter()
                .filter_map(|pk| items.iter().find(|(_, s)| s == pk).map(|(c, _)| c.clone()))
                .collect();
            if clients.len() != set.len() {
                debug!(
                    target: ADCNET,
                    round = target,
                    have = clients.len(),
                    set = set.len(),
                    "adcnet leader: missing ciphertexts for announced set members"
                );
                return None;
            }
            clients
        };
        let share_vec: Vec<ServerShare> = shares.values().cloned().collect();
        match combine_round(
            &self.config,
            target,
            &clients,
            &share_vec,
            self.expected_servers,
        ) {
            Ok(payloads) => {
                trace!(target: ADCNET, round = target, n = payloads.len(), "adcnet leader: combined");
                self.combined_rounds.insert(target);
                self.clients_by_round.remove(&target);
                self.agg_by_round.remove(&target);
                self.shares_by_round.remove(&target);
                Some(payloads)
            }
            // The round's payloads are lost: shares are consumed and clients
            // sent them once.
            Err(e) => {
                warn!(
                    target: ADCNET,
                    round = target,
                    set = set.len(),
                    shares = share_vec.len(),
                    error = ?e,
                    "adcnet leader: combine failed; round produced no output"
                );
                None
            }
        }
    }
}

impl Session for AdcnetServerSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        self.cur_round = round as u32;
        self.prune_stale();
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let msg = match bincode::deserialize::<AdcnetWire>(&payload) {
            Ok(m) => m,
            Err(e) => {
                debug!(
                    target: ADCNET,
                    len = payload.len(),
                    error = %e,
                    "adcnet server: undecodable wire message"
                );
                return Vec::new();
            }
        };
        match msg {
            AdcnetWire::Client { contribution, key } => {
                // Non-leaders never read client data (they share off the ClientSet).
                if self.is_leader {
                    let (Ok((c, signer)), Ok((ke, key_signer))) =
                        (contribution.recover(), key.recover())
                    else {
                        debug!(
                            target: ADCNET,
                            "adcnet leader: contribution or key signature did not recover, dropped"
                        );
                        return Vec::new();
                    };
                    // Reject unless key and contribution share a signer, else the
                    // signing↔xpub binding can't be trusted.
                    if key_signer != signer {
                        debug!(
                            target: ADCNET,
                            c_round = c.round,
                            "adcnet leader: key and contribution signers differ, dropped"
                        );
                        return Vec::new();
                    }
                    // Late: the set for `c.round` is already finalized.
                    if c.round < self.cur_round
                        || c.round > self.cur_round.saturating_add(FUTURE_ROUND_SLACK)
                    {
                        debug!(
                            target: ADCNET,
                            signer = %hex::encode(&signer.as_bytes()[..4]),
                            c_round = c.round,
                            cur = self.cur_round,
                            now_ms = crate::config::now_unix_ms(),
                            "adcnet leader: dropped out-of-window client contribution"
                        );
                        return Vec::new();
                    }
                    let (c, signer) = (c.clone(), signer.clone());
                    let signer_pk = <[u8; 32]>::try_from(signer.as_bytes())
                        .map(Pubkey::from_bytes)
                        .ok();
                    if !signer_pk.is_some_and(|pk| self.good_clients.allows(&pk)) {
                        debug!(
                            target: ADCNET,
                            signer = %hex::encode(&signer.as_bytes()[..4]),
                            c_round = c.round,
                            "adcnet leader: signer not an accepted client, dropped"
                        );
                        return Vec::new();
                    }
                    let bucket = self.clients_by_round.entry(c.round).or_default();
                    // One contribution per signer per round: a replayed duplicate
                    // would double-sum into the combine and corrupt the round.
                    if bucket.iter().any(|(_, s)| *s == signer) {
                        trace!(
                            target: ADCNET,
                            signer = %hex::encode(&signer.as_bytes()[..4]),
                            c_round = c.round,
                            "adcnet leader: duplicate client contribution ignored"
                        );
                        return Vec::new();
                    }
                    if bucket.len() >= self.client_set_max {
                        debug!(
                            target: ADCNET,
                            signer = %hex::encode(&signer.as_bytes()[..4]),
                            c_round = c.round,
                            max = self.client_set_max,
                            "adcnet leader: dropped client contribution, round at capacity"
                        );
                        return Vec::new();
                    }
                    self.cache_client_key(&signer, ke, key.clone());
                    trace!(
                        target: ADCNET,
                        signer = %hex::encode(&signer.as_bytes()[..4]),
                        c_round = c.round,
                        cur = self.cur_round,
                        now_ms = crate::config::now_unix_ms(),
                        "adcnet leader: accepted client contribution"
                    );
                    self.clients_by_round
                        .entry(c.round)
                        .or_default()
                        .push((c, signer));
                }
            }
            AdcnetWire::Server(signed) => {
                if self.is_leader {
                    // Every rejection here costs the round one share towards the
                    // combine threshold.
                    let Ok((s, signer)) = signed.recover() else {
                        debug!(target: ADCNET, "adcnet leader: share signature did not recover, dropped");
                        return Vec::new();
                    };
                    {
                        if s.round.saturating_add(ROUND_WINDOW) < self.cur_round
                            || s.round > self.cur_round.saturating_add(FUTURE_ROUND_SLACK)
                        {
                            debug!(
                                target: ADCNET,
                                s_round = s.round,
                                cur = self.cur_round,
                                "adcnet leader: share outside round window, dropped"
                            );
                            return Vec::new();
                        }
                        // The slot is the signer's roster position, not the self-claimed
                        // wire id: a relay can't occupy another's slot or forge its count.
                        let Some(sid) = self.server_id_of(signer) else {
                            debug!(
                                target: ADCNET,
                                s_round = s.round,
                                roster = self.roster.len(),
                                "adcnet leader: share from a non-roster signer, dropped"
                            );
                            return Vec::new();
                        };
                        let mut share = s.clone();
                        share.server_id = ServerId(sid);
                        self.shares_by_round
                            .entry(share.round)
                            .or_default()
                            .insert(ServerId(sid), share);
                    }
                }
            }
            AdcnetWire::ClientSet { round, clients } => {
                if round.saturating_add(ROUND_WINDOW) < self.cur_round
                    || round > self.cur_round.saturating_add(FUTURE_ROUND_SLACK)
                {
                    debug!(
                        target: ADCNET,
                        round,
                        cur = self.cur_round,
                        "adcnet: ClientSet outside round window, ignored"
                    );
                    return Vec::new();
                }
                if from != self.leader_pk {
                    debug!(
                        target: ADCNET,
                        round,
                        n = clients.len(),
                        "adcnet: ClientSet from a non-leader, ignored"
                    );
                } else {
                    if clients.len() > self.client_set_max {
                        debug!(
                            target: ADCNET,
                            round,
                            n = clients.len(),
                            max = self.client_set_max,
                            "adcnet: oversized ClientSet"
                        );
                        return Vec::new();
                    }
                    // Derive a shared secret with each member from its signed key
                    // (a non-leader has never seen these clients otherwise).
                    let mut signers = Vec::with_capacity(clients.len());
                    for signed in &clients {
                        if let Ok((ke, signer)) = signed.recover() {
                            let signer = signer.clone();
                            self.cache_client_key(&signer, ke, signed.clone());
                            signers.push(signer);
                        }
                    }
                    // A member we can't recover leaves us short a shared secret, so
                    // `end_round` skips sharing over this round entirely.
                    if signers.len() != clients.len() {
                        debug!(
                            target: ADCNET,
                            round,
                            recovered = signers.len(),
                            announced = clients.len(),
                            "adcnet: unrecoverable member keys in the announced ClientSet"
                        );
                    }
                    self.client_set_by_round.entry(round).or_insert(signers);
                }
            }
            AdcnetWire::Decoded { round, payloads } => {
                // `round` is a past round's label, not "now" — combine legitimately
                // lands late, so only a future claim (mod boundary skew) is rejected.
                let in_window = round <= self.cur_round.saturating_add(ROUND_WINDOW);
                if from != self.leader_pk {
                    debug!(
                        target: ADCNET,
                        round,
                        "adcnet: Decoded from a non-leader, ignored"
                    );
                } else if !in_window {
                    debug!(
                        target: ADCNET,
                        round,
                        cur = self.cur_round,
                        n = payloads.len(),
                        "adcnet: Decoded claims a future round, ignored"
                    );
                } else if self.routed_rounds.insert(round) {
                    self.pending_decoded.extend(payloads);
                }
            }
            AdcnetWire::GroupAggregate {
                round,
                group,
                blinded,
                clients,
                signer,
                signature,
            } => {
                let Some(agg) = self.aggregation.as_ref() else {
                    debug!(
                        target: ADCNET,
                        round,
                        group,
                        "adcnet: group aggregate on a non-aggregated subnet, dropped"
                    );
                    return Vec::new();
                };
                let Some(roster) = agg.roster.get(&group) else {
                    debug!(
                        target: ADCNET,
                        round,
                        group,
                        groups = agg.roster.len(),
                        "adcnet: group aggregate for an unknown group, dropped"
                    );
                    return Vec::new();
                };
                trace!(
                    target: ADCNET,
                    round,
                    group,
                    cur = self.cur_round,
                    "adcnet leader: group aggregate received"
                );
                // An oversized group pushes the canonical union past what
                // servers accept, making the whole round undecodable.
                let group_cap = (self.client_set_max / agg.roster.len().max(1)).max(1);
                if *roster != signer
                    || clients.len() > group_cap
                    || !signer.verify(
                        &group_aggregate_signing_bytes(round, group, &blinded, &clients),
                        &signature,
                    )
                    || round.saturating_add(ROUND_WINDOW) < self.cur_round
                    || round > self.cur_round.saturating_add(FUTURE_ROUND_SLACK)
                {
                    debug!(
                        target: ADCNET,
                        round,
                        group,
                        n = clients.len(),
                        group_cap,
                        cur = self.cur_round,
                        in_roster = *roster == signer,
                        "adcnet leader: rejected group aggregate"
                    );
                    return Vec::new();
                }
                let mut signers = Vec::with_capacity(clients.len());
                for signed in &clients {
                    if let Ok((ke, s)) = signed.recover() {
                        let s = s.clone();
                        self.cache_client_key(&s, ke, signed.clone());
                        signers.push(s);
                    }
                }
                if signers.len() != clients.len() {
                    debug!(
                        target: ADCNET,
                        round,
                        group,
                        recovered = signers.len(),
                        announced = clients.len(),
                        "adcnet leader: unrecoverable member keys in a group aggregate"
                    );
                }
                self.agg_by_round
                    .entry(round)
                    .or_default()
                    .entry(group)
                    .or_insert((blinded, signers));
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, round: Round, _now: Instant) -> RoundOutcome {
        // Withhold: emit nothing this round (no client-set, share, or combine),
        // so the leader sees us missing and output stalls. Still surface anything
        // already decoded from the leader's broadcasts.
        if self.misbehavior == Some(Misbehavior::Withhold) {
            let decoded = std::mem::take(&mut self.pending_decoded);
            return RoundOutcome {
                outbound: Vec::new(),
                decoded,
                faults: Vec::new(),
            };
        }
        let cur = round as u32;
        let mut outbound = Vec::new();

        // Phase A (leader, aggregated): announce a round's set once every group
        // aggregate has arrived (one round after the clients contributed).
        if self.is_leader && self.aggregation.is_some() {
            let ready: Vec<u32> = self
                .agg_by_round
                .keys()
                .copied()
                .filter(|r| !self.announced_rounds.contains(r))
                .collect();
            for r in ready {
                let Some(keys) = self.leader_agg_set_for_round(r) else {
                    continue;
                };
                if keys.is_empty() {
                    debug!(
                        target: ADCNET,
                        round = r,
                        "adcnet leader: group aggregates held but no announceable members"
                    );
                    continue;
                }
                trace!(
                    target: ADCNET,
                    round = r,
                    set = keys.len(),
                    "adcnet leader: announce aggregated client set"
                );
                let signers: Vec<PublicKey> = keys
                    .iter()
                    .filter_map(|k| k.recover().ok().map(|(_, s)| s.clone()))
                    .collect();
                self.client_set_by_round.entry(r).or_insert(signers);
                outbound.push(
                    bincode::serialize(&AdcnetWire::ClientSet {
                        round: r,
                        clients: keys,
                    })
                    .expect("serialise client set"),
                );
                self.announced_rounds.insert(r);
            }
        }

        // Phase A (leader only, direct): announce the canonical client set for `cur`.
        if self.is_leader && self.aggregation.is_none() && !self.announced_rounds.contains(&cur) {
            let keys = self.leader_set_for_round(cur);
            if tracing::enabled!(target: ADCNET, tracing::Level::TRACE) {
                // Contribution spread across round buckets: clients landing in
                // many rounds means each canonical set is a fraction of the population.
                let mut buckets: Vec<(u32, usize)> = self
                    .clients_by_round
                    .iter()
                    .map(|(r, v)| (*r, v.len()))
                    .collect();
                buckets.sort_unstable();
                trace!(
                    target: ADCNET,
                    round = cur,
                    contributions_this_round =
                        self.clients_by_round.get(&cur).map_or(0, |v| v.len()),
                    announced_set = keys.len(),
                    cached_keys = self.client_keys.len(),
                    ?buckets,
                    "adcnet leader: canonical set for round"
                );
            }
            if !keys.is_empty() {
                let signers: Vec<PublicKey> = keys
                    .iter()
                    .filter_map(|k| k.recover().ok().map(|(_, s)| s.clone()))
                    .collect();
                self.client_set_by_round.entry(cur).or_insert(signers);
                outbound.push(
                    bincode::serialize(&AdcnetWire::ClientSet {
                        round: cur,
                        clients: keys,
                    })
                    .expect("serialise client set"),
                );
                self.announced_rounds.insert(cur);
            }
        }

        // Phase B (all relays): share over every known canonical set not yet
        // contributed to — a non-leader needs only the set, never the ciphertexts.
        let pending_share_rounds: Vec<u32> = self
            .client_set_by_round
            .keys()
            .copied()
            .filter(|r| !self.shared_rounds.contains(r))
            .collect();
        for t in pending_share_rounds {
            let set = self
                .client_set_by_round
                .get(&t)
                .cloned()
                .unwrap_or_default();
            let mut secrets = HashMap::new();
            for pk in &set {
                if let Some(s) = self.shared_secrets.get(pk) {
                    secrets.insert(pk.clone(), s.clone());
                }
            }
            // Without a secret per canonical member the share would be over a
            // different set, so we stay silent for this round — and the leader
            // never reaches its threshold.
            if secrets.len() != set.len() || secrets.is_empty() {
                debug!(
                    target: ADCNET,
                    round = t,
                    secrets = secrets.len(),
                    set = set.len(),
                    "adcnet: missing shared secrets for the canonical set; no share emitted"
                );
                continue;
            }
            // CorruptShare: flip a byte of one shared secret so the (validly
            // signed) share is wrong — the leader can't combine it but also
            // can't single us out, hence an unattributable fault.
            if self.misbehavior == Some(Misbehavior::CorruptShare) {
                if let Some(s) = secrets.values_mut().next() {
                    if let Some(b) = s.0.first_mut() {
                        *b ^= 0xff;
                    }
                }
            }
            match server_contribute(&self.config, t, self.server_id, &self.signing_key, &secrets) {
                Ok(signed) => {
                    if self.is_leader {
                        if let Ok((own, _)) = signed.recover() {
                            self.shares_by_round
                                .entry(t)
                                .or_default()
                                .insert(self.server_id, own.clone());
                        }
                    }
                    trace!(
                        target: ADCNET,
                        round = t,
                        server_id = self.server_id.0,
                        set = set.len(),
                        "adcnet: emitting share"
                    );
                    outbound.push(
                        bincode::serialize(&AdcnetWire::Server(signed)).expect("serialise share"),
                    );
                    self.shared_rounds.insert(t);
                }
                // Retried next round (`shared_rounds` is not marked), but until it
                // succeeds this relay is missing from the combine.
                Err(e) => warn!(
                    target: ADCNET,
                    round = t,
                    server_id = self.server_id.0,
                    set = set.len(),
                    error = ?e,
                    "adcnet: server_contribute failed; no share for this round"
                ),
            }
        }

        // Phase C (leader only): combine ready rounds and broadcast the result.
        if self.is_leader {
            let combine_rounds: Vec<u32> = self.client_set_by_round.keys().copied().collect();
            for t in combine_rounds {
                if let Some(payloads) = self.leader_combine(t) {
                    outbound.push(
                        bincode::serialize(&AdcnetWire::Decoded { round: t, payloads })
                            .expect("serialise decoded"),
                    );
                }
            }
        }

        let decoded = std::mem::take(&mut self.pending_decoded);
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

/// Non-relay watcher for a 1-round ADCNet subnet. Never combines — surfaces the
/// leader's `Decoded` broadcasts for pipe routing, carrying zero crypto state.
pub struct AdcnetWatchSession {
    leader_pk: PeerId,
    routed_rounds: std::collections::HashSet<u32>,
    pending_decoded: Vec<Vec<u8>>,
}

impl AdcnetWatchSession {
    pub fn new(leader_pk: PeerId) -> Self {
        AdcnetWatchSession {
            leader_pk,
            routed_rounds: std::collections::HashSet::new(),
            pending_decoded: Vec::new(),
        }
    }
}

impl Session for AdcnetWatchSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(AdcnetWire::Decoded { round, payloads }) =
            bincode::deserialize::<AdcnetWire>(&payload)
        {
            if from != self.leader_pk {
                // A stale leader here means this watcher never surfaces any
                // output at all — every inbound payload disappears.
                debug!(
                    target: ADCNET,
                    round,
                    expected_leader = %self.leader_pk,
                    "adcnet watch: Decoded from a non-leader, ignored"
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

// ---------------------------------------------------------------------------
// ScheduledAdcnet (2-round) sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScheduledClient {
    message: Signed<ClientRoundMessage>,
    key: Signed<KeyExchange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScheduledSet {
    round: i64,
    clients: Vec<ScheduledClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScheduledResult {
    broadcast: RoundBroadcast,
    completed: bool,
}

pub fn is_scheduled_client_feedback(payload: &[u8]) -> bool {
    use bincode::Options;
    matches!(
        bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit(16 * 1024 * 1024).reject_trailing_bytes()
            .deserialize::<ScheduledAdcnetWire>(payload),
        Ok(ScheduledAdcnetWire::Broadcast(_))
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ScheduledAdcnetWire {
    Client(ScheduledClient),
    ClientSet(Signed<ScheduledSet>),
    Partial(Signed<ServerPartialDecryptionMessage>),
    Broadcast(Signed<ScheduledResult>),
}

pub(crate) fn empty_scheduled_broadcast(config: &UpstreamAdcNetConfig, round: i64) -> RoundBroadcast {
    RoundBroadcast {
        round_number: round,
        auction_vector: adcnet::auction::iblt::IbltVector::new(config.auction_slots),
        message_vector: Vec::new(),
    }
}

pub(crate) fn scheduled_max_wire_estimate(
    cfg: &crate::config::ScheduledAdcnetConfig,
    n_relays: usize,
) -> usize {
    let auction = adcnet::auction::iblt::iblt_field_element_count(
        cfg.auction_slots,
        adcnet::auction::auction::AUCTION_BID_XI,
    )
    .saturating_mul(8);
    let contribution = auction
        .saturating_add(cfg.message_length)
        .saturating_add(n_relays.saturating_mul(4))
        .saturating_add(512);
    let client_set = contribution
        .saturating_mul(cfg.client_set_max as usize)
        .saturating_add(256);
    let partial = contribution
        .saturating_mul(2)
        .saturating_add((cfg.client_set_max as usize).saturating_mul(128));
    client_set.max(partial)
}

pub(crate) fn scheduled_config(cfg: &crate::config::ScheduledAdcnetConfig) -> UpstreamAdcNetConfig {
    UpstreamAdcNetConfig {
        auction_slots: cfg.auction_slots,
        message_length: cfg.message_length,
        min_clients: cfg.client_set_min,
        round_duration: std::time::Duration::from_millis(cfg.round_duration_ms),
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    }
}

pub struct ScheduledAdcnetClientSession {
    config: UpstreamAdcNetConfig,
    signing_key: PrivateKey,
    key: Signed<KeyExchange>,
    shared: HashMap<ServerId, SharedKey>,
    pending: std::collections::VecDeque<(Vec<u8>, u32)>,
    inflight: Option<(Vec<u8>, u32, i64)>,
    previous: RoundBroadcast,
    current_round: i64,
    leader: Pubkey,
    cover_rate: f32,
    min_message_size: usize,
    submitted_round: Option<i64>,
    node: Option<std::sync::Weak<AnymoneInner>>,
}

impl ScheduledAdcnetClientSession {
    pub fn new(
        config: UpstreamAdcNetConfig,
        signing_key: PrivateKey,
        exchange_key: ExchangePrivateKey,
        servers: &[(ServerId, adcnet::crypto::ExchangePublicKey)],
        initial_broadcast: RoundBroadcast,
        starting_round: i64,
        leader: Pubkey,
    ) -> Self {
        let key = Signed::new(
            &signing_key,
            KeyExchange {
                xpub: exchange_key.public().to_sec1_bytes(),
            },
        )
        .expect("sign client exchange key");
        Self {
            config,
            signing_key,
            key,
            shared: servers
                .iter()
                .map(|(id, key)| (*id, exchange_key.ecdh(key)))
                .collect(),
            pending: Default::default(),
            inflight: None,
            previous: initial_broadcast,
            current_round: starting_round,
            leader,
            cover_rate: 1.0,
            min_message_size: 1,
            submitted_round: None,
            node: None,
        }
    }

    pub fn stage_message(&mut self, mut payload: Vec<u8>, bid_value: u32) {
        payload.resize(payload.len().max(self.min_message_size), 0);
        self.pending.push_back((payload, bid_value));
    }

    pub fn messages_for_current_round(&mut self) -> Result<Vec<Vec<u8>>, String> {
        if self.previous.round_number != self.current_round - 1
            || self.submitted_round == Some(self.current_round)
        {
            return Ok(Vec::new());
        }
        if self
            .inflight
            .as_ref()
            .is_some_and(|(_, _, r)| *r != self.current_round - 1)
        {
            let (payload, bid, _) = self.inflight.take().unwrap();
            self.pending.push_front((payload, bid));
        }
        if self.pending.is_empty()
            && self.inflight.is_none()
            && rand::thread_rng().gen::<f32>() >= self.cover_rate
        {
            return Ok(Vec::new());
        }
        let bid = self.pending.front().map(|(payload, bid)| {
            adcnet::auction::auction::AuctionData::from_message(payload, *bid)
        });
        let message = self
            .inflight
            .as_ref()
            .map(|(p, _, _)| p.as_slice())
            .unwrap_or_default();
        let messager = adcnet::protocol::messager::ClientMessager {
            config: &self.config,
            shared_secrets: &self.shared,
        };
        let (message, won) = messager.prepare_message(
            self.current_round,
            &self.previous,
            message,
            bid.as_ref(),
            &mut rand::thread_rng(),
        ).map_err(|e| e.to_string())?;
        tracing::trace!(target: ADCNET, round = self.current_round, won, pending = self.pending.len(), inflight = self.inflight.is_some(), "scheduled submit");
        let signed = Signed::new(&self.signing_key, message).map_err(|e| e.to_string())?;
        let next = self.pending.pop_front();
        if let Some((payload, bid, _)) = self.inflight.take() {
            if !won {
                self.pending.push_back((payload, bid));
            }
        }
        self.inflight = next.map(|(p, bid)| (p, bid, self.current_round));
        self.submitted_round = Some(self.current_round);
        Ok(vec![
            bincode::serialize(&ScheduledAdcnetWire::Client(ScheduledClient {
                message: signed,
                key: self.key.clone(),
            }))
            .expect("serialize scheduled client"),
        ])
    }

    pub fn schedule_message_for_next_round(&mut self, payload: Vec<u8>, bid: u32) -> Result<(), String> {
        if payload.len().max(self.min_message_size) > self.config.message_length {
            return Err("payload exceeds scheduled message capacity".into());
        }
        self.stage_message(payload, bid);
        Ok(())
    }

    pub fn advance_to_round(&mut self, round: i64) -> Result<(), String> {
        if round < self.current_round || round < 1 {
            return Err("scheduled ADCNet round moved backwards".into());
        }
        self.current_round = round;
        Ok(())
    }

    pub fn process_round_broadcast(&mut self, payload: &[u8]) -> Result<(), String> {
        use bincode::Options;
        let ScheduledAdcnetWire::Broadcast(signed) = bincode::DefaultOptions::new()
            .with_fixint_encoding().with_limit(16 * 1024 * 1024).reject_trailing_bytes()
            .deserialize(payload).map_err(|e| e.to_string())?
        else {
            return Err("expected a scheduled ADCNet broadcast".into());
        };
        let (result, signer) = signed.recover().map_err(|e| e.to_string())?;
        let rb = &result.broadcast;
        if signer.as_bytes() != self.leader.0
            || rb.round_number < self.previous.round_number
            || rb.round_number > self.current_round
        {
            return Err("invalid broadcast signer or round".into());
        }
        if rb.round_number == self.previous.round_number
            && bincode::serialize(rb).map_err(|e| e.to_string())?
                != bincode::serialize(&self.previous).map_err(|e| e.to_string())?
        {
            return Err("conflicting broadcast for the same round".into());
        }
        self.previous = rb.clone();
        Ok(())
    }

    pub(crate) fn set_min_message_size(&mut self, size: usize) {
        self.min_message_size = size;
    }

    pub fn pending_message_count(&self) -> usize {
        self.pending.len() + usize::from(self.inflight.is_some())
    }

    pub(crate) fn take_pending_messages(&mut self) -> Vec<Vec<u8>> {
        if let Some((payload, bid, _)) = self.inflight.take() {
            self.pending.push_front((payload, bid));
        }
        self.pending.drain(..).map(|(payload, _)| payload).collect()
    }
}

impl Drop for ScheduledAdcnetClientSession {
    fn drop(&mut self) {
        let Some(inner) = self.node.as_ref().and_then(|node| node.upgrade()) else {
            return;
        };
        let pending = self.take_pending_messages();
        let mut outbox = inner.outbox.lock().unwrap();
        for payload in pending.into_iter().rev() {
            outbox.push_front(payload);
        }
    }
}

impl Session for ScheduledAdcnetClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if self.advance_to_round(round as i64 + 1).is_err() {
            return Vec::new();
        }
        self.messages_for_current_round().unwrap_or_default()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if self.process_round_broadcast(&payload).is_ok() {
            self.messages_for_current_round().unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        self.stage_message(payload, 1);
    }
    fn set_cover_rate(&mut self, rate: f32) {
        self.cover_rate = rate;
    }
    fn has_pending_transmissions(&self) -> bool {
        !self.pending.is_empty() || self.inflight.is_some()
    }
}

pub struct ScheduledAdcnetServerSession {
    svc: ServerService,
    config: UpstreamAdcNetConfig,
    current_round: i64,
    leader: Pubkey,
    roster: Vec<ServerId>,
    clients: std::collections::BTreeMap<Pubkey, ScheduledClient>,
    early_clients: std::collections::BTreeMap<Pubkey, ScheduledClient>,
    registered_clients: Vec<PublicKey>,
    client_set_max: usize,
    good_clients: GoodClients,
    selected: bool,
    pending_broadcast: Option<RoundBroadcast>,
    published: bool,
    previous: RoundBroadcast,
    misbehavior: Option<Misbehavior>,
}

impl ScheduledAdcnetServerSession {
    pub fn new(
        config: UpstreamAdcNetConfig,
        server_id: ServerId,
        signing_key: PrivateKey,
        exchange_key: ExchangePrivateKey,
        clients: &[(PublicKey, adcnet::crypto::ExchangePublicKey)],
        peer_servers: &[(ServerId, PublicKey)],
        starting_round: i64,
        leader: Pubkey,
    ) -> Self {
        assert!(matches!(config.aggregation, AggregationMode::Disabled));
        let svc = ServerService::new(config.clone(), server_id, signing_key, exchange_key);
        for (pk, xpub) in clients {
            svc.register_client(pk, xpub).expect("register client");
        }
        for (sid, pk) in peer_servers {
            svc.register_peer_server(*sid, pk.clone());
        }
        svc.advance_to_round(UpstreamRound::new(starting_round, RoundContext::Client));
        let mut roster: Vec<_> = peer_servers.iter().map(|(sid, _)| *sid).collect();
        roster.sort();
        Self {
            previous: empty_scheduled_broadcast(&config, starting_round - 1),
            svc,
            config,
            current_round: starting_round,
            leader,
            roster,
            clients: Default::default(),
            early_clients: Default::default(),
            registered_clients: clients.iter().map(|(pk, _)| pk.clone()).collect(),
            client_set_max: 300,
            good_clients: GoodClients::all(),
            selected: false,
            pending_broadcast: None,
            published: false,
            misbehavior: None,
        }
    }

    fn is_leader(&self) -> bool {
        self.svc.signing_key().public_key().unwrap().as_bytes() == self.leader.0
    }

    fn valid_client(
        &self,
        client: &ScheduledClient,
        round: i64,
    ) -> Option<(Pubkey, ExchangePublicKey)> {
        let (message, signer) = client.message.recover().ok()?;
        let (key, key_signer) = client.key.recover().ok()?;
        let pk = Pubkey(signer.as_bytes().try_into().ok()?);
        let auction_len = adcnet::auction::iblt::iblt_field_element_count(
            self.config.auction_slots,
            adcnet::auction::auction::AUCTION_BID_XI,
        );
        let expected_message_len = adcnet::protocol::messager::ClientMessager {
            config: &self.config,
            shared_secrets: &HashMap::new(),
        }
        .process_previous_auction(&self.previous.auction_vector, &[])
        .total_allocated;
        if signer != key_signer
            || !self.good_clients.allows(&pk)
            || message.round_number != round
            || message.all_server_ids != self.roster
            || message.auction_vector.len() != auction_len
            || message.message_vector.len() != expected_message_len
        {
            tracing::debug!(target: ADCNET, round = self.current_round, message_round = message.round_number, expected_message_len, actual_message_len = message.message_vector.len(), "scheduled client rejected");
            return None;
        }
        Some((pk, ExchangePublicKey::from_sec1_bytes(&key.xpub).ok()?))
    }

    fn broadcast_result(&mut self) -> Vec<Vec<u8>> {
        if !self.is_leader() || self.published {
            return Vec::new();
        }
        self.published = true;
        let completed = self.pending_broadcast.is_some();
        tracing::trace!(target: ADCNET, round = self.current_round, completed, clients = self.registered_clients.len(), "scheduled result");
        let broadcast = self
            .pending_broadcast
            .take()
            .unwrap_or_else(|| empty_scheduled_broadcast(&self.config, self.current_round));
        self.previous = broadcast.clone();
        let result = Signed::new(
            self.svc.signing_key(),
            ScheduledResult {
                broadcast,
                completed,
            },
        )
        .expect("sign round result");
        vec![bincode::serialize(&ScheduledAdcnetWire::Broadcast(result))
            .expect("serialize broadcast")]
    }
}

impl Session for ScheduledAdcnetServerSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        self.current_round = round as i64 + 1;
        self.svc
            .advance_to_round(UpstreamRound::new(self.current_round, RoundContext::Client));
        for pk in self.registered_clients.drain(..) {
            self.svc.deregister_client(&pk);
        }
        self.clients.clear();
        self.selected = false;
        self.pending_broadcast = None;
        self.published = false;
        if self.previous.round_number != self.current_round - 1 {
            self.previous = empty_scheduled_broadcast(&self.config, self.current_round - 1);
        }
        for (pk, client) in std::mem::take(&mut self.early_clients) {
            if self.valid_client(&client, self.current_round).is_some() {
                self.clients.insert(pk, client);
            }
        }
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let Ok(msg) = bincode::deserialize::<ScheduledAdcnetWire>(&payload) else {
            return Vec::new();
        };
        match msg {
            ScheduledAdcnetWire::Client(client) if self.is_leader() => {
                let round = client.message.object.round_number;
                if round == self.current_round + 1 && self.published {
                    if self.early_clients.len() < self.client_set_max {
                        if let Some((pk, _)) = self.valid_client(&client, round) {
                            self.early_clients.entry(pk).or_insert(client);
                        }
                    }
                } else if round == self.current_round
                    && !self.selected
                    && self.clients.len() < self.client_set_max
                {
                    if let Some((pk, _)) = self.valid_client(&client, round) {
                        self.clients.entry(pk).or_insert(client);
                    }
                }
            }
            ScheduledAdcnetWire::ClientSet(signed) if !self.selected => {
                let Ok((set, signer)) = signed.recover() else {
                    return Vec::new();
                };
                if signer.as_bytes() != self.leader.0
                    || set.round != self.current_round
                    || set.clients.len() > self.client_set_max
                    || (!set.clients.is_empty()
                        && set.clients.len() < self.config.min_clients as usize)
                {
                    return Vec::new();
                }
                let Some(keys) = set
                    .clients
                    .iter()
                    .map(|c| self.valid_client(c, self.current_round))
                    .collect::<Option<Vec<_>>>()
                else {
                    return Vec::new();
                };
                if keys.windows(2).any(|w| w[0].0 >= w[1].0) {
                    return Vec::new();
                }
                self.selected = true;
                for (client, (pk, xpub)) in set.clients.iter().zip(keys) {
                    let public = PublicKey::from_bytes(&pk.0);
                    if self.svc.register_client(&public, &xpub).is_err() {
                        return Vec::new();
                    }
                    self.registered_clients.push(public);
                    if self.svc.process_client_message(&client.message).is_err() {
                        return Vec::new();
                    }
                }
                if self.misbehavior == Some(Misbehavior::Withhold) {
                    return Vec::new();
                }
                if let Ok(mut partial) = self.svc.finalize_partial_for_direct_aggregate() {
                    if self.misbehavior == Some(Misbehavior::CorruptShare) {
                        if let Some(value) = partial.message_vector.first_mut() {
                            *value ^= 1;
                        } else if let Some(value) = partial.auction_vector.first_mut() {
                            *value ^= 1;
                        }
                    }
                    let signed = self.svc.sign_partial(partial).expect("sign partial");
                    if self.is_leader() {
                        if let Ok(Some(rb)) = self
                            .svc
                            .process_signed_partial_decryption_message(signed.clone())
                        {
                            self.pending_broadcast = Some(rb);
                        }
                    }
                    return vec![bincode::serialize(&ScheduledAdcnetWire::Partial(signed))
                        .expect("serialize partial")];
                }
            }
            ScheduledAdcnetWire::Partial(partial) if self.is_leader() => {
                if let Ok(Some(rb)) = self.svc.process_signed_partial_decryption_message(partial) {
                    self.pending_broadcast = Some(rb);
                    return self.broadcast_result();
                }
            }
            ScheduledAdcnetWire::Broadcast(signed) => {
                if let Ok((result, signer)) = signed.recover() {
                    if signer.as_bytes() == self.leader.0
                        && result.broadcast.round_number >= self.previous.round_number
                        && result.broadcast.round_number <= self.current_round
                    {
                        self.previous = result.broadcast.clone();
                    }
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn checkpoint(&mut self, _round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if k != 1 || !self.is_leader() || self.selected {
            return Vec::new();
        }
        let clients = if self.clients.len() >= self.config.min_clients as usize {
            std::mem::take(&mut self.clients).into_values().collect()
        } else {
            Vec::new()
        };
        let set = Signed::new(
            self.svc.signing_key(),
            ScheduledSet {
                round: self.current_round,
                clients,
            },
        )
        .expect("sign client set");
        let bytes =
            bincode::serialize(&ScheduledAdcnetWire::ClientSet(set)).expect("serialize client set");
        let partials = self.on_inbound(self.leader, bytes.clone());
        let mut outbound = vec![bytes];
        outbound.extend(partials);
        if self.pending_broadcast.is_some() {
            outbound.extend(self.broadcast_result());
        }
        outbound
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome {
            outbound: self.broadcast_result(),
            ..Default::default()
        }
    }

    fn set_misbehavior(&mut self, mode: Option<Misbehavior>) {
        self.misbehavior = mode;
    }
}

pub struct ScheduledAdcnetWatchSession {
    config: UpstreamAdcNetConfig,
    leader: Pubkey,
    previous: Option<RoundBroadcast>,
    decoded: Vec<Vec<u8>>,
}

impl ScheduledAdcnetWatchSession {
    pub fn new(config: &crate::config::ScheduledAdcnetConfig, leader: Pubkey) -> Self {
        Self {
            config: scheduled_config(config),
            leader,
            previous: None,
            decoded: Vec::new(),
        }
    }
}

impl Session for ScheduledAdcnetWatchSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }
    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let Ok(ScheduledAdcnetWire::Broadcast(signed)) = bincode::deserialize(&payload) else {
            return Vec::new();
        };
        let Ok((result, signer)) = signed.recover() else {
            return Vec::new();
        };
        let rb = &result.broadcast;
        if signer.as_bytes() != self.leader.0
            || rb.round_number < 1
            || self
                .previous
                .as_ref()
                .is_some_and(|prev| rb.round_number <= prev.round_number)
        {
            return Vec::new();
        }
        if let Some(previous) = &self.previous {
            if result.completed && previous.round_number + 1 == rb.round_number {
                self.decoded
                    .extend(extract_payloads(rb, &previous.auction_vector, &self.config));
            }
        }
        self.previous = Some(rb.clone());
        Vec::new()
    }
    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome {
            decoded: std::mem::take(&mut self.decoded),
            ..Default::default()
        }
    }
}

/// Decode the payloads in `rb.message_vector` using the auction winners
/// recovered from `prev_auction` (the previous round's auction IBLT). Returns
/// one entry per winner — the slot bytes. Empty winners or undecodable
/// auction yields no payloads.
fn extract_payloads(
    rb: &RoundBroadcast,
    prev_auction: &adcnet::auction::iblt::IbltVector,
    cfg: &UpstreamAdcNetConfig,
) -> Vec<Vec<u8>> {
    use adcnet::encoders::{auction_iblt, message_slots};
    let els = prev_auction.encode_as_field_elements();
    let Ok(winners) =
        auction_iblt::decode_winners(&els, cfg.auction_slots, cfg.message_length as u32, 1)
    else {
        return Vec::new();
    };
    if winners.is_empty() || rb.message_vector.is_empty() {
        return Vec::new();
    }
    message_slots::read_slots(&rb.message_vector, &winners)
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;

    #[test]
    fn scheduled_adcnet_authenticates_keys_shares_and_results() {
        let leader = Identity::generate();
        let peer = Identity::generate();
        let client_id = Identity::generate();
        let stranger = Identity::generate();
        let exchange =
            |id: &Identity| ExchangePrivateKey::from_bytes(&id.exchange().scalar_bytes()).unwrap();
        let cfg = crate::config::ScheduledAdcnetConfig {
            round_duration_ms: 200,
            message_length: 1024,
            auction_slots: 16,
            min_message_size: 1,
            client_set_min: 0,
            client_set_max: 8,
        };
        let config = scheduled_config(&cfg);
        let peers = [
            (ServerId(0), leader.to_adcnet_public_key()),
            (ServerId(1), peer.to_adcnet_public_key()),
        ];
        let mut server = ScheduledAdcnetServerSession::new(
            config.clone(),
            ServerId(0),
            leader.to_adcnet_signing_key(),
            exchange(&leader),
            &[],
            &peers,
            1,
            leader.pubkey(),
        );
        let mut client = ScheduledAdcnetClientSession::new(
            config.clone(),
            client_id.to_adcnet_signing_key(),
            exchange(&client_id),
            &[
                (ServerId(0), leader.exchange_pubkey()),
                (ServerId(1), peer.exchange_pubkey()),
            ],
            empty_scheduled_broadcast(&config, 0),
            1,
            leader.pubkey(),
        );
        let now = Instant::now();
        client.stage(b"payload".to_vec());
        let bytes = client.begin_round(0, now).pop().unwrap();
        let ScheduledAdcnetWire::Client(mut contribution) = bincode::deserialize(&bytes).unwrap()
        else {
            panic!()
        };
        contribution.key = Signed::new(
            &stranger.to_adcnet_signing_key(),
            contribution.key.object.clone(),
        )
        .unwrap();
        server.on_inbound(
            client_id.pubkey(),
            bincode::serialize(&ScheduledAdcnetWire::Client(contribution)).unwrap(),
        );
        assert!(server.clients.is_empty());
        server.good_clients = GoodClients::new(|_| false);
        server.on_inbound(client_id.pubkey(), bytes.clone());
        assert!(server.clients.is_empty());
        server.good_clients = GoodClients::all();
        server.on_inbound(client_id.pubkey(), bytes);
        assert_eq!(server.clients.len(), 1);
        let outputs = server.checkpoint(0, 1, now);
        let mut partial = outputs
            .into_iter()
            .find_map(|bytes| match bincode::deserialize(&bytes).unwrap() {
                ScheduledAdcnetWire::Partial(signed) => Some(signed.object),
                _ => None,
            })
            .unwrap();
        partial.server_id = ServerId(1);
        let forged = Signed::new(&stranger.to_adcnet_signing_key(), partial).unwrap();
        assert!(server
            .on_inbound(
                peer.pubkey(),
                bincode::serialize(&ScheduledAdcnetWire::Partial(forged)).unwrap()
            )
            .is_empty());
        assert!(!server.published);
        let result = ScheduledResult {
            broadcast: empty_scheduled_broadcast(&config, 1),
            completed: true,
        };
        let forged = Signed::new(&stranger.to_adcnet_signing_key(), result).unwrap();
        let bytes = bincode::serialize(&ScheduledAdcnetWire::Broadcast(forged)).unwrap();
        client.on_inbound(leader.pubkey(), bytes.clone());
        assert_eq!(client.previous.round_number, 0);
        let mut watcher = ScheduledAdcnetWatchSession::new(&cfg, leader.pubkey());
        watcher.begin_round(0, now);
        watcher.on_inbound(leader.pubkey(), bytes);
        assert!(watcher.previous.is_none());
    }
}
