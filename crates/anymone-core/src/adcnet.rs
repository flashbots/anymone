//! ADCNet `Session` wrappers. Two flows, picked per subnet via
//! [`crate::ProtocolConfig`]: a 1-round IBLT-message flow ([`AdcnetClientSession`]
//! / [`AdcnetServerSession`]) and a 2-round auction-then-broadcast flow
//! ([`ScheduledAdcnetClientSession`] / [`ScheduledAdcnetServerSession`], which
//! wrap the upstream stateful services). See IMPLEMENTATION.md §ADCNet sessions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::identity::{ExchangeIdentity, Identity};
use adcnet::crypto::{
    ExchangePrivateKey, ExchangePublicKey, PrivateKey, PublicKey, ServerId, SharedKey,
};
use adcnet::protocol::messages::Signed;
use adcnet::protocol::session::one_round::{
    client_contribute, combine_round, server_contribute, ClientContribution, IbltMsgParamsOwned,
    OneRoundConfig, ServerShare,
};
use adcnet::protocol::session::two_round::{ClientService, ServerService};
use adcnet::protocol::{
    AdcNetConfig as UpstreamAdcNetConfig, AggregationMode, ClientRoundMessage,
    Round as UpstreamRound, RoundBroadcast, RoundContext, ServerPartialDecryptionMessage,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::{AdcnetConfig, ProtocolConfig, Round, Subnet};
use crate::faults::Fault;
use crate::identity::Pubkey;
use crate::runtime::{
    aggregator_group_of, client_aggregator_topic, deadline_for, egress_dest, gossip_faults,
    publish_and_loop_back, recv_any, round_at, route_to_pipe, subnet_aggregation, subnet_leader_pk,
    AnymoneInner, SessionKey, StageMsg, FAULT_THRESHOLD,
};
use crate::session::{LeaderAggregation, Misbehavior, PeerId, RoundOutcome, Session};
use crate::transport::{Inbound, Subscription};
use crate::wire::RouteTag;

/// Per-subnet ADCNet parameters (IBLT sizing), built once at subnet start.
fn one_round_config(cfg: &AdcnetConfig) -> OneRoundConfig {
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
    let iblt = IbltMsgParamsOwned { estimated_messages, max_payload_bytes: message_size };
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
fn client_shared_secrets(
    cfg: &AdcnetConfig,
    identity: &Identity,
    subnet: &Subnet,
) -> HashMap<ServerId, SharedKey> {
    crate::keys::roster_exchange_pubkeys(&subnet.relays, &cfg.relay_exchange_keys)
        .into_iter()
        .map(|(i, xk)| (ServerId(i as u32), identity.exchange().ecdh(&xk)))
        .collect()
}

fn client_session(one_round: &OneRoundConfig, cfg: &AdcnetConfig, subnet: &Subnet, identity: &Identity) -> Box<dyn Session> {
    let shared_secrets = client_shared_secrets(cfg, identity, subnet);
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    Box::new(AdcnetClientSession::new(
        one_round.clone(),
        identity.to_adcnet_signing_key(),
        shared_secrets,
        identity.exchange_pubkey(),
        seed,
    ))
}

fn server_session(
    one_round: &OneRoundConfig,
    cfg: &AdcnetConfig,
    subnet: &Subnet,
    identity: &Identity,
    leader_pk: Pubkey,
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
    Box::new(AdcnetServerSession::new(
        one_round.clone(),
        ServerId(idx),
        identity.to_adcnet_signing_key(),
        identity.exchange().clone(),
        subnet.relays.len(),
        cfg.client_set_min as usize,
        is_leader,
        leader_pk,
        aggregation,
    ))
}

/// Self-contained ADCNet subnet driver: builds this node's sessions, then owns
/// the round loop. The runtime dispatches here for ADCNet subnets.
pub(crate) async fn run_subnet(
    subnet: Subnet,
    inner: Arc<AnymoneInner>,
    mut stage_rx: mpsc::UnboundedReceiver<StageMsg>,
    mut subscriptions: Vec<Subscription>,
    base_round: Round,
    epoch_unix_ms: u64,
) {
    let cfg = match &subnet.protocol {
        ProtocolConfig::Adcnet(c) => c.clone(),
        _ => unreachable!("adcnet::run_subnet on a non-ADCNet subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let one_round = one_round_config(&cfg);
    let leader_pk = subnet_leader_pk(&subnet);
    let client_agg_topic = client_aggregator_topic(&subnet, identity_pk);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut client_homes: HashSet<RouteTag> = HashSet::new();
    let mut cover_rate = subnet.cover_rate;

    if subnet.relays.contains(&identity_pk) {
        sessions.insert(
            SessionKey::Server,
            server_session(&one_round, &cfg, &subnet, &inner.identity, leader_pk),
        );
    } else {
        sessions.insert(SessionKey::Watch, Box::new(AdcnetWatchSession::new(leader_pk)));
    }
    if let Some(a) = subnet_aggregation(&subnet) {
        if let Some(group) = aggregator_group_of(a, identity_pk) {
            sessions.insert(
                SessionKey::Aggregator,
                Box::new(AdcnetAggregatorSession::new(
                    group,
                    a.groups.len() as u32,
                    inner.identity.clone(),
                )),
            );
        }
    }
    // Leader-side liveness monitor: sees every relay's share and the local output,
    // reconstructing the observer's wire view. One reporter per subnet.
    let mut fault_monitor: Option<Box<dyn Session>> = if leader_pk == identity_pk {
        let mut roster = subnet.relays.clone();
        roster.sort();
        Some(Box::new(AdcnetObserverSession::new(roster, leader_pk, FAULT_THRESHOLD)))
    } else {
        None
    };

    let egress = |key: &SessionKey, bytes: &[u8]| {
        egress_dest(
            subnet.id,
            true,
            is_server_share,
            is_client_message,
            client_agg_topic.as_deref(),
            key,
            bytes,
        )
    };

    // Round labels derive from the signed wall-clock epoch, not a local counter,
    // so every node agrees regardless of when it joined; `deadline` aligns to
    // absolute boundaries and a node that falls behind re-derives and skips ahead.
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

            _ = tokio::time::sleep_until(mid_deadline), if !mid_done => {
                mid_done = true;
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.mid_round(round, Instant::now()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            _ = tokio::time::sleep_until(deadline) => {
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
                let Inbound { from, payload } = msg;
                if let Some(m) = fault_monitor.as_mut() {
                    m.on_inbound(from, payload.clone());
                }
                let outs: Vec<(SessionKey, Vec<u8>)> = sessions
                    .iter_mut()
                    .flat_map(|(key, s)| {
                        let key = *key;
                        s.on_inbound(from, payload.clone()).into_iter().map(move |out| (key, out))
                    })
                    .collect();
                for (key, out) in outs {
                    publish_and_loop_back(&mut sessions, &mut fault_monitor, &inner, &egress, identity_pk, key, out)
                        .await;
                }
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::Join { client_tag } => {
                        client_homes.insert(client_tag);
                        sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&one_round, &cfg, &subnet, &inner.identity))
                            .set_cover_rate(cover_rate);
                    }
                    StageMsg::Stage { client_tag, payload } => {
                        client_homes.insert(client_tag);
                        let sess = sessions
                            .entry(SessionKey::Client)
                            .or_insert_with(|| client_session(&one_round, &cfg, &subnet, &inner.identity));
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
    /// Relay at 0-based index `idx` published its decryption share for `round`.
    Share {
        round: u64,
        idx: usize,
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
            Ok((s, _)) => AdcnetObserved::Share {
                round: s.round as u64,
                idx: s.server_id.0 as usize,
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

/// Liveness observer for an ADCNet subnet — run by the committee/dashboard
/// without participating. Recognises ADCNet share/output messages and feeds a
/// protocol-agnostic [`OutputFaultTracker`].
pub struct AdcnetObserverSession {
    tracker: crate::faults::OutputFaultTracker,
    /// Canonical client set size per round — the per-round anonymity set.
    anon_set_by_round: std::collections::BTreeMap<u64, usize>,
    /// Only this peer's `ClientSet`/`Decoded` are trusted (forgery guard).
    leader: PeerId,
}

const ANON_SET_HISTORY: usize = 16;

impl AdcnetObserverSession {
    pub fn new(roster: Vec<PeerId>, leader: PeerId, fault_threshold: u64) -> Self {
        AdcnetObserverSession {
            tracker: crate::faults::OutputFaultTracker::new(roster, fault_threshold),
            anon_set_by_round: std::collections::BTreeMap::new(),
            leader,
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
}

impl Session for AdcnetObserverSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        match observe_adcnet(&payload) {
            AdcnetObserved::Share { round, idx } => {
                self.tracker.observe_share(round, idx);
            }
            AdcnetObserved::Output { round } if from == self.leader => {
                self.tracker.observe_output(round);
            }
            AdcnetObserved::ClientSet { size, round } if from == self.leader => {
                self.anon_set_by_round.insert(round, size);
                while self.anon_set_by_round.len() > ANON_SET_HISTORY {
                    let oldest = *self.anon_set_by_round.keys().next().unwrap();
                    self.anon_set_by_round.remove(&oldest);
                }
            }
            _ => {}
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
            KeyExchange { xpub: leader.exchange_pubkey().to_sec1_bytes() },
        )
        .unwrap();
        let cs = bincode::serialize(&AdcnetWire::ClientSet { round: 1, clients: vec![signed] }).unwrap();
        obs.on_inbound(other.pubkey(), cs.clone());
        assert_eq!(obs.anonymity_set(), None, "non-leader ClientSet must be ignored");
        obs.on_inbound(leader_pk, cs);
        assert_eq!(obs.anonymity_set(), Some(1));

        let dec = bincode::serialize(&AdcnetWire::Decoded { round: 5, payloads: vec![] }).unwrap();
        obs.on_inbound(other.pubkey(), dec.clone());
        assert_eq!(obs.output_frontier(), None, "forged Decoded must not advance output");
        obs.on_inbound(leader_pk, dec);
        assert_eq!(obs.output_frontier(), Some(5));
    }

    #[test]
    fn wire_estimate_covers_real_messages() {
        let (msg_size, est_msgs, cset) = (256usize, 32u32, 40u32);
        let est = max_wire_estimate(msg_size, est_msgs, cset, 3);

        let iblt = IbltMsgParamsOwned { estimated_messages: est_msgs, max_payload_bytes: msg_size };
        let n = iblt.as_params().encoded_len();
        let id = Identity::generate();
        let share = Signed::new(
            &id.to_adcnet_signing_key(),
            ServerShare { server_id: ServerId(0), round: 1, share: vec![0u64; n] },
        )
        .unwrap();
        let share_wire = bincode::serialize(&AdcnetWire::Server(share)).unwrap();
        assert!(est >= share_wire.len(), "estimate {est} < real share {}", share_wire.len());

        let key = Signed::new(
            &id.to_adcnet_signing_key(),
            KeyExchange { xpub: id.exchange_pubkey().to_sec1_bytes() },
        )
        .unwrap();
        let cs = bincode::serialize(&AdcnetWire::ClientSet {
            round: 1,
            clients: vec![key; cset as usize],
        })
        .unwrap();
        assert!(est >= cs.len(), "estimate {est} < real client set {}", cs.len());
        assert!(est <= 4 * share_wire.len().max(cs.len()), "estimate {est} wildly loose");
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

impl Session for AdcnetClientSession {
    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        // Sign our exchange key once, reuse it every round; skip the round if it fails.
        if self.signed_key.is_none() {
            match Signed::new(
                &self.signing_key,
                KeyExchange {
                    xpub: self.client_xpub.clone(),
                },
            ) {
                Ok(signed) => self.signed_key = Some(signed),
                Err(_) => return Vec::new(),
            }
        }
        let key = self.signed_key.clone().expect("signed key present");

        let round_u32 = round as u32;
        let payload = self.pending.take();
        if payload.is_none() && self.rng.gen::<f32>() >= self.cover_rate {
            return Vec::new();
        }
        let contribution = match client_contribute(
            &self.config,
            round_u32,
            &self.signing_key,
            &self.shared_secrets,
            payload.as_deref(),
            &mut self.rng,
        ) {
            Ok(s) => s,
            Err(e) => {
                debug!(round = round_u32, secrets = self.shared_secrets.len(), error = ?e, "adcnet client: contribute failed");
                return Vec::new();
            }
        };
        let out = bincode::serialize(&AdcnetWire::Client { contribution, key })
            .expect("serialise client");
        debug!(
            round = round_u32,
            now_ms = crate::config::now_unix_ms(),
            "adcnet client: submit contribution"
        );
        vec![out]
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
        }
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
                return Vec::new();
            };
            if key_signer != signer
                || adcnet_client_group(signer.as_bytes(), self.group_count) != self.group
            {
                return Vec::new();
            }
            self.rounds
                .entry(c.round)
                .or_default()
                .insert(signer.clone(), (c.blinded.clone(), key.clone()));
        }
        Vec::new()
    }

    /// Emit the group's batch mid-round, so the leader announces the set and
    /// combines within the round rather than a round late.
    fn mid_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
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
    /// Anonymity floor: the leader won't decode a canonical set smaller than this.
    min_clients: usize,
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

impl AdcnetServerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: OneRoundConfig,
        server_id: ServerId,
        signing_key: PrivateKey,
        exchange: ExchangeIdentity,
        expected_servers: usize,
        min_clients: usize,
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
            min_clients,
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
            return None;
        }
        let shares = self.shares_by_round.get(&target)?;
        if shares.len() < self.expected_servers {
            return None;
        }
        // Aggregated: each group's summed blinded is one ClientContribution; the
        // leader re-sums them (combine_round's aggregate_clients is associative).
        let clients: Vec<ClientContribution> = if self.aggregation.is_some() {
            self.agg_by_round
                .get(&target)?
                .values()
                .map(|(blinded, _)| ClientContribution {
                    round: target,
                    blinded: blinded.clone(),
                })
                .collect()
        } else {
            let items = self.clients_by_round.get(&target)?;
            let clients: Vec<ClientContribution> = set
                .iter()
                .filter_map(|pk| items.iter().find(|(_, s)| s == pk).map(|(c, _)| c.clone()))
                .collect();
            if clients.len() != set.len() {
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
                self.combined_rounds.insert(target);
                self.clients_by_round.remove(&target);
                self.agg_by_round.remove(&target);
                self.shares_by_round.remove(&target);
                Some(payloads)
            }
            Err(_) => None,
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
        let Ok(msg) = bincode::deserialize::<AdcnetWire>(&payload) else {
            return Vec::new();
        };
        match msg {
            AdcnetWire::Client { contribution, key } => {
                // Non-leaders never read client data (they share off the ClientSet).
                if self.is_leader {
                    let (Ok((c, signer)), Ok((ke, key_signer))) =
                        (contribution.recover(), key.recover())
                    else {
                        return Vec::new();
                    };
                    // Reject unless key and contribution share a signer, else the
                    // signing↔xpub binding can't be trusted.
                    if key_signer != signer {
                        return Vec::new();
                    }
                    // Late: the set for `c.round` is already finalized.
                    if c.round < self.cur_round {
                        debug!(
                            signer = %hex::encode(&signer.as_bytes()[..4]),
                            c_round = c.round,
                            cur = self.cur_round,
                            now_ms = crate::config::now_unix_ms(),
                            "adcnet leader: dropped LATE client contribution"
                        );
                        return Vec::new();
                    }
                    let (c, signer) = (c.clone(), signer.clone());
                    self.cache_client_key(&signer, ke, key.clone());
                    debug!(
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
                    if let Ok((s, _signer)) = signed.recover() {
                        if s.round + ROUND_WINDOW < self.cur_round {
                            return Vec::new();
                        }
                        self.shares_by_round
                            .entry(s.round)
                            .or_default()
                            .insert(s.server_id, s.clone());
                    }
                }
            }
            AdcnetWire::ClientSet { round, clients } => {
                if round + ROUND_WINDOW < self.cur_round {
                    return Vec::new();
                }
                if from == self.leader_pk {
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
                    self.client_set_by_round.entry(round).or_insert(signers);
                }
            }
            AdcnetWire::Decoded { round, payloads } => {
                if from == self.leader_pk && !self.routed_rounds.contains(&round) {
                    self.routed_rounds.insert(round);
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
                    return Vec::new();
                };
                let Some(roster) = agg.roster.get(&group) else {
                    return Vec::new();
                };
                if !roster.contains(&signer)
                    || !signer.verify(
                        &group_aggregate_signing_bytes(round, group, &blinded, &clients),
                        &signature,
                    )
                    || round + ROUND_WINDOW < self.cur_round
                {
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
                    continue;
                }
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
            if tracing::enabled!(tracing::Level::DEBUG) {
                // Contribution spread across round buckets: clients landing in
                // many rounds means each canonical set is a fraction of the population.
                let mut buckets: Vec<(u32, usize)> = self
                    .clients_by_round
                    .iter()
                    .map(|(r, v)| (*r, v.len()))
                    .collect();
                buckets.sort_unstable();
                debug!(
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
            if secrets.len() != set.len() || secrets.is_empty() {
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
            if let Ok(signed) =
                server_contribute(&self.config, t, self.server_id, &self.signing_key, &secrets)
            {
                if self.is_leader {
                    if let Ok((own, _)) = signed.recover() {
                        self.shares_by_round
                            .entry(t)
                            .or_default()
                            .insert(self.server_id, own.clone());
                    }
                }
                outbound.push(
                    bincode::serialize(&AdcnetWire::Server(signed)).expect("serialise share"),
                );
                self.shared_rounds.insert(t);
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

// ---------------------------------------------------------------------------
// ScheduledAdcnet (2-round) sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ScheduledAdcnetWire {
    Client(Signed<ClientRoundMessage>),
    Partial(ServerPartialDecryptionMessage),
    /// Decoded round result; clients read it to find their winning slots next round.
    Broadcast(RoundBroadcast),
}

pub struct ScheduledAdcnetClientSession {
    svc: ClientService,
    pending: Option<(Vec<u8>, u32)>,
    current_round: i64,
}

impl ScheduledAdcnetClientSession {
    pub fn new(
        config: UpstreamAdcNetConfig,
        signing_key: PrivateKey,
        exchange_key: ExchangePrivateKey,
        servers: &[(ServerId, adcnet::crypto::ExchangePublicKey)],
        initial_broadcast: RoundBroadcast,
        starting_round: i64,
    ) -> Self {
        let svc = ClientService::new(config, signing_key, exchange_key);
        for (sid, xpub) in servers {
            svc.register_server(*sid, xpub).expect("register server");
        }
        svc.advance_to_round(UpstreamRound::new(starting_round, RoundContext::Client));
        svc.process_round_broadcast(initial_broadcast);
        ScheduledAdcnetClientSession {
            svc,
            pending: None,
            current_round: starting_round,
        }
    }

    pub fn stage_message(&mut self, payload: Vec<u8>, bid_value: u32) {
        self.pending = Some((payload, bid_value));
    }
}

impl Session for ScheduledAdcnetClientSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if let Some((payload, bid)) = self.pending.take() {
            let _ = self.svc.schedule_message_for_next_round(&payload, bid);
        }
        let mut out = Vec::new();
        if let Ok((signed, _won)) = self.svc.messages_for_current_round() {
            out.push(
                bincode::serialize(&ScheduledAdcnetWire::Client(signed)).expect("serialise client"),
            );
        }
        out
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if let Ok(ScheduledAdcnetWire::Broadcast(rb)) = bincode::deserialize(&payload) {
            // Advance through every round we've now observed.
            while self.current_round < rb.round_number + 1 {
                self.current_round += 1;
                self.svc
                    .advance_to_round(UpstreamRound::new(self.current_round, RoundContext::Client));
            }
            self.svc.process_round_broadcast(rb);
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }
}

pub struct ScheduledAdcnetServerSession {
    svc: ServerService,
    config: UpstreamAdcNetConfig,
    current_round: i64,
    has_clients_this_round: bool,
    emitted_my_partial: bool,
    pending_broadcast: Option<RoundBroadcast>,
    /// Auction state from the previous round — needed by `extract_payloads`
    /// because round R's `message_vector` slots are allocated by round R-1's
    /// winners (cf. `ClientMessager::process_previous_auction`).
    prev_auction: Option<adcnet::auction::iblt::IbltVector>,
}

impl ScheduledAdcnetServerSession {
    pub fn new(
        config: UpstreamAdcNetConfig,
        server_id: ServerId,
        signing_key: PrivateKey,
        exchange_key: ExchangePrivateKey,
        clients: &[(PublicKey, adcnet::crypto::ExchangePublicKey)],
        starting_round: i64,
    ) -> Self {
        assert!(
            matches!(config.aggregation, AggregationMode::Disabled),
            "ScheduledAdcnetServerSession requires AggregationMode::Disabled"
        );
        let svc = ServerService::new(config.clone(), server_id, signing_key, exchange_key);
        for (pk, xpub) in clients {
            svc.register_client(pk, xpub).expect("register client");
        }
        svc.advance_to_round(UpstreamRound::new(starting_round, RoundContext::Client));
        ScheduledAdcnetServerSession {
            svc,
            config,
            current_round: starting_round,
            has_clients_this_round: false,
            emitted_my_partial: false,
            pending_broadcast: None,
            prev_auction: None,
        }
    }
}

impl Session for ScheduledAdcnetServerSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let Ok(msg) = bincode::deserialize::<ScheduledAdcnetWire>(&payload) else {
            return Vec::new();
        };
        match msg {
            ScheduledAdcnetWire::Client(signed) => {
                if self.svc.process_client_message(&signed).is_ok() {
                    self.has_clients_this_round = true;
                }
            }
            ScheduledAdcnetWire::Partial(partial) => {
                if let Ok(Some(bc)) = self.svc.process_partial_decryption_message(partial) {
                    self.pending_broadcast = Some(bc);
                }
            }
            ScheduledAdcnetWire::Broadcast(_) => {
                // Server doesn't need peer broadcasts — its own service
                // produces them.
            }
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        let mut outbound = Vec::new();
        let mut decoded = Vec::new();

        if !self.emitted_my_partial && self.has_clients_this_round {
            if let Ok(partial) = self.svc.finalize_partial_for_direct_aggregate() {
                // Process_partial counts our own partial as one of the
                // collected shares and may produce the round broadcast right
                // away if it's the last partial we needed.
                if let Ok(Some(bc)) = self.svc.process_partial_decryption_message(partial.clone()) {
                    self.pending_broadcast = Some(bc);
                }
                outbound.push(
                    bincode::serialize(&ScheduledAdcnetWire::Partial(partial))
                        .expect("serialise partial"),
                );
                self.emitted_my_partial = true;
            }
        }

        if let Some(rb) = self.pending_broadcast.take() {
            // Decode this round's payloads using the *previous* round's
            // auction (winners determine slot offsets in this round's
            // `message_vector`). The first broadcast has no prior auction —
            // skip decode there (its `message_vector` is empty anyway).
            if let Some(prev_auction) = &self.prev_auction {
                decoded.extend(extract_payloads(&rb, prev_auction, &self.config));
            }
            // Stash this round's auction for next round's decoder.
            self.prev_auction = Some(rb.auction_vector.clone());
            outbound.push(
                bincode::serialize(&ScheduledAdcnetWire::Broadcast(rb))
                    .expect("serialise broadcast"),
            );
            // Advance to the next round.
            self.current_round += 1;
            self.svc
                .advance_to_round(UpstreamRound::new(self.current_round, RoundContext::Client));
            self.has_clients_this_round = false;
            self.emitted_my_partial = false;
        }

        RoundOutcome {
            outbound,
            decoded,
            faults: Vec::new(),
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
