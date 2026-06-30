//! Aggregated 1-round ADCNet flow over a synchronous bus: clients send their
//! blinded contributions to a 1-of-n aggregator committee per group; each
//! aggregator sums its group and forwards a signed `GroupAggregate` (with the
//! members' keys); the leader announces the ClientSet from the union and
//! combines the re-summed group totals against the relays' shares.

use std::collections::HashMap;
use std::time::Instant;

use anymone_core::adcnet::{AdcnetAggregatorSession, AdcnetClientSession, AdcnetServerSession};
use anymone_core::session::{LeaderAggregation, Session};
use anymone_core::{Identity, Pubkey};

use adcnet::crypto::{ServerId, SharedKey};
use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};

fn test_config() -> OneRoundConfig {
    OneRoundConfig {
        iblt: IbltMsgParamsOwned { estimated_messages: 8, max_payload_bytes: 256 },
    }
}

/// `live_replicas` aggregators per group emit (1 ⇒ exercises 1-of-n liveness).
/// Returns all payloads the leader (relay 0) decoded.
fn run_adcnet_aggregated(
    n_servers: usize,
    n_clients: usize,
    group_count: u32,
    replication: u32,
    live_replicas: u32,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let cfg = test_config();
    let mut relay_ids: Vec<Identity> = (0..n_servers).map(|_| Identity::generate()).collect();
    relay_ids.sort_by_key(|i| i.pubkey());
    let relay_pks: Vec<Pubkey> = relay_ids.iter().map(|i| i.pubkey()).collect();
    let server_ids: Vec<ServerId> = (1..=n_servers as u32).map(ServerId).collect();
    let leader_pk = relay_pks[0];

    let agg_ids: Vec<Vec<Identity>> = (0..group_count)
        .map(|_| (0..replication).map(|_| Identity::generate()).collect())
        .collect();
    let roster: HashMap<u32, Vec<Pubkey>> = agg_ids
        .iter()
        .enumerate()
        .map(|(g, ids)| (g as u32, ids.iter().map(|i| i.pubkey()).collect()))
        .collect();

    let client_ids: Vec<Identity> = (0..n_clients).map(|_| Identity::generate()).collect();
    let client_pks: Vec<Pubkey> = client_ids.iter().map(|i| i.pubkey()).collect();
    let mut clients: Vec<AdcnetClientSession> = client_ids
        .iter()
        .enumerate()
        .map(|(i, cid)| {
            let mut shared: HashMap<ServerId, SharedKey> = HashMap::new();
            for (j, sid) in server_ids.iter().enumerate() {
                shared.insert(*sid, cid.exchange().ecdh(&relay_ids[j].exchange_pubkey()));
            }
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            AdcnetClientSession::new(cfg.clone(), cid.to_adcnet_signing_key(), shared, cid.exchange_pubkey(), seed)
        })
        .collect();
    clients[0].stage_message(payload.to_vec());

    let mut servers: Vec<AdcnetServerSession> = (0..n_servers)
        .map(|i| {
            AdcnetServerSession::new(
                cfg.clone(),
                server_ids[i],
                relay_ids[i].to_adcnet_signing_key(),
                relay_ids[i].exchange().clone(),
                n_servers,
                0,
                i == 0,
                leader_pk,
                if i == 0 { Some(LeaderAggregation { roster: roster.clone() }) } else { None },
            )
        })
        .collect();

    let mut aggregators: Vec<(Pubkey, AdcnetAggregatorSession)> = agg_ids
        .iter()
        .enumerate()
        .flat_map(|(g, ids)| {
            ids.iter()
                .take(live_replicas as usize)
                .map(move |id| (id.pubkey(), AdcnetAggregatorSession::new(g as u32, group_count, id.clone())))
                .collect::<Vec<_>>()
        })
        .collect();

    let now = Instant::now();
    let mut bus: Vec<(Pubkey, Vec<u8>)> = Vec::new();
    let deliver =
        |bus: &mut Vec<(Pubkey, Vec<u8>)>, servers: &mut [AdcnetServerSession], aggs: &mut [(Pubkey, AdcnetAggregatorSession)]| {
            for (from, msg) in bus.drain(..) {
                for s in servers.iter_mut() {
                    s.on_inbound(from, msg.clone());
                }
                for (_, a) in aggs.iter_mut() {
                    a.on_inbound(from, msg.clone());
                }
            }
        };

    let mut decoded: Vec<Vec<u8>> = Vec::new();
    for r in 0..14u64 {
        for (i, c) in clients.iter_mut().enumerate() {
            for m in c.begin_round(r, now) {
                bus.push((client_pks[i], m));
            }
        }
        deliver(&mut bus, &mut servers, &mut aggregators);
        for (pk, a) in aggregators.iter_mut() {
            for m in a.mid_round(r, now) {
                bus.push((*pk, m));
            }
        }
        deliver(&mut bus, &mut servers, &mut aggregators);
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            if i == 0 {
                decoded.extend(out.decoded);
            }
            for m in out.outbound {
                bus.push((relay_pks[i], m));
            }
        }
        deliver(&mut bus, &mut servers, &mut aggregators);
    }
    decoded
}

/// Rounds the non-leader subnet's returns trail the leader; the window exists to
/// absorb this. Unlike `run_adcnet_aggregated`, this advances every relay clock,
/// so late-rejection + pruning fire. The payload rides round 0 only (cover after),
/// so a missed round-0 combine loses it. Returns the rounds it surfaced.
const SUBNET_LAG: u64 = 1;

fn run_realtime(aggregated: bool, payload: &[u8]) -> Vec<u64> {
    let cfg = test_config();
    let n_servers = 3usize;
    let group_count = 2u32;
    let mut relay_ids: Vec<Identity> = (0..n_servers).map(|_| Identity::generate()).collect();
    relay_ids.sort_by_key(|i| i.pubkey());
    let relay_pks: Vec<Pubkey> = relay_ids.iter().map(|i| i.pubkey()).collect();
    let server_ids: Vec<ServerId> = (1..=n_servers as u32).map(ServerId).collect();
    let leader_pk = relay_pks[0];

    let agg_ids: Vec<Identity> = (0..group_count).map(|_| Identity::generate()).collect();
    let roster: HashMap<u32, Vec<Pubkey>> =
        agg_ids.iter().enumerate().map(|(g, id)| (g as u32, vec![id.pubkey()])).collect();

    let client_ids: Vec<Identity> = (0..6).map(|_| Identity::generate()).collect();
    let client_pks: Vec<Pubkey> = client_ids.iter().map(|i| i.pubkey()).collect();
    let mut clients: Vec<AdcnetClientSession> = client_ids
        .iter()
        .enumerate()
        .map(|(i, cid)| {
            let mut shared: HashMap<ServerId, SharedKey> = HashMap::new();
            for (j, sid) in server_ids.iter().enumerate() {
                shared.insert(*sid, cid.exchange().ecdh(&relay_ids[j].exchange_pubkey()));
            }
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            AdcnetClientSession::new(cfg.clone(), cid.to_adcnet_signing_key(), shared, cid.exchange_pubkey(), seed)
        })
        .collect();
    clients[0].stage_message(payload.to_vec());

    let mut servers: Vec<AdcnetServerSession> = (0..n_servers)
        .map(|i| {
            AdcnetServerSession::new(
                cfg.clone(),
                server_ids[i],
                relay_ids[i].to_adcnet_signing_key(),
                relay_ids[i].exchange().clone(),
                n_servers,
                0,
                i == 0,
                leader_pk,
                if i == 0 && aggregated { Some(LeaderAggregation { roster: roster.clone() }) } else { None },
            )
        })
        .collect();
    let mut aggregators: Vec<(Pubkey, AdcnetAggregatorSession)> = if aggregated {
        agg_ids.iter().enumerate().map(|(g, id)| (id.pubkey(), AdcnetAggregatorSession::new(g as u32, group_count, id.clone()))).collect()
    } else {
        Vec::new()
    };

    let now = Instant::now();
    let mut queue: HashMap<u64, Vec<(Pubkey, Vec<u8>)>> = HashMap::new();
    let mut decoded_at: Vec<u64> = Vec::new();
    for r in 0..20u64 {
        let mut inbound: Vec<(Pubkey, Vec<u8>)> = queue.remove(&r).unwrap_or_default();
        for (i, c) in clients.iter_mut().enumerate() {
            // Client contributions reach relays/aggregators the same round.
            for m in c.begin_round(r, now) {
                inbound.push((client_pks[i], m));
            }
        }
        for (_, a) in aggregators.iter_mut() {
            a.begin_round(r, now);
        }
        for s in servers.iter_mut() {
            s.begin_round(r, now);
        }
        for (from, msg) in &inbound {
            for s in servers.iter_mut() {
                s.on_inbound(*from, msg.clone());
            }
            for (_, a) in aggregators.iter_mut() {
                a.on_inbound(*from, msg.clone());
            }
        }
        // Emitted mid-round, the aggregate reaches the leader before the round
        // closes — delivered this round, ahead of the servers' end_round.
        for (pk, a) in aggregators.iter_mut() {
            for m in a.mid_round(r, now) {
                for s in servers.iter_mut() {
                    s.on_inbound(*pk, m.clone());
                }
            }
        }
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            if i == 0 && out.decoded.iter().any(|d| d == payload) {
                decoded_at.push(r);
            }
            let delay = if i == 0 { 1 } else { 1 + SUBNET_LAG };
            queue.entry(r + delay).or_default().extend(out.outbound.into_iter().map(|m| (relay_pks[i], m)));
        }
    }
    decoded_at
}

/// Both flows must decode within the subnet-lag window. The aggregated flow's
/// whole-round aggregator batch + the leader's aggregate-driven announce add the
/// extra latency that currently pushes its combine out of the window.
#[test]
fn aggregated_decodes_within_subnet_lag_window() {
    let payload = b"aggregated round-0 payload".to_vec();
    assert!(!run_realtime(false, &payload).is_empty(), "direct decodes with one round of subnet lag");
    assert!(!run_realtime(true, &payload).is_empty(), "aggregated must also decode within the window");
}

#[test]
fn adcnet_aggregated_decodes_through_groups() {
    let payload = b"aggregated adcnet across groups".to_vec();
    let decoded = run_adcnet_aggregated(3, 6, 2, 2, 2, &payload);
    assert!(decoded.contains(&payload), "payload never decoded; got {decoded:?}");
}

#[test]
fn adcnet_aggregated_survives_one_dead_replica_per_group() {
    let payload = b"one live adcnet aggregator suffices".to_vec();
    let decoded = run_adcnet_aggregated(3, 6, 2, 2, 1, &payload);
    assert!(decoded.contains(&payload), "payload never decoded; got {decoded:?}");
}
