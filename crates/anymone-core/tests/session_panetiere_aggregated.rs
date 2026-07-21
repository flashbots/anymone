//! Aggregated Panetiere flow, driven directly via `Vec<u8>` buffers (no
//! transport, no clock): >16 clients across aggregator groups post their public
//! ciphertext+commitment to a 1-of-2 aggregator committee; relays still receive
//! openings as usual; the leader re-sums the signed group aggregates and decodes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anymone_core::panetiere::{
    PanetiereAggregatorSession, PanetiereClientSession, PanetiereServerSession, SetMode,
};
use anymone_core::session::{LeaderAggregation, Session};
use anymone_core::{Identity, Pubkey};

use panetiere::mse::{MseEncoding, MseParams};
use panetiere::pke;
use panetiere::protocol::{ClientId, ProtocolParams, ServerId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn server_env(n: usize) -> (Vec<Identity>, Vec<Pubkey>, Vec<(ServerId, pke::PublicKey)>) {
    let mut ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    ids.sort_by_key(|i| i.pubkey());
    let pks = ids.iter().map(|i| i.pubkey()).collect();
    let xpubs = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (ServerId(i as u32), id.exchange().pke().public()))
        .collect();
    (ids, pks, xpubs)
}

fn server_pubkeys(server_pks: &[Pubkey]) -> HashMap<ServerId, Pubkey> {
    server_pks.iter().enumerate().map(|(i, pk)| (ServerId(i as u32), *pk)).collect()
}

/// Run the aggregated two-round flow. `live_replicas` aggregators per group
/// actually emit (1 ⇒ exercises 1-of-2 liveness). Returns the leader's decoded
/// payloads.
fn run_aggregated(
    n_servers: usize,
    n_clients: u32,
    group_count: u32,
    replication: u32,
    live_replicas: u32,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    // Only client 0 is active; the IBLT is sized to the active count.
    let mse = MseParams::new(4, 1, 32, [0xAA; 32]);
    let n_polys = MseEncoding::n_polys(&mse);
    let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(&mut setup_rng, n_servers, n_polys, 1));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let (ids, server_pks, xpubs) = server_env(n_servers);

    // Aggregator identities: `replication` per group.
    let agg_ids: Vec<Vec<Identity>> = (0..group_count)
        .map(|_| (0..replication).map(|_| Identity::generate()).collect())
        .collect();
    let roster: HashMap<u32, Vec<Pubkey>> = agg_ids
        .iter()
        .enumerate()
        .map(|(g, ids)| (g as u32, ids.iter().map(|i| i.pubkey()).collect()))
        .collect();
    let leader_agg = || LeaderAggregation { roster: roster.clone() };

    // Clients: client 0 carries `payload`, the rest send cover (zero) traffic.
    let mut clients: Vec<PanetiereClientSession> = (0..n_clients)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            PanetiereClientSession::new(pp.clone(), mse.clone(), ClientId(i), xpubs.clone(), seed)
        })
        .collect();
    clients[0].stage(payload.to_vec());

    // Every relay runs in aggregated mode; only the leader (server 0) emits.
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                if sid.0 == 0 { SetMode::Leader } else { SetMode::SelfDerived },
                0,
                server_pubkeys(&server_pks),
                Some(leader_agg()),
            )
        })
        .collect();

    let mut aggregators: Vec<PanetiereAggregatorSession> = agg_ids
        .iter()
        .enumerate()
        .flat_map(|(g, ids)| {
            ids.iter()
                .take(live_replicas as usize)
                .map(move |id| PanetiereAggregatorSession::new(g as u32, group_count, id.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    let now = Instant::now();

    // Round 0: clients emit ClientPublic (→ aggregators) + openings (→ relays).
    for c in clients.iter_mut() {
        let out = c.begin_round(0, now);
        let (client_public, openings) = out.split_first().expect("ClientPublic + openings");
        for a in aggregators.iter_mut() {
            a.on_inbound(server_pks[0], client_public.clone());
        }
        for s in servers.iter_mut() {
            for op in openings {
                s.on_inbound(server_pks[0], op.clone());
            }
        }
    }

    // Aggregators emit mid-round, delivered to every relay before end_round(0) —
    // matching production, where mid_round fires at the round's midpoint.
    let group_aggs: Vec<Vec<u8>> =
        aggregators.iter_mut().flat_map(|a| a.mid_round(0, now)).collect();
    for s in servers.iter_mut() {
        for m in &group_aggs {
            s.on_inbound(server_pks[0], m.clone());
        }
    }
    let server_publics: Vec<(usize, Vec<u8>)> = servers
        .iter_mut()
        .enumerate()
        .flat_map(|(i, s)| s.end_round(0, now).outbound.into_iter().map(move |m| (i, m)))
        .collect();

    // Round 1: peer ServerPublics cross-delivered.
    for i in 0..servers.len() {
        for (j, m) in &server_publics {
            if i != *j {
                servers[i].on_inbound(server_pks[*j], m.clone());
            }
        }
    }

    servers
        .iter_mut()
        .enumerate()
        .flat_map(|(i, s)| {
            let outcome = s.end_round(1, now);
            if i == 0 { outcome.decoded } else { Vec::new() }
        })
        .collect()
}

#[test]
fn aggregated_flow_decodes_through_groups() {
    let payload = b"aggregated panetiere across two groups".to_vec();
    // 20 clients (> 16 threshold), 2 groups of ~10, 1-of-2 committees all live.
    let decoded = run_aggregated(3, 20, 2, 2, 2, &payload);
    let got = decoded.first().expect("leader decodes the aggregated round");
    assert!(got.len() >= payload.len());
    assert_eq!(&got[..payload.len()], payload.as_slice());
}

#[test]
fn aggregated_flow_survives_one_dead_replica_per_group() {
    let payload = b"one live aggregator per group is enough".to_vec();
    // Only 1 of the 2 replicas per group emits — 1-of-n liveness.
    let decoded = run_aggregated(3, 20, 2, 2, 1, &payload);
    let got = decoded.first().expect("leader decodes with one live replica per group");
    assert_eq!(&got[..payload.len()], payload.as_slice());
}
