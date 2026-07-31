//! Scheduled (staggered, two-phase) Panetiere flow, driven directly via
//! `Vec<u8>` buffers (no transport, no clock): reservation → grant →
//! fulfillment across the fixed round gap, plus a dropped-reservation retry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anymone_core::config::ScheduledPanetiereConfig;
use anymone_core::panetiere::SetMode;
use anymone_core::panetiere_scheduled::{
    params_for, ReservationEntries, ScheduledPanetiereClientSession,
    ScheduledPanetiereServerSession,
};
use anymone_core::session::Session;
use anymone_core::{Identity, Pubkey};

use panetiere::channel::ChannelParams;
use panetiere::pke;
use panetiere::protocol::{ProtocolParams, ServerId};

/// Must match `panetiere_scheduled::RESERVATION_TO_MSG_GAP` (crate-private):
/// a grant from round `R`'s `Reservations` is always due at round `R + GAP`.
const GAP: u64 = 2;

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

fn fresh_entries(n: usize) -> Vec<ReservationEntries> {
    (0..n).map(|_| ReservationEntries::default()).collect()
}

/// A scheduled subnet carrying `set_max` clients and a `vector_bytes` message
/// vector, `rho` reservations per round.
fn subnet(rho: u32, vector_bytes: usize, set_max: u32) -> ScheduledPanetiereConfig {
    ScheduledPanetiereConfig {
        vector_bytes,
        estimated_messages: rho,
        client_set_max: set_max,
        ..Default::default()
    }
}

fn server_pubkeys(server_pks: &[Pubkey]) -> HashMap<ServerId, Pubkey> {
    server_pks
        .iter()
        .enumerate()
        .map(|(i, pk)| (ServerId(i as u32), *pk))
        .collect()
}

/// `entries`: each relay node's `ReservationEntries` store, index-aligned with
/// `ids` — shared with a successor session to model a same-node worker respawn.
fn make_servers(
    pp: &Arc<ProtocolParams>,
    sched_mse: &ChannelParams,
    vector_bytes: usize,
    ids: &[Identity],
    server_pks: &[Pubkey],
    entries: &[ReservationEntries],
) -> Vec<ScheduledPanetiereServerSession> {
    (0..ids.len())
        .map(|i| {
            ScheduledPanetiereServerSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                ServerId(i as u32),
                ids[i].clone(),
                if i == 0 {
                    SetMode::Leader
                } else {
                    SetMode::Follower {
                        leader: server_pks[0],
                    }
                },
                server_pks[0],
                server_pubkeys(server_pks),
                entries[i].clone(),
            )
        })
        .collect()
}

/// One round's cadence for the direct flow: every client submits at
/// checkpoint 1, the leader announces at checkpoint 3, then every relay's
/// `end_round` emits shares, decodes whatever is now settled, and broadcasts.
/// Every relay's outbound is delivered to every other relay and every client —
/// mirrors gossip (ServerPublics on shares, Reservations/Decoded/ClientSet on
/// broadcast; each session ignores what it doesn't recognize). Returns each
/// relay's decoded payloads, index-aligned with `servers`.
fn direct_round(
    round: u64,
    now: Instant,
    clients: &mut [ScheduledPanetiereClientSession],
    client_pks: &[Pubkey],
    servers: &mut [ScheduledPanetiereServerSession],
    server_pks: &[Pubkey],
    submitted: &mut Vec<Option<usize>>,
) -> Vec<Vec<Vec<u8>>> {
    submitted.clear();
    for (i, c) in clients.iter_mut().enumerate() {
        c.begin_round(round, now);
        let out = c.checkpoint(round, 1, now);
        // The head is the `ClientPublic`; its length is the round's geometry.
        submitted.push(out.first().map(|m| m.len()));
        for s in servers.iter_mut() {
            for m in &out {
                s.on_inbound(client_pks[i], m.clone());
            }
        }
    }
    let widths: Vec<usize> = submitted.iter().flatten().copied().collect();
    assert!(
        widths.windows(2).all(|w| w[0] == w[1]),
        "round {round}: clients disagreed on entry width {widths:?} — a ragged \
         set panics the KAHE ciphertext sum"
    );
    for s in servers.iter_mut() {
        s.begin_round(round, now);
    }
    let announce = servers[0].checkpoint(round, 3, now);
    for s in servers[1..].iter_mut() {
        for m in &announce {
            s.on_inbound(server_pks[0], m.clone());
        }
    }
    let mut all_outbound: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut decoded = vec![Vec::new(); servers.len()];
    for (i, s) in servers.iter_mut().enumerate() {
        let outcome = s.end_round(round, now);
        decoded[i] = outcome.decoded;
        all_outbound.extend(outcome.outbound.into_iter().map(|m| (i, m)));
    }
    for (i, m) in &all_outbound {
        for (j, s) in servers.iter_mut().enumerate() {
            if j != *i {
                s.on_inbound(server_pks[*i], m.clone());
            }
        }
        for c in clients.iter_mut() {
            c.on_inbound(server_pks[*i], m.clone());
        }
    }
    decoded
}

#[test]
fn scheduled_direct_flow_pipelines_reservations() {
    let n_servers = 3;
    let vector_bytes = 128usize;
    let (sched_mse, pp) = params_for(&subnet(2, vector_bytes, 8), n_servers);

    let (ids, server_pks, xpubs) = server_env(n_servers);

    let payload_a = b"first client message".to_vec();
    let payload_b = b"second client message here".to_vec();
    let client_identities: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let client_pks: Vec<Pubkey> = client_identities.iter().map(|id| id.pubkey()).collect();
    let mut clients: Vec<ScheduledPanetiereClientSession> = (0..2usize)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ScheduledPanetiereClientSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                client_identities[i].clone(),
                xpubs.clone(),
                server_pks[0],
                seed,
                ReservationEntries::default(),
            )
        })
        .collect();
    clients[0].stage(payload_a.clone());
    clients[1].stage(payload_b.clone());

    let stores = fresh_entries(ids.len());
    let mut servers = make_servers(
        &pp,
        &sched_mse,
        vector_bytes,
        &ids,
        &server_pks,
        &stores,
    );
    let now = Instant::now();

    let mut final_decoded: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut submitted = Vec::new();
    let mut fulfilling_width = 0usize;
    for round in 0..=(GAP + 1) {
        let decoded = direct_round(
            round,
            now,
            &mut clients,
            &client_pks,
            &mut servers,
            &server_pks,
            &mut submitted,
        );
        // Round 0's grants are placed at round GAP; the decode surfaces a round
        // later, once the relays' shares are in.
        if round == GAP {
            fulfilling_width = submitted[0].expect("client 0 submits its granted payload");
        }
        if round < GAP + 1 {
            for (i, d) in decoded.iter().enumerate() {
                assert!(
                    d.is_empty(),
                    "relay {i} round {round}: nothing should decode before the fulfillment round"
                );
            }
        } else {
            final_decoded = decoded;
        }
    }
    for (i, decoded) in final_decoded.iter().enumerate() {
        assert!(
            decoded.contains(&payload_a),
            "relay {i}: must decode client 0's payload at the fulfillment round"
        );
        assert!(
            decoded.contains(&payload_b),
            "relay {i}: must decode client 1's payload at the fulfillment round"
        );
    }

    // A further cover-only round (nothing staged) must decode nothing new.
    let cover_round = GAP + 2;
    let decoded = direct_round(
        cover_round,
        now,
        &mut clients,
        &client_pks,
        &mut servers,
        &server_pks,
        &mut submitted,
    );
    for (i, d) in decoded.iter().enumerate() {
        assert!(
            d.is_empty(),
            "relay {i}: cover-only round must decode nothing"
        );
    }

    // The ciphertext rides the coded shares, so the post is constant: a
    // cover-only round is indistinguishable in width from a fulfilling one.
    let cover_width = submitted[0].expect("client 0 still reserves cover");
    assert_eq!(
        cover_width, fulfilling_width,
        "the RS post must not reveal whether a round fulfilled a grant"
    );

    // Worker respawn on a config cutover: the successor's first round is a
    // fulfillment round, and its predecessor deposits that round's reservations
    // in the very `end_round` the successor spawns alongside. A leader is fed
    // only by that deposit — it never receives its own `Reservations` off the
    // wire — so a width cache taken once at `begin_round` is stale for the whole
    // round, and every client entry is rejected as wrong-geometry.
    let res_round = cover_round + 1;
    clients[0].stage(payload_a.clone());
    for round in res_round..(res_round + GAP) {
        direct_round(
            round,
            now,
            &mut clients,
            &client_pks,
            &mut servers,
            &server_pks,
            &mut submitted,
        );
    }
    let cut = res_round + GAP;
    let deposit = stores[0].lock().unwrap()[&res_round].clone();
    let successor_store = ReservationEntries::default();
    let mut successor = make_servers(
        &pp,
        &sched_mse,
        vector_bytes,
        &ids[..1],
        &server_pks,
        std::slice::from_ref(&successor_store),
    )
    .remove(0);
    successor.begin_round(cut, now);
    successor_store.lock().unwrap().insert(res_round, deposit);
    successor.checkpoint(cut, 1, now);
    for (i, c) in clients.iter_mut().enumerate() {
        c.begin_round(cut, now);
        for m in c.checkpoint(cut, 1, now) {
            successor.on_inbound(client_pks[i], m);
        }
    }
    assert!(
        !successor.checkpoint(cut, 3, now).is_empty(),
        "a successor spawned on the cutover boundary must admit round {cut}'s \
         entries and announce a ClientSet"
    );
}

#[test]
fn dropped_reservation_is_retried() {
    let n_servers = 3;
    // Wide enough for exactly one 4-byte payload's aligned slot, not two —
    // the second reservation each round must overflow `codec::allocate`.
    let vector_bytes = 4usize;
    let (sched_mse, pp) = params_for(&subnet(2, vector_bytes, 8), n_servers);
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let payload_a = b"AAAA".to_vec();
    let payload_b = b"BBBB".to_vec();
    let client_identities: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let client_pks: Vec<Pubkey> = client_identities.iter().map(|id| id.pubkey()).collect();
    let mut clients: Vec<ScheduledPanetiereClientSession> = (0..2usize)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ScheduledPanetiereClientSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                client_identities[i].clone(),
                xpubs.clone(),
                server_pks[0],
                seed,
                ReservationEntries::default(),
            )
        })
        .collect();
    clients[0].stage(payload_a.clone());
    clients[1].stage(payload_b.clone());

    let mut servers = make_servers(
        &pp,
        &sched_mse,
        vector_bytes,
        &ids,
        &server_pks,
        &fresh_entries(ids.len()),
    );
    let now = Instant::now();

    // Run well past two fulfillment cycles: the overflowing client's payload
    // re-reserves at whichever round it lands back in `staged`, so it needs
    // its own full GAP+1 round-trip after that — generous margin here.
    let mut all_decoded: Vec<Vec<u8>> = Vec::new();
    let mut submitted = Vec::new();
    for round in 0..(3 * (GAP + 1)) {
        let decoded = direct_round(
            round,
            now,
            &mut clients,
            &client_pks,
            &mut servers,
            &server_pks,
            &mut submitted,
        );
        all_decoded.extend(decoded[0].clone());
    }
    assert!(
        all_decoded.contains(&payload_a),
        "the winning reservation must be delivered"
    );
    assert!(
        all_decoded.contains(&payload_b),
        "the overflowed reservation must be retried and eventually delivered"
    );
}
