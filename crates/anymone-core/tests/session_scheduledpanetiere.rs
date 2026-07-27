//! Scheduled (staggered, two-phase) Panetiere flow, driven directly via
//! `Vec<u8>` buffers (no transport, no clock): reservation → grant →
//! fulfillment across the fixed round gap, for both the direct and aggregated
//! flows, plus a dropped-reservation retry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anymone_core::panetiere::{client_id_from_pubkey, PanetiereAggregatorSession, SetMode};
use anymone_core::panetiere_scheduled::{
    ReservationEntries, ScheduledPanetiereClientSession, ScheduledPanetiereServerSession,
};
use anymone_core::session::{LeaderAggregation, Session};
use anymone_core::{Identity, Pubkey};

use chipmunk_code::N;
use panetiere::bulletin::ClientBulletinEntry;
use panetiere::mse::{MseEncoding, MseParams};
use panetiere::pke;
use panetiere::protocol::{ProtocolParams, ServerId};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Must match `panetiere_scheduled::RESERVATION_TO_MSG_GAP` (crate-private):
/// a grant from round `R`'s `Reservations` is always due at round `R + GAP`.
const GAP: u64 = 2;
const BYTES_PER_POLY: usize = N * 4;

/// PRF key from the test's seeded RNG, like production `channel_mse_params` —
/// a hardcoded key can land the IBLT on a rare peel stall at tight δ.
fn prf_key(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

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
    sched_mse: &MseParams,
    vector_bytes: usize,
    ids: &[Identity],
    server_pks: &[Pubkey],
    aggregation: Option<&HashMap<u32, Vec<Pubkey>>>,
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
                0,
                server_pubkeys(server_pks),
                aggregation.map(|roster| LeaderAggregation {
                    roster: roster.clone(),
                }),
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
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let rho = 2u32;
    let sched_mse = MseParams::new(
        4,
        (3 * rho as usize).div_ceil(4),
        2,
        prf_key(&mut setup_rng),
    );
    let vector_bytes = 128usize;
    let sched_polys = MseEncoding::n_polys(&sched_mse);
    let msg_polys = vector_bytes.div_ceil(BYTES_PER_POLY);
    let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(
        &mut setup_rng,
        n_servers,
        sched_polys + msg_polys,
        1,
    ));

    let (ids, server_pks, xpubs) = server_env(n_servers);

    let payload_a = b"first client message".to_vec();
    let payload_b = b"second client message here".to_vec();
    let client_pks: Vec<Pubkey> = (0..2).map(|_| Identity::generate().pubkey()).collect();
    let mut clients: Vec<ScheduledPanetiereClientSession> = (0..2usize)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ScheduledPanetiereClientSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                client_id_from_pubkey(client_pks[i]),
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
        None,
        &fresh_entries(ids.len()),
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

    // The saving: a round whose reservations are all zero-length cover carries
    // no message vector at all, where a fulfilling round carries one poly.
    let cover_width = submitted[0].expect("client 0 still reserves cover");
    let one_poly = ClientBulletinEntry::packed_len(sched_polys + 1)
        - ClientBulletinEntry::packed_len(sched_polys);
    assert_eq!(
        fulfilling_width - cover_width,
        one_poly,
        "a cover-only round must drop the message vector entirely"
    );
}

#[test]
fn dropped_reservation_is_retried() {
    let mut setup_rng = ChaCha20Rng::from_seed([9u8; 32]);
    let n_servers = 3;
    let rho = 2u32;
    let sched_mse = MseParams::new(
        4,
        (3 * rho as usize).div_ceil(4),
        2,
        prf_key(&mut setup_rng),
    );
    // Wide enough for exactly one 4-byte payload's aligned slot, not two —
    // the second reservation each round must overflow `codec::allocate`.
    let vector_bytes = 4usize;
    let sched_polys = MseEncoding::n_polys(&sched_mse);
    let msg_polys = vector_bytes.div_ceil(BYTES_PER_POLY);
    let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(
        &mut setup_rng,
        n_servers,
        sched_polys + msg_polys,
        1,
    ));
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let payload_a = b"AAAA".to_vec();
    let payload_b = b"BBBB".to_vec();
    let client_pks: Vec<Pubkey> = (0..2).map(|_| Identity::generate().pubkey()).collect();
    let mut clients: Vec<ScheduledPanetiereClientSession> = (0..2usize)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ScheduledPanetiereClientSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                client_id_from_pubkey(client_pks[i]),
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
        None,
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

/// One aggregated-flow round: clients submit to the aggregator (openings
/// still go straight to relays), the aggregator emits its group sum before
/// the leader announces, then the same shares/decode/broadcast cadence.
#[allow(clippy::too_many_arguments)]
fn aggregated_round(
    round: u64,
    now: Instant,
    clients: &mut [ScheduledPanetiereClientSession],
    client_pks: &[Pubkey],
    aggregators: &mut [PanetiereAggregatorSession],
    servers: &mut [ScheduledPanetiereServerSession],
    server_pks: &[Pubkey],
) -> (Vec<Vec<Vec<u8>>>, Vec<(Pubkey, Vec<u8>)>) {
    for (i, c) in clients.iter_mut().enumerate() {
        c.begin_round(round, now);
        let out = c.checkpoint(round, 1, now);
        let Some((client_public, openings)) = out.split_first() else {
            continue;
        };
        for a in aggregators.iter_mut() {
            a.on_inbound(client_pks[i], client_public.clone());
        }
        for s in servers.iter_mut() {
            for op in openings {
                s.on_inbound(client_pks[i], op.clone());
            }
        }
    }
    let group_aggs: Vec<Vec<u8>> = aggregators
        .iter_mut()
        .flat_map(|a| a.checkpoint(round, 1, now))
        .collect();
    for s in servers.iter_mut() {
        for m in &group_aggs {
            s.on_inbound(server_pks[0], m.clone());
        }
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
    let mut wire: Vec<(Pubkey, Vec<u8>)> = group_aggs
        .into_iter()
        .chain(announce)
        .map(|m| (server_pks[0], m))
        .collect();
    wire.extend(all_outbound.into_iter().map(|(i, m)| (server_pks[i], m)));
    (decoded, wire)
}

#[test]
fn scheduled_aggregated_flow_decodes_through_groups() {
    let mut setup_rng = ChaCha20Rng::from_seed([11u8; 32]);
    let n_servers = 3;
    let rho = 2u32;
    let sched_mse = MseParams::new(
        4,
        (3 * rho as usize).div_ceil(4),
        2,
        prf_key(&mut setup_rng),
    );
    let vector_bytes = 128usize;
    let sched_polys = MseEncoding::n_polys(&sched_mse);
    let msg_polys = vector_bytes.div_ceil(BYTES_PER_POLY);
    let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(
        &mut setup_rng,
        n_servers,
        sched_polys + msg_polys,
        1,
    ));
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let group_count = 2u32;
    let agg_ids: Vec<Identity> = (0..group_count).map(|_| Identity::generate()).collect();
    let roster: HashMap<u32, Vec<Pubkey>> = agg_ids
        .iter()
        .enumerate()
        .map(|(g, id)| (g as u32, vec![id.pubkey()]))
        .collect();

    let payload_a = b"group zero's scheduled message".to_vec();
    let payload_b = b"group one's scheduled message".to_vec();
    // Pick client pubkeys landing in distinct groups via `client_id % group_count`.
    let (pk_a, pk_b) = loop {
        let a = Identity::generate().pubkey();
        let b = Identity::generate().pubkey();
        let ga = client_id_from_pubkey(a).0 % group_count;
        let gb = client_id_from_pubkey(b).0 % group_count;
        if ga == 0 && gb != 0 {
            break (a, b);
        }
        if gb == 0 && ga != 0 {
            break (b, a);
        }
    };
    let client_pks = [pk_a, pk_b];
    let mut clients: Vec<ScheduledPanetiereClientSession> = (0..2usize)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&(i as u32).to_le_bytes());
            ScheduledPanetiereClientSession::new(
                pp.clone(),
                sched_mse.clone(),
                vector_bytes,
                client_id_from_pubkey(client_pks[i]),
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
        Some(&roster),
        &stores,
    );
    let mut aggregators: Vec<PanetiereAggregatorSession> = agg_ids
        .iter()
        .enumerate()
        .map(|(g, id)| PanetiereAggregatorSession::new(g as u32, group_count, id.clone()))
        .collect();
    let now = Instant::now();

    let mut final_decoded: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut final_wire: Vec<(Pubkey, Vec<u8>)> = Vec::new();
    for round in 0..=(GAP + 1) {
        let (decoded, wire) = aggregated_round(
            round,
            now,
            &mut clients,
            &client_pks,
            &mut aggregators,
            &mut servers,
            &server_pks,
        );
        if round < GAP + 1 {
            for (i, d) in decoded.iter().enumerate() {
                assert!(
                    d.is_empty(),
                    "relay {i} round {round}: nothing should decode before the fulfillment round"
                );
            }
        } else {
            final_decoded = decoded;
            final_wire = wire;
        }
    }
    for (i, decoded) in final_decoded.iter().enumerate() {
        assert!(
            decoded.contains(&payload_a),
            "relay {i}: must decode group 0's payload"
        );
        assert!(
            decoded.contains(&payload_b),
            "relay {i}: must decode group 1's payload"
        );
    }

    // Cutover successor: a leader session first ticked at GAP+2 must ignore
    // the predecessor's rounds wholesale — even with matching geometry it
    // would otherwise re-decode round GAP+1 from the redelivered aggregates,
    // set, and shares (and re-broadcast its reservations), duplicating the
    // draining predecessor's work.
    let mut successor = make_servers(
        &pp,
        &sched_mse,
        vector_bytes,
        &ids,
        &server_pks,
        Some(&roster),
        &fresh_entries(ids.len()),
    )
    .remove(0);
    successor.begin_round(GAP + 2, now);
    for (from, m) in &final_wire {
        let out = successor.on_inbound(*from, m.clone());
        assert!(out.is_empty(), "successor: pre-spawn wire produced output");
    }
    let outcome = successor.end_round(GAP + 2, now);
    assert!(
        outcome.outbound.is_empty(),
        "successor: emitted over a pre-spawn round"
    );
    assert!(
        outcome.decoded.is_empty(),
        "successor: decoded a pre-spawn round"
    );

    // Worker respawn with the node-scoped entries store: a payload reserved
    // under the old workers (round GAP+2) must decode on successor sessions
    // that never saw `Reservations{GAP+2}` — they read the entries the
    // predecessors deposited. On the leader node that broadcast can never
    // arrive (self-inbound is dropped); the store is what closes the window.
    let payload_c = b"payload across the worker swap".to_vec();
    clients[0].stage(payload_c.clone());
    aggregated_round(
        GAP + 2,
        now,
        &mut clients,
        &client_pks,
        &mut aggregators,
        &mut servers,
        &server_pks,
    );
    // Predecessors' drain round: decode round GAP+2 (its shares arrived above),
    // depositing entries{GAP+2}; only the clients see the grant broadcast.
    for s in servers.iter_mut() {
        for m in s.end_round(GAP + 3, now).outbound {
            for c in clients.iter_mut() {
                c.on_inbound(server_pks[0], m.clone());
            }
        }
    }
    let mut servers = make_servers(
        &pp,
        &sched_mse,
        vector_bytes,
        &ids,
        &server_pks,
        Some(&roster),
        &stores,
    );
    for s in servers.iter_mut() {
        s.begin_round(GAP + 3, now);
    }
    let mut swap_decoded: Vec<Vec<Vec<u8>>> = Vec::new();
    for round in (GAP + 3)..=(2 * GAP + 3) {
        (swap_decoded, _) = aggregated_round(
            round,
            now,
            &mut clients,
            &client_pks,
            &mut aggregators,
            &mut servers,
            &server_pks,
        );
    }
    for (i, decoded) in swap_decoded.iter().enumerate() {
        assert!(
            decoded.contains(&payload_c),
            "successor relay {i}: must decode the payload reserved before the swap"
        );
    }
}
