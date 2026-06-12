//! Happy-path test for `ScheduledAdcnetClient/ServerSession` (2-round flow).
//!
//! ADCNet's 2-round protocol takes two logical rounds to deliver one payload:
//! round 1 carries the auction bid, round 2 carries the message at the
//! winning slot. Each logical round needs two Session-trait cycles (clients
//! → servers → partial-exchange → broadcast), so the full round-trip is four
//! `begin_round`/`end_round` cycles.

use std::time::Instant;

use anymone_core::adcnet::{ScheduledAdcnetClientSession, ScheduledAdcnetServerSession};
use anymone_core::session::Session;
use anymone_core::Identity;

use adcnet::auction::iblt::IbltVector;
use adcnet::crypto::{generate_keypair, ExchangePrivateKey, ExchangePublicKey, ServerId};
use adcnet::protocol::{
    AdcNetConfig, AggregationMode, RoundBroadcast,
};

#[test]
fn scheduled_adcnet_session_happy_path() {
    let n_servers = 3usize;
    let starting_round = 1i64;

    let config = AdcNetConfig {
        auction_slots: 16,
        // Knapsack quantises to `KNAPSACK_CHUNK_BYTES` (1 KiB), so
        // `message_length` must be ≥ 1 KiB or the auction returns zero
        // winners and the round-2 message_vector ends up empty.
        message_length: 1024,
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    };

    // Server identities.
    let server_signing: Vec<_> = (0..n_servers).map(|_| generate_keypair().1).collect();
    let server_xks: Vec<_> = (0..n_servers).map(|_| ExchangePrivateKey::generate()).collect();
    let server_xpubs: Vec<ExchangePublicKey> = server_xks.iter().map(|k| k.public()).collect();
    let server_ids: Vec<ServerId> = (1..=n_servers as u32).map(ServerId).collect();

    // Client identity.
    let (client_pub, client_signing_key) = generate_keypair();
    let client_xk = ExchangePrivateKey::generate();

    // Server-side client roster.
    let clients_for_servers: Vec<_> = vec![(client_pub.clone(), client_xk.public())];
    // Client-side server roster.
    let servers_for_client: Vec<_> = server_ids
        .iter()
        .zip(server_xpubs.iter())
        .map(|(sid, xpub)| (*sid, xpub.clone()))
        .collect();

    // Empty initial broadcast for round 0 — clients/servers anchor on this.
    let initial_bc = RoundBroadcast {
        round_number: starting_round - 1,
        auction_vector: IbltVector::new(config.auction_slots),
        message_vector: Vec::new(),
    };

    let mut client = ScheduledAdcnetClientSession::new(
        config.clone(),
        client_signing_key,
        client_xk,
        &servers_for_client,
        initial_bc,
        starting_round,
    );
    let mut servers: Vec<ScheduledAdcnetServerSession> = (0..n_servers)
        .map(|i| {
            ScheduledAdcnetServerSession::new(
                config.clone(),
                server_ids[i],
                server_signing[i].clone(),
                server_xks[i].clone(),
                &clients_for_servers,
                starting_round,
            )
        })
        .collect();

    let now = Instant::now();
    let client_anymone_pk = Identity::generate().pubkey();
    let other_anymone_pk = Identity::generate().pubkey();
    let payload = b"hello via scheduled adcnet".to_vec();

    // Stage payload; it'll be bid in cycle 1 and transmitted in cycle 3.
    client.stage_message(payload.clone(), /* bid_value */ 32);

    // --- Cycle 1 (ADCNet round 1 phase A): client sends bid, servers ingest ---
    let out1 = client.begin_round(0, now);
    assert_eq!(out1.len(), 1, "client emits one envelope per cycle");
    for s in servers.iter_mut() {
        for m in &out1 {
            s.on_inbound(client_anymone_pk, m.clone());
        }
    }
    let mid1: Vec<_> = servers.iter_mut().map(|s| s.end_round(0, now)).collect();
    for o in &mid1 {
        assert_eq!(o.outbound.len(), 1, "each server emits its partial");
    }

    // --- Cycle 2 (ADCNet round 1 phase B): cross-feed partials, broadcast ---
    for i in 0..servers.len() {
        for (j, o) in mid1.iter().enumerate() {
            if i == j {
                continue;
            }
            for m in &o.outbound {
                servers[i].on_inbound(other_anymone_pk, m.clone());
            }
        }
    }
    let mid2: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    // At least one server should now have emitted the round-1 broadcast.
    let bc1 = mid2
        .iter()
        .find_map(|o| o.outbound.iter().find(|_| !o.outbound.is_empty()))
        .expect("server should emit the round-1 broadcast");
    // Feed the broadcast into the client so it learns its winning slot.
    client.on_inbound(other_anymone_pk, bc1.clone());

    // --- Cycle 3 (ADCNet round 2 phase A): client sends payload ---
    let out3 = client.begin_round(2, now);
    assert!(!out3.is_empty(), "client emits payload envelope");
    for s in servers.iter_mut() {
        for m in &out3 {
            s.on_inbound(client_anymone_pk, m.clone());
        }
    }
    let mid3: Vec<_> = servers.iter_mut().map(|s| s.end_round(2, now)).collect();

    // --- Cycle 4 (ADCNet round 2 phase B): cross-feed partials, decode ---
    for i in 0..servers.len() {
        for (j, o) in mid3.iter().enumerate() {
            if i == j {
                continue;
            }
            for m in &o.outbound {
                servers[i].on_inbound(other_anymone_pk, m.clone());
            }
        }
    }
    let final_outcomes: Vec<_> = servers.iter_mut().map(|s| s.end_round(3, now)).collect();

    let any = final_outcomes
        .iter()
        .find(|o| !o.decoded.is_empty())
        .expect("at least one server should decode the round-2 broadcast");
    // `extract_payloads` currently returns the full message_vector — search
    // it for our payload bytes (the auction allocates a slot; the rest of
    // the vector is zero-padded).
    let vec = &any.decoded[0];
    let found = (0..vec.len()).any(|start| {
        start + payload.len() <= vec.len() && &vec[start..start + payload.len()] == payload.as_slice()
    });
    assert!(
        found,
        "payload not found in decoded message_vector: {:?}",
        vec
    );
}
