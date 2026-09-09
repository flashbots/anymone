use std::time::Instant;

use adcnet::auction::iblt::IbltVector;
use adcnet::crypto::ServerId;
use adcnet::protocol::{AdcNetConfig, AggregationMode, RoundBroadcast};
use anymone_core::adcnet::{
    ScheduledAdcnetClientSession, ScheduledAdcnetServerSession, ScheduledAdcnetWatchSession,
};
use anymone_core::config::ScheduledAdcnetConfig;
use anymone_core::session::Session;
use anymone_core::Identity;

#[test]
fn scheduled_adcnet_session_happy_path() {
    let identities: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
    let leader = identities[0].pubkey();
    let peers: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| (ServerId(i as u32), id.to_adcnet_public_key()))
        .collect();
    let exchanges: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| (ServerId(i as u32), id.exchange_pubkey()))
        .collect();
    let config = AdcNetConfig {
        auction_slots: 16,
        message_length: 1024,
        aggregation: AggregationMode::Disabled,
        ..Default::default()
    };
    let client_identity = Identity::generate();
    let exchange = |id: &Identity| {
        adcnet::crypto::ExchangePrivateKey::from_bytes(&id.exchange().scalar_bytes()).unwrap()
    };
    let mut client = ScheduledAdcnetClientSession::new(
        config.clone(),
        client_identity.to_adcnet_signing_key(),
        exchange(&client_identity),
        &exchanges,
        RoundBroadcast {
            round_number: 0,
            auction_vector: IbltVector::new(16),
            message_vector: Vec::new(),
        },
        1,
        leader,
    );
    let mut servers: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| {
            ScheduledAdcnetServerSession::new(
                config.clone(),
                ServerId(i as u32),
                id.to_adcnet_signing_key(),
                exchange(id),
                &[],
                &peers,
                1,
                leader,
            )
        })
        .collect();
    let mut watcher = ScheduledAdcnetWatchSession::new(
        &ScheduledAdcnetConfig {
            round_duration_ms: 200,
            message_length: 1024,
            auction_slots: 16,
            min_message_size: 1,
            client_set_min: 0,
            client_set_max: 8,
        },
        leader,
    );
    client.stage(b"first".to_vec());
    client.stage(b"second".to_vec());
    let mut decoded = Vec::new();
    let now = Instant::now();
    for round in 0..4 {
        watcher.begin_round(round, now);
        let outgoing = client.begin_round(round, now);
        if round > 0 {
            for bytes in &outgoing {
                servers[0].on_inbound(client_identity.pubkey(), bytes.clone());
            }
        }
        for server in &mut servers {
            server.begin_round(round, now);
        }
        if round == 0 {
            for bytes in outgoing {
                servers[0].on_inbound(client_identity.pubkey(), bytes);
            }
        }
        let sets = servers[0].checkpoint(round, 1, now);
        let mut partials = Vec::new();
        for server in &mut servers {
            for set in &sets {
                partials.extend(server.on_inbound(leader, set.clone()));
            }
        }
        let mut broadcasts = Vec::new();
        for bytes in partials {
            broadcasts.extend(servers[0].on_inbound(leader, bytes));
        }
        broadcasts.extend(servers[0].end_round(round, now).outbound);
        for bytes in broadcasts {
            client.on_inbound(leader, bytes.clone());
            watcher.on_inbound(leader, bytes.clone());
            for server in &mut servers {
                server.on_inbound(leader, bytes.clone());
            }
        }
        decoded.extend(watcher.end_round(round, now).decoded);
    }
    assert_eq!(decoded.len(), 2);
    for (actual, expected) in decoded
        .iter()
        .zip([b"first".as_slice(), b"second".as_slice()])
    {
        assert!(actual.starts_with(expected));
        assert!(actual[expected.len()..].iter().all(|b| *b == 0));
    }
    assert!(!client.has_pending_transmissions());
}
