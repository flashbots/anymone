//! A relay that leads one `ADCNet` subnet sees every client contribution sent to
//! it. Nothing in a contribution binds it to that subnet, so the relay can
//! forward it to another subnet's leader in the same round. If the other
//! subnet accepts it, the payload decodes on both subnets, and the client is
//! the only member of both rounds' client sets — which links it to the payload.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{
    now_unix_ms, AdcnetConfig, AnymoneRoundConfigurationBody, AttestationPolicy, Subnet,
};
use anymone_core::discovery::Endpoints;
use anymone_core::runtime::{subnet_leader_pk, Event};
use anymone_core::transport::Transport;
use anymone_core::{
    Anymone, AnymoneRoundConfiguration, Identity, InMemoryNetwork, ProtocolConfig, ServiceEntry,
    ServiceTag,
};
use serial_test::serial;

fn tag() -> ServiceTag {
    ServiceTag::from_label("anymone.replay")
}

fn adcnet() -> ProtocolConfig {
    ProtocolConfig::Adcnet(AdcnetConfig {
        round_duration_ms: 200,
        max_payload_bytes: 1024,
        estimated_messages: 8,
        client_set_min: 0,
        client_set_max: 8,
        aggregation: None,
    })
}

fn two_subnet_config(
    committee: &Identity,
    relays: &[Identity],
    service: &Identity,
) -> AnymoneRoundConfiguration {
    let mut relay_pks: Vec<_> = relays.iter().map(Identity::pubkey).collect();
    relay_pks.sort();
    let mut relay_exchange_keys: Vec<_> = relays
        .iter()
        .map(|i| (i.pubkey(), i.exchange_keys()))
        .collect();
    relay_exchange_keys.sort_by_key(|(pk, _)| *pk);
    let body = AnymoneRoundConfigurationBody {
        endpoints: Endpoints::default(),
        round: 0,
        epoch_unix_ms: now_unix_ms(),
        services: vec![ServiceEntry {
            tag: tag(),
            pubkey: service.pubkey(),
        }],
        relay_exchange_keys,
        subnets: vec![
            Subnet::new(0, relay_pks.clone(), adcnet()),
            Subnet::new(1, relay_pks, adcnet()),
        ],
        relay_client_addrs: Vec::new(),
        watchers: Vec::new(),
        attestation: AttestationPolicy::default(),
    };
    AnymoneRoundConfiguration::new(body).sign_with(&[committee])
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn adcnet_contribution_replayed_to_another_subnet_is_rejected() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = two_subnet_config(&committee, &relays, &service);

    let relay_pks: Vec<_> = relays.iter().map(Identity::pubkey).collect();
    let leaders = [
        subnet_leader_pk(&cfg.body.subnets[0]),
        subnet_leader_pk(&cfg.body.subnets[1]),
    ];
    assert_ne!(leaders[0], leaders[1], "each subnet needs its own leader");

    // The malicious relay: it reads what clients send to the leader it controls
    // and forwards each contribution to the other subnet's leader.
    for (from_subnet, to_subnet) in [(0u32, 1u32), (1, 0)] {
        let leader = leaders[from_subnet as usize];
        let mut tap = net.handle(leader).inbox(from_subnet).await;
        let forwarder = net.handle(leader);
        let target = leaders[to_subnet as usize];
        let relay_pks = relay_pks.clone();
        tokio::spawn(async move {
            while let Some(msg) = tap.recv().await {
                if relay_pks.contains(&msg.from) {
                    continue;
                }
                forwarder.send(target, to_subnet, msg.payload).await;
            }
        });
    }

    let mut nodes: Vec<Anymone> = Vec::new();
    for id in relays {
        let handle = net.handle(id.pubkey());
        nodes.push(Anymone::start_with_config(id, Arc::new(handle), cfg.clone()).await);
    }
    let service_node = Anymone::start_with_config(
        service.clone(),
        Arc::new(net.handle(service.pubkey())),
        cfg.clone(),
    )
    .await;
    let client_node = Anymone::start_with_config(
        client.clone(),
        Arc::new(net.handle(client.pubkey())),
        cfg.clone(),
    )
    .await;

    let mut events = service_node.events();
    let mut service_pipe = service_node.bind(tag()).await.unwrap();
    let client_pipe = client_node.open(tag()).await.unwrap();
    client_pipe.send(b"who sent this?".to_vec()).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(15), service_pipe.recv())
        .await
        .expect("the payload was never delivered")
        .expect("service pipe closed");
    assert_eq!(first.payload, b"who sent this?");

    let mut deliveries = vec![first.round];
    let mut decoded_on: HashMap<u64, Vec<u32>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            Some(msg) = service_pipe.recv() => {
                if msg.payload == b"who sent this?" {
                    deliveries.push(msg.round);
                }
            }
            Ok(event) = events.recv() => {
                if let Event::RoundDecoded { round, subnet, .. } = event {
                    decoded_on.entry(round).or_default().push(subnet);
                }
            }
        }
    }

    assert_eq!(
        deliveries.len(),
        1,
        "the payload was decoded {} times (rounds {deliveries:?}); subnets that decoded \
         something in those rounds: {:?}",
        deliveries.len(),
        deliveries
            .iter()
            .map(|r| (r, decoded_on.get(r)))
            .collect::<Vec<_>>(),
    );

    drop(nodes);
    drop(client_node);
}
