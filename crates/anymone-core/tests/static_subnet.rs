//! Stage-2 test: one committee member publishes a hand-crafted signed
//! `AnymoneRoundConfiguration` on the governance topic; relayers, the
//! service, and the client all pick it up over the same in-memory transport
//! and run a Noop echo round-trip.
//!
//! No scheduling routine, no registration — just identity + bootstrap +
//! governance ingest + runtime + Pipe + Noop sessions, end-to-end through
//! the topic. Timer-free: subscriptions are set up sequentially in phase 1
//! and the config publish happens in phase 2.

#![cfg(feature = "test-util")]

use std::sync::Arc;
use std::time::Duration;

use anymone_core::test_util::Node;
use anymone_core::{
    AnymoneRoundConfiguration, GovernanceBootstrap, InMemoryNetwork, NoopConfig, ProtocolConfig,
    ServiceEntry, ServiceTag, Subnet, Transport, TOPIC_CONFIG,
};

fn echo_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.echo")
}

#[tokio::test(flavor = "multi_thread")]
async fn echo_via_governance_topic() {
    let net = InMemoryNetwork::new();

    let mut committee = Node::fresh(&net);
    let mut relays: Vec<Node> = (0..3).map(|_| Node::fresh(&net)).collect();
    let mut service = Node::fresh(&net);
    let mut client = Node::fresh(&net);

    let committee_pk = committee.pubkey();
    let bootstrap = GovernanceBootstrap {
        committee: vec![committee_pk],
        threshold: 1,
    };

    // Build and sign the static configuration. One subnet, Noop, with all
    // three relays and the echo service.
    let mut unsigned = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        relays.iter().map(|r| r.pubkey()).collect(),
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service.pubkey(),
        }],
    );
    // A malformed (empty-relay) subnet in the signed config must be skipped, not
    // panic the runtime — the echo below still round-trips on subnet 0.
    unsigned.body.subnets.push(Subnet {
        id: 1,
        relays: vec![],
        protocol: ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        cover_rate: 1.0,
    });
    let signed_cfg = unsigned.sign_with(&[committee.identity()]);
    let signed_bytes = bincode::serialize(&signed_cfg).expect("serialise cfg");

    // Phase 1: every node subscribes to anymone/config synchronously.
    let mut relay_preps = Vec::new();
    for r in relays.iter_mut() {
        relay_preps.push(r.prepare_as_participant(bootstrap.clone()).await);
    }
    let service_prep = service.prepare_as_participant(bootstrap.clone()).await;
    let client_prep = client.prepare_as_participant(bootstrap.clone()).await;

    // Phase 2: committee publishes the signed config once. All subscribers
    // above are already in place so the message reaches them.
    let committee_transport: Arc<dyn Transport> = Arc::new(net.handle(committee_pk));
    committee_transport
        .publish(TOPIC_CONFIG, signed_bytes)
        .await;

    // Phase 3: each prep awaits the config it just received and starts its
    // subnet runtime. Run all starts concurrently.
    let mut start_handles = Vec::new();
    for p in relay_preps {
        start_handles.push(tokio::spawn(async move { p.start().await.unwrap() }));
    }
    let service_h = tokio::spawn(async move { service_prep.start().await.unwrap() });
    let client_h = tokio::spawn(async move { client_prep.start().await.unwrap() });

    let mut relay_nodes = Vec::new();
    for h in start_handles {
        relay_nodes.push(h.await.unwrap());
    }
    let service_node = service_h.await.unwrap();
    let client_node = client_h.await.unwrap();

    // Echo loop on the service.
    let mut svc_pipe = service_node.anymone().bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_node.anymone().open(echo_tag()).await.unwrap();
    pipe.send(b"hello".to_vec()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), pipe.recv())
        .await
        .expect("recv timed out")
        .expect("pipe closed");
    assert_eq!(reply.payload, b"hello");

    drop(relay_nodes);
    drop(service_node);
    drop(client_node);
    drop(committee);
}
