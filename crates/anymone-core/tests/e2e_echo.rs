//! M5 end-to-end demo: the full stack on the in-memory transport.
//!
//! Nodes are brought up from a static signed config (`singleton_subnet` +
//! `start_with_config`) rather than a scheduler: three relays + an echo service
//! + a client all adopt the same Noop subnet. The client opens a pipe to the
//! service, sends a message, and gets it back.
//!
//! Timer-free orchestration: every node subscribes (synchronously, inside
//! `start_with_config`) before the client's first send. The registration →
//! committee → config path is exercised by the committee-scheduler tests.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::config::{NoopConfig, ProtocolConfig, ServiceEntry};
use anymone_core::test_util::Node;
use anymone_core::{AnymoneRoundConfiguration, InMemoryNetwork, ServiceTag};

const ECHO_TAG: ServiceTag = ServiceTag::from_bytes([
    b'a', b'n', b'y', b'm', b'o', b'n', b'e', b'.', b'e', b'c', b'h', b'o', 0, 0, 0, 0, 0, 0, 0, 0,
]);

#[tokio::test(flavor = "multi_thread")]
async fn e2e_echo_over_static_subnet() {
    let net = InMemoryNetwork::new();

    let relays: Vec<Node> = (0..3).map(|_| Node::fresh(&net)).collect();
    let service = Node::fresh(&net);
    let client = Node::fresh(&net);

    let relay_pks = relays.iter().map(|n| n.pubkey()).collect();
    let services = vec![ServiceEntry { tag: ECHO_TAG, pubkey: service.pubkey() }];
    let protocol = ProtocolConfig::Noop(NoopConfig {
        round_duration_ms: 30,
        message_size: 1024,
        client_set_min: 0,
        client_set_max: 256,
    });
    let config = AnymoneRoundConfiguration::singleton_subnet(0, protocol, relay_pks, services);

    // Start everyone (subscribes synchronously); service before client so the
    // service's subnet subscription is in place before the first send.
    let mut relay_nodes = Vec::new();
    for r in relays {
        relay_nodes.push(r.start_with_config(config.clone()).await);
    }
    let service_node = service.start_with_config(config.clone()).await;
    let client_node = client.start_with_config(config.clone()).await;

    // Echo service.
    let mut svc_pipe = service_node.anymone().bind(ECHO_TAG).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // Client send/recv.
    let mut pipe = client_node.anymone().open(ECHO_TAG).await.unwrap();
    pipe.send(b"hello".to_vec()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), pipe.recv())
        .await
        .expect("recv timed out")
        .expect("pipe closed");
    assert_eq!(reply.payload, b"hello");

    drop(relay_nodes);
    drop(service_node);
    drop(client_node);
}
