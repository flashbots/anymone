//! M5 end-to-end demo: the full stack on the in-memory transport.
//!
//! - One committee node runs `spawn_committee_scheduler`, watching
//!   `anymone/registration`.
//! - Three relayers and one echo service publish registrations and start as
//!   participants.
//! - The committee builds the first `AnymoneRoundConfiguration` from the
//!   registrations it observes, signs it, and publishes on `anymone/config`.
//! - The client opens a pipe to the echo service, sends a message, and gets
//!   the same message back.
//!
//! Timer-free orchestration: every subscriber subscribes in phase 1 before
//! any publisher fires in phase 2. libp2p as the transport is still deferred
//! — `InMemoryNetwork` stands in.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::scheduling::SchedulerConfig;
use anymone_core::test_util::Node;
use anymone_core::{GovernanceBootstrap, InMemoryNetwork, ServiceTag};

const ECHO_TAG: ServiceTag = ServiceTag::from_bytes([
    b'a', b'n', b'y', b'm', b'o', b'n', b'e', b'.', b'e', b'c', b'h', b'o', 0, 0, 0, 0, 0, 0, 0, 0,
]);

#[tokio::test(flavor = "multi_thread")]
async fn e2e_echo_with_real_scheduling() {
    let net = InMemoryNetwork::new();

    let mut committee = Node::fresh(&net);
    let mut relays: Vec<Node> = (0..3).map(|_| Node::fresh(&net)).collect();
    let mut service = Node::fresh(&net);
    let mut client = Node::fresh(&net);

    let bootstrap = GovernanceBootstrap {
        committee: vec![committee.pubkey()],
        threshold: 1,
    };
    let scheduler_cfg = SchedulerConfig {
        min_relays: 3,
        min_services: 1,
        subnet_round_duration: Duration::from_millis(30),
        protocol: anymone_core::SchedulerProtocol::Noop,
    };

    // Phase 1 — sequential subscriptions. Committee subscribes to
    // `anymone/registration` (via the scheduler) AND to `anymone/config`
    // (via its own Anymone prep). The relays/service/client each subscribe
    // to `anymone/config`. Service/relays carry a deferred registration
    // that gets published in phase 2.
    let committee_prep = committee
        .prepare_as_committee(bootstrap.clone(), scheduler_cfg)
        .await;
    let mut relay_preps = Vec::new();
    for r in relays.iter_mut() {
        relay_preps.push(r.prepare_as_relay(bootstrap.clone()).await);
    }
    let service_prep = service
        .prepare_as_service(bootstrap.clone(), ECHO_TAG)
        .await;
    let client_prep = client.prepare_as_participant(bootstrap.clone()).await;

    // Phase 2+3 — start every node concurrently. `NodePrep::start` publishes
    // any deferred registration first (now that the committee scheduler is
    // already subscribed), then awaits the first signed config and brings up
    // the subnet runtime.
    let committee_h = tokio::spawn(async move { committee_prep.start().await.unwrap() });
    let relay_handles: Vec<_> = relay_preps
        .into_iter()
        .map(|p| tokio::spawn(async move { p.start().await.unwrap() }))
        .collect();
    let service_h = tokio::spawn(async move { service_prep.start().await.unwrap() });
    let client_h = tokio::spawn(async move { client_prep.start().await.unwrap() });

    let committee_node = committee_h.await.unwrap();
    let mut relay_nodes = Vec::new();
    for h in relay_handles {
        relay_nodes.push(h.await.unwrap());
    }
    let service_node = service_h.await.unwrap();
    let client_node = client_h.await.unwrap();

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
    drop(committee_node);
}
