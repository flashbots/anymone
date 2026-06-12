//! Layer-1 component test for the scheduler.
//!
//! Just spawn_committee_scheduler + a single publisher node. Asserts that
//! after publishing the right registrations, a valid signed config shows up
//! on `anymone/config`.

#![cfg(feature = "test-util")]

use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::scheduling::{
    announce_relay_registration, announce_service_registration, spawn_committee_scheduler,
    SchedulerConfig,
};
use anymone_core::{
    AnymoneRoundConfiguration, Identity, InMemoryNetwork, ServiceTag, Transport, TOPIC_CONFIG,
};

fn xk(id: &Identity) -> ExchangePublicKeyWire {
    ExchangePublicKeyWire::from_key(&id.exchange_pubkey())
}

#[tokio::test(flavor = "multi_thread")]
async fn scheduler_publishes_config_after_quorum() {
    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let committee_pk = committee.pubkey();
    let relay_a = Identity::generate();
    let relay_b = Identity::generate();
    let service = Identity::generate();
    let echo_tag = ServiceTag::from_label("anymone.echo");

    let scheduler_transport: Arc<dyn Transport> = Arc::new(net.handle(committee_pk));
    let publisher_transport: Arc<dyn Transport> = Arc::new(net.handle(relay_a.pubkey()));
    let observer_transport: Arc<dyn Transport> = Arc::new(net.handle(Identity::generate().pubkey()));

    // Observer subscribes first so it'll see the scheduler's eventual publish.
    let mut config_sub = observer_transport.subscribe(TOPIC_CONFIG).await;
    eprintln!("[test] observer subscribed");

    // Scheduler subscribes synchronously to TOPIC_REGISTRATION inside this call.
    let scheduler_handle = spawn_committee_scheduler(
        scheduler_transport,
        committee,
        SchedulerConfig {
            min_relays: 2,
            min_services: 1,
            subnet_round_duration: Duration::from_millis(30),
            protocol: anymone_core::SchedulerProtocol::Noop,
        },
    )
    .await;
    eprintln!("[test] scheduler spawned");

    // Now safe to publish registrations.
    announce_relay_registration(publisher_transport.clone(), &relay_a, xk(&relay_a)).await;
    eprintln!("[test] published relay_a");
    announce_relay_registration(publisher_transport.clone(), &relay_b, xk(&relay_b)).await;
    eprintln!("[test] published relay_b");
    announce_service_registration(publisher_transport.clone(), &service, echo_tag, xk(&service)).await;
    eprintln!("[test] published service");

    // Wait for the config to appear.
    let msg = tokio::time::timeout(Duration::from_secs(2), config_sub.recv())
        .await
        .expect("config never arrived")
        .expect("subscription closed");
    eprintln!("[test] got config message, {} bytes", msg.payload.len());

    let cfg: AnymoneRoundConfiguration = bincode::deserialize(&msg.payload).expect("decode cfg");
    cfg.verify_multisig(&[committee_pk], 1).expect("multisig verifies");

    let subnet = &cfg.body.subnets[0];
    assert_eq!(subnet.relays.len(), 2);
    assert_eq!(subnet.services.len(), 1);
    assert_eq!(subnet.services[0].tag, echo_tag);

    scheduler_handle.abort();
}
