//! Full Anymone echo round-trips over the in-memory transport, one test per
//! protocol (Noop, Panetiere). Five instances in one process — 1 service, 3
//! relays, 1 client — share an `InMemoryNetwork`; the governance topic is
//! bypassed (see `static_subnet.rs` for that). ADCNet echo lives in
//! `in_memory_echo_adcnet.rs` alongside its reconfiguration tests.

use std::sync::Arc;
use std::time::Duration;

use anymone_core::{
    Anymone, AnymoneRoundConfiguration, PanetiereConfig, Identity, InMemoryNetwork, NoopConfig,
    ProtocolConfig, Pubkey, ServiceEntry, ServiceTag,
};

fn echo_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.echo")
}

fn noop_config(committee: &Identity, relays: &[Identity], service_pk: Pubkey) -> AnymoneRoundConfiguration {
    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        relays.iter().map(|i| i.pubkey()).collect(),
        vec![ServiceEntry { tag: echo_tag(), pubkey: service_pk }],
    )
    .sign_with(&[committee])
}

fn panetiere_config(committee: &Identity, relays: &[Identity], service_pk: Pubkey) -> AnymoneRoundConfiguration {
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let relay_xk = relays
        .iter()
        .map(|i| {
            (i.pubkey(), anymone_core::config::ExchangePublicKeyWire::from_key(&i.exchange_pubkey()))
        })
        .collect();
    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 250,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7u8; 32],
            relay_exchange_keys: relay_xk,
            aggregation: None,
        }),
        relay_pks,
        vec![ServiceEntry { tag: echo_tag(), pubkey: service_pk }],
    )
    .sign_with(&[committee])
}

/// Stand up 3 relays + service + client under `cfg`, run the echo service, send
/// `msg`, and return the reply payload.
async fn echo_roundtrip(cfg: AnymoneRoundConfiguration, relays: Vec<Identity>, service: Identity, client: Identity, msg: &[u8], timeout: Duration) -> Vec<u8> {
    let net = InMemoryNetwork::new();
    let mut anymones: Vec<Anymone> = Vec::new();
    for id in relays {
        anymones.push(Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone()).await);
    }
    let service_anymone =
        Anymone::start_with_config(service.clone(), Arc::new(net.handle(service.pubkey())), cfg.clone()).await;
    let client_anymone =
        Anymone::start_with_config(client.clone(), Arc::new(net.handle(client.pubkey())), cfg.clone()).await;

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_anymone.open(echo_tag()).await.unwrap();
    pipe.send(msg.to_vec()).await.unwrap();
    let reply = tokio::time::timeout(timeout, pipe.recv())
        .await
        .expect("recv timed out")
        .expect("pipe closed");
    drop(anymones);
    reply.payload
}

#[tokio::test(flavor = "multi_thread")]
async fn noop_echo_roundtrip() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = noop_config(&committee, &relays, service.pubkey());
    let reply = echo_roundtrip(cfg, relays, service, client, b"hello", Duration::from_secs(2)).await;
    assert_eq!(reply, b"hello");
}

#[tokio::test(flavor = "multi_thread")]
async fn panetiere_echo_roundtrip() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = panetiere_config(&committee, &relays, service.pubkey());
    let reply = echo_roundtrip(cfg, relays, service, client, b"hello panetiere", Duration::from_secs(15)).await;
    assert_eq!(&reply[..15], b"hello panetiere");
}

/// `subscribe` registers a tag receiver without owning it: a message to the tag
/// reaches every subscriber, not just one owner.
#[tokio::test(flavor = "multi_thread")]
async fn subscribe_delivers_broadcast_to_participants() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let alice = Identity::generate();
    let bob = Identity::generate();
    let cfg = noop_config(&committee, &relays, service.pubkey());

    let net = InMemoryNetwork::new();
    let mut anymones: Vec<Anymone> = Vec::new();
    for id in &relays {
        anymones.push(
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone()).await,
        );
    }
    let alice_anymone =
        Anymone::start_with_config(alice.clone(), Arc::new(net.handle(alice.pubkey())), cfg.clone()).await;
    let bob_anymone =
        Anymone::start_with_config(bob.clone(), Arc::new(net.handle(bob.pubkey())), cfg.clone()).await;

    let alice_pipe = alice_anymone.subscribe(echo_tag()).await.unwrap();
    let mut bob_pipe = bob_anymone.subscribe(echo_tag()).await.unwrap();

    alice_pipe.send(b"hi room".to_vec()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), bob_pipe.recv())
        .await
        .expect("bob recv timed out")
        .expect("pipe closed");
    assert_eq!(got.payload, b"hi room");
    drop(anymones);
}
