//! Full Anymone echo round-trips over the in-memory transport, one test per
//! protocol (Noop, Panetiere). Five instances in one process — 1 service, 3
//! relays, 1 client — share an `InMemoryNetwork`; the governance topic is
//! bypassed (see `static_subnet.rs` for that). ADCNet echo lives in
//! `in_memory_echo_adcnet.rs` alongside its reconfiguration tests.

use std::sync::Arc;
use std::time::Duration;

use anymone_core::{
    Anymone, AnymoneRoundConfiguration, Identity, InMemoryNetwork, NoopConfig, PanetiereConfig,
    ProtocolConfig, Pubkey, ServiceEntry, ServiceTag,
};

fn echo_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.echo")
}

fn noop_config(
    committee: &Identity,
    relays: &[Identity],
    service_pk: Pubkey,
) -> AnymoneRoundConfiguration {
    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        relays.iter().map(|i| i.pubkey()).collect(),
        vec![],
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service_pk,
        }],
    )
    .sign_with(&[committee])
}

fn panetiere_config(
    committee: &Identity,
    relays: &[Identity],
    service_pk: Pubkey,
) -> AnymoneRoundConfiguration {
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let relay_xk = relays
        .iter()
        .map(|i| (i.pubkey(), i.exchange_keys()))
        .collect();
    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 250,
            message_size: 1024,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7u8; 32],
            encoding: anymone_core::config::Encoding::default(),
        }),
        relay_pks,
        relay_xk,
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service_pk,
        }],
    )
    .sign_with(&[committee])
}

/// Stand up 3 relays + service + client under `cfg`, run the echo service, send
/// `msg`, and return the reply as delivered (payload plus its decode round).
async fn echo_roundtrip(
    cfg: AnymoneRoundConfiguration,
    relays: Vec<Identity>,
    service: Identity,
    client: Identity,
    msg: &[u8],
    timeout: Duration,
) -> anymone_core::PipeIncoming {
    let net = InMemoryNetwork::new();
    let mut anymones: Vec<Anymone> = Vec::new();
    for id in relays {
        anymones.push(
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await,
        );
    }
    let service_anymone = Anymone::start_with_config(
        service.clone(),
        Arc::new(net.handle(service.pubkey())),
        cfg.clone(),
    )
    .await;
    let client_anymone = Anymone::start_with_config(
        client.clone(),
        Arc::new(net.handle(client.pubkey())),
        cfg.clone(),
    )
    .await;

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
    reply
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread")]
async fn noop_echo_roundtrip() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = noop_config(&committee, &relays, service.pubkey());
    let reply = echo_roundtrip(
        cfg,
        relays,
        service,
        client,
        b"hello",
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(reply.payload, b"hello");
    // The round the reply decoded in: an echo needs the request's round plus a
    // later one, so it can never be the genesis round the clock starts at.
    assert!(reply.round > 0, "delivery round not tracked");
}

#[serial_test::serial]
#[tokio::test(flavor = "multi_thread")]
async fn panetiere_echo_roundtrip() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = panetiere_config(&committee, &relays, service.pubkey());
    let reply = echo_roundtrip(
        cfg,
        relays,
        service,
        client,
        b"hello panetiere",
        // Headroom for the suite's parallel test binaries starving the rounds.
        Duration::from_secs(25),
    )
    .await;
    assert_eq!(&reply.payload[..15], b"hello panetiere");
    assert!(reply.round > 0, "delivery round not tracked");
}

/// A payload too big for one subnet message is rejected up front, not silently
/// truncated/dropped downstream.
#[serial_test::serial]
#[tokio::test(flavor = "multi_thread")]
async fn oversized_send_is_rejected() {
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let cfg = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 30,
            message_size: 64,
            client_set_min: 0,
            client_set_max: 256,
        }),
        relays.iter().map(|i| i.pubkey()).collect(),
        vec![],
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service.pubkey(),
        }],
    )
    .sign_with(&[&committee]);

    let net = InMemoryNetwork::new();
    let client_anymone =
        Anymone::start_with_config(client.clone(), Arc::new(net.handle(client.pubkey())), cfg)
            .await;
    let pipe = client_anymone.open(echo_tag()).await.unwrap();
    let err = pipe.send(vec![0u8; 500]).await.unwrap_err();
    assert!(
        matches!(err, anymone_core::SendError::PayloadTooLarge { .. }),
        "expected PayloadTooLarge, got {err:?}"
    );

    // max_message_payload's boundary matches the real send-time check exactly:
    // one byte over is rejected, right at the limit succeeds.
    let max = anymone_core::max_message_payload(64);
    pipe.send(vec![0u8; max])
        .await
        .expect("payload at the limit must fit");
    let err = pipe.send(vec![0u8; max + 1]).await.unwrap_err();
    assert!(
        matches!(err, anymone_core::SendError::PayloadTooLarge { .. }),
        "expected PayloadTooLarge, got {err:?}"
    );
}

/// `subscribe` registers a tag receiver without owning it: a message to the tag
/// reaches every subscriber, not just one owner.
#[serial_test::serial]
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
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await,
        );
    }
    let alice_anymone = Anymone::start_with_config(
        alice.clone(),
        Arc::new(net.handle(alice.pubkey())),
        cfg.clone(),
    )
    .await;
    let bob_anymone =
        Anymone::start_with_config(bob.clone(), Arc::new(net.handle(bob.pubkey())), cfg.clone())
            .await;

    let alice_pipe = alice_anymone.subscribe(echo_tag()).await.unwrap();
    let mut bob_pipe = bob_anymone.subscribe(echo_tag()).await.unwrap();

    // A read-only member reads the room but cannot transmit, so it contributes
    // no cover and stays out of the anonymity set.
    let carol = Identity::generate();
    let carol_anymone = Anymone::start_with_config(
        carol.clone(),
        Arc::new(net.handle(carol.pubkey())),
        cfg.clone(),
    )
    .await;
    let mut carol_pipe = carol_anymone.listen(echo_tag()).await.unwrap();
    assert!(matches!(
        carol_pipe.send(b"not allowed".to_vec()).await.unwrap_err(),
        anymone_core::SendError::NoPeerTag
    ));

    alice_pipe.send(b"hi room".to_vec()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(2), bob_pipe.recv())
        .await
        .expect("bob recv timed out")
        .expect("pipe closed");
    assert_eq!(got.payload, b"hi room");
    assert_eq!(got.return_tag, alice_pipe.return_tag());

    let seen = tokio::time::timeout(Duration::from_secs(2), carol_pipe.recv())
        .await
        .expect("carol recv timed out")
        .expect("pipe closed");
    assert_eq!(seen.payload, b"hi room", "a listener still receives");

    // send_unlinkable: two sends from the same pipe carry different, random
    // return tags, neither equal to the pipe's own — bus traffic can't be
    // linked back to the sender or to each other via the return path.
    alice_pipe
        .send_unlinkable(b"anon 1".to_vec())
        .await
        .unwrap();
    let anon1 = tokio::time::timeout(Duration::from_secs(2), bob_pipe.recv())
        .await
        .expect("bob recv timed out")
        .expect("pipe closed");
    alice_pipe
        .send_unlinkable(b"anon 2".to_vec())
        .await
        .unwrap();
    let anon2 = tokio::time::timeout(Duration::from_secs(2), bob_pipe.recv())
        .await
        .expect("bob recv timed out")
        .expect("pipe closed");
    assert_eq!(anon1.payload, b"anon 1");
    assert_eq!(anon2.payload, b"anon 2");
    assert_ne!(anon1.return_tag, alice_pipe.return_tag());
    assert_ne!(anon2.return_tag, alice_pipe.return_tag());
    assert_ne!(anon1.return_tag, anon2.return_tag);

    drop(anymones);
}
