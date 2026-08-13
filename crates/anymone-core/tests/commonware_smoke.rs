//! Layer-1 backbone test: two `CommonwareNetwork` instances on loopback. There
//! is no publish buffering, so publishes are retried until the authenticated
//! connection exists.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::cw::{CommonwareConfig, CommonwareNetwork};
use anymone_core::transport::{NetView, Topic, Transport};
use anymone_core::Identity;

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Publish until the subscriber receives, or fail after `tries`.
async fn publish_until<T: Transport + ?Sized>(
    net: &T,
    sub: &mut anymone_core::Subscription,
    topic: Topic,
    payload: &[u8],
    tries: usize,
) -> anymone_core::Inbound {
    for _ in 0..tries {
        net.publish(topic, payload.to_vec()).await;
        if let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), sub.recv()).await
        {
            return msg;
        }
    }
    panic!("no delivery on {topic} after {tries} attempts");
}

/// Send to `to`'s inbox until it receives, or fail after `tries`.
async fn send_until<T: Transport + ?Sized>(
    net: &T,
    to: anymone_core::Pubkey,
    subnet: u32,
    sub: &mut anymone_core::Subscription,
    payload: &[u8],
    tries: usize,
) -> anymone_core::Inbound {
    for _ in 0..tries {
        net.send(to, subnet, payload.to_vec()).await;
        if let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), sub.recv()).await
        {
            return msg;
        }
    }
    panic!("no direct delivery on subnet {subnet} after {tries} attempts");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_exchange_topics_and_pull_config() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let port_a = portpicker::pick_unused_port().expect("free port");
    let port_b = portpicker::pick_unused_port().expect("free port");

    // Both track the same genesis set, so each accepts the other's handshake.
    // A is the committee: registrations are delivered to it and nobody else.
    let peers = vec![id_a.pubkey(), id_b.pubkey()];
    let net_a = CommonwareNetwork::start(
        &id_a,
        CommonwareConfig {
            listen: addr(port_a),
            dialable: addr(port_a),
            bootstrappers: Vec::new(),
            genesis_peers: peers.clone(),
            committee: vec![id_a.pubkey()],
            local: true,
            stream_listen: None,
            good_clients: anymone_core::GoodClients::all(),
        },
    );
    let net_b = CommonwareNetwork::start(
        &id_b,
        CommonwareConfig {
            listen: addr(port_b),
            dialable: addr(port_b),
            // B dials A, so only B needs a bootstrapper.
            bootstrappers: vec![(id_a.pubkey(), addr(port_a))],
            genesis_peers: peers,
            committee: vec![id_a.pubkey()],
            local: true,
            stream_listen: None,
            good_clients: anymone_core::GoodClients::all(),
        },
    );

    let mut sub_b = net_b.subscribe(Topic::Config).await;
    let mut sub_a = net_a.subscribe(Topic::Config).await;

    let msg = publish_until(&*net_a, &mut sub_b, Topic::Config, b"hello", 60).await;
    assert_eq!(msg.from, id_a.pubkey(), "sender must be authenticated");
    assert_eq!(msg.payload, b"hello");

    // The publisher never receives its own message, which the runtime relies on.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), sub_a.recv())
            .await
            .is_err(),
        "publisher must not receive its own publish"
    );

    // A subnet topic rides a different physical channel than governance.
    let mut data_b = net_b.subscribe(Topic::Shares(0)).await;
    let msg = publish_until(&*net_a, &mut data_b, Topic::Shares(0), b"share-frame", 60).await;
    assert_eq!(msg.payload, b"share-frame");

    // A direct send reaches only the addressee's inbox for that subnet.
    let mut inbox_b = net_b.inbox(7).await;
    let mut inbox_a = net_a.inbox(7).await;
    let msg = send_until(&*net_a, id_b.pubkey(), 7, &mut inbox_b, b"laned", 60).await;
    assert_eq!(msg.from, id_a.pubkey());
    assert_eq!(msg.payload, b"laned");
    let msg = send_until(&*net_b, id_a.pubkey(), 7, &mut inbox_a, b"back", 60).await;
    assert_eq!(msg.from, id_b.pubkey());
    assert_eq!(msg.payload, b"back");
    assert!(
        inbox_b.try_recv().is_none(),
        "a frame addressed to A must not reach B"
    );

    // Config pull: B answers A's request from what it serves.
    net_b.serve_config(b"signed-config".to_vec());
    let mut pulled = None;
    for _ in 0..20 {
        if let Some(bytes) = net_a.fetch_config().await {
            pulled = Some(bytes);
            break;
        }
    }
    assert_eq!(
        pulled.as_deref(),
        Some(&b"signed-config"[..]),
        "config pull must return the peer's served config"
    );

    // Two subscribes on one topic share the local fan-out.
    let mut second = net_b.subscribe(Topic::Config).await;
    let msg = publish_until(&*net_a, &mut second, Topic::Config, b"again", 60).await;
    assert_eq!(msg.payload, b"again");

    // A node outside every tracked set can't join: membership comes from the
    // signed config, so C stays unreachable until A and B track it.
    let id_c = Identity::generate();
    let port_c = portpicker::pick_unused_port().expect("free port");
    let net_c = CommonwareNetwork::start(
        &id_c,
        CommonwareConfig {
            listen: addr(port_c),
            dialable: addr(port_c),
            bootstrappers: vec![(id_a.pubkey(), addr(port_a))],
            genesis_peers: vec![id_a.pubkey(), id_b.pubkey(), id_c.pubkey()],
            committee: vec![id_a.pubkey()],
            local: true,
            stream_listen: None,
            good_clients: anymone_core::GoodClients::all(),
        },
    );
    let mut from_c = net_a.subscribe(Topic::Registration).await;
    for _ in 0..10 {
        net_c
            .publish(Topic::Registration, b"untracked".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        from_c.try_recv().is_none(),
        "an untracked peer must not be able to deliver"
    );

    // Adopting a config that includes C is what admits it.
    let tracked = vec![id_a.pubkey(), id_b.pubkey(), id_c.pubkey()];
    let view = || NetView {
        index: 1,
        primary: tracked.clone(),
        registration_recipients: vec![id_a.pubkey()],
        ..NetView::default()
    };
    net_a.apply(view());
    net_b.apply(view());
    net_c.apply(view());
    let mut reg_b = net_b.subscribe(Topic::Registration).await;
    let msg = publish_until(&*net_c, &mut from_c, Topic::Registration, b"tracked", 80).await;
    assert_eq!(msg.from, id_c.pubkey());
    assert_eq!(msg.payload, b"tracked");
    // Registrations are addressed to the committee, not broadcast: B is a
    // tracked peer yet must not receive them.
    assert!(
        reg_b.try_recv().is_none(),
        "a registration must reach only its named recipients"
    );

    // Reconfiguration drops a worker's subscriptions; a later worker re-opens
    // the same topic and must still receive.
    let topic = Topic::Shares(3);
    let sub = net_b.subscribe(topic).await;
    drop(sub);
    let mut resubscribed = net_b.subscribe(topic).await;
    let msg = publish_until(&*net_a, &mut resubscribed, topic, b"after-resubscribe", 80).await;
    assert_eq!(
        msg.payload, b"after-resubscribe",
        "a re-subscribed topic must still receive"
    );
}
