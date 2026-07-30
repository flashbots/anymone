//! The client plane: a client that never joins the p2p backbone still submits
//! through a node and receives what that node publishes.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::cw::{
    CommonwareConfig, CommonwareNetwork, StreamClientConfig, StreamClientNetwork,
};
use anymone_core::transport::Transport;
use anymone_core::{GoodClients, Identity};

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn node(id: &Identity, port: u16, stream_port: u16, good: GoodClients) -> CommonwareConfig {
    CommonwareConfig {
        listen: addr(port),
        dialable: addr(port),
        bootstrappers: Vec::new(),
        genesis_peers: vec![id.pubkey()],
        local: true,
        stream_listen: Some(addr(stream_port)),
        good_clients: good,
    }
}

async fn recv_soon(
    sub: &mut anymone_core::Subscription,
    label: &str,
) -> anymone_core::Inbound {
    tokio::time::timeout(Duration::from_secs(10), sub.recv())
        .await
        .unwrap_or_else(|_| panic!("{label}: nothing arrived"))
        .expect("subscription closed")
}

#[tokio::test(flavor = "multi_thread")]
async fn client_submits_and_receives_over_a_stream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let relay = Identity::generate();
    let client = Identity::generate();
    let p2p_port = portpicker::pick_unused_port().expect("free port");
    let stream_port = portpicker::pick_unused_port().expect("free port");

    let net = CommonwareNetwork::start(
        &relay,
        node(&relay, p2p_port, stream_port, GoodClients::all()),
    );
    // The relay's own session is what must see the client's contribution.
    let mut ingress = net.subscribe("anymone/subnet/0/ingress").await;
    net.serve_config(b"the-signed-config".to_vec());

    let client_net = StreamClientNetwork::start(
        &client,
        StreamClientConfig {
            servers: vec![(relay.pubkey(), addr(stream_port))],
        },
    );

    // Pulling the config over the stream is how a client learns the network.
    let mut pulled = None;
    for _ in 0..20 {
        if let Some(bytes) = client_net.fetch_config().await {
            pulled = Some(bytes);
            break;
        }
    }
    assert_eq!(pulled.as_deref(), Some(&b"the-signed-config"[..]));

    // Submitted client traffic reaches the relay tagged with the client's own
    // key, not the relay's — origin survives the forward.
    let mut got = None;
    for _ in 0..20 {
        client_net
            .publish("anymone/subnet/0/ingress", b"client-public".to_vec())
            .await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), ingress.recv()).await
        {
            got = Some(msg);
            break;
        }
    }
    let msg = got.expect("client submission never reached the relay");
    assert_eq!(msg.from, client.pubkey(), "the client is the origin");
    assert_eq!(msg.payload, b"client-public");

    // The relay's own broadcast reaches the client, which the backbone alone
    // could never do: a publisher is not delivered its own message.
    let mut feed = client_net.subscribe("anymone/subnet/0").await;
    let mut delivered = None;
    for _ in 0..20 {
        net.publish("anymone/subnet/0", b"decoded-round".to_vec()).await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), feed.recv()).await {
            delivered = Some(msg);
            break;
        }
    }
    let msg = delivered.expect("relay broadcast never reached the client");
    assert_eq!(msg.from, relay.pubkey(), "frames are attributed to the node");
    assert_eq!(msg.payload, b"decoded-round");

    // A roster-bound topic is closed to clients. Forwarding would put the frame
    // on the wire under the relay's key — which IS in the roster — so admission
    // downstream would pass and the roster would mean nothing.
    let mut policy = anymone_core::transport::TopicPolicy::new();
    policy.insert(
        "anymone/subnet/0".to_string(),
        std::collections::HashSet::from([relay.pubkey()]),
    );
    net.set_topic_policy(policy);
    let mut bound = net.subscribe("anymone/subnet/0/relayonly").await;
    let _ = bound.try_recv();
    let mut broadcast_sub = net.subscribe("anymone/subnet/0").await;
    // Drain the frame the relay itself published earlier in this test.
    while broadcast_sub.try_recv().is_some() {}
    for _ in 0..10 {
        client_net
            .publish("anymone/subnet/0", b"forged-relay-frame".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        broadcast_sub.try_recv().is_none(),
        "a client must not reach a roster-bound topic through its relay"
    );
    // The unbound ingress topic still accepts the same client.
    let mut still_works = None;
    for _ in 0..20 {
        client_net
            .publish("anymone/subnet/0/ingress", b"still-allowed".to_vec())
            .await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), ingress.recv()).await
        {
            still_works = Some(msg);
            break;
        }
    }
    assert_eq!(
        still_works.expect("ingress must stay open").payload,
        b"still-allowed"
    );

    // A client outside the good-clients list is refused at the handshake, so it
    // can neither submit nor be fed.
    let stranger = Identity::generate();
    let allowed = client.pubkey();
    let strict_port = portpicker::pick_unused_port().expect("free port");
    let strict_stream = portpicker::pick_unused_port().expect("free port");
    let strict_id = Identity::generate();
    let strict = CommonwareNetwork::start(
        &strict_id,
        node(
            &strict_id,
            strict_port,
            strict_stream,
            GoodClients::new(move |pk| *pk == allowed),
        ),
    );
    let mut strict_ingress = strict.subscribe("anymone/subnet/0/ingress").await;
    let refused = StreamClientNetwork::start(
        &stranger,
        StreamClientConfig {
            servers: vec![(strict_id.pubkey(), addr(strict_stream))],
        },
    );
    for _ in 0..10 {
        refused
            .publish("anymone/subnet/0/ingress", b"not-allowed".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        strict_ingress.try_recv().is_none(),
        "a client outside the good-clients list must not be served"
    );

    // The same node still serves an allowed client, so the refusal was the
    // screen and not a broken listener.
    let ok_client = StreamClientNetwork::start(
        &client,
        StreamClientConfig {
            servers: vec![(strict_id.pubkey(), addr(strict_stream))],
        },
    );
    let mut seen = None;
    for _ in 0..20 {
        ok_client
            .publish("anymone/subnet/0/ingress", b"allowed".to_vec())
            .await;
        if let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), strict_ingress.recv()).await
        {
            seen = Some(msg);
            break;
        }
    }
    assert_eq!(
        seen.expect("allowed client was not served").payload,
        b"allowed"
    );
    let _ = recv_soon;
}
