//! The client plane: a client that never joins the p2p backbone still submits
//! to a node directly and receives what that node publishes.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::cw::{
    CommonwareConfig, CommonwareNetwork, StreamClientConfig, StreamClientNetwork,
};
use anymone_core::transport::{NetView, Topic, Transport};
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
        committee: vec![id.pubkey()],
        local: true,
        stream_listen: Some(addr(stream_port)),
        good_clients: good,
    }
}

/// The view a node adopts so clients may submit on subnet 0: its broadcast is
/// relay-bound (a real protocol subnet); subnet 1's broadcast is open (Noop).
fn serving_view(relay: anymone_core::Pubkey) -> NetView {
    NetView {
        subnets: vec![0, 1],
        senders: std::collections::HashMap::from([(
            Topic::Broadcast(0),
            std::collections::HashSet::from([relay]),
        )]),
        ..NetView::default()
    }
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
    net.apply(serving_view(relay.pubkey()));
    // The relay's own session is what must see the client's data.
    let mut inbox = net.inbox(0).await;
    net.serve_config(b"the-signed-config".to_vec());

    let client_net = StreamClientNetwork::start(
        &client,
        StreamClientConfig {
            servers: vec![(relay.pubkey(), addr(stream_port))],
            ..Default::default()
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

    // Client data reaches the addressed relay tagged with the client's own
    // key, not the relay's — the relay is the addressee, nothing is forwarded.
    let mut got = None;
    for _ in 0..20 {
        client_net
            .send(relay.pubkey(), 0, b"client-public".to_vec())
            .await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), inbox.recv()).await
        {
            got = Some(msg);
            break;
        }
    }
    let msg = got.expect("client data never reached the relay");
    assert_eq!(msg.from, client.pubkey(), "the client is the origin");
    assert_eq!(msg.payload, b"client-public");

    // The relay's own broadcast reaches the client, which the backbone alone
    // could never do: a publisher is not delivered its own message.
    let mut feed = client_net.subscribe(Topic::Broadcast(0)).await;
    let mut delivered = None;
    for _ in 0..20 {
        net.publish(Topic::Broadcast(0), b"decoded-round".to_vec())
            .await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), feed.recv()).await {
            delivered = Some(msg);
            break;
        }
    }
    let msg = delivered.expect("relay broadcast never reached the client");
    assert_eq!(
        msg.from,
        relay.pubkey(),
        "frames are attributed to the node"
    );
    assert_eq!(msg.payload, b"decoded-round");

    // Data for a subnet outside the served config is refused.
    let mut unknown = net.inbox(9).await;
    for _ in 0..10 {
        client_net
            .send(relay.pubkey(), 9, b"unknown-subnet".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        unknown.try_recv().is_none(),
        "data for an unknown subnet must be dropped"
    );

    // A roster-bound broadcast is closed to clients — forwarding would put the
    // frame on the wire under the relay's key, which IS in the roster.
    let mut broadcast_sub = net.subscribe(Topic::Broadcast(0)).await;
    for _ in 0..10 {
        client_net
            .publish(Topic::Broadcast(0), b"forged-relay-frame".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        broadcast_sub.try_recv().is_none(),
        "a client must not reach a roster-bound topic through its relay"
    );
    // An open broadcast (a Noop subnet's whole protocol) accepts the same
    // client, delivered under its own key.
    let mut open_sub = net.subscribe(Topic::Broadcast(1)).await;
    let mut open_seen = None;
    for _ in 0..20 {
        client_net
            .publish(Topic::Broadcast(1), b"noop-contribution".to_vec())
            .await;
        if let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), open_sub.recv()).await
        {
            open_seen = Some(msg);
            break;
        }
    }
    let msg = open_seen.expect("open-broadcast submission never surfaced");
    assert_eq!(msg.from, client.pubkey());
    assert_eq!(msg.payload, b"noop-contribution");

    // A registration rides the stream and lands on the node's registration
    // subscription under the client's own key.
    let mut regs = net.subscribe(Topic::Registration).await;
    let reg = anymone_core::scheduling::Registration::watcher(&client).encode();
    let mut seen = None;
    for _ in 0..20 {
        client_net.publish(Topic::Registration, reg.clone()).await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(400), regs.recv()).await {
            seen = Some(msg);
            break;
        }
    }
    let msg = seen.expect("registration never reached the node");
    assert_eq!(msg.from, client.pubkey());
    assert_eq!(msg.payload, reg);

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
    strict.apply(serving_view(strict_id.pubkey()));
    let mut strict_inbox = strict.inbox(0).await;
    let refused = StreamClientNetwork::start(
        &stranger,
        StreamClientConfig {
            servers: vec![(strict_id.pubkey(), addr(strict_stream))],
            ..Default::default()
        },
    );
    for _ in 0..10 {
        refused
            .send(strict_id.pubkey(), 0, b"not-allowed".to_vec())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        strict_inbox.try_recv().is_none(),
        "a client outside the good-clients list must not be served"
    );

    // The same node still serves an allowed client, so the refusal was the
    // screen and not a broken listener.
    let ok_client = StreamClientNetwork::start(
        &client,
        StreamClientConfig {
            servers: vec![(strict_id.pubkey(), addr(strict_stream))],
            ..Default::default()
        },
    );
    let mut seen = None;
    for _ in 0..20 {
        ok_client
            .send(strict_id.pubkey(), 0, b"allowed".to_vec())
            .await;
        if let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(400), strict_inbox.recv()).await
        {
            seen = Some(msg);
            break;
        }
    }
    assert_eq!(
        seen.expect("allowed client was not served").payload,
        b"allowed"
    );
}
