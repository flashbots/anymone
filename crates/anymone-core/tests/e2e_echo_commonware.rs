//! Full echo in the deployed topology: relays on the authenticated backbone;
//! the service and the client reaching the network only over streams — neither
//! is a member of any peer set.

#![cfg(feature = "test-util")]

use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{NoopConfig, ProtocolConfig, ServiceEntry};
use anymone_core::cw::{
    CommonwareConfig, CommonwareNetwork, StreamClientConfig, StreamClientNetwork,
};
use anymone_core::{Anymone, AnymoneRoundConfiguration, GoodClients, Identity, Pubkey, ServiceTag};

fn addr(port: u16) -> std::net::SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn pick() -> u16 {
    portpicker::pick_unused_port().expect("free port")
}

/// A backbone node. `genesis_peers` is deliberately empty: membership must come
/// from the adopted config via `Transport::apply`, so nothing here can mask a broken
/// config-to-peer-set path (a round-0 config once collided with the genesis
/// index and was discarded, and an all-inclusive genesis set hid it).
fn backbone(
    port: u16,
    bootstrappers: Vec<(Pubkey, std::net::SocketAddr)>,
    stream_listen: Option<std::net::SocketAddr>,
) -> CommonwareConfig {
    CommonwareConfig {
        listen: addr(port),
        dialable: addr(port),
        bootstrappers,
        genesis_peers: Vec::new(),
        committee: Vec::new(),
        local: true,
        stream_listen,
        good_clients: GoodClients::all(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_echo_with_client_over_a_stream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let echo_tag = ServiceTag::from_label("anymone.echo");
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let committee = Identity::generate();

    // Relay 0 is the hub every other node bootstraps from, and the only node
    // that serves clients.
    let hub_port = pick();
    let hub_stream = pick();
    let hub_net = CommonwareNetwork::start(
        &relays[0],
        backbone(hub_port, Vec::new(), Some(addr(hub_stream))),
    );
    let dial = vec![(relays[0].pubkey(), addr(hub_port))];

    let mut nets: Vec<(Identity, Arc<CommonwareNetwork>)> =
        vec![(relays[0].clone(), hub_net.clone())];
    for id in relays.iter().skip(1) {
        let net = CommonwareNetwork::start(id, backbone(pick(), dial.clone(), None));
        nets.push((id.clone(), net));
    }

    // One fixed Noop subnet; governance over commonware is covered elsewhere.
    let config = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: 100,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        relays.iter().map(|i| i.pubkey()).collect(),
        vec![],
        vec![ServiceEntry {
            tag: echo_tag,
            pubkey: service.pubkey(),
        }],
    )
    .sign_with(&[&committee]);

    let mut backbone_nodes: Vec<Anymone> = Vec::new();
    for (id, net) in &nets {
        let node = Anymone::start_with_config(id.clone(), net.clone(), config.clone()).await;
        backbone_nodes.push(node);
    }

    // The service is not an authorized p2p peer: it works the same client
    // plane the client does.
    let service_net = StreamClientNetwork::start(
        &service,
        StreamClientConfig {
            servers: vec![(relays[0].pubkey(), addr(hub_stream))],
            ..Default::default()
        },
    );
    let service_anymone =
        Anymone::start_with_config(service.clone(), service_net, config.clone()).await;

    let mut svc_pipe = service_anymone.bind(echo_tag).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // The client joins no peer set: it only holds a stream to the hub.
    let client_net = StreamClientNetwork::start(
        &client,
        StreamClientConfig {
            servers: vec![(relays[0].pubkey(), addr(hub_stream))],
            ..Default::default()
        },
    );
    let client_anymone =
        Anymone::start_with_config(client.clone(), client_net.clone(), config.clone()).await;

    let mut pipe = client_anymone.open(echo_tag).await.unwrap();
    // Re-sent per round: a stream frame dropped while the backbone mesh is still
    // forming is lost, exactly as on the p2p side.
    let reply = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let _ = pipe.send(b"hello over a stream".to_vec()).await;
            if let Ok(Some(reply)) = tokio::time::timeout(Duration::from_secs(2), pipe.recv()).await
            {
                return reply;
            }
        }
    })
    .await
    .expect("echo never came back to the stream client");

    assert_eq!(&reply.payload[..19], b"hello over a stream");
}
