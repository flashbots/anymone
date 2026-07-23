//! Layer-1 libp2p test: two `Libp2pNetwork` instances on loopback,
//! one subscribes, the other publishes, the subscriber receives it.
//! A single publish suffices because the swarm task buffers publishes
//! issued before the gossipsub mesh has any remote subscribers, and
//! re-tries them on the `Subscribed` event.

#![cfg(feature = "test-util")]

use std::time::Duration;

use anymone_core::p2p::{Libp2pConfig, Libp2pNetwork};
use anymone_core::transport::Transport;
use anymone_core::Identity;
use libp2p::Multiaddr;

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_can_gossip() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let port_a = portpicker::pick_unused_port().expect("free port");
    let port_b = portpicker::pick_unused_port().expect("free port");

    let listen_a: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_a}").parse().unwrap();
    let listen_b: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_b}").parse().unwrap();

    let net_a = Libp2pNetwork::start(
        &id_a,
        Libp2pConfig {
            listen: listen_a.clone(),
            bootstrap_peers: vec![],
        },
    )
    .await
    .unwrap();
    let a_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port_a}/p2p/{}", net_a.local_peer_id())
        .parse()
        .unwrap();

    let net_b = Libp2pNetwork::start(
        &id_b,
        Libp2pConfig {
            listen: listen_b,
            bootstrap_peers: vec![a_addr],
        },
    )
    .await
    .unwrap();

    let mut sub_b = net_b.subscribe("test/topic").await;
    let _sub_a = net_a.subscribe("test/topic").await;

    let payload = b"hello over libp2p".to_vec();
    net_a.publish("test/topic", payload.clone()).await;

    let msg = tokio::time::timeout(Duration::from_secs(5), sub_b.recv())
        .await
        .expect("B never received")
        .expect("subscription closed");
    assert_eq!(msg.from, id_a.pubkey());
    assert_eq!(msg.payload, payload);
}

/// Discovery gate: A and B each know ONLY the bootnode, yet end up directly
/// connected and gossiping. The bootnode never subscribes to the topic, so a
/// message reaching B proves a direct A↔B mesh formed via Kademlia discovery,
/// not bootnode relaying.
#[tokio::test(flavor = "multi_thread")]
async fn bootnode_only_peers_discover_each_other() {
    async fn node(
        port: u16,
        bootstrap: Vec<Multiaddr>,
    ) -> (Identity, std::sync::Arc<Libp2pNetwork>) {
        let id = Identity::generate();
        let listen: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
        let net = Libp2pNetwork::start(
            &id,
            Libp2pConfig {
                listen,
                bootstrap_peers: bootstrap,
            },
        )
        .await
        .unwrap();
        (id, net)
    }
    fn addr_of(port: u16, net: &Libp2pNetwork) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", net.local_peer_id())
            .parse()
            .unwrap()
    }

    let port_boot = portpicker::pick_unused_port().expect("free port");
    let port_a = portpicker::pick_unused_port().expect("free port");
    let port_b = portpicker::pick_unused_port().expect("free port");

    let (_id_boot, boot) = node(port_boot, vec![]).await;
    let boot_addr = addr_of(port_boot, &boot);

    let (id_a, net_a) = node(port_a, vec![boot_addr.clone()]).await;
    let (id_b, net_b) = node(port_b, vec![boot_addr]).await;

    let mut sub_b = net_b.subscribe("test/discovery").await;
    let _sub_a = net_a.subscribe("test/discovery").await;

    let payload = b"discovered via kademlia".to_vec();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let msg = loop {
        net_a.publish("test/discovery", payload.clone()).await;
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(500), sub_b.recv()).await
        {
            break msg;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "B never received — discovery failed"
        );
    };
    assert_eq!(msg.from, id_a.pubkey());
    assert_eq!(msg.payload, payload);
    assert!(
        net_a.peer_snapshot().contains(&id_b.pubkey()),
        "A not directly connected to B"
    );
}
