//! Full e2e demo over real libp2p (loopback TCP + noise + yamux + gossipsub).
//!
//! Same orchestration as `tests/e2e_echo.rs` but each node uses its own
//! [`Libp2pNetwork`] instead of an [`InMemoryNetwork`] handle. Proves that
//! the same anymone runtime, scheduler, and pipe code path works without
//! changes against a real network transport.

#![cfg(feature = "test-util")]

use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{ExchangePublicKeyWire, NoopConfig, ProtocolConfig, ServiceEntry};
use anymone_core::governance::TOPIC_FAULTS;
use anymone_core::p2p::{Libp2pConfig, Libp2pNetwork};
use anymone_core::scheduling::{announce_relay_registration, announce_service_registration};
use anymone_core::transport::Transport;
use anymone_core::{
    committee_roster, spawn_panetiere_committee_scheduler, Anymone, AnymoneRoundConfiguration,
    GovernanceBootstrap, Identity, PanetiereCommitteeConfig, ServiceTag, TOPIC_CONFIG,
    TOPIC_REGISTRATION,
};
use libp2p::Multiaddr;

const ECHO_TAG: ServiceTag = ServiceTag::from_bytes([
    b'a', b'n', b'y', b'm', b'o', b'n', b'e', b'.', b'e', b'c', b'h', b'o', 0, 0, 0, 0, 0, 0, 0, 0,
]);

struct NodeWithNet {
    identity: Identity,
    net: Arc<Libp2pNetwork>,
}

async fn start_node(identity: Identity, port: u16, bootstrap_addrs: Vec<Multiaddr>) -> NodeWithNet {
    let listen: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    let net = Libp2pNetwork::start(
        &identity,
        Libp2pConfig {
            listen,
            bootstrap_peers: bootstrap_addrs,
        },
    )
    .await
    .unwrap();
    NodeWithNet { identity, net }
}

fn addr_for(port: u16, net: &Libp2pNetwork) -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", net.local_peer_id())
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_echo_via_libp2p() {
    // Free ports + identities.
    let port_c = portpicker::pick_unused_port().unwrap();
    let port_r1 = portpicker::pick_unused_port().unwrap();
    let port_r2 = portpicker::pick_unused_port().unwrap();
    let port_r3 = portpicker::pick_unused_port().unwrap();
    let port_s = portpicker::pick_unused_port().unwrap();
    let port_x = portpicker::pick_unused_port().unwrap();

    let committee_id = Identity::generate();
    let r1_id = Identity::generate();
    let r2_id = Identity::generate();
    let r3_id = Identity::generate();
    let svc_id = Identity::generate();
    let cli_id = Identity::generate();

    // Committee first (no bootstrap peer), then everyone else dials committee.
    let committee = start_node(committee_id.clone(), port_c, vec![]).await;
    let committee_addr = addr_for(port_c, &committee.net);
    let dial = vec![committee_addr.clone()];

    let r1 = start_node(r1_id.clone(), port_r1, dial.clone()).await;
    let r2 = start_node(r2_id.clone(), port_r2, dial.clone()).await;
    let r3 = start_node(r3_id.clone(), port_r3, dial.clone()).await;
    let service = start_node(svc_id.clone(), port_s, dial.clone()).await;
    let client = start_node(cli_id.clone(), port_x, dial).await;

    // Static Noop subnet every node adopts directly (no scheduler). The
    // committee node has no special role here — it's just the mesh hub the
    // others dial. Registration → committee → config is covered by the
    // committee-scheduler tests below.
    let relay_pks = vec![r1_id.pubkey(), r2_id.pubkey(), r3_id.pubkey()];
    let services = vec![ServiceEntry {
        tag: ECHO_TAG,
        pubkey: svc_id.pubkey(),
    }];
    let protocol = ProtocolConfig::Noop(NoopConfig {
        round_duration_ms: 30,
        message_size: 1024,
        client_set_min: 0,
        client_set_max: 256,
    });
    let config =
        AnymoneRoundConfiguration::singleton_subnet(0, protocol, relay_pks, vec![], services);

    let _committee_anymone =
        Anymone::start_with_config(committee_id.clone(), committee.net.clone(), config.clone())
            .await;
    let _r1 = Anymone::start_with_config(r1_id.clone(), r1.net.clone(), config.clone()).await;
    let _r2 = Anymone::start_with_config(r2_id.clone(), r2.net.clone(), config.clone()).await;
    let _r3 = Anymone::start_with_config(r3_id.clone(), r3.net.clone(), config.clone()).await;
    let service_anymone =
        Anymone::start_with_config(svc_id.clone(), service.net.clone(), config.clone()).await;
    let client_anymone =
        Anymone::start_with_config(cli_id.clone(), client.net.clone(), config.clone()).await;

    let mut svc_pipe = service_anymone.bind(ECHO_TAG).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_anymone.open(ECHO_TAG).await.unwrap();
    pipe.send(b"hello".to_vec()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(30), pipe.recv())
        .await
        .expect("recv timed out")
        .expect("pipe closed");
    assert_eq!(reply.payload, b"hello");
}

/// Reproduces the standalone deployment topology: a discovery **bootnode**, a
/// 3-member Panetiere committee, and a registered relay + service — every node
/// seeding ONLY from the bootnode (Kademlia discovery, not direct dials). The
/// committee must schedule a subnet carrying the service, with no clients
/// present. Mirrors `deploy/gen-configs.sh`.
#[tokio::test(flavor = "multi_thread")]
async fn deployment_schedules_subnet_via_bootnode() {
    fn pick() -> u16 {
        portpicker::pick_unused_port().unwrap()
    }
    fn xk(id: &Identity) -> ExchangePublicKeyWire {
        id.exchange_keys()
    }

    let echo_tag = ServiceTag::from_label("anymone.echo");
    let mut keep: Vec<Arc<Libp2pNetwork>> = Vec::new();

    // Bootnode: no seed of its own; joins the governance topics so it relays
    // them while the mesh forms.
    let p_boot = pick();
    let boot = start_node(Identity::generate(), p_boot, vec![]).await;
    let dial = vec![addr_for(p_boot, &boot.net)];
    let boot_t: Arc<dyn Transport> = boot.net.clone();
    let _boot_subs = vec![
        boot_t.subscribe(TOPIC_CONFIG).await,
        boot_t.subscribe(TOPIC_REGISTRATION).await,
        boot_t.subscribe(TOPIC_FAULTS).await,
    ];
    keep.push(boot.net.clone());

    // 3-member Panetiere committee, each seeding only from the bootnode.
    let committee_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let roster = committee_roster(&committee_ids);
    let threshold = 2u32;
    let ccfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(1000),
        public_round_duration: Duration::from_millis(1000),
        min_relays: 1,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };
    let mut handles = Vec::new();
    for id in &committee_ids {
        let node = start_node(id.clone(), pick(), dial.clone()).await;
        handles.push(
            spawn_panetiere_committee_scheduler(
                node.net.clone(),
                id.clone(),
                roster.clone(),
                threshold,
                ccfg.clone(),
            )
            .await,
        );
        keep.push(node.net);
    }

    // A registered relay + service, both plain libp2p nodes seeding from the
    // bootnode. No clients anywhere.
    let relay_id = Identity::generate();
    let relay = start_node(relay_id.clone(), pick(), dial.clone()).await;
    announce_relay_registration(relay.net.clone(), &relay_id, xk(&relay_id)).await;
    keep.push(relay.net);

    let svc_id = Identity::generate();
    let svc = start_node(svc_id.clone(), pick(), dial.clone()).await;
    announce_service_registration(svc.net.clone(), &svc_id, echo_tag, xk(&svc_id)).await;
    keep.push(svc.net);

    // Observer subscribes to the config topic and waits for a scheduled subnet.
    let obs = start_node(Identity::generate(), pick(), dial.clone()).await;
    let obs_t: Arc<dyn Transport> = obs.net.clone();
    let mut config_sub = obs_t.subscribe(TOPIC_CONFIG).await;
    keep.push(obs.net);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut scheduled: Option<AnymoneRoundConfiguration> = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), config_sub.recv()).await {
            Ok(Some(msg)) => {
                if let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) {
                    if !cfg.body.subnets.is_empty() {
                        scheduled = Some(cfg);
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }

    let cfg = scheduled.expect("committee never scheduled a subnet over the bootnode mesh");
    assert!(
        cfg.body.services.iter().any(|svc| svc.tag == echo_tag) && !cfg.body.subnets.is_empty(),
        "scheduled config carries no subnet for the registered service"
    );

    let _keep = keep;
    let _handles = handles;
}

/// Faithful reproduction of the standalone deployment (`deploy/run.sh`): every
/// role is a full `Anymone` over libp2p, seeded ONLY from the bootnode, exactly
/// as the deployed binaries run. Echo must round-trip.
///
/// Crucially the relays/service come up and begin announcing BEFORE the
/// committee exists — the deployment's actual launch order. A single startup
/// registration is lost to the unformed gossip mesh (and ages out of gossipsub's
/// message cache before the committee subscribes), so the committee would never
/// schedule them. `start_announcing` re-publishes until placed, which is what
/// gets the subnet built. This is the test that repros the multi-process
/// no-subnet bug in-process.
#[tokio::test(flavor = "multi_thread")]
async fn deployment_echo_full_nodes_via_bootnode() {
    fn pick() -> u16 {
        portpicker::pick_unused_port().unwrap()
    }
    fn xk(id: &Identity) -> ExchangePublicKeyWire {
        id.exchange_keys()
    }

    // Bootnode: the lone seed; relays governance topics while the mesh forms.
    let p_boot = pick();
    let boot = start_node(Identity::generate(), p_boot, vec![]).await;
    let dial = vec![addr_for(p_boot, &boot.net)];
    let boot_t: Arc<dyn Transport> = boot.net.clone();
    let _boot_subs = vec![
        boot_t.subscribe(TOPIC_CONFIG).await,
        boot_t.subscribe(TOPIC_REGISTRATION).await,
        boot_t.subscribe(TOPIC_FAULTS).await,
    ];

    // 3-member Panetiere committee, each seeding only from the bootnode.
    let committee_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let roster = committee_roster(&committee_ids);
    let gov = GovernanceBootstrap {
        committee: committee_ids.iter().map(|i| i.pubkey()).collect(),
        threshold: 2,
    };
    let ccfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(1000),
        public_round_duration: Duration::from_millis(1000),
        min_relays: 1,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };
    let mut keep: Vec<Arc<Libp2pNetwork>> = vec![boot.net.clone()];
    // Relays + service start announcing while there's no committee to hear them;
    // the lifetime re-announcer keeps re-publishing until the committee comes up.
    let mut starts = Vec::new();
    for _ in 0..2 {
        let id = Identity::generate();
        let node = start_node(id.clone(), pick(), dial.clone()).await;
        keep.push(node.net.clone());
        let net: Arc<dyn Transport> = node.net.clone();
        announce_relay_registration(net.clone(), &id, xk(&id)).await;
        let gov = gov.clone();
        starts.push(tokio::spawn(async move {
            Anymone::prepare(id, net, gov).await.start().await
        }));
    }

    let svc_id = Identity::generate();
    let svc_node = start_node(svc_id.clone(), pick(), dial.clone()).await;
    keep.push(svc_node.net.clone());
    let svc_handle = {
        let gov = gov.clone();
        let net: Arc<dyn Transport> = svc_node.net.clone();
        announce_service_registration(net.clone(), &svc_id, ECHO_TAG, xk(&svc_id)).await;
        tokio::spawn(async move { Anymone::prepare(svc_id, net, gov).await.start().await })
    };

    let cli_id = Identity::generate();
    let cli_node = start_node(cli_id.clone(), pick(), dial.clone()).await;
    keep.push(cli_node.net.clone());
    let cli_handle = {
        let gov = gov.clone();
        let net = cli_node.net.clone();
        tokio::spawn(async move { Anymone::start(cli_id, net, gov).await })
    };

    // Let the first announcements age out of the gossip mcache, so only a
    // re-announcement can reach the committee that comes up now.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let mut handles = Vec::new();
    for id in &committee_ids {
        let node = start_node(id.clone(), pick(), dial.clone()).await;
        handles.push(
            spawn_panetiere_committee_scheduler(
                node.net.clone(),
                id.clone(),
                roster.clone(),
                2,
                ccfg.clone(),
            )
            .await,
        );
        keep.push(node.net);
    }

    let bounded = Duration::from_secs(60);
    let service_anymone = tokio::time::timeout(bounded, svc_handle)
        .await
        .expect("service Anymone::start timed out — committee never published a config")
        .unwrap()
        .unwrap();
    let client_anymone = tokio::time::timeout(bounded, cli_handle)
        .await
        .expect("client Anymone::start timed out")
        .unwrap()
        .unwrap();

    let mut svc_pipe = service_anymone.bind(ECHO_TAG).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_anymone.open(ECHO_TAG).await.unwrap();
    pipe.send(b"hello".to_vec()).await.unwrap();
    let reply = tokio::time::timeout(bounded, pipe.recv())
        .await
        .expect("echo reply timed out")
        .expect("pipe closed");
    assert_eq!(reply.payload, b"hello");

    let _keep = keep;
    let _handles = handles;
    let _starts = starts;
}
