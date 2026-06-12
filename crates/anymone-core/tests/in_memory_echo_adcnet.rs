//! P1 smoke: full Anymone echo over an ADCNet (1-round) subnet on the
//! in-memory transport. Verifies that `runtime::build_*_session` constructs
//! AdcnetClient/Server/Watch sessions, that the runtime threads exchange
//! keys to ECDH-derive shared secrets, and that decoded payloads route to
//! pipes via the existing `route_to_pipe` path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{
    now_unix_ms, AdcnetConfig, AnymoneRoundConfigurationBody, ExchangePublicKeyWire, Subnet,
};
use anymone_core::runtime::subnet_broadcast_topic;
use anymone_core::session::Session;
use anymone_core::transport::Transport;
use anymone_core::{
    AdcnetObserverSession, Anymone, AnymoneRoundConfiguration, GovernanceBootstrap, Identity,
    InMemoryNetwork, ProtocolConfig, ServiceEntry, ServiceTag, TOPIC_CONFIG,
};
use serial_test::serial;

fn echo_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.echo")
}

fn xkw(id: &Identity) -> ExchangePublicKeyWire {
    ExchangePublicKeyWire::from_key(&id.exchange_pubkey())
}

fn build_config(
    committee: &Identity,
    relays: &[Identity],
    service: &Identity,
    client: &Identity,
) -> AnymoneRoundConfiguration {
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();

    // Only relay exchange keys go in the config. Clients (the sender and the
    // echo service, which replies as a client) announce their own exchange
    // keys on the subnet via signed `ClientKey` messages — no config entry.
    let _ = (service, client);
    let mut relay_xk: Vec<_> = relays
        .iter()
        .map(|i| (i.pubkey(), xkw(i)))
        .collect();
    relay_xk.sort_by_key(|(p, _)| *p);

    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 1024,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            relay_exchange_keys: relay_xk,
            aggregation: None,
        }),
        relay_pks,
        vec![ServiceEntry { tag: echo_tag(), pubkey: service.pubkey() }],
    )
    .sign_with(&[committee])
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn adcnet_echo_roundtrip_in_memory() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();
    let idle = Identity::generate();

    let cfg = build_config(&committee, &relays, &service, &client);
    let roster: Vec<_> = cfg.body.subnets[0].relays.clone();

    let mut anymones: Vec<Anymone> = Vec::new();
    for id in relays.into_iter() {
        let handle = net.handle(id.pubkey());
        anymones.push(Anymone::start_with_config(id, Arc::new(handle), cfg.clone()).await);
    }
    let service_handle = net.handle(service.pubkey());
    let service_anymone =
        Anymone::start_with_config(service, Arc::new(service_handle), cfg.clone()).await;
    let client_handle = net.handle(client.pubkey());
    let client_anymone =
        Anymone::start_with_config(client, Arc::new(client_handle), cfg.clone()).await;
    let idle_anymone =
        Anymone::start_with_config(idle.clone(), Arc::new(net.handle(idle.pubkey())), cfg.clone())
            .await;

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // Observer reconstructs the anon set from the leader's ClientSet broadcasts.
    let anon = Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let mut sub =
            net.handle(Identity::generate().pubkey()).subscribe(&subnet_broadcast_topic(0)).await;
        let anon = anon.clone();
        tokio::spawn(async move {
            let mut o = AdcnetObserverSession::new(roster, 2);
            while let Some(m) = sub.recv().await {
                o.on_inbound(m.from, m.payload);
                anon.fetch_max(o.anonymity_set().unwrap_or(0) as u64, Ordering::Relaxed);
            }
        });
    }

    // Cover traffic: this pipe opens but never sends — it must still join the
    // anonymity set every round via zero messages.
    let _idle_pipe = idle_anymone.open(echo_tag()).await.unwrap();

    let mut pipe = client_anymone.open(echo_tag()).await.unwrap();
    pipe.send(b"hello adcnet".to_vec()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(15), pipe.recv())
        .await
        .expect("recv timed out")
        .expect("pipe closed");
    let reply_str = &reply.payload[..reply.payload.len().min(12)];
    assert_eq!(reply_str, b"hello adcnet");

    // Both the sender and the idle pipe must be in the anonymity set (≥2),
    // proving the idle pipe contributes cover with no `send`.
    let reached = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if anon.load(Ordering::Relaxed) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "idle open pipe never appeared in the anon set (no cover)");

    drop(anymones);
}

/// Broadcast-room self-receipt (the chat pattern), via the *genuine* channel:
/// one node `subscribe`s (recv) and `open`s (send) the same tag and must see
/// its own message come back in the leader's decoded broadcast — no local
/// shortcut. Also drives N extra senders to check decode survives the demo's
/// concurrent-sender + cover load.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_room_participant_sees_own_message_via_channel() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    // The room owner (as in the demo, where the chat service node is also a
    // participant) both subscribes and opens its own tag.
    let owner = Identity::generate();
    // A couple of distinct-signer senders for concurrency; the owner's two
    // same-signer pipes are what the fix is about.
    let others: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();

    let cfg = build_config(&committee, &relays, &owner, &owner);

    let mut keep: Vec<Anymone> = Vec::new();
    for id in relays.into_iter() {
        keep.push(
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await,
        );
    }
    let owner_anymone =
        Anymone::start_with_config(owner.clone(), Arc::new(net.handle(owner.pubkey())), cfg.clone())
            .await;
    for id in &others {
        let a = Anymone::start_with_config(
            id.clone(),
            Arc::new(net.handle(id.pubkey())),
            cfg.clone(),
        )
        .await;
        let pipe = a.subscribe(echo_tag()).await.unwrap();
        keep.push(a);
        tokio::spawn(async move {
            loop {
                let _ = pipe.send(b"other".to_vec()).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        });
    }

    let mut recv = owner_anymone.subscribe(echo_tag()).await.unwrap();
    let send = owner_anymone.open(echo_tag()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            send.send(b"owner-msg".to_vec()).await.unwrap();
            // Collect a few inbound and look for our own message.
            for _ in 0..4 {
                if let Ok(Some(m)) =
                    tokio::time::timeout(Duration::from_millis(300), recv.recv()).await
                {
                    if m.payload.starts_with(b"owner-msg") {
                        return m;
                    }
                }
            }
        }
    })
    .await
    .expect("owner never received its own message via the channel");
    assert!(got.payload.starts_with(b"owner-msg"));

    drop(keep);
}

/// Two ADCNet subnets in one config, each with its own leader
/// (`sorted_relays[id % n]`). The echo service lives only on subnet 1, so the
/// client is routed there — exercising a subnet whose leader is NOT the
/// sorted-first relay (the case sharding introduces). A round-trip proves a
/// non-zero-index leader announces the set, the relays share to it, and it
/// combines + broadcasts the output.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn adcnet_second_subnet_with_distinct_leader_roundtrips() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);
    let proto = || {
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 256,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            relay_exchange_keys: relay_xk.clone(),
            aggregation: None,
        })
    };
    // Subnet 0 carries no service (idle); the echo service is on subnet 1, whose
    // leader is sorted_relays[1 % 3] — not the sorted-first relay.
    let body = AnymoneRoundConfigurationBody {
        round: 0,
        epoch_unix_ms: anymone_core::config::now_unix_ms(),
        subnets: vec![
            Subnet { id: 0, services: vec![], relays: relay_pks.clone(), protocol: proto() },
            Subnet {
                id: 1,
                services: vec![ServiceEntry { tag: echo_tag(), pubkey: service.pubkey() }],
                relays: relay_pks.clone(),
                protocol: proto(),
            },
        ],
    };
    let cfg = AnymoneRoundConfiguration::new(body).sign_with(&[&committee]);

    let mut anymones: Vec<Anymone> = Vec::new();
    for id in relays.into_iter() {
        let handle = net.handle(id.pubkey());
        anymones.push(Anymone::start_with_config(id, Arc::new(handle), cfg.clone()).await);
    }
    let service_anymone =
        Anymone::start_with_config(service.clone(), Arc::new(net.handle(service.pubkey())), cfg.clone())
            .await;
    let client_anymone =
        Anymone::start_with_config(client.clone(), Arc::new(net.handle(client.pubkey())), cfg.clone())
            .await;

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_anymone.open(echo_tag()).await.unwrap();
    // Resend each round until the echo returns, so the test doesn't hinge on the
    // first contribution landing after every relay has subscribed.
    let reply = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            pipe.send(b"hello subnet1".to_vec()).await.unwrap();
            if let Ok(Some(m)) =
                tokio::time::timeout(Duration::from_millis(400), pipe.recv()).await
            {
                break m;
            }
        }
    })
    .await
    .expect("no echo via the subnet-1 (distinct-leader) path");
    assert_eq!(&reply.payload[..reply.payload.len().min(13)], b"hello subnet1");

    drop(anymones);
}

/// Live reconfiguration. Nodes start under v0 (service on subnet 0), then the
/// committee publishes v1 that moves the service to a newly-scheduled subnet 1
/// and leaves subnet 0 serviceless. Nodes started via `prepare`/`start` must
/// adopt v1 on the fly: relays spin up subnet 1, the service's subnet-1 worker
/// comes up, and the client re-homes its sends to subnet 1 (now the only
/// carrier of the tag) — so the echo keeps working across the reconfiguration,
/// proving the no-live-reconfiguration gap is closed.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn live_reconfiguration_moves_service_to_a_new_subnet() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let gov = GovernanceBootstrap { committee: vec![committee.pubkey()], threshold: 1 };
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);
    let proto = || {
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 256,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            relay_exchange_keys: relay_xk.clone(),
            aggregation: None,
        })
    };
    let svc_entry = || ServiceEntry { tag: echo_tag(), pubkey: service.pubkey() };

    // v0: a single subnet (id 0) carrying the service.
    let v0 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 0,
        epoch_unix_ms: now_unix_ms(),
        subnets: vec![Subnet {
            id: 0,
            services: vec![svc_entry()],
            relays: relay_pks.clone(),
            protocol: proto(),
        }],
    })
    .sign_with(&[&committee]);

    // Prepare (subscribe to the config topic) BEFORE publishing v0.
    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await);
    }
    let svc_prep =
        Anymone::prepare(service.clone(), Arc::new(net.handle(service.pubkey())), gov.clone()).await;
    let cli_prep =
        Anymone::prepare(client.clone(), Arc::new(net.handle(client.pubkey())), gov.clone()).await;

    let publisher = net.handle(committee.pubkey());
    publisher.publish(TOPIC_CONFIG, bincode::serialize(&v0).unwrap()).await;

    let mut anymones: Vec<Anymone> = Vec::new();
    for p in relay_preps {
        anymones.push(p.start().await.expect("relay start"));
    }
    let svc = svc_prep.start().await.expect("service start");
    let cli = cli_prep.start().await.expect("client start");

    let mut svc_pipe = svc.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = cli.open(echo_tag()).await.unwrap();

    // Echo works under v0 (service on subnet 0). Resend each round until the
    // reply lands, so the test doesn't hinge on a single round's timing.
    let reply = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            pipe.send(b"v0 hello".to_vec()).await.unwrap();
            if let Ok(Some(m)) = tokio::time::timeout(Duration::from_millis(400), pipe.recv()).await {
                break m;
            }
        }
    })
    .await
    .expect("no echo under v0");
    assert_eq!(&reply.payload[..reply.payload.len().min(8)], b"v0 hello");

    // v1: service moves to a newly-scheduled subnet 1; subnet 0 stays but
    // carries no service. A higher round makes the watcher adopt it.
    let v1 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 1,
        epoch_unix_ms: now_unix_ms(),
        subnets: vec![
            Subnet { id: 0, services: vec![], relays: relay_pks.clone(), protocol: proto() },
            Subnet { id: 1, services: vec![svc_entry()], relays: relay_pks.clone(), protocol: proto() },
        ],
    })
    .sign_with(&[&committee]);
    publisher.publish(TOPIC_CONFIG, bincode::serialize(&v1).unwrap()).await;

    // After adoption, the only carrier of the tag is subnet 1: the client must
    // re-home there and the echo must come back over the newly-spun-up subnet.
    // Skip any stale v0 echoes still buffered from the first phase.
    let reply = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            pipe.send(b"v1 hello".to_vec()).await.unwrap();
            while let Ok(Some(m)) =
                tokio::time::timeout(Duration::from_millis(400), pipe.recv()).await
            {
                if m.payload.starts_with(b"v1 hello") {
                    return m;
                }
            }
        }
    })
    .await
    .expect("no echo after reconfiguration to subnet 1");
    assert_eq!(&reply.payload[..reply.payload.len().min(8)], b"v1 hello");

    drop(anymones);
}

/// When the committee adds a subnet, clients that re-home must **leave** the
/// subnet they came from — not keep padding its anonymity set with cover
/// traffic. Without retiring the old client session, the population is
/// double-counted (old subnet keeps all N while the new one also fills up).
/// Here all clients start on subnet 0, a reconfig adds subnet 1 (the tag is on
/// both), and an observer watching subnet 0 must see its set shrink below N as
/// roughly half the clients move to subnet 1.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn rehome_sheds_clients_from_the_old_subnet() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let gov = GovernanceBootstrap { committee: vec![committee.pubkey()], threshold: 1 };
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let n_clients = 8usize;
    let clients: Vec<Identity> = (0..n_clients).map(|_| Identity::generate()).collect();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);
    let proto = || {
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 256,
            estimated_messages: 64,
            client_set_min: 0,
            client_set_max: 64,
            relay_exchange_keys: relay_xk.clone(),
            aggregation: None,
        })
    };
    let svc = || ServiceEntry { tag: echo_tag(), pubkey: service.pubkey() };

    let v0 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 0,
        epoch_unix_ms: now_unix_ms(),
        subnets: vec![Subnet { id: 0, services: vec![svc()], relays: relay_pks.clone(), protocol: proto() }],
    })
    .sign_with(&[&committee]);
    // v1 carries the service on BOTH subnets, so ~half the clients re-home to
    // subnet 1 and the rest stay on subnet 0.
    let v1 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 1,
        epoch_unix_ms: now_unix_ms(),
        subnets: vec![
            Subnet { id: 0, services: vec![svc()], relays: relay_pks.clone(), protocol: proto() },
            Subnet { id: 1, services: vec![svc()], relays: relay_pks.clone(), protocol: proto() },
        ],
    })
    .sign_with(&[&committee]);

    // Observer on subnet 0's broadcast topic → tracks its live anonymity set.
    let anon0 = Arc::new(AtomicU64::new(0));
    {
        let mut sub0 = net.handle(Identity::generate().pubkey()).subscribe(&subnet_broadcast_topic(0)).await;
        let anon0 = anon0.clone();
        let roster = relay_pks.clone();
        tokio::spawn(async move {
            let mut o = AdcnetObserverSession::new(roster, 2);
            while let Some(m) = sub0.recv().await {
                o.on_inbound(m.from, m.payload);
                anon0.store(o.anonymity_set().unwrap_or(0) as u64, Ordering::Relaxed);
            }
        });
    }

    // Prepare everyone before publishing v0.
    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await);
    }
    let svc_prep = Anymone::prepare(service.clone(), Arc::new(net.handle(service.pubkey())), gov.clone()).await;
    let mut client_preps = Vec::new();
    for id in &clients {
        client_preps.push(Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await);
    }

    net.handle(committee.pubkey()).publish(TOPIC_CONFIG, bincode::serialize(&v0).unwrap()).await;

    let mut keep: Vec<Anymone> = Vec::new();
    for p in relay_preps {
        keep.push(p.start().await.expect("relay start"));
    }
    let svc_anymone = svc_prep.start().await.expect("service start");
    let mut svc_pipe = svc_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });
    keep.push(svc_anymone);

    for prep in client_preps {
        tokio::spawn(async move {
            let Ok(a) = prep.start().await else { return };
            let Ok(pipe) = a.open(echo_tag()).await else { return };
            let _keep = a;
            loop {
                let _ = pipe.send(b"x".to_vec()).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        });
    }

    // Wait until all clients are on subnet 0. Generous bound: heavy integration
    // tests run in parallel, so wall-clock stretches under contention.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if anon0.load(Ordering::Relaxed) as usize >= n_clients {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("subnet 0 never gathered all clients");

    // Add subnet 1; clients re-home and must leave subnet 0.
    net.handle(committee.pubkey()).publish(TOPIC_CONFIG, bincode::serialize(&v1).unwrap()).await;

    // Give re-homing several rounds, then subnet 0 must have shed clients.
    let shed = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if (anon0.load(Ordering::Relaxed) as usize) < n_clients {
                break anon0.load(Ordering::Relaxed) as usize;
            }
        }
    })
    .await
    .expect("subnet 0 kept all clients after the split — double-counted across subnets");
    assert!(shed < n_clients, "subnet 0 must shed re-homed clients, still has {shed}/{n_clients}");

    drop(keep);
}
