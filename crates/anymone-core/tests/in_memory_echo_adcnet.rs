//! P1 smoke: full Anymone echo over an ADCNet (1-round) subnet on the
//! in-memory transport. Verifies that `runtime::build_*_session` constructs
//! AdcnetClient/Server/Watch sessions, that the runtime threads exchange
//! keys to ECDH-derive shared secrets, and that decoded payloads route to
//! pipes via the existing `route_to_pipe` path.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{
    now_unix_ms, AdcnetConfig, Aggregation, AggregatorGroup, AnymoneRoundConfigurationBody,
    ExchangePublicKeyWire, Subnet,
};
use anymone_core::runtime::{subnet_broadcast_topic, subnet_shares_topic};
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
    id.exchange_keys()
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
    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);

    AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 1024,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            aggregation: None,
        }),
        relay_pks,
        relay_xk,
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service.pubkey(),
        }],
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
    let idle_anymone = Anymone::start_with_config(
        idle.clone(),
        Arc::new(net.handle(idle.pubkey())),
        cfg.clone(),
    )
    .await;

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // Observer reconstructs the anon set from the leader's ClientSet broadcasts.
    let leader = anymone_core::runtime::subnet_leader_pk(&cfg.body.subnets[0]);
    let anon = Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let mut sub = net
            .handle(Identity::generate().pubkey())
            .subscribe(&subnet_broadcast_topic(0))
            .await;
        let anon = anon.clone();
        tokio::spawn(async move {
            let mut o = AdcnetObserverSession::new(roster, leader, 2);
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
    assert!(
        reached.is_ok(),
        "idle open pipe never appeared in the anon set (no cover)"
    );

    drop(anymones);
}

/// Aggregation's single group is assigned relay 0 (`build_subnet_aggregation`'s
/// round-robin), and subnet 0's leader is also relay 0 (`leader_of`) — so for a
/// subnet's first group, the leader IS its own sole aggregator. Its `GroupAggregate`
/// publish must still reach its own Server session even though the transport
/// filters out a node's own messages from its own subscriptions.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn adcnet_aggregated_echo_roundtrip_when_leader_is_aggregator() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let mut relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    relays.sort_by_key(|i| i.pubkey());
    let service = Identity::generate();
    let client = Identity::generate();

    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);
    let relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();

    let cfg = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 1024,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            aggregation: Some(Aggregation {
                replication: 1,
                groups: vec![AggregatorGroup {
                    aggregators: vec![relay_pks[0]],
                }],
            }),
        }),
        relay_pks.clone(),
        relay_xk,
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service.pubkey(),
        }],
    )
    .sign_with(&[&committee]);
    assert_eq!(
        anymone_core::runtime::subnet_leader_pk(&cfg.body.subnets[0]),
        relay_pks[0],
        "test assumes leader == the sole aggregator, matching production for a subnet's first group"
    );

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

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    let mut pipe = client_anymone.open(echo_tag()).await.unwrap();
    pipe.send(b"hello aggregated adcnet".to_vec())
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(15), pipe.recv())
        .await
        .expect(
            "recv timed out — the leader's own aggregator output never reached its Server session",
        )
        .expect("pipe closed");
    let reply_str = &reply.payload[..reply.payload.len().min(24)];
    assert_eq!(reply_str, b"hello aggregated adcnet");

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
    let owner_anymone = Anymone::start_with_config(
        owner.clone(),
        Arc::new(net.handle(owner.pubkey())),
        cfg.clone(),
    )
    .await;
    for id in &others {
        let a =
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
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

/// When the committee adds a subnet, the population must split across the two,
/// never double-count (each node participates in exactly one drawn subnet per
/// round). With one subnet, subnet 0's set gathers all N; after the split an
/// observer watching subnet 0 must see its per-round set fall below N as the
/// draw spreads clients across both.
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
    let gov = GovernanceBootstrap {
        committee: vec![committee.pubkey()],
        threshold: 1,
    };
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
            // Long round: many in-process nodes jitter under one runtime; slack keeps each contribution in the round the leader is collecting.
            round_duration_ms: 1000,
            max_payload_bytes: 256,
            estimated_messages: 64,
            client_set_min: 0,
            client_set_max: 64,
            aggregation: None,
        })
    };
    let services = vec![ServiceEntry {
        tag: echo_tag(),
        pubkey: service.pubkey(),
    }];

    let v0 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 0,
        epoch_unix_ms: now_unix_ms(),
        services: services.clone(),
        relay_exchange_keys: relay_xk.clone(),
        subnets: vec![Subnet::new(0, relay_pks.clone(), proto())],
        relay_client_addrs: vec![],
        watchers: vec![],
    })
    .sign_with(&[&committee]);
    // Every subnet carries every service, so growing to two subnets lets
    // ~half the clients re-home to subnet 1 and the rest stay on subnet 0.
    // Subnet 0's config also changes (capacity resize), so v1 exercises the
    // same-id graceful respawn, not just the added subnet.
    let resized = || {
        let ProtocolConfig::Adcnet(mut c) = proto() else {
            unreachable!()
        };
        c.client_set_max = 96;
        ProtocolConfig::Adcnet(c)
    };
    let v1 = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: 1,
        epoch_unix_ms: now_unix_ms(),
        services,
        relay_exchange_keys: relay_xk,
        subnets: vec![
            Subnet::new(0, relay_pks.clone(), resized()),
            Subnet::new(1, relay_pks.clone(), resized()),
        ],
        relay_client_addrs: vec![],
        watchers: vec![],
    })
    .sign_with(&[&committee]);

    // Observer on subnet 0's broadcast topic → live anonymity set + frontier.
    let anon0 = Arc::new(AtomicU64::new(0));
    let frontier0 = Arc::new(AtomicU64::new(0));
    {
        let mut sub0 = net
            .handle(Identity::generate().pubkey())
            .subscribe(&subnet_broadcast_topic(0))
            .await;
        let anon0 = anon0.clone();
        let frontier0 = frontier0.clone();
        let roster = relay_pks.clone();
        let leader = {
            let mut r = relay_pks.clone();
            r.sort();
            r[0]
        };
        tokio::spawn(async move {
            let mut o = AdcnetObserverSession::new(roster, leader, 2);
            while let Some(m) = sub0.recv().await {
                o.on_inbound(m.from, m.payload);
                anon0.store(o.anonymity_set().unwrap_or(0) as u64, Ordering::Relaxed);
                frontier0.store(o.anon_set_round().unwrap_or(0), Ordering::Relaxed);
            }
        });
    }

    // Prepare everyone before publishing v0.
    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(
            Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await,
        );
    }
    let svc_prep = Anymone::prepare(
        service.clone(),
        Arc::new(net.handle(service.pubkey())),
        gov.clone(),
    )
    .await;
    let mut client_preps = Vec::new();
    for id in &clients {
        client_preps.push(
            Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await,
        );
    }

    net.handle(committee.pubkey())
        .publish(TOPIC_CONFIG, bincode::serialize(&v0).unwrap())
        .await;

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
            let Ok(pipe) = a.open(echo_tag()).await else {
                return;
            };
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
    net.handle(committee.pubkey())
        .publish(TOPIC_CONFIG, bincode::serialize(&v1).unwrap())
        .await;

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
    assert!(
        shed < n_clients,
        "subnet 0 must shed re-homed clients, still has {shed}/{n_clients}"
    );

    // Subnet 1's leader is sorted_relays[1 % 3] = relay_pks[1], NOT the
    // sorted-first relay — so a non-zero-index leader must be the one announcing
    // the canonical set and broadcasting output on subnet 1.
    let subnet1_leader = relay_pks[1 % relay_pks.len()];
    let mut bcast1 = net
        .handle(Identity::generate().pubkey())
        .subscribe(&subnet_broadcast_topic(1))
        .await;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let m = bcast1
                .recv()
                .await
                .expect("subnet 1 broadcast topic closed");
            if m.from == subnet1_leader {
                return;
            }
        }
    })
    .await
    .expect("subnet 1's distinct (non-first) leader never broadcast");

    // v1's admission policy binds subnet 1's shares topic to its relay roster;
    // an outsider's publish there must not reach anyone (real relay share
    // traffic keeps flowing, so filter for the forged payload specifically).
    let outsider = Identity::generate();
    let mut shares1 = net
        .handle(Identity::generate().pubkey())
        .subscribe(&subnet_shares_topic(1))
        .await;
    net.handle(outsider.pubkey())
        .publish(&subnet_shares_topic(1), b"forged share".to_vec())
        .await;
    let saw_forged = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            let msg = shares1.recv().await.expect("shares topic closed");
            if msg.payload == b"forged share" {
                return;
            }
        }
    })
    .await
    .is_ok();
    assert!(
        !saw_forged,
        "publish from outside subnet 1's relay roster must be rejected"
    );

    // Config storm: several versions in quick succession, faster than one
    // graceful cutover completes. The subnet must keep running afterwards.
    for (v, max) in [(2u64, 80), (3, 88), (4, 96)] {
        let cfg = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
            round: v,
            epoch_unix_ms: now_unix_ms(),
            services: vec![ServiceEntry {
                tag: echo_tag(),
                pubkey: service.pubkey(),
            }],
            relay_exchange_keys: relays.iter().map(|i| (i.pubkey(), xkw(i))).collect(),
            subnets: vec![
                Subnet::new(0, relay_pks.clone(), {
                    let ProtocolConfig::Adcnet(mut c) = proto() else {
                        unreachable!()
                    };
                    c.client_set_max = max;
                    ProtocolConfig::Adcnet(c)
                }),
                Subnet::new(1, relay_pks.clone(), proto()),
            ],
            relay_client_addrs: vec![],
            watchers: vec![],
        })
        .sign_with(&[&committee]);
        net.handle(committee.pubkey())
            .publish(TOPIC_CONFIG, bincode::serialize(&cfg).unwrap())
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let before = frontier0.load(Ordering::Relaxed);
    let advanced = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if frontier0.load(Ordering::Relaxed) > before {
                return;
            }
        }
    })
    .await;
    assert!(
        advanced.is_ok(),
        "subnet 0 stopped announcing after a config storm (frontier stuck at {before})"
    );

    drop(keep);
}

/// Dropping a never-sent-on pipe must still retire its local client session.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pipe_drop_retires_client_without_further_sends() {
    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let gov = GovernanceBootstrap {
        committee: vec![committee.pubkey()],
        threshold: 1,
    };
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let leader = relay_pks[0];
    let cfg = build_config(&committee, &relays, &service, &client);

    // The leader never broadcasts an empty ClientSet, so retirement shows up
    // as this count freezing, not as it reaching zero.
    let anon_broadcasts = Arc::new(AtomicU64::new(0));
    {
        let mut sub0 = net
            .handle(Identity::generate().pubkey())
            .subscribe(&subnet_broadcast_topic(0))
            .await;
        let anon_broadcasts = anon_broadcasts.clone();
        let roster = relay_pks.clone();
        tokio::spawn(async move {
            let mut o = AdcnetObserverSession::new(roster, leader, 2);
            let mut last_round = None;
            while let Some(m) = sub0.recv().await {
                o.on_inbound(m.from, m.payload);
                if let (Some(r), Some(sz)) = (o.anon_set_round(), o.anonymity_set()) {
                    if sz >= 1 && last_round != Some(r) {
                        last_round = Some(r);
                        anon_broadcasts.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(
            Anymone::prepare(id.clone(), Arc::new(net.handle(id.pubkey())), gov.clone()).await,
        );
    }
    let client_prep = Anymone::prepare(
        client.clone(),
        Arc::new(net.handle(client.pubkey())),
        gov.clone(),
    )
    .await;

    net.handle(committee.pubkey())
        .publish(TOPIC_CONFIG, bincode::serialize(&cfg).unwrap())
        .await;

    let mut relays_running = Vec::new();
    for p in relay_preps {
        relays_running.push(p.start().await.expect("relay start"));
    }

    let client_anymone = client_prep.start().await.expect("client start");
    // Never sends — cover traffic alone must be enough to join and to retire.
    let pipe = client_anymone.open(echo_tag()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(20), async {
        while anon_broadcasts.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("client never settled into the observed canonical set via cover traffic");

    drop(pipe); // Anymone/subnet worker stay alive; only the Pipe goes away.

    // One already in-flight round may still land after Retire; the count must
    // then stabilize rather than keep climbing.
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut prev = anon_broadcasts.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            let cur = anon_broadcasts.load(Ordering::Relaxed);
            if cur == prev {
                break;
            }
            prev = cur;
        }
    })
    .await
    .expect("client kept padding the anonymity set after its Pipe was dropped");

    drop(client_anymone);
    drop(relays_running);
}
