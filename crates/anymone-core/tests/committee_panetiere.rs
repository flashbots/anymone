//! D5c test: Panetiere-coordinated committee scheduling on an in-memory
//! transport. Three committee members run an internal Panetiere subnet to
//! deliberate; the lead member proposes a body; all members independently
//! sign and gossip; once two signatures land on `anymone/committee/sigs`
//! the multisig-assembled config appears on `anymone/config`.

use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{ExchangePublicKeyWire, ProtocolConfig};
use anymone_core::{
    committee_roster, spawn_panetiere_committee_scheduler, Anymone, AnymoneRoundConfiguration,
    PanetiereCommitteeConfig, GovernanceBootstrap, Identity, InMemoryNetwork, Misbehavior,
    Registration, ServiceTag, TOPIC_CONFIG, TOPIC_REGISTRATION,
};
use anymone_core::transport::Transport;

fn xkw(id: &Identity) -> ExchangePublicKeyWire {
    ExchangePublicKeyWire::from_key(&id.exchange_pubkey())
}

#[tokio::test(flavor = "multi_thread")]
async fn committee_panetiere_publishes_multisig_config() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let c0 = Identity::generate();
    let c1 = Identity::generate();
    let c2 = Identity::generate();
    let committee_pks = vec![c0.pubkey(), c1.pubkey(), c2.pubkey()];
    let roster = committee_roster(&[c0.clone(), c1.clone(), c2.clone()]);
    let threshold = 2u32;

    // Spawn one Panetiere committee scheduler per member, each backed by
    // their own InMemoryHandle on the shared network.
    let mk_handle = |pk| -> Arc<dyn Transport> { Arc::new(net.handle(pk)) };

    let cfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(200),
        public_round_duration: Duration::from_millis(200),
        min_relays: 1,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };

    let _h0 = spawn_panetiere_committee_scheduler(
        mk_handle(c0.pubkey()),
        c0.clone(),
        roster.clone(),
        threshold,
        cfg.clone(),
    )
    .await;
    let _h1 = spawn_panetiere_committee_scheduler(
        mk_handle(c1.pubkey()),
        c1.clone(),
        roster.clone(),
        threshold,
        cfg.clone(),
    )
    .await;
    let _h2 = spawn_panetiere_committee_scheduler(
        mk_handle(c2.pubkey()),
        c2.clone(),
        roster.clone(),
        threshold,
        cfg.clone(),
    )
    .await;

    // Subscribe to TOPIC_CONFIG from a separate observer handle.
    let observer = Identity::generate();
    let obs_transport: Arc<dyn Transport> = Arc::new(net.handle(observer.pubkey()));
    let mut config_sub = obs_transport.subscribe(TOPIC_CONFIG).await;

    // Publish a relay + service registration via another observer handle.
    let relay = Identity::generate();
    let relay_pk = relay.pubkey();
    let relay_xk = anymone_core::config::ExchangePublicKeyWire::from_key(&relay.exchange_pubkey());
    let svc = Identity::generate();
    let svc_pk = svc.pubkey();
    let svc_xk = anymone_core::config::ExchangePublicKeyWire::from_key(&svc.exchange_pubkey());
    let publisher = Identity::generate();
    let pub_transport: Arc<dyn Transport> = Arc::new(net.handle(publisher.pubkey()));
    pub_transport
        .publish(
            TOPIC_REGISTRATION,
            Registration::relay(&relay, relay_xk).encode(),
        )
        .await;
    pub_transport
        .publish(
            TOPIC_REGISTRATION,
            Registration::service(&svc, ServiceTag::from_label("anymone.echo"), svc_xk).encode(),
        )
        .await;

    // Await a signed config on the config topic.
    let bound = Duration::from_secs(30);
    let cfg_msg = tokio::time::timeout(bound, config_sub.recv())
        .await
        .expect("timed out waiting for signed config")
        .expect("config topic closed");
    let cfg: AnymoneRoundConfiguration =
        bincode::deserialize(&cfg_msg.payload).expect("config bytes decode");

    cfg.verify_multisig(&committee_pks, threshold)
        .expect("multisig verifies");

    // Configuration body sanity-check.
    assert_eq!(cfg.body.subnets.len(), 1);
    assert!(cfg.body.subnets[0]
        .relays
        .iter()
        .any(|p| *p == relay_pk));
    assert!(cfg.body.subnets[0]
        .services
        .iter()
        .any(|s| s.pubkey == svc_pk));
}

/// Committee members spawned several rounds apart (vs run.sh's simultaneous
/// launch) must still publish a config.
#[tokio::test(flavor = "multi_thread")]
async fn committee_converges_despite_staggered_member_start() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let c0 = Identity::generate();
    let c1 = Identity::generate();
    let c2 = Identity::generate();
    let committee_pks = vec![c0.pubkey(), c1.pubkey(), c2.pubkey()];
    let roster = committee_roster(&[c0.clone(), c1.clone(), c2.clone()]);
    let threshold = 2u32;
    let mk_handle = |pk| -> Arc<dyn Transport> { Arc::new(net.handle(pk)) };

    let cfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(200),
        public_round_duration: Duration::from_millis(200),
        min_relays: 1,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };

    let observer = Identity::generate();
    let obs_transport: Arc<dyn Transport> = Arc::new(net.handle(observer.pubkey()));
    let mut config_sub = obs_transport.subscribe(TOPIC_CONFIG).await;

    let relay = Identity::generate();
    let svc = Identity::generate();
    let publisher = Identity::generate();
    let pub_transport: Arc<dyn Transport> = Arc::new(net.handle(publisher.pubkey()));
    let relay_reg = Registration::relay(&relay, xkw(&relay)).encode();
    let svc_reg =
        Registration::service(&svc, ServiceTag::from_label("anymone.echo"), xkw(&svc)).encode();
    // Relays/services re-announce until placed (AnymonePrep::start_announcing):
    // a one-shot publish before the committee subscribes is dropped (broadcast
    // has no replay), which is exactly the race a staggered start creates.
    let announce = tokio::spawn({
        let pub_transport = pub_transport.clone();
        async move {
            loop {
                pub_transport.publish(TOPIC_REGISTRATION, relay_reg.clone()).await;
                pub_transport.publish(TOPIC_REGISTRATION, svc_reg.clone()).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    });

    let stagger = Duration::from_millis(1500);
    let _h0 = spawn_panetiere_committee_scheduler(
        mk_handle(c0.pubkey()), c0.clone(), roster.clone(), threshold, cfg.clone(),
    )
    .await;
    tokio::time::sleep(stagger).await;
    let _h1 = spawn_panetiere_committee_scheduler(
        mk_handle(c1.pubkey()), c1.clone(), roster.clone(), threshold, cfg.clone(),
    )
    .await;
    tokio::time::sleep(stagger).await;
    let _h2 = spawn_panetiere_committee_scheduler(
        mk_handle(c2.pubkey()), c2.clone(), roster.clone(), threshold, cfg.clone(),
    )
    .await;

    let cfg_msg = tokio::time::timeout(Duration::from_secs(30), config_sub.recv())
        .await
        .expect("no signed config within 30s after staggered committee start")
        .expect("config topic closed");
    announce.abort();
    let rc: AnymoneRoundConfiguration =
        bincode::deserialize(&cfg_msg.payload).expect("config bytes decode");
    rc.verify_multisig(&committee_pks, threshold)
        .expect("multisig verifies");
    assert_eq!(rc.body.subnets.len(), 1);
}

/// Full-stack reproduction of the demo's "stuck at one subnet" report: a real
/// committee + relays + service + a client population that exceeds one subnet's
/// capacity must drive the committee to schedule a SECOND subnet and publish it.
/// This is the integration the two narrower tests don't cover — committee
/// observes the busy subnet via `on_subnet_message`, `tick` grows the count, and
/// the larger config is anonymised through the committee Panetiere and published.
#[tokio::test(flavor = "multi_thread")]
async fn committee_scales_to_second_subnet_under_load() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let committee_pks: Vec<_> = committee_ids.iter().map(|i| i.pubkey()).collect();
    let threshold = 2u32;
    let gov = GovernanceBootstrap { committee: committee_pks.clone(), threshold };
    let mk = |pk| -> Arc<dyn Transport> { Arc::new(net.handle(pk)) };

    let ccfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(1500),
        public_round_duration: Duration::from_millis(1500),
        min_relays: 3,
        min_services: 1,
        fault_grace: 2,
        escalation_grace: 5,
        subnet_grow_at: 31,
        message_size: 64,
    };
    let mut committee_tasks = Vec::new();
    for id in &committee_ids {
        committee_tasks.push(
            spawn_panetiere_committee_scheduler(
                mk(id.pubkey()),
                id.clone(),
                committee_roster(&committee_ids),
                threshold,
                ccfg.clone(),
            )
            .await,
        );
    }

    let obs = Identity::generate();
    let mut config_sub = mk(obs.pubkey()).subscribe(TOPIC_CONFIG).await;

    // Prepare relays + service + a client population (> the configured grow mark)
    // before any registration is published, so nobody misses the first config.
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let chat = ServiceTag::from_label("anymone.echo");
    let n_clients = 48usize;
    let clients: Vec<Identity> = (0..n_clients).map(|_| Identity::generate()).collect();

    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(Anymone::prepare(id.clone(), mk(id.pubkey()), gov.clone()).await);
    }
    let svc_prep = Anymone::prepare(service.clone(), mk(service.pubkey()), gov.clone()).await;
    let mut client_preps = Vec::new();
    for id in &clients {
        client_preps.push(Anymone::prepare(id.clone(), mk(id.pubkey()), gov.clone()).await);
    }

    // Register relays + service so the committee proposes v0.
    let pubh = mk(Identity::generate().pubkey());
    for id in &relays {
        pubh.publish(TOPIC_REGISTRATION, Registration::relay(id, xkw(id)).encode()).await;
    }
    pubh.publish(
        TOPIC_REGISTRATION,
        Registration::service(&service, chat, xkw(&service)).encode(),
    )
    .await;

    // Start relays + service (held alive in `keep`).
    let mut keep: Vec<Anymone> = Vec::new();
    for p in relay_preps {
        keep.push(p.start().await.expect("relay start"));
    }
    let svc = svc_prep.start().await.expect("service start");
    let mut svc_pipe = svc.bind(chat).await.expect("service bind");
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });
    keep.push(svc);

    // Each client starts, opens the tag, and sends every round — so once its
    // session is built it stays in the canonical set, pushing the anon set past
    // one subnet's capacity.
    for prep in client_preps {
        tokio::spawn(async move {
            let Ok(a) = prep.start().await else { return };
            let Ok(pipe) = a.open(chat).await else { return };
            let _keep = a;
            loop {
                let _ = pipe.send(b"load".to_vec()).await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
        });
    }

    // The committee must observe the busy subnet, grow the count, and publish a
    // ≥2-subnet config.
    // Generous bound: this is a heavy 30-client integration test, and the whole
    // suite runs its binaries in parallel, so wall-clock stretches under load.
    let two = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let msg = config_sub.recv().await.expect("config topic closed");
            if let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) {
                if cfg.body.subnets.len() >= 2 {
                    return cfg;
                }
            }
        }
    })
    .await
    .expect("committee never scheduled a second subnet under client load");

    two.verify_multisig(&committee_pks, threshold).expect("multisig verifies");
    assert!(two.body.subnets.len() >= 2);
    let _committee_tasks = committee_tasks;
    let _keep = keep;
}

/// The demo's headline: a live ADCNet subnet loses a relay (in-band via
/// `set_misbehavior`, the demo's `fault` knob), the committee — observing the
/// subnet's shares topic — detects the liveness fault, sidelines the relay, and
/// escalates the subnet ADCNet→Panetiere, publishing the new config. Proves the
/// fault→escalation path the demo relies on, end to end over a real committee.
#[tokio::test(flavor = "multi_thread")]
async fn committee_escalates_to_panetiere_on_relay_fault() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let committee_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let committee_pks: Vec<_> = committee_ids.iter().map(|i| i.pubkey()).collect();
    let threshold = 2u32;
    let gov = GovernanceBootstrap { committee: committee_pks.clone(), threshold };
    let mk = |pk| -> Arc<dyn Transport> { Arc::new(net.handle(pk)) };

    // `min_relays` = the full relay count, exactly as the demo configures it.
    // Sidelining a faulted relay drops it from the registered set, so the
    // committee must still escalate with the relays that remain — not wedge.
    let n_relays = 3;
    let ccfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(600),
        public_round_duration: Duration::from_millis(600),
        min_relays: n_relays,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };
    let mut committee_tasks = Vec::new();
    for id in &committee_ids {
        committee_tasks.push(
            spawn_panetiere_committee_scheduler(
                mk(id.pubkey()),
                id.clone(),
                committee_roster(&committee_ids),
                threshold,
                ccfg.clone(),
            )
            .await,
        );
    }

    let obs = Identity::generate();
    let mut config_sub = mk(obs.pubkey()).subscribe(TOPIC_CONFIG).await;

    let relays: Vec<Identity> = (0..n_relays).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let chat = ServiceTag::from_label("anymone.echo");
    let client = Identity::generate();

    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(Anymone::prepare(id.clone(), mk(id.pubkey()), gov.clone()).await);
    }
    let svc_prep = Anymone::prepare(service.clone(), mk(service.pubkey()), gov.clone()).await;
    let client_prep = Anymone::prepare(client.clone(), mk(client.pubkey()), gov.clone()).await;

    let pubh = mk(Identity::generate().pubkey());
    for id in &relays {
        pubh.publish(TOPIC_REGISTRATION, Registration::relay(id, xkw(id)).encode()).await;
    }
    pubh.publish(
        TOPIC_REGISTRATION,
        Registration::service(&service, chat, xkw(&service)).encode(),
    )
    .await;

    // Start relays, keeping each Anymone paired with its identity so we can
    // poison a specific non-leader one later.
    let mut relay_nodes: Vec<(Identity, Anymone)> = Vec::new();
    for (id, prep) in relays.iter().zip(relay_preps) {
        relay_nodes.push((id.clone(), prep.start().await.expect("relay start")));
    }
    let svc = svc_prep.start().await.expect("service start");
    let mut svc_pipe = svc.bind(chat).await.expect("service bind");
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // One client sends every round, so the subnet runs rounds and relays publish
    // shares — without traffic there's nothing for the committee to miss.
    let client_node = client_prep.start().await.expect("client start");
    let pipe = client_node.open(chat).await.expect("client open");
    tokio::spawn(async move {
        let _keep = client_node;
        loop {
            let _ = pipe.send(b"ping".to_vec()).await;
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    });

    // First config must be a single ADCNet subnet.
    let v0 = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let msg = config_sub.recv().await.expect("config topic closed");
            if let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) {
                if !cfg.body.subnets.is_empty() {
                    return cfg;
                }
            }
        }
    })
    .await
    .expect("committee never published a first config");
    assert!(
        matches!(v0.body.subnets[0].protocol, ProtocolConfig::Adcnet(_)),
        "the subnet should start on ADCNet, got {:?}",
        v0.body.subnets[0].protocol
    );

    // Poison a non-leader relay (leader = sorted(relays)[0]; pick the max pk).
    let leader = relays.iter().map(|i| i.pubkey()).min().unwrap();
    let victim = relays.iter().map(|i| i.pubkey()).max().unwrap();
    assert_ne!(leader, victim);
    relay_nodes
        .iter()
        .find(|(id, _)| id.pubkey() == victim)
        .map(|(_, a)| a.set_misbehavior(Some(Misbehavior::Withhold)))
        .expect("victim relay present");

    // The committee must observe the stall and publish a Panetiere config.
    let escalated = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let msg = config_sub.recv().await.expect("config topic closed");
            if let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) {
                if matches!(cfg.body.subnets[0].protocol, ProtocolConfig::Panetiere(_)) {
                    return cfg;
                }
            }
        }
    })
    .await
    .expect("committee never escalated the faulted subnet to Panetiere");

    escalated.verify_multisig(&committee_pks, threshold).expect("multisig verifies");
    assert!(escalated.body.round > v0.body.round, "escalated config is a newer version");
    let _committee_tasks = committee_tasks;
    let _relay_nodes = relay_nodes;
    let _svc = svc;
}
