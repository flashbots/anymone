//! Repro: clients that join a *running* committee-scheduled ADCNet subnet (the
//! demo's "clients" knob) must (a) get a config and finish `Anymone::start`, and
//! (b) actually contribute, growing the observed anonymity set. In the demo the
//! anon-set number stayed pinned no matter how high the knob went. This drives
//! the same path — committee + relays + service over the in-memory transport —
//! and starts clients *after* the first config to see if they join at all.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::scheduling::{announce_relay_registration, announce_service_registration};
use anymone_core::session::Session;
use anymone_core::transport::Transport;
use anymone_core::{
    committee_roster, spawn_panetiere_committee_scheduler, AdcnetObserverSession, Anymone,
    AnymoneRoundConfiguration, PanetiereCommitteeConfig, GovernanceBootstrap, Identity,
    InMemoryNetwork, Pubkey, ServiceTag, TOPIC_CONFIG,
};

fn xk(id: &Identity) -> ExchangePublicKeyWire {
    ExchangePublicKeyWire::from_key(&id.exchange_pubkey())
}

#[tokio::test(flavor = "multi_thread")]
async fn late_clients_join_and_grow_anon_set() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let net = InMemoryNetwork::new();
    let h = |pk: Pubkey| -> Arc<dyn Transport> { Arc::new(net.handle(pk)) };

    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let committee_pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
    let threshold = 2u32;
    let gov = GovernanceBootstrap { committee: committee_pks.clone(), threshold };
    let chat = ServiceTag::from_label("anymone.chat");

    let ccfg = PanetiereCommitteeConfig {
        // Public subnet at 4s so the leader has time to absorb every client's
        // contribution before the round (and its canonical set) closes. The
        // committee tick is kept short here so the test isn't dominated by
        // config-deliberation latency (the demo runs the committee at 10s).
        committee_round_duration: Duration::from_millis(1000),
        public_round_duration: Duration::from_millis(4000),
        min_relays: 3,
        min_services: 1,
        fault_grace: 2,
        message_size: 64,
        ..PanetiereCommitteeConfig::default()
    };
    for id in &committee {
        spawn_panetiere_committee_scheduler(
            h(id.pubkey()),
            id.clone(),
            committee_roster(&committee),
            threshold,
            ccfg.clone(),
        )
        .await;
    }

    // Relays + service: prepare (subscribe to config) before registering.
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let svc = Identity::generate();
    let mut relay_preps = Vec::new();
    for id in &relays {
        relay_preps.push(Anymone::prepare(id.clone(), h(id.pubkey()), gov.clone()).await);
    }
    let svc_prep = Anymone::prepare(svc.clone(), h(svc.pubkey()), gov.clone()).await;

    // Observer watching the config topic, set up before any registration.
    let obs_cfg = Identity::generate();
    let mut config_sub = h(obs_cfg.pubkey()).subscribe(TOPIC_CONFIG).await;

    for id in &relays {
        announce_relay_registration(h(id.pubkey()), id, xk(id)).await;
    }
    announce_service_registration(h(svc.pubkey()), &svc, chat, xk(&svc)).await;

    for prep in relay_preps {
        tokio::spawn(async move {
            if let Ok(a) = prep.start().await {
                let _keep = a;
                std::future::pending::<()>().await;
            }
        });
    }
    let service = svc_prep.start().await.expect("service start");
    let mut svc_pipe = service.bind(chat).await.expect("service bind");
    tokio::spawn(async move {
        let _keep = service;
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // First config: learn the relay roster for the observer session.
    let cfg_msg = tokio::time::timeout(Duration::from_secs(60), config_sub.recv())
        .await
        .expect("timed out waiting for first config")
        .expect("config topic closed");
    let configuration: AnymoneRoundConfiguration =
        bincode::deserialize(&cfg_msg.payload).expect("config decode");
    let roster = configuration.body.subnets[0].relays.clone();

    // Observer reconstructing the anon set exactly as the dashboard does.
    let max_anon = Arc::new(AtomicU64::new(0));
    {
        let obs_id = Identity::generate();
        let mut sub = h(obs_id.pubkey()).subscribe("anymone/subnet/0").await;
        let mut session = AdcnetObserverSession::new(roster, 2);
        let max_anon = max_anon.clone();
        tokio::spawn(async move {
            while let Some(m) = sub.recv().await {
                session.on_inbound(m.from, m.payload);
                if let Some(n) = session.anonymity_set() {
                    max_anon.fetch_max(n as u64, Ordering::Relaxed);
                }
            }
        });
    }

    // Let the subnet run a little with no clients, then add 3 *late* clients
    // through the normal start path — they must catch the (re-broadcast) config.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Spawn the clients concurrently (as the demo does) so they all join within
    // ~one config re-broadcast, rather than serializing on each `start`.
    const N: u64 = 12;
    for _ in 0..N {
        let cid = Identity::generate();
        let transport = h(cid.pubkey());
        let gov = gov.clone();
        tokio::spawn(async move {
            let Ok(client) = Anymone::start(cid, transport, gov).await else { return };
            let Ok(mut pipe) = client.open(chat).await else { return };
            let _keep = client;
            // Send every round so a client session is built and contributes —
            // an idle pipe never spins one up (it only watches).
            loop {
                let _ = pipe.send(b"hi".to_vec()).await;
                for _ in 0..4 {
                    match tokio::time::timeout(Duration::from_millis(1), pipe.recv()).await {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }

    // Each running client contributes every round, so the leader's canonical
    // set — hence the observed anon set — tracks the full client population.
    // Before the fixes (prune + drop-late + direct leader-ingress routing) it
    // was pinned at the relay count (3) regardless of how many clients joined.
    let mut reached = 0u64;
    for _ in 0..150 {
        reached = max_anon.load(Ordering::Relaxed);
        if reached >= N {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("anon set reached {reached} (population {N})");
    assert!(
        reached >= N,
        "anon set reached only {reached} of {N} late clients \
         (was capped at the relay count before the fix)"
    );
}
