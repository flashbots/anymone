//! INVESTIGATION SCRATCH (delete or fold after diagnosis): live deployment
//! shows each client silently skipping ~20% of rounds (canonical set 7-11 of
//! 12) at cover 1.0 on a single Panetiere subnet. This reproduces that topology
//! in-memory: 4 relays, 12 subscribe-only clients, and an observer counting
//! every leader ClientSet.

use std::sync::Arc;
use std::time::Duration;

use anymone_core::{
    Anymone, AnymoneRoundConfiguration, Identity, InMemoryNetwork, PanetiereConfig,
    PanetiereObserverSession, ProtocolConfig, ServiceEntry, ServiceTag, Session,
};

fn room_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.repro.room")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock rounds vs real crypto: meaningful in --release on a quiet machine only"]
async fn subnet_counts_all_clients_every_round() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..4).map(|_| Identity::generate()).collect();
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let relay_xk = relays
        .iter()
        .map(|i| (i.pubkey(), i.exchange_keys()))
        .collect();
    let cfg = AnymoneRoundConfiguration::singleton_subnet(
        0,
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 1000,
            message_size: 64,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: std::env::var("REPRO_CAPACITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            threshold: 2,
            setup_seed: [7u8; 32],
            encoding: anymone_core::config::Encoding::default(),
            ..Default::default()
        }),
        relay_pks.clone(),
        relay_xk,
        vec![ServiceEntry {
            tag: room_tag(),
            pubkey: Identity::generate().pubkey(),
        }],
    )
    .sign_with(&[&committee]);
    let subnet = cfg.body.subnets[0].clone();
    let leader_pk = anymone_core::subnet_leader_pk(&subnet);

    let net = InMemoryNetwork::new();
    let mut nodes: Vec<Anymone> = Vec::new();
    for id in &relays {
        nodes.push(
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await,
        );
    }
    let n_clients: usize = std::env::var("REPRO_CLIENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let mut client_pipes = Vec::new();
    for _ in 0..n_clients {
        let id = Identity::generate();
        let a =
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await;
        let pipe = a.subscribe(room_tag()).await.unwrap();
        client_pipes.push(pipe);
        nodes.push(a);
    }

    // Observer vantage: leader ClientSet broadcasts ride the shares topic.
    let obs_id = Identity::generate();
    let obs_transport = net.handle(obs_id.pubkey());
    let mut shares_sub = anymone_core::Transport::subscribe(
        &obs_transport,
        anymone_core::Topic::Shares(subnet.id),
    )
    .await;
    let mut observer = PanetiereObserverSession::new(relay_pks.clone(), Some(leader_pk), 2);

    // Sample (round, size) pairs as they become the observer's latest set.
    let mut sizes: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    let run = Duration::from_millis(1000 * 15);
    let deadline = tokio::time::Instant::now() + run;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            msg = shares_sub.recv() => {
                let Some(m) = msg else { break };
                observer.on_inbound(m.from, m.payload);
                if let (Some(r), Some(n)) = (observer.anon_set_round(), observer.anonymity_set()) {
                    sizes.insert(r, n);
                }
            }
        }
    }

    let counted: Vec<(u64, usize)> = sizes.iter().map(|(r, n)| (*r, *n)).collect();
    println!("canonical set sizes per round: {counted:?}");
    // Skip the first couple of rounds (startup) and the trailing edge.
    let settled: Vec<usize> = counted
        .iter()
        .skip(2)
        .rev()
        .skip(1)
        .map(|(_, n)| *n)
        .collect();
    assert!(
        settled.len() >= 8,
        "too few settled rounds observed: {counted:?}"
    );
    assert!(
        settled.iter().all(|&n| n == n_clients),
        "canonical set dropped below the full {n_clients} clients: {counted:?}"
    );
}
