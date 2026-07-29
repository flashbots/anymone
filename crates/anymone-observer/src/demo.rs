//! `anymone-observer demo` — a whole network in one process.
//!
//! Spins up a Panetiere-coordinated committee, a set of relays, an echo service,
//! and a client that sends continuously — all over a single in-memory transport
//! — then attaches the observer to the same transport and serves the global
//! dashboard. No config files, no ports to wire: run it, open the dashboard.
//!
//! The transport is in-memory, so there's no real TCP mesh; the dashboard's
//! mesh view falls back to logical edges (committee clique + relay↔service).
//! Everything else — real Panetiere/ADCNet rounds, committee deliberation,
//! goodput, config history — is the genuine protocol running live.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::scheduling::{announce_relay_registration, announce_service_registration};
use anymone_core::transport::Transport;
use anymone_core::{
    committee_roster, spawn_panetiere_committee_scheduler, Anymone, GovernanceBootstrap, Identity,
    InMemoryNetwork, Misbehavior, PanetiereCommitteeConfig, ServiceTag,
};

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::observatory::Observatory;

const CHAT_TAG_LABEL: &str = "anymone.chat";
const COMMITTEE_SIZE: usize = 3;
const COMMITTEE_THRESHOLD: u32 = 2;

#[derive(Parser, Debug)]
pub struct DemoArgs {
    /// Port to serve the dashboard + `/state` on.
    #[arg(long, default_value = "7000")]
    pub dashboard_port: u16,

    /// Number of relays to run.
    #[arg(long, default_value = "4")]
    pub relays: usize,

    /// Initial number of active clients. The dashboard "clients" knob raises or
    /// lowers this live with no upper bound — clients are spawned on demand and
    /// torn down when the knob drops. Every client holds an open pipe, so it
    /// contributes to the anonymity set every round via protocol-level cover,
    /// whether or not it sends. The knob is the anonymity-set dial.
    #[arg(long, default_value = "8")]
    pub clients: usize,

    /// Per-client send rate (0.0–1.0): the probability that each active client
    /// sends a *real* message in a given round. This is goodput, not cover —
    /// cover is automatic for every open pipe — so it sets channel utilization
    /// without changing the anonymity set. Relays can't tell a real submission
    /// from a cover one.
    #[arg(long = "client-rate", alias = "channel-usage", default_value = "0.5")]
    pub client_rate: f64,

    /// Cover rate (0.0–1.0): the probability that a client with nothing real to
    /// send fills its slot with a zero message anyway. The dashboard "cover"
    /// knob drives this live. 1.0 keeps every open pipe in the anonymity set
    /// every round; lowering it thins cover so the set tracks real senders.
    #[arg(long = "cover-rate", default_value = "1.0")]
    pub cover_rate: f64,

    /// Public-subnet round duration, in milliseconds. Long enough for the
    /// leader to absorb every client's contribution before the round (and its
    /// canonical set) closes — short rounds cap the observed anonymity set.
    #[arg(long, default_value = "4000")]
    pub public_round_ms: u64,

    /// Committee internal-Panetiere round duration, in milliseconds.
    #[arg(long, default_value = "10000")]
    pub committee_round_ms: u64,

    /// Port to serve the chat web app on (separate from the dashboard). The
    /// dashboard's chat feed reads this participant's transcript.
    #[arg(long, default_value = "7001")]
    pub chat_port: u16,
}

fn xk(id: &Identity) -> ExchangePublicKeyWire {
    id.exchange_keys()
}

pub async fn run_demo(args: DemoArgs) -> Result<()> {
    let net = InMemoryNetwork::new();
    let handle = |id: &Identity| -> Arc<dyn Transport> { Arc::new(net.handle(id.pubkey())) };

    // --- committee ---------------------------------------------------------
    let committee_ids: Vec<Identity> = (0..COMMITTEE_SIZE).map(|_| Identity::generate()).collect();
    let committee_pks: Vec<_> = committee_ids.iter().map(|i| i.pubkey()).collect();
    let gov = GovernanceBootstrap {
        committee: committee_pks.clone(),
        threshold: COMMITTEE_THRESHOLD,
    };

    let cover_target = Arc::new(AtomicU32::new(
        (args.cover_rate.clamp(0.0, 1.0) as f32).to_bits(),
    ));
    let ccfg = PanetiereCommitteeConfig {
        committee_round_duration: Duration::from_millis(args.committee_round_ms),
        public_round_duration: Duration::from_millis(args.public_round_ms),
        min_relays: args.relays,
        min_services: 1,
        fault_grace: 2,
        cover_rate: cover_target.clone(),
        // Panetiere-only demo: pin the protocol so the subnet runs Panetiere
        // from the first config instead of starting on ADCNet and escalating.
        // Sidelining on a corrupt-share fault still runs (the fault knob).
        protocol: Some("panetiere".to_string()),
        ..PanetiereCommitteeConfig::default()
    };
    // Schedulers subscribe to the registration topic before returning, so it's
    // safe to publish registrations afterwards.
    let mut committee_tasks = Vec::new();
    for id in &committee_ids {
        committee_tasks.push(
            spawn_panetiere_committee_scheduler(
                handle(id),
                id.clone(),
                committee_roster(&committee_ids),
                COMMITTEE_THRESHOLD,
                ccfg.clone(),
            )
            .await,
        );
    }

    // --- prepare every config consumer (subscribe to anymone/config) BEFORE
    //     any registration is published, so nobody misses the first config ---
    let relay_ids: Vec<Identity> = (0..args.relays).map(|_| Identity::generate()).collect();
    let svc_id = Identity::generate();
    let client_ids: Vec<Identity> = (0..args.clients.max(1))
        .map(|_| Identity::generate())
        .collect();
    let chat_tag = ServiceTag::from_label(CHAT_TAG_LABEL);

    let mut relay_preps = Vec::new();
    for id in &relay_ids {
        relay_preps.push(Anymone::prepare(id.clone(), handle(id), gov.clone()).await);
    }
    let svc_prep = Anymone::prepare(svc_id.clone(), handle(&svc_id), gov.clone()).await;
    let mut client_preps = Vec::new();
    for id in &client_ids {
        client_preps.push(Anymone::prepare(id.clone(), handle(id), gov.clone()).await);
    }

    // --- observer on the same transport ------------------------------------
    let obs_id = Identity::generate();
    let obs_transport = handle(&obs_id);
    let observatory: crate::Shared = Arc::new(Mutex::new(Observatory::new(
        committee_pks.clone(),
        COMMITTEE_THRESHOLD,
        "in-process demo · in-memory gossip".to_string(),
        args.committee_round_ms,
    )));
    crate::spawn_config_loop(
        obs_transport.clone(),
        observatory.clone(),
        committee_pks.clone(),
        COMMITTEE_THRESHOLD,
    );
    crate::spawn_registration_loop(obs_transport.clone(), observatory.clone());
    crate::spawn_committee_loop(
        obs_transport.clone(),
        observatory.clone(),
        committee_pks.clone(),
    );
    crate::spawn_fault_loop(obs_transport.clone(), observatory.clone());

    // --- publish registrations; committee now has quorum and emits a config -
    for id in &relay_ids {
        announce_relay_registration(handle(id), id, xk(id)).await;
    }
    announce_service_registration(handle(&svc_id), &svc_id, chat_tag, xk(&svc_id)).await;

    // --- start everyone (each awaits the now-published config) --------------
    // The `fault` knob drives one relay's misbehavior. It must be a non-leader
    // (subnet 0's leader is sorted(relays)[0] and is the fault reporter), so we
    // target the max-pubkey relay — guaranteed non-leader on the single subnet.
    let fault_target = relay_ids
        .iter()
        .map(|i| i.pubkey())
        .max()
        .expect("relays non-empty");

    // Relays: hold the Anymone alive inside a parked task (dropping it would
    // tear down its subnet workers). Start the fault target on the main path so
    // we keep a handle for the supervisor.
    let mut fault_relay: Option<Anymone> = None;
    for (id, prep) in relay_ids.iter().zip(relay_preps) {
        if id.pubkey() == fault_target {
            let a = prep
                .start()
                .await
                .map_err(|e| anyhow!("fault-relay start: {e}"))?;
            fault_relay = Some(a.clone());
            tokio::spawn(async move {
                let _keep = a;
                std::future::pending::<()>().await;
            });
        } else {
            tokio::spawn(async move {
                match prep.start().await {
                    Ok(a) => {
                        let _keep = a;
                        std::future::pending::<()>().await;
                    }
                    Err(e) => tracing::warn!("relay start: {e}"),
                }
            });
        }
    }
    let fault_relay = fault_relay.expect("fault target is among the relays");

    // Chat backend: a real participant serving the chat app; the dashboard
    // reads its transcript rather than decoding the channel itself.
    let svc = svc_prep
        .start()
        .await
        .map_err(|e| anyhow!("chat backend start: {e}"))?;
    let chat_port = args.chat_port;
    // Virtual clients for the chat backend come off the same in-memory network
    // as everyone else here.
    let chat_spawn: anymone_core::SpawnClient = {
        let net = net.clone();
        let gov = gov.clone();
        Arc::new(move || {
            let net = net.clone();
            let gov = gov.clone();
            Box::pin(async move {
                let id = Identity::generate();
                let transport: Arc<dyn Transport> = Arc::new(net.handle(id.pubkey()));
                Anymone::start(id, transport, gov).await.ok()
            })
        })
    };
    tokio::spawn(async move {
        // Open CORS: the dashboard may be viewed from any host, and the feed is
        // the public broadcast transcript.
        if let Err(e) = anymone_chat::serve(svc, chat_port, None, chat_spawn, 8).await {
            tracing::warn!("chat backend: {e}");
        }
    });
    observatory
        .lock()
        .unwrap()
        .set_chat_endpoint(Some(format!("http://localhost:{chat_port}")));

    // Clients: spawned on demand by the dashboard "clients" knob (no cap). The
    // knob sets the client population, which is the anonymity set — every open
    // pipe contributes cover every round. `--client-rate` is the chance a
    // client layers a real send on top, setting goodput independently.
    let n_clients = args.clients.max(1);
    let round = Duration::from_millis(args.public_round_ms);
    let send_prob = args.client_rate.clamp(0.0, 1.0);
    let cover_pct = (args.cover_rate.clamp(0.0, 1.0) * 100.0).round() as usize;
    let controls = Arc::new(
        crate::DemoControls::new()
            .with(
                "clients",
                crate::Knob::new("clients · anonymity set", n_clients, 1),
            )
            .with(
                "cover",
                crate::Knob::new("cover · % of idle clients sending zero msg", cover_pct, 0),
            )
            .with(
                "fault",
                crate::Knob::enumerated(
                    "fault · target relay misbehavior",
                    vec!["none".into(), "withhold".into(), "corrupt-share".into()],
                    0,
                ),
            ),
    );

    // Fault supervisor: drive the target relay's misbehavior from the knob and
    // tell the observer which relay is under attack. Corrupt-share is
    // unattributable under ADCNet but attributed once escalated to Panetiere.
    {
        let controls = controls.clone();
        let observatory = observatory.clone();
        tokio::spawn(async move {
            loop {
                let mode = match controls.knob("fault").map(|k| k.get()).unwrap_or(0) {
                    1 => Some(Misbehavior::Withhold),
                    2 => Some(Misbehavior::CorruptShare),
                    _ => None,
                };
                fault_relay.set_misbehavior(mode);
                observatory
                    .lock()
                    .unwrap()
                    .set_fault_target(mode.map(|_| fault_target));
                tokio::time::sleep(round).await;
            }
        });
    }
    // Push the "cover" knob into the shared committee target each round.
    {
        let controls = controls.clone();
        let cover_target = cover_target.clone();
        tokio::spawn(async move {
            loop {
                let pct = controls.knob("cover").map(|k| k.get()).unwrap_or(100);
                cover_target.store((pct as f32 / 100.0).to_bits(), Ordering::Relaxed);
                tokio::time::sleep(round).await;
            }
        });
    }

    tracing::info!(
        clients = n_clients,
        client_rate = send_prob,
        "each active client submits randomly at this per-round rate"
    );

    // Supervisor: reconcile the live client population to the knob each tick.
    // New clients join through the normal `Anymone::start` path — the committee
    // re-broadcasts the current config every public round, so a client coming up
    // after the first config still catches it. Lowering the knob aborts the
    // surplus tasks, which drops their `Anymone` and tears down their workers.
    {
        let controls = controls.clone();
        let gov = gov.clone();
        let net = net.clone();
        tokio::spawn(async move {
            let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
            let mut next_index: usize = 0;
            loop {
                let want = controls.knob("clients").map(|k| k.get()).unwrap_or(0);
                while tasks.len() < want {
                    let id = Identity::generate();
                    let transport: Arc<dyn Transport> = Arc::new(net.handle(id.pubkey()));
                    tasks.push(tokio::spawn(client_loop(
                        id,
                        transport,
                        gov.clone(),
                        chat_tag,
                        send_prob,
                        round,
                        next_index,
                    )));
                    next_index += 1;
                }
                while tasks.len() > want {
                    if let Some(h) = tasks.pop() {
                        h.abort();
                    }
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });
    }

    tracing::info!(
        relays = args.relays,
        committee = COMMITTEE_SIZE,
        "demo network running; open the dashboard"
    );
    let _committee_tasks = committee_tasks; // keep schedulers alive
    crate::serve(observatory, args.dashboard_port, Some(controls)).await
}

const HANDLES: &[&str] = &[
    "lark", "moss", "vega", "puck", "wren", "flux", "iris", "nyx",
];
const LINES: &[&str] = &[
    "anyone else here?",
    "the broadcast actually works",
    "no one can tell who sent this",
    "cover traffic hides the real ones",
    "watching the anon set climb",
    "gm from the channel",
    "escalation when?",
    "this is fully anonymous, neat",
];

fn handle_for(index: usize) -> String {
    let base = HANDLES[index % HANDLES.len()];
    if index < HANDLES.len() {
        base.to_string()
    } else {
        format!("{base}{index}")
    }
}

/// One demo chat participant: join, subscribe to the room, and send a random
/// line each round with probability `send_prob`. The client population (the
/// "clients" knob) is the anonymity set; every open pipe contributes cover.
async fn client_loop(
    id: Identity,
    transport: Arc<dyn Transport>,
    gov: GovernanceBootstrap,
    chat_tag: ServiceTag,
    send_prob: f64,
    round: Duration,
    index: usize,
) {
    let client = match Anymone::start(id, transport, gov).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("client {index} start: {e}");
            return;
        }
    };
    let mut pipe = match client.subscribe(chat_tag).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("client {index} subscribe: {e}");
            return;
        }
    };
    let handle = handle_for(index);
    let say = |text: &str| {
        serde_json::to_vec(&anymone_chat::ChatMessage {
            from: handle.clone(),
            text: text.to_string(),
        })
        .expect("ChatMessage serializes")
    };
    if index == 0 {
        let _ = pipe.send(say("hello from the anonymity set")).await;
    }
    loop {
        tokio::time::sleep(round).await;
        if rand::random::<f64>() < send_prob {
            let line = LINES[rand::random::<usize>() % LINES.len()];
            let _ = pipe.send(say(line)).await;
        }
        for _ in 0..8 {
            match tokio::time::timeout(Duration::from_millis(1), pipe.recv()).await {
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    }
}
