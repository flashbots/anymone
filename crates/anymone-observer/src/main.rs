//! anymone-observer — non-participating node that reconstructs a global view of
//! the network and serves it to the dashboard.
//!
//! It subscribes to the governance + subnet topics (learning subnets, faults,
//! and goodput by running the same watch/observer sessions a real node runs),
//! scrapes each node's `/state/peers` for the p2p mesh, and serves the
//! reconstructed `/state` JSON + the dashboard page. See `DASHBOARD.md`.

mod demo;
mod loadgen;
mod observatory;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anymone_core::committee::TOPIC_COMMITTEE_PANETIERE;
use anymone_core::config::{AnymoneRoundConfiguration, ProtocolConfig, Subnet, SubnetId};
use anymone_core::governance::{TOPIC_CONFIG, TOPIC_FAULTS, TOPIC_REGISTRATION};
use anymone_core::runtime::watch_session_for;
use anymone_core::scheduling::Registration;
use anymone_core::session::Session;
use anymone_core::transport::Transport;
use anymone_core::{
    AdcnetObserverSession, BootstrapConfig, Identity, PanetiereObserverSession, Pubkey,
};

use anyhow::{Context, Result};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use observatory::{Observatory, SubnetLive};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

pub(crate) type Shared = Arc<Mutex<Observatory>>;

pub(crate) const DASHBOARD: &str = include_str!("../static/dashboard.html");

/// One live demo lever: an integer level the demo's tasks poll each round.
/// `clients` is the first; relays and services will be added the same way
/// (momentary actions like fault injection will get their own trigger path).
/// Uncapped on purpose — the demo is meant to be pushed arbitrarily far; only a
/// floor (`min`) is enforced.
pub(crate) struct Knob {
    pub label: String,
    pub min: usize,
    value: AtomicUsize,
    /// Discrete choices: when set, the value is an index into these and the
    /// dashboard renders labeled buttons instead of a number stepper.
    options: Option<Vec<String>>,
}

impl Knob {
    pub fn new(label: impl Into<String>, initial: usize, min: usize) -> Self {
        Self {
            label: label.into(),
            min,
            value: AtomicUsize::new(initial.max(min)),
            options: None,
        }
    }
    /// A discrete knob whose value selects one of `options` by index.
    pub fn enumerated(label: impl Into<String>, options: Vec<String>, initial: usize) -> Self {
        let max = options.len().saturating_sub(1);
        Self {
            label: label.into(),
            min: 0,
            value: AtomicUsize::new(initial.min(max)),
            options: Some(options),
        }
    }
    pub fn get(&self) -> usize {
        self.value.load(Ordering::Relaxed)
    }
    fn set(&self, n: usize) {
        let n = match &self.options {
            Some(opts) => n.min(opts.len().saturating_sub(1)),
            None => n.max(self.min),
        };
        self.value.store(n, Ordering::Relaxed);
    }
    fn to_json(&self) -> serde_json::Value {
        let mut v =
            serde_json::json!({ "label": self.label, "value": self.get(), "min": self.min });
        if let Some(opts) = &self.options {
            v["options"] = serde_json::json!(opts);
        }
        v
    }
}

/// The demo's live control surface: a registry of named knobs the dashboard
/// renders and drives via `POST /admin/knob/{name}`. Only present in `demo`
/// mode (a live network has no process-local levers), so the dashboard hides
/// the controls when `/state` omits `control`.
pub(crate) struct DemoControls {
    knobs: std::collections::BTreeMap<String, Knob>,
}

impl DemoControls {
    pub fn new() -> Self {
        Self {
            knobs: std::collections::BTreeMap::new(),
        }
    }
    pub fn with(mut self, name: impl Into<String>, knob: Knob) -> Self {
        self.knobs.insert(name.into(), knob);
        self
    }
    pub fn knob(&self, name: &str) -> Option<&Knob> {
        self.knobs.get(name)
    }
    fn set(&self, name: &str, n: usize) -> bool {
        match self.knobs.get(name) {
            Some(k) => {
                k.set(n);
                true
            }
            None => false,
        }
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.knobs
                .iter()
                .map(|(k, v)| (k.clone(), v.to_json()))
                .collect(),
        )
    }
}

#[derive(Deserialize)]
struct KnobReq {
    count: usize,
}

/// Consecutive output-less rounds before the observer flags a liveness fault
/// (the demo's "fault on the second round").
const FAULT_THRESHOLD: u64 = 2;

/// How many rounds back from the share frontier a relay may have last shared
/// and still count as "live" on the dashboard — covers normal share→combine
/// jitter without flagging a relay that's merely a round behind.
const SHARE_LIVENESS_WINDOW: u64 = 3;

/// How far the output frontier may lag the wire round before the anon set is
/// treated as unknown rather than looked up at the frozen frontier — matches
/// the "stalled" status boundary.
const ANON_SET_STALL_ROUNDS: u64 = 5;

/// Retry cadence for `spawn_config_loop`'s fetch_config fallback.
const CONFIG_PULL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser, Debug)]
#[command(name = "anymone-observer", about = "Global network view for anymone.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Attach to a live network as a watcher and serve the global dashboard.
    Run(RunArgs),
    /// Spin up a whole anymone network (committee + relays + service + client)
    /// in this process over an in-memory transport, and serve the dashboard.
    /// One command, no config, no ports to wire — just open the dashboard.
    Demo(demo::DemoArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Bootstrap TOML (identity, network, governance) — same shape as a node's.
    #[arg(long)]
    config: PathBuf,

    /// Port to serve the dashboard + `/state` on.
    #[arg(long, default_value = "7000")]
    dashboard_port: u16,

    /// Node `/state/peers` base URLs to scrape for the mesh (repeatable),
    /// e.g. `--scrape http://127.0.0.1:7101 --scrape http://127.0.0.1:7102`.
    #[arg(long = "scrape")]
    scrape: Vec<String>,

    /// URL of a chat participant's HTTP API; the dashboard reads its transcript
    /// for the chat feed (the demo sets this in-process).
    #[arg(long)]
    chat_endpoint: Option<String>,

    /// URL of an anymone-eth-bridge gateway; the dashboard reads its `/tx/feed`
    /// for the tx-bus feed.
    #[arg(long)]
    tx_endpoint: Option<String>,

    /// Enable the live load-control panel: the dashboard's `clients` knob spawns
    /// artificial chat clients (one `anymone-chat --bot` process each) against
    /// this same network, reconciled to the knob.
    #[arg(long)]
    enable_load: bool,

    /// Initial artificial-client count (only with --enable-load).
    #[arg(long, default_value = "0")]
    clients: usize,

    /// Path to the `anymone-chat` binary used for load clients.
    #[arg(long, default_value = "anymone-chat")]
    chat_bin: PathBuf,

    /// Directory for per-client identities + generated configs.
    #[arg(long, default_value = "/var/lib/anymone/loadgen")]
    load_state_dir: PathBuf,
}

#[derive(Deserialize)]
struct PeersResp {
    pubkey: Pubkey,
    #[allow(dead_code)]
    role: String,
    peers: Vec<Pubkey>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Run(args) => run(args).await,
        Cmd::Demo(args) => demo::run_demo(args).await,
    }
}

/// Serve the dashboard page at `/` and the reconstructed state at `/state`.
/// Blocks forever. Shared by `run` and the demo.
pub(crate) async fn serve(
    obs: Shared,
    port: u16,
    controls: Option<Arc<DemoControls>>,
) -> Result<()> {
    let mut app = Router::new()
        .route("/", get(|| async { Html(DASHBOARD) }))
        .route(
            "/state",
            get({
                let obs = obs.clone();
                let controls = controls.clone();
                move || {
                    let obs = obs.clone();
                    let controls = controls.clone();
                    async move {
                        let mut v = obs.lock().unwrap().to_json();
                        if let (Some(ctrl), Some(map)) = (&controls, v.as_object_mut()) {
                            map.insert("control".to_string(), ctrl.to_json());
                        }
                        Json(v)
                    }
                }
            }),
        );
    if let Some(ctrl) = controls {
        app = app.route(
            "/admin/knob/:name",
            post(
                move |axum::extract::Path(name): axum::extract::Path<String>,
                      Json(req): Json<KnobReq>| {
                    let ctrl = ctrl.clone();
                    async move {
                        let ok = ctrl.set(&name, req.count);
                        Json(serde_json::json!({ "ok": ok, "control": ctrl.to_json() }))
                    }
                },
            ),
        );
    }
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind dashboard on {addr}"))?;
    tracing::info!(%addr, "observer dashboard live");
    axum::serve(listener, app)
        .await
        .context("dashboard server")?;
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;

    let transport = anymone_core::backend::start_node_transport(
        &identity,
        &bootstrap,
        anymone_core::GoodClients::all(),
    )?;
    // A watcher follows without contributing, so governance lists it as a
    // secondary peer: reachable, never in a subnet roster.
    let _reannounce =
        anymone_core::announce_watcher_registration(transport.clone(), &identity).await;

    let committee: Vec<Pubkey> = bootstrap
        .governance
        .committee
        .iter()
        .map(|m| m.pubkey)
        .collect();
    let threshold = bootstrap.governance.threshold;
    // `run` attaches to an existing network, so the committee's round cadence
    // isn't known here — use the `PanetiereCommitteeConfig` default (1s) for the
    // card's phase ring. The committee round number itself is observed live.
    let vantage = if args.scrape.is_empty() {
        "live network · gossip only (no peer scrape)".to_string()
    } else {
        format!("live network · scraping {} nodes", args.scrape.len())
    };
    let obs: Shared = Arc::new(Mutex::new(Observatory::new(
        committee.clone(),
        threshold,
        vantage,
        // Committee round duration isn't observable from gossip; 0 ⇒ render "-".
        0,
    )));
    if let Some(url) = args.chat_endpoint {
        obs.lock().unwrap().set_chat_endpoint(Some(url));
    }
    if let Some(url) = args.tx_endpoint {
        obs.lock().unwrap().set_tx_endpoint(Some(url));
    }

    spawn_config_loop(transport.clone(), obs.clone(), committee.clone(), threshold);
    spawn_registration_loop(transport.clone(), obs.clone());
    spawn_committee_loop(transport.clone(), obs.clone(), committee);
    spawn_fault_loop(transport.clone(), obs.clone());
    if !args.scrape.is_empty() {
        spawn_scrape_loop(args.scrape.clone(), obs.clone());
    }

    // Optional live load control: the same dashboard knob panel as the demo, but
    // backed by real `anymone-chat --bot` processes joining this network.
    let controls = if args.enable_load {
        let config_text = std::fs::read_to_string(&args.config)
            .with_context(|| format!("reading {} for loadgen", args.config.display()))?;
        let controls = Arc::new(DemoControls::new().with(
            "clients",
            Knob::new("clients · anonymity set", args.clients, 0),
        ));
        loadgen::spawn_supervisor(
            controls.clone(),
            config_text,
            args.chat_bin.clone(),
            args.load_state_dir.clone(),
        );
        Some(controls)
    } else {
        None
    };

    serve(obs, args.dashboard_port, controls).await
}

/// Track config changes; (re)spawn a watcher per subnet whose protocol/version
/// changed, and drop watchers for subnets that disappeared.
fn spawn_config_loop(
    transport: Arc<dyn Transport>,
    obs: Shared,
    committee: Vec<Pubkey>,
    threshold: u32,
) {
    tokio::spawn(async move {
        let mut sub = transport.subscribe(TOPIC_CONFIG).await;
        // Per subnet: a signature of its wiring (protocol + sorted roster) and
        // the watcher task. Respawn whenever the signature changes — a roster
        // swap on renegotiation keeps the protocol but must rebuild the watch
        // session so the new roster (replacement relay) is tracked and the
        // dropped relay stops rendering "missing" forever.
        let mut watchers: HashMap<SubnetId, (String, tokio::task::JoinHandle<()>)> = HashMap::new();
        // TOPIC_CONFIG is a one-shot push per version; retry fetch_config (the
        // relay/service bootstrap path) until gossip or a pull seeds us.
        let mut seeded = false;
        let mut pull_tick = tokio::time::interval(CONFIG_PULL_INTERVAL);
        pull_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let cfg = tokio::select! {
                biased;
                Some(msg) = sub.recv() => {
                    let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload) else {
                        continue;
                    };
                    cfg
                }
                _ = pull_tick.tick(), if !seeded => {
                    let Some(bytes) = transport.fetch_config().await else { continue; };
                    let Ok(cfg) = bincode::deserialize::<AnymoneRoundConfiguration>(&bytes) else { continue; };
                    cfg
                }
            };
            if cfg.verify_multisig(&committee, threshold).is_err() {
                continue;
            }
            let is_new = obs.lock().unwrap().on_config(cfg.clone());
            seeded = true;
            if !is_new {
                continue;
            }
            let present: std::collections::HashSet<SubnetId> =
                cfg.body.subnets.iter().map(|s| s.id).collect();
            // drop watchers for subnets no longer in the config
            watchers.retain(|id, (_, h)| {
                if present.contains(id) {
                    true
                } else {
                    h.abort();
                    false
                }
            });
            for subnet in &cfg.body.subnets {
                if !anymone_core::runtime::subnet_runnable(subnet) {
                    continue;
                }
                let sig = subnet_sig(subnet);
                let needs_respawn = watchers.get(&subnet.id).map_or(true, |(s, _)| *s != sig);
                if needs_respawn {
                    if let Some((_, h)) = watchers.remove(&subnet.id) {
                        h.abort();
                    }
                    let h =
                        tokio::spawn(watch_subnet(subnet.clone(), transport.clone(), obs.clone()));
                    watchers.insert(subnet.id, (sig, h));
                }
            }
        }
    });
}

/// One subnet's live reconstruction: a watch session decodes outputs (goodput
/// + output frontier); on ADCNet an observer session also tracks the share
/// frontier and liveness faults. Round is anchored from the config and ticked
/// on the protocol's own cadence (the node's clock isn't observable).
async fn watch_subnet(subnet: Subnet, transport: Arc<dyn Transport>, obs: Shared) {
    let mut sub = transport
        .subscribe(anymone_core::Topic::Broadcast(subnet.id))
        .await;
    // The observer derives round stats from real wire messages: anon set +
    // msgs/round + output frontier from the broadcast round output (`ClientSet`
    // / `Decoded`), and the share frontier / liveness from the relays' shares on
    // the shares topic. Client contributions are addressed to the relays and
    // never pass an observer.
    let mut shares = if anymone_core::runtime::subnet_uses_ingress(&subnet) {
        Some(
            transport
                .subscribe(anymone_core::Topic::Shares(subnet.id))
                .await,
        )
    } else {
        None
    };
    let mut watch = watch_session_for(&subnet);
    let mut roster = subnet.relays.clone();
    roster.sort();
    let leader = anymone_core::subnet_leader_pk(&subnet);
    let mut adcnet_obs = match subnet.protocol {
        ProtocolConfig::Adcnet(_) | ProtocolConfig::ScheduledAdcnet(_) => {
            Some(AdcnetObserverSession::for_protocol(
                matches!(subnet.protocol, ProtocolConfig::ScheduledAdcnet(_)),
                roster.clone(),
                leader,
                FAULT_THRESHOLD,
            ))
        }
        _ => None,
    };
    let mut panetiere_obs = match subnet.protocol {
        ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => Some(
            PanetiereObserverSession::new(roster.clone(), Some(leader), FAULT_THRESHOLD),
        ),
        _ => None,
    };

    let dur = subnet.protocol.round_duration();
    let mut deadline = tokio::time::Instant::now() + dur;
    let mut decoded_total: u64 = 0;
    // Wire-overhead accounting: bytes seen on the topics the observer watches
    // (broadcast announcements + relay shares) vs the useful decoded payload
    // bytes. The high-volume client→leader ingress isn't observable, so this is
    // the observed overhead, not the full link cost.
    let mut raw_bytes: u64 = 0;
    let mut goodput_bytes: u64 = 0;

    // The observer sessions track rounds from wire `on_inbound` alone — a real
    // `begin_round` would clamp their acceptance window to a clock this task
    // doesn't keep. The watch session ignores its round arg, so 0 is passed.
    let now = Instant::now();
    watch.begin_round(0, now);

    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                let now = Instant::now();
                let out = watch.end_round(0, now);
                decoded_total += out.decoded.len() as u64;
                goodput_bytes += out.decoded.iter().map(|d| d.len() as u64).sum::<u64>();

                // Frontiers come only from real wire messages — `None` until seen,
                // never a synthesized value.
                let mut faults = Vec::new();
                let (share_frontier, output_frontier): (Option<u64>, Option<u64>) =
                    if let Some(o) = adcnet_obs.as_mut() {
                        faults = o.end_round(0, now).faults;
                        (o.share_frontier(), o.output_frontier())
                    } else if let Some(o) = panetiere_obs.as_mut() {
                        faults = o.end_round(0, now).faults;
                        (o.share_frontier().or_else(|| o.round()), o.output_frontier())
                    } else {
                        (None, None)
                    };

                // Highest round actually seen on the wire (share / output /
                // client-set); `None` before any traffic — the dashboard shows `—`.
                let wire_round: Option<u64> = adcnet_obs
                    .as_ref()
                    .and_then(|o| {
                        [o.share_frontier(), o.output_frontier(), o.anon_set_round()]
                            .into_iter()
                            .flatten()
                            .max()
                    })
                    .or_else(|| panetiere_obs.as_ref().and_then(|o| o.round()));

                // Output trails shares by a round or two (latency); a growing gap
                // is a stall. With no fault-tracking observer (Noop) the subnet is
                // just relaying — healthy if it's up.
                let has_observer = adcnet_obs.is_some() || panetiere_obs.is_some();
                let status = match (has_observer, share_frontier, output_frontier) {
                    (false, _, _) => "healthy",
                    (true, None, _) => "starting",
                    (true, Some(_), None) => "lagging",
                    (true, Some(s), Some(o)) => match s.saturating_sub(o) {
                        0..=2 => "healthy",
                        3..=5 => "lagging",
                        _ => "stalled",
                    },
                };
                // Relays observed sharing recently → live; the rest of the
                // roster renders "missing". Indices map into the sorted roster.
                let recent_idxs = adcnet_obs
                    .as_ref()
                    .map(|o| o.relays_shared_recent(SHARE_LIVENESS_WINDOW))
                    .or_else(|| panetiere_obs.as_ref().map(|o| o.relays_shared_recent(SHARE_LIVENESS_WINDOW)));
                let live_relays: Vec<Pubkey> = recent_idxs
                    .map(|idxs| idxs.into_iter().filter_map(|i| roster.get(i).copied()).collect())
                    .unwrap_or_default();
                // Anon set for the output frontier (the round whose msgs we count),
                // so per-round msgs never exceed it (anon = msgs + cover). A
                // stalled decode freezes the frontier, and the fallback lookup
                // would replay the set of that long-dead round (possibly from a
                // different client-population era) indefinitely — show nothing
                // instead once the frontier lags the wire.
                // Scheduled flow: a message hides among clients present in both
                // its reservation and delivery rounds, so the honest anon
                // number is the returning set, not one round's membership.
                let scheduled = matches!(
                    subnet.protocol,
                    anymone_core::ProtocolConfig::ScheduledPanetiere(_)
                );
                let anon_set = output_frontier
                    .filter(|of| {
                        wire_round.is_none_or(|w| w.saturating_sub(*of) <= ANON_SET_STALL_ROUNDS)
                    })
                    .and_then(|r| {
                        let pan = panetiere_obs.as_ref();
                        adcnet_obs
                            .as_ref()
                            .and_then(|o| o.anonymity_set_for(r))
                            .or_else(|| {
                                if scheduled {
                                    pan.and_then(|o| o.returning_set())
                                } else {
                                    pan.and_then(|o| o.anonymity_set_for(r))
                                }
                            })
                    })
                    .unwrap_or(0) as u64;
                // Ids behind that set, so the participant count can dedupe a
                // client announced on more than one subnet.
                let clients: Vec<u32> = panetiere_obs
                    .as_ref()
                    .and_then(|o| o.latest_clients().map(|(_, c)| c.to_vec()))
                    .unwrap_or_default();
                {
                    let mut g = obs.lock().unwrap();
                    g.update_live(subnet.id, SubnetLive {
                        round: wire_round,
                        decoded: decoded_total,
                        share_frontier,
                        output_frontier,
                        status: status.to_string(),
                        anon_set,
                        clients,
                        live_relays,
                        raw_bytes,
                        goodput_bytes,
                    });
                    // Attribute a fault only to the round it was actually seen in.
                    if let Some(r) = wire_round {
                        for f in &faults {
                            g.record_fault(r, subnet.id, f);
                        }
                    }
                }

                deadline += dur;
                watch.begin_round(0, now);
            }
            Some(msg) = sub.recv() => {
                let anymone_core::Inbound { from, payload } = msg;
                raw_bytes += payload.len() as u64;
                watch.on_inbound(from, payload.clone());
                if let Some(o) = adcnet_obs.as_mut() { o.on_inbound(from, payload.clone()); }
                if let Some(o) = panetiere_obs.as_mut() { o.on_inbound(from, payload); }
            }
            Some(msg) = async {
                match shares.as_mut() {
                    Some(s) => s.recv().await,
                    None => std::future::pending::<Option<anymone_core::Inbound>>().await,
                }
            } => {
                // Shares topic: each relay's decryption share. Feed the observer
                // so the share frontier / liveness track from the real shares.
                let anymone_core::Inbound { from, payload } = msg;
                raw_bytes += payload.len() as u64;
                if let Some(o) = adcnet_obs.as_mut() { o.on_inbound(from, payload.clone()); }
                if let Some(o) = panetiere_obs.as_mut() { o.on_inbound(from, payload); }
            }
        }
    }
}

fn spawn_registration_loop(transport: Arc<dyn Transport>, obs: Shared) {
    tokio::spawn(async move {
        let mut sub = transport.subscribe(TOPIC_REGISTRATION).await;
        while let Some(msg) = sub.recv().await {
            if let Ok(reg) = bincode::deserialize::<Registration>(&msg.payload) {
                if reg.verify() {
                    if let Registration::Relay { pubkey, .. } = reg {
                        obs.lock().unwrap().on_relay_registration(pubkey);
                    }
                }
            }
        }
    });
}

fn spawn_committee_loop(transport: Arc<dyn Transport>, obs: Shared, committee: Vec<Pubkey>) {
    tokio::spawn(async move {
        let mut sub = transport.subscribe(TOPIC_COMMITTEE_PANETIERE).await;
        let mut sigs = transport
            .subscribe(anymone_core::committee::TOPIC_COMMITTEE_SIGS)
            .await;
        // Read the committee's round off its genuine Panetiere messages (each
        // carries the round) rather than guessing from a clock or message count.
        // Members stamp their sorted-committee index, so the roster must be sorted.
        let mut roster = committee.clone();
        roster.sort();
        let mut observer = PanetiereObserverSession::new(roster, None, 0);
        loop {
            tokio::select! {
                Some(msg) = sub.recv() => {
                    observer.on_inbound(msg.from, msg.payload);
                    let mut g = obs.lock().unwrap();
                    if let Some(round) = observer.round() {
                        g.set_committee_round(round);
                        if let Some(n) = observer.anonymity_set_for(round) {
                            g.set_committee_anon_set(n as u64);
                        }
                    }
                }
                // A member's signature over a body that isn't the current config
                // is a deliberation in progress (fault renegotiation, capacity
                // re-proposal, subnet growth alike).
                Some(msg) = sigs.recv() => {
                    if let Ok(sig) =
                        bincode::deserialize::<anymone_core::scheduler_core::CommitteeSig>(&msg.payload)
                    {
                        if committee.contains(&sig.signer) {
                            obs.lock().unwrap().on_committee_sig(&sig.body_bytes);
                        }
                    }
                }
                else => break,
            }
        }
    });
}

fn spawn_fault_loop(transport: Arc<dyn Transport>, obs: Shared) {
    // Parse `FaultReport`s gossiped by subnet leaders and fold them into the
    // dashboard feed. The observer also derives faults itself from the
    // per-subnet watchers; `record_fault` dedups by round+subnet+kind, so a
    // gossiped report and a self-derived one collapse to one entry.
    tokio::spawn(async move {
        let mut sub = transport.subscribe(TOPIC_FAULTS).await;
        while let Some(msg) = sub.recv().await {
            if let Some(report) = anymone_core::FaultReport::decode(&msg.payload) {
                obs.lock()
                    .unwrap()
                    .record_fault(report.round, report.subnet, &report.fault);
            }
        }
    });
}

fn spawn_scrape_loop(urls: Vec<String>, obs: Shared) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            for base in &urls {
                let url = format!("{}/state/peers", base.trim_end_matches('/'));
                match client
                    .get(&url)
                    .timeout(Duration::from_millis(800))
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if let Ok(p) = resp.json::<PeersResp>().await {
                            obs.lock().unwrap().apply_scrape(p.pubkey, p.role, p.peers);
                        }
                    }
                    Err(_) => { /* node down or not serving peers; skip this round */ }
                }
            }
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    });
}

fn proto_key(p: &ProtocolConfig) -> String {
    match p {
        ProtocolConfig::Noop(_) => "noop",
        ProtocolConfig::Panetiere(_) => "panetiere",
        ProtocolConfig::ScheduledPanetiere(_) => "scheduledpanetiere",
        ProtocolConfig::Adcnet(_) => "adcnet",
        ProtocolConfig::ScheduledAdcnet(_) => "scheduledadcnet",
    }
    .to_string()
}

/// Signature of a subnet's wiring (protocol + sorted roster). The config watcher
/// respawns a subnet's watch session whenever this changes — so a renegotiation
/// that swaps a relay but keeps the protocol still rebuilds the observer with
/// the new roster.
fn subnet_sig(s: &Subnet) -> String {
    let mut roster = s.relays.clone();
    roster.sort();
    let relays: Vec<String> = roster.iter().map(|p| hex::encode(p.0)).collect();
    format!("{}|{}", proto_key(&s.protocol), relays.join(","))
}
