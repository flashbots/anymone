//! anymone-node — thin binary wrapper around `anymone-core`.
//!
//! `run` brings up a real libp2p transport and starts an `Anymone` in one of
//! four roles (committee, relay, service, client). `bootnode` runs a discovery
//! seed that peers dial to find each other. `keygen` mints node identities for
//! a deployment's config.

use std::path::PathBuf;
use std::sync::Arc;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::p2p::{Libp2pConfig, Libp2pNetwork};
use anymone_core::transport::Transport;
use anymone_core::{
    announce_relay_registration, announce_service_registration,
    spawn_panetiere_committee_scheduler, Anymone, BootstrapConfig, GovernanceBootstrap, Identity,
    ServiceTag,
};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use libp2p::{Multiaddr, PeerId};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "anymone-node", version, about = "Run an anymone node.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a participating node in one of the four roles.
    Run(RunArgs),
    /// Run a discovery bootnode: a seed peers dial to find one another.
    Bootnode(BootnodeArgs),
    /// Generate a node identity and print its public material for configs.
    Keygen(KeygenArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to the bootstrap TOML config.
    #[arg(long)]
    config: PathBuf,

    /// What role this node plays.
    #[arg(long, value_enum)]
    role: Role,

    /// Service tag (label) — required when role == service.
    #[arg(long)]
    service_tag: Option<String>,

    /// If set, serve `GET /state/peers` on this port for the observer's mesh view.
    #[arg(long)]
    peers_port: Option<u16>,
}

#[derive(Parser, Debug)]
struct BootnodeArgs {
    /// Path to the bootstrap TOML config (only identity_path + network are read).
    #[arg(long)]
    config: PathBuf,
}

#[derive(Parser, Debug)]
struct KeygenArgs {
    /// Identity file to create (a `.exchange` sibling is written alongside).
    #[arg(long)]
    out: PathBuf,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
enum Role {
    Committee,
    Relay,
    Service,
    Client,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Committee => "committee",
            Role::Relay => "relay",
            Role::Service => "service",
            Role::Client => "client",
        }
    }
}

fn spawn_peers_endpoint(net: Arc<Libp2pNetwork>, role: &'static str, port: u16) {
    use axum::{routing::get, Json, Router};
    let pubkey = net.local_pubkey();
    let app = Router::new().route(
        "/state/peers",
        get({
            let net = net.clone();
            move || {
                let net = net.clone();
                async move {
                    let gossip = net.gossip_snapshot().await;
                    Json(serde_json::json!({
                        "pubkey": pubkey,
                        "role": role,
                        "peers": net.peer_snapshot(),
                        "gossip": gossip,
                    }))
                }
            }
        }),
    );
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                tracing::info!(%port, "serving /state/peers");
                let _ = axum::serve(listener, app).await;
            }
            Err(e) => tracing::warn!("peers endpoint bind {port}: {e}"),
        }
    });
}

/// Parse `network.listen` + `network.bootstrap_peers` from a loaded config.
fn network_config(bootstrap: &BootstrapConfig) -> Result<Libp2pConfig> {
    let listen: Multiaddr = bootstrap
        .network
        .listen
        .parse()
        .with_context(|| format!("bad listen multiaddr: {}", bootstrap.network.listen))?;
    let bootstrap_peers: Vec<Multiaddr> = bootstrap
        .network
        .bootstrap_peers
        .iter()
        .map(|s| s.parse::<Multiaddr>().with_context(|| format!("bad bootstrap multiaddr: {s}")))
        .collect::<Result<_>>()?;
    Ok(Libp2pConfig { listen, bootstrap_peers })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    match Cli::parse().cmd {
        Cmd::Run(args) => run(args).await,
        Cmd::Bootnode(args) => bootnode(args).await,
        Cmd::Keygen(args) => keygen(args),
    }
}

fn keygen(args: KeygenArgs) -> Result<()> {
    if args.out.exists() {
        return Err(anyhow!("{} already exists; refusing to overwrite", args.out.display()));
    }
    let identity = Identity::generate();
    identity.save(&args.out).with_context(|| format!("writing identity to {}", args.out.display()))?;
    let peer_id = PeerId::from(identity.to_libp2p_keypair().public());
    let xpub = ExchangePublicKeyWire::from_key(&identity.exchange_pubkey());
    println!("identity_path  {}", args.out.display());
    println!("pubkey         {}", identity.pubkey());
    println!("exchange_pubkey {}", hex::encode(&xpub.0));
    println!("peer_id        {peer_id}");
    Ok(())
}

async fn bootnode(args: BootnodeArgs) -> Result<()> {
    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;
    let peer_id = PeerId::from(identity.to_libp2p_keypair().public());
    tracing::info!(%peer_id, listen = %bootstrap.network.listen, "starting bootnode");

    let net = Libp2pNetwork::start(&identity, network_config(&bootstrap)?)
        .await
        .map_err(|e| anyhow!("libp2p start: {e}"))?;
    // Join the governance topics so the bootnode is in those meshes; held for
    // the process lifetime so the subscriptions stay live.
    let transport: Arc<dyn Transport> = net;
    let mut _subs = Vec::new();
    for topic in [
        anymone_core::governance::TOPIC_CONFIG,
        anymone_core::governance::TOPIC_REGISTRATION,
        anymone_core::governance::TOPIC_FAULTS,
    ] {
        _subs.push(transport.subscribe(topic).await);
    }
    tracing::info!("bootnode online; waiting for ctrl-c");
    tokio::signal::ctrl_c().await.ok();
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;

    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;
    tracing::info!(role = ?args.role, pubkey = %identity.pubkey(), "starting node");

    let net = Libp2pNetwork::start(&identity, network_config(&bootstrap)?)
        .await
        .map_err(|e| anyhow!("libp2p start: {e}"))?;
    let transport: Arc<dyn Transport> = net.clone();
    let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);

    if let Some(port) = args.peers_port {
        spawn_peers_endpoint(net.clone(), args.role.as_str(), port);
    }

    match args.role {
        Role::Committee => {
            let roster = bootstrap.governance.roster();
            let threshold = bootstrap.governance.threshold;
            let ccfg = bootstrap.committee.clone().into_config();
            let _scheduler =
                spawn_panetiere_committee_scheduler(transport, identity, roster, threshold, ccfg)
                    .await;
            tracing::info!("committee online; waiting for ctrl-c");
            tokio::signal::ctrl_c().await.ok();
        }
        Role::Relay => {
            let xk = ExchangePublicKeyWire::from_key(&identity.exchange_pubkey());
            let _reannounce = announce_relay_registration(transport.clone(), &identity, xk).await;
            let _anymone = Anymone::prepare(identity, transport, gov)
                .await
                .start()
                .await
                .map_err(|e| anyhow!("anymone start: {e}"))?;
            tracing::info!("relay online; waiting for ctrl-c");
            tokio::signal::ctrl_c().await.ok();
        }
        Role::Service => {
            let label = args
                .service_tag
                .ok_or_else(|| anyhow!("--service-tag is required for role=service"))?;
            let tag = ServiceTag::from_label(&label);
            let xk = ExchangePublicKeyWire::from_key(&identity.exchange_pubkey());
            let _reannounce =
                announce_service_registration(transport.clone(), &identity, tag, xk).await;
            let anymone = Anymone::prepare(identity, transport, gov)
                .await
                .start()
                .await
                .map_err(|e| anyhow!("anymone start: {e}"))?;
            let mut pipe = anymone
                .bind(tag)
                .await
                .map_err(|e| anyhow!("bind tag {label}: {e}"))?;
            tracing::info!(tag = %label, "service bound; echo loop running");
            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => break,
                    inc = pipe.recv() => {
                        let Some(req) = inc else { break };
                        if let Err(e) = pipe.send_to(req.return_tag, req.payload).await {
                            tracing::warn!("send_to error: {e}");
                        }
                    }
                }
            }
        }
        Role::Client => {
            let _anymone = Anymone::start(identity, transport, gov)
                .await
                .map_err(|e| anyhow!("anymone start: {e}"))?;
            tracing::info!("client online; waiting for ctrl-c");
            tokio::signal::ctrl_c().await.ok();
        }
    }

    Ok(())
}
