//! anymone-node — thin binary wrapper around `anymone-core`.
//!
//! `run` brings up a real network transport and starts an `Anymone` in one of
//! four roles (committee, relay, service, client). `bootnode` runs a discovery
//! seed that peers dial to find each other. `keygen` mints node identities for
//! a deployment's config.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use anymone_core::transport::Transport;
use anymone_core::{
    announce_relay_registration_at, announce_service_registration,
    spawn_panetiere_committee_scheduler, Anymone, BootstrapConfig, GoodClients,
    GovernanceBootstrap, Identity, Misbehavior, ServiceTag,
};
use clap::{Parser, Subcommand, ValueEnum};
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
    /// Print the public material of an existing identity.
    Pubkeys(PubkeysArgs),
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

#[derive(Parser, Debug)]
struct PubkeysArgs {
    /// Identity file to read (its `.exchange` sibling is read alongside).
    #[arg(long)]
    identity: PathBuf,
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

/// Slot the relay role fills with its `Anymone` handle once started; the
/// misbehavior route answers 503 until then, so the endpoint itself can come
/// up before the first config is adopted.
type AnymoneSlot = Arc<std::sync::RwLock<Option<Arc<Anymone>>>>;

/// `anymone` is `Some` only for the relay role — it's what backs the
/// `/state/misbehavior` fault-injection knob (corrupt/withhold shares live, to
/// showcase Panetiere's attribution). Other roles get no such route. The knob
/// only accepts loopback connections; `/state/peers` stays open for scrapes.
fn spawn_peers_endpoint(
    net: Arc<dyn Transport>,
    role: &'static str,
    port: u16,
    anymone: Option<AnymoneSlot>,
) {
    use axum::extract::ConnectInfo;
    use axum::http::StatusCode;
    use axum::{routing::get, routing::post, Json, Router};
    use std::net::SocketAddr;
    let pubkey = net.local_pubkey();
    let mut app = Router::new().route(
        "/state/peers",
        get({
            let net = net.clone();
            move || {
                let net = net.clone();
                async move {
                    Json(serde_json::json!({
                        "pubkey": pubkey,
                        "role": role,
                        "peers": net.peers(),
                    }))
                }
            }
        }),
    );
    if let Some(slot) = anymone {
        #[derive(serde::Deserialize)]
        struct MisbehaviorBody {
            mode: String,
        }
        app = app.route(
            "/state/misbehavior",
            post(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>,
                      Json(body): Json<MisbehaviorBody>| {
                    let slot = slot.clone();
                    async move {
                        if !peer.ip().is_loopback() {
                            return (StatusCode::FORBIDDEN, "loopback only");
                        }
                        let Some(anymone) = slot.read().unwrap().clone() else {
                            return (StatusCode::SERVICE_UNAVAILABLE, "no config adopted yet");
                        };
                        let mode = match body.mode.as_str() {
                            "honest" => Some(None),
                            "withhold" => Some(Some(Misbehavior::Withhold)),
                            "corrupt_share" => Some(Some(Misbehavior::CorruptShare)),
                            _ => None,
                        };
                        match mode {
                            Some(mode) => {
                                anymone.set_misbehavior(mode);
                                (StatusCode::OK, "ok")
                            }
                            None => (
                                StatusCode::BAD_REQUEST,
                                "mode must be honest|withhold|corrupt_share",
                            ),
                        }
                    }
                },
            ),
        );
    }
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                tracing::info!(%port, "serving /state/peers");
                let _ = axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await;
            }
            Err(e) => tracing::warn!("peers endpoint bind {port}: {e}"),
        }
    });
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
        Cmd::Bootnode(args) => bootnode(args).await,
        Cmd::Keygen(args) => keygen(args),
        Cmd::Pubkeys(args) => pubkeys(args),
    }
}

fn keygen(args: KeygenArgs) -> Result<()> {
    if args.out.exists() {
        return Err(anyhow!(
            "{} already exists; refusing to overwrite",
            args.out.display()
        ));
    }
    let identity = Identity::generate();
    identity
        .save(&args.out)
        .with_context(|| format!("writing identity to {}", args.out.display()))?;
    print_public_material(&args.out, &identity);
    Ok(())
}

fn pubkeys(args: PubkeysArgs) -> Result<()> {
    let identity = Identity::load(&args.identity)
        .with_context(|| format!("loading identity from {}", args.identity.display()))?;
    print_public_material(&args.identity, &identity);
    Ok(())
}

/// The lines a deployment scrapes to render configs. `exchange_pubkey` in a
/// `[[governance.committee]]` entry takes both keys:
/// `{ ecdh = "<exchange_ecdh>", kem = "<exchange_kem>" }`.
fn print_public_material(path: &Path, identity: &Identity) {
    let xpub = identity.exchange_keys();
    println!("identity_path  {}", path.display());
    println!("pubkey         {}", identity.pubkey());
    println!("exchange_ecdh  {}", hex::encode(&xpub.ecdh));
    println!("exchange_kem   {}", hex::encode(&xpub.kem));
}

async fn bootnode(args: BootnodeArgs) -> Result<()> {
    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;
    tracing::info!(pubkey = %identity.pubkey(), "starting bootnode");

    let _transport =
        anymone_core::backend::start_node_transport(&identity, &bootstrap, GoodClients::all())?;
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

    let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);
    let tee = bootstrap.tee.setup().await;
    // Every client is accepted onto the connection; attested subnets narrow it
    // further, per the signed config's policy.
    // Committee and relays are authorized p2p peers; services and clients live
    // on the client plane.
    let transport = match args.role {
        Role::Committee | Role::Relay => {
            anymone_core::backend::start_node_transport(&identity, &bootstrap, GoodClients::all())?
        }
        Role::Service | Role::Client => {
            anymone_core::backend::start_client_transport(&identity, &bootstrap, gov.clone())?.0
        }
    };

    // Endpoint comes up before Anymone start (which blocks on the first
    // config), so scrapes work during bootstrap. The relay's misbehavior route
    // answers 503 until its slot is filled below.
    let misbehavior_slot: Option<AnymoneSlot> =
        (args.role == Role::Relay).then(|| Arc::new(std::sync::RwLock::new(None)));
    if let Some(port) = args.peers_port {
        spawn_peers_endpoint(
            transport.clone(),
            args.role.as_str(),
            port,
            misbehavior_slot.clone(),
        );
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
            let xk = identity.exchange_keys();
            // Advertising the stream address is what lets clients find a relay
            // from the signed config without joining the p2p network. The
            // announcement itself rides a stream connection when one is
            // configured — a relay outside every tracked set can't reach the
            // committee over the backbone.
            let _reannounce = announce_relay_registration_at(
                anymone_core::backend::registration_transport(&identity, &bootstrap, &transport),
                &identity,
                xk,
                bootstrap.network.stream_listen.clone(),
            )
            .await;
            let anymone = Arc::new({
                let mut prep = Anymone::prepare(identity, transport, gov).await;
                prep.set_tee(tee);
                prep.start()
                    .await
                    .map_err(|e| anyhow!("anymone start: {e}"))?
            });
            if let Some(slot) = &misbehavior_slot {
                *slot.write().unwrap() = Some(anymone.clone());
            }
            tracing::info!("relay online; waiting for ctrl-c");
            tokio::signal::ctrl_c().await.ok();
        }
        Role::Service => {
            let label = args
                .service_tag
                .ok_or_else(|| anyhow!("--service-tag is required for role=service"))?;
            let tag = ServiceTag::from_label(&label);
            let xk = identity.exchange_keys();
            let _reannounce =
                announce_service_registration(transport.clone(), &identity, tag, xk).await;
            let anymone = {
                let mut prep = Anymone::prepare(identity, transport, gov).await;
                prep.set_tee(tee);
                prep.start()
                    .await
                    .map_err(|e| anyhow!("anymone start: {e}"))?
            };
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
