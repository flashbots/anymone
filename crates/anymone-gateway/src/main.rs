//! `anymone-gateway` — a REST front door to one anymone channel.
//!
//! Reads a bootstrap TOML, joins the network as a real participant, and serves
//! `POST /messages`, `GET /messages?from=&to=`, `GET /round` for the service tag
//! named by `--tag`. Anything that speaks HTTP can use the channel; no anymone
//! library dependency on the caller's side.

use std::path::PathBuf;

use anymone_core::{
    announce_service_registration, Anymone, BootstrapConfig, GovernanceBootstrap, Identity,
    ServiceTag,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "anymone-gateway",
    about = "HTTP/REST gateway to an anymone channel: POST to submit, GET to read back by round."
)]
struct Args {
    /// Bootstrap TOML (identity, network, governance) — same shape as a node's.
    #[arg(long)]
    config: PathBuf,

    /// Service tag label of the channel to gateway.
    #[arg(long)]
    tag: String,

    /// Port to serve the REST API on.
    #[arg(long, default_value = "8090")]
    port: u16,

    /// Messages kept for retrieval. The oldest are dropped past this, so it
    /// bounds how far back `GET /messages` reaches.
    #[arg(long, default_value = "1000")]
    capacity: usize,

    /// Register the tag with the committee so it's carried on a subnet. Set on
    /// exactly one identity per deployment: the service registry is
    /// last-write-wins per tag, so two identities announcing the same tag make
    /// the committee's proposal flap between them.
    #[arg(long)]
    announce: bool,

    /// Clients to submit through at most, this gateway's own included. Virtual
    /// clients are spawned while submissions are queued; `1` disables them.
    #[arg(long, default_value = "8")]
    max_clients: usize,

    /// Origin allowed to read the API via CORS. Defaults to `*`.
    #[arg(long)]
    allow_origin: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;

    let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);
    let tag = ServiceTag::from_label(&args.tag);
    // Registering the tag makes this a service, which belongs on the backbone.
    // Otherwise it is purely a client of someone else's service.
    let (transport, spawn) = if args.announce {
        (
            anymone_core::backend::start_node_transport(
                &identity,
                &bootstrap,
                anymone_core::GoodClients::all(),
            )?,
            anymone_core::backend::virtual_client_spawner(&bootstrap, gov.clone())?,
        )
    } else {
        anymone_core::backend::start_client_transport(&identity, &bootstrap, gov.clone())?
    };

    // Announce before starting: `Anymone::start` blocks until the first config
    // is adopted, so registering first lets the committee carry the tag in that
    // very first config. Re-announced until placed.
    let _reannounce = if args.announce {
        let xk = identity.exchange_keys();
        Some(announce_service_registration(transport.clone(), &identity, tag, xk).await)
    } else {
        None
    };

    let anymone = Anymone::start(identity, transport, gov)
        .await
        .map_err(|e| anyhow!("anymone start: {e}"))?;

    tracing::info!(
        tag = %args.tag,
        port = args.port,
        max_clients = args.max_clients,
        "anymone-gateway starting"
    );
    anymone_gateway::serve(
        anymone,
        tag,
        spawn,
        args.max_clients,
        args.port,
        args.capacity,
        args.allow_origin,
    )
    .await
}
