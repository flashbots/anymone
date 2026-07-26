//! `anymone-chat` — a deployable anonymous-broadcast chat node.
//!
//! Reads a bootstrap TOML, joins over libp2p as a real participant, registers
//! the chat room, and serves the chat web app. Anyone with the config can run
//! it and participate; every instance sees every message.

use std::path::PathBuf;
use std::sync::Arc;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::p2p::Libp2pNetwork;
use anymone_core::transport::Transport;
use anymone_core::{
    announce_service_registration, Anymone, BootstrapConfig, GovernanceBootstrap, Identity,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "anymone-chat",
    about = "Anonymous broadcast chat over anymone."
)]
struct Args {
    /// Bootstrap TOML (identity, network, governance) — same shape as a node's.
    #[arg(long)]
    config: PathBuf,

    /// Port to serve the chat web app on.
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Run headless as a client with this handle instead of serving the web app
    /// — seeds traffic into a deployment. One bot = one client.
    #[arg(long)]
    bot: Option<String>,

    /// (bot) Probability [0,1] of sending a real message each round. The round
    /// duration that paces sends is taken from the adopted config.
    #[arg(long, default_value = "0.5")]
    send_rate: f64,

    /// Origin allowed to read `/chat/feed` via CORS. Defaults to `*`.
    #[arg(long)]
    dashboard_origin: Option<String>,
}

// A chat client is one gossip subscription and one client round per protocol
// round; the default pool sizes to the machine's CPUs, so a demo box running
// dozens of bots spends thousands of threads to do nothing between rounds.
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

    let net = Libp2pNetwork::start(&identity, bootstrap.libp2p_config()?)
        .await
        .map_err(|e| anyhow!("libp2p start: {e}"))?;
    let transport: Arc<dyn Transport> = net.clone();
    let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);

    match args.bot {
        // A bot is a pure client: no service registration, just a participant in
        // the anonymity set. One bot = one client.
        Some(handle) => {
            let anymone = Anymone::start(identity, transport, gov)
                .await
                .map_err(|e| anyhow!("anymone start: {e}"))?;
            anymone_chat::run_bot(anymone, handle, args.send_rate).await
        }
        // Serving the web app: register the chat room so the committee places it
        // (placement is by tag, so a duplicate registration is harmless;
        // re-announced until placed).
        None => {
            let xk = ExchangePublicKeyWire::from_key(&identity.exchange_pubkey());
            let _reannounce = announce_service_registration(
                transport.clone(),
                &identity,
                anymone_chat::chat_tag(),
                xk,
            )
            .await;
            let anymone = Anymone::prepare(identity, transport, gov)
                .await
                .start()
                .await
                .map_err(|e| anyhow!("anymone start: {e}"))?;
            anymone_chat::serve(anymone, args.port, args.dashboard_origin).await
        }
    }
}
