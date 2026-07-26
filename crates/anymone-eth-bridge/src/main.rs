//! `anymone-eth-bridge` — the anonymous tx bus's bridge to plain Ethereum
//! JSON-RPC. `--serve <addr>` runs the `eth_sendRawTransaction` front door
//! (bus ingress, for wallets); `--forward-to <rpc-url>` forwards bus traffic
//! to any node's `eth_sendRawTransaction` (bus egress, for node operators).
//! Enable either or both in one process — no reth dependency, works against
//! any client. See `reth_anon_mempool_design.md` §3/§6.

use std::path::PathBuf;
use std::sync::Arc;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::p2p::Libp2pNetwork;
use anymone_core::transport::Transport;
use anymone_core::{
    announce_service_registration, Anymone, BootstrapConfig, GovernanceBootstrap, Identity,
};
use anymone_eth_bridge::{bus_loop, router, AppState, HttpRpcSink, TxFeed};
use anymone_txbus::StatelessLimits;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "anymone-eth-bridge",
    about = "Bridge the anonymous tx bus to plain Ethereum JSON-RPC: --serve for ingress, --forward-to for egress."
)]
struct Args {
    /// Bootstrap TOML (identity, network, governance) — same shape as a node's.
    #[arg(long)]
    config: PathBuf,

    /// Chain the bus tag and eth_chainId responses are scoped to.
    #[arg(long)]
    chain_id: u64,

    /// Serve eth_sendRawTransaction/eth_chainId here for wallets to submit
    /// onto the bus, e.g. 127.0.0.1:8645. Requires --serve and/or --forward-to.
    #[arg(long)]
    serve: Option<String>,

    /// Forward every valid bus tx to this node's eth_sendRawTransaction RPC,
    /// e.g. http://127.0.0.1:8545. Requires --serve and/or --forward-to.
    #[arg(long)]
    forward_to: Option<String>,

    /// Reject any tx whose effective gas price is under this (wei). Bus spam
    /// floor — see design §8; no peer-reputation fallback exists once a tx
    /// leaves this process, so this is the only gate before the bus.
    #[arg(long, default_value = "1000000000")]
    min_gas_price: u128,

    #[arg(long, default_value = "30000000")]
    max_gas_limit: u64,

    /// Largest EIP-2718 payload accepted, in bytes. Must not exceed
    /// `anymone_txbus::max_tx_size(carrier_message_size)` for whatever subnet
    /// actually carries this deployment's tx bus (default assumes the common
    /// 1024-byte carrier) or every accepted tx will be rejected downstream by
    /// the pipe's own send-time size check.
    #[arg(long, default_value_t = anymone_txbus::max_tx_size(1024))]
    max_tx_size: usize,

    /// Register this chain's tx bus tag with the committee so it's carried
    /// on a subnet — `anymone-node`'s own `--role service` runs a bind+echo
    /// demo loop, wrong for a broadcast bus with no owner and no replies, so
    /// the tag needs its own announcer. Set on exactly one identity per
    /// deployment: the committee's service registry is last-write-wins per
    /// tag, so two different identities both announcing the same tag make
    /// the committee's proposal flap between them (design §5).
    #[arg(long)]
    announce: bool,
}

fn limits(args: &Args) -> StatelessLimits {
    StatelessLimits {
        chain_id: args.chain_id,
        max_encoded_size: args.max_tx_size,
        max_gas_limit: args.max_gas_limit,
        min_gas_price: args.min_gas_price,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if args.serve.is_none() && args.forward_to.is_none() {
        return Err(anyhow!(
            "at least one of --serve or --forward-to is required"
        ));
    }

    let bootstrap = BootstrapConfig::load(&args.config)
        .with_context(|| format!("loading {}", args.config.display()))?;
    let identity = Identity::load_or_generate(&bootstrap.identity_path)
        .with_context(|| format!("identity at {}", bootstrap.identity_path.display()))?;

    let net = Libp2pNetwork::start(&identity, bootstrap.libp2p_config()?)
        .await
        .map_err(|e| anyhow!("libp2p start: {e}"))?;
    let transport: Arc<dyn Transport> = net.clone();
    let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);

    // Announce before Anymone::start (which blocks until the first config is
    // adopted), so the committee can see this registration in time to
    // include the tag in that very first config.
    let _reannounce = if args.announce {
        let xk = ExchangePublicKeyWire::from_key(&identity.exchange_pubkey());
        Some(
            announce_service_registration(
                transport.clone(),
                &identity,
                anymone_txbus::tx_bus_tag(args.chain_id),
                xk,
            )
            .await,
        )
    } else {
        None
    };

    let anymone = Anymone::start(identity, transport, gov)
        .await
        .map_err(|e| anyhow!("anymone start: {e}"))?;

    // One standing pipe for the process lifetime, serving both directions.
    // `subscribe` (rather than `open`) receives the bus as well as sending to
    // it, which is what lets the page show what the bus carried and confirm a
    // submission came back off it; it joins the bus's home subnet just the
    // same, so the process contributes cover every round it is up (design §6).
    // Exactly one subscription per process: the runtime keys pipes by tag, so a
    // second one would silently leave the first deaf.
    let pipe = anymone
        .subscribe(anymone_txbus::tx_bus_tag(args.chain_id))
        .await
        .map_err(|e| anyhow!("subscribing to the tx bus: {e}"))?;
    let feed = Arc::new(TxFeed::new());
    let (staging, staging_rx) = mpsc::unbounded_channel();

    let mut tasks = Vec::new();

    if let Some(listen) = args.serve.clone() {
        let state = Arc::new(AppState {
            pipe: staging,
            limits: limits(&args),
            feed: feed.clone(),
        });
        tracing::info!(listen = %listen, chain_id = args.chain_id, "anymone-eth-bridge serving ingress");
        tasks.push(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            axum::serve(listener, router(state))
                .await
                .context("serving")
        }));
    }

    let sink = args.forward_to.clone().map(|rpc_url| {
        tracing::info!(rpc_url = %rpc_url, chain_id = args.chain_id, "anymone-eth-bridge forwarding egress");
        HttpRpcSink::new(rpc_url)
    });
    let bus_limits = limits(&args);
    tasks.push(tokio::spawn(async move {
        bus_loop(pipe, sink, bus_limits, feed, staging_rx).await;
        Ok::<(), anyhow::Error>(())
    }));

    for task in tasks {
        task.await??;
    }
    Ok(())
}
