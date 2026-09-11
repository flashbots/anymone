use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{ensure, Result};
use anymone_core::{discovery::{Genesis, NetworkInfo}, transport::Transport, BootstrapConfig};
use axum::{http::StatusCode, routing::get, Json, Router};
use clap::Args;

#[derive(Args, Debug)]
pub struct DiscoveryArgs {
    /// Listen address for GET /network, the public read-only discovery endpoint.
    #[arg(long)]
    rpc_listen: Option<SocketAddr>,
    /// Public discovery URL advertised by a relay.
    #[arg(long, requires = "rpc_listen")]
    pub rpc_url: Option<String>,
}

pub async fn start(args: &DiscoveryArgs, bootstrap: &BootstrapConfig,
                   transport: Arc<dyn Transport>) -> Result<()> {
    ensure!(anymone_core::discovery::valid_endpoint(args.rpc_url.as_deref()), "invalid --rpc-url");
    let Some(listen) = args.rpc_listen else { return Ok(()); };
    let genesis = Genesis::new(bootstrap.governance.clone());
    genesis.validate()?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(genesis = %hex::encode(genesis.hash()), %listen, "serving GET /network");
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let app = Router::new().route("/network", get(move || {
        let (genesis, transport, permits) = (genesis.clone(), transport.clone(), permits.clone());
        async move {
            let _permit = permits.try_acquire().map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
            let bytes = match transport.cached_config() {
                Some(bytes) => bytes,
                None => tokio::time::timeout(Duration::from_secs(5), transport.fetch_config()).await
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?.ok_or(StatusCode::SERVICE_UNAVAILABLE)?,
            };
            let config = anymone_core::AnymoneRoundConfiguration::decode(&bytes).ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            genesis.verify_config(&config).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            Ok::<_, StatusCode>(Json(NetworkInfo { genesis, config }))
        }
    }));
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await { tracing::error!(%error, "discovery API stopped"); }
    });
    Ok(())
}
