mod board;
mod forward;
mod service;

use std::{path::PathBuf, collections::BTreeMap, net::SocketAddr, path::Path, sync::Arc, time::Duration,
    time::SystemTime, time::UNIX_EPOCH};
use clap::{Parser, Subcommand};
use anyhow::{ensure, Result};
use anymone_core::{Anymone, BootstrapConfig, GovernanceBootstrap, Identity,
    ServiceTag};
use anymone_eth_service::{FeedDescriptor, crypto::request_public_key, crypto::Reassembler, ReplyPacket,
    RequestEnvelope, ServiceDescriptor, ServiceLimits, SignedServiceDescriptor, VERSION};
use axum::{body::Bytes, extract::DefaultBodyLimit, extract::Path as HttpPath, extract::State, http::HeaderMap,
    http::StatusCode, routing::get, routing::post, Json, Router};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;
use crate::{board::ResponseBoard, forward::RpcForwarder, forward::RpcRoute, service::RpcService,
    forward::ExecutionRpc};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Service { #[arg(long)] config: PathBuf },
    Board { #[arg(long)] config: PathBuf },
}

#[tokio::main(worker_threads = 8)]
async fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::Service { config } => run_service(
            serde_json::from_slice(&std::fs::read(config)?)?).await,
        Command::Board { config } => run_board(
            serde_json::from_slice(&std::fs::read(config)?)?).await,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub endpoint: String,
    pub methods: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub bootstrap: PathBuf,
    #[serde(default)]
    pub network: Option<[u8; 32]>,
    pub chain: u64,
    pub tag: String,
    pub limits: ServiceLimits,
    pub feed: FeedDescriptor,
    pub expires_at: u64,
    pub signing_key: PathBuf,
    pub request_key: PathBuf,
    pub database: PathBuf,
    pub routes: BTreeMap<String, RouteConfig>,
    pub listen: SocketAddr,
    pub board_endpoint: String,
    pub board_token: PathBuf,
    pub feed_mirrors: Vec<String>,
    pub descriptor_url: String,
}

struct ServiceState {
    engine: Arc<RpcService>,
    descriptor: SignedServiceDescriptor,
    request_key: Zeroizing<[u8; 32]>,
    permits: Arc<Semaphore>,
}

pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

pub fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let decoded = if bytes.len() == 32 { Zeroizing::new(bytes.to_vec()) }
        else { Zeroizing::new(hex::decode(std::str::from_utf8(&bytes)?.trim())?) };
    Ok(Zeroizing::new(decoded.as_slice().try_into().map_err(|_| anyhow::anyhow!("key must contain 32 bytes"))?))
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).no_proxy().build()?)
}

fn read_token(path: &Path) -> Result<Zeroizing<String>> {
    let token = Zeroizing::new(std::fs::read_to_string(path)?);
    ensure!(token.trim().len() >= 32, "authentication token too short");
    Ok(Zeroizing::new(token.trim().to_owned()))
}

pub async fn run_service(config: ServiceConfig) -> Result<()> {
    let bootstrap = BootstrapConfig::load(&config.bootstrap)?;
    let identity = Identity::load(&bootstrap.identity_path)?;
    let genesis = anymone_core::discovery::Genesis::new(bootstrap.governance.clone());
    genesis.validate()?;
    ensure!(config.network.is_none_or(|network| network == genesis.hash()), "network must match the genesis hash");
    ensure!(!config.feed_mirrors.is_empty(), "public feed_mirrors required");
    for endpoint in config.feed_mirrors.iter().chain(std::iter::once(&config.descriptor_url)) {
        let url = reqwest::Url::parse(endpoint)?;
        ensure!(matches!(url.scheme(), "http" | "https") && url.username().is_empty()
            && url.password().is_none() && url.fragment().is_none(), "invalid public feed URL");
    }
    let request_key = read_key(&config.request_key)?;
    let signing_key = SigningKey::from_bytes(&*read_key(&config.signing_key)?);
    let descriptor = ServiceDescriptor {
        version: VERSION, network: genesis.hash(), chain: config.chain, tag: config.tag,
        service_identity: identity.pubkey().0, signing_key: signing_key.verifying_key().to_bytes(),
        request_key: request_public_key(&request_key)?, backend_routes: config.routes.keys().cloned().collect(),
        limits: config.limits, feed: config.feed, feed_mirrors: config.feed_mirrors, expires_at: config.expires_at,
    };
    descriptor.validate(now())?;
    let mut routes = BTreeMap::new();
    for (name, route) in config.routes {
        let upstream = ExecutionRpc::new(&route.endpoint, Duration::from_secs(30),
            descriptor.limits.max_response_bytes as usize)?;
        if route.methods.iter().any(|m| m == "eth_chainId") {
            upstream.check_chain(descriptor.chain).await?;
        }
        routes.insert(name, RpcRoute { upstream, methods: route.methods });
    }
    let forwarder = RpcForwarder { chain: descriptor.chain, routes,
        max_log_blocks: descriptor.limits.max_log_blocks };
    let signed = SignedServiceDescriptor { signature: identity.sign(&descriptor.signing_bytes()?),
        descriptor: descriptor.clone() };
    let tag = ServiceTag::from_label(&descriptor.tag);
    let engine = Arc::new(RpcService::new(descriptor, forwarder, signing_key, &config.database, now())?);
    let endpoint = config.board_endpoint;
    let token = read_token(&config.board_token)?;
    let publisher_engine = engine.clone();
    let client = http_client()?;
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticks.tick().await;
            let feed = &publisher_engine.descriptor.feed;
            let Ok(epoch) = feed.epoch(now()) else { continue; };
            let Ok(packets) = publisher_engine.pending_publications(epoch, now()) else { continue; };
            for packet in packets {
                let _ = client.post(format!("{}/responses/{epoch}", endpoint.trim_end_matches('/')))
                    .bearer_auth(token.as_str()).body(packet).send().await;
            }
        }
    });
    let state = Arc::new(ServiceState { engine, descriptor: signed, request_key, permits: Arc::new(Semaphore::new(8)) });
    let governance = GovernanceBootstrap::from_bootstrap_config(&bootstrap);
    let (transport, _spawn) = anymone_core::backend::start_client_transport(&identity, &bootstrap, governance.clone())?;
    let _registration = anymone_core::scheduling::announce_registration(transport.clone(),
        anymone_core::Registration::service_at(&identity, tag, identity.exchange_keys(), Some(config.descriptor_url)));
    let node = Anymone::start(identity, transport, governance).await?;
    let mut pipe = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            match node.bind(tag).await {
                Ok(pipe) => return Ok(pipe),
                Err(anymone_core::OpenError::TagNotInConfig) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(error) => return Err(error),
            }
        }
    }).await.map_err(|_| anyhow::anyhow!("service registration did not enter the network configuration"))??;
    let receiving = state.clone();
    tokio::spawn(async move {
        let mut fragments = Reassembler::new(64, 16 * 1024 * 1024, receiving.engine.descriptor.limits.max_lifetime_seconds);
        while let Some(incoming) = pipe.recv().await {
            let Ok(Some((operation, bytes))) = fragments.receive(&receiving.request_key, &incoming.payload, now()) else { continue; };
            let Ok(request) = RequestEnvelope::from_bytes(&bytes) else { continue; };
            let Ok(permit) = receiving.permits.clone().try_acquire_owned() else { continue; };
            let engine = receiving.engine.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = engine.execute(request, operation, now()).await;
            });
        }
    });
    let _network = (node, _spawn, _registration);
    let app = Router::new().route("/descriptor", get(|State(s): State<Arc<ServiceState>>| async move { Json(s.descriptor.clone()) }))
        .with_state(state);
    axum::serve(tokio::net::TcpListener::bind(config.listen).await?, app).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardWriter { pub token: PathBuf, pub quota_bytes: u32 }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardConfig {
    pub feed: FeedDescriptor,
    pub database: PathBuf,
    pub listen: SocketAddr,
    pub writers: BTreeMap<String, BoardWriter>,
}

struct BoardState {
    board: ResponseBoard,
    writers: Vec<(String, Zeroizing<String>, u32)>,
}

fn authenticated(headers: &HeaderMap, token: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    headers.get("authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|provided| bool::from(Sha256::digest(provided.as_bytes()).ct_eq(&Sha256::digest(token.as_bytes()))))
}

pub async fn run_board(config: BoardConfig) -> Result<()> {
    let mut writers = Vec::new();
    for (name, writer) in config.writers { writers.push((name, read_token(&writer.token)?, writer.quota_bytes)); }
    let state = Arc::new(BoardState { board: ResponseBoard::open(&config.database, config.feed)?, writers });
    let max_epoch_bytes = state.board.descriptor().max_epoch_bytes as usize;
    let app = Router::new()
        .route("/feed", get(|State(s): State<Arc<BoardState>>| async move { Json(s.board.descriptor().clone()) }))
        .route("/epochs/:epoch", get(|State(s): State<Arc<BoardState>>, HttpPath(epoch): HttpPath<u64>, headers: HeaderMap| async move {
            if headers.contains_key("range") { return Err(StatusCode::BAD_REQUEST); }
            let batch = s.board.epoch(epoch, now()).map_err(|_| StatusCode::GONE)?;
            bincode::serialize(&batch).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }))
        .route("/responses/:epoch", post(|State(s): State<Arc<BoardState>>, HttpPath(epoch): HttpPath<u64>, headers: HeaderMap, body: Bytes| async move {
            let writer = s.writers.iter().find(|(_, token, _)| authenticated(&headers, token)).ok_or(StatusCode::UNAUTHORIZED)?;
            let packet: ReplyPacket = bincode::deserialize(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            s.board.enqueue(&writer.0, writer.2, epoch, &packet, now()).map_err(|_| StatusCode::CONFLICT)?;
            Ok::<_, StatusCode>(StatusCode::NO_CONTENT)
        }))
        .layer(DefaultBodyLimit::max(max_epoch_bytes))
        .with_state(state);
    axum::serve(tokio::net::TcpListener::bind(config.listen).await?, app).await?;
    Ok(())
}
