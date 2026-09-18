mod broker;
mod response_feed;
mod remote_session;
mod discovery;

use std::{path::PathBuf, sync::Arc, collections::BTreeMap, collections::HashSet, net::SocketAddr};
use anyhow::{Result, ensure};
use crate::{broker::now, broker::Broker, broker::Upload, remote_session::RemoteSession};
use anymone_eth_service::{crypto::ResponseCapability, ReplyPacket, SignedServiceDescriptor};
use axum::{body::Bytes, extract::DefaultBodyLimit, extract::Path, extract::State, http::HeaderMap,
    http::StatusCode, response::IntoResponse, response::Response, routing::get, routing::post, Json, Router};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
use anymone_core::Pubkey;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Args { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    Serve(discovery::ServeArgs),
    Decrypt { #[arg(long)] capability: PathBuf, #[arg(long)] response: PathBuf },
}

struct ApiState {
    broker: Arc<Broker>,
    remote_session: Option<Arc<RemoteSession>>,
    token: Zeroizing<String>,
    host: String,
    permits: tokio::sync::Semaphore,
}

#[tokio::main(worker_threads = 8)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_|
            tracing_subscriber::EnvFilter::new("anymone_rpc_client=info,anymone_remote_session=info")))
        .with_target(false)
        .init();
    match Args::parse().command {
        Command::Decrypt { capability, response } => {
            let secret = Zeroizing::new(std::fs::read(capability)?);
            let cap: ResponseCapability = serde_json::from_slice(&secret)?;
            let bytes = std::fs::read(response)?;
            anyhow::ensure!(bytes.len() <= 2 * 1024 * 1024, "response exceeds limit");
            let packet: ReplyPacket = bincode::deserialize(&bytes)?;
            let plaintext = cap.open(&packet.binding, &packet.sealed, now())?;
            println!("{}", std::str::from_utf8(&plaintext)?);
            Ok(())
        }
        Command::Serve(args) => {
            if let Some(config) = &args.config {
                serve(serde_json::from_slice(&std::fs::read(config)?)?, None).await
            } else {
                let (profile, discovery) = discovery::Discovery::start(args).await?;
                serve(profile, Some(discovery)).await
            }
        }
    }
}

async fn serve(config: ClientProfile, discovery: Option<discovery::Discovery>) -> Result<()> {
    let profile = config.broker;
    profile.validate(now())?;
    let connect_on_start = config.remote_session.as_ref().is_some_and(|session| session.remote.is_some());
    let remote_session = config.remote_session.map(|session| RemoteSession::new(session,
        profile.services.values().cloned().collect())).transpose()?;
    let token = Zeroizing::new(std::fs::read_to_string(&profile.token)?);
    anyhow::ensure!(token.trim().len() >= 32, "broker token must contain at least 32 characters");
    let listen = profile.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "RPC client listening");
    let host = listen.to_string();
    let upload = remote_session.clone().map(|session| session as Arc<dyn Upload>);
    let broker = Broker::new(profile, upload)?;
    broker.start_reader().await?;
    if let Some(discovery) = discovery { discovery.follow(broker.clone(), remote_session.clone()); }
    if connect_on_start {
        if let Some(remote) = &remote_session {
            tracing::info!("connecting to phone");
            remote.connect().await?;
            tracing::info!("phone connected");
        }
    }
    let state = Arc::new(ApiState { broker, remote_session, token: Zeroizing::new(token.trim().to_owned()), host,
        permits: tokio::sync::Semaphore::new(8) });
    let app = Router::new()
        .route("/status", get(|State(s): State<Arc<ApiState>>| async move {
            let mut status = s.broker.status().await;
            status["uploadSession"] = s.remote_session.as_ref().map(|r| r.status())
                .transpose().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.unwrap_or(Value::Null);
            Ok::<_, StatusCode>(Json(status))
        }))
        .route("/session/connect", post(|State(s): State<Arc<ApiState>>| async move {
            s.broker.start_reader().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if let Some(remote) = &s.remote_session {
                remote.connect().await.map_err(|error| {
                    tracing::error!(error = %error, "phone connection failed");
                    StatusCode::SERVICE_UNAVAILABLE
                })?;
                tracing::info!("phone connected");
            }
            Ok::<_, StatusCode>(Json(s.broker.status().await))
        }))
        .route("/session/disconnect", post(|State(s): State<Arc<ApiState>>| async move {
            if let Some(remote) = &s.remote_session {
                remote.disconnect().await.map_err(|error| {
                    tracing::error!(%error, "phone disconnect failed");
                    StatusCode::SERVICE_UNAVAILABLE
                })?;
                tracing::info!("phone disconnected");
            }
            Ok::<_, StatusCode>(StatusCode::NO_CONTENT)
        }))
        .route("/rpc/:service/:route", post(rpc))
        .route("/operations/:id", get(|State(s): State<Arc<ApiState>>, Path(id): Path<String>| async move {
            let operation = operation_id(&id)?;
            let result = s.broker.store.response(&operation).map_err(|_| StatusCode::NOT_FOUND)?;
            let response = result.as_ref().and_then(|b| serde_json::from_slice::<Value>(b).ok());
            Ok::<_, StatusCode>(Json(json!({"operation":id,"response":response,"responseReceived":result.is_some()})))
        }))
        .route("/operations/:id/capability", get(|State(s): State<Arc<ApiState>>, Path(id): Path<String>| async move {
            let cap = s.broker.store.capability(&operation_id(&id)?).map_err(|_| StatusCode::NOT_FOUND)?;
            Ok::<_, StatusCode>(Json(cap))
        }))
        .route("/operations/:id/response", get(|State(s): State<Arc<ApiState>>, Path(id): Path<String>| async move {
            let packet = s.broker.store.packet(&operation_id(&id)?).map_err(|_| StatusCode::NOT_FOUND)?
                .ok_or(StatusCode::NOT_FOUND)?;
            bincode::serialize(&packet).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn rpc(State(state): State<Arc<ApiState>>, Path((service, route)): Path<(String, String)>, body: Bytes) -> Response {
    let Ok(_permit) = state.permits.try_acquire() else { return StatusCode::TOO_MANY_REQUESTS.into_response(); };
    match state.broker.rpc(&service, &route, &body).await {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            tracing::error!(%error, %service, %route, "RPC failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn authenticate(State(state): State<Arc<ApiState>>, request: axum::extract::Request,
                      next: axum::middleware::Next) -> Response {
    if !valid_headers(request.headers(), &state.host, &state.token) { return StatusCode::UNAUTHORIZED.into_response(); }
    next.run(request).await
}

fn valid_headers(headers: &HeaderMap, host: &str, token: &str) -> bool {
    if headers.contains_key("origin") || headers.get("host").and_then(|h| h.to_str().ok()) != Some(host) { return false; }
    headers.get("authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|provided| bool::from(Sha256::digest(provided).ct_eq(&Sha256::digest(token))))
}

fn operation_id(id: &str) -> Result<[u8; 32], StatusCode> {
    hex::decode(id).map_err(|_| StatusCode::BAD_REQUEST)?.try_into().map_err(|_| StatusCode::BAD_REQUEST)
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn browser_origins_rebinding_hosts_and_wrong_credentials_fail() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "127.0.0.1:8546".parse().unwrap());
        headers.insert("authorization", "Bearer secret".parse().unwrap());
        assert!(valid_headers(&headers, "127.0.0.1:8546", "secret"));
        assert!(!valid_headers(&headers, "127.0.0.1:8546", "wrong"));
        headers.insert("origin", "https://example.com".parse().unwrap());
        assert!(!valid_headers(&headers, "127.0.0.1:8546", "secret"));
        headers.remove("origin");
        headers.insert("host", "attacker.example:8546".parse().unwrap());
        assert!(!valid_headers(&headers, "127.0.0.1:8546", "secret"));
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTarget {
    pub service_identity: [u8; 32],
    pub signed: SignedServiceDescriptor,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    pub broker: BrokerProfile,
    pub remote_session: Option<RemoteSessionConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSessionConfig {
    pub bootstrap: PathBuf,
    pub pairing: Option<PathBuf>,
    pub remote: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerProfile {
    pub services: BTreeMap<String, ServiceTarget>,
    pub feed_mirrors: Vec<String>,
    pub listen: SocketAddr,
    pub token: PathBuf,
    pub database: PathBuf,
    pub session_seconds: u64,
}

impl BrokerProfile {
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(self.listen.ip().is_loopback(), "broker must listen on loopback");
        ensure!((1..=86400).contains(&self.session_seconds), "invalid session duration");
        let first = &self.services.values().next().ok_or_else(|| anyhow::anyhow!("missing services"))?.signed.descriptor;
        let mut tags = HashSet::new();
        for (name, target) in &self.services {
            ensure!(!name.is_empty() && name.len() <= 64 && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "invalid service name");
            let descriptor = &target.signed.descriptor;
            descriptor.validate(now)?;
            ensure!(target.service_identity == descriptor.service_identity
                && Pubkey(target.service_identity).verify(&descriptor.signing_bytes()?, &target.signed.signature),
                "service descriptor does not match its pinned identity");
            ensure!(descriptor.network == first.network && descriptor.chain == first.chain && descriptor.feed == first.feed,
                "services must share a network, chain and response feed");
            ensure!(tags.insert(&descriptor.tag), "duplicate service tag");
        }
        ensure!(!self.feed_mirrors.is_empty(), "missing feed mirrors");
        for mirror in &self.feed_mirrors {
            let mirror = reqwest::Url::parse(mirror)?;
            ensure!(matches!(mirror.scheme(), "http" | "https") && mirror.username().is_empty()
                && mirror.password().is_none(), "invalid public mirror endpoint");
        }
        Ok(())
    }
}
