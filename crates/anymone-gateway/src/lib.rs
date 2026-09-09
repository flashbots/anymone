//! `anymone-gateway`: a plain HTTP/REST front door to one anymone service tag.
//!
//! Three endpoints over the anonymous broadcast channel the tag names:
//! `POST /messages` submits bytes onto it, `GET /messages` reads back what the
//! channel carried over a range of rounds, `GET /round` reports the round
//! frontier so a caller can poll from where it left off.
//!
//! Submissions go through an [`anymone_core::ClientPool`]: the gateway
//! broadcasts unlinkably (nobody replies, and reusing one return path across
//! submissions would mark them as coming from the same submitter), and since one
//! client carries at most one message per round, the pool queues messages. With `--max-clients N` above one, it can spawn
//! virtual clients while callers wait. Everything the gateway read back is public
//! channel traffic — who sent a message is not knowable here, which is the
//! property the channel exists to provide.
//!
//! Retrieval is this process's own view: a bounded in-memory ring filled from
//! the round the gateway joined onward. It is not a chain — restarting starts
//! it empty rather than serving anything stale, and rounds older than the ring
//! are gone.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use anymone_core::{
    Anymone, ClientPool, Event, PoolError, Round, SendError, ServiceTag, SpawnClient,
};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One message the channel carried, as served over REST. `data` is hex; `text`
/// is present only when the payload is valid UTF-8, so a caller that put text
/// on the channel can read it without decoding.
#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub seq: u64,
    pub round: Round,
    pub len: usize,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// The gateway's bounded view of the channel: the last `capacity` messages it
/// saw, plus the highest round it has observed decoding anywhere on the mesh.
pub struct Store {
    capacity: usize,
    inner: Mutex<StoreInner>,
}

struct StoreInner {
    seq: u64,
    msgs: VecDeque<Message>,
    frontier: Option<Round>,
}

impl Store {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(StoreInner {
                seq: 0,
                msgs: VecDeque::new(),
                frontier: None,
            }),
        }
    }

    pub fn push(&self, round: Round, payload: Vec<u8>) {
        let msg = Message {
            seq: 0,
            round,
            len: payload.len(),
            data: hex::encode(&payload),
            text: String::from_utf8(payload).ok(),
        };
        let mut inner = self.inner.lock().unwrap();
        let seq = inner.seq;
        inner.seq += 1;
        inner.msgs.push_back(Message { seq, ..msg });
        while inner.msgs.len() > self.capacity {
            inner.msgs.pop_front();
        }
        inner.frontier = Some(inner.frontier.map_or(round, |f| f.max(round)));
    }

    /// A round decoded somewhere on the mesh, carrying nothing for this tag.
    /// The frontier tracks it too: it is the channel's clock as observed on the
    /// wire, so a poller's cursor advances through rounds this tag was quiet in.
    pub fn observe_round(&self, round: Round) {
        let mut inner = self.inner.lock().unwrap();
        inner.frontier = Some(inner.frontier.map_or(round, |f| f.max(round)));
    }

    /// Highest round observed, or `None` before any traffic.
    pub fn frontier(&self) -> Option<Round> {
        self.inner.lock().unwrap().frontier
    }

    /// Oldest round still in the ring, or `None` while it is empty.
    pub fn earliest(&self) -> Option<Round> {
        self.inner.lock().unwrap().msgs.front().map(|m| m.round)
    }

    /// Messages in rounds `from..=to`, oldest first, at most `limit` of them.
    /// `0` is open-ended at either end: `from = 0` is the oldest round in the
    /// ring, `to = 0` the frontier. Returns the resolved bounds alongside the
    /// messages, plus whether `limit` cut the range short.
    pub fn range(&self, from: Round, to: Round, limit: usize) -> Range {
        let inner = self.inner.lock().unwrap();
        let earliest = inner.msgs.front().map(|m| m.round).unwrap_or(0);
        let latest = inner.frontier.unwrap_or(0);
        let from = if from == 0 { earliest } else { from };
        let to = if to == 0 { latest } else { to };
        let mut msgs: Vec<Message> = Vec::new();
        let mut truncated = false;
        for m in inner
            .msgs
            .iter()
            .filter(|m| m.round >= from && m.round <= to)
        {
            if msgs.len() == limit {
                truncated = true;
                break;
            }
            msgs.push(m.clone());
        }
        Range {
            from,
            to,
            truncated,
            msgs,
        }
    }
}

pub struct Range {
    pub from: Round,
    pub to: Round,
    pub truncated: bool,
    pub msgs: Vec<Message>,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    /// The clients that carry submissions, grown with virtual clients while
    /// callers are queued up.
    pub pool: ClientPool,
    /// Round duration of the adopted config, refreshed by [`gateway_loop`];
    /// `0` until the gateway has attached to the channel.
    pub round_ms: Arc<AtomicU64>,
    /// `Access-Control-Allow-Origin`; `*` if unset.
    pub allow_origin: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/messages", post(submit).get(messages))
        .route("/round", get(round))
        .with_state(state)
}

/// The loop that owns the channel's receive pipe: files everything the channel
/// carries into `store` and tracks the round frontier from the runtime's own
/// events. Sending is the [`ClientPool`]'s job, straight from the handler.
pub async fn gateway_loop(
    anymone: Anymone,
    mut pipe: anymone_core::Pipe,
    store: Arc<Store>,
    round_ms: Arc<AtomicU64>,
) {
    let mut events = anymone.events();
    round_ms.store(
        anymone.round_duration().as_millis() as u64,
        Ordering::Relaxed,
    );
    loop {
        tokio::select! {
            inbound = pipe.recv() => {
                let Some(inc) = inbound else { break };
                store.push(inc.round, inc.payload);
            }
            event = events.recv() => {
                match event {
                    // Every node decodes every subnet payload, so this ticks
                    // with mesh traffic whether or not it was for this tag.
                    Ok(Event::RoundDecoded { round, .. }) => store.observe_round(round),
                    Ok(Event::ConfigUpdated { .. }) => {
                        round_ms.store(anymone.round_duration().as_millis() as u64, Ordering::Relaxed);
                    }
                    Ok(_) => {}
                    // Lagging drops the oldest events; the frontier catches up
                    // on the next one rather than the loop giving up.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

/// Attach to `tag` and serve the REST API on `port`. Submissions ride the
/// gateway's own client plus up to `max_clients - 1` virtual clients minted by
/// `spawn` when callers queue up. Blocks forever; holds `anymone` alive.
pub async fn serve(
    anymone: Anymone,
    tag: ServiceTag,
    spawn: SpawnClient,
    max_clients: usize,
    port: u16,
    capacity: usize,
    allow_origin: Option<String>,
) -> Result<()> {
    let store = Arc::new(Store::new(capacity));
    let round_ms = Arc::new(AtomicU64::new(0));
    let pool = ClientPool::new(anymone.clone(), tag, spawn, max_clients);

    // Attach in the background so the API is reachable before the committee has
    // placed the tag on a subnet; submissions until then fail with the pool's
    // own error rather than the port refusing connections.
    {
        let store = store.clone();
        let round_ms = round_ms.clone();
        tokio::spawn(async move {
            let mut waited = 0u32;
            let pipe = loop {
                match anymone.subscribe(tag).await {
                    Ok(pipe) => break pipe,
                    Err(e) => {
                        if waited % 20 == 0 {
                            tracing::info!(waited_ms = waited * 500, error = %e, "gateway: waiting for the channel to be placed");
                        }
                        waited += 1;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            };
            tracing::info!("gateway: attached to the channel");
            gateway_loop(anymone, pipe, store, round_ms).await;
        });
    }

    let state = AppState {
        store,
        pool,
        round_ms,
        allow_origin: allow_origin.unwrap_or_else(|| "*".to_string()),
    };
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind gateway on {addr}"))?;
    tracing::info!(%addr, "gateway live");
    axum::serve(listener, router(state))
        .await
        .context("gateway server")?;
    Ok(())
}

fn cors(state: &AppState) -> [(header::HeaderName, String); 1] {
    [(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        state.allow_origin.clone(),
    )]
}

/// Submit the request body onto the channel as one message. The body is the
/// payload, bytes as sent — no envelope, since what the payload means is the
/// caller's protocol, not the gateway's.
async fn submit(State(state): State<AppState>, body: axum::body::Bytes) -> impl IntoResponse {
    let headers = cors(&state);
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            headers,
            Json(json!({ "ok": false, "error": "empty body" })),
        );
    }
    let len = body.len();
    match state.pool.send(body.to_vec()) {
        // Accepted onto the channel, not yet carried by it: the message goes out
        // in a later round, on whichever client is free first (its subnet draw,
        // and under a scheduled protocol its reservation gap, decide when).
        // `after_round` is where a reader should start looking for it.
        Ok(()) => (
            StatusCode::ACCEPTED,
            headers,
            Json(json!({
                "ok": true,
                "bytes": len,
                "after_round": state.store.frontier(),
                "clients": state.pool.clients(),
            })),
        ),
        Err(e) => {
            let code = match &e {
                PoolError::Send(SendError::PayloadTooLarge { .. }) => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            tracing::warn!(error = %e, "gateway: submission never reached the channel");
            (
                code,
                headers,
                Json(json!({ "ok": false, "error": e.to_string() })),
            )
        }
    }
}

#[derive(Debug, Deserialize)]
struct RangeQuery {
    #[serde(default)]
    from: Round,
    #[serde(default)]
    to: Round,
    limit: Option<usize>,
}

/// Everything the channel carried in `from..=to`, oldest first. Both bounds are
/// inclusive and default to `0`, which means "open": `from=0` starts at the
/// oldest round still held, `to=0` ends at the round frontier.
async fn messages(State(state): State<AppState>, Query(q): Query<RangeQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(usize::MAX);
    let range = state.store.range(q.from, q.to, limit);
    (
        cors(&state),
        Json(json!({
            "from": range.from,
            "to": range.to,
            "count": range.msgs.len(),
            "truncated": range.truncated,
            "last_round": state.store.frontier(),
            "messages": range.msgs,
        })),
    )
}

/// The round frontier: what to poll from, and how far back retrieval reaches.
/// `last_round` is the highest round this gateway observed decoding on the
/// wire; `null` before it has seen any.
async fn round(State(state): State<AppState>) -> impl IntoResponse {
    let round_ms = state.round_ms.load(Ordering::Relaxed);
    (
        cors(&state),
        Json(json!({
            "last_round": state.store.frontier(),
            "earliest_round": state.store.earliest(),
            "round_ms": if round_ms == 0 { Value::Null } else { json!(round_ms) },
            "capacity": state.store.capacity,
            "clients": state.pool.clients(),
            "queued": state.pool.queued(),
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anymone_core::{
        AnymoneRoundConfiguration, Identity, InMemoryNetwork, NoopConfig, ProtocolConfig,
        ServiceEntry,
    };
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_tag() -> ServiceTag {
        ServiceTag::from_label("anymone.gateway.unit")
    }

    /// State over a real (in-memory, single-node) mesh, so submissions exercise
    /// the pool and the carrier's true size limit rather than a stand-in.
    async fn state() -> AppState {
        let committee = Identity::generate();
        let relay = Identity::generate();
        let gateway = Identity::generate();
        let cfg = AnymoneRoundConfiguration::singleton_subnet(
            0,
            ProtocolConfig::Noop(NoopConfig {
                round_duration_ms: 200,
                message_size: 1024,
                client_set_min: 0,
                client_set_max: 8,
            }),
            vec![relay.pubkey()],
            vec![(relay.pubkey(), relay.exchange_keys())],
            vec![ServiceEntry {
                tag: test_tag(),
                pubkey: Identity::generate().pubkey(),
            }],
        )
        .sign_with(&[&committee]);

        let net = InMemoryNetwork::new();
        let anymone = Anymone::start_with_config(
            gateway.clone(),
            Arc::new(net.handle(gateway.pubkey())),
            cfg.clone(),
        )
        .await;
        let spawn: SpawnClient = {
            let net = net.clone();
            let cfg = cfg.clone();
            Arc::new(move || {
                let net = net.clone();
                let cfg = cfg.clone();
                Box::pin(async move {
                    let id = Identity::generate();
                    let transport = Arc::new(net.handle(id.pubkey()));
                    Some(Anymone::start_with_config(id, transport, cfg).await)
                })
            })
        };
        let pool = ClientPool::new(anymone, test_tag(), spawn, 4);
        wait_for_clients(&pool, 1).await;
        AppState {
            store: Arc::new(Store::new(4)),
            pool,
            round_ms: Arc::new(AtomicU64::new(1000)),
            allow_origin: "*".to_string(),
        }
    }

    async fn wait_for_clients(pool: &ClientPool, want: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while pool.clients() < want {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {want} client(s); pool has {}",
                pool.clients()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn call(state: AppState, method: &str, uri: &str, body: &[u8]) -> (StatusCode, Value) {
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::from(body.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Round bounds: `0` is open at either end, both bounds are inclusive, a
    /// range narrower than the ring excludes the rest, and `limit` cuts the
    /// range short from the oldest end while saying so.
    #[test]
    fn range_bounds_are_inclusive_and_zero_is_open_ended() {
        let store = Store::new(4);
        store.push(7, b"a".to_vec());
        store.push(8, b"b".to_vec());
        store.push(8, b"c".to_vec());
        store.push(10, b"d".to_vec());
        store.observe_round(11);

        let all = store.range(0, 0, usize::MAX);
        assert_eq!((all.from, all.to), (7, 11));
        assert_eq!(all.msgs.len(), 4);
        assert!(!all.truncated);
        assert_eq!(all.msgs[0].seq, 0);

        let mid = store.range(8, 8, usize::MAX);
        assert_eq!(
            mid.msgs.iter().map(|m| m.data.as_str()).collect::<Vec<_>>(),
            vec![hex::encode("b"), hex::encode("c")]
        );

        let capped = store.range(0, 0, 2);
        assert!(capped.truncated);
        assert_eq!(capped.msgs.len(), 2);
        assert_eq!(capped.msgs[1].data, hex::encode("b"));

        // Beyond the frontier: an empty answer, not an error.
        assert!(store.range(12, 0, usize::MAX).msgs.is_empty());

        // The ring drops the oldest round once full, and `from=0` follows it.
        store.push(12, b"e".to_vec());
        assert_eq!(store.earliest(), Some(8));
        assert_eq!(store.range(0, 0, usize::MAX).from, 8);
        assert_eq!(store.frontier(), Some(12));
    }

    /// A submission is accepted and reported with the frontier to start polling
    /// from. Three at once outrun one client — a client carries one message per
    /// round — so the pool grows, and every accepted message leaves the queue
    /// rather than piling up behind the first client.
    #[tokio::test]
    async fn submit_grows_the_pool_and_drains_every_queued_message() {
        let st = state().await;
        st.store.observe_round(41);

        let (status, body) = call(st.clone(), "POST", "/messages", b"\x00hello\xff").await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["bytes"], json!(7));
        assert_eq!(body["after_round"], json!(41));
        assert_eq!(body["clients"], json!(1));

        for body in [b"second".as_slice(), b"third".as_slice()] {
            let (status, _) = call(st.clone(), "POST", "/messages", body).await;
            assert_eq!(status, StatusCode::ACCEPTED);
        }
        wait_for_clients(&st.pool, 2).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while st.pool.queued() > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "queue never drained: {} left on {} client(s)",
                st.pool.queued(),
                st.pool.clients()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Both refusals a submitter can hit: nothing to send, and a payload the
    /// carrier cannot fit — reported against the subnet's real message size,
    /// never truncated to fit.
    #[tokio::test]
    async fn submit_rejects_empty_and_oversize_bodies() {
        let st = state().await;

        let (status, _) = call(st.clone(), "POST", "/messages", b"").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, body) = call(st.clone(), "POST", "/messages", &vec![b'x'; 2048]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["ok"], json!(false));
        assert!(
            body["error"].as_str().unwrap().contains("too large"),
            "saw {body}"
        );
        assert_eq!(st.pool.queued(), 0, "a refused payload is queued nowhere");
    }

    /// Retrieval over HTTP: hex plus decoded text for UTF-8 payloads, `text`
    /// absent for binary ones, and a frontier that includes rounds this tag was
    /// quiet in.
    #[tokio::test]
    async fn get_messages_and_round_serve_the_stored_view() {
        let st = state().await;
        let (status, body) = call(st.clone(), "GET", "/round", b"").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["last_round"], Value::Null);
        assert_eq!(body["round_ms"], json!(1000));

        st.store.push(3, b"hi".to_vec());
        st.store.push(4, vec![0xff, 0xfe]);
        st.store.observe_round(9);

        let (_, body) = call(st.clone(), "GET", "/messages?from=4", b"").await;
        assert_eq!(body["count"], json!(1));
        assert_eq!(body["to"], json!(9));
        assert_eq!(body["messages"][0]["data"], json!("fffe"));
        assert!(body["messages"][0].get("text").is_none());

        let (_, body) = call(st.clone(), "GET", "/messages?to=3", b"").await;
        assert_eq!(body["messages"][0]["text"], json!("hi"));
        assert_eq!(body["messages"][0]["round"], json!(3));

        let (_, body) = call(st, "GET", "/round", b"").await;
        assert_eq!(body["last_round"], json!(9));
        assert_eq!(body["earliest_round"], json!(3));
        assert_eq!(body["capacity"], json!(4));
    }
}
