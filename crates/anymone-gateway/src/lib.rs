//! `anymone-gateway`: a plain HTTP/REST front door to one anymone service tag.
//!
//! Three endpoints over the anonymous broadcast channel the tag names:
//! `POST /messages` submits bytes onto it, `GET /messages` reads back what the
//! channel carried over a range of rounds, `GET /round` reports the round
//! frontier so a caller can poll from where it left off.
//!
//! Submissions use [`anymone_core::Pipe::send_unlinkable`]: the gateway
//! broadcasts, nobody replies, and reusing one return path across submissions
//! would mark them as coming from the same submitter. Everything the gateway
//! read back is public channel traffic — who sent a message is not knowable
//! here, which is the property the channel exists to provide.
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
use anymone_core::{Anymone, Event, Round, ServiceTag};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

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
        for m in inner.msgs.iter().filter(|m| m.round >= from && m.round <= to) {
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

/// A submission handed from an HTTP handler to [`gateway_loop`], which owns the
/// pipe. `ack` carries the send's real outcome back, so `POST` answers
/// "accepted onto the channel" rather than "queued somewhere".
pub struct Staged {
    pub payload: Vec<u8>,
    pub ack: oneshot::Sender<Result<(), String>>,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub outgoing: mpsc::UnboundedSender<Staged>,
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

/// The one loop that owns the channel pipe: files everything the channel
/// carries into `store`, tracks the round frontier from the runtime's own
/// events, and performs the unlinkable sends the HTTP handler stages.
pub async fn gateway_loop(
    anymone: Anymone,
    mut pipe: anymone_core::Pipe,
    store: Arc<Store>,
    round_ms: Arc<AtomicU64>,
    mut staged: mpsc::UnboundedReceiver<Staged>,
) {
    let mut events = anymone.events();
    let mut staging_open = true;
    round_ms.store(anymone.round_duration().as_millis() as u64, Ordering::Relaxed);
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
            submission = staged.recv(), if staging_open => {
                // `None` = every HTTP sender is gone; stop polling this branch
                // instead of spinning on it, and keep serving retrieval.
                let Some(Staged { payload, ack }) = submission else { staging_open = false; continue };
                let result = pipe.send_unlinkable(payload).await.map_err(|e| e.to_string());
                if let Err(e) = &result {
                    tracing::warn!(error = %e, "gateway: submission never reached the channel");
                }
                let _ = ack.send(result);
            }
        }
    }
}

/// Attach to `tag` and serve the REST API on `port`. Blocks forever; holds
/// `anymone` alive.
pub async fn serve(
    anymone: Anymone,
    tag: ServiceTag,
    port: u16,
    capacity: usize,
    allow_origin: Option<String>,
) -> Result<()> {
    let store = Arc::new(Store::new(capacity));
    let round_ms = Arc::new(AtomicU64::new(0));
    let (outgoing, staged) = mpsc::unbounded_channel::<Staged>();

    // Attach in the background so the API is reachable before the committee has
    // placed the tag on a subnet; submissions until then fail with the pipe's
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
            gateway_loop(anymone, pipe, store, round_ms, staged).await;
        });
    }

    let state = AppState {
        store,
        outgoing,
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
    let (ack, acked) = oneshot::channel();
    if state
        .outgoing
        .send(Staged {
            payload: body.to_vec(),
            ack,
        })
        .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            headers,
            Json(json!({ "ok": false, "error": "gateway backend closed" })),
        );
    }
    match acked.await {
        // Accepted onto the channel, not yet carried by it: the message goes
        // out in a later round (the sender's subnet draw, and under a scheduled
        // protocol its reservation gap, decide which). `after_round` is where a
        // reader should start looking for it.
        Ok(Ok(())) => (
            StatusCode::ACCEPTED,
            headers,
            Json(json!({
                "ok": true,
                "bytes": len,
                "after_round": state.store.frontier(),
            })),
        ),
        Ok(Err(e)) => {
            let code = if e.contains("too large") {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (code, headers, Json(json!({ "ok": false, "error": e })))
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            headers,
            Json(json!({ "ok": false, "error": "gateway backend closed" })),
        ),
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
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state() -> (AppState, mpsc::UnboundedReceiver<Staged>) {
        let (outgoing, rx) = mpsc::unbounded_channel();
        (
            AppState {
                store: Arc::new(Store::new(4)),
                outgoing,
                round_ms: Arc::new(AtomicU64::new(1000)),
                allow_origin: "*".to_string(),
            },
            rx,
        )
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

    /// A submitted body reaches the pipe as the exact bytes posted, and the
    /// response only claims acceptance once the send itself succeeded.
    #[tokio::test]
    async fn submit_stages_exact_bytes_and_waits_for_the_send() {
        let (st, mut rx) = state();
        st.store.observe_round(41);
        let handler = tokio::spawn({
            let st = st.clone();
            async move { call(st, "POST", "/messages", b"\x00hello\xff").await }
        });

        let staged = rx.recv().await.unwrap();
        assert_eq!(staged.payload, b"\x00hello\xff");
        staged.ack.send(Ok(())).unwrap();

        let (status, body) = handler.await.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["bytes"], json!(7));
        assert_eq!(body["after_round"], json!(41));
    }

    /// The one silent-loss path — a send that failed after the handler let go of
    /// the payload — is reported to the submitter, oversize as 413.
    #[tokio::test]
    async fn submit_reports_a_failed_send() {
        let (st, mut rx) = state();
        let handler = tokio::spawn({
            let st = st.clone();
            async move { call(st, "POST", "/messages", b"x").await }
        });
        rx.recv()
            .await
            .unwrap()
            .ack
            .send(Err(
                "payload too large: 9000 bytes exceeds the subnet's 1024-byte message limit"
                    .to_string(),
            ))
            .unwrap();
        let (status, body) = handler.await.unwrap();
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["ok"], json!(false));

        let (status, _) = call(st, "POST", "/messages", b"").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Retrieval over HTTP: hex plus decoded text for UTF-8 payloads, `text`
    /// absent for binary ones, and a frontier that includes rounds this tag was
    /// quiet in.
    #[tokio::test]
    async fn get_messages_and_round_serve_the_stored_view() {
        let (st, _rx) = state();
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
