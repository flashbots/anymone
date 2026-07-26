//! `anymone-eth-bridge`: the on-ramp and off-ramp between plain Ethereum
//! JSON-RPC and the anonymous tx bus (`anymone-txbus`). Ingress (`router`/
//! `AppState`) serves a stateless `eth_sendRawTransaction` front door plus the
//! submit-and-watch page; egress forwards bus traffic to any target node's
//! `eth_sendRawTransaction`. Both directions share one bus pipe, driven by
//! [`bus_loop`] — the shape `anymone-chat` uses for its room. Neither
//! direction touches chain state or links against reth — see
//! `reth_anon_mempool_design.md` §3/§6.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::Transaction;
use alloy_primitives::TxHash;
use anymone_txbus::{PooledTx, StatelessLimits, TxReject};
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

/// Most recent bus transactions and submissions kept for the page.
const FEED_CAP: usize = 200;

pub(crate) const TX_HTML: &str = include_str!("../static/tx.html");

/// What the gateway needs to stage a payload for the bus. Implemented by the
/// channel the HTTP handler hands payloads to (the pipe itself lives in
/// [`bus_loop`], which performs the unlinkable send), and by `Pipe` directly.
#[async_trait::async_trait]
pub trait BusSend: Send + Sync {
    async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), String>;
}

#[async_trait::async_trait]
impl BusSend for anymone_core::Pipe {
    async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), String> {
        anymone_core::Pipe::send_unlinkable(self, payload)
            .await
            .map_err(|e| e.to_string())
    }
}

#[async_trait::async_trait]
impl BusSend for mpsc::UnboundedSender<Vec<u8>> {
    async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), String> {
        self.send(payload)
            .map_err(|_| "bus loop closed".to_string())
    }
}

/// The one bus pipe, as [`bus_loop`] uses it: blocking receive plus send.
/// Abstracted so the loop's tests need no anymone transport.
#[async_trait::async_trait]
pub trait BusPipe: BusSend {
    async fn recv(&mut self) -> Option<Vec<u8>>;
}

#[async_trait::async_trait]
impl BusPipe for anymone_core::Pipe {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        anymone_core::Pipe::recv(self)
            .await
            .map(|incoming| incoming.payload)
    }
}

/// Where a forwarded tx goes: any Ethereum node's `eth_sendRawTransaction`.
#[async_trait::async_trait]
pub trait RawTxSink: Send + Sync {
    async fn send_raw(&self, raw: &[u8]) -> Result<(), String>;
}

/// Forwards to a target node's JSON-RPC over plain HTTP — reth, geth, anvil,
/// or anything else that speaks `eth_sendRawTransaction`.
pub struct HttpRpcSink {
    client: reqwest::Client,
    rpc_url: String,
}

impl HttpRpcSink {
    pub fn new(rpc_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            rpc_url,
        }
    }
}

#[async_trait::async_trait]
impl RawTxSink for HttpRpcSink {
    async fn send_raw(&self, raw: &[u8]) -> Result<(), String> {
        let raw_hex = format!("0x{}", hex::encode(raw));
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let v: Value = resp.json().await.map_err(|e| e.to_string())?;
        // Includes harmless outcomes like "already known" on a re-delivered
        // bus message — the target node is the authority on acceptance.
        match v.get("error") {
            Some(err) => Err(err.to_string()),
            None => Ok(()),
        }
    }
}

/// One transaction observed on the bus. Every field is public information
/// carried in the transaction itself — including `signer`, recovered from the
/// signature. Which anymone client submitted it is not knowable here, which is
/// the property the bus exists to provide.
#[derive(Debug, Clone, Serialize)]
struct BusTx {
    seq: u64,
    t_ms: u64,
    hash: String,
    signer: Option<String>,
    to: Option<String>,
    value: String,
    nonce: u64,
    max_fee_per_gas: String,
    size: usize,
    /// Submitted through this gateway's own RPC.
    mine: bool,
}

/// One submission attempt through this gateway's `eth_sendRawTransaction`.
#[derive(Debug, Clone, Serialize)]
struct Submission {
    seq: u64,
    t_ms: u64,
    hash: Option<String>,
    error: Option<String>,
}

/// What the page reads: everything this gateway saw on the bus, and every
/// submission made through it. Both are bounded in-memory rings — restarting
/// the bridge starts them empty rather than serving anything stale.
pub struct TxFeed {
    inner: Mutex<FeedInner>,
}

struct FeedInner {
    seq: u64,
    bus: VecDeque<BusTx>,
    submitted: VecDeque<Submission>,
    mine: HashSet<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl TxFeed {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FeedInner {
                seq: 0,
                bus: VecDeque::new(),
                submitted: VecDeque::new(),
                mine: HashSet::new(),
            }),
        }
    }

    fn record_submission(&self, hash: Option<TxHash>, error: Option<String>) {
        let hash = hash.map(|h| format!("{h:#x}"));
        let mut f = self.inner.lock().unwrap();
        let seq = f.seq;
        f.seq += 1;
        if let Some(h) = &hash {
            f.mine.insert(h.clone());
        }
        f.submitted.push_back(Submission {
            seq,
            t_ms: now_ms(),
            hash,
            error,
        });
        while f.submitted.len() > FEED_CAP {
            if let Some(dropped) = f.submitted.pop_front() {
                if let Some(h) = dropped.hash {
                    f.mine.remove(&h);
                }
            }
        }
    }

    fn record_bus_tx(&self, tx: &PooledTx, size: usize) {
        // Decode and ecrecover before taking the lock, never under it.
        let hash = format!("{:#x}", anymone_txbus::tx_hash(tx));
        let signer = tx.recover_signer().ok().map(|a| format!("{a:#x}"));
        let to = tx.to().map(|a| format!("{a:#x}"));
        let (value, nonce, max_fee_per_gas) = (
            tx.value().to_string(),
            tx.nonce(),
            tx.max_fee_per_gas().to_string(),
        );

        let mut f = self.inner.lock().unwrap();
        let seq = f.seq;
        f.seq += 1;
        let mine = f.mine.contains(&hash);
        f.bus.push_back(BusTx {
            seq,
            t_ms: now_ms(),
            hash,
            signer,
            to,
            value,
            nonce,
            max_fee_per_gas,
            size,
            mine,
        });
        while f.bus.len() > FEED_CAP {
            f.bus.pop_front();
        }
    }

    fn to_json(&self, limits: &StatelessLimits) -> Value {
        let f = self.inner.lock().unwrap();
        json!({
            "chain_id": limits.chain_id,
            "limits": {
                "max_tx_size": limits.max_encoded_size,
                "min_gas_price": limits.min_gas_price.to_string(),
            },
            "submitted": f.submitted.iter().rev().collect::<Vec<_>>(),
            "bus": f.bus.iter().rev().collect::<Vec<_>>(),
        })
    }
}

impl Default for TxFeed {
    fn default() -> Self {
        Self::new()
    }
}

/// The one loop that owns the bus pipe: records every transaction the bus
/// carries, forwards each valid one to `sink` when egress is enabled, and
/// performs the unlinkable sends the RPC handler stages on `outgoing`.
///
/// One pipe, not two: `Anymone::subscribe` registers under the service tag in
/// a one-sender-per-key map, so a second subscription to the same tag in one
/// process would silently leave the first pipe deaf.
pub async fn bus_loop<P: BusPipe, S: RawTxSink>(
    mut pipe: P,
    sink: Option<S>,
    limits: StatelessLimits,
    feed: Arc<TxFeed>,
    mut outgoing: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let mut staging_open = true;
    loop {
        tokio::select! {
            inbound = pipe.recv() => {
                let Some(payload) = inbound else { break };
                let tx = match anymone_txbus::decode_tx(&payload) {
                    Ok(tx) => tx,
                    Err(e) => {
                        tracing::debug!(%e, "dropping undecodable bus payload");
                        continue;
                    }
                };
                feed.record_bus_tx(&tx, payload.len());
                let hash = anymone_txbus::tx_hash(&tx);
                if let Err(reject) = anymone_txbus::check_stateless(payload.len(), &tx, &limits) {
                    tracing::debug!(%hash, %reject, "stateless reject, not forwarding");
                    continue;
                }
                if let Some(sink) = &sink {
                    match sink.send_raw(&payload).await {
                        Ok(()) => tracing::debug!(%hash, "forwarded to rpc"),
                        Err(e) => tracing::debug!(%hash, %e, "rpc rejected or failed"),
                    }
                }
            }
            staged = outgoing.recv(), if staging_open => {
                // `None` means every sender is gone (no ingress in this
                // process); stop polling this branch instead of spinning on it.
                let Some(payload) = staged else { staging_open = false; continue };
                if let Err(e) = pipe.send_unlinkable(payload).await {
                    tracing::warn!(%e, "staging a submitted tx onto the bus failed");
                }
            }
        }
    }
}

pub struct AppState<B: BusSend> {
    pub pipe: B,
    pub limits: StatelessLimits,
    pub feed: Arc<TxFeed>,
}

pub fn router<B: BusSend + 'static>(state: Arc<AppState<B>>) -> Router {
    Router::new()
        .route("/", get(page).post(rpc::<B>))
        .route("/tx/feed", get(tx_feed::<B>))
        .with_state(state)
}

async fn page() -> Html<&'static str> {
    Html(TX_HTML)
}

async fn tx_feed<B: BusSend>(State(st): State<Arc<AppState<B>>>) -> impl IntoResponse {
    // CORS: the observer dashboard reads this from another port.
    (
        [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
        Json(st.feed.to_json(&st.limits)),
    )
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

fn ok_response(id: Value, result: Value) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn err_response(id: Value, code: i32, message: impl Into<String>) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() },
    }))
}

async fn rpc<B: BusSend>(
    State(st): State<Arc<AppState<B>>>,
    Json(req): Json<RpcRequest>,
) -> Json<Value> {
    match req.method.as_str() {
        "eth_chainId" => ok_response(req.id, json!(format!("0x{:x}", st.limits.chain_id))),
        "eth_sendRawTransaction" => send_raw(&st, req).await,
        other => err_response(
            req.id,
            -32601,
            format!("the anymone gateway only serves eth_sendRawTransaction and eth_chainId, not {other}"),
        ),
    }
}

fn parse_raw_param(params: &[Value]) -> Result<Vec<u8>, String> {
    let s = params
        .first()
        .and_then(Value::as_str)
        .ok_or("expected params[0] to be a 0x-prefixed hex string")?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

async fn send_raw<B: BusSend>(st: &AppState<B>, req: RpcRequest) -> Json<Value> {
    let raw = match parse_raw_param(&req.params) {
        Ok(bytes) => bytes,
        Err(msg) => {
            st.feed.record_submission(None, Some(msg.clone()));
            return err_response(req.id, -32602, msg);
        }
    };
    let tx = match anymone_txbus::decode_tx(&raw) {
        Ok(tx) => tx,
        Err(e) => {
            st.feed.record_submission(None, Some(e.to_string()));
            return err_response(req.id, -32602, e.to_string());
        }
    };
    let hash = anymone_txbus::tx_hash(&tx);
    if let Err(reject) = anymone_txbus::check_stateless(raw.len(), &tx, &st.limits) {
        let code = if matches!(reject, TxReject::TooLarge { .. }) {
            -32000
        } else {
            -32602
        };
        st.feed
            .record_submission(Some(hash), Some(reject.to_string()));
        return err_response(req.id, code, reject.to_string());
    }
    // Success means "staged into the next round", not "delivered" — the
    // sender's hash-only contract (design §3); anything past this point is a
    // receipt-polling concern, safe post-broadcast since the tx is public.
    // The page's own confirmation is the tx coming back off the bus.
    if let Err(msg) = st.pipe.send_unlinkable(raw).await {
        let msg = format!("bus send failed: {msg}");
        st.feed.record_submission(Some(hash), Some(msg.clone()));
        return err_response(req.id, -32000, msg);
    }
    st.feed.record_submission(Some(hash), None);
    ok_response(req.id, json!(format!("{hash:#x}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Signature, U256};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct StubPipe {
        sent: Mutex<Vec<Vec<u8>>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl BusSend for StubPipe {
        async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), String> {
            if self.fail {
                return Err("stub failure".to_string());
            }
            self.sent.lock().unwrap().push(payload);
            Ok(())
        }
    }

    fn signed_tx(chain_id: u64, nonce: u64, max_fee_per_gas: u128, gas_limit: u64) -> PooledTx {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas: max_fee_per_gas,
            to: Address::ZERO.into(),
            value: U256::ZERO,
            access_list: AccessList::default(),
            input: Default::default(),
        };
        let signed = tx.into_signed(Signature::test_signature());
        PooledTx::Eip1559(signed)
    }

    fn state(pipe: StubPipe) -> Arc<AppState<StubPipe>> {
        Arc::new(AppState {
            pipe,
            limits: limits(),
            feed: Arc::new(TxFeed::new()),
        })
    }

    /// The page's view of `/tx/feed`, as JSON.
    fn feed_json(st: &AppState<StubPipe>) -> Value {
        st.feed.to_json(&st.limits)
    }

    async fn call(state: Arc<AppState<StubPipe>>, body: Value) -> Value {
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Happy path: a well-formed raw tx is decoded, passes stateless checks,
    /// is forwarded to the bus with the exact original bytes, the returned
    /// hash matches what the sender would compute locally, and the page sees
    /// the submission recorded without an error.
    #[tokio::test]
    async fn send_raw_transaction_stages_and_returns_hash() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let expected_hash = anymone_txbus::tx_hash(&tx);
        let raw = anymone_txbus::encode_tx(&tx);
        let raw_hex = format!("0x{}", hex::encode(&raw));

        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let st = state(pipe);
        let resp = call(
            st.clone(),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]}),
        )
        .await;

        assert_eq!(resp["result"], format!("{expected_hash:#x}"));
        assert_eq!(st.pipe.sent.lock().unwrap().as_slice(), &[raw]);

        let feed = feed_json(&st);
        assert_eq!(feed["submitted"][0]["hash"], format!("{expected_hash:#x}"));
        assert!(feed["submitted"][0]["error"].is_null());
        // Nothing has come back off the bus yet: staged, not carried.
        assert_eq!(feed["bus"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn eth_chain_id_reports_configured_chain() {
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let resp = call(
            state(pipe),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}),
        )
        .await;
        assert_eq!(resp["result"], "0x1");
    }

    #[tokio::test]
    async fn rejects_malformed_hex() {
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let resp = call(
            state(pipe),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xzz"]}),
        )
        .await;
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn rejects_stateless_invalid_without_touching_the_bus() {
        // Wrong chain id vs. the gateway's configured chain (1).
        let tx = signed_tx(999, 0, 1_000_000_000, 21_000);
        let raw_hex = format!("0x{}", hex::encode(anymone_txbus::encode_tx(&tx)));
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let st = state(pipe);
        let resp = call(
            st.clone(),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]}),
        )
        .await;
        assert_eq!(resp["error"]["code"], -32602);
        assert!(st.pipe.sent.lock().unwrap().is_empty());
        // The refusal is visible on the page, with the reason as written.
        let feed = feed_json(&st);
        assert_eq!(
            feed["submitted"][0]["error"],
            TxReject::WrongChain.to_string()
        );
    }

    #[tokio::test]
    async fn surfaces_bus_send_failure() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let raw_hex = format!("0x{}", hex::encode(anymone_txbus::encode_tx(&tx)));
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: true,
        };
        let st = state(pipe);
        let resp = call(
            st.clone(),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]}),
        )
        .await;
        assert_eq!(resp["error"]["code"], -32000);
        // A tx that passed every check and still never reached the bus is the
        // one silent-loss path here; it must show up on the page.
        let feed = feed_json(&st);
        assert!(feed["submitted"][0]["error"]
            .as_str()
            .unwrap()
            .contains("bus send failed"));
    }

    #[tokio::test]
    async fn unknown_method_is_rejected() {
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let resp = call(
            state(pipe),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[]}),
        )
        .await;
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn serves_the_page_at_root() {
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: false,
        };
        let response = router(state(pipe))
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("eth_sendRawTransaction"));
    }

    struct StubBusPipe {
        inbound: std::collections::VecDeque<Vec<u8>>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Stay open once drained instead of closing the loop, so a test can
        /// exercise the staging branch without racing the loop's exit.
        pend_when_empty: bool,
    }

    #[async_trait::async_trait]
    impl BusSend for StubBusPipe {
        async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), String> {
            self.sent.lock().unwrap().push(payload);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl BusPipe for StubBusPipe {
        async fn recv(&mut self) -> Option<Vec<u8>> {
            match self.inbound.pop_front() {
                Some(payload) => Some(payload),
                None if self.pend_when_empty => std::future::pending().await,
                None => None,
            }
        }
    }

    struct RecordingSink(Arc<Mutex<Vec<Vec<u8>>>>, bool);

    #[async_trait::async_trait]
    impl RawTxSink for RecordingSink {
        async fn send_raw(&self, raw: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().push(raw.to_vec());
            if self.1 {
                Err("stub rpc failure".to_string())
            } else {
                Ok(())
            }
        }
    }

    fn limits() -> StatelessLimits {
        StatelessLimits {
            chain_id: 1,
            max_encoded_size: anymone_txbus::max_tx_size(1024),
            max_gas_limit: 30_000_000,
            min_gas_price: 1,
        }
    }

    /// The bus loop forwards every valid tx, skips invalid ones without
    /// forwarding, survives an RPC failure on each call, and records what the
    /// bus carried for the page — including the txs it refused to forward,
    /// since the bus did carry those.
    #[tokio::test]
    async fn bus_loop_forwards_valid_skips_invalid_and_survives_sink_failure() {
        let raw_a = anymone_txbus::encode_tx(&signed_tx(1, 0, 1_000_000_000, 21_000));
        // Wrong chain id vs. `limits()` (1) — must never reach the sink.
        let raw_invalid = anymone_txbus::encode_tx(&signed_tx(999, 0, 1_000_000_000, 21_000));
        let raw_b = anymone_txbus::encode_tx(&signed_tx(1, 0, 2_000_000_000, 21_000));

        let pipe = StubBusPipe {
            inbound: [raw_a.clone(), raw_invalid.clone(), raw_b.clone()]
                .into_iter()
                .collect(),
            sent: Arc::new(Mutex::new(Vec::new())),
            pend_when_empty: false,
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let feed = Arc::new(TxFeed::new());
        let (_staging, staging_rx) = mpsc::unbounded_channel();
        // `fail: true` on every call — the loop must still drain all three
        // messages rather than stopping at the first RPC error.
        bus_loop(
            pipe,
            Some(RecordingSink(calls.clone(), true)),
            limits(),
            feed.clone(),
            staging_rx,
        )
        .await;

        assert_eq!(calls.lock().unwrap().as_slice(), &[raw_a, raw_b.clone()]);

        let json = feed.to_json(&limits());
        let bus = json["bus"].as_array().unwrap();
        assert_eq!(bus.len(), 3, "every decodable bus tx is shown");
        // Newest first, and none of these were submitted through this gateway.
        assert!(bus.iter().all(|e| e["mine"] == json!(false)));
        assert_eq!(bus[0]["size"], json!(raw_b.len()));
    }

    /// A tx staged by the RPC handler is sent on the pipe with the exact bytes,
    /// and when it comes back off the bus the page can tell it was ours.
    #[tokio::test]
    async fn staged_tx_is_sent_and_marked_mine_when_it_returns() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let raw = anymone_txbus::encode_tx(&tx);
        let hash = anymone_txbus::tx_hash(&tx);

        let feed = Arc::new(TxFeed::new());
        feed.record_submission(Some(hash), None);

        let sent = Arc::new(Mutex::new(Vec::new()));
        let pipe = StubBusPipe {
            inbound: [raw.clone()].into_iter().collect(),
            sent: sent.clone(),
            // Both branches must run regardless of which `select!` polls first,
            // so the pipe stays open and the timeout ends the loop instead.
            pend_when_empty: true,
        };
        let (staging, staging_rx) = mpsc::unbounded_channel();
        staging.send(raw.clone()).unwrap();
        drop(staging);

        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            bus_loop(
                pipe,
                None::<RecordingSink>,
                limits(),
                feed.clone(),
                staging_rx,
            ),
        )
        .await;

        assert_eq!(sent.lock().unwrap().as_slice(), &[raw]);
        let json = feed.to_json(&limits());
        assert_eq!(json["bus"][0]["hash"], format!("{hash:#x}"));
        assert_eq!(json["bus"][0]["mine"], json!(true));
    }
}
