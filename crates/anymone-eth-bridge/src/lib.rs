//! `anymone-eth-bridge`: the on-ramp and off-ramp between plain Ethereum
//! JSON-RPC and the anonymous tx bus (`anymone-txbus`). Ingress (`router`/
//! `AppState`) serves a stateless `eth_sendRawTransaction` front door that
//! decodes, stateless-validates, and forwards onto the bus. Egress
//! (`forward_loop`) does the reverse: reads bus traffic and forwards each
//! valid tx to any target node's `eth_sendRawTransaction`. Neither direction
//! touches chain state or links against reth — see
//! `reth_anon_mempool_design.md` §3/§6.

use std::sync::Arc;

use anymone_txbus::{StatelessLimits, TxReject};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// What the gateway needs from a pipe: send with no return-path linkage
/// (`Pipe::send_unlinkable`), abstracted so handler tests don't need a real
/// anymone transport.
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

/// What egress needs from a pipe: blocking receive of raw bus payloads,
/// abstracted so `forward_loop` tests don't need a real anymone transport.
#[async_trait::async_trait]
pub trait BusRecv: Send {
    async fn recv(&mut self) -> Option<Vec<u8>>;
}

#[async_trait::async_trait]
impl BusRecv for anymone_core::Pipe {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        anymone_core::Pipe::recv(self).await.map(|incoming| incoming.payload)
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

/// Egress loop: drains a bus subscription and forwards every stateless-valid
/// tx to `sink`. Runs until the pipe closes; never crashes on a single tx's
/// decode/reject/RPC failure.
pub async fn forward_loop<P: BusRecv, S: RawTxSink>(mut pipe: P, sink: S, limits: StatelessLimits) {
    while let Some(payload) = pipe.recv().await {
        let tx = match anymone_txbus::decode_tx(&payload) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::debug!(%e, "dropping undecodable bus payload");
                continue;
            }
        };
        let hash = anymone_txbus::tx_hash(&tx);
        if let Err(reject) = anymone_txbus::check_stateless(payload.len(), &tx, &limits) {
            tracing::debug!(%hash, %reject, "stateless reject, not forwarding");
            continue;
        }
        match sink.send_raw(&payload).await {
            Ok(()) => tracing::debug!(%hash, "forwarded to rpc"),
            Err(e) => tracing::debug!(%hash, %e, "rpc rejected or failed"),
        }
    }
}

pub struct AppState<B: BusSend> {
    pub pipe: B,
    pub limits: StatelessLimits,
}

pub fn router<B: BusSend + 'static>(state: Arc<AppState<B>>) -> Router {
    Router::new().route("/", post(rpc::<B>)).with_state(state)
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
        Err(msg) => return err_response(req.id, -32602, msg),
    };
    let tx = match anymone_txbus::decode_tx(&raw) {
        Ok(tx) => tx,
        Err(e) => return err_response(req.id, -32602, e.to_string()),
    };
    if let Err(reject) = anymone_txbus::check_stateless(raw.len(), &tx, &st.limits) {
        let code = if matches!(reject, TxReject::TooLarge { .. }) {
            -32000
        } else {
            -32602
        };
        return err_response(req.id, code, reject.to_string());
    }
    let hash = anymone_txbus::tx_hash(&tx);
    // Success means "staged into the next round", not "delivered" — the
    // sender's hash-only contract (design §3); anything past this point is a
    // receipt-polling concern, safe post-broadcast since the tx is public.
    if let Err(msg) = st.pipe.send_unlinkable(raw).await {
        return err_response(req.id, -32000, format!("bus send failed: {msg}"));
    }
    ok_response(req.id, json!(format!("{hash:#x}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Signature, U256};
    use anymone_txbus::PooledTx;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Mutex;
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
            limits: StatelessLimits {
                chain_id: 1,
                max_encoded_size: anymone_txbus::max_tx_size(1024),
                max_gas_limit: 30_000_000,
                min_gas_price: 1,
            },
        })
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
    /// is forwarded to the bus with the exact original bytes, and the
    /// returned hash matches what the sender would compute locally.
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
    }

    #[tokio::test]
    async fn surfaces_bus_send_failure() {
        let tx = signed_tx(1, 0, 1_000_000_000, 21_000);
        let raw_hex = format!("0x{}", hex::encode(anymone_txbus::encode_tx(&tx)));
        let pipe = StubPipe {
            sent: Mutex::new(Vec::new()),
            fail: true,
        };
        let resp = call(
            state(pipe),
            json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_hex]}),
        )
        .await;
        assert_eq!(resp["error"]["code"], -32000);
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

    struct StubBusRecv(std::collections::VecDeque<Vec<u8>>);

    #[async_trait::async_trait]
    impl BusRecv for StubBusRecv {
        async fn recv(&mut self) -> Option<Vec<u8>> {
            self.0.pop_front()
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

    #[tokio::test]
    async fn forward_loop_forwards_valid_skips_invalid_and_survives_sink_failure() {
        let raw_a = anymone_txbus::encode_tx(&signed_tx(1, 0, 1_000_000_000, 21_000));
        // Wrong chain id vs. `limits()` (1) — must never reach the sink.
        let raw_invalid = anymone_txbus::encode_tx(&signed_tx(999, 0, 1_000_000_000, 21_000));
        let raw_b = anymone_txbus::encode_tx(&signed_tx(1, 0, 2_000_000_000, 21_000));

        let pipe = StubBusRecv([raw_a.clone(), raw_invalid, raw_b.clone()].into_iter().collect());
        let calls = Arc::new(Mutex::new(Vec::new()));
        // `fail: true` on every call — the loop must still drain all three
        // messages rather than stopping at the first RPC error.
        forward_loop(pipe, RecordingSink(calls.clone(), true), limits()).await;

        assert_eq!(calls.lock().unwrap().as_slice(), &[raw_a, raw_b]);
    }
}
