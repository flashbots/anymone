use std::{collections::BTreeMap, time::Duration};
use anyhow::{ensure, Result, bail};
use anymone_eth_service::{digest, RpcCall, is_read_method, validate_response};
use serde_json::{json, Value};
use crate::{service::Dispatch, service::ServiceStore};

pub struct RpcRoute {
    pub upstream: ExecutionRpc,
    pub methods: Vec<String>,
}

pub struct RpcForwarder {
    pub chain: u64,
    pub routes: BTreeMap<String, RpcRoute>,
    pub max_log_blocks: u64,
}

pub fn is_submission(method: &str) -> bool {
    matches!(method, "eth_sendRawTransaction" | "eth_sendUserOperation")
}

impl RpcForwarder {
    pub async fn call(&self, route: &str, call: &RpcCall, store: &ServiceStore) -> Value {
        let id = call.id.clone().unwrap_or(Value::Null);
        match self.forward(route, call, store).await {
            Ok(mut reply) => { reply["id"] = id; reply }
            Err(_) => rpc_error(id, -32000, "Upstream unavailable"),
        }
    }

    async fn forward(&self, name: &str, call: &RpcCall, store: &ServiceStore) -> Result<Value> {
        let route = self.routes.get(name).ok_or_else(|| anyhow::anyhow!("unknown route"))?;
        if !route.methods.contains(&call.method) {
            return Ok(rpc_error(Value::Null, -32601, "Method not supported by route"));
        }
        if call.method == "eth_getLogs" && !valid_logs(call.params.as_ref(), self.max_log_blocks) {
            return Ok(rpc_error(Value::Null, -32602, "Use a blockHash or a bounded numeric block range"));
        }
        if !is_submission(&call.method) {
            return route.upstream.call(&call.method, call.params.clone()).await;
        }
        let key = digest(&serde_json::to_vec(&(self.chain, name, &call.method, &call.params))?);
        match store.reserve(&key)? {
            Dispatch::Saved(reply) => return Ok(reply),
            Dispatch::Unknown => return Ok(unknown()),
            Dispatch::Fresh => {}
        }
        let reply = match route.upstream.call(&call.method, call.params.clone()).await {
            Ok(reply) => reply,
            Err(_) => return Ok(unknown()),
        };
        if store.finish(&key, &reply).is_err() { return Ok(unknown()); }
        Ok(reply)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.routes.is_empty(), "no upstream routes");
        for route in self.routes.values() {
            ensure!(!route.methods.is_empty(), "empty route method list");
            ensure!(route.methods.iter().all(|m| allowed_method(m)), "unsupported upstream method");
        }
        Ok(())
    }
}

fn unknown() -> Value {
    rpc_error(Value::Null, -32098, "Submission outcome unknown")
}

pub fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

pub(crate) fn valid_logs(params: Option<&Value>, max_blocks: u64) -> bool {
    let Some(params) = params.and_then(Value::as_array).filter(|p| p.len() == 1) else {
        return false;
    };
    let Some(filter) = params[0].as_object() else { return false; };
    if let Some(hash) = filter.get("blockHash") {
        return !filter.contains_key("fromBlock") && !filter.contains_key("toBlock")
            && hash.as_str().is_some_and(|h| h.len() == 66 && h.starts_with("0x") && hex::decode(&h[2..]).is_ok());
    }
    let number = |field: &str| filter.get(field).and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("0x")).and_then(|s| u64::from_str_radix(s, 16).ok());
    match (number("fromBlock"), number("toBlock")) {
        (Some(from), Some(to)) => to >= from && max_blocks > 0 && to - from < max_blocks,
        _ => false,
    }
}

pub(crate) fn allowed_method(method: &str) -> bool {
    is_read_method(method) || matches!(method,
        "eth_sendRawTransaction" | "eth_sendUserOperation" | "eth_supportedEntryPoints"
        | "eth_estimateUserOperationGas" | "eth_getUserOperationByHash" | "eth_getUserOperationReceipt"
        | "pimlico_getUserOperationGasPrice" | "pimlico_getUserOperationStatus"
        | "pm_getPaymasterStubData" | "pm_getPaymasterData" | "pm_sponsorUserOperation")
}

#[cfg(test)]
mod forward_tests {
    use super::*;
    use std::{path::Path, sync::Arc, sync::atomic::AtomicUsize, sync::atomic::Ordering, time::Duration};
    use axum::{routing::post, Json, Router};
    use serde_json::json;

    #[tokio::test]
    async fn forwards_bundler_errors_and_deduplicates_without_interpreting_user_operations() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let upstream_error = json!({"code":-32500,"message":"AA21 didn't pay prefund","data":{"detail":"provider data"}});
        let expected = upstream_error.clone();
        let app = Router::new().route("/", post(move |Json(request): Json<Value>| {
            let calls = counter.clone();
            let error = upstream_error.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request["params"], json!([{"futureUserOperationField":true},"0xentrypoint"]));
                Json(json!({"jsonrpc":"2.0","id":1,"error":error}))
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let forwarder = RpcForwarder {
            chain: 1, max_log_blocks: 100,
            routes: BTreeMap::from([("pimlico".into(), RpcRoute {
                upstream: ExecutionRpc::new(&endpoint, Duration::from_secs(1), 4096).unwrap(),
                methods: vec!["eth_sendUserOperation".into()],
            })]),
        };
        let store = ServiceStore::open(Path::new(":memory:")).unwrap();
        let mut call = RpcCall { method: "eth_sendUserOperation".into(),
            params: Some(json!([{"futureUserOperationField":true},"0xentrypoint"])), id: Some(json!(7)) };
        assert_eq!(forwarder.call("pimlico", &call, &store).await["error"], expected);
        call.id = Some(json!(8));
        let reply = forwarder.call("pimlico", &call, &store).await;
        assert_eq!(reply["id"], 8);
        assert_eq!(reply["error"], expected);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn log_queries_have_a_bounded_cost() {
        assert!(valid_logs(Some(&json!([{"fromBlock":"0x10","toBlock":"0x1f"}])), 16));
        assert!(!valid_logs(Some(&json!([{"fromBlock":"0x10","toBlock":"0x20"}])), 16));
        assert!(!valid_logs(Some(&json!([{"fromBlock":"earliest","toBlock":"latest"}])), 16));
        assert!(!valid_logs(Some(&json!([{"blockHash":"0x01"}])), 16));
    }

    #[test]
    fn saved_intent_never_authorizes_another_dispatch() {
        let journal = ServiceStore::open(Path::new(":memory:")).unwrap();
        assert!(matches!(journal.reserve(&[1;32]).unwrap(), Dispatch::Fresh));
        assert!(matches!(journal.reserve(&[1;32]).unwrap(), Dispatch::Unknown));
    }
}

#[derive(Clone)]
pub struct ExecutionRpc {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    max_response_bytes: usize,
}

impl ExecutionRpc {
    pub fn new(endpoint: &str, timeout: Duration, max_response_bytes: usize) -> Result<Self> {
        let endpoint = reqwest::Url::parse(endpoint)?;
        ensure!(matches!(endpoint.scheme(), "http" | "https"), "unsupported upstream scheme");
        ensure!(max_response_bytes > 0 && max_response_bytes <= 8 * 1024 * 1024,
            "invalid upstream response limit");
        let client = reqwest::Client::builder().timeout(timeout)
            .redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())
            .no_proxy().build()?;
        Ok(Self { client, endpoint, max_response_bytes })
    }

    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let request = RpcCall { method: method.to_owned(), params, id: Some(json!(1)) }.to_value();
        let mut response = self.client.post(self.endpoint.clone()).json(&request).send().await
            .map_err(|_| anyhow::anyhow!("upstream transport failure"))?;
        ensure!(response.status().is_success(), "upstream HTTP failure");
        if response.content_length().is_some_and(|n| n > self.max_response_bytes as u64) {
            bail!("upstream response exceeds limit");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("upstream body failure"))? {
            ensure!(bytes.len().saturating_add(chunk.len()) <= self.max_response_bytes,
                "upstream response exceeds limit");
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        validate_response(&value, &json!(1))?;
        Ok(value)
    }

    pub async fn check_chain(&self, expected: u64) -> Result<()> {
        let reply = self.call("eth_chainId", Some(json!([]))).await?;
        let chain = reply.get("result").and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("0x")).and_then(|s| u64::from_str_radix(s, 16).ok());
        ensure!(chain == Some(expected), "upstream chain mismatch");
        Ok(())
    }
}

#[cfg(test)]
mod upstream_tests {
    use super::*;
    use axum::{routing::post, Json, Router};

    #[tokio::test]
    async fn rejects_wrong_id_and_oversized_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/", post(|| async {
            Json(json!({"jsonrpc":"2.0","id":2,"result":"0x1"}))
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let rpc = ExecutionRpc::new(&format!("http://{address}"), Duration::from_secs(1), 1024).unwrap();
        assert!(rpc.call("eth_chainId", None).await.is_err());
        let rpc = ExecutionRpc::new(&format!("http://{address}"), Duration::from_secs(1), 4).unwrap();
        assert!(rpc.call("eth_chainId", None).await.is_err());
        server.abort();
    }
}
