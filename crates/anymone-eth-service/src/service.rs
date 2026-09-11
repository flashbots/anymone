use std::{path::Path, sync::Mutex};
use anyhow::{ensure, Result};
use anymone_eth_service::{digest, crypto::DeliveryBinding, crypto::DeliverySpec, ReplyPacket, RequestEnvelope,
    ServiceDescriptor, parse_request, RpcCall};
use ed25519_dalek::SigningKey;
use rusqlite::{params, OptionalExtension, Connection};
use serde_json::Value;
use crate::{forward::RpcForwarder, forward::rpc_error};

pub struct RpcService {
    pub descriptor: ServiceDescriptor,
    pub forwarder: RpcForwarder,
    signing_key: SigningKey,
    store: ServiceStore,
    dispatch: tokio::sync::Mutex<()>,
}

impl RpcService {
    pub fn new(descriptor: ServiceDescriptor, forwarder: RpcForwarder, signing_key: SigningKey, path: &Path, now: u64) -> Result<Self> {
        descriptor.validate(now)?;
        ensure!(descriptor.signing_key == signing_key.verifying_key().to_bytes(), "service signing key mismatch");
        ensure!(descriptor.backend_routes.iter().all(|route| forwarder.routes.contains_key(route)), "unsupported backend route");
        forwarder.validate()?;
        ensure!(descriptor.chain == forwarder.chain, "upstream chain mismatch");
        Ok(Self { descriptor, forwarder, signing_key, store: ServiceStore::open(path)?,
            dispatch: tokio::sync::Mutex::new(()) })
    }

    pub async fn execute(&self, request: RequestEnvelope, operation: [u8; 32],
                         now: u64) -> Result<ReplyPacket> {
        let started = std::time::Instant::now();
        request.validate(&self.descriptor, operation, now)?;
        let _guard = self.dispatch.lock().await;
        request.validate(&self.descriptor, operation, now.saturating_add(started.elapsed().as_secs()))?;
        let request_hash = digest(&request.to_bytes()?);
        {
            let mut connection = self.store.connection.lock().map_err(|_| anyhow::anyhow!("operation lock poisoned"))?;
            let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            transaction.execute("DELETE FROM operations WHERE expires<=?1", [now])?;
            let existing: Option<(Vec<u8>, Option<Vec<u8>>)> = transaction.query_row(
                "SELECT digest,reply FROM operations WHERE operation=?1", [operation.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            if let Some((hash, reply)) = existing {
                ensure!(hash == request_hash, "conflicting operation replay");
                if let Some(reply) = reply { return Ok(bincode::deserialize(&reply)?); }
            } else {
                let count: u32 = transaction.query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))?;
                ensure!(count < 1024, "operation capacity exhausted");
                transaction.execute("INSERT INTO operations(operation,digest,expires) VALUES(?1,?2,?3)",
                    params![operation.as_slice(), request_hash.as_slice(), request.capability.context.expires_at])?;
            }
            transaction.commit()?;
        }
        let reply = self.dispatch_rpc(&request.backend_route, &request.payload).await;
        let now = now.saturating_add(started.elapsed().as_secs());
        let mut content = serde_json::to_vec(&reply)?;
        if content.len() > self.descriptor.limits.max_response_bytes as usize {
            content = serde_json::to_vec(&limit_errors(&request.payload))?;
        }
        let DeliverySpec { first_epoch, last_epoch, .. } = &request.capability.delivery;
        let feed = &self.descriptor.feed;
        let epoch = feed.epoch(now)?.checked_add(1).ok_or_else(|| anyhow::anyhow!("epoch overflow"))?.max(*first_epoch);
        ensure!(epoch <= *last_epoch, "publication window exhausted");
        ensure!(feed.closes_at(epoch)? < request.capability.context.expires_at, "response expires before publication");
        ensure!(content.len() <= self.descriptor.limits.max_response_bytes as usize, "response exceeds service limit");
        let binding = DeliveryBinding { feed: feed.feed, epoch, locator: request.capability.locator(epoch)? };
        let sealed = request.capability.seal(&binding, &content, &self.signing_key, now)?;
        let packet = ReplyPacket { binding, sealed };
        let mut connection = self.store.connection.lock().map_err(|_| anyhow::anyhow!("operation lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute("UPDATE operations SET reply=?2 WHERE operation=?1",
            params![operation.as_slice(), bincode::serialize(&packet)?])?;
        transaction.execute("INSERT INTO publications(epoch,locator,packet,expires) VALUES(?1,?2,?3,?4)",
            params![epoch, packet.binding.locator.as_slice(), bincode::serialize(&packet)?, request.capability.context.expires_at])?;
        transaction.commit()?;
        Ok(packet)
    }

    pub fn pending_publications(&self, epoch: u64, now: u64) -> Result<Vec<Vec<u8>>> {
        let connection = self.store.connection.lock().map_err(|_| anyhow::anyhow!("operation lock poisoned"))?;
        connection.execute("DELETE FROM publications WHERE expires<=?1", [now])?;
        let mut statement = connection.prepare("SELECT packet FROM publications WHERE epoch=?1 AND expires>?2")?;
        let rows = statement.query_map(params![epoch, now], |r| r.get::<_, Vec<u8>>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    async fn dispatch_rpc(&self, route: &str, bytes: &[u8]) -> Option<Value> {
        let (batch, items) = match parse_request(bytes, self.descriptor.limits.max_batch as usize) {
            Ok(parsed) => parsed,
            Err(anymone_eth_service::Error::Encoding(_)) => return Some(rpc_error(Value::Null, -32700, "Parse error")),
            Err(_) => return Some(rpc_error(Value::Null, -32600, "Invalid Request")),
        };
        let mut replies = Vec::new();
        for item in items {
            let call = match RpcCall::parse(&item) {
                Ok(call) => call,
                Err(_) => { replies.push(rpc_error(Value::Null, -32600, "Invalid Request")); continue; }
            };
            let reply = self.forwarder.call(route, &call, &self.store).await;
            if call.id.is_some() { replies.push(reply); }
        }
        if replies.is_empty() { None } else if batch { Some(Value::Array(replies)) } else { replies.pop() }
    }
}

fn limit_errors(bytes: &[u8]) -> Option<Value> {
    let (batch, items) = parse_request(bytes, 128).ok()?;
    let mut errors: Vec<_> = items.iter().filter_map(|item| RpcCall::parse(item).ok()?.id)
        .map(|id| rpc_error(id, -32005, "Response exceeds service limit")).collect();
    if errors.is_empty() { None } else if batch { Some(Value::Array(errors)) } else { errors.pop() }
}


#[cfg(test)]
mod engine_tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Arc, sync::atomic::AtomicUsize, sync::atomic::Ordering, time::Duration};
    use anymone_eth_service::{FeedDescriptor, crypto::open_request, crypto::request_keypair, crypto::seal_request,
        crypto::ResponseCapability, crypto::ResponseKeyContext, ServiceLimits, VERSION};
    use axum::{routing::post, Json, Router};
    use serde_json::json;
    use crate::{forward::RpcRoute, forward::ExecutionRpc};

    #[tokio::test]
    async fn encrypted_rpc_round_trips_and_publication_retries_reuse_exact_packets() {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}",listener.local_addr().unwrap());
        let app = Router::new().route("/",post(move || {
            calls.fetch_add(1,Ordering::SeqCst);
            async { Json(json!({"jsonrpc":"2.0","id":1,"result":"0x1"})) }
        }));
        let server = tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
        let key = SigningKey::from_bytes(&[7;32]);
        let (secret, public) = request_keypair();
        let feed = FeedDescriptor { feed:[3;32], genesis_time:0,epoch_seconds:10,max_epoch_bytes:16384,
            retained_epochs:10 };
        let descriptor = ServiceDescriptor { feed_mirrors: vec![], version:VERSION,network:[1;32],chain:1,service_identity:[2;32],
            signing_key:key.verifying_key().to_bytes(),request_key:public,tag:"provider".into(),
            backend_routes:vec!["execution".into()],
            limits:ServiceLimits { max_request_bytes:4096,max_response_bytes:4096,max_batch:8,max_log_blocks:100,
                max_lifetime_seconds:1000 },feed,expires_at:2000 };
        let forwarder = RpcForwarder { chain:1,max_log_blocks:100,
            routes:BTreeMap::from([("execution".into(),RpcRoute {
                upstream:ExecutionRpc::new(&endpoint,Duration::from_secs(1),4096).unwrap(),
                methods:vec!["eth_chainId".into(),"eth_sendRawTransaction".into()] })]) };
        let service = RpcService::new(descriptor,forwarder,key,Path::new(":memory:"),1).unwrap();
        let payload = serde_json::to_vec(&json!([
            {"jsonrpc":"2.0","id":"alpha","method":"eth_chainId","params":[]},
            {"jsonrpc":"2.0","method":"eth_chainId","params":[]},
            {"jsonrpc":"2.0","id":null,"method":"eth_chainId","params":[]},
            {"jsonrpc":"2.0","id":"submit","method":"eth_sendRawTransaction","params":["0x01"]}
        ])).unwrap();
        let capability = ResponseCapability::generate(ResponseKeyContext { version:VERSION,network:[1;32],
            service:service.descriptor.signing_key,chain:1,operation:[4;32],
            request_digest:RequestEnvelope::payload_digest("execution",&payload).unwrap(),expires_at:1000 },
            DeliverySpec {feed:[3;32],first_epoch:1,last_epoch:9});
        let request = RequestEnvelope {capability:capability.clone(),backend_route:"execution".into(),payload};
        let wire = seal_request(&public,&request.to_bytes().unwrap()).unwrap();
        let received = RequestEnvelope::from_bytes(&open_request(&secret,&wire).unwrap()).unwrap();
        let packet = service.execute(received,[4;32],1).await.unwrap();
        let plaintext = capability.open(&packet.binding,&packet.sealed,2).unwrap();
        let reply: Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(reply,json!([{"jsonrpc":"2.0","id":"alpha","result":"0x1"},{"jsonrpc":"2.0","id":null,"result":"0x1"},
            {"jsonrpc":"2.0","id":"submit","result":"0x1"}]));
        let retry = service.execute(request.clone(),[4;32],2).await.unwrap();
        assert_eq!(bincode::serialize(&packet).unwrap(),bincode::serialize(&retry).unwrap());
        assert_eq!(count.load(Ordering::SeqCst),4);
        let mut second = request;
        second.capability.context.operation = [5;32];
        service.execute(second,[5;32],3).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst),7);
        let first = service.pending_publications(1,10).unwrap();
        assert!(!first.is_empty());
        assert_eq!(first,service.pending_publications(1,11).unwrap());
        server.abort();
    }
}

pub enum Dispatch {
    Fresh,
    Saved(Value),
    Unknown,
}

pub struct ServiceStore {
    connection: Mutex<Connection>,
}

impl ServiceStore {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS operations (operation BLOB PRIMARY KEY, digest BLOB NOT NULL,
                expires INTEGER NOT NULL, reply BLOB);
            CREATE TABLE IF NOT EXISTS publications(epoch INTEGER NOT NULL, locator BLOB NOT NULL,
                packet BLOB NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(epoch,locator));
            CREATE TABLE IF NOT EXISTS rpc_dispatches (
                digest BLOB PRIMARY KEY, reply TEXT
            );")?;
        Ok(Self { connection: Mutex::new(connection) })
    }

    pub fn reserve(&self, digest: &[u8; 32]) -> Result<Dispatch> {
        let mut connection = self.connection.lock().map_err(|_| anyhow::anyhow!("journal lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let reply: Option<Option<String>> = transaction.query_row(
            "SELECT reply FROM rpc_dispatches WHERE digest=?1", [digest.as_slice()],
            |row| row.get(0)).optional()?;
        if let Some(reply) = reply {
            return Ok(match reply {
                Some(reply) => Dispatch::Saved(serde_json::from_str(&reply)?),
                None => Dispatch::Unknown,
            });
        }
        let entries: u64 = transaction.query_row("SELECT COUNT(*) FROM rpc_dispatches", [], |r| r.get(0))?;
        ensure!(entries < 100_000, "submission journal capacity exhausted");
        transaction.execute("INSERT INTO rpc_dispatches(digest) VALUES(?1)", [digest.as_slice()])?;
        transaction.commit()?;
        Ok(Dispatch::Fresh)
    }

    pub fn finish(&self, digest: &[u8; 32], reply: &Value) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("journal lock poisoned"))?;
        ensure!(connection.execute("UPDATE rpc_dispatches SET reply=?2 WHERE digest=?1",
            params![digest.as_slice(), serde_json::to_string(reply)?])? == 1, "missing submission intent");
        Ok(())
    }
}
