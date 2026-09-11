use std::{sync::Arc, time::Duration, time::SystemTime, time::UNIX_EPOCH, path::Path, sync::Mutex as StoreMutex};
use anyhow::{ensure, Result};
use anymone_eth_service::{crypto::DeliverySpec, crypto::ResponseCapability, crypto::ResponseKeyContext,
    crypto::seal_fragments, RequestEnvelope, RpcCall, VERSION, ReplyPacket};
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use crate::BrokerProfile;
use rusqlite::{params, Connection, OptionalExtension};

pub trait Upload: Send + Sync {
    fn capacity(&self) -> Result<usize>;
    fn send(&self, tag: &str, fragments: Vec<Vec<u8>>) -> Result<()>;
}

struct Reader {
    stop_at: u64,
    task: tokio::task::JoinHandle<Result<()>>,
}

pub struct Broker {
    profile: std::sync::RwLock<BrokerProfile>,
    pub store: OperationStore,
    reader: Mutex<Option<Reader>>,
    upload: Option<Arc<dyn Upload>>,
}

pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

impl Broker {
    pub fn new(profile: BrokerProfile, upload: Option<Arc<dyn Upload>>) -> Result<Arc<Self>> {
        profile.validate(now())?;
        Ok(Arc::new(Self { store: OperationStore::open(&profile.database)?, profile: std::sync::RwLock::new(profile),
            reader: Mutex::new(None), upload }))
    }

    pub fn profile(&self) -> BrokerProfile { self.profile.read().unwrap().clone() }

    pub fn update_profile(&self, profile: BrokerProfile) { *self.profile.write().unwrap() = profile; }

    pub fn authorize_services(&self, config: &anymone_core::AnymoneRoundConfiguration) {
        for service in self.profile.write().unwrap().services.values_mut() {
            let tag = anymone_core::ServiceTag::from_label(&service.signed.descriptor.tag);
            if !config.body.services.iter().any(|entry| entry.tag == tag && entry.pubkey.0 == service.service_identity) {
                service.revoked = true;
            }
        }
    }

    pub async fn start_reader(self: &Arc<Self>) -> Result<()> {
        let mut reader = self.reader.lock().await;
        if reader.as_ref().is_some_and(|r| !r.task.is_finished() && now() < r.stop_at) { return Ok(()); }
        if let Some(previous) = reader.take() { previous.task.abort(); }
        let stop_at = now().saturating_add(self.profile().session_seconds);
        let broker = self.clone();
        *reader = Some(Reader { stop_at, task: tokio::spawn(async move {
            crate::response_feed::follow(broker, stop_at).await
        }) });
        Ok(())
    }

    pub async fn status(&self) -> Value {
        let reader = self.reader.lock().await;
        let profile = self.profile();
        let first = profile.services.values().next().expect("validated services");
        let services: serde_json::Map<String, Value> = profile.services.iter()
            .filter(|(_, target)| !target.revoked && target.signed.descriptor.expires_at > now())
            .map(|(name, target)| (name.clone(), json!(target.signed.descriptor.backend_routes))).collect();
        json!({"chainId":first.signed.descriptor.chain, "services":services,
            "active":reader.as_ref().is_some_and(|r| !r.task.is_finished() && now() < r.stop_at),
            "stopAt":reader.as_ref().map(|r| r.stop_at)})
    }

    pub async fn rpc(&self, service: &str, route: &str, bytes: &[u8]) -> Result<Option<Value>> {
        let profile = self.profile();
        let target = profile.services.get(service).ok_or_else(|| anyhow::anyhow!("unknown service"))?;
        ensure!(!target.revoked, "service removed from configuration");
        let descriptor = &target.signed.descriptor;
        ensure!(descriptor.backend_routes.iter().any(|r| r == route), "unsupported backend route");
        let stop_at = {
            let reader = self.reader.lock().await;
            let reader = reader.as_ref().ok_or_else(|| anyhow::anyhow!("response reader is inactive"))?;
            ensure!(!reader.task.is_finished() && now() < reader.stop_at, "response reader expired");
            reader.stop_at
        };
        let upload = self.upload.as_ref().ok_or_else(|| anyhow::anyhow!("upload transport unavailable"))?;
        let capacity = upload.capacity()?;
        let mut operation = [0; 32];
        rand::rng().fill_bytes(&mut operation);
        let expires_at = now().saturating_add(descriptor.limits.max_lifetime_seconds).min(descriptor.expires_at).min(stop_at);
        let feed = &descriptor.feed;
        let epoch = feed.epoch(now())?;
        ensure!(feed.retained_epochs >= 3 && feed.closes_at(epoch + 2)? < expires_at, "insufficient publication window");
        let delivery = DeliverySpec { feed: feed.feed, first_epoch: epoch + 1,
            last_epoch: epoch + u64::from(feed.retained_epochs) - 1 };
        let capability = ResponseCapability::generate(ResponseKeyContext { version: VERSION, network: descriptor.network,
            service: descriptor.signing_key, chain: descriptor.chain, operation,
            request_digest: RequestEnvelope::payload_digest(route, bytes)?, expires_at }, delivery);
        let request = RequestEnvelope { capability: capability.clone(), backend_route: route.to_owned(), payload: bytes.to_vec() };
        request.validate(descriptor, operation, now())?;
        let fragments = seal_fragments(&descriptor.request_key, operation, expires_at, &request.to_bytes()?, capacity)?;
        self.store.insert(&capability, descriptor.limits.max_response_bytes, now())?;
        if upload.send(&descriptor.tag, fragments).is_err() { return Ok(unknown(bytes, operation)); }
        while now() < expires_at {
            if let Some(bytes) = self.store.response(&operation)? { return Ok(serde_json::from_slice(&bytes)?); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(unknown(bytes, operation))
    }
}

pub async fn bounded_response(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(response.status().is_success(), "remote service unavailable");
    ensure!(!response.content_length().is_some_and(|n| n > limit as u64), "response exceeds limit");
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len().saturating_add(chunk.len()) <= limit, "response exceeds limit");
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn unknown(bytes: &[u8], operation: [u8; 32]) -> Option<Value> {
    let error = |id| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32098,"message":"Operation outcome unknown",
        "data":{"outcome":"Unknown","operation":hex::encode(operation)}}});
    let reply = |item: &Value| match RpcCall::parse(item) {
        Ok(call) => call.id.map(&error),
        Err(_) => Some(error(Value::Null)),
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Array(items)) if !items.is_empty() => {
            let replies: Vec<_> = items.iter().filter_map(reply).collect();
            if replies.is_empty() { None } else { Some(Value::Array(replies)) }
        }
        Ok(item) => reply(&item),
        Err(_) => Some(error(Value::Null)),
    }
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    use std::collections::BTreeMap;
    use anymone_core::Identity;
    use anymone_eth_service::{FeedDescriptor, crypto::request_keypair, crypto::DeliveryBinding,
        crypto::Reassembler, ReplyPacket, ServiceDescriptor, ServiceLimits, SignedServiceDescriptor};
    use crate::ServiceTarget;
    use ed25519_dalek::SigningKey;

    struct CaptureUpload(tokio::sync::mpsc::UnboundedSender<(String, Vec<Vec<u8>>)>);
    impl Upload for CaptureUpload {
        fn capacity(&self) -> Result<usize> { Ok(4096) }
        fn send(&self, tag: &str, fragments: Vec<Vec<u8>>) -> Result<()> {
            self.0.send((tag.to_owned(), fragments))?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn batch_crosses_upload_intact_and_returns_all_replies() {
        let identity = Identity::from_secrets(&[3;64]).unwrap();
        let signer = SigningKey::from_bytes(&[7;32]);
        let (private, public) = request_keypair();
        let descriptor = ServiceDescriptor { feed_mirrors: vec![], version:VERSION, network:[2;32], chain:1,
            service_identity:identity.pubkey().0, signing_key:signer.verifying_key().to_bytes(),
            request_key:public, tag:"provider".into(), backend_routes:vec!["execution".into()],
            limits:ServiceLimits { max_request_bytes:4096,max_response_bytes:4096,max_batch:8,
                max_log_blocks:100,max_lifetime_seconds:100 },
            feed:FeedDescriptor { feed:[1;32],genesis_time:now(),epoch_seconds:10,
                max_epoch_bytes:16384,retained_epochs:10 }, expires_at:now()+100 };
        let target = ServiceTarget { service_identity:identity.pubkey().0, revoked: false,
            signed:SignedServiceDescriptor { signature:identity.sign(&descriptor.signing_bytes().unwrap()),descriptor } };
        let profile = BrokerProfile { services:BTreeMap::from([("provider".into(),target)]),
            feed_mirrors:vec!["http://127.0.0.1:1".into()],listen:"127.0.0.1:8546".parse().unwrap(),
            token:"unused".into(),database:":memory:".into(),session_seconds:100 };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let broker = Broker::new(profile,Some(Arc::new(CaptureUpload(tx)))).unwrap();
        broker.start_reader().await.unwrap();
        let payload = serde_json::to_vec(&json!([
            {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
            {"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction","params":["0x01"]}
        ])).unwrap();
        let sending = broker.clone();
        let expected = payload.clone();
        let call = tokio::spawn(async move { sending.rpc("provider","execution",&payload).await });
        let (tag, fragments) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        assert_eq!(tag,"provider");
        assert_eq!(fragments.len(),1);
        let mut reassembler = Reassembler::new(1,8192,100);
        let (operation, bytes) = reassembler.receive(&private,&fragments[0],now()).unwrap().unwrap();
        let request = RequestEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(request.payload,expected);
        assert_eq!(request.capability.context.operation,operation);
        let response = json!([{"jsonrpc":"2.0","id":1,"result":"0x1"},{"jsonrpc":"2.0","id":2,"result":"0xtx"}]);
        let content = serde_json::to_vec(&response).unwrap();
        let cap = request.capability;
        let mut updated = broker.profile();
        updated.services.get_mut("provider").unwrap().revoked = true;
        broker.update_profile(updated);
        let pending = broker.store.pending(now()).unwrap();
        assert_eq!(pending[0].0.context.operation, operation);
        assert_eq!(pending[0].1, Some(4096));
        assert!(broker.rpc("provider", "execution", &expected).await.is_err());
        let epoch = cap.delivery.first_epoch;
        let binding = DeliveryBinding { feed:cap.delivery.feed,epoch,locator:cap.locator(epoch).unwrap() };
        let sealed = cap.seal(&binding,&content,&signer,now()).unwrap();
        broker.store.record(&cap,&ReplyPacket { binding,sealed },4096,now()).unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2),call).await.unwrap().unwrap().unwrap(),Some(response));
        assert!(rx.try_recv().is_err());
        broker.reader.lock().await.take().unwrap().task.abort();
    }
}

pub struct OperationStore { connection: StoreMutex<Connection> }

impl OperationStore {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)] if !(cfg!(test) && path == Path::new(":memory:")) {
            use std::{os::unix::fs::OpenOptionsExt, os::unix::fs::PermissionsExt};
            let file = std::fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600).open(path)?;
            ensure!(file.metadata()?.permissions().mode() & 0o077 == 0, "operation database must be private to its owner");
        }
        #[cfg(not(unix))]
        anyhow::bail!("private operation storage currently requires a Unix filesystem");
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS operations(operation BLOB PRIMARY KEY, capability BLOB NOT NULL,
                expires INTEGER NOT NULL, response BLOB, packet BLOB);
            CREATE TABLE IF NOT EXISTS cursors(feed BLOB PRIMARY KEY, next_epoch INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS operation_limits(operation BLOB PRIMARY KEY, response_bytes INTEGER NOT NULL);")?;
        Ok(Self { connection: StoreMutex::new(connection) })
    }

    pub fn insert(&self, cap: &ResponseCapability, max_response_bytes: u32, now: u64) -> Result<()> {
        let mut connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        let connection = connection.transaction()?;
        let count: u32 = connection.query_row("SELECT COUNT(*) FROM operations WHERE expires>?1 AND response IS NULL", [now], |r| r.get(0))?;
        ensure!(count < 128, "too many outstanding operations");
        connection.execute("INSERT INTO operations(operation,capability,expires) VALUES(?1,?2,?3)",
            params![cap.context.operation.as_slice(), bincode::serialize(cap)?, cap.context.expires_at])?;
        connection.execute("INSERT INTO operation_limits(operation,response_bytes) VALUES(?1,?2)",
            params![cap.context.operation.as_slice(), max_response_bytes])?;
        connection.commit()?;
        Ok(())
    }

    pub fn capability(&self, operation: &[u8; 32]) -> Result<ResponseCapability> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        let cap: Vec<u8> = connection.query_row("SELECT capability FROM operations WHERE operation=?1", [operation.as_slice()], |r| r.get(0))?;
        Ok(bincode::deserialize(&cap)?)
    }

    pub fn pending(&self, now: u64) -> Result<Vec<(ResponseCapability, Option<u32>)>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        let mut statement = connection.prepare("SELECT capability,response_bytes FROM operations
            LEFT JOIN operation_limits USING(operation) WHERE expires>?1 AND response IS NULL")?;
        let rows = statement.query_map([now], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<u32>>(1)?)))?;
        let mut caps = Vec::new();
        for row in rows { let (bytes, limit) = row?; caps.push((bincode::deserialize(&bytes)?, limit)); }
        Ok(caps)
    }

    pub fn record(&self, cap: &ResponseCapability, packet: &ReplyPacket, max_response_bytes: u32, now: u64) -> Result<()> {
        let response = cap.open(&packet.binding, &packet.sealed, now)?;
        ensure!(response.len() <= max_response_bytes as usize, "response exceeds service limit");
        let _: Option<serde_json::Value> = serde_json::from_slice(&response)?;
        let mut connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let operation = cap.context.operation.as_slice();
        let bytes = bincode::serialize(packet)?;
        let existing: Option<Vec<u8>> = transaction.query_row("SELECT packet FROM operations WHERE operation=?1",
            [operation], |r| r.get(0))?;
        if let Some(existing) = existing {
            ensure!(existing == bytes, "conflicting response");
            return Ok(());
        }
        transaction.execute("UPDATE operations SET response=?2,packet=?3 WHERE operation=?1",
            params![operation, response, bytes])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn response(&self, operation: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        Ok(connection.query_row("SELECT response FROM operations WHERE operation=?1", [operation.as_slice()], |r| r.get(0))?)
    }

    pub fn packet(&self, operation: &[u8; 32]) -> Result<Option<ReplyPacket>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        let bytes: Option<Vec<u8>> = connection.query_row("SELECT packet FROM operations WHERE operation=?1",
            [operation.as_slice()], |r| r.get(0))?;
        Ok(bytes.map(|bytes| bincode::deserialize(&bytes)).transpose()?)
    }

    pub fn cursor(&self, feed: &[u8; 32]) -> Result<Option<u64>> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        Ok(connection.query_row("SELECT next_epoch FROM cursors WHERE feed=?1", [feed.as_slice()], |r| r.get(0)).optional()?)
    }

    pub fn advance(&self, feed: &[u8; 32], epoch: u64) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("operation store poisoned"))?;
        connection.execute("INSERT INTO cursors(feed,next_epoch) VALUES(?1,?2)
            ON CONFLICT(feed) DO UPDATE SET next_epoch=MAX(next_epoch,excluded.next_epoch)",
            params![feed.as_slice(), epoch.saturating_add(1)])?;
        Ok(())
    }
}
