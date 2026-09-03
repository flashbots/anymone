//! The client object the shells drive: start, join a tag, send and receive.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anymone_core::cw::StreamClientNetwork;
use anymone_core::runtime::TeeSetup;
use anymone_core::wire::RouteTag;
use anymone_core::{Anymone, BootstrapConfig, Event, GovernanceBootstrap, Pipe, ServiceTag};
use tokio::sync::broadcast::error::RecvError;

use crate::attest::{AttestationStatus, AttestationTokenFetcher, BridgeProver, MobileScheme};
use crate::secrets::SecretStore;
use crate::{on_runtime, AnymoneError};

/// How often a pending `subscribe`/`listen`/`open` retries while the tag is not
/// yet in the signed config.
const OPEN_RETRY: Duration = Duration::from_millis(500);

#[derive(uniffi::Enum)]
pub enum AnymoneEvent {
    RoundDecoded {
        round: u64,
        subnet: u32,
        n_messages: u32,
    },
    Fault {
        round: u64,
        subnet: u32,
        detail: String,
    },
    ConfigUpdated {
        round: u64,
    },
}

impl From<Event> for AnymoneEvent {
    fn from(e: Event) -> Self {
        match e {
            Event::RoundDecoded {
                round,
                subnet,
                n_messages,
            } => AnymoneEvent::RoundDecoded {
                round,
                subnet,
                n_messages: n_messages as u32,
            },
            Event::Fault {
                round,
                subnet,
                fault,
            } => AnymoneEvent::Fault {
                round,
                subnet,
                detail: format!("{fault:?}"),
            },
            Event::ConfigUpdated { round } => AnymoneEvent::ConfigUpdated { round },
        }
    }
}

/// One decoded round payload. `own_echo` marks our own send coming back, which
/// is the only send confirmation the protocol gives.
#[derive(uniffi::Record)]
pub struct IncomingMessage {
    pub payload: Vec<u8>,
    pub round: u64,
    pub return_tag: Vec<u8>,
    pub own_echo: bool,
}

struct Started {
    anymone: Anymone,
    prover: Option<Arc<BridgeProver>>,
}

#[derive(uniffi::Object)]
pub struct AnymoneClient {
    /// `None` after `stop`: the runtime, its subnet workers and the stream
    /// transport are all dropped with it.
    started: std::sync::Mutex<Option<Started>>,
    events: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<Event>>,
}

impl AnymoneClient {
    fn wrap(anymone: Anymone, prover: Option<Arc<BridgeProver>>) -> Arc<Self> {
        let events = anymone.events();
        Arc::new(AnymoneClient {
            started: std::sync::Mutex::new(Some(Started { anymone, prover })),
            events: tokio::sync::Mutex::new(events),
        })
    }

    fn live(&self) -> Result<Anymone, AnymoneError> {
        self.started
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.anymone.clone())
            .ok_or(AnymoneError::Stopped)
    }

    /// `data_dir` holds only transport state — the identity comes from `store`,
    /// and commonware's storage goes here rather than the system temp dir (which
    /// an Android app cannot write).
    async fn bring_up(
        config_toml: String,
        data_dir: String,
        store: Arc<dyn SecretStore>,
        prover: Option<Arc<BridgeProver>>,
    ) -> Result<Arc<Self>, AnymoneError> {
        let data = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data).map_err(|e| AnymoneError::Config(e.to_string()))?;

        let bootstrap = BootstrapConfig::from_toml_str(&config_toml)?;
        let identity = crate::secrets::identity(store.as_ref())?;
        let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);

        let mut stream_cfg = bootstrap.stream_client_config()?;
        stream_cfg.storage_dir = Some(data.join("cw"));
        let transport = StreamClientNetwork::start(&identity, stream_cfg);

        let mut prep = Anymone::prepare(identity, transport, gov).await;
        if let Some(prover) = prover.clone() {
            prep.set_tee(TeeSetup::with_prover(prover));
        }
        Ok(Self::wrap(prep.start().await?, prover))
    }

    async fn open_with_retry<F, Fut>(
        &self,
        wait_ms: u64,
        open: F,
    ) -> Result<Arc<AnymonePipe>, AnymoneError>
    where
        F: Fn(Anymone) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<Pipe, anymone_core::OpenError>> + Send,
    {
        let anymone = self.live()?;
        on_runtime(async move {
            let deadline = std::time::Instant::now() + Duration::from_millis(wait_ms);
            loop {
                match open(anymone.clone()).await {
                    Ok(pipe) => return Ok(AnymonePipe::wrap(pipe)),
                    // The committee places a tag only once a service registers,
                    // so this is the normal state right after startup.
                    Err(anymone_core::OpenError::TagNotInConfig)
                        if std::time::Instant::now() < deadline =>
                    {
                        tokio::time::sleep(OPEN_RETRY).await;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AnymoneClient {
    /// Blocks until a committee-signed config arrives (up to ~65 s), then
    /// brings up the subnets it describes. `store` holds the identity across
    /// launches; a store that mints a fresh one each time would look like a new
    /// client to every relay.
    #[uniffi::constructor]
    pub async fn start(
        config_toml: String,
        data_dir: String,
        store: Arc<dyn SecretStore>,
    ) -> Result<Arc<Self>, AnymoneError> {
        on_runtime(Self::bring_up(config_toml, data_dir, store, None)).await
    }

    /// Same, plus a platform attestation so the client is admitted on attested
    /// subnets. The first token is fetched in the background; until it lands the
    /// client simply stays off those subnets.
    #[uniffi::constructor]
    pub async fn start_attested(
        config_toml: String,
        data_dir: String,
        store: Arc<dyn SecretStore>,
        scheme: MobileScheme,
        fetcher: Arc<dyn AttestationTokenFetcher>,
    ) -> Result<Arc<Self>, AnymoneError> {
        let prover = Arc::new(BridgeProver::new(scheme, fetcher));
        on_runtime(Self::bring_up(config_toml, data_dir, store, Some(prover))).await
    }

    /// Join a broadcast room: receive every message on `tag`, send to it, and
    /// contribute cover traffic every idle round.
    pub async fn subscribe(
        &self,
        tag: String,
        wait_ms: u64,
    ) -> Result<Arc<AnymonePipe>, AnymoneError> {
        let t = ServiceTag::from_label(&tag);
        self.open_with_retry(wait_ms, move |a| async move { a.subscribe(t).await })
            .await
    }

    /// Read a room without joining it: no sends, no cover, not in the
    /// anonymity set.
    pub async fn listen(
        &self,
        tag: String,
        wait_ms: u64,
    ) -> Result<Arc<AnymonePipe>, AnymoneError> {
        let t = ServiceTag::from_label(&tag);
        self.open_with_retry(wait_ms, move |a| async move { a.listen(t).await })
            .await
    }

    /// Open a request/reply pipe to a service.
    pub async fn open(&self, tag: String, wait_ms: u64) -> Result<Arc<AnymonePipe>, AnymoneError> {
        let t = ServiceTag::from_label(&tag);
        self.open_with_retry(wait_ms, move |a| async move { a.open(t).await })
            .await
    }

    /// The next runtime event, or `None` once the client is stopped.
    pub async fn next_event(&self) -> Option<AnymoneEvent> {
        let mut events = self.events.lock().await;
        loop {
            match events.recv().await {
                Ok(e) => return Some(e.into()),
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Drop the runtime and the stream transport. Pipes handed out earlier
    /// start failing with `PipeClosed`.
    pub fn stop(&self) {
        self.started.lock().unwrap().take();
    }

    pub fn round_duration_ms(&self) -> Result<u64, AnymoneError> {
        Ok(self.live()?.round_duration().as_millis() as u64)
    }

    /// Payloads already accepted but not yet on the wire; at most one leaves
    /// per round, so this is how many rounds the next send waits.
    pub fn queued_outbound(&self) -> Result<u64, AnymoneError> {
        Ok(self.live()?.queued_outbound() as u64)
    }

    /// Largest payload a single `send` accepts under the adopted config.
    pub fn max_payload(&self) -> Result<u64, AnymoneError> {
        Ok(self.live()?.max_payload() as u64)
    }

    pub fn pubkey(&self) -> Result<String, AnymoneError> {
        Ok(self.live()?.pubkey().to_string())
    }

    pub fn attestation_status(&self) -> AttestationStatus {
        let started = self.started.lock().unwrap();
        match started.as_ref().and_then(|s| s.prover.as_ref()) {
            Some(p) => p.status(),
            None => AttestationStatus::Unattested,
        }
    }
}

#[derive(uniffi::Object)]
pub struct AnymonePipe {
    /// `recv` needs `&mut`, and uniffi objects are shared.
    pipe: tokio::sync::Mutex<Pipe>,
    own_tag: RouteTag,
}

impl AnymonePipe {
    fn wrap(pipe: Pipe) -> Arc<Self> {
        let own_tag = pipe.return_tag();
        Arc::new(AnymonePipe {
            pipe: tokio::sync::Mutex::new(pipe),
            own_tag,
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AnymonePipe {
    /// The next message on this pipe, or `None` once it is closed.
    pub async fn recv(&self) -> Option<IncomingMessage> {
        let mut pipe = self.pipe.lock().await;
        let msg = pipe.recv().await?;
        Some(IncomingMessage {
            payload: msg.payload,
            round: msg.round,
            own_echo: msg.return_tag == self.own_tag,
            return_tag: msg.return_tag.0.to_vec(),
        })
    }

    /// Queues one payload for the next round this node is drawn to submit in;
    /// it never blocks on the network.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), AnymoneError> {
        Ok(self.pipe.lock().await.send(payload).await?)
    }

    /// Reply to a `return_tag` taken from an `IncomingMessage`.
    pub async fn send_to(&self, return_tag: Vec<u8>, payload: Vec<u8>) -> Result<(), AnymoneError> {
        let tag = route_tag(&return_tag)?;
        Ok(self.pipe.lock().await.send_to(tag, payload).await?)
    }

    /// Send with a one-off return path, so the recipient cannot link this
    /// message to anything else this pipe sends.
    pub async fn send_unlinkable(&self, payload: Vec<u8>) -> Result<(), AnymoneError> {
        Ok(self.pipe.lock().await.send_unlinkable(payload).await?)
    }

    pub fn own_return_tag(&self) -> Vec<u8> {
        self.own_tag.0.to_vec()
    }
}

fn route_tag(bytes: &[u8]) -> Result<RouteTag, AnymoneError> {
    let arr: [u8; anymone_core::wire::SERVICE_TAG_LEN] = bytes
        .try_into()
        .map_err(|_| AnymoneError::Send(format!("return tag must be {} bytes", bytes.len())))?;
    Ok(RouteTag::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anymone_core::config::{AdcnetConfig, ExchangePublicKeyWire};
    use anymone_core::{
        AnymoneRoundConfiguration, Identity, InMemoryNetwork, ProtocolConfig, ServiceEntry,
    };

    fn echo_tag() -> ServiceTag {
        ServiceTag::from_label("anymone.echo")
    }

    /// The exported wrappers over a real in-process ADCNet subnet: a client
    /// sends through `AnymonePipe::send` and reads the echo back on `recv`.
    #[tokio::test(flavor = "multi_thread")]
    async fn echo_roundtrip_through_ffi_wrappers() {
        let net = InMemoryNetwork::new();
        let committee = Identity::generate();
        let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
        let service = Identity::generate();
        let client = Identity::generate();

        let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
        relay_pks.sort();
        let mut relay_xk: Vec<(_, ExchangePublicKeyWire)> = relays
            .iter()
            .map(|i| (i.pubkey(), i.exchange_keys()))
            .collect();
        relay_xk.sort_by_key(|(p, _)| *p);

        let cfg = AnymoneRoundConfiguration::singleton_subnet(
            0,
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 200,
                max_payload_bytes: 1024,
                estimated_messages: 8,
                client_set_min: 0,
                client_set_max: 8,
                aggregation: None,
            }),
            relay_pks,
            relay_xk,
            vec![ServiceEntry {
                tag: echo_tag(),
                pubkey: service.pubkey(),
            }],
        )
        .sign_with(&[&committee]);

        let mut keep = Vec::new();
        for id in relays {
            let handle = net.handle(id.pubkey());
            keep.push(Anymone::start_with_config(id, Arc::new(handle), cfg.clone()).await);
        }

        let service_anymone = Anymone::start_with_config(
            service.clone(),
            Arc::new(net.handle(service.pubkey())),
            cfg.clone(),
        )
        .await;
        let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
        tokio::spawn(async move {
            while let Some(req) = svc_pipe.recv().await {
                let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
            }
        });

        let client_anymone = Anymone::start_with_config(
            client.clone(),
            Arc::new(net.handle(client.pubkey())),
            cfg.clone(),
        )
        .await;
        let ffi = AnymoneClient::wrap(client_anymone, None);

        assert!(ffi.max_payload().unwrap() > 0);
        assert_eq!(ffi.pubkey().unwrap(), client.pubkey().to_string());
        assert_eq!(ffi.round_duration_ms().unwrap(), 200);
        assert!(matches!(
            ffi.attestation_status(),
            AttestationStatus::Unattested
        ));

        let pipe = ffi.open("anymone.echo".into(), 5_000).await.unwrap();
        pipe.send(b"hello ffi".to_vec()).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(15), pipe.recv())
            .await
            .expect("recv timed out")
            .expect("pipe closed");
        assert!(reply.payload.starts_with(b"hello ffi"));
        assert_eq!(
            pipe.own_return_tag().len(),
            anymone_core::wire::SERVICE_TAG_LEN
        );

        ffi.stop();
        assert!(matches!(ffi.max_payload(), Err(AnymoneError::Stopped)));

        drop(keep);
    }

    /// `bring_up` is the only place that could leak key material to storage, so
    /// this drives it against a real transport and searches the data dir for the
    /// seed. Startup fails (no committee answers), which is fine — the identity
    /// is built before the config wait.
    #[tokio::test]
    async fn no_key_material_reaches_the_data_directory() {
        let dir = std::env::temp_dir().join(format!("anymone-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(crate::secrets::tests::InMemoryStore::empty());

        let toml = r#"
            [network]
            stream_bootstrappers = ["ed25519:0000000000000000000000000000000000000000000000000000000000000000@127.0.0.1:1"]
            [governance]
            threshold = 1
            [[governance.committee]]
            pubkey = "ed25519:0000000000000000000000000000000000000000000000000000000000000000"
            exchange_pubkey = { ecdh = "00", kem = "00" }
        "#;

        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            AnymoneClient::bring_up(toml.into(), dir.display().to_string(), store.clone(), None),
        )
        .await;
        assert!(
            outcome.is_err(),
            "no committee answers, so start cannot finish"
        );

        let secrets = store.0.lock().unwrap().clone().expect("identity minted");
        assert_eq!(secrets.len(), anymone_core::identity::SECRETS_LEN);

        // The file-backed path wrote these two.
        assert!(!dir.join("identity").exists());
        assert!(!dir.join("identity.exchange").exists());

        let mut stack = vec![dir.clone()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap_or_default();
                for window in bytes.windows(32) {
                    assert!(
                        window != &secrets[..32] && window != &secrets[32..],
                        "{} contains key material",
                        path.display()
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_tag_gives_up_after_the_wait_budget() {
        let net = InMemoryNetwork::new();
        let committee = Identity::generate();
        let relay = Identity::generate();
        let service = Identity::generate();
        let client = Identity::generate();

        let cfg = AnymoneRoundConfiguration::singleton_subnet(
            0,
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 200,
                max_payload_bytes: 1024,
                estimated_messages: 8,
                client_set_min: 0,
                client_set_max: 8,
                aggregation: None,
            }),
            vec![relay.pubkey()],
            vec![(relay.pubkey(), relay.exchange_keys())],
            vec![ServiceEntry {
                tag: echo_tag(),
                pubkey: service.pubkey(),
            }],
        )
        .sign_with(&[&committee]);

        let client_anymone =
            Anymone::start_with_config(client.clone(), Arc::new(net.handle(client.pubkey())), cfg)
                .await;
        let ffi = AnymoneClient::wrap(client_anymone, None);

        let outcome = ffi.subscribe("anymone.absent".into(), 100).await;
        assert!(
            matches!(outcome, Err(AnymoneError::TagNotInConfig)),
            "absent tag must not resolve"
        );
    }
}
