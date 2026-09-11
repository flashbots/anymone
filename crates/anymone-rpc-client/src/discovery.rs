use std::{collections::BTreeMap, net::SocketAddr, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use anymone_core::{discovery::{check_config, Genesis, NetworkInfo}, BootstrapConfig, Identity, NetworkConfig, ServiceTag};
use anymone_eth_service::SignedServiceDescriptor;
use clap::Args;
use rand::RngCore;

use crate::{broker::{bounded_response, now, Broker}, remote_session::RemoteSession,
    BrokerProfile, ClientProfile, RemoteSessionConfig, ServiceTarget};

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long, conflicts_with_all = ["bootnode", "node_rpc", "genesis", "remote", "remote_pairing", "state_dir"])]
    pub config: Option<PathBuf>,
    /// Discovery bootnode URL; append #<genesis-hash> on first use.
    #[arg(long, conflicts_with = "node_rpc", required_unless_present_any = ["config", "node_rpc"])]
    bootnode: Option<String>,
    /// Node discovery URL; append #<genesis-hash> on first use.
    #[arg(long, required_unless_present_any = ["config", "bootnode"])]
    node_rpc: Option<String>,
    /// Trusted genesis JSON to import instead of a URL hash.
    #[arg(long)]
    genesis: Option<PathBuf>,
    /// Local state directory (default: $XDG_STATE_HOME/anymone-rpc-client).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[command(flatten)]
    remote: anymone_remote_session::desktop::RemoteArgs,
    #[arg(long, default_value = "127.0.0.1:8546")]
    listen: SocketAddr,
}

pub struct Discovery {
    genesis: Genesis,
    config: Option<anymone_core::AnymoneRoundConfiguration>,
    endpoint: String,
    state: PathBuf,
    client: reqwest::Client,
    bootstrap: BootstrapConfig,
}

impl Discovery {
    pub async fn start(args: ServeArgs) -> Result<(ClientProfile, Self)> {
        ensure!(args.listen.ip().is_loopback(), "RPC client must listen on loopback");
        let state = args.state_dir.unwrap_or(default_state()?);
        std::fs::create_dir_all(&state)?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        }
        let state = std::fs::canonicalize(state)?;
        let mut endpoint = reqwest::Url::parse(args.bootnode.as_ref().or(args.node_rpc.as_ref()).context("discovery URL required")?)?;
        let expected = endpoint.fragment().map(hex::decode).transpose()?;
        if let Some(expected) = &expected { ensure!(expected.len() == 32, "genesis hash must contain 32 bytes"); }
        endpoint.set_fragment(None);
        validate_url(endpoint.as_str())?;
        let endpoint = endpoint.to_string().trim_end_matches('/').to_owned();
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never()).timeout(Duration::from_secs(10)).build()?;
        let pinned = state.join("genesis.json");
        let imported: Option<Genesis> = args.genesis.map(|path| -> Result<_> {
            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
        }).transpose()?;
        let genesis: Genesis = if pinned.exists() {
            let saved: Genesis = serde_json::from_slice(&std::fs::read(&pinned)?)?;
            ensure!(imported.as_ref().is_none_or(|imported| imported.hash() == saved.hash()), "state belongs to a different genesis");
            saved
        } else if let Some(imported) = imported { imported } else {
            ensure!(expected.is_some(), "first use requires --genesis <path> or a discovery URL ending in #<genesis-hash>");
            get::<NetworkInfo>(&client, &endpoint, "network").await?.genesis
        };
        genesis.validate()?;
        ensure!(expected.as_ref().is_none_or(|expected| expected.as_slice() == genesis.hash()), "genesis hash mismatch");
        private_json(&pinned, &genesis)?;
        let identity_path = state.join("identity");
        Identity::load_or_generate(&identity_path)?;
        let token = state.join("token");
        if !token.exists() {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            private_write(&token, hex::encode(bytes).as_bytes())?;
        }
        let bootstrap = BootstrapConfig {
            identity_path,
            network: NetworkConfig { listen_addr: None, dialable_addr: None, bootstrappers: vec![],
                genesis_peers: vec![], stream_listen: None, stream_bootstrappers: vec![], local: false },
            governance: genesis.governance.clone(), committee: Default::default(), tee: Default::default(),
        };
        let config = match std::fs::read(state.join("network.json")) {
            Ok(bytes) => {
                let saved = serde_json::from_slice(&bytes)?;
                genesis.verify_config(&saved)?;
                Some(saved)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut discovery = Self { genesis, config, endpoint, state, client, bootstrap };
        discovery.refresh().await?;
        let profile = discovery.profile(args.listen, token).await?;
        let remote_session = Some(RemoteSessionConfig {
            bootstrap: discovery.state.join("bootstrap.toml"),
            pairing: args.remote.remote_pairing,
            remote: args.remote.remote,
        });
        discovery.connection(&profile)?;
        Ok((ClientProfile { broker: profile, remote_session }, discovery))
    }

    async fn refresh(&mut self) -> Result<()> {
        let mut endpoints = vec![self.endpoint.clone()];
        if let Some(config) = &self.config {
            endpoints.extend(config.body.endpoints.nodes.iter().map(|(_, url)| url.clone()));
        }
        let mut found = false;
        for endpoint in endpoints.into_iter().take(8) {
            if validate_url(&endpoint).is_err() { continue; }
            let Ok(network) = get::<NetworkInfo>(&self.client, &endpoint, "network").await else { continue; };
            if network.genesis.hash() != self.genesis.hash()
                || check_config(&self.genesis, &network.config, self.config.as_ref()).is_err() { continue; }
            self.config = Some(network.config);
            found = true;
            break;
        }
        ensure!(found, "no discovery endpoint returned a valid configuration");
        let config = self.config.as_ref().unwrap();
        private_json(&self.state.join("network.json"), config)?;
        let streams: Vec<_> = config.body.relay_client_addrs.iter()
            .filter(|(_, addr)| addr.parse::<SocketAddr>().is_ok_and(|addr| !addr.ip().is_unspecified()))
            .map(|(key, addr)| format!("{key}@{addr}")).collect();
        ensure!(!streams.is_empty(), "no client stream endpoints discovered");
        self.bootstrap.network.stream_bootstrappers = streams;
        let temporary = self.state.join("bootstrap.next.toml");
        self.bootstrap.write_to(&temporary)?;
        std::fs::rename(temporary, self.state.join("bootstrap.toml"))?;
        Ok(())
    }

    async fn profile(&self, listen: SocketAddr, token: PathBuf) -> Result<BrokerProfile> {
        let mut services = BTreeMap::new();
        let mut mirrors = Vec::new();
        let config = self.config.as_ref().context("configuration unavailable")?;
        for (tag, endpoint) in &config.body.endpoints.services {
            let Some(placement) = config.body.services.iter().find(|service| service.tag == *tag) else { continue; };
            if validate_url(endpoint).is_err() { continue; }
            let Ok(signed) = get::<SignedServiceDescriptor>(&self.client, endpoint, "").await else { continue; };
            let descriptor = &signed.descriptor;
            if descriptor.network != self.genesis.hash() || descriptor.service_identity != placement.pubkey.0
                || ServiceTag::from_label(&descriptor.tag) != *tag || descriptor.validate(now()).is_err()
                || !placement.pubkey.verify(&descriptor.signing_bytes()?, &signed.signature)
            { continue; }
            let name = if descriptor.tag.len() <= 64 && !descriptor.tag.is_empty()
                && descriptor.tag.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
                descriptor.tag.clone()
            } else { hex::encode(tag.0) };
            ensure!(!descriptor.feed_mirrors.is_empty(), "service has no public feed URLs");
            mirrors.extend(descriptor.feed_mirrors.clone());
            ensure!(services.insert(name, ServiceTarget { service_identity: placement.pubkey.0,
                signed, revoked: false }).is_none(), "duplicate service alias");
        }
        mirrors.sort(); mirrors.dedup();
        let profile = BrokerProfile { services, feed_mirrors: mirrors, listen, token,
            database: self.state.join("operations.sqlite"), session_seconds: 3600 };
        profile.validate(now())?;
        Ok(profile)
    }

    fn connection(&self, profile: &BrokerProfile) -> Result<()> {
        private_json(&self.state.join("connection.json"), &serde_json::json!({
            "endpoint": format!("http://{}", profile.listen), "tokenFile": profile.token,
            "services": profile.services.iter().map(|(name, service)|
                (name.clone(), service.signed.descriptor.backend_routes.clone())).collect::<BTreeMap<_, _>>()
        }))
    }

    pub fn follow(mut self, broker: Arc<Broker>, remote: Option<Arc<RemoteSession>>) {
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(30));
            timer.tick().await;
            loop {
                timer.tick().await;
                let update = async {
                    self.refresh().await?;
                    if let Some(config) = &self.config { broker.authorize_services(config); }
                    let old = broker.profile();
                    let next = self.profile(old.listen, old.token.clone()).await?;
                    ensure!(old.services.values().next().map(|s| (&s.signed.descriptor.feed, s.signed.descriptor.chain))
                        == next.services.values().next().map(|s| (&s.signed.descriptor.feed, s.signed.descriptor.chain)),
                        "response feed or chain changed; restart the RPC client");
                    if let Some(remote) = &remote { remote.update_targets(next.services.values().cloned().collect()).await?; }
                    self.connection(&next)?;
                    broker.update_profile(next);
                    Ok::<_, anyhow::Error>(())
                }.await;
                if let Err(error) = update { eprintln!("discovery refresh: {error}"); }
            }
        });
    }
}

fn default_state() -> Result<PathBuf> {
    Ok(std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .context("set --state-dir")?.join("anymone-rpc-client"))
}

fn validate_url(endpoint: &str) -> Result<()> {
    let url = reqwest::Url::parse(endpoint)?;
    ensure!(matches!(url.scheme(), "http" | "https") && url.host().is_some() && url.username().is_empty()
        && url.password().is_none() && url.query().is_none() && url.fragment().is_none(), "invalid discovery URL");
    Ok(())
}

async fn get<T: serde::de::DeserializeOwned>(client: &reqwest::Client, endpoint: &str, route: &str) -> Result<T> {
    let url = if route.is_empty() { endpoint.to_owned() } else { format!("{}/{route}", endpoint.trim_end_matches('/')) };
    let response = client.get(url).send().await?;
    Ok(serde_json::from_slice(&bounded_response(response, if route.is_empty() { 64 * 1024 } else { 32 * 1024 * 1024 }).await?)?)
}

fn private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    private_write(path, &serde_json::to_vec_pretty(value)?)
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anymone_core::{AnymoneRoundConfiguration, CommitteeMember, GovernanceConfig,
        NoopConfig, ProtocolConfig, ServiceEntry};
    use anymone_eth_service::{FeedDescriptor, ServiceDescriptor, ServiceLimits, VERSION};
    use axum::{routing::get, Json, Router};

    #[test]
    fn interactive_and_automation_pairing_flags_are_exclusive() {
        use clap::Parser;
        let parse = |flags: &[&str]| {
            let mut args = vec!["anymone-rpc-client", "serve", "--bootnode", "https://seed.example"];
            args.extend_from_slice(flags);
            crate::Args::try_parse_from(args)
        };
        let crate::Command::Serve(args) = parse(&["--remote"]).unwrap().command else { panic!() };
        assert_eq!(args.remote.remote.as_deref(), Some("discover"));
        assert!(args.remote.remote_pairing.is_none());
        let crate::Command::Serve(args) = parse(&["--remote", "192.0.2.1:9443"]).unwrap().command else { panic!() };
        assert_eq!(args.remote.remote.as_deref(), Some("192.0.2.1:9443"));
        for flag in ["--remote-pairing", "--pairing"] {
            let crate::Command::Serve(args) = parse(&[flag, "automation.json"]).unwrap().command else { panic!() };
            assert_eq!(args.remote.remote_pairing, Some(PathBuf::from("automation.json")));
            assert!(parse(&["--remote", flag, "automation.json"]).is_err());
        }
        let crate::Command::Serve(args) = parse(&[]).unwrap().command else { panic!() };
        assert!(!args.remote.enabled());
        assert!(crate::Args::try_parse_from(["client", "serve", "--config", "client.json", "--remote"]).is_err());
    }

    #[tokio::test]
    async fn profile_uses_authorized_descriptors_and_signed_feed_urls() {
        let committee = Identity::generate();
        let provider = Identity::generate();
        let genesis = Genesis::new(GovernanceConfig { threshold: 1, committee: vec![CommitteeMember {
            pubkey: committee.pubkey(), exchange_pubkey: committee.exchange_keys(),
        }] });
        let descriptor = ServiceDescriptor { version: VERSION, network: genesis.hash(), chain: 1,
            service_identity: provider.pubkey().0, signing_key: [7; 32], request_key: [4; 32],
            tag: "provider".into(), backend_routes: vec!["execution".into()],
            limits: ServiceLimits { max_request_bytes: 4096, max_response_bytes: 4096, max_batch: 8,
                max_log_blocks: 100, max_lifetime_seconds: 100 },
            feed: FeedDescriptor { feed: [1; 32], genesis_time: now(), epoch_seconds: 10,
                max_epoch_bytes: 16384, retained_epochs: 10 },
            feed_mirrors: vec!["https://feed.example".into()], expires_at: now() + 300 };
        let signed = SignedServiceDescriptor { signature: provider.sign(&descriptor.signing_bytes().unwrap()), descriptor };
        let held = Arc::new(std::sync::RwLock::new(signed));
        let serving = held.clone();
        let app = Router::new().route("/descriptor", get(move || {
            let serving = serving.clone();
            async move { Json(serving.read().unwrap().clone()) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/descriptor", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let tag = ServiceTag::from_label("provider");
        let mut config = AnymoneRoundConfiguration::singleton_subnet(1,
            ProtocolConfig::Noop(NoopConfig { round_duration_ms: 1000, message_size: 256,
                client_set_min: 0, client_set_max: 8 }), vec![], vec![],
            vec![ServiceEntry { tag, pubkey: provider.pubkey() }]);
        config.body.endpoints.services.push((tag, endpoint));
        config = config.sign_with(&[&committee]);
        let mut discovery = Discovery { config: Some(config), endpoint: String::new(), state: PathBuf::new(),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            bootstrap: BootstrapConfig { identity_path: PathBuf::new(), governance: genesis.governance.clone(),
                network: NetworkConfig { listen_addr: None, dialable_addr: None, bootstrappers: vec![],
                    genesis_peers: vec![], stream_listen: None, stream_bootstrappers: vec![], local: false },
                committee: Default::default(), tee: Default::default() }, genesis };
        let listen = "127.0.0.1:8546".parse().unwrap();
        let profile = discovery.profile(listen, "unused".into()).await.unwrap();
        assert_eq!(profile.feed_mirrors, vec!["https://feed.example"]);
        held.write().unwrap().descriptor.feed_mirrors = vec!["https://forged.example".into()];
        assert!(discovery.profile(listen, "unused".into()).await.is_err());
        {
            let mut signed = held.write().unwrap();
            signed.signature = provider.sign(&signed.descriptor.signing_bytes().unwrap());
        }
        assert_eq!(discovery.profile(listen, "unused".into()).await.unwrap().feed_mirrors,
            vec!["https://forged.example"]);
        discovery.config.as_mut().unwrap().body.services.clear();
        assert!(discovery.profile(listen, "unused".into()).await.is_err());
        server.abort();
    }
}
