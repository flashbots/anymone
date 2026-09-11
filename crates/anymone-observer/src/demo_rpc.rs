use std::{fs::{File, OpenOptions}, io::Write, net::TcpListener, path::Path,
    process::{Child, Command, Stdio}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

use anyhow::{bail, ensure, Context, Result};
use anymone_core::{discovery::NetworkInfo, BootstrapConfig, Identity, ServiceTag};
use rand::RngCore;
use serde_json::{json, Value};

const EXECUTION_METHODS: &str = "eth_chainId net_version eth_blockNumber eth_syncing eth_getBalance
eth_getTransactionCount eth_getCode eth_getStorageAt eth_getProof eth_call eth_estimateGas
eth_gasPrice eth_maxPriorityFeePerGas eth_feeHistory eth_getBlockByHash eth_getBlockByNumber
eth_getBlockTransactionCountByHash eth_getBlockTransactionCountByNumber eth_getTransactionByHash
eth_getTransactionByBlockHashAndIndex eth_getTransactionByBlockNumberAndIndex
eth_getTransactionReceipt eth_getBlockReceipts eth_getLogs eth_createAccessList eth_sendRawTransaction";
const BUNDLER_METHODS: &str = "eth_chainId eth_supportedEntryPoints eth_estimateUserOperationGas
eth_getUserOperationByHash eth_getUserOperationReceipt pimlico_getUserOperationGasPrice
pimlico_getUserOperationStatus pm_getPaymasterStubData pm_getPaymasterData
pm_sponsorUserOperation eth_sendUserOperation";

pub struct RpcDemo {
    children: Vec<(String, Child)>,
    client: reqwest::Client,
}

impl RpcDemo {
    pub async fn start(output: &Path, upstream: &str, bundler: Option<&str>, pairing: Option<&Path>) -> Result<Self> {
        let bin = std::env::current_exe()?.parent().context("binary directory")?.to_owned();
        for name in ["anymone-eth-service", "anymone-rpc-client"].into_iter()
            .chain(pairing.is_none().then_some("anymone-remote-session")) {
            ensure!(bin.join(name).is_file(), "build {name} alongside anymone-observer first");
        }
        if let Some(pairing) = pairing { ensure!(pairing.is_file(), "pairing export does not exist"); }
        let mut demo = Self {
            children: Vec::new(),
            client: reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).build()?,
        };
        let chain = demo.chain(upstream).await?;
        if let Some(bundler) = bundler {
            ensure!(demo.chain(bundler).await? == chain, "bundler and execution chains differ");
        }
        let sockets = (0..3).map(|_| TcpListener::bind("127.0.0.1:0"))
            .collect::<std::io::Result<Vec<_>>>()?;
        let addresses = sockets.iter().map(TcpListener::local_addr).collect::<std::io::Result<Vec<_>>>()?;
        let service_url = format!("http://{}", addresses[0]);
        let board_url = format!("http://{}", addresses[1]);
        let client_url = format!("http://{}", addresses[2]);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let feed = json!({"feed": random_key(), "genesis_time": now,
            "epoch_seconds": 5, "max_epoch_bytes": 1048576, "retained_epochs": 24});
        let bootstrap = BootstrapConfig::load(&output.join("client.toml"))?;
        Identity::load_or_generate(&bootstrap.identity_path)?;
        for name in ["signing.key", "request.key", "writer.token"] {
            private_file(&output.join(name))?.write_all(hex::encode(random_key()).as_bytes())?;
        }
        let mut routes = json!({"execution": {"endpoint": upstream,
            "methods": EXECUTION_METHODS.split_whitespace().collect::<Vec<_>>()}});
        if let Some(bundler) = bundler {
            routes["bundler"] = json!({"endpoint": bundler,
                "methods": BUNDLER_METHODS.split_whitespace().collect::<Vec<_>>()});
        }
        let descriptor = format!("{service_url}/descriptor");
        write_json(&output.join("service.json"), &json!({
            "bootstrap": output.join("client.toml"), "chain": chain, "tag": "ethereum",
            "limits": {"max_request_bytes": 65536, "max_response_bytes": 65536, "max_batch": 32,
                "max_log_blocks": 499, "max_lifetime_seconds": 180},
            "feed": feed, "expires_at": now + 86400, "signing_key": output.join("signing.key"),
            "request_key": output.join("request.key"), "database": output.join("service.sqlite"),
            "routes": routes, "listen": addresses[0], "board_endpoint": board_url,
            "board_token": output.join("writer.token"), "feed_mirrors": [board_url],
            "descriptor_url": descriptor,
        }))?;
        write_json(&output.join("board.json"), &json!({
            "feed": feed, "database": output.join("board.sqlite"), "listen": addresses[1],
            "writers": {"ethereum": {"token": output.join("writer.token"), "quota_bytes": 1048064}},
        }))?;
        drop(sockets);
        for role in ["board", "service"] {
            let mut command = Command::new(bin.join("anymone-eth-service"));
            command.arg(role).arg("--config").arg(output.join(format!("{role}.json")));
            demo.spawn(command, role, output, None)?;
        }
        let pinned = std::fs::read_to_string(output.join("discovery-url.txt"))?;
        let discovery = pinned.trim().split('#').next().context("discovery URL")?;
        let ready = Instant::now();
        loop {
            demo.check()?;
            if let Ok(response) = demo.client.get(format!("{discovery}/network")).send().await {
                if let Ok(info) = response.json::<NetworkInfo>().await {
                    if info.genesis.verify_config(&info.config).is_ok()
                        && info.config.body.endpoints.services.iter()
                            .any(|(tag, url)| *tag == ServiceTag::from_label("ethereum") && url == &descriptor) {
                        break;
                    }
                }
            }
            ensure!(ready.elapsed() < Duration::from_secs(180), "Ethereum service did not enter discovery; see service.log");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        demo.wait_http(&format!("{board_url}/feed"), None).await?;
        demo.wait_http(&descriptor, None).await?;
        let pairing = if let Some(pairing) = pairing {
            std::fs::canonicalize(pairing)?
        } else {
            let pairing = output.join("pairing.json");
            let mut command = Command::new(bin.join("anymone-remote-session"));
            command.args(["host", "--listen", "127.0.0.1:0"]);
            demo.spawn(command, "session", output, Some(private_file(&pairing)?))?;
            demo.wait_json(&pairing).await?;
            println!("Using a software developer session with ordinary signing keys (no hardware attestation).");
            pairing
        };
        let state = output.join("rpc-client");
        let mut command = Command::new(bin.join("anymone-rpc-client"));
        command.arg("serve").arg("--node-rpc").arg(pinned.trim())
            .arg("--pairing").arg(pairing).arg("--state-dir").arg(&state)
            .arg("--listen").arg(addresses[2].to_string());
        demo.spawn(command, "rpc-client", output, None)?;
        demo.wait_json(&state.join("connection.json")).await?;
        let token = std::fs::read_to_string(state.join("token"))?;
        demo.wait_http(&format!("{client_url}/status"), Some(token.trim())).await?;
        println!("RPC demo ready on chain {chain}; Kohaku connection: {}", state.join("connection.json").display());
        println!("Service logs: {}", output.display());
        Ok(demo)
    }

    async fn chain(&self, endpoint: &str) -> Result<u64> {
        let result = async {
            let value: Value = self.client.post(endpoint)
                .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}))
                .send().await?.error_for_status()?.json().await?;
            ensure!(value["jsonrpc"] == "2.0" && value["id"] == 1 && value.get("error").is_none(), "invalid response");
            let chain = value["result"].as_str().and_then(|s| s.strip_prefix("0x"))
                .context("missing chain ID")?;
            Ok::<_, anyhow::Error>(u64::from_str_radix(chain, 16)?)
        }.await;
        result.map_err(|_| anyhow::anyhow!("upstream eth_chainId failed; check the RPC URL"))
    }

    fn spawn(&mut self, mut command: Command, name: &str, output: &Path, stdout: Option<File>) -> Result<()> {
        let log = private_file(&output.join(format!("{name}.log")))?;
        command.env("RAYON_NUM_THREADS", "8").stdin(Stdio::null())
            .stdout(stdout.unwrap_or(log.try_clone()?)).stderr(log);
        self.children.push((name.to_owned(), command.spawn().with_context(|| format!("start {name}"))?));
        Ok(())
    }

    fn check(&mut self) -> Result<()> {
        for (name, child) in &mut self.children {
            if let Some(status) = child.try_wait()? { bail!("{name} exited ({status}); see {name}.log"); }
        }
        Ok(())
    }

    async fn wait_http(&mut self, url: &str, token: Option<&str>) -> Result<()> {
        let start = Instant::now();
        loop {
            self.check()?;
            let mut request = self.client.get(url);
            if let Some(token) = token { request = request.bearer_auth(token); }
            if request.send().await.is_ok_and(|r| r.status().is_success()) { return Ok(()); }
            ensure!(start.elapsed() < Duration::from_secs(180), "demo endpoint did not start: {url}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn wait_json(&mut self, path: &Path) -> Result<()> {
        let start = Instant::now();
        loop {
            self.check()?;
            if std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()).is_some() {
                return Ok(());
            }
            ensure!(start.elapsed() < Duration::from_secs(180), "demo file was not produced: {}", path.display());
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn supervise(&mut self) -> Result<()> {
        loop {
            self.check()?;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

impl Drop for RpcDemo {
    fn drop(&mut self) {
        for (_, child) in self.children.iter_mut().rev() { let _ = child.kill(); }
        for (_, child) in self.children.iter_mut().rev() { let _ = child.wait(); }
    }
}

fn random_key() -> [u8; 32] {
    let mut key = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    serde_json::to_writer_pretty(private_file(path)?, value)?;
    Ok(())
}
