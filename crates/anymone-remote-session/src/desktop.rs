use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::{HostStatus, RemoteClientBackend, RemoteSessionClient};

pub const SERVICE_TYPE: &str = "_anymone-remote._tcp.local.";

#[derive(clap::Args, Debug)]
pub struct RemoteArgs {
    /// Discover a phone and enter its code, or connect directly to IP:PORT.
    #[arg(long, num_args = 0..=1, default_missing_value = "discover", value_name = "IP:PORT", conflicts_with = "remote_pairing")]
    pub remote: Option<String>,

    /// Pairing JSON for automated tests.
    #[arg(long, alias = "pairing")]
    pub remote_pairing: Option<PathBuf>,
}

impl RemoteArgs {
    pub fn enabled(&self) -> bool {
        self.remote.is_some() || self.remote_pairing.is_some()
    }

    pub async fn pair_client(&self) -> Result<(RemoteSessionClient, HostStatus)> {
        if let Some(path) = &self.remote_pairing {
            let bytes = std::fs::read(path).with_context(|| format!("reading pairing file {}", path.display()))?;
            let pairing = serde_json::from_slice(&bytes).with_context(|| format!("parsing pairing file {}", path.display()))?;
            return RemoteSessionClient::pair(pairing).await.context("pairing with remote host");
        }
        let endpoint = self.remote.clone().unwrap_or_else(|| "discover".into());
        let (address, code) = tokio::task::spawn_blocking(move || -> Result<_> {
            anyhow::ensure!(std::io::stdin().is_terminal(), "code pairing needs an interactive terminal; use --remote-pairing FILE for automation");
            let address = if endpoint == "discover" {
                eprintln!("Looking for phones on the local network…");
                let hosts = discover(Duration::from_secs(5))?;
                anyhow::ensure!(!hosts.is_empty(), "no phones found; start Remote on the phone, allow Local Network access, or use --remote IP:PORT");
                for (index, host) in hosts.iter().enumerate() {
                    eprintln!("  {}. {} ({})", index + 1, host.name.escape_debug(), host.address);
                }
                loop {
                    let choice = prompt("Select phone [1]: ")?;
                    let number = if choice.is_empty() { Some(1) } else { choice.parse::<usize>().ok() };
                    if let Some(host) = number.and_then(|n| n.checked_sub(1)).and_then(|n| hosts.get(n)) {
                        break host.address.to_string();
                    }
                    eprintln!("Enter a number from 1 to {}.", hosts.len());
                }
            } else {
                endpoint.parse::<SocketAddr>().context("remote address must be IP:PORT")?.to_string()
            };
            let code = zeroize::Zeroizing::new(prompt("Pairing code shown on the phone: ")?);
            Ok((address, code))
        }).await??;
        let paired = RemoteSessionClient::pair_with_code(&address, &code).await
            .context("code pairing failed; check the code, or restart Remote if its code is unavailable")?;
        eprintln!("Connected to phone at {address}.");
        Ok(paired)
    }

    pub async fn connect(&self) -> Result<Option<Arc<RemoteClientBackend>>> {
        if !self.enabled() { return Ok(None); }
        let (client, host) = self.pair_client().await?;
        Ok(Some(RemoteClientBackend::from_client(client, host)?))
    }
}

fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    anyhow::ensure!(std::io::stdin().read_line(&mut line)? > 0, "pairing cancelled: terminal input closed");
    Ok(line.trim().to_string())
}

#[derive(Debug)]
pub struct DiscoveredHost {
    pub name: String,
    pub address: SocketAddr,
}

struct Discovery(ServiceDaemon);

impl Drop for Discovery {
    fn drop(&mut self) { let _ = self.0.shutdown(); }
}

pub fn discover(duration: Duration) -> Result<Vec<DiscoveredHost>> {
    let daemon = Discovery(ServiceDaemon::new().context("starting mDNS discovery")?);
    let receiver = daemon.0.browse(SERVICE_TYPE).context("browsing remote hosts")?;
    let deadline = Instant::now() + duration;
    let mut hosts = BTreeMap::new();
    let version = crate::INTERFACE_VERSION.to_string();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        let Ok(event) = receiver.recv_timeout(left) else { break };
        match event {
            ServiceEvent::ServiceResolved(info) => {
                if info.get_property_val_str("version") != Some(version.as_str())
                    || info.get_property_val_str("pairing") != Some("code") { continue; }
                if hosts.len() >= 64 { continue; }
                if let Some(ip) = info.get_addresses_v4().into_iter().min() {
                    let name = info.get_fullname().trim_end_matches(SERVICE_TYPE).trim_end_matches('.').to_string();
                    hosts.insert(info.get_fullname().to_string(), DiscoveredHost {
                        name, address: SocketAddr::new(ip.into(), info.get_port()),
                    });
                }
            }
            ServiceEvent::ServiceRemoved(_, name) => { hosts.remove(&name); }
            _ => {}
        }
    }
    Ok(hosts.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires local IPv4 multicast networking"]
    async fn discovers_and_pairs_advertised_host() {
        let host = crate::RemoteSessionHost::new(None).unwrap()
            .listen("0.0.0.0:0".parse().unwrap()).await.unwrap();
        let port = host.pairing.address.parse::<SocketAddr>().unwrap().port();
        let name = format!("Anymone-test-{}", rand::random::<u32>());
        let daemon = Discovery(ServiceDaemon::new().unwrap());
        let info = mdns_sd::ServiceInfo::new(
            SERVICE_TYPE, &name, &format!("{name}.local."), "", port,
            [("version", "0"), ("pairing", "code")].as_slice(),
        ).unwrap().enable_addr_auto();
        daemon.0.register(info).unwrap();
        let hosts = tokio::task::spawn_blocking(|| discover(Duration::from_secs(5))).await.unwrap().unwrap();
        let discovered = hosts.iter().find(|found| found.name == name).expect("advertised host discovered");
        let (mut client, status) = RemoteSessionClient::pair_with_code(&discovered.address.to_string(), &host.pairing_code).await.unwrap();
        assert!(status.paired);
        client.close().await.unwrap();
        host.shutdown().await;
    }
}
