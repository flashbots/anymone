use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use anymone_core::{Anymone, BootstrapConfig, GovernanceBootstrap, Identity, ProtocolAction};
use anymone_remote_session::{HostConfig, PairingInfo, RemoteSessionClient, RemoteSessionHost};
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    ExportConfig {
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        subnet: u32,
    },
    Discover {
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u64).range(1..=60))]
        seconds: u64,
        /// Resolve a discovered Bonjour instance on macOS.
        #[arg(long)]
        instance: Option<String>,
    },
    Host {
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
    },
    Drive {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        pairing: PathBuf,
        /// Discovered endpoint; the pairing certificate remains pinned.
        #[arg(long)]
        address: Option<SocketAddr>,
        #[arg(long)]
        actions: PathBuf,
        #[arg(long)]
        reconnect_between_actions: bool,
    },
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    Ok(serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::ExportConfig { bootstrap, subnet } => {
            let bootstrap = BootstrapConfig::load(&bootstrap)?;
            let identity = Identity::load_or_generate(&bootstrap.identity_path)?;
            let gov = GovernanceBootstrap::from_bootstrap_config(&bootstrap);
            let (transport, _) =
                anymone_core::backend::start_client_transport(&identity, &bootstrap, gov.clone())?;
            let node = Anymone::start(identity, transport, gov)
                .await
                .map_err(anyhow::Error::msg)?;
            let config = node.configuration();
            let subnet = config
                .body
                .subnets
                .iter()
                .find(|s| s.id == subnet)
                .context("subnet not present in adopted configuration")?
                .clone();
            anyhow::ensure!(!subnet.attested, "developer hosts require an open subnet");
            let starting_round = anymone_core::config::now_unix_ms()
                .saturating_sub(config.body.epoch_unix_ms)
                / subnet.protocol.round_duration().as_millis().max(1) as u64;
            let config = HostConfig {
                subnet,
                relay_exchange_keys: config.body.relay_exchange_keys,
                starting_round,
            };
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::Discover { seconds, instance } => {
            let mut command = if cfg!(target_os = "macos") {
                let mut command = tokio::process::Command::new("dns-sd");
                if let Some(instance) = instance {
                    command.args(["-L", &instance, "_anymone-remote._tcp", "local."]);
                } else {
                    command.args(["-B", "_anymone-remote._tcp", "local."]);
                }
                command
            } else {
                anyhow::ensure!(
                    instance.is_none(),
                    "--instance is only needed for macOS resolution"
                );
                let mut command = tokio::process::Command::new("avahi-browse");
                command.args(["-rp", "_anymone-remote._tcp"]);
                command
            };
            let mut child = command
                .kill_on_drop(true)
                .spawn()
                .context("install avahi-utils on Linux, or use the macOS dns-sd utility")?;
            match tokio::time::timeout(std::time::Duration::from_secs(seconds), child.wait()).await
            {
                Ok(result) => anyhow::ensure!(result?.success(), "discovery utility failed"),
                Err(_) => {
                    child.kill().await?;
                }
            }
        }
        Command::Host { listen } => {
            let handle = RemoteSessionHost::new(None)?.listen(listen).await?;
            println!("{}", serde_json::to_string(&handle.pairing)?);
            tokio::signal::ctrl_c().await?;
        }
        Command::Drive {
            config,
            pairing,
            address,
            actions,
            reconnect_between_actions,
        } => {
            let mut pairing: PairingInfo = read_json(&pairing)?;
            if let Some(address) = address {
                pairing.address = address.to_string();
            }
            let actions: Vec<ProtocolAction> = read_json(&actions)?;
            let (mut client, status) = RemoteSessionClient::pair(pairing).await?;
            eprintln!("{}", serde_json::to_string(&status)?);
            let (status, returned) = client.configure(read_json(&config)?).await?;
            anyhow::ensure!(returned.is_empty(), "configuration returned unsent payloads; use the service backend to requeue them");
            eprintln!("{}", serde_json::to_string(&status)?);
            for action in actions {
                if reconnect_between_actions {
                    client.reconnect().await?;
                }
                let messages = match action {
                    ProtocolAction::Panetiere(action) => client.panetiere(action).await?,
                    ProtocolAction::ScheduledPanetiere(action) => {
                        client.scheduled_panetiere(action).await?
                    }
                    ProtocolAction::Adcnet(anymone_core::AdcnetAction::Contribute {
                        round,
                        payload,
                    }) => vec![client.adcnet_contribute(round, payload).await?],
                    ProtocolAction::ScheduledAdcnet(action) => {
                        client.scheduled_adcnet(action).await?
                    }
                };
                println!(
                    "{}",
                    serde_json::to_string(&messages.iter().map(hex::encode).collect::<Vec<_>>())?
                );
            }
            client.close().await?;
        }
    }
    Ok(())
}
