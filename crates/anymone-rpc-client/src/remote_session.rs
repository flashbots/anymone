use std::{collections::BTreeMap, sync::Arc, sync::RwLock, time::Duration};
use anyhow::{ensure, Context, Result};
use anymone_core::{Anymone, BootstrapConfig, GovernanceBootstrap, Identity, PipeSender, ServiceTag};
use anymone_remote_session::{desktop::RemoteArgs, RemoteClientBackend};
use serde_json::{json, Value};

use crate::{broker::Upload, RemoteSessionConfig, ServiceTarget};

struct Participant {
    node: Arc<Anymone>,
    remote: Arc<RemoteClientBackend>,
    pipes: BTreeMap<String, PipeSender>,
}

pub struct RemoteSession {
    config: RemoteSessionConfig,
    targets: RwLock<Vec<ServiceTarget>>,
    participant: RwLock<Option<Participant>>,
    connecting: tokio::sync::Mutex<()>,
}

impl RemoteSessionConfig {
    fn pairing_args(&self) -> Result<RemoteArgs> {
        ensure!(self.remote.is_none() || self.pairing.is_none(), "choose code pairing or an automation pairing file");
        Ok(RemoteArgs {
            remote: self.remote.clone().or_else(|| self.pairing.is_none().then(|| "discover".into())),
            remote_pairing: self.pairing.clone(),
        })
    }
}

impl RemoteSession {
    pub fn new(config: RemoteSessionConfig, targets: Vec<ServiceTarget>) -> Result<Arc<Self>> {
        config.pairing_args()?;
        Ok(Arc::new(Self { config, targets: RwLock::new(targets), participant: RwLock::new(None),
            connecting: tokio::sync::Mutex::new(()) }))
    }

    pub async fn connect(&self) -> Result<()> {
        let _connecting = self.connecting.lock().await;
        if self.participant.read().map_err(|_| anyhow::anyhow!("session lock poisoned"))?.is_some() { return Ok(()); }
        let remote = self.config.pairing_args()?.connect().await?.context("remote pairing is disabled")?;
        let result = self.start(remote.clone()).await;
        match result {
            Ok(participant) => {
                *self.participant.write().map_err(|_| anyhow::anyhow!("session lock poisoned"))? = Some(participant);
                tracing::info!("remote protocol session started");
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "remote protocol session failed to start");
                let _ = remote.close().await;
                Err(error)
            }
        }
    }

    async fn start(&self, remote: Arc<RemoteClientBackend>) -> Result<Participant> {
        let bootstrap = BootstrapConfig::load(&self.config.bootstrap)?;
        let identity = Identity::load(&bootstrap.identity_path)?;
        let governance = GovernanceBootstrap::from_bootstrap_config(&bootstrap);
        let (transport, _spawn) = anymone_core::backend::start_client_transport(&identity, &bootstrap, governance.clone())?;
        let node = tokio::time::timeout(Duration::from_secs(30), Anymone::start(identity, transport, governance)).await??;
        remote.install(&node).map_err(anyhow::Error::msg)?;
        let targets = self.targets.read().map_err(|_| anyhow::anyhow!("targets lock poisoned"))?.clone();
        let pipes = Self::open_pipes(&node, &targets).await?;
        Ok(Participant { node: Arc::new(node), remote, pipes })
    }

    async fn open_pipes(node: &Anymone, targets: &[ServiceTarget]) -> Result<BTreeMap<String, PipeSender>> {
        let mut pipes = BTreeMap::new();
        for target in targets {
            let descriptor = &target.signed.descriptor;
            let tag = ServiceTag::from_label(&descriptor.tag);
            ensure!(node.configuration().body.services.iter().any(|s| s.tag == tag && s.pubkey.0 == target.service_identity),
                "service identity does not match signed Anymone placement");
            let (sender, _receiver) = node.open(tag).await?.split();
            pipes.insert(descriptor.tag.clone(), sender);
        }
        Ok(pipes)
    }

    pub async fn update_targets(&self, targets: Vec<ServiceTarget>) -> Result<()> {
        let _connecting = self.connecting.lock().await;
        let active = self.participant.read().map_err(|_| anyhow::anyhow!("session lock poisoned"))?
            .as_ref().map(|participant| (participant.node.clone(), participant.pipes.clone()));
        if let Some((node, mut pipes)) = active {
            let missing: Vec<_> = targets.iter().filter(|target| !pipes.contains_key(&target.signed.descriptor.tag)).cloned().collect();
            pipes.extend(Self::open_pipes(&node, &missing).await?);
            if let Some(participant) = self.participant.write().map_err(|_| anyhow::anyhow!("session lock poisoned"))?.as_mut() {
                participant.pipes = pipes;
            }
        }
        *self.targets.write().map_err(|_| anyhow::anyhow!("targets lock poisoned"))? = targets;
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        let _connecting = self.connecting.lock().await;
        let participant = self.participant.write().map_err(|_| anyhow::anyhow!("session lock poisoned"))?.take();
        if let Some(participant) = participant { participant.remote.close().await?; }
        tracing::info!("remote protocol session stopped");
        Ok(())
    }

    pub fn status(&self) -> Result<Value> {
        let participant = self.participant.read().map_err(|_| anyhow::anyhow!("session lock poisoned"))?;
        let error = participant.as_ref().and_then(|participant| participant.remote.last_error());
        Ok(json!({"connected":participant.is_some() && error.is_none(),
            "configured":participant.as_ref().is_some_and(|p| p.remote.context().is_some()),
            "error":error}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_defaults_to_code_pairing_and_accepts_explicit_automation() {
        let mut config: RemoteSessionConfig = serde_json::from_value(json!({"bootstrap":"bootstrap.toml"})).unwrap();
        let args = config.pairing_args().unwrap();
        assert_eq!(args.remote.as_deref(), Some("discover"));
        assert!(args.remote_pairing.is_none());
        config.pairing = Some("automation.json".into());
        let args = config.pairing_args().unwrap();
        assert!(args.remote.is_none());
        assert_eq!(args.remote_pairing, config.pairing);
        config.remote = Some("discover".into());
        assert!(RemoteSession::new(config, vec![]).is_err());
    }
}

impl Upload for RemoteSession {
    fn capacity(&self) -> Result<usize> {
        let participant = self.participant.read().map_err(|_| anyhow::anyhow!("session lock poisoned"))?;
        Ok(participant.as_ref().ok_or_else(|| anyhow::anyhow!("upload session disconnected"))?.node.max_payload())
    }

    fn send(&self, tag: &str, fragments: Vec<Vec<u8>>) -> Result<()> {
        let participant = self.participant.read().map_err(|_| anyhow::anyhow!("session lock poisoned"))?;
        let participant = participant.as_ref().ok_or_else(|| anyhow::anyhow!("upload session disconnected"))?;
        let targets = self.targets.read().map_err(|_| anyhow::anyhow!("targets lock poisoned"))?;
        let target = targets.iter().find(|target| target.signed.descriptor.tag == tag)
            .ok_or_else(|| anyhow::anyhow!("service no longer discovered"))?;
        ensure!(participant.node.configuration().body.services.iter().any(|service|
            service.tag == ServiceTag::from_label(tag) && service.pubkey.0 == target.service_identity),
            "service identity no longer authorized");
        let pipe = participant.pipes.get(tag).ok_or_else(|| anyhow::anyhow!("upload pipe missing"))?;
        for fragment in fragments { pipe.send_unlinkable(fragment)?; }
        Ok(())
    }
}
