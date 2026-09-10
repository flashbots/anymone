use std::sync::{Arc, Mutex};

use anymone_remote_session::{HostConfig, RemoteSessionHost, RemoteSessionHostHandle};

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum RemoteHostError {
    #[error("{0}")]
    Failed(String),
}

fn failed(error: impl std::fmt::Display) -> RemoteHostError {
    RemoteHostError::Failed(error.to_string())
}

#[derive(uniffi::Object)]
pub struct RemoteProtocolHost {
    handle: Mutex<Option<RemoteSessionHostHandle>>,
    pairing: String,
}

#[uniffi::export]
impl RemoteProtocolHost {
    #[uniffi::constructor]
    pub async fn start_developer(
        config_json: String,
        listen_address: String,
    ) -> Result<Arc<Self>, RemoteHostError> {
        if config_json.len() > 1024 * 1024 {
            return Err(failed("host configuration exceeds 1 MiB"));
        }
        let config: HostConfig = serde_json::from_str(&config_json).map_err(failed)?;
        let address = listen_address
            .parse::<std::net::SocketAddr>()
            .map_err(failed)?;
        if address.ip().is_unspecified() {
            return Err(failed("select a reachable interface address"));
        }
        crate::on_runtime(async move {
            let session = tokio::task::spawn_blocking(move || config.developer_session())
                .await
                .map_err(failed)?
                .map_err(failed)?;
            let handle = RemoteSessionHost::new(session)
                .map_err(failed)?
                .listen(address)
                .await
                .map_err(failed)?;
            let pairing = serde_json::to_string(&handle.pairing).map_err(failed)?;
            Ok(Arc::new(Self {
                handle: Mutex::new(Some(handle)),
                pairing,
            }))
        })
        .await
    }

    pub fn pairing_json(&self) -> Result<String, RemoteHostError> {
        if self.handle.lock().unwrap().is_none() {
            return Err(failed("host is stopped"));
        }
        Ok(self.pairing.clone())
    }

    pub async fn status_json(&self) -> Result<String, RemoteHostError> {
        let session = self
            .handle
            .lock()
            .unwrap()
            .as_ref()
            .ok_or_else(|| failed("host is stopped"))?
            .session();
        crate::on_runtime(async move {
            let status = session.lock().await.status();
            serde_json::to_string(&status).map_err(failed)
        })
        .await
    }

    pub async fn stop(&self) {
        let handle = self.handle.lock().unwrap().take();
        if let Some(handle) = handle {
            crate::on_runtime(handle.shutdown()).await;
        }
    }
}
