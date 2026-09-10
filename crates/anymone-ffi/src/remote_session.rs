use std::sync::{Arc, Mutex};

use anymone_remote_session::{ RemoteSessionHost, RemoteSessionHostHandle};

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
        listen_address: String,
    ) -> Result<Arc<Self>, RemoteHostError> {
        let address = listen_address
            .parse::<std::net::SocketAddr>()
            .map_err(failed)?;
        if address.ip().is_unspecified() {
            return Err(failed("select a reachable interface address"));
        }
        crate::on_runtime(async move {
            let handle = RemoteSessionHost::new(None)
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

    pub fn pairing_code(&self) -> Result<String, RemoteHostError> {
        let handle = self.handle.lock().unwrap();
        Ok(handle.as_ref().ok_or_else(|| failed("host is stopped"))?.pairing_code.to_string())
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
