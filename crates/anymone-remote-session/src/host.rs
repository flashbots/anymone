use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use anymone_core::{RemoteAttestedSession, RemoteSessionError};

use crate::wire::{CommandResult, HostStatus, PairRequest, PairingInfo, SessionCommand, SessionInput, SessionReply};
use crate::{RemoteTransportError, MAX_FRAME_BYTES};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

pub struct HostState {
    client: Option<RemoteAttestedSession>,
    session_id: [u8; 32],
    next_request: u64,
    last_reply: Option<([u8; 32], Result<CommandResult, RemoteSessionError>)>,
    closed: bool,
}

impl HostState {
    pub fn status(&self) -> HostStatus {
        HostStatus {
            session_id: self.session_id,
            next_request: self.next_request,
            closed: self.closed,
            client: self.client.as_ref().map(RemoteAttestedSession::status),
        }
    }

    fn close(&mut self) {
        if let Some(client) = &mut self.client { client.close(); }
        self.last_reply = None;
        self.closed = true;
    }

    fn execute(&mut self, sequence: u64, command: SessionCommand) -> Result<CommandResult, RemoteSessionError> {
        if self.closed { return Err(RemoteSessionError::Closed); }
        let bytes = bincode::serialize(&command).map_err(|e| RemoteSessionError::Protocol(e.to_string()))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if sequence.checked_add(1) == Some(self.next_request) {
            if let Some((previous, result)) = &self.last_reply {
                return if *previous == digest { result.clone() } else { Err(RemoteSessionError::RequestConflict) };
            }
        }
        if sequence != self.next_request {
            return Err(RemoteSessionError::RequestSequence { expected: self.next_request });
        }
        self.next_request = sequence.checked_add(1).ok_or(RemoteSessionError::SequenceExhausted)?;
        let result = self.apply(command, bytes.len());
        self.last_reply = Some((digest, result.clone()));
        result
    }

    fn apply(&mut self, command: SessionCommand, size: usize) -> Result<CommandResult, RemoteSessionError> {
        match command {
            SessionCommand::Configure(config) => {
                if size > 1024 * 1024 { return Err(RemoteSessionError::InvalidConfig); }
                let returned_payloads = if let Some(client) = &mut self.client {
                    client.reconfigure(&config.subnet, &config.relay_exchange_keys, config.starting_round)?
                } else {
                    self.client = Some(config.developer_session()?);
                    Vec::new()
                };
                Ok(CommandResult::Configured {
                    status: self.client.as_ref().unwrap().status(),
                    returned_payloads,
                })
            }
            SessionCommand::Action(action) => {
                let client = self.client.as_mut().ok_or_else(|| RemoteSessionError::Protocol("configure the client first".into()))?;
                client.apply(action).map(CommandResult::Messages)
            }
        }
    }
}

pub struct RemoteSessionHost {
    session: Arc<Mutex<HostState>>,
    pairing_token: [u8; 32],
    controller: Arc<Mutex<Option<[u8; 32]>>>,
    tls: Arc<rustls::ServerConfig>,
    certificate_der: Vec<u8>,
}

pub struct RemoteSessionHostHandle {
    pub pairing: PairingInfo,
    session: Arc<Mutex<HostState>>,
    task: tokio::task::JoinHandle<()>,
}

impl RemoteSessionHostHandle {
    pub fn session(&self) -> Arc<Mutex<HostState>> {
        self.session.clone()
    }

    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
        self.session.lock().await.close();
    }
}

impl Drop for RemoteSessionHostHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RemoteSessionHost {
    pub fn new(session: impl Into<Option<RemoteAttestedSession>>) -> Result<Self, RemoteTransportError> {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["anymone.local".to_string()])?;
        let certificate = cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key.into())?;
        let mut pairing_token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut pairing_token);
        Ok(Self {
            session: Arc::new(Mutex::new(HostState {
                client: session.into(),
                session_id: rand::random(),
                next_request: 0,
                last_reply: None,
                closed: false,
            })),
            pairing_token,
            controller: Arc::new(Mutex::new(None)),
            tls: Arc::new(tls),
            certificate_der: certificate.as_ref().to_vec(),
        })
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<RemoteSessionHostHandle, RemoteTransportError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let pairing = PairingInfo {
            interface_version: crate::INTERFACE_VERSION,
            address: address.to_string(),
            certificate_der: self.certificate_der.clone(),
            certificate_sha256: Sha256::digest(&self.certificate_der).into(),
            pairing_token: self.pairing_token,
        };
        let session = self.session.clone();
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(self.tls.clone());
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    accepted = listener.accept() => {
                        let Ok((tcp, _)) = accepted else { break };
                        if tcp.set_nodelay(true).is_err() { continue; }
                        if connections.len() >= 8 { continue; }
                        let acceptor = acceptor.clone();
                        let session = self.session.clone();
                        let controller = self.controller.clone();
                        let token = self.pairing_token;
                        connections.spawn(async move {
                            if let Ok(Ok(mut tls)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                                let _ = serve_connection(&mut tls, session, controller, token).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(RemoteSessionHostHandle {
            pairing,
            session,
            task,
        })
    }
}

async fn serve_connection<S>(
    stream: &mut S,
    session: Arc<Mutex<HostState>>,
    controller: Arc<Mutex<Option<[u8; 32]>>>,
    pairing_token: [u8; 32],
) -> Result<(), RemoteTransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first: SessionInput = timeout(HANDSHAKE_TIMEOUT, read_frame(stream))
        .await
        .map_err(|_| RemoteTransportError::Timeout)??;
    let accepted = {
        let mut held = controller.lock().await;
        match first {
            SessionInput::Pair(PairRequest::First {
                token,
                controller_secret,
            }) if token == pairing_token && held.is_none_or(|saved| saved == controller_secret) => {
                *held = Some(controller_secret);
                true
            }
            SessionInput::Pair(PairRequest::Resume { controller_secret }) => {
                *held == Some(controller_secret)
            }
            _ => false,
        }
    };
    if !accepted {
        write_frame(stream, &SessionReply::Error("pairing failed".into())).await?;
        return Err(RemoteTransportError::PairingFailed);
    }
    let status = session.lock().await.status();
    write_frame(stream, &SessionReply::Paired(status)).await?;
    loop {
        let input = match read_frame::<_, SessionInput>(stream).await {
            Ok(input) => input,
            Err(RemoteTransportError::Io(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        let session = session.clone();
        let reply = tokio::task::spawn_blocking(move || {
            let mut held = session.blocking_lock();
            match input {
                SessionInput::Pair(_) => SessionReply::Error("connection is already paired".into()),
                SessionInput::Request { sequence, command } => SessionReply::Executed {
                    sequence,
                    result: held.execute(sequence, command),
                },
                SessionInput::Status => SessionReply::Status(held.status()),
                SessionInput::Close => {
                    held.close();
                    SessionReply::Closed
                }
            }
        })
        .await
        .map_err(|e| RemoteTransportError::Rejected(e.to_string()))?;
        write_frame(stream, &reply).await?;
    }
}

pub(crate) async fn write_frame<S, T>(stream: &mut S, value: &T) -> Result<(), RemoteTransportError>
where
    S: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let bytes =
        bincode::serialize(value).map_err(|e| RemoteTransportError::Encode(e.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(RemoteTransportError::FrameTooLarge(bytes.len()));
    }
    timeout(IO_TIMEOUT, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| RemoteTransportError::Timeout)??;
    Ok(())
}

pub(crate) async fn read_frame<S, T>(stream: &mut S) -> Result<T, RemoteTransportError>
where
    S: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    use bincode::Options;
    let bytes = timeout(IO_TIMEOUT, async {
        let len = stream.read_u32().await? as usize;
        if len > MAX_FRAME_BYTES {
            return Err(RemoteTransportError::FrameTooLarge(len));
        }
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        Ok(bytes)
    })
    .await
    .map_err(|_| RemoteTransportError::Timeout)??;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .map_err(|e| RemoteTransportError::Encode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_frames_and_trailing_bytes() {
        let (mut tx, mut rx) = tokio::io::duplex(128);
        tx.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
        assert!(matches!(
            read_frame::<_, SessionInput>(&mut rx).await,
            Err(RemoteTransportError::FrameTooLarge(_))
        ));
        let (mut tx, mut rx) = tokio::io::duplex(128);
        let mut bytes = bincode::serialize(&SessionInput::Status).unwrap();
        bytes.push(0);
        tx.write_u32(bytes.len() as u32).await.unwrap();
        tx.write_all(&bytes).await.unwrap();
        assert!(matches!(
            read_frame::<_, SessionInput>(&mut rx).await,
            Err(RemoteTransportError::Encode(_))
        ));
    }
}
