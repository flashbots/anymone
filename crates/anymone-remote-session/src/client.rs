use std::sync::Arc;
use std::time::Duration;

use anymone_core::{
    AdcnetAction, PanetiereAction, ProtocolAction, RemoteSessionStatus, Round,
    ScheduledAdcnetAction, ScheduledPanetiereAction,
};
use rustls::pki_types::{CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::host::{read_frame, write_frame};
use crate::wire::{CommandResult, HostStatus, PairRequest, PairingInfo, SessionCommand, SessionInput, SessionReply};
use crate::HostConfig;
use crate::RemoteTransportError;

pub struct RemoteSessionClient {
    stream: Option<TlsStream<TcpStream>>,
    controller_secret: [u8; 32],
    pairing: PairingInfo,
    next_request: u64,
    pending: Option<(u64, SessionCommand)>,
    session_id: [u8; 32],
}

impl RemoteSessionClient {
    pub async fn pair(
        pairing: PairingInfo,
    ) -> Result<(Self, HostStatus), RemoteTransportError> {
        if pairing.interface_version != crate::INTERFACE_VERSION
            || Sha256::digest(&pairing.certificate_der).as_slice() != pairing.certificate_sha256
        {
            return Err(RemoteTransportError::PairingFailed);
        }
        let controller_secret = rand::random();
        let mut last_error = RemoteTransportError::PairingFailed;
        for _ in 0..3 {
            let attempt = async {
                let mut stream = connect_tls(&pairing).await?;
                write_frame(
                    &mut stream,
                    &SessionInput::Pair(PairRequest::First {
                        token: pairing.pairing_token,
                        controller_secret,
                    }),
                )
                .await?;
                match read_frame(&mut stream).await? {
                    SessionReply::Paired(status) => Ok((stream, status)),
                    SessionReply::Error(error) => Err(RemoteTransportError::Rejected(error)),
                    _ => Err(RemoteTransportError::PairingFailed),
                }
            }
            .await;
            match attempt {
                Ok((stream, status)) => {
                    return Ok((
                        Self {
                            stream: Some(stream),
                            controller_secret,
                            pairing,
                            next_request: status.next_request,
                            pending: None,
                            session_id: status.session_id,
                        },
                        status,
                    ))
                }
                Err(
                    error @ (RemoteTransportError::Rejected(_)
                    | RemoteTransportError::PairingFailed),
                ) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub async fn reconnect(&mut self) -> Result<HostStatus, RemoteTransportError> {
        self.stream = None;
        let mut stream = connect_tls(&self.pairing).await?;
        write_frame(
            &mut stream,
            &SessionInput::Pair(PairRequest::Resume {
                controller_secret: self.controller_secret,
            }),
        )
        .await?;
        match read_frame(&mut stream).await? {
            SessionReply::Paired(status) if status.session_id == self.session_id => {
                if self.pending.is_none() {
                    self.next_request = status.next_request;
                }
                self.stream = Some(stream);
                Ok(status)
            }
            SessionReply::Error(error) => Err(RemoteTransportError::Rejected(error)),
            _ => Err(RemoteTransportError::PairingFailed),
        }
    }

    pub async fn status(&mut self) -> Result<HostStatus, RemoteTransportError> {
        match self.exchange(SessionInput::Status).await? {
            SessionReply::Status(status) => Ok(status),
            _ => Err(RemoteTransportError::UnexpectedReply),
        }
    }

    pub async fn close(&mut self) -> Result<(), RemoteTransportError> {
        match self.exchange(SessionInput::Close).await? {
            SessionReply::Closed => {
                self.pending = None;
                Ok(())
            }
            _ => Err(RemoteTransportError::UnexpectedReply),
        }
    }

    pub async fn panetiere(
        &mut self,
        action: PanetiereAction,
    ) -> Result<Vec<Vec<u8>>, RemoteTransportError> {
        self.action(ProtocolAction::Panetiere(action)).await
    }

    pub async fn scheduled_panetiere(
        &mut self,
        action: ScheduledPanetiereAction,
    ) -> Result<Vec<Vec<u8>>, RemoteTransportError> {
        self.action(ProtocolAction::ScheduledPanetiere(action))
            .await
    }

    pub async fn adcnet_contribute(
        &mut self,
        round: Round,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, RemoteTransportError> {
        let mut messages = self
            .action(ProtocolAction::Adcnet(AdcnetAction::Contribute {
                round,
                payload,
            }))
            .await?;
        if messages.len() != 1 {
            return Err(RemoteTransportError::UnexpectedReply);
        }
        Ok(messages.remove(0))
    }

    pub async fn scheduled_adcnet(
        &mut self,
        action: ScheduledAdcnetAction,
    ) -> Result<Vec<Vec<u8>>, RemoteTransportError> {
        self.action(ProtocolAction::ScheduledAdcnet(action)).await
    }

    pub async fn configure(
        &mut self,
        config: HostConfig,
    ) -> Result<(RemoteSessionStatus, Vec<Vec<u8>>), RemoteTransportError> {
        match self.perform_command(SessionCommand::Configure(config)).await? {
            CommandResult::Configured { status, returned_payloads } => Ok((status, returned_payloads)),
            _ => Err(RemoteTransportError::UnexpectedReply),
        }
    }

    pub(crate) fn pending_command(&self) -> Option<SessionCommand> {
        self.pending.as_ref().map(|(_, command)| command.clone())
    }

    pub(crate) async fn perform(
        &mut self,
        action: ProtocolAction,
    ) -> Result<Vec<Vec<u8>>, RemoteTransportError> {
        match self.perform_command(SessionCommand::Action(action)).await? {
            CommandResult::Messages(messages) => Ok(messages),
            _ => Err(RemoteTransportError::UnexpectedReply),
        }
    }

    async fn perform_command(&mut self, command: SessionCommand) -> Result<CommandResult, RemoteTransportError> {
        if self.stream.is_none() { self.reconnect().await?; }
        if let Some((_, pending)) = &self.pending {
            if pending != &command { return Err(RemoteTransportError::PendingRequest); }
        } else {
            self.pending = Some((self.next_request, command));
        }
        self.retry_pending().await
    }

    async fn action(&mut self, action: ProtocolAction) -> Result<Vec<Vec<u8>>, RemoteTransportError> {
        if self.pending.is_some() { return Err(RemoteTransportError::PendingRequest); }
        self.perform(action).await
    }

    pub async fn retry_pending(&mut self) -> Result<CommandResult, RemoteTransportError> {
        if self.stream.is_none() { self.reconnect().await?; }
        let (sequence, command) = self.pending.clone().ok_or(RemoteTransportError::NoPendingRequest)?;
        match self.exchange(SessionInput::Request { sequence, command }).await? {
            SessionReply::Executed { sequence: received, result } if received == sequence => {
                self.pending = None;
                self.next_request = sequence.checked_add(1).ok_or(RemoteTransportError::UnexpectedReply)?;
                result.map_err(RemoteTransportError::Protocol)
            }
            _ => Err(RemoteTransportError::UnexpectedReply),
        }
    }

    async fn exchange(
        &mut self,
        input: SessionInput,
    ) -> Result<SessionReply, RemoteTransportError> {
        let mut stream = self
            .stream
            .take()
            .ok_or(RemoteTransportError::Disconnected)?;
        let result = async {
            write_frame(&mut stream, &input).await?;
            match read_frame(&mut stream).await? {
                SessionReply::Error(error) => Err(RemoteTransportError::Rejected(error)),
                reply => Ok(reply),
            }
        }
        .await;
        if result.is_ok() {
            self.stream = Some(stream);
        }
        result
    }
}

async fn connect_tls(pairing: &PairingInfo) -> Result<TlsStream<TcpStream>, RemoteTransportError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(pairing.certificate_der.clone()))?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect(&pairing.address).await?;
        tcp.set_nodelay(true)?;
        let server_name = ServerName::try_from("anymone.local")
            .map_err(|e| RemoteTransportError::Encode(e.to_string()))?;
        Ok(TlsConnector::from(Arc::new(config))
            .connect(server_name, tcp)
            .await?)
    })
    .await
    .map_err(|_| RemoteTransportError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RemoteSessionHost;
    use anymone_core::{AdcnetConfig, Identity, ProtocolConfig, RemoteAttestedSession, Subnet};

    #[tokio::test]
    async fn lost_reply_is_replayed_after_reconnect() {
        let relay = Identity::generate();
        let subnet = Subnet::new(
            0,
            vec![relay.pubkey()],
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 1000,
                max_payload_bytes: 64,
                estimated_messages: 1,
                client_set_min: 0,
                client_set_max: 4,
                aggregation: None,
            }),
        );
        let session = RemoteAttestedSession::developer(
            &subnet,
            &[(relay.pubkey(), relay.exchange_keys())],
            0,
        )
        .unwrap();
        let handle = RemoteSessionHost::new(session)
            .unwrap()
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let (mut client, _) = RemoteSessionClient::pair(handle.pairing.clone())
            .await
            .unwrap();
        let action = ProtocolAction::Adcnet(AdcnetAction::Contribute {
            round: 0,
            payload: Some(b"lost reply".to_vec()),
        });
        client.pending = Some((0, SessionCommand::Action(action.clone())));
        let stream = client.stream.as_mut().unwrap();
        write_frame(
            stream,
            &SessionInput::Request {
                sequence: 0,
                command: SessionCommand::Action(action),
            },
        )
        .await
        .unwrap();
        let SessionReply::Executed {
            result: Ok(expected),
            ..
        } = read_frame(stream).await.unwrap()
        else {
            panic!("expected native contribution")
        };
        assert!(client.pending.is_some());
        assert_eq!(client.reconnect().await.unwrap().next_request, 1);
        assert_eq!(client.retry_pending().await.unwrap(), expected);
        assert!(!client.adcnet_contribute(1, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancelled_action_reconnects_before_replaying() {
        let relay = Identity::generate();
        let subnet = Subnet::new(
            0,
            vec![relay.pubkey()],
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 1000,
                max_payload_bytes: 64,
                estimated_messages: 1,
                client_set_min: 0,
                client_set_max: 4,
                aggregation: None,
            }),
        );
        let session = RemoteAttestedSession::developer(
            &subnet,
            &[(relay.pubkey(), relay.exchange_keys())],
            0,
        ).unwrap();
        let host = RemoteSessionHost::new(session).unwrap()
            .listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut client, _) = RemoteSessionClient::pair(host.pairing.clone()).await.unwrap();
        let session = host.session();
        let held = session.lock().await;
        let action = ProtocolAction::Adcnet(AdcnetAction::Contribute {
            round: 0,
            payload: Some(b"cancelled request".to_vec()),
        });
        assert!(timeout(Duration::from_millis(25), client.perform(action.clone())).await.is_err());
        assert!(client.stream.is_none());
        assert!(client.pending.is_some());
        drop(held);
        let messages = client.perform(action).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(client.status().await.unwrap().next_request, 1);
        assert!(client.pending.is_none());
        assert!(!client.adcnet_contribute(1, None).await.unwrap().is_empty());
        host.shutdown().await;
    }


    #[tokio::test]
    async fn configuration_replay_preserves_keys_state_and_returned_payloads() {
        let relay = Identity::generate();
        let mut config = HostConfig {
            subnet: Subnet::new(0, vec![relay.pubkey()],
                ProtocolConfig::ScheduledAdcnet(anymone_core::ScheduledAdcnetConfig {
                    round_duration_ms: 1000, message_length: 1024, auction_slots: 4,
                    min_message_size: 1, client_set_min: 0, client_set_max: 4,
                })),
            relay_exchange_keys: vec![(relay.pubkey(), relay.exchange_keys())],
            starting_round: 0,
        };
        let host = RemoteSessionHost::new(None).unwrap()
            .listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (mut client, initial) = RemoteSessionClient::pair(host.pairing.clone()).await.unwrap();
        assert!(initial.client.is_none());
        let (configured, returned) = client.configure(config.clone()).await.unwrap();
        assert!(returned.is_empty());
        client.scheduled_adcnet(ScheduledAdcnetAction::ScheduleMessageForNextRound {
            payload: b"preserved".to_vec(), bid: 1,
        }).await.unwrap();
        config.starting_round = 1;
        let (same, returned) = client.configure(config.clone()).await.unwrap();
        assert_eq!(same.participant, configured.participant);
        assert_eq!(same.pending_messages, 1);
        assert!(returned.is_empty());
        let mut invalid = config.clone();
        invalid.subnet.relays.clear();
        assert!(client.configure(invalid).await.is_err());
        assert_eq!(client.status().await.unwrap().client.unwrap().pending_messages, 1);
        config.subnet.protocol = ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 1000, max_payload_bytes: 64, estimated_messages: 1,
            client_set_min: 0, client_set_max: 4, aggregation: None,
        });
        let sequence = client.next_request;
        let command = SessionCommand::Configure(config.clone());
        client.pending = Some((sequence, command.clone()));
        let stream = client.stream.as_mut().unwrap();
        write_frame(stream, &SessionInput::Request { sequence, command }).await.unwrap();
        let SessionReply::Executed { result: Ok(expected), .. } = read_frame(stream).await.unwrap()
        else { panic!("expected configuration reply") };
        let CommandResult::Configured { status, returned_payloads } = &expected
        else { panic!("expected configured client") };
        assert_eq!(status.participant, configured.participant);
        assert_eq!(returned_payloads, &vec![b"preserved".to_vec()]);
        assert_eq!(client.reconnect().await.unwrap().session_id, initial.session_id);
        assert_eq!(client.retry_pending().await.unwrap(), expected);
        assert!(client.configure(config.clone()).await.unwrap().1.is_empty());
        let message = client.adcnet_contribute(1, Some(b"next".to_vec())).await.unwrap();
        client.configure(config).await.unwrap();
        assert_eq!(client.adcnet_contribute(1, Some(b"next".to_vec())).await.unwrap(), message);
        host.shutdown().await;
    }

}
