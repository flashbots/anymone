use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::session::ClientSessionFactory;
use anymone_core::{
    AdcnetAction, Anymone, PanetiereAction as P, PeerId, ProtocolAction as A, Pubkey,
    RemoteProtocol, RemoteSessionStatus, Round, RoundOutcome, ScheduledAdcnetAction as SA,
    ScheduledPanetiereAction as SP, Session, Subnet,
};

use crate::{PairingInfo, RemoteSessionClient, RemoteTransportError};

pub struct RemoteClientBackend {
    context: RemoteSessionStatus,
    client: tokio::sync::Mutex<RemoteSessionClient>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Pending>,
    payload: Option<Vec<u8>>,
    pending_messages: usize,
    cover_rate: f32,
    last_error: Option<String>,
}

#[derive(Clone)]
struct Pending {
    action: A,
    consumes_payload: bool,
}

impl State {
    fn push(&mut self, action: A, consumes_payload: bool) -> bool {
        if self.queue.len() >= 64 {
            self.last_error = Some("remote action queue full; desktop is backpressured".into());
            return false;
        }
        self.queue.push_back(Pending {
            action,
            consumes_payload,
        });
        true
    }
}

impl RemoteClientBackend {
    pub async fn pair(pairing: PairingInfo) -> Result<Arc<Self>, RemoteTransportError> {
        let (client, context) = RemoteSessionClient::pair(pairing).await?;
        if context.closed || !context.developer_mode || context.subnet.attested {
            return Err(RemoteTransportError::Rejected(
                "requires an open developer subnet".into(),
            ));
        }
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                pending_messages: context.pending_messages,
                ..State::default()
            }),
            context,
            client: tokio::sync::Mutex::new(client),
        }))
    }

    pub fn install(self: &Arc<Self>, node: &Anymone) -> Result<(), String> {
        node.set_client_factory(Arc::new(SharedFactory(self.clone())))
    }

    pub fn context(&self) -> &RemoteSessionStatus {
        &self.context
    }

    pub fn last_error(&self) -> Option<String> {
        self.state.lock().unwrap().last_error.clone()
    }

    pub async fn close(&self) -> Result<(), RemoteTransportError> {
        let mut client = self.client.lock().await;
        client.reconnect().await?;
        client.close().await
    }
}

impl RemoteClientBackend {
    pub fn accepts(&self, subnet: &Subnet, relay_keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        let expected = &self.context;
        if subnet.attested
            || subnet.id != expected.subnet.id
            || subnet.protocol != expected.subnet.protocol
            || subnet.relays.len() != expected.subnet.relays.len()
        {
            return false;
        }
        subnet.relays.iter().all(|key| {
            expected.subnet.relays.contains(key)
                && relay_keys.iter().find(|(pk, _)| pk == key)
                    == expected
                        .relay_exchange_keys
                        .iter()
                        .find(|(pk, _)| pk == key)
        })
    }
}

struct SharedFactory(Arc<RemoteClientBackend>);

impl ClientSessionFactory for SharedFactory {
    fn accepts(&self, subnet: &Subnet, keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        self.0.accepts(subnet, keys)
    }

    fn create(&self) -> Box<dyn Session> {
        Box::new(DesktopSession {
            backend: self.0.clone(),
        })
    }
}

struct DesktopSession {
    backend: Arc<RemoteClientBackend>,
}

impl Session for DesktopSession {
    fn can_stage(&self) -> bool {
        self.backend.state.lock().unwrap().payload.is_none()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        let mut state = self.backend.state.lock().unwrap();
        assert!(state.payload.is_none(), "check can_stage before staging");
        state.payload = Some(payload);
    }

    fn set_cover_rate(&mut self, rate: f32) {
        self.backend.state.lock().unwrap().cover_rate = rate;
    }

    fn has_pending_transmissions(&self) -> bool {
        let state = self.backend.state.lock().unwrap();
        state.payload.is_some() || !state.queue.is_empty() || state.pending_messages != 0
    }

    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        let mut state = self.backend.state.lock().unwrap();
        if state.queue.len() > 58 {
            state.last_error = Some("remote action queue full; desktop is backpressured".into());
            return Vec::new();
        }
        let payload = if state.queue.iter().any(|pending| pending.consumes_payload) {
            None
        } else {
            state.payload.clone()
        };
        let consumes = payload.is_some();
        let rate = state.cover_rate;
        match self.backend.context.protocol {
            RemoteProtocol::Panetiere if rate > 0.0 || consumes => {
                state.push(A::Panetiere(P::FinalizeRound { round, payload }), consumes);
            }
            RemoteProtocol::Adcnet if rate > 0.0 || consumes => {
                state.push(
                    A::Adcnet(AdcnetAction::Contribute { round, payload }),
                    consumes,
                );
            }
            RemoteProtocol::ScheduledPanetiere => {
                state.push(A::ScheduledPanetiere(SP::SetCoverRate { rate }), false);
                state.push(A::ScheduledPanetiere(SP::AdvanceRound { round }), false);
                if let Some(payload) = payload {
                    state.push(A::ScheduledPanetiere(SP::ReserveMessage { payload }), true);
                }
            }
            RemoteProtocol::ScheduledAdcnet => {
                state.push(A::ScheduledAdcnet(SA::SetCoverRate { rate }), false);
                state.push(
                    A::ScheduledAdcnet(SA::AdvanceToRound {
                        round: round as i64 + 1,
                    }),
                    false,
                );
                if let Some(payload) = payload {
                    state.push(
                        A::ScheduledAdcnet(SA::ScheduleMessageForNextRound { payload, bid: 1 }),
                        true,
                    );
                }
                state.push(A::ScheduledAdcnet(SA::MessagesForCurrentRound), false);
            }
            _ => {}
        }
        Vec::new()
    }

    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        let action = match (self.backend.context.protocol, k) {
            (RemoteProtocol::Panetiere, 1) => Some(A::Panetiere(P::PrepareRound {
                round: round.saturating_add(1),
            })),
            (RemoteProtocol::Panetiere, 3) => Some(A::Panetiere(P::BuildRepair { round })),
            (RemoteProtocol::ScheduledPanetiere, 1) => {
                Some(A::ScheduledPanetiere(SP::FinalizeRound { round }))
            }
            (RemoteProtocol::ScheduledPanetiere, 2) => {
                Some(A::ScheduledPanetiere(SP::PrepareRound {
                    round: round.saturating_add(1),
                }))
            }
            (RemoteProtocol::ScheduledPanetiere, 3) => {
                Some(A::ScheduledPanetiere(SP::BuildRepair { round }))
            }
            _ => None,
        };
        if let Some(action) = action {
            self.backend.state.lock().unwrap().push(action, false);
        }
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let protocol = self.backend.context.protocol;
        let mut state = self.backend.state.lock().unwrap();
        match protocol {
            RemoteProtocol::Panetiere | RemoteProtocol::ScheduledPanetiere => {
                if let Ok(Some(action)) =
                    anymone_core::remote_session::panetiere_feedback(protocol, &payload)
                {
                    state.push(action, false);
                }
            }
            RemoteProtocol::ScheduledAdcnet
                if anymone_core::adcnet::is_scheduled_client_feedback(&payload) =>
            {
                if state.queue.len() <= 62 {
                    state.push(
                        A::ScheduledAdcnet(SA::ProcessRoundBroadcast { message: payload }),
                        false,
                    );
                    state.push(A::ScheduledAdcnet(SA::MessagesForCurrentRound), false);
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn flush(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Vec<u8>>, String>> + Send + '_>,
    > {
        Box::pin(async move {
            if self.backend.state.lock().unwrap().queue.is_empty() {
                return Ok(Vec::new());
            }
            let mut client = self.backend.client.lock().await;
            let mut outputs = Vec::new();
            loop {
                let pending = self.backend.state.lock().unwrap().queue.front().cloned();
                let Some(pending) = pending else {
                    break;
                };
                match client.perform(pending.action).await {
                    Ok(messages) => {
                        outputs.extend(messages);
                        let mut state = self.backend.state.lock().unwrap();
                        state.queue.pop_front();
                        if pending.consumes_payload {
                            state.payload = None;
                        }
                        state.last_error = None;
                    }
                    Err(error) => {
                        let mut state = self.backend.state.lock().unwrap();
                        state.last_error = Some(error.to_string());
                        tracing::warn!(%error, "remote protocol action failed");
                        if matches!(error, RemoteTransportError::Protocol(_)) {
                            state.queue.pop_front();
                            continue;
                        }
                        return if outputs.is_empty() {
                            Err(error.to_string())
                        } else {
                            Ok(outputs)
                        };
                    }
                }
            }
            match client.status().await {
                Ok(status) => {
                    self.backend.state.lock().unwrap().pending_messages = status.pending_messages
                }
                Err(error) => {
                    self.backend.state.lock().unwrap().last_error = Some(error.to_string())
                }
            }
            Ok(outputs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostConfig, RemoteSessionHost};
    use anymone_core::{AdcnetConfig, Identity, ProtocolConfig};

    #[tokio::test]
    async fn disconnected_host_retains_payload_without_local_output() {
        let relay = Identity::generate();
        let config = HostConfig {
            subnet: Subnet::new(
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
            ),
            relay_exchange_keys: vec![(relay.pubkey(), relay.exchange_keys())],
            starting_round: 0,
        };
        let host = RemoteSessionHost::new(config.developer_session().unwrap())
            .unwrap()
            .listen("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let remote = RemoteClientBackend::pair(host.pairing.clone())
            .await
            .unwrap();
        let mut session = SharedFactory(remote.clone()).create();
        session.set_cover_rate(1.0);
        session.stage(b"retained".to_vec());
        host.shutdown().await;
        assert!(session.begin_round(0, Instant::now()).is_empty());
        assert!(session.flush().await.is_err());
        assert!(!session.can_stage());
        assert!(session.has_pending_transmissions());
        assert!(remote.last_error().is_some());
        drop(session);
        let mut recreated = SharedFactory(remote.clone()).create();
        assert!(!recreated.can_stage());
        assert!(recreated.begin_round(1, Instant::now()).is_empty());
        assert!(recreated.flush().await.is_err());
        assert_eq!(
            remote.state.lock().unwrap().payload.as_deref(),
            Some(b"retained".as_slice())
        );
        assert!(!remote.accepts(&config.subnet, &[]));
    }
}
