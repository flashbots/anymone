use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use anymone_core::config::ExchangePublicKeyWire;
use anymone_core::session::ClientSessionFactory;
use anymone_core::{
    AdcnetAction, Anymone, PanetiereAction as P, PeerId, ProtocolAction as A, Pubkey,
    RemoteProtocol, RemoteSessionStatus, Round, RoundOutcome, ScheduledAdcnetAction as SA,
    ScheduledPanetiereAction as SP, Session, Subnet,
};

use crate::{CommandResult, HostConfig, PairingInfo, RemoteSessionClient, RemoteTransportError, SessionCommand};

pub struct RemoteClientBackend {
    subnet: AtomicU32,
    generation: AtomicU64,
    client: tokio::sync::Mutex<RemoteSessionClient>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    returned_payloads: VecDeque<Vec<u8>>,
    context: Option<RemoteSessionStatus>,
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
    fn adopt(&mut self, status: RemoteSessionStatus, returned: Vec<Vec<u8>>) {
        if !returned.is_empty() {
            if let Some(payload) = self.payload.take() { self.returned_payloads.push_front(payload); }
            for payload in returned.into_iter().rev() { self.returned_payloads.push_front(payload); }
        }
        self.pending_messages = status.pending_messages;
        self.context = Some(status);
    }


}

impl RemoteClientBackend {
    pub async fn pair(pairing: PairingInfo) -> Result<Arc<Self>, RemoteTransportError> {
        let (client, host) = RemoteSessionClient::pair(pairing).await?;
        if host.closed {
            return Err(RemoteTransportError::Rejected("host is closed".into()));
        }
        Ok(Arc::new(Self {
            subnet: AtomicU32::new(host.client.as_ref().map_or(0, |c| c.subnet.id)),
            generation: AtomicU64::new(0),
            state: Mutex::new(State {
                context: host.client,
                ..State::default()
            }),
            client: tokio::sync::Mutex::new(client),
        }))
    }

    pub fn install(self: &Arc<Self>, node: &Anymone) -> Result<(), String> {
        let config = node.configuration();
        let subnet = config.body.subnets.iter()
            .filter(|s| !s.attested && !matches!(s.protocol, anymone_core::ProtocolConfig::Noop(_)))
            .min_by_key(|s| s.id).ok_or("no open remote-client subnet")?;
        self.subnet.store(subnet.id, Ordering::Relaxed);
        node.set_client_factory(Arc::new(SharedFactory(self.clone())))
    }

    pub fn context(&self) -> Option<RemoteSessionStatus> {
        self.state.lock().unwrap().context.clone()
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
    pub fn accepts(&self, subnet: &Subnet, _relay_keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        !subnet.attested
            && subnet.id == self.subnet.load(Ordering::Relaxed)
            && !matches!(subnet.protocol, anymone_core::ProtocolConfig::Noop(_))
    }

}

struct SharedFactory(Arc<RemoteClientBackend>);

impl ClientSessionFactory for SharedFactory {
    fn accepts(&self, subnet: &Subnet, keys: &[(Pubkey, ExchangePublicKeyWire)]) -> bool {
        self.0.accepts(subnet, keys)
    }

    fn create(&self, subnet: &Subnet, keys: &[(Pubkey, ExchangePublicKeyWire)], round: Round) -> Box<dyn Session> {
        Box::new(DesktopSession {
            backend: self.0.clone(),
            generation: self.0.generation.fetch_add(1, Ordering::SeqCst) + 1,
            queue: VecDeque::new(),
            initialized: false,
            config: HostConfig {
                subnet: subnet.clone(),
                relay_exchange_keys: keys.iter().filter(|(pk, _)| subnet.relays.contains(pk)).cloned().collect(),
                starting_round: round,
            },
            round,
        })
    }
}

struct DesktopSession {
    backend: Arc<RemoteClientBackend>,
    config: HostConfig,
    round: Round,
    generation: u64,
    queue: VecDeque<Pending>,
    initialized: bool,
}

impl DesktopSession {
    fn active(&self) -> bool {
        self.generation == self.backend.generation.load(Ordering::SeqCst)
    }

    fn push(&mut self, action: A, consumes_payload: bool) {
        if self.queue.len() >= 64 {
            self.backend.state.lock().unwrap().last_error = Some("remote action queue full; desktop is backpressured".into());
        } else {
            self.queue.push_back(Pending { action, consumes_payload });
        }
    }
}

impl Session for DesktopSession {
    fn can_stage(&self) -> bool {
        if !self.active() { return false; }
        let state = self.backend.state.lock().unwrap();
        state.payload.is_none() && state.returned_payloads.is_empty()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        let mut state = self.backend.state.lock().unwrap();
        assert!(state.payload.is_none(), "check can_stage before staging");
        state.payload = Some(payload);
    }

    fn set_cover_rate(&mut self, rate: f32) {
        if !self.active() { return; }
        self.backend.state.lock().unwrap().cover_rate = rate;
    }

    fn has_pending_transmissions(&self) -> bool {
        if !self.active() { return false; }
        let state = self.backend.state.lock().unwrap();
        state.payload.is_some() || !state.returned_payloads.is_empty() || !self.queue.is_empty() || state.pending_messages != 0
    }

    fn begin_round(&mut self, round: Round, _now: Instant) -> Vec<Vec<u8>> {
        if !self.active() { return Vec::new(); }
        self.round = round;
        let mut state = self.backend.state.lock().unwrap();
        if self.queue.len() > 58 {
            state.last_error = Some("remote action queue full; desktop is backpressured".into());
            return Vec::new();
        }
        if state.payload.is_none() { state.payload = state.returned_payloads.pop_front(); }
        let payload = if self.queue.iter().any(|pending| pending.consumes_payload) {
            None
        } else {
            state.payload.clone()
        };
        let consumes = payload.is_some();
        let rate = state.cover_rate;
        drop(state);
        match self.config.protocol() {
            RemoteProtocol::Panetiere if rate > 0.0 || consumes => {
                self.push(A::Panetiere(P::FinalizeRound { round, payload }), consumes);
            }
            RemoteProtocol::Adcnet if rate > 0.0 || consumes => {
                self.push(
                    A::Adcnet(AdcnetAction::Contribute { round, payload }),
                    consumes,
                );
            }
            RemoteProtocol::ScheduledPanetiere => {
                self.push(A::ScheduledPanetiere(SP::SetCoverRate { rate }), false);
                self.push(A::ScheduledPanetiere(SP::AdvanceRound { round }), false);
                if let Some(payload) = payload {
                    self.push(A::ScheduledPanetiere(SP::ReserveMessage { payload }), true);
                }
            }
            RemoteProtocol::ScheduledAdcnet => {
                self.push(A::ScheduledAdcnet(SA::SetCoverRate { rate }), false);
                self.push(
                    A::ScheduledAdcnet(SA::AdvanceToRound {
                        round: round as i64 + 1,
                    }),
                    false,
                );
                if let Some(payload) = payload {
                    self.push(
                        A::ScheduledAdcnet(SA::ScheduleMessageForNextRound { payload, bid: 1 }),
                        true,
                    );
                }
                self.push(A::ScheduledAdcnet(SA::MessagesForCurrentRound), false);
            }
            _ => {}
        }
        Vec::new()
    }

    fn checkpoint(&mut self, round: Round, k: u8, _now: Instant) -> Vec<Vec<u8>> {
        if !self.active() { return Vec::new(); }
        let action = match (self.config.protocol(), k) {
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
            self.push(action, false);
        }
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if !self.active() { return Vec::new(); }
        let protocol = self.config.protocol();
        match protocol {
            RemoteProtocol::Panetiere | RemoteProtocol::ScheduledPanetiere => {
                if let Ok(Some(action)) =
                    anymone_core::remote_session::panetiere_feedback(protocol, &payload)
                {
                    self.push(action, false);
                }
            }
            RemoteProtocol::ScheduledAdcnet
                if anymone_core::adcnet::is_scheduled_client_feedback(&payload) =>
            {
                if self.queue.len() <= 62 {
                    self.push(
                        A::ScheduledAdcnet(SA::ProcessRoundBroadcast { message: payload }),
                        false,
                    );
                    self.push(A::ScheduledAdcnet(SA::MessagesForCurrentRound), false);
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
            let backend = self.backend.clone();
            let mut client = backend.client.lock().await;
            if !self.active() { return Ok(Vec::new()); }
            if !self.initialized {
                if let Some(pending) = client.pending_command() {
                    match client.retry_pending().await {
                        Ok(CommandResult::Configured { status, returned_payloads }) => {
                            backend.state.lock().unwrap().adopt(status, returned_payloads);
                        }
                        Ok(CommandResult::Messages(_)) => {
                            if matches!(pending,
                                SessionCommand::Action(A::ScheduledPanetiere(SP::ReserveMessage { .. }))
                                | SessionCommand::Action(A::ScheduledAdcnet(SA::ScheduleMessageForNextRound { .. })))
                            {
                                backend.state.lock().unwrap().payload = None;
                            }
                        }
                        Err(RemoteTransportError::Protocol(_)) => {}
                        Err(error) => {
                            backend.state.lock().unwrap().last_error = Some(error.to_string());
                            return Err(error.to_string());
                        },
                    }
                }
                let config = HostConfig { starting_round: self.round, ..self.config.clone() };
                let (status, returned) = client.configure(config.clone()).await.map_err(|e| {
                    backend.state.lock().unwrap().last_error = Some(e.to_string());
                    e.to_string()
                })?;
                {
                    let mut state = backend.state.lock().unwrap();
                    state.adopt(status, returned);
                }
                self.queue.clear();
                self.initialized = true;
                self.begin_round(self.round, Instant::now());
            }
            if self.queue.is_empty() { return Ok(Vec::new()); }
            let mut outputs = Vec::new();
            loop {
                let pending = self.queue.front().cloned();
                let Some(pending) = pending else {
                    break;
                };
                match client.perform(pending.action).await {
                    Ok(messages) => {
                        outputs.extend(messages);
                        let mut state = self.backend.state.lock().unwrap();
                        self.queue.pop_front();
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
                            self.queue.pop_front();
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
                    self.backend.state.lock().unwrap().pending_messages = status.client.map_or(0, |c| c.pending_messages)
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
        let mut session = SharedFactory(remote.clone()).create(&config.subnet, &config.relay_exchange_keys, 0);
        session.set_cover_rate(1.0);
        session.stage(b"retained".to_vec());
        host.shutdown().await;
        assert!(session.begin_round(0, Instant::now()).is_empty());
        assert!(session.flush().await.is_err());
        assert!(!session.can_stage());
        assert!(session.has_pending_transmissions());
        assert!(remote.last_error().is_some());
        drop(session);
        let mut recreated = SharedFactory(remote.clone()).create(&config.subnet, &config.relay_exchange_keys, 0);
        assert!(!recreated.can_stage());
        assert!(recreated.begin_round(1, Instant::now()).is_empty());
        assert!(recreated.flush().await.is_err());
        assert_eq!(
            remote.state.lock().unwrap().payload.as_deref(),
            Some(b"retained".as_slice())
        );
        let mut attested = config.subnet.clone();
        attested.attested = true;
        assert!(!remote.accepts(&attested, &config.relay_exchange_keys));
    }
    #[tokio::test]
    async fn changed_configuration_preserves_pairing_and_requeues_scheduled_payload() {
        let relay = Identity::generate();
        let keys = vec![(relay.pubkey(), relay.exchange_keys())];
        let scheduled = Subnet::new(0, vec![relay.pubkey()],
            ProtocolConfig::ScheduledAdcnet(anymone_core::ScheduledAdcnetConfig {
                round_duration_ms: 1000, message_length: 1024, auction_slots: 4,
                min_message_size: 1, client_set_min: 0, client_set_max: 4,
            }));
        let host = RemoteSessionHost::new(None).unwrap()
            .listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let remote = RemoteClientBackend::pair(host.pairing.clone()).await.unwrap();
        let mut session = SharedFactory(remote.clone()).create(&scheduled, &keys, 0);
        session.set_cover_rate(1.0);
        session.stage(b"survives update".to_vec());
        session.begin_round(0, Instant::now());
        assert!(!session.flush().await.unwrap().is_empty());
        let before = host.session().lock().await.status();
        assert_eq!(before.client.as_ref().unwrap().pending_messages, 1);
        let mut previous = session;
        let ordinary = Subnet::new(0, vec![relay.pubkey()],
            ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 1000, max_payload_bytes: 64, estimated_messages: 1,
                client_set_min: 0, client_set_max: 4, aggregation: None,
            }));
        let mut session = SharedFactory(remote.clone()).create(&ordinary, &keys, 1);
        session.set_cover_rate(1.0);
        session.begin_round(1, Instant::now());
        assert_eq!(session.flush().await.unwrap().len(), 1);
        let after = host.session().lock().await.status();
        assert_eq!(after.session_id, before.session_id);
        assert_eq!(after.client.as_ref().unwrap().participant, before.client.as_ref().unwrap().participant);
        assert_eq!(after.client.unwrap().protocol, RemoteProtocol::Adcnet);
        assert!(session.can_stage());
        assert!(!session.has_pending_transmissions());
        assert!(!previous.can_stage());
        assert!(previous.begin_round(2, Instant::now()).is_empty());
        assert!(previous.flush().await.unwrap().is_empty());
        assert_eq!(host.session().lock().await.status().client.unwrap().protocol, RemoteProtocol::Adcnet);
        host.shutdown().await;
    }
}
