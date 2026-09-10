use std::collections::BTreeSet;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::adcnet::{AdcnetClientSession, ScheduledAdcnetClientSession};
use crate::config::{ExchangePublicKeyWire, ProtocolConfig, Round, SetFormation, Subnet};
use crate::panetiere::{PanetiereClientSession, PanetiereWire};
use crate::panetiere_scheduled::ScheduledPanetiereClientSession;
use crate::{Identity, Pubkey};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemoteProtocol {
    Panetiere,
    ScheduledPanetiere,
    Adcnet,
    ScheduledAdcnet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PanetiereAction {
    PrepareRound {
        round: Round,
    },
    FinalizeRound {
        round: Round,
        payload: Option<Vec<u8>>,
    },
    AcceptReceiptBatch {
        round: Round,
        batch: Vec<u8>,
    },
    BuildRepair {
        round: Round,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScheduledPanetiereAction {
    SetCoverRate { rate: f32 },
    AdvanceRound { round: Round },
    ReserveMessage { payload: Vec<u8> },
    PrepareRound { round: Round },
    FinalizeRound { round: Round },
    AcceptReservations { message: Vec<u8> },
    AcceptReceiptBatch { round: Round, batch: Vec<u8> },
    BuildRepair { round: Round },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdcnetAction {
    Contribute {
        round: Round,
        payload: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScheduledAdcnetAction {
    SetCoverRate { rate: f32 },
    AdvanceToRound { round: i64 },
    ScheduleMessageForNextRound { payload: Vec<u8>, bid: u32 },
    ProcessRoundBroadcast { message: Vec<u8> },
    MessagesForCurrentRound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtocolAction {
    Panetiere(PanetiereAction),
    ScheduledPanetiere(ScheduledPanetiereAction),
    Adcnet(AdcnetAction),
    ScheduledAdcnet(ScheduledAdcnetAction),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemoteSessionStatus {
    pub subnet: Subnet,
    pub relay_exchange_keys: Vec<(Pubkey, ExchangePublicKeyWire)>,
    pub session_id: [u8; 32],
    pub protocol: RemoteProtocol,
    pub participant: Pubkey,
    pub exchange_keys: ExchangePublicKeyWire,
    pub current_round: Round,
    pub next_request: u64,
    pub closed: bool,
    pub developer_mode: bool,
    pub pending_messages: usize,
}

enum Client {
    Panetiere(PanetiereClientSession),
    ScheduledPanetiere(ScheduledPanetiereClientSession),
    Adcnet(AdcnetClientSession),
    ScheduledAdcnet(ScheduledAdcnetClientSession),
}

struct FinalizedRound {
    round: Round,
    input: [u8; 32],
    messages: Vec<Vec<u8>>,
}

struct Reply {
    sequence: u64,
    input: [u8; 32],
    result: Result<Vec<Vec<u8>>, RemoteSessionError>,
}

pub struct RemoteAttestedSession {
    client: Option<Client>,
    status: RemoteSessionStatus,
    last_reply: Option<Reply>,
    finalized: Option<FinalizedRound>,
    repair: Option<(Round, Vec<Vec<u8>>)>,
    max_payload: usize,
}

impl RemoteAttestedSession {
    pub fn developer(
        subnet: &Subnet,
        relay_exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
        starting_round: Round,
    ) -> Result<Self, RemoteSessionError> {
        validate_config(subnet, starting_round)?;
        let identity = Identity::generate();
        let mut seed = [0; 32];
        let mut session_id = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        let (client, protocol, max_payload) = match &subnet.protocol {
            ProtocolConfig::Panetiere(cfg) => {
                let servers = crate::panetiere::seal_roster(relay_exchange_keys, subnet);
                require_roster(servers.len(), subnet)?;
                let set_pks = consensus_roster(cfg.set_formation, relay_exchange_keys, subnet)?;
                let (channel, params) = crate::panetiere::params_for(cfg, subnet.relays.len());
                let mut client =
                    PanetiereClientSession::new(params, channel, identity.clone(), servers, seed);
                client.set_setup_seed(cfg.setup_seed);
                if let Some(pks) = set_pks {
                    client.set_consensus(pks);
                }
                (
                    Client::Panetiere(client),
                    RemoteProtocol::Panetiere,
                    cfg.message_size,
                )
            }
            ProtocolConfig::ScheduledPanetiere(cfg) => {
                let servers = crate::panetiere::seal_roster(relay_exchange_keys, subnet);
                require_roster(servers.len(), subnet)?;
                let set_pks = consensus_roster(cfg.set_formation, relay_exchange_keys, subnet)?;
                let (channel, params) =
                    crate::panetiere_scheduled::params_for(cfg, subnet.relays.len());
                let mut client = ScheduledPanetiereClientSession::new(
                    params,
                    channel,
                    cfg.vector_bytes,
                    identity.clone(),
                    servers,
                    crate::subnet_leader_pk(subnet),
                    seed,
                    Default::default(),
                );
                client.set_setup_seed(cfg.setup_seed);
                client.advance_round(starting_round);
                if let Some(pks) = set_pks {
                    client.set_consensus(pks);
                }
                (
                    Client::ScheduledPanetiere(client),
                    RemoteProtocol::ScheduledPanetiere,
                    cfg.message_size,
                )
            }
            ProtocolConfig::Adcnet(cfg) => {
                let shared =
                    crate::adcnet::client_shared_secrets(relay_exchange_keys, &identity, subnet);
                require_roster(shared.len(), subnet)?;
                let client = AdcnetClientSession::new(
                    crate::adcnet::one_round_config(cfg),
                    identity.to_adcnet_signing_key(),
                    shared,
                    identity.exchange_pubkey(),
                    seed,
                );
                (
                    Client::Adcnet(client),
                    RemoteProtocol::Adcnet,
                    cfg.max_payload_bytes,
                )
            }
            ProtocolConfig::ScheduledAdcnet(cfg) => {
                let servers: Vec<_> =
                    crate::keys::roster_exchange_pubkeys(&subnet.relays, relay_exchange_keys)
                        .into_iter()
                        .map(|(i, key)| (adcnet::crypto::ServerId(i as u32), key))
                        .collect();
                require_roster(servers.len(), subnet)?;
                let config = crate::adcnet::scheduled_config(cfg);
                let initial = crate::adcnet::empty_scheduled_broadcast(&config, 0);
                let mut client = ScheduledAdcnetClientSession::new(
                    config,
                    identity.to_adcnet_signing_key(),
                    adcnet::crypto::ExchangePrivateKey::from_bytes(
                        &identity.exchange().scalar_bytes(),
                    )
                    .map_err(|e| RemoteSessionError::Protocol(e.to_string()))?,
                    &servers,
                    initial,
                    starting_round as i64 + 1,
                    crate::subnet_leader_pk(subnet),
                );
                client.set_min_message_size(cfg.min_message_size as usize);
                (
                    Client::ScheduledAdcnet(client),
                    RemoteProtocol::ScheduledAdcnet,
                    cfg.message_length,
                )
            }
            ProtocolConfig::Noop(_) => return Err(RemoteSessionError::UnsupportedProtocol),
        };
        Ok(Self {
            client: Some(client),
            status: RemoteSessionStatus {
                subnet: subnet.clone(),
                relay_exchange_keys: relay_exchange_keys.to_vec(),
                session_id,
                protocol,
                participant: identity.pubkey(),
                exchange_keys: identity.exchange_keys(),
                current_round: starting_round,
                next_request: 0,
                closed: false,
                developer_mode: true,
                pending_messages: 0,
            },
            last_reply: None,
            finalized: None,
            repair: None,
            max_payload,
        })
    }

    pub fn status(&self) -> RemoteSessionStatus {
        let mut status = self.status.clone();
        status.pending_messages = match self.client.as_ref() {
            Some(Client::ScheduledPanetiere(client)) => client.pending_message_count(),
            Some(Client::ScheduledAdcnet(client)) => client.pending_message_count(),
            _ => 0,
        };
        status
    }

    pub fn close(&mut self) {
        self.client = None;
        self.finalized = None;
        self.repair = None;
        self.last_reply = None;
        self.status.closed = true;
    }

    pub fn execute(
        &mut self,
        sequence: u64,
        action: ProtocolAction,
    ) -> Result<Vec<Vec<u8>>, RemoteSessionError> {
        if self.status.closed {
            return Err(RemoteSessionError::Closed);
        }
        let input = action_digest(&action)?;
        if let Some(reply) = &self.last_reply {
            if sequence == reply.sequence {
                return if input == reply.input {
                    reply.result.clone()
                } else {
                    Err(RemoteSessionError::RequestConflict)
                };
            }
        }
        if sequence != self.status.next_request {
            return Err(RemoteSessionError::RequestSequence {
                expected: self.status.next_request,
            });
        }
        self.status.next_request = sequence
            .checked_add(1)
            .ok_or(RemoteSessionError::SequenceExhausted)?;
        let result = self.execute_action(action, input);
        self.last_reply = Some(Reply {
            sequence,
            input,
            result: result.clone(),
        });
        result
    }

    fn execute_action(
        &mut self,
        action: ProtocolAction,
        input: [u8; 32],
    ) -> Result<Vec<Vec<u8>>, RemoteSessionError> {
        use ProtocolAction::*;
        let finalize_round = match &action {
            Panetiere(PanetiereAction::FinalizeRound { round, .. })
            | ScheduledPanetiere(ScheduledPanetiereAction::FinalizeRound { round })
            | Adcnet(AdcnetAction::Contribute { round, .. }) => Some(*round),
            ScheduledAdcnet(ScheduledAdcnetAction::MessagesForCurrentRound) => {
                Some(self.status.current_round)
            }
            _ => None,
        };
        if let Some(round) = finalize_round {
            if let Some(finalized) = &self.finalized {
                if round < finalized.round {
                    return Err(RemoteSessionError::RoundOrder);
                }
                if round == finalized.round {
                    return if finalized.input == input {
                        Ok(finalized.messages.clone())
                    } else {
                        Err(RemoteSessionError::RoundConflict)
                    };
                }
            }
            self.check_round(round)?;
        }
        match &action {
            ScheduledPanetiere(ScheduledPanetiereAction::SetCoverRate { rate })
            | ScheduledAdcnet(ScheduledAdcnetAction::SetCoverRate { rate })
                if !rate.is_finite() || !(0.0..=1.0).contains(rate) => {
                return Err(RemoteSessionError::Protocol("invalid cover rate".into()));
            }
            Panetiere(PanetiereAction::PrepareRound { round })
            | ScheduledPanetiere(ScheduledPanetiereAction::PrepareRound { round }) => {
                self.check_round(*round)?;
                if self.finalized.as_ref().is_some_and(|f| *round <= f.round) {
                    return Err(RemoteSessionError::RoundOrder);
                }
            }
            Panetiere(PanetiereAction::BuildRepair { round })
            | ScheduledPanetiere(ScheduledPanetiereAction::BuildRepair { round }) => {
                if self.finalized.as_ref().is_none_or(|f| *round > f.round) {
                    return Err(RemoteSessionError::RoundOrder);
                }
                if let Some((saved_round, messages)) = &self.repair {
                    if round == saved_round {
                        return Ok(messages.clone());
                    }
                    if round < saved_round {
                        return Err(RemoteSessionError::RoundOrder);
                    }
                }
            }
            Panetiere(PanetiereAction::FinalizeRound {
                payload: Some(payload),
                ..
            })
            | Adcnet(AdcnetAction::Contribute {
                payload: Some(payload),
                ..
            }) => self.check_payload(payload)?,
            ScheduledPanetiere(ScheduledPanetiereAction::ReserveMessage { payload })
            | ScheduledAdcnet(ScheduledAdcnetAction::ScheduleMessageForNextRound {
                payload, ..
            }) => {
                self.check_payload(payload)?;
                let pending = match self.client.as_ref() {
                    Some(Client::ScheduledPanetiere(client)) => client.pending_message_count(),
                    Some(Client::ScheduledAdcnet(client)) => client.pending_message_count(),
                    _ => 0,
                };
                if pending >= 64 {
                    return Err(RemoteSessionError::QueueFull);
                }
            }
            ScheduledPanetiere(ScheduledPanetiereAction::AdvanceRound { round }) => {
                self.check_round(*round)?
            }
            ScheduledAdcnet(ScheduledAdcnetAction::AdvanceToRound { round }) => {
                let round = u64::try_from(*round)
                    .ok()
                    .and_then(|r| r.checked_sub(1))
                    .ok_or(RemoteSessionError::RoundOrder)?;
                self.check_round(round)?;
            }
            _ => {}
        }
        let mut repair_round = None;
        let messages = match (
            self.client.as_mut().ok_or(RemoteSessionError::Closed)?,
            action,
        ) {
            (Client::Panetiere(client), Panetiere(action)) => match action {
                PanetiereAction::PrepareRound { round } => {
                    client.prepare_round(round);
                    Vec::new()
                }
                PanetiereAction::FinalizeRound { round, payload } => client
                    .finalize_round(round, payload)
                    .map_err(RemoteSessionError::Protocol)?,
                PanetiereAction::AcceptReceiptBatch { round, batch } => {
                    client
                        .accept_receipt_batch(round, &batch)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                PanetiereAction::BuildRepair { round } => {
                    repair_round = Some(round);
                    client.build_repair(round)
                }
            },
            (Client::ScheduledPanetiere(client), ScheduledPanetiere(action)) => match action {
                ScheduledPanetiereAction::SetCoverRate { rate } => {
                    crate::Session::set_cover_rate(client, rate);
                    Vec::new()
                }
                ScheduledPanetiereAction::AdvanceRound { round } => {
                    self.status.current_round = round;
                    client.advance_round(round)
                }
                ScheduledPanetiereAction::ReserveMessage { payload } => {
                    client
                        .reserve_message(payload)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                ScheduledPanetiereAction::PrepareRound { round } => {
                    client.prepare_round(round);
                    Vec::new()
                }
                ScheduledPanetiereAction::FinalizeRound { round } => {
                    if round != self.status.current_round {
                        return Err(RemoteSessionError::RoundOrder);
                    }
                    client.finalize_round(round)
                }
                ScheduledPanetiereAction::AcceptReservations { message } => {
                    let PanetiereWire::Reservations {
                        round,
                        entries,
                        signature,
                    } = decode_native(&message)?
                    else {
                        return Err(RemoteSessionError::Protocol("expected reservations".into()));
                    };
                    client
                        .accept_reservations(round, entries, &signature)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                ScheduledPanetiereAction::AcceptReceiptBatch { round, batch } => {
                    client
                        .accept_receipt_batch(round, &batch)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                ScheduledPanetiereAction::BuildRepair { round } => {
                    repair_round = Some(round);
                    client.build_repair(round)
                }
            },
            (Client::Adcnet(client), Adcnet(AdcnetAction::Contribute { round, payload })) => {
                vec![client
                    .contribute(round, payload.as_deref())
                    .map_err(RemoteSessionError::Protocol)?]
            }
            (Client::ScheduledAdcnet(client), ScheduledAdcnet(action)) => match action {
                ScheduledAdcnetAction::SetCoverRate { rate } => {
                    crate::Session::set_cover_rate(client, rate);
                    Vec::new()
                }
                ScheduledAdcnetAction::AdvanceToRound { round } => {
                    client
                        .advance_to_round(round)
                        .map_err(RemoteSessionError::Protocol)?;
                    self.status.current_round = round as u64 - 1;
                    Vec::new()
                }
                ScheduledAdcnetAction::ScheduleMessageForNextRound { payload, bid } => {
                    client
                        .schedule_message_for_next_round(payload, bid)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                ScheduledAdcnetAction::ProcessRoundBroadcast { message } => {
                    client
                        .process_round_broadcast(&message)
                        .map_err(RemoteSessionError::Protocol)?;
                    Vec::new()
                }
                ScheduledAdcnetAction::MessagesForCurrentRound => client
                    .messages_for_current_round()
                    .map_err(RemoteSessionError::Protocol)?,
            },
            _ => return Err(RemoteSessionError::WrongProtocol),
        };
        if let Some(round) = finalize_round.filter(|_| !messages.is_empty()) {
            self.status.current_round = round;
            self.finalized = Some(FinalizedRound {
                round,
                input,
                messages: messages.clone(),
            });
        }
        if let Some(round) = repair_round.filter(|_| !messages.is_empty()) {
            self.repair = Some((round, messages.clone()));
        }
        Ok(messages)
    }

    fn check_round(&self, round: Round) -> Result<(), RemoteSessionError> {
        if round < self.status.current_round || round >= u32::MAX as u64 {
            Err(RemoteSessionError::RoundOrder)
        } else {
            Ok(())
        }
    }

    fn check_payload(&self, payload: &[u8]) -> Result<(), RemoteSessionError> {
        if payload.len() > self.max_payload {
            Err(RemoteSessionError::PayloadTooLarge)
        } else {
            Ok(())
        }
    }
}

fn action_digest(action: &ProtocolAction) -> Result<[u8; 32], RemoteSessionError> {
    let bytes =
        bincode::serialize(action).map_err(|e| RemoteSessionError::Protocol(e.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

pub fn panetiere_feedback(
    protocol: RemoteProtocol,
    message: &[u8],
) -> Result<Option<ProtocolAction>, RemoteSessionError> {
    let wire = decode_native(message)?;
    Ok(match (protocol, wire) {
        (RemoteProtocol::Panetiere, PanetiereWire::SetBatch { round, data }) => Some(
            ProtocolAction::Panetiere(PanetiereAction::AcceptReceiptBatch { round, batch: data }),
        ),
        (RemoteProtocol::ScheduledPanetiere, PanetiereWire::SetBatch { round, data }) => {
            Some(ProtocolAction::ScheduledPanetiere(
                ScheduledPanetiereAction::AcceptReceiptBatch { round, batch: data },
            ))
        }
        (RemoteProtocol::ScheduledPanetiere, PanetiereWire::Reservations { .. }) => Some(
            ProtocolAction::ScheduledPanetiere(ScheduledPanetiereAction::AcceptReservations {
                message: message.to_vec(),
            }),
        ),
        _ => None,
    })
}

fn decode_native<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RemoteSessionError> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| RemoteSessionError::Protocol(e.to_string()))
}

fn require_roster(size: usize, subnet: &Subnet) -> Result<(), RemoteSessionError> {
    if size == subnet.relays.len() {
        Ok(())
    } else {
        Err(RemoteSessionError::IncompleteRoster)
    }
}

fn consensus_roster(
    mode: SetFormation,
    keys: &[(Pubkey, ExchangePublicKeyWire)],
    subnet: &Subnet,
) -> Result<Option<Vec<panetiere::sig::VerifyingKey>>, RemoteSessionError> {
    if mode == SetFormation::Consensus {
        crate::panetiere::set_roster(keys, subnet)
            .map(Some)
            .ok_or(RemoteSessionError::IncompleteRoster)
    } else {
        Ok(None)
    }
}

fn validate_config(subnet: &Subnet, starting_round: Round) -> Result<(), RemoteSessionError> {
    let n = subnet.relays.len();
    if !(1..=32).contains(&n)
        || starting_round >= u32::MAX as u64
        || subnet.relays.iter().collect::<BTreeSet<_>>().len() != n
    {
        return Err(RemoteSessionError::InvalidConfig);
    }
    let (bytes, estimate, min, max, threshold) = match &subnet.protocol {
        ProtocolConfig::Panetiere(c) => (
            c.message_size,
            c.estimated_messages,
            c.client_set_min,
            c.client_set_max,
            c.threshold,
        ),
        ProtocolConfig::ScheduledPanetiere(c) => {
            if c.message_size > u16::MAX as usize || c.message_size > c.vector_bytes {
                return Err(RemoteSessionError::InvalidConfig);
            }
            (
                c.vector_bytes,
                c.estimated_messages,
                c.client_set_min,
                c.client_set_max,
                c.threshold,
            )
        }
        ProtocolConfig::Adcnet(c) => (
            c.max_payload_bytes,
            c.estimated_messages,
            c.client_set_min,
            c.client_set_max,
            1,
        ),
        ProtocolConfig::ScheduledAdcnet(c) => {
            if c.message_length % 1024 != 0 || c.min_message_size as usize > c.message_length {
                return Err(RemoteSessionError::InvalidConfig);
            }
            (
                c.message_length,
                c.auction_slots,
                c.client_set_min,
                c.client_set_max,
                1,
            )
        }
        ProtocolConfig::Noop(_) => return Err(RemoteSessionError::UnsupportedProtocol),
    };
    if bytes == 0
        || estimate == 0
        || estimate > 4096
        || max == 0
        || max > 65536
        || min > max
        || threshold == 0
        || threshold as usize > n
        || bytes.saturating_mul(estimate as usize) > 1024 * 1024
    {
        return Err(RemoteSessionError::InvalidConfig);
    }
    let largest_message = match &subnet.protocol {
        ProtocolConfig::Panetiere(c) => crate::panetiere::max_wire_estimate(
            c.message_size,
            c.estimated_messages,
            c.client_set_max,
            n,
            c.threshold,
            c.encoding,
            c.set_formation,
        ),
        ProtocolConfig::ScheduledPanetiere(c) => crate::panetiere_scheduled::max_wire_estimate(
            c.vector_bytes,
            c.estimated_messages,
            c.client_set_max,
            n,
            c.threshold,
            c.set_formation,
        ),
        ProtocolConfig::Adcnet(c) => crate::adcnet::max_wire_estimate(
            c.max_payload_bytes,
            c.estimated_messages,
            c.client_set_max,
            n,
        ),
        ProtocolConfig::ScheduledAdcnet(c) => crate::adcnet::scheduled_max_wire_estimate(c, n),
        ProtocolConfig::Noop(_) => unreachable!(),
    };
    let fanout = match subnet.protocol {
        ProtocolConfig::Panetiere(_) | ProtocolConfig::ScheduledPanetiere(_) => 1 + 2 * n,
        _ => 1,
    };
    if largest_message.saturating_mul(fanout) > 15 * 1024 * 1024 {
        return Err(RemoteSessionError::InvalidConfig);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, Error, PartialEq, Eq)]
pub enum RemoteSessionError {
    #[error("session is closed")]
    Closed,
    #[error("unsupported remote protocol")]
    UnsupportedProtocol,
    #[error("action belongs to another protocol")]
    WrongProtocol,
    #[error("invalid or oversized protocol configuration")]
    InvalidConfig,
    #[error("relay exchange-key roster is incomplete")]
    IncompleteRoster,
    #[error("round is out of order or exceeds protocol limits")]
    RoundOrder,
    #[error("round was already finalized with different inputs")]
    RoundConflict,
    #[error("request sequence was reused with different input")]
    RequestConflict,
    #[error("expected request sequence {expected}")]
    RequestSequence { expected: u64 },
    #[error("request sequence exhausted")]
    SequenceExhausted,
    #[error("payload exceeds protocol capacity")]
    PayloadTooLarge,
    #[error("pending message queue is full")]
    QueueFull,
    #[error("{0}")]
    Protocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdcnetConfig, Encoding, PanetiereConfig, ScheduledAdcnetConfig, ScheduledPanetiereConfig,
    };
    use crate::panetiere::{PanetiereServerSession, SetMode};
    use crate::panetiere_scheduled::ScheduledPanetiereServerSession;
    use crate::session::{GoodClients, Session};
    use std::collections::HashMap;
    use std::time::Instant;

    fn fixture(protocol: ProtocolConfig) -> (RemoteAttestedSession, Subnet, Vec<Identity>) {
        let mut ids: Vec<_> = (0..3).map(|_| Identity::generate()).collect();
        ids.sort_by_key(Identity::pubkey);
        let subnet = Subnet::new(0, ids.iter().map(Identity::pubkey).collect(), protocol);
        let keys: Vec<_> = ids
            .iter()
            .map(|id| (id.pubkey(), id.exchange_keys()))
            .collect();
        let session = RemoteAttestedSession::developer(&subnet, &keys, 0).unwrap();
        (session, subnet, ids)
    }

    fn call(session: &mut RemoteAttestedSession, action: ProtocolAction) -> Vec<Vec<u8>> {
        session
            .execute(session.status().next_request, action)
            .unwrap()
    }

    fn pan_config() -> PanetiereConfig {
        PanetiereConfig {
            message_size: 64,
            estimated_messages: 1,
            client_set_max: 1,
            encoding: Encoding::Mse,
            ..Default::default()
        }
    }

    fn adc_config() -> AdcnetConfig {
        AdcnetConfig {
            round_duration_ms: 1000,
            max_payload_bytes: 64,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            aggregation: None,
        }
    }

    #[test]
    fn remote_panetiere_receipts_enable_native_repair() {
        let cfg = PanetiereConfig {
            set_formation: SetFormation::Consensus,
            ..pan_config()
        };
        let (mut session, _, ids) = fixture(ProtocolConfig::Panetiere(cfg.clone()));
        let (channel, pp) = crate::panetiere::params_for(&cfg, ids.len());
        let roster = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (panetiere::protocol::ServerId(i as u32), id.pubkey()))
            .collect();
        let mut server = PanetiereServerSession::new(
            pp,
            channel,
            panetiere::protocol::ServerId(0),
            ids[0].clone(),
            SetMode::Consensus {
                publisher: ids[0].pubkey(),
            },
            roster,
        );
        server.set_consensus_keys(
            ids[0].exchange().set_signing_key().clone(),
            ids.iter()
                .map(|id| id.exchange().set_verifying_key())
                .collect(),
        );
        let messages = call(
            &mut session,
            ProtocolAction::Panetiere(PanetiereAction::FinalizeRound {
                round: 0,
                payload: Some(b"repair".to_vec()),
            }),
        );
        let repair = ProtocolAction::Panetiere(PanetiereAction::BuildRepair { round: 0 });
        assert!(call(&mut session, repair.clone()).is_empty());
        server.begin_round(0, Instant::now());
        for bytes in messages {
            server.on_inbound(Identity::generate().pubkey(), bytes);
        }
        let mut accepted = false;
        for bytes in server.checkpoint(0, 2, Instant::now()) {
            if let Some(action) = panetiere_feedback(RemoteProtocol::Panetiere, &bytes).unwrap() {
                let ProtocolAction::Panetiere(PanetiereAction::AcceptReceiptBatch { round, batch }) =
                    &action
                else {
                    unreachable!()
                };
                let mut forged = batch.clone();
                *forged.last_mut().unwrap() ^= 1;
                let sequence = session.status().next_request;
                assert!(session
                    .execute(
                        sequence,
                        ProtocolAction::Panetiere(PanetiereAction::AcceptReceiptBatch {
                            round: *round,
                            batch: forged
                        },)
                    )
                    .is_err());
                call(&mut session, action);
                accepted = true;
            }
        }
        assert!(accepted);
        let fragments = call(&mut session, repair.clone());
        assert!(!fragments.is_empty());
        assert_eq!(call(&mut session, repair), fragments);
        for bytes in fragments {
            server.on_inbound(Identity::generate().pubkey(), bytes);
        }
    }

    #[test]
    fn configuration_and_queue_limits_fail_explicitly() {
        let relay = Identity::generate();
        let keys = vec![(relay.pubkey(), relay.exchange_keys())];
        let mut cfg = adc_config();
        cfg.estimated_messages = u32::MAX;
        let subnet = Subnet::new(0, vec![relay.pubkey()], ProtocolConfig::Adcnet(cfg));
        assert!(matches!(
            RemoteAttestedSession::developer(&subnet, &keys, 0),
            Err(RemoteSessionError::InvalidConfig)
        ));
        let cfg = ScheduledAdcnetConfig {
            round_duration_ms: 200,
            message_length: 1024,
            auction_slots: 16,
            min_message_size: 1,
            client_set_min: 0,
            client_set_max: 8,
        };
        let (mut session, _, _) = fixture(ProtocolConfig::ScheduledAdcnet(cfg));
        let action =
            ProtocolAction::ScheduledAdcnet(ScheduledAdcnetAction::ScheduleMessageForNextRound {
                payload: vec![1],
                bid: 1,
            });
        for _ in 0..64 {
            call(&mut session, action.clone());
        }
        assert_eq!(
            session.execute(session.status().next_request, action),
            Err(RemoteSessionError::QueueFull)
        );
    }

    #[test]
    fn retries_preserve_outputs_and_reject_new_inputs_for_finalized_rounds() {
        let (mut session, _, _) = fixture(ProtocolConfig::Adcnet(adc_config()));
        let action = ProtocolAction::Adcnet(AdcnetAction::Contribute {
            round: 0,
            payload: Some(b"native".to_vec()),
        });
        let first = session.execute(0, action.clone()).unwrap();
        assert_eq!(session.execute(0, action.clone()).unwrap(), first);
        assert_eq!(call(&mut session, action.clone()), first);
        let changed = ProtocolAction::Adcnet(AdcnetAction::Contribute {
            round: 0,
            payload: Some(b"different".to_vec()),
        });
        assert_eq!(
            session.execute(1, changed.clone()),
            Err(RemoteSessionError::RequestConflict)
        );
        assert_eq!(
            session.execute(2, changed),
            Err(RemoteSessionError::RoundConflict)
        );
        assert_eq!(
            session.execute(0, action),
            Err(RemoteSessionError::RequestSequence { expected: 3 })
        );
        let malformed = ProtocolAction::Adcnet(AdcnetAction::Contribute {
            round: 1,
            payload: Some(vec![0; 65]),
        });
        assert_eq!(
            session.execute(3, malformed),
            Err(RemoteSessionError::PayloadTooLarge)
        );
        assert!(!call(
            &mut session,
            ProtocolAction::Adcnet(AdcnetAction::Contribute {
                round: 1,
                payload: None,
            })
        )
        .is_empty());
        session.close();
        assert!(session.status().closed);
        assert!(session.client.is_none());
    }

    #[test]
    fn remote_panetiere_outputs_pass_native_relay_verification() {
        let (mut session, subnet, ids) = fixture(ProtocolConfig::Panetiere(pan_config()));
        let ProtocolConfig::Panetiere(cfg) = &subnet.protocol else {
            unreachable!()
        };
        let (channel, pp) = crate::panetiere::params_for(cfg, ids.len());
        let roster: HashMap<_, _> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (panetiere::protocol::ServerId(i as u32), id.pubkey()))
            .collect();
        let participant = session.status().participant;
        let mut servers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let mut server = PanetiereServerSession::new(
                    pp.clone(),
                    channel.clone(),
                    panetiere::protocol::ServerId(i as u32),
                    id.clone(),
                    SetMode::SelfDerived,
                    roster.clone(),
                );
                server.set_good_clients(GoodClients::new(move |pk| *pk == participant));
                server
            })
            .collect();
        call(
            &mut session,
            ProtocolAction::Panetiere(PanetiereAction::PrepareRound { round: 0 }),
        );
        let payload = b"remote panetiere".to_vec();
        let output = call(
            &mut session,
            ProtocolAction::Panetiere(PanetiereAction::FinalizeRound {
                round: 0,
                payload: Some(payload.clone()),
            }),
        );
        let forwarder = Identity::generate().pubkey();
        for server in &mut servers {
            for bytes in &output {
                server.on_inbound(forwarder, bytes.clone());
            }
        }
        let now = Instant::now();
        let shares: Vec<_> = servers.iter_mut().map(|s| s.end_round(0, now)).collect();
        for (i, server) in servers.iter_mut().enumerate() {
            for (j, outcome) in shares.iter().enumerate() {
                if i != j {
                    for bytes in &outcome.outbound {
                        server.on_inbound(ids[j].pubkey(), bytes.clone());
                    }
                }
            }
        }
        assert!(servers
            .iter_mut()
            .flat_map(|s| s.end_round(1, now).decoded)
            .any(|bytes| bytes.starts_with(&payload)));
    }

    #[test]
    fn remote_adcnet_outputs_pass_native_relay_verification() {
        let cfg = adc_config();
        let (mut session, _, ids) = fixture(ProtocolConfig::Adcnet(cfg.clone()));
        let participant = session.status().participant;
        let leader = ids[0].pubkey();
        let roster: Vec<_> = ids.iter().map(Identity::pubkey).collect();
        let mut servers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let mut server = crate::adcnet::AdcnetServerSession::new(
                    crate::adcnet::one_round_config(&cfg),
                    adcnet::crypto::ServerId(i as u32),
                    id.to_adcnet_signing_key(),
                    id.exchange().clone(),
                    ids.len(),
                    roster.clone(),
                    0,
                    8,
                    i == 0,
                    leader,
                    None,
                );
                server.set_good_clients(GoodClients::new(move |pk| *pk == participant));
                server
            })
            .collect();
        let forwarder = Identity::generate().pubkey();
        let payload = b"remote adcnet".to_vec();
        let mut decoded = Vec::new();
        for round in 0..8 {
            let messages = call(
                &mut session,
                ProtocolAction::Adcnet(AdcnetAction::Contribute {
                    round,
                    payload: (round == 0).then(|| payload.clone()),
                }),
            );
            for server in &mut servers {
                for bytes in &messages {
                    server.on_inbound(forwarder, bytes.clone());
                    server.on_inbound(forwarder, bytes.clone());
                }
            }
            let outcomes: Vec<_> = servers
                .iter_mut()
                .map(|s| s.end_round(round, Instant::now()))
                .collect();
            for (i, outcome) in outcomes.into_iter().enumerate() {
                decoded.extend(outcome.decoded);
                for server in &mut servers {
                    for bytes in &outcome.outbound {
                        server.on_inbound(ids[i].pubkey(), bytes.clone());
                    }
                }
            }
        }
        assert!(decoded.contains(&payload));
    }

    #[test]
    fn remote_scheduled_panetiere_verifies_reservations_and_fulfils_them() {
        let cfg = ScheduledPanetiereConfig {
            message_size: 64,
            vector_bytes: 128,
            estimated_messages: 1,
            client_set_max: 1,
            ..Default::default()
        };
        let (mut session, _, ids) = fixture(ProtocolConfig::ScheduledPanetiere(cfg.clone()));
        let (channel, pp) = crate::panetiere_scheduled::params_for(&cfg, ids.len());
        let leader = ids[0].pubkey();
        let roster: HashMap<_, _> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (panetiere::protocol::ServerId(i as u32), id.pubkey()))
            .collect();
        let mut servers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                ScheduledPanetiereServerSession::new(
                    pp.clone(),
                    channel.clone(),
                    cfg.vector_bytes,
                    panetiere::protocol::ServerId(i as u32),
                    id.clone(),
                    if i == 0 {
                        SetMode::Leader
                    } else {
                        SetMode::Follower { leader }
                    },
                    leader,
                    roster.clone(),
                    Default::default(),
                )
            })
            .collect();
        let payload = b"scheduled remote panetiere".to_vec();
        call(
            &mut session,
            ProtocolAction::ScheduledPanetiere(ScheduledPanetiereAction::ReserveMessage {
                payload: payload.clone(),
            }),
        );
        let forwarder = Identity::generate().pubkey();
        let now = Instant::now();
        let mut decoded = Vec::new();
        let mut checked_forgery = false;
        for round in 0..7 {
            call(
                &mut session,
                ProtocolAction::ScheduledPanetiere(ScheduledPanetiereAction::AdvanceRound {
                    round,
                }),
            );
            call(
                &mut session,
                ProtocolAction::ScheduledPanetiere(ScheduledPanetiereAction::PrepareRound {
                    round,
                }),
            );
            let messages = call(
                &mut session,
                ProtocolAction::ScheduledPanetiere(ScheduledPanetiereAction::FinalizeRound {
                    round,
                }),
            );
            for server in &mut servers {
                server.begin_round(round, now);
                for bytes in &messages {
                    server.on_inbound(forwarder, bytes.clone());
                }
            }
            let announcements = servers[0].checkpoint(round, 3, now);
            for server in &mut servers[1..] {
                for bytes in &announcements {
                    server.on_inbound(leader, bytes.clone());
                }
            }
            let outcomes: Vec<_> = servers
                .iter_mut()
                .map(|s| s.end_round(round, now))
                .collect();
            for (i, outcome) in outcomes.into_iter().enumerate() {
                decoded.extend(outcome.decoded);
                for bytes in outcome.outbound {
                    if let Some(action) =
                        panetiere_feedback(RemoteProtocol::ScheduledPanetiere, &bytes).unwrap()
                    {
                        if !checked_forgery {
                            let mut forged = bytes.clone();
                            *forged.last_mut().unwrap() ^= 1;
                            let sequence = session.status().next_request;
                            assert!(session
                                .execute(
                                    sequence,
                                    ProtocolAction::ScheduledPanetiere(
                                        ScheduledPanetiereAction::AcceptReservations {
                                            message: forged
                                        },
                                    )
                                )
                                .is_err());
                            checked_forgery = true;
                        }
                        call(&mut session, action);
                    }
                    for (j, server) in servers.iter_mut().enumerate() {
                        if i != j {
                            server.on_inbound(ids[i].pubkey(), bytes.clone());
                        }
                    }
                }
            }
        }
        assert!(checked_forgery);
        assert!(decoded.iter().any(|bytes| bytes.starts_with(&payload)));
    }

    #[test]
    fn remote_scheduled_adcnet_uses_native_auction_and_signed_broadcasts() {
        let cfg = ScheduledAdcnetConfig {
            round_duration_ms: 200,
            message_length: 1024,
            auction_slots: 16,
            min_message_size: 1,
            client_set_min: 0,
            client_set_max: 8,
        };
        let (mut session, _, ids) = fixture(ProtocolConfig::ScheduledAdcnet(cfg.clone()));
        let leader = ids[0].pubkey();
        let peers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                (
                    adcnet::crypto::ServerId(i as u32),
                    id.to_adcnet_public_key(),
                )
            })
            .collect();
        let mut servers: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                crate::adcnet::ScheduledAdcnetServerSession::new(
                    crate::adcnet::scheduled_config(&cfg),
                    adcnet::crypto::ServerId(i as u32),
                    id.to_adcnet_signing_key(),
                    adcnet::crypto::ExchangePrivateKey::from_bytes(&id.exchange().scalar_bytes())
                        .unwrap(),
                    &[],
                    &peers,
                    1,
                    leader,
                )
            })
            .collect();
        let mut watch = crate::adcnet::ScheduledAdcnetWatchSession::new(&cfg, leader);
        for payload in [b"first".to_vec(), b"second".to_vec()] {
            call(
                &mut session,
                ProtocolAction::ScheduledAdcnet(
                    ScheduledAdcnetAction::ScheduleMessageForNextRound { payload, bid: 1 },
                ),
            );
        }
        let now = Instant::now();
        let mut decoded = Vec::new();
        let mut checked_forgery = false;
        for round in 0..5 {
            call(
                &mut session,
                ProtocolAction::ScheduledAdcnet(ScheduledAdcnetAction::AdvanceToRound {
                    round: round as i64 + 1,
                }),
            );
            let messages = call(
                &mut session,
                ProtocolAction::ScheduledAdcnet(ScheduledAdcnetAction::MessagesForCurrentRound),
            );
            for server in &mut servers {
                server.begin_round(round, now);
            }
            watch.begin_round(round, now);
            for bytes in messages {
                servers[0].on_inbound(Identity::generate().pubkey(), bytes);
            }
            let sets = servers[0].checkpoint(round, 1, now);
            let mut partials = Vec::new();
            for server in &mut servers {
                for bytes in &sets {
                    partials.extend(server.on_inbound(leader, bytes.clone()));
                }
            }
            let mut broadcasts = Vec::new();
            for bytes in partials {
                broadcasts.extend(servers[0].on_inbound(leader, bytes));
            }
            broadcasts.extend(servers[0].end_round(round, now).outbound);
            for bytes in broadcasts {
                if !checked_forgery {
                    let mut forged = bytes.clone();
                    *forged.last_mut().unwrap() ^= 1;
                    let sequence = session.status().next_request;
                    assert!(session
                        .execute(
                            sequence,
                            ProtocolAction::ScheduledAdcnet(
                                ScheduledAdcnetAction::ProcessRoundBroadcast { message: forged },
                            )
                        )
                        .is_err());
                    checked_forgery = true;
                }
                call(
                    &mut session,
                    ProtocolAction::ScheduledAdcnet(ScheduledAdcnetAction::ProcessRoundBroadcast {
                        message: bytes.clone(),
                    }),
                );
                watch.on_inbound(leader, bytes.clone());
                for server in &mut servers {
                    server.on_inbound(leader, bytes.clone());
                }
            }
            decoded.extend(watch.end_round(round, now).decoded);
        }
        assert!(checked_forgery);
        assert_eq!(decoded.len(), 2);
        assert!(decoded[0].starts_with(b"first"));
        assert!(decoded[1].starts_with(b"second"));
    }
}
