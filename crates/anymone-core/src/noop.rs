//! Noop anonymous broadcast: no crypto. Every client message becomes part of
//! the round output.
//!
//! Used for bringing up the runtime, pipe, and transport layers before any
//! cryptography is involved. If a Noop subnet misbehaves, the bug isn't in
//! panetiere/adcnet — it's in the runtime, the wire format, or the transport.

use std::time::Instant;

use crate::config::{NoopConfig, Round};
use crate::faults::{Attribution, Fault, FaultKind};
use crate::session::{PeerId, RoundOutcome, Session};

/// Upper bound on the largest per-round Noop wire message: the leader relays every
/// client's message, so the round output is up to `client_set_max` × `message_size`.
pub(crate) fn max_wire_estimate(
    message_size: usize,
    _estimated_messages: u32,
    client_set_max: u32,
    _n_relays: usize,
) -> usize {
    client_set_max as usize * message_size + 64
}

/// Client session: emits a staged payload at `begin_round`, ignores inbound,
/// produces nothing at `end_round`.
pub struct NoopClientSession {
    cfg: NoopConfig,
    pending: Option<Vec<u8>>,
}

impl NoopClientSession {
    pub fn new(cfg: NoopConfig) -> Self {
        NoopClientSession { cfg, pending: None }
    }

    /// Stage a payload to send out on the next `begin_round`. The Pipe layer
    /// calls this; tests can call it directly.
    pub fn stage(&mut self, payload: Vec<u8>) {
        self.pending = Some(payload);
    }
}

impl Session for NoopClientSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        match self.pending.take() {
            Some(p) if p.len() <= self.cfg.message_size => vec![p],
            // Pipe sends reject oversize payloads; direct session callers must
            // enforce the same limit before staging.
            Some(_) => vec![],
            None => vec![],
        }
    }

    fn on_inbound(&mut self, _from: PeerId, _payload: Vec<u8>) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        RoundOutcome::default()
    }

    fn stage(&mut self, payload: Vec<u8>) {
        self.pending = Some(payload);
    }
}

/// Server session: appends inbound to its inbox, emits the inbox as
/// `decoded` at `end_round`. Surfaces a Liveness fault if the inbox is
/// smaller than `client_set_min`.
pub struct NoopServerSession {
    cfg: NoopConfig,
    inbox: Vec<Vec<u8>>,
}

impl NoopServerSession {
    pub fn new(cfg: NoopConfig) -> Self {
        NoopServerSession {
            cfg,
            inbox: Vec::new(),
        }
    }
}

impl Session for NoopServerSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn on_inbound(&mut self, _from: PeerId, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if payload.len() <= self.cfg.message_size {
            self.inbox.push(payload);
        }
        Vec::new()
    }

    fn end_round(&mut self, _round: Round, _now: Instant) -> RoundOutcome {
        let decoded = std::mem::take(&mut self.inbox);
        let mut faults = Vec::new();
        if (decoded.len() as u32) < self.cfg.client_set_min {
            faults.push(Fault {
                kind: FaultKind::Liveness,
                attribution: Attribution::None,
                evidence: Vec::new(),
            });
        }
        RoundOutcome {
            outbound: Vec::new(),
            decoded,
            faults,
        }
    }
}

pub fn client_session(cfg: &NoopConfig) -> Box<dyn Session> {
    Box::new(NoopClientSession::new(cfg.clone()))
}

pub fn server_session(cfg: &NoopConfig) -> Box<dyn Session> {
    Box::new(NoopServerSession::new(cfg.clone()))
}

/// Self-contained Noop subnet driver. No crypto, no ingress/shares split, no
/// aggregator or leader monitor: clients and servers all share the broadcast
/// topic. The runtime dispatches here for Noop subnets.
pub(crate) async fn run_subnet(
    subnet: crate::config::Subnet,
    inner: std::sync::Arc<crate::runtime::AnymoneInner>,
    mut stage_rx: tokio::sync::mpsc::UnboundedReceiver<crate::runtime::StageMsg>,
    mut subscriptions: Vec<crate::transport::Subscription>,
    base_round: crate::config::Round,
    epoch_unix_ms: u64,
    armed: bool,
) {
    use crate::config::ProtocolConfig;
    use crate::runtime::{
        deadline_for, gossip_faults, recv_any, round_at, route_to_pipe, sync_client_round,
        SessionKey, StageMsg,
    };
    use crate::transport::{Inbound, Topic};
    use std::collections::HashMap;

    let cfg = match &subnet.protocol {
        ProtocolConfig::Noop(c) => c.clone(),
        _ => unreachable!("noop::run_subnet on a non-Noop subnet"),
    };
    let identity_pk = inner.identity.pubkey();
    let topic = Topic::Broadcast(subnet.id);

    let mut sessions: HashMap<SessionKey, Box<dyn Session>> = HashMap::new();
    let mut cover_rate = subnet.cover_rate;
    let key = if subnet.relays.contains(&identity_pk) {
        SessionKey::Server
    } else {
        SessionKey::Watch
    };
    sessions.insert(key, server_session(&cfg));

    let dur_ms = (subnet.protocol.round_duration().as_millis() as u64).max(1);
    if armed
        && !crate::runtime::arm_until_cutover(
            base_round,
            epoch_unix_ms,
            dur_ms,
            &mut stage_rx,
            &mut cover_rate,
        )
        .await
    {
        return;
    }
    let mut final_round: Option<crate::config::Round> = None;
    let now_ms = crate::config::now_unix_ms();
    let mut round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms);
    let spawn_round = round;
    let mut deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);

    sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
        client_session(&cfg)
    });
    for s in sessions.values_mut() {
        for out in s.begin_round(round, Instant::now()) {
            inner.transport.publish(topic, out).await;
        }
    }

    let mut reported = crate::runtime::ReportedFaults::default();
    loop {
        tokio::select! {
            biased;

            _ = tokio::time::sleep_until(deadline) => {
                let mut decoded_all: Vec<Vec<u8>> = Vec::new();
                let mut faults = Vec::new();
                for s in sessions.values_mut() {
                    let outcome = s.end_round(round, Instant::now());
                    for out in outcome.outbound {
                        inner.transport.publish(topic, out).await;
                    }
                    decoded_all.extend(outcome.decoded);
                    faults.extend(outcome.faults);
                }
                let n_decoded = decoded_all.len();
                for bytes in decoded_all {
                    route_to_pipe(&inner, round, &bytes);
                }
                if n_decoded > 0 {
                    let _ = inner.events.send(crate::runtime::Event::RoundDecoded {
                        round,
                        subnet: subnet.id,
                        n_messages: n_decoded,
                    });
                }
                if round >= spawn_round + crate::runtime::RECONFIG_FAULT_GRACE {
                    gossip_faults(&inner, subnet.id, identity_pk, &mut reported, faults.into_iter().map(|f| (round, f)).collect()).await;
                }

                if final_round.is_some_and(|f| round >= f) {
                    return;
                }
                let now_ms = crate::config::now_unix_ms();
                round = round_at(base_round, epoch_unix_ms, dur_ms, now_ms).max(round + 1);
                deadline = deadline_for(round, base_round, epoch_unix_ms, dur_ms, now_ms);
                sync_client_round(&inner, subnet.id, round, cover_rate, &mut sessions, || {
                    client_session(&cfg)
                });
                for s in sessions.values_mut() {
                    for out in s.begin_round(round, Instant::now()) {
                        inner.transport.publish(topic, out).await;
                    }
                }
            }

            msg = recv_any(&mut subscriptions) => {
                let Inbound { from, payload } = msg;
                for s in sessions.values_mut() {
                    for out in s.on_inbound(from, payload.clone()) {
                        inner.transport.publish(topic, out).await;
                    }
                }
            }

            Some(stage) = stage_rx.recv() => {
                match stage {
                    StageMsg::SetCoverRate(rate) => cover_rate = rate,
                    StageMsg::Shutdown => {
                        final_round.get_or_insert(round + 1);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn happy_path_one_client_three_servers() {
        let cfg = NoopConfig::default();
        let client_id = Identity::generate();
        let mut client = NoopClientSession::new(cfg.clone());
        let mut servers: Vec<NoopServerSession> = (0..3)
            .map(|_| NoopServerSession::new(cfg.clone()))
            .collect();

        let round = 0u64;
        let now = Instant::now();
        let payload = b"hello".to_vec();

        client.stage(payload.clone());
        let from_client = client.begin_round(round, now);
        assert_eq!(from_client.len(), 1);
        assert_eq!(from_client[0], payload);

        for s in &mut servers {
            for m in &from_client {
                let resp = s.on_inbound(client_id.pubkey(), m.clone());
                assert!(resp.is_empty());
            }
        }

        for s in &mut servers {
            let outcome = s.end_round(round, now);
            assert!(outcome.outbound.is_empty());
            assert!(outcome.faults.is_empty(), "no faults: {:?}", outcome.faults);
            assert_eq!(outcome.decoded, vec![payload.clone()]);
        }

        // Client end_round is a no-op.
        let client_out = client.end_round(round, now);
        assert_eq!(client_out, RoundOutcome::default());
    }

    #[test]
    fn no_clients_triggers_liveness_fault() {
        let mut cfg = NoopConfig::default();
        cfg.client_set_min = 1;
        let mut server = NoopServerSession::new(cfg);
        let outcome = server.end_round(0, Instant::now());
        assert_eq!(outcome.faults.len(), 1);
        assert_eq!(outcome.faults[0].kind, FaultKind::Liveness);
    }

    #[test]
    fn oversize_client_payload_dropped() {
        let mut cfg = NoopConfig::default();
        cfg.message_size = 4;
        let mut client = NoopClientSession::new(cfg);
        client.stage(b"too long".to_vec());
        let out = client.begin_round(0, Instant::now());
        assert!(out.is_empty());
    }

    #[test]
    fn oversize_inbound_dropped_by_server() {
        let mut cfg = NoopConfig::default();
        cfg.message_size = 4;
        cfg.client_set_min = 0;
        let mut server = NoopServerSession::new(cfg);
        server.on_inbound(Identity::generate().pubkey(), b"too long".to_vec());
        let outcome = server.end_round(0, Instant::now());
        assert!(outcome.decoded.is_empty());
    }
}
