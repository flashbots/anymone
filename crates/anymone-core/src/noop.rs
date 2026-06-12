//! Noop anonymous broadcast: no crypto. Every client message becomes part of
//! the round output.
//!
//! Used for bringing up the runtime, pipe, and libp2p layers before any
//! cryptography is involved. If a Noop subnet misbehaves, the bug isn't in
//! panetiere/adcnet — it's in the runtime, the wire format, or the transport.

use std::time::Instant;

use crate::config::{NoopConfig, Round};
use crate::session::{Attribution, Fault, FaultKind, PeerId, RoundOutcome, Session};

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
    /// (M2) calls this; tests can call it directly.
    pub fn stage(&mut self, payload: Vec<u8>) {
        self.pending = Some(payload);
    }
}

impl Session for NoopClientSession {
    fn begin_round(&mut self, _round: Round, _now: Instant) -> Vec<Vec<u8>> {
        match self.pending.take() {
            Some(p) if p.len() <= self.cfg.message_size => vec![p],
            // TODO: oversize payloads are dropped silently here; the runtime is
            // responsible for fragmenting before staging.
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
