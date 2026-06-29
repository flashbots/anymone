//! 1-round ADCNet `Session` tests over a tiny synchronous broadcast bus — no
//! transport, no clock. Covers the leader-centric happy path (client → leader
//! announces set → relays share → leader combines → watcher surfaces) and the
//! committee's liveness observation (healthy = silent; a silent non-leader is
//! attributed).

use std::collections::HashMap;
use std::time::Instant;

use anymone_core::adcnet::{
    AdcnetClientSession, AdcnetObserverSession, AdcnetServerSession, AdcnetWatchSession,
};
use anymone_core::session::{Attribution, FaultKind, Session};
use anymone_core::{Identity, Pubkey};

use adcnet::crypto::{ServerId, SharedKey};
use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};

fn test_config() -> OneRoundConfig {
    OneRoundConfig {
        iblt: IbltMsgParamsOwned { estimated_messages: 8, max_payload_bytes: 256 },
    }
}

#[test]
fn adcnet_session_happy_path() {
    let n_servers = 3usize;
    let cfg = test_config();

    let client_id = Identity::generate();
    let servers_id: Vec<Identity> = (0..n_servers).map(|_| Identity::generate()).collect();
    let server_ids: Vec<ServerId> = (1..=n_servers as u32).map(ServerId).collect();
    let leader_pk = servers_id[0].pubkey();

    let mut client_shared: HashMap<ServerId, SharedKey> = HashMap::new();
    for (i, sid) in server_ids.iter().enumerate() {
        client_shared.insert(*sid, client_id.exchange().ecdh(&servers_id[i].exchange_pubkey()));
    }

    let client_anymone = client_id.pubkey();
    let mut client = AdcnetClientSession::new(
        cfg.clone(),
        client_id.to_adcnet_signing_key(),
        client_shared,
        client_id.exchange_pubkey(),
        [42u8; 32],
    );
    let mut servers: Vec<AdcnetServerSession> = (0..n_servers)
        .map(|i| {
            AdcnetServerSession::new(
                cfg.clone(),
                server_ids[i],
                servers_id[i].to_adcnet_signing_key(),
                servers_id[i].exchange().clone(),
                n_servers,
                i == 0,
                leader_pk,
                None,
            )
        })
        .collect();
    let mut watch = AdcnetWatchSession::new(leader_pk);

    let payload = b"hello via one-round adcnet".to_vec();
    client.stage_message(payload.clone());
    let now = Instant::now();

    let mut bus: Vec<(Pubkey, Vec<u8>)> = Vec::new();
    let deliver = |bus: &mut Vec<(Pubkey, Vec<u8>)>, servers: &mut [AdcnetServerSession], watch: &mut AdcnetWatchSession| {
        for (from, msg) in bus.drain(..) {
            for s in servers.iter_mut() { s.on_inbound(from, msg.clone()); }
            watch.on_inbound(from, msg.clone());
        }
    };

    let mut decoded_all: Vec<Vec<u8>> = Vec::new();
    for r in 0..8u64 {
        for m in client.begin_round(r, now) { bus.push((client_anymone, m)); }
        deliver(&mut bus, &mut servers, &mut watch);
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            decoded_all.extend(out.decoded);
            for m in out.outbound { bus.push((servers_id[i].pubkey(), m)); }
        }
        decoded_all.extend(watch.end_round(r, now).decoded);
        deliver(&mut bus, &mut servers, &mut watch);
    }

    assert!(decoded_all.contains(&payload), "payload never decoded; got {decoded_all:?}");

    // Idle client: covers at rate 1.0, silent at 0.0; a staged payload always sends.
    let mk = |rate: f32| {
        let mut shared: HashMap<ServerId, SharedKey> = HashMap::new();
        for (i, sid) in server_ids.iter().enumerate() {
            shared.insert(*sid, client_id.exchange().ecdh(&servers_id[i].exchange_pubkey()));
        }
        let mut c = AdcnetClientSession::new(
            cfg.clone(),
            client_id.to_adcnet_signing_key(),
            shared,
            client_id.exchange_pubkey(),
            [7u8; 32],
        );
        c.set_cover_rate(rate);
        c
    };
    assert!(mk(0.0).begin_round(0, now).is_empty(), "rate 0 idle stays silent");
    assert!(!mk(1.0).begin_round(0, now).is_empty(), "rate 1 idle covers");
    let mut staged = mk(0.0);
    staged.stage_message(b"x".to_vec());
    assert!(!staged.begin_round(0, now).is_empty(), "staged payload always sends");
}

/// A live 1-round ADCNet subnet (one client + N relays, relay 0 the leader)
/// over a synchronous bus, with an `AdcnetObserverSession` fed all its traffic
/// — exactly what the committee does.
struct Subnet {
    client: AdcnetClientSession,
    client_pk: Pubkey,
    relays: Vec<AdcnetServerSession>,
    relay_pks: Vec<Pubkey>,
    observer: AdcnetObserverSession,
    bus: Vec<(Pubkey, Vec<u8>)>,
    now: Instant,
}

impl Subnet {
    fn new(n_servers: usize, fault_threshold: u64) -> Self {
        let cfg = test_config();
        let client_id = Identity::generate();
        let mut relay_ids: Vec<Identity> = (0..n_servers).map(|_| Identity::generate()).collect();
        relay_ids.sort_by_key(|i| i.pubkey());
        let relay_pks: Vec<Pubkey> = relay_ids.iter().map(|i| i.pubkey()).collect();
        let leader_pk = relay_pks[0];

        let mut client_shared: HashMap<ServerId, SharedKey> = HashMap::new();
        for (i, rid) in relay_ids.iter().enumerate() {
            client_shared.insert(ServerId((i + 1) as u32), client_id.exchange().ecdh(&rid.exchange_pubkey()));
        }

        let client = AdcnetClientSession::new(
            cfg.clone(),
            client_id.to_adcnet_signing_key(),
            client_shared,
            client_id.exchange_pubkey(),
            [9u8; 32],
        );
        let relays: Vec<AdcnetServerSession> = (0..n_servers)
            .map(|i| {
                AdcnetServerSession::new(
                    cfg.clone(),
                    ServerId((i + 1) as u32),
                    relay_ids[i].to_adcnet_signing_key(),
                    relay_ids[i].exchange().clone(),
                    n_servers,
                    i == 0,
                    leader_pk,
                    None,
                )
            })
            .collect();
        let observer = AdcnetObserverSession::new(relay_pks.clone(), fault_threshold);

        Subnet {
            client,
            client_pk: client_id.pubkey(),
            relays,
            relay_pks,
            observer,
            bus: Vec::new(),
            now: Instant::now(),
        }
    }

    fn deliver(&mut self) {
        for (from, msg) in self.bus.drain(..) {
            for relay in self.relays.iter_mut() { relay.on_inbound(from, msg.clone()); }
            self.observer.on_inbound(from, msg.clone());
        }
    }

    /// Run one round; `alive` lists participating relay indices. Returns the
    /// faults the observer emitted.
    fn round(&mut self, r: u64, alive: &[usize]) -> Vec<anymone_core::Fault> {
        for m in self.client.begin_round(r, self.now) { self.bus.push((self.client_pk, m)); }
        self.deliver();
        for i in 0..self.relays.len() {
            if !alive.contains(&i) { continue; }
            let out = self.relays[i].end_round(r, self.now);
            let pk = self.relay_pks[i];
            for m in out.outbound { self.bus.push((pk, m)); }
        }
        let faults = self.observer.end_round(r, self.now).faults;
        self.deliver();
        faults
    }
}

#[test]
fn observer_silent_on_healthy_subnet() {
    let mut net = Subnet::new(3, 2);
    let mut all_faults = Vec::new();
    for r in 0..16u64 {
        all_faults.extend(net.round(r, &[0, 1, 2]));
    }
    assert!(all_faults.is_empty(), "healthy subnet must not fault; got {all_faults:?}");
}

#[test]
fn observer_attributes_non_leader_silence() {
    let mut net = Subnet::new(3, 2);
    let victim = 1usize; // non-leader (leader is relay 0)
    let victim_pk = net.relay_pks[victim];

    for r in 0..8u64 {
        assert!(net.round(r, &[0, 1, 2]).is_empty(), "no fault while healthy (round {r})");
    }

    let mut faults = Vec::new();
    for r in 8..24u64 {
        faults.extend(net.round(r, &[0, 2]));
    }

    assert_eq!(faults.len(), 1, "exactly one fault expected");
    assert_eq!(faults[0].kind, FaultKind::Liveness);
    assert_eq!(faults[0].attribution, Attribution::Peers(vec![victim_pk]));
}
