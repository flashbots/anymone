//! Panetiere `Session` wrapper tests, driven directly via `Vec<u8>` buffers —
//! no transport, no clock. Covers a single round-trip, the committee's
//! config-anonymising round-trip, and a many-round no-stall run.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use anymone_core::config::{
    now_unix_ms, AdcnetConfig, AnymoneRoundConfigurationBody, ExchangePublicKeyWire, ProtocolConfig,
    Subnet,
};
use anymone_core::panetiere::{PanetiereClientSession, PanetiereServerSession};
use anymone_core::identity::ExchangeIdentity;
use anymone_core::session::{Attribution, FaultKind, Misbehavior, Session};
use anymone_core::{Identity, Pubkey, ServiceEntry, ServiceTag};

use adcnet::crypto::ExchangePublicKey;
use panetiere::codec;
use panetiere::protocol::ProtocolParams;
use panetiere::protocol::{ClientId, ServerId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Per-server exchange identities + the client's view of their pubkeys
/// (openings are sealed per server).
fn exchange_env(n: usize) -> (Vec<ExchangeIdentity>, HashMap<ServerId, ExchangePublicKey>) {
    let exchanges: Vec<ExchangeIdentity> = (0..n).map(|_| ExchangeIdentity::generate()).collect();
    let xpubs = exchanges
        .iter()
        .enumerate()
        .map(|(i, e)| (ServerId(i as u32), e.public()))
        .collect();
    (exchanges, xpubs)
}

fn server_pubkeys(server_pks: &[Pubkey]) -> HashMap<ServerId, Pubkey> {
    server_pks.iter().enumerate().map(|(i, pk)| (ServerId(i as u32), *pk)).collect()
}

#[test]
fn panetiere_session_happy_path() {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let pp = Arc::new(ProtocolParams::setup(&mut setup_rng, n_servers));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_id = ClientId(0);
    let client_pk = Identity::generate().pubkey();
    let server_pks: Vec<_> = (0..n_servers).map(|_| Identity::generate().pubkey()).collect();

    let (exchanges, xpubs) = exchange_env(n_servers);
    let mut client =
        PanetiereClientSession::new(pp.clone(), client_id, server_ids.clone(), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), *sid, 8, exchanges[sid.0 as usize].clone(), false, server_pubkeys(&server_pks), None)
        })
        .collect();

    let payload: Vec<u8> = b"hello panetiere over the session trait".to_vec();
    client.stage_message(codec::encode_raw(&payload));

    let now = Instant::now();
    let client_out = client.begin_round(0, now);
    assert_eq!(client_out.len(), 1 + n_servers, "expected 1 ClientPublic + {n_servers} Openings");

    for s in servers.iter_mut() {
        for m in &client_out {
            assert!(s.on_inbound(client_pk, m.clone()).is_empty(), "server should not respond synchronously");
        }
    }

    let mid: Vec<_> = servers.iter_mut().map(|s| s.end_round(0, now)).collect();
    for o in &mid {
        assert_eq!(o.outbound.len(), 1, "each server emits one ServerPublic");
        assert!(o.decoded.is_empty(), "decoding requires peer ServerPublics");
        assert!(o.faults.is_empty(), "no faults: {:?}", o.faults);
    }

    for i in 0..servers.len() {
        for (j, o) in mid.iter().enumerate() {
            if i == j { continue; }
            for m in &o.outbound {
                servers[i].on_inbound(server_pks[j], m.clone());
            }
        }
    }

    let final_outcomes: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    let any_decoded = final_outcomes
        .iter()
        .find(|o| !o.decoded.is_empty())
        .expect("at least one server should decode");
    // Decoded buffer is the payload plus codec zero-padding.
    let decoded_bytes = &any_decoded.decoded[0];
    assert!(decoded_bytes.len() >= payload.len());
    assert_eq!(&decoded_bytes[..payload.len()], payload.as_slice());
}

/// Round-trip a payload through a committee-sized (3-server) Panetiere exactly
/// as the committee does to anonymise its config proposal. Returns the decoded
/// bytes (with codec zero padding).
fn committee_panetiere_roundtrip(payload: &[u8]) -> Vec<u8> {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let pp = Arc::new(ProtocolParams::setup(&mut setup_rng, n_servers));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let server_pks: Vec<_> = (0..n_servers).map(|_| Identity::generate().pubkey()).collect();

    let (exchanges, xpubs) = exchange_env(n_servers);
    let mut client =
        PanetiereClientSession::new(pp.clone(), ClientId(0), server_ids.clone(), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), *sid, 8, exchanges[sid.0 as usize].clone(), false, server_pubkeys(&server_pks), None)
        })
        .collect();

    client.stage(payload.to_vec());
    let now = Instant::now();
    let client_out = client.begin_round(0, now);
    for s in servers.iter_mut() {
        for m in &client_out {
            s.on_inbound(client_pk, m.clone());
        }
    }
    let mid: Vec<_> = servers.iter_mut().map(|s| s.end_round(0, now)).collect();
    for i in 0..servers.len() {
        for (j, o) in mid.iter().enumerate() {
            if i == j { continue; }
            for m in &o.outbound {
                servers[i].on_inbound(server_pks[j], m.clone());
            }
        }
    }
    let finals: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    finals
        .into_iter()
        .find_map(|o| o.decoded.into_iter().next())
        .expect("at least one server decodes")
}

/// Round conflation repro: a client that submits **every** anymone round (what
/// the runtime and demo actually do — cover traffic plus real sends) must not
/// lose messages. Each Panetiere round spans two anymone rounds, so round `r`'s
/// client ciphertext and round `r-1`'s server share-exchange overlap; if the
/// server filed inbound into round-agnostic state, the stable client id would
/// overwrite ciphertexts and mix openings, dropping rounds. Servers exchange
/// their `ServerPublic`s with a one-round delay (as the gossip transport does).
#[test]
fn panetiere_back_to_back_rounds_lose_nothing() {
    const N_ROUNDS: u64 = 12;
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3usize;
    let pp = Arc::new(ProtocolParams::setup(&mut setup_rng, n_servers));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let server_pks: Vec<_> = (0..n_servers).map(|_| Identity::generate().pubkey()).collect();

    let (exchanges, xpubs) = exchange_env(n_servers);
    let mut client =
        PanetiereClientSession::new(pp.clone(), ClientId(0), server_ids.clone(), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), *sid, 8, exchanges[sid.0 as usize].clone(), false, server_pubkeys(&server_pks), None)
        })
        .collect();

    let now = Instant::now();
    // ServerPublics emitted at end_round(r) reach peers during round r+1.
    let mut share_bus: Vec<(anymone_core::Pubkey, Vec<u8>)> = Vec::new();
    let mut decoded: HashSet<Vec<u8>> = HashSet::new();

    for r in 0..N_ROUNDS {
        // Deliver the previous round's server shares first.
        for (from, m) in share_bus.drain(..) {
            for s in servers.iter_mut() {
                s.on_inbound(from, m.clone());
            }
        }
        // Client submits a distinct message every single round.
        client.stage(format!("msg-{r:02}").into_bytes());
        let client_out = client.begin_round(r, now);
        for s in servers.iter_mut() {
            for m in &client_out {
                s.on_inbound(client_pk, m.clone());
            }
        }
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            for m in out.outbound {
                share_bus.push((server_pks[i], m));
            }
            for d in out.decoded {
                let trimmed: Vec<u8> = d.iter().take_while(|b| **b != 0).copied().collect();
                if !trimmed.is_empty() {
                    decoded.insert(trimmed);
                }
            }
        }
    }

    // Every message except possibly the last couple (still in the decode
    // pipeline when the loop ends) must have decoded.
    for r in 0..(N_ROUNDS - 2) {
        let want = format!("msg-{r:02}").into_bytes();
        assert!(
            decoded.contains(&want),
            "round {r} message never decoded under back-to-back sends; got {} distinct",
            decoded.len()
        );
    }
}

/// A relay that submits a share which no longer matches its (valid) opening is
/// caught by the Panetiere verifier: the decoding leader still recovers the
/// payload from the honest shares (t-of-n) AND attributes a single `Integrity`
/// fault to the culprit, carrying the offending wire bytes as evidence.
#[test]
fn panetiere_corrupt_share_attributes_integrity() {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let pp = Arc::new(ProtocolParams::setup(&mut setup_rng, n_servers));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let server_pks: Vec<_> = (0..n_servers).map(|_| Identity::generate().pubkey()).collect();
    let (exchanges, xpubs) = exchange_env(n_servers);

    let mut client =
        PanetiereClientSession::new(pp.clone(), ClientId(0), server_ids.clone(), xpubs, [42u8; 32]);
    // Server 0 is the decoding leader; server 2 corrupts its share.
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                *sid,
                8,
                exchanges[sid.0 as usize].clone(),
                sid.0 == 0,
                server_pubkeys(&server_pks),
                None,
            )
        })
        .collect();
    servers[2].set_misbehavior(Some(Misbehavior::CorruptShare));

    let payload = b"integrity-checked payload".to_vec();
    client.stage_message(codec::encode_raw(&payload));
    let now = Instant::now();
    let client_out = client.begin_round(0, now);
    for s in servers.iter_mut() {
        for m in &client_out {
            s.on_inbound(client_pk, m.clone());
        }
    }
    let mid: Vec<_> = servers.iter_mut().map(|s| s.end_round(0, now)).collect();
    for i in 0..servers.len() {
        for (j, o) in mid.iter().enumerate() {
            if i == j { continue; }
            for m in &o.outbound {
                servers[i].on_inbound(server_pks[j], m.clone());
            }
        }
    }
    let finals: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    let leader = &finals[0];

    let decoded = leader
        .decoded
        .iter()
        .find(|d| d.iter().any(|b| *b != 0))
        .expect("leader decodes from the honest shares despite the bad one");
    assert_eq!(&decoded[..payload.len()], payload.as_slice());

    assert_eq!(leader.faults.len(), 1, "one integrity fault, got {:?}", leader.faults);
    let fault = &leader.faults[0];
    assert_eq!(fault.kind, FaultKind::Integrity);
    assert_eq!(fault.attribution, Attribution::Peers(vec![server_pks[2]]));
    assert!(!fault.evidence.is_empty(), "evidence is the offending ServerPublic bytes");
}

fn adcnet_config_body(n_subnets: usize) -> AnymoneRoundConfigurationBody {
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays
        .iter()
        .map(|i| (i.pubkey(), ExchangePublicKeyWire::from_key(&i.exchange_pubkey())))
        .collect();
    relay_xk.sort_by_key(|(p, _)| *p);
    let svc = Identity::generate();
    let subnets = (0..n_subnets)
        .map(|id| Subnet {
            id: id as u32,
            services: vec![ServiceEntry { tag: ServiceTag::from_label("anymone.chat"), pubkey: svc.pubkey() }],
            relays: relay_pks.clone(),
            protocol: ProtocolConfig::Adcnet(AdcnetConfig {
                round_duration_ms: 3000,
                max_payload_bytes: 256,
                estimated_messages: 32,
                client_set_min: 0,
                client_set_max: 32,
                relay_exchange_keys: relay_xk.clone(),
                aggregation: None,
            }),
        })
        .collect();
    AnymoneRoundConfigurationBody { round: 1, epoch_unix_ms: now_unix_ms(), subnets }
}

/// Reproduces the demo's "stuck at one subnet" bug at the committee layer: a
/// grown (multi-subnet) config body must survive the committee's own Panetiere
/// codec, or it never deserializes back and the grown config never publishes.
#[test]
fn committee_panetiere_carries_multi_subnet_config() {
    for n in [1usize, 2, 3] {
        let body = adcnet_config_body(n);
        let bytes = bincode::serialize(&body).expect("serialise body");
        let decoded = committee_panetiere_roundtrip(&bytes);
        let got: AnymoneRoundConfigurationBody = bincode::deserialize(&decoded).unwrap_or_else(|e| {
            panic!("{n}-subnet config body ({} bytes) did not survive the committee Panetiere: {e}", bytes.len())
        });
        assert_eq!(got, body, "config body must round-trip byte-exact through the committee Panetiere");
    }
}

/// Drive one client + N servers through many consecutive rounds, reusing the
/// same session objects exactly as the committee's lead proposer does. Every
/// staged message must decode — pinning down the committee-Panetiere stall.
#[test]
fn panetiere_fixed_seed_multiround_no_stall() {
    const N_MSGS: usize = 10;
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3usize;
    let pp = Arc::new(ProtocolParams::setup(&mut setup_rng, n_servers));
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let server_pks: Vec<_> = (0..n_servers).map(|_| Identity::generate().pubkey()).collect();

    let (exchanges, xpubs) = exchange_env(n_servers);
    let mut client =
        PanetiereClientSession::new(pp.clone(), ClientId(0), server_ids.clone(), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), *sid, 8, exchanges[sid.0 as usize].clone(), false, server_pubkeys(&server_pks), None)
        })
        .collect();

    let now = Instant::now();
    let mut bus: Vec<(anymone_core::Pubkey, Vec<u8>)> = Vec::new();
    let mut decoded: HashSet<Vec<u8>> = HashSet::new();
    let mut staged = 0usize;

    for r in 0..(N_MSGS as u64 * 2 + 8) {
        for (from, m) in bus.drain(..) {
            for s in servers.iter_mut() { s.on_inbound(from, m.clone()); }
        }
        if r % 2 == 0 && staged < N_MSGS {
            client.stage(format!("committee-proposal-{staged:02}").into_bytes());
            staged += 1;
        }
        for m in client.begin_round(r, now) {
            bus.push((client_pk, m));
        }
        for (from, m) in bus.drain(..) {
            for s in servers.iter_mut() { s.on_inbound(from, m.clone()); }
        }
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            for m in out.outbound { bus.push((server_pks[i], m)); }
            for d in out.decoded {
                let trimmed: Vec<u8> = d.iter().take_while(|b| **b != 0).copied().collect();
                if !trimmed.is_empty() { decoded.insert(trimmed); }
            }
        }
    }

    for i in 0..N_MSGS {
        let want = format!("committee-proposal-{i:02}").into_bytes();
        assert!(decoded.contains(&want), "message {i} never decoded; got {} distinct", decoded.len());
    }
}
