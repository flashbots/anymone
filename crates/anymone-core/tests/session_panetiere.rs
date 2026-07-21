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
use anymone_core::panetiere::{
    PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, SetMode,
};
use anymone_core::faults::{Attribution, FaultKind};
use anymone_core::session::{Misbehavior, Session};
use anymone_core::{Identity, Pubkey, ServiceEntry, ServiceTag};

use panetiere::mse::{MseEncoding, MseParams};
use panetiere::pke;
use panetiere::protocol::ProtocolParams;
use panetiere::protocol::{ClientId, ServerId};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Per-server identities (sorted by pubkey, matching the runtime's slot order)
/// plus the client's view of their exchange pubkeys.
fn server_env(n: usize) -> (Vec<Identity>, Vec<Pubkey>, Vec<(ServerId, pke::PublicKey)>) {
    let mut ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    ids.sort_by_key(|i| i.pubkey());
    let pks = ids.iter().map(|i| i.pubkey()).collect();
    let xpubs = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (ServerId(i as u32), id.exchange().pke().public()))
        .collect();
    (ids, pks, xpubs)
}

fn server_pubkeys(server_pks: &[Pubkey]) -> HashMap<ServerId, Pubkey> {
    server_pks.iter().enumerate().map(|(i, pk)| (ServerId(i as u32), *pk)).collect()
}

/// MSE channel params (γ=4, δ≈3 buckets/insert, ξ for `msg_bytes`) plus a KAHE
/// `pp` whose message width holds exactly one MSE pack — what the wrapper builds.
fn channel(
    rng: &mut ChaCha20Rng,
    n_servers: usize,
    rho: usize,
    msg_bytes: usize,
) -> (MseParams, Arc<ProtocolParams>) {
    let delta = (3 * rho.max(1)).div_ceil(4);
    let xi = msg_bytes.div_ceil(2).max(1);
    // Draw the PRF key from the test's own RNG rather than a fixed constant —
    // one magic key reused everywhere can coincidentally peel-stall at a tight delta.
    let mut prf_key = [0u8; 32];
    rng.fill_bytes(&mut prf_key);
    let mse = MseParams::new(4, delta, xi, prf_key);
    let n_polys = MseEncoding::n_polys(&mse);
    let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(rng, n_servers, n_polys, 1));
    (mse, pp)
}

#[test]
fn panetiere_session_happy_path() {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let (mse, pp) = channel(&mut setup_rng, n_servers, 1, 64);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_id = ClientId(0);
    let client_pk = Identity::generate().pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(), mse.clone(), client_id, xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(), SetMode::SelfDerived, 0, server_pubkeys(&server_pks), None)
        })
        .collect();

    let payload: Vec<u8> = b"hello panetiere over the session trait".to_vec();
    client.stage(payload.clone());

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
    let decoded_bytes = &any_decoded.decoded[0];
    assert!(decoded_bytes.len() >= payload.len());
    assert_eq!(&decoded_bytes[..payload.len()], payload.as_slice());
}

/// Round-trip a payload through a committee-sized (3-server) Panetiere exactly
/// as the committee does to anonymise its config proposal. Returns the decoded
/// bytes (with trailing zero padding).
fn committee_panetiere_roundtrip(payload: &[u8]) -> Vec<u8> {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    // ρ=3, message bound matching the committee's COMMITTEE_MSG_BYTES.
    let (mse, pp) = channel(&mut setup_rng, n_servers, 3, 4096);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(), mse.clone(), ClientId(0), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(), SetMode::SelfDerived, 0, server_pubkeys(&server_pks), None)
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
    let (mse, pp) = channel(&mut setup_rng, n_servers, 1, 64);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(), mse.clone(), ClientId(0), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(), SetMode::SelfDerived, 0, server_pubkeys(&server_pks), None)
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
    let (mse, pp) = channel(&mut setup_rng, n_servers, 1, 64);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let mut client = PanetiereClientSession::new(
        pp.clone(), mse.clone(), ClientId(0), xpubs, [42u8; 32]);
    // Server 0 is the decoding leader; server 2 corrupts its share.
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                if sid.0 == 0 { SetMode::Leader } else { SetMode::SelfDerived },
                0,
                server_pubkeys(&server_pks),
                None,
            )
        })
        .collect();
    servers[2].set_misbehavior(Some(Misbehavior::CorruptShare));
    let mut monitor = PanetiereObserverSession::new(server_pks.clone(), Some(server_pks[0]), 2);

    let payload = b"integrity-checked payload".to_vec();
    client.stage(payload.clone());
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
    for (j, o) in mid.iter().enumerate() {
        for m in &o.outbound {
            monitor.on_inbound(server_pks[j], m.clone());
        }
    }
    let faults = monitor.end_round(0, now).faults;
    let finals: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    let leader = &finals[0];

    let decoded = leader
        .decoded
        .iter()
        .find(|d| d.iter().any(|b| *b != 0))
        .expect("leader decodes from the honest shares despite the bad one");
    assert_eq!(&decoded[..payload.len()], payload.as_slice());

    assert_eq!(faults.len(), 1, "one integrity fault, got {:?}", faults);
    let fault = &faults[0];
    assert_eq!(fault.kind, FaultKind::Integrity);
    assert_eq!(fault.attribution, Attribution::Peers(vec![server_pks[2]]));
    assert!(!fault.evidence.is_empty(), "evidence is the offending ServerPublic bytes");
}

/// Several clients sending DISTINCT real messages in the SAME round, plus cover
/// clients, must all decode — the MSE peels each insert out of the summed
/// plaintext (a single summed buffer would lose all but one). Cover adds nothing.
#[test]
fn panetiere_concurrent_clients_all_decode() {
    let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
    let n_servers = 3;
    let active = 4usize;
    let cover = 2usize;
    let total = active + cover;
    let (mse, pp) = channel(&mut setup_rng, n_servers, active, 64);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pks: Vec<Pubkey> = (0..total).map(|_| Identity::generate().pubkey()).collect();
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let mut clients: Vec<PanetiereClientSession> = (0..total)
        .map(|i| {
            PanetiereClientSession::new(
                pp.clone(),
                mse.clone(),
                ClientId(i as u32),
                xpubs.clone(),
                [40 + i as u8; 32],
            )
        })
        .collect();
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(), if sid.0 == 0 { SetMode::Leader } else { SetMode::SelfDerived }, 0, server_pubkeys(&server_pks), None)
        })
        .collect();

    // First `active` clients send real messages; the rest stay idle → cover.
    let payloads: Vec<Vec<u8>> =
        (0..active).map(|i| format!("client-{i}-says-hi").into_bytes()).collect();
    for (i, p) in payloads.iter().enumerate() {
        clients[i].stage(p.clone());
    }

    let now = Instant::now();
    for (i, c) in clients.iter_mut().enumerate() {
        for m in c.begin_round(0, now) {
            for s in servers.iter_mut() {
                s.on_inbound(client_pks[i], m.clone());
            }
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
    let decoded: Vec<Vec<u8>> = finals.iter().flat_map(|o| o.decoded.clone()).collect();
    for p in &payloads {
        assert!(
            decoded.iter().any(|d| d.windows(p.len()).any(|w| w == p.as_slice())),
            "message {:?} not recovered; all concurrent messages must decode, got {} buffers",
            String::from_utf8_lossy(p),
            decoded.len(),
        );
    }
    // Cover contributes nothing: exactly `active` distinct messages come out.
    let distinct: HashSet<Vec<u8>> = decoded
        .iter()
        .map(|d| d.iter().take_while(|b| **b != 0).copied().collect())
        .collect();
    assert_eq!(distinct.len(), active, "cover must not add messages; got {}", distinct.len());
}

/// Followers must share over the *leader's* announced set (not a self-derived
/// one), so decode succeeds; and the leader refuses to decode below the min
/// client set. `run` returns how many payloads were decoded across all relays.
#[test]
fn panetiere_followers_use_leader_set_with_min_floor() {
    fn run(min_clients: u32, n_clients: usize) -> usize {
        let mut setup_rng = ChaCha20Rng::from_seed([11u8; 32]);
        let n_servers = 3;
        let (mse, pp) = channel(&mut setup_rng, n_servers, n_clients, 64);
        let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
        let client_pks: Vec<Pubkey> = (0..n_clients).map(|_| Identity::generate().pubkey()).collect();
        let (ids, server_pks, xpubs) = server_env(n_servers);
        let leader_pk = server_pks[0];

        let mut clients: Vec<PanetiereClientSession> = (0..n_clients)
            .map(|i| {
                PanetiereClientSession::new(
                    pp.clone(), mse.clone(), ClientId(i as u32),
                    xpubs.clone(), [50 + i as u8; 32],
                )
            })
            .collect();
        for (i, c) in clients.iter_mut().enumerate() {
            c.stage(format!("msg-{i}").into_bytes());
        }
        let mut servers: Vec<PanetiereServerSession> = server_ids
            .iter()
            .map(|sid| {
                let mode = if sid.0 == 0 {
                    SetMode::Leader
                } else {
                    SetMode::Follower { leader: leader_pk }
                };
                PanetiereServerSession::new(
                    pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(),
                    mode, min_clients, server_pubkeys(&server_pks), None,
                )
            })
            .collect();

        let now = Instant::now();
        for (i, c) in clients.iter_mut().enumerate() {
            for m in c.begin_round(0, now) {
                for s in servers.iter_mut() {
                    s.on_inbound(client_pks[i], m.clone());
                }
            }
        }
        // The leader announces its set at end_round(0); followers receive it and
        // share over it at end_round(1); the leader decodes at end_round(2).
        let mut decoded_total = 0usize;
        for r in 0..4u64 {
            let outs: Vec<_> = servers.iter_mut().map(|s| s.end_round(r, now)).collect();
            decoded_total += outs.iter().map(|o| o.decoded.len()).sum::<usize>();
            for i in 0..servers.len() {
                for (j, o) in outs.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    for m in &o.outbound {
                        servers[i].on_inbound(server_pks[j], m.clone());
                    }
                }
            }
        }
        decoded_total
    }
    assert!(run(2, 2) >= 1, "followers adopt the leader's set and decode at the floor");
    assert_eq!(run(3, 2), 0, "decode is refused below the min client set");
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
        .map(|id| {
            Subnet::new(
                id as u32,
                relay_pks.clone(),
                ProtocolConfig::Adcnet(AdcnetConfig {
                    round_duration_ms: 3000,
                    max_payload_bytes: 256,
                    estimated_messages: 32,
                    client_set_min: 0,
                    client_set_max: 32,
                    relay_exchange_keys: relay_xk.clone(),
                    aggregation: None,
                }),
            )
        })
        .collect();
    AnymoneRoundConfigurationBody {
        round: 1,
        epoch_unix_ms: now_unix_ms(),
        services: vec![ServiceEntry { tag: ServiceTag::from_label("anymone.chat"), pubkey: svc.pubkey() }],
        subnets,
    }
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
    let (mse, pp) = channel(&mut setup_rng, n_servers, 1, 64);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_pk = Identity::generate().pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(), mse.clone(), ClientId(0), xpubs, [42u8; 32]);
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(pp.clone(), mse.clone(), *sid, ids[sid.0 as usize].clone(), SetMode::SelfDerived, 0, server_pubkeys(&server_pks), None)
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
