//! Panetiere `Session` wrapper tests, driven directly via `Vec<u8>` buffers —
//! no transport, no clock. Covers a single round-trip, the committee's
//! config-anonymising round-trip, and a many-round no-stall run.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anymone_core::config::{
    now_unix_ms, AdcnetConfig, Aggregation, AggregatorGroup, AnymoneRoundConfigurationBody,
    Encoding, PanetiereConfig, ProtocolConfig, Subnet,
};
use anymone_core::faults::{Attribution, FaultKind};
use anymone_core::panetiere::{
    params_for, PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, SetMode,
};
use anymone_core::session::{Misbehavior, Session};
use anymone_core::{Identity, Pubkey, ServiceEntry, ServiceTag};

use panetiere::pke;
use panetiere::protocol::ServerId;

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
    server_pks
        .iter()
        .enumerate()
        .map(|(i, pk)| (ServerId(i as u32), *pk))
        .collect()
}

/// A subnet carrying `set_max` clients, `rho` of them sending `msg_bytes` each.
/// MSE, not the default sketch: peeling degrades gracefully, so a decode failure
/// here means the session wiring broke, not that a round hit capacity.
fn subnet(rho: usize, msg_bytes: usize, set_max: usize) -> PanetiereConfig {
    PanetiereConfig {
        message_size: msg_bytes,
        estimated_messages: rho as u32,
        client_set_max: set_max as u32,
        encoding: Encoding::Mse,
        ..Default::default()
    }
}

#[test]
fn panetiere_session_happy_path() {
    let n_servers = 3;
    let (mse, pp) = params_for(&subnet(1, 64, 1), n_servers);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identity = Identity::generate();
    let client_pk = client_identity.pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_identity.clone(),
        xpubs,
        [42u8; 32],
    );
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                SetMode::SelfDerived,
                server_pubkeys(&server_pks),
            )
        })
        .collect();

    let payload: Vec<u8> = b"hello panetiere over the session trait".to_vec();
    client.stage(payload.clone());

    let now = Instant::now();
    let client_out = client.begin_round(0, now);
    assert_eq!(
        client_out.len(),
        1 + 2 * n_servers,
        "expected 1 ClientPublic + {n_servers} ClientSlices + {n_servers} Openings"
    );
    // The ciphertext leaves as coded shares, so the bulletin post no longer
    // carries it: it is the smallest thing the client emits, not the largest.
    let slice_len = client_out[1].len();
    assert!(
        client_out[0].len() < slice_len,
        "RS post {} should be smaller than a coded share {slice_len}",
        client_out[0].len()
    );

    for s in servers.iter_mut() {
        for m in &client_out {
            assert!(
                s.on_inbound(client_pk, m.clone()).is_empty(),
                "server should not respond synchronously"
            );
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
            if i == j {
                continue;
            }
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

    // `signature` is the last wire field, so flipping its final byte forges it.
    let mut forged = client_out[0].clone();
    *forged.last_mut().expect("non-empty public") ^= 1;
    let mut fresh: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                SetMode::SelfDerived,
                server_pubkeys(&server_pks),
            )
        })
        .collect();
    for s in fresh.iter_mut() {
        s.on_inbound(client_pk, forged.clone());
        for m in &client_out[1..] {
            s.on_inbound(client_pk, m.clone());
        }
    }
    let mid: Vec<_> = fresh.iter_mut().map(|s| s.end_round(0, now)).collect();
    for i in 0..fresh.len() {
        for (j, o) in mid.iter().enumerate() {
            if i != j {
                for m in &o.outbound {
                    fresh[i].on_inbound(server_pks[j], m.clone());
                }
            }
        }
    }
    for o in fresh.iter_mut().map(|s| s.end_round(1, now)) {
        assert!(
            o.decoded.is_empty(),
            "a public with a broken signature must not enter the canonical set"
        );
    }
}

/// Round-trip a payload through a committee-sized (3-server) Panetiere exactly
/// as the committee does to anonymise its config proposal. Returns the decoded
/// bytes (with trailing zero padding).
fn committee_panetiere_roundtrip(payload: &[u8]) -> Vec<u8> {
    let n_servers = 3;
    // ρ=3, at the committee's own message bound.
    let (mse, pp) = params_for(
        &subnet(3, anymone_core::panetiere::COMMITTEE_MSG_BYTES, 3),
        n_servers,
    );
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identity = Identity::generate();
    let client_pk = client_identity.pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_identity.clone(),
        xpubs,
        [42u8; 32],
    );
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                SetMode::SelfDerived,
                server_pubkeys(&server_pks),
            )
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
            if i == j {
                continue;
            }
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
    let n_servers = 3usize;
    let (mse, pp) = params_for(&subnet(1, 64, 1), n_servers);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identity = Identity::generate();
    let client_pk = client_identity.pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_identity.clone(),
        xpubs,
        [42u8; 32],
    );
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                SetMode::SelfDerived,
                server_pubkeys(&server_pks),
            )
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
    let n_servers = 3;
    let (mse, pp) = params_for(&subnet(1, 64, 1), n_servers);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identity = Identity::generate();
    let client_pk = client_identity.pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let mut client = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_identity.clone(),
        xpubs,
        [42u8; 32],
    );
    // Server 0 is the decoding leader; server 2 corrupts its share.
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                if sid.0 == 0 {
                    SetMode::Leader
                } else {
                    SetMode::SelfDerived
                },
                server_pubkeys(&server_pks),
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
            if i == j {
                continue;
            }
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
    assert!(
        !fault.evidence.is_empty(),
        "evidence is the offending ServerPublic bytes"
    );

    // The same relay's lane sum no longer opens against the signed roots, so
    // reconstruction names it too and finishes on the k honest lanes.
    let lane_fault = leader
        .faults
        .iter()
        .find(|f| f.kind == FaultKind::Integrity)
        .expect("the lying lane is named by the RS reconstruction");
    assert_eq!(
        lane_fault.attribution,
        Attribution::Peers(vec![server_pks[2]])
    );
    assert!(!lane_fault.evidence.is_empty());
}

/// Several clients sending DISTINCT real messages in the SAME round, plus cover
/// clients, must all decode — the MSE peels each insert out of the summed
/// plaintext (a single summed buffer would lose all but one). Cover adds nothing.
#[test]
fn panetiere_concurrent_clients_all_decode() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let n_servers = 3;
    let active = 4usize;
    let cover = 2usize;
    let total = active + cover;
    let (mse, pp) = params_for(&subnet(active, 64, total), n_servers);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identities: Vec<Identity> = (0..total).map(|_| Identity::generate()).collect();
    let client_pks: Vec<Pubkey> = client_identities.iter().map(|id| id.pubkey()).collect();
    let (ids, server_pks, xpubs) = server_env(n_servers);

    let mut clients: Vec<PanetiereClientSession> = (0..total)
        .map(|i| {
            PanetiereClientSession::new(
                pp.clone(),
                mse.clone(),
                client_identities[i].clone(),
                xpubs.clone(),
                [40 + i as u8; 32],
            )
        })
        .collect();
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                if sid.0 == 0 {
                    SetMode::Leader
                } else {
                    SetMode::SelfDerived
                },
                server_pubkeys(&server_pks),
            )
        })
        .collect();

    // First `active` clients send real messages; the rest stay idle → cover.
    let payloads: Vec<Vec<u8>> = (0..active)
        .map(|i| format!("client-{i}-says-hi").into_bytes())
        .collect();
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
            if i == j {
                continue;
            }
            for m in &o.outbound {
                servers[i].on_inbound(server_pks[j], m.clone());
            }
        }
    }
    let finals: Vec<_> = servers.iter_mut().map(|s| s.end_round(1, now)).collect();
    let decoded: Vec<Vec<u8>> = finals.iter().flat_map(|o| o.decoded.clone()).collect();
    for p in &payloads {
        assert!(
            decoded
                .iter()
                .any(|d| d.windows(p.len()).any(|w| w == p.as_slice())),
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
    assert_eq!(
        distinct.len(),
        active,
        "cover must not add messages; got {}",
        distinct.len()
    );
}

/// Followers must share over the *leader's* announced set (not a self-derived
/// one), so decode succeeds; and the leader refuses to decode below the min
/// client set. `run` returns how many payloads were decoded across all relays.
#[test]
fn panetiere_followers_use_leader_set_with_min_floor() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    fn run(min_clients: u32, n_clients: usize, client_set_max: usize) -> usize {
        let n_servers = 3;
        let cfg = PanetiereConfig {
            client_set_min: min_clients,
            ..subnet(n_clients, 64, n_clients)
        };
        let (mse, pp) = params_for(&cfg, n_servers);
        let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
        let client_identities: Vec<Identity> =
            (0..n_clients).map(|_| Identity::generate()).collect();
        let client_pks: Vec<Pubkey> = client_identities.iter().map(|id| id.pubkey()).collect();
        let (ids, server_pks, xpubs) = server_env(n_servers);
        let leader_pk = server_pks[0];

        let mut clients: Vec<PanetiereClientSession> = (0..n_clients)
            .map(|i| {
                PanetiereClientSession::new(
                    pp.clone(),
                    mse.clone(),
                    client_identities[i].clone(),
                    xpubs.clone(),
                    [50 + i as u8; 32],
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
                let mut s = PanetiereServerSession::new(
                    pp.clone(),
                    mse.clone(),
                    *sid,
                    ids[sid.0 as usize].clone(),
                    mode,
                    server_pubkeys(&server_pks),
                );
                s.set_client_set_max(client_set_max);
                s
            })
            .collect();

        let now = Instant::now();
        // Each server sees the clients in a different arrival order (as on a
        // real network) — admission must not make servers keep different
        // subsets once submitters exceed `client_set_max`.
        let msgs: Vec<Vec<Vec<u8>>> = clients.iter_mut().map(|c| c.begin_round(0, now)).collect();
        for (j, s) in servers.iter_mut().enumerate() {
            for k in 0..n_clients {
                let i = (k + j) % n_clients;
                for m in &msgs[i] {
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
    assert!(
        run(2, 2, usize::MAX) >= 1,
        "followers adopt the leader's set and decode at the floor"
    );
    assert_eq!(
        run(3, 2, usize::MAX),
        0,
        "decode is refused below the min client set"
    );
    assert!(
        run(2, 6, 4) >= 1,
        "more submitters than client_set_max must still decode a capped set"
    );
}

fn adcnet_config_body(n_subnets: usize) -> AnymoneRoundConfigurationBody {
    let relays: Vec<Identity> = (0..8).map(|_| Identity::generate()).collect();
    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays
        .iter()
        .map(|i| (i.pubkey(), i.exchange_keys()))
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
                    aggregation: Some(Aggregation {
                        replication: 1,
                        groups: (0..8)
                            .map(|g| AggregatorGroup {
                                aggregators: vec![relay_pks[g]],
                            })
                            .collect(),
                    }),
                }),
            )
        })
        .collect();
    AnymoneRoundConfigurationBody {
        round: 1,
        epoch_unix_ms: now_unix_ms(),
        services: vec![ServiceEntry {
            tag: ServiceTag::from_label("anymone.chat"),
            pubkey: svc.pubkey(),
        }],
        relay_exchange_keys: relay_xk,
        subnets,
        relay_client_addrs: vec![],
        watchers: vec![],
    }
}

/// Reproduces the demo's "stuck at one subnet" bug at the committee layer: a
/// grown (multi-subnet) config body must survive the committee's own Panetiere
/// codec, or it never deserializes back and the grown config never publishes.
/// Sized to the worst case: MAX_SUBNETS, 8 relays, max aggregator groups.
#[test]
fn committee_panetiere_carries_multi_subnet_config() {
    for n in [1usize, 3, anymone_core::scheduler_core::MAX_SUBNETS] {
        let body = adcnet_config_body(n);
        let bytes = bincode::serialize(&body).expect("serialise body");
        let decoded = committee_panetiere_roundtrip(&bytes);
        let got: AnymoneRoundConfigurationBody = bincode::deserialize(&decoded).unwrap_or_else(|e| {
            panic!("{n}-subnet config body ({} bytes) did not survive the committee Panetiere: {e}", bytes.len())
        });
        assert_eq!(
            got, body,
            "config body must round-trip byte-exact through the committee Panetiere"
        );
    }
}

/// Drive one client + N servers through many consecutive rounds, reusing the
/// same session objects exactly as the committee's lead proposer does. Every
/// staged message must decode — pinning down the committee-Panetiere stall.
#[test]
fn panetiere_fixed_seed_multiround_no_stall() {
    const N_MSGS: usize = 10;
    let n_servers = 3usize;
    let (mse, pp) = params_for(&subnet(1, 64, 1), n_servers);
    let server_ids: Vec<ServerId> = (0..n_servers as u32).map(ServerId).collect();
    let client_identity = Identity::generate();
    let client_pk = client_identity.pubkey();
    let (ids, server_pks, xpubs) = server_env(n_servers);
    let mut client = PanetiereClientSession::new(
        pp.clone(),
        mse.clone(),
        client_identity.clone(),
        xpubs,
        [42u8; 32],
    );
    let mut servers: Vec<PanetiereServerSession> = server_ids
        .iter()
        .map(|sid| {
            PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                *sid,
                ids[sid.0 as usize].clone(),
                SetMode::SelfDerived,
                server_pubkeys(&server_pks),
            )
        })
        .collect();

    let now = Instant::now();
    let mut bus: Vec<(anymone_core::Pubkey, Vec<u8>)> = Vec::new();
    let mut decoded: HashSet<Vec<u8>> = HashSet::new();
    let mut staged = 0usize;

    for r in 0..(N_MSGS as u64 * 2 + 8) {
        for (from, m) in bus.drain(..) {
            for s in servers.iter_mut() {
                s.on_inbound(from, m.clone());
            }
        }
        if r % 2 == 0 && staged < N_MSGS {
            client.stage(format!("committee-proposal-{staged:02}").into_bytes());
            staged += 1;
        }
        for m in client.begin_round(r, now) {
            bus.push((client_pk, m));
        }
        for (from, m) in bus.drain(..) {
            for s in servers.iter_mut() {
                s.on_inbound(from, m.clone());
            }
        }
        for (i, s) in servers.iter_mut().enumerate() {
            let out = s.end_round(r, now);
            for m in out.outbound {
                bus.push((server_pks[i], m));
            }
            for d in out.decoded {
                let trimmed: Vec<u8> = d.iter().take_while(|b| **b != 0).copied().collect();
                if !trimmed.is_empty() {
                    decoded.insert(trimmed);
                }
            }
        }
    }

    for i in 0..N_MSGS {
        let want = format!("committee-proposal-{i:02}").into_bytes();
        assert!(
            decoded.contains(&want),
            "message {i} never decoded; got {} distinct",
            decoded.len()
        );
    }
}

/// Consensus set formation end to end, over the checkpoint grid the driver
/// fires: bundles, batched receipts, evidence, echo, the Dolev–Strong rounds,
/// then a set every relay fixes for itself. Also covers the two attacks the
/// mode exists for — evidence handed to only one relay, and a host that boots
/// twice — asserting the verdict is the same at every relay either way.
#[test]
fn consensus_set_formation_agrees_and_excludes_a_double_boot() {
    const N: usize = 5;
    const HONEST: usize = 0;
    const LONE: usize = 1;
    const TWICE: usize = 2;
    let cfg = PanetiereConfig {
        set_formation: anymone_core::config::SetFormation::Consensus,
        ..subnet(4, 64, 8)
    };
    let (mse, pp) = params_for(&cfg, N);
    let (ids, server_pks, xpubs) = server_env(N);
    let set_pks: Vec<panetiere::sig::VerifyingKey> = ids
        .iter()
        .map(|i| i.exchange().set_verifying_key())
        .collect();
    let publisher = server_pks[0];
    let now = Instant::now();

    let mut servers: Vec<PanetiereServerSession> = (0..N)
        .map(|i| {
            let mut s = PanetiereServerSession::new(
                pp.clone(),
                mse.clone(),
                ServerId(i as u32),
                ids[i].clone(),
                SetMode::Consensus { publisher },
                server_pubkeys(&server_pks),
            );
            s.set_client_set_max(8);
            s.set_consensus_keys(ids[i].exchange().set_signing_key().clone(), set_pks.clone());
            s
        })
        .collect();

    // `TWICE`'s host runs the boot twice: two sessions, two ephemeral post
    // keys, both claiming the same client id.
    let client_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut clients: Vec<PanetiereClientSession> = (0..4)
        .map(|i| {
            let identity = client_ids[i.min(2)].clone();
            let mut c = PanetiereClientSession::new(
                pp.clone(),
                mse.clone(),
                identity,
                xpubs.clone(),
                [70 + i as u8; 32],
            );
            c.set_consensus(set_pks.clone());
            c
        })
        .collect();
    let payloads: Vec<Vec<u8>> = (0..3).map(|i| format!("consensus-{i}").into_bytes()).collect();
    for (i, p) in payloads.iter().enumerate() {
        clients[i].stage(p.clone());
    }
    clients[3].stage(b"second-boot".to_vec());

    // Submission: every relay sees every bundle, so the receipts are complete.
    for (i, c) in clients.iter_mut().enumerate() {
        let from = client_ids[i.min(2)].pubkey();
        for m in c.begin_round(0, now) {
            for s in servers.iter_mut() {
                s.on_inbound(from, m.clone());
            }
        }
    }

    // Receipts back to their own client only.
    let certs: Vec<Vec<Vec<u8>>> = servers
        .iter_mut()
        .map(|s| s.checkpoint(0, 2, now))
        .collect();
    for (j, batch) in certs.iter().enumerate() {
        for m in batch {
            for c in clients.iter_mut() {
                c.on_inbound(server_pks[j], m.clone());
            }
        }
    }

    // Evidence: the honest client reaches every certifier, `LONE` reaches one
    // relay only, and both of `TWICE`'s boots reach disjoint halves.
    for (i, c) in clients.iter_mut().enumerate() {
        let from = client_ids[i.min(2)].pubkey();
        for (p, m) in c.checkpoint(0, 3, now).into_iter().enumerate() {
            match i {
                LONE => {
                    if p == 0 {
                        servers[0].on_inbound(from, m);
                    }
                }
                TWICE => {
                    if p < N / 2 {
                        servers[p].on_inbound(from, m);
                    }
                }
                3 => {
                    if p >= N / 2 {
                        servers[p].on_inbound(from, m);
                    }
                }
                _ => {
                    for s in servers.iter_mut() {
                        s.on_inbound(from, m.clone());
                    }
                }
            }
        }
    }

    // Each lane publishes its batch, then the relay rounds carry it.
    let mut bus: Vec<(Pubkey, Vec<u8>)> = Vec::new();
    for (j, s) in servers.iter_mut().enumerate() {
        for m in s.checkpoint(0, 2, now) {
            bus.push((server_pks[j], m));
        }
    }
    for ds in 1..=anymone_core::client_set::relay_rounds(&pp) {
        let batch = std::mem::take(&mut bus);
        for (j, s) in servers.iter_mut().enumerate() {
            for (from, m) in &batch {
                if *from != server_pks[j] {
                    s.on_inbound(*from, m.clone());
                }
            }
            for m in s.checkpoint(0, 3 + ds as u8, now) {
                bus.push((server_pks[j], m));
            }
        }
    }

    // Sets are fixed inside `end_round` and published as shares; one observer
    // per relay reads back the set that relay actually shared over.
    let outs: Vec<Vec<Vec<u8>>> = servers
        .iter_mut()
        .map(|s| s.end_round(0, now).outbound)
        .collect();
    let sets: Vec<Vec<u32>> = outs
        .iter()
        .enumerate()
        .map(|(j, out)| {
            let mut obs = PanetiereObserverSession::new(server_pks.clone(), None, 2);
            for m in out {
                obs.on_inbound(server_pks[j], m.clone());
            }
            let (_, clients) = obs
                .latest_clients()
                .unwrap_or_else(|| panic!("relay {j} published no share"));
            let mut c = clients.to_vec();
            c.sort();
            c
        })
        .collect();
    assert!(
        sets.windows(2).all(|w| w[0] == w[1]),
        "relays disagreed on the consensus set: {sets:?}"
    );
    let set = &sets[0];
    let cid = |i: usize| anymone_core::panetiere::client_id_from_pubkey(client_ids[i].pubkey()).0;
    assert!(
        set.contains(&cid(HONEST)),
        "the client every relay saw must be in"
    );
    assert!(
        set.contains(&cid(LONE)),
        "evidence handed to one relay must still reach every set"
    );
    assert!(
        !set.contains(&cid(TWICE)),
        "a host that finished two boots must be excluded"
    );

    // Decode lands a round later, off the peers' shares.
    for (i, out) in outs.iter().enumerate() {
        for (j, s) in servers.iter_mut().enumerate() {
            if i == j {
                continue;
            }
            for m in out {
                s.on_inbound(server_pks[i], m.clone());
            }
        }
    }
    let decoded: Vec<Vec<u8>> = servers[0].end_round(1, now).decoded;
    for (i, p) in payloads.iter().enumerate().take(2) {
        assert!(
            decoded.iter().any(|d| d.windows(p.len()).any(|w| w == &p[..])),
            "payload {i} not decoded from the consensus set"
        );
    }
}
