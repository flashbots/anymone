//! Synchronous tests for the sans-IO `SchedulerCore` — the deterministic
//! replacement for the flaky full-stack committee e2e. No tokio, no timers, no
//! transport: drive the decision machine with synthetic registrations/faults
//! (escalation, healing, multisig assembly) and with real ADCNet subnet traffic
//! (capacity-driven grow/shrink).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anymone_core::adcnet::{AdcnetClientSession, AdcnetServerSession};
use anymone_core::config::{
    AdcnetConfig, AnymoneRoundConfiguration, AnymoneRoundConfigurationBody, ExchangePublicKeyWire,
    NoopConfig, ProtocolConfig,
};
use anymone_core::faults::{Attribution, Fault, FaultKind};
use anymone_core::panetiere::{
    PanetiereClientSession, PanetiereObserverSession, PanetiereServerSession, SetMode,
};
use anymone_core::scheduler_core::{
    CommitteeSig, SchedulerAction, SchedulerCore, SchedulerParams, SignedProposal,
};
use anymone_core::session::{Misbehavior, Session};
use anymone_core::{FaultReport, Identity, Pubkey, Registration, ServiceTag, TOPIC_CONFIG};

use adcnet::crypto::{ServerId, SharedKey};
use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};
use panetiere::channel::ChannelParams;
use panetiere::mse::{MseEncoding, MseParams};
use panetiere::protocol::{ProtocolParams, ServerId as PanServerId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn xkw(id: &Identity) -> ExchangePublicKeyWire {
    id.exchange_keys()
}

fn staged_proposal(actions: &[SchedulerAction]) -> Option<SignedProposal> {
    actions.iter().find_map(|a| match a {
        SchedulerAction::StageProposal(bytes) => Some(bincode::deserialize(bytes).unwrap()),
        _ => None,
    })
}

fn staged_body(actions: &[SchedulerAction]) -> Option<AnymoneRoundConfigurationBody> {
    staged_proposal(actions).map(|p| p.body)
}

/// Drive a staged proposal to publication the way the committee Panetiere +
/// gossip would: the lead signs it, then a peer's signature crosses threshold.
/// The core records it published, so the lead stops re-staging the same content.
fn enact(core: &mut SchedulerCore, committee: &[Identity], proposal: SignedProposal) {
    let canonical = proposal.body.canonical_bytes();
    let approve_bytes = proposal.body.approve_bytes();
    core.on_decoded_body(proposal);
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    let peer = &sorted[1];
    let actions = core.on_committee_sig(CommitteeSig {
        body_bytes: canonical.clone(),
        signer: peer.pubkey(),
        signature: peer.sign(&approve_bytes),
    });
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, SchedulerAction::Publish { topic, .. } if topic == TOPIC_CONFIG)),
        "enact: proposal must publish a config at threshold"
    );
}

fn proto_name(body: &AnymoneRoundConfigurationBody) -> &'static str {
    match &body.subnets[0].protocol {
        ProtocolConfig::Adcnet(_) => "adcnet",
        ProtocolConfig::Panetiere(_) => "panetiere",
        ProtocolConfig::ScheduledPanetiere(_) => "scheduled-panetiere",
        ProtocolConfig::Noop(_) => "noop",
        _ => "other",
    }
}

/// Lead core: sorted(committee)[0], so `is_lead` is true and it stages.
fn lead_core(committee: &[Identity], threshold: u32) -> SchedulerCore {
    let mut sorted: Vec<_> = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
    SchedulerCore::new(
        sorted[0].clone(),
        pks,
        threshold,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: None,
            vector_bytes: 0,
            aggregation: true,
        },
    )
}

/// Like [`lead_core`] but with a caller-chosen `message_size` — the
/// scheduled-mode upgrade/downgrade thresholds scale off it (`2x`/`0.5x`), so
/// mode-selection tests need it small enough for real test traffic to cross.
/// `escalation_grace` is generous so an unrelated honest-traffic de-escalation
/// (the original fault healing) doesn't interfere with a mode-selection test
/// running many rounds of otherwise-clean traffic.
fn lead_core_msg_size(
    committee: &[Identity],
    threshold: u32,
    message_size: usize,
) -> SchedulerCore {
    let mut sorted: Vec<_> = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
    SchedulerCore::new(
        sorted[0].clone(),
        pks,
        threshold,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 100,
            grow_at: 31,
            message_size,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: None,
            vector_bytes: 0,
            aggregation: true,
        },
    )
}

fn register_relays_and_service(core: &mut SchedulerCore, relays: &[Identity], service: &Identity) {
    for r in relays {
        core.on_registration(Registration::relay(r, xkw(r)));
    }
    core.on_registration(Registration::service(
        service,
        ServiceTag::from_label("anymone.echo"),
        xkw(service),
    ));
}

#[test]
fn renegotiates_adcnet_panetiere_adcnet() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    assert!(core.is_lead());

    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    // First tick: optimistic ADCNet with all 3 relays.
    let proposal = staged_proposal(&core.tick(0, 0)).expect("first proposal staged");
    let body = proposal.body.clone();
    assert_eq!(proto_name(&body), "adcnet");
    assert_eq!(body.subnets[0].relays.len(), 3);
    // IBLT sized to the active half, decoupled from the full anonymity bound.
    let adc = adcnet_cfg_of(&body);
    assert_eq!(adc.estimated_messages, adc.client_set_max.div_ceil(2));
    assert!(adc.estimated_messages < adc.client_set_max);

    // Once enacted, unchanged content → no further proposal (the lead re-stages
    // only until the config it proposed is published).
    enact(&mut core, &committee, proposal);
    assert!(staged_body(&core.tick(1, 0)).is_none());
    assert!(staged_body(&core.tick(2, 0)).is_none());

    // Liveness fault attributed to relay #1 (partial shares seen, #1's missing).
    let victim = relays[1].pubkey();
    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::Peers(vec![victim]),
            evidence: Vec::new(),
        }],
        0,
    );

    // Escalate to Panetiere with the victim dropped.
    let body = staged_body(&core.tick(3, 0)).expect("escalation proposal staged");
    assert_eq!(proto_name(&body), "panetiere");
    assert_eq!(body.subnets[0].relays.len(), 2);
    assert!(!body.subnets[0].relays.contains(&victim));
    // No observed traffic ⇒ capacity sits at the floor (≤ 16), so the aggregator
    // layer stays off.
    match &body.subnets[0].protocol {
        ProtocolConfig::Panetiere(c) => assert!(c.aggregation.is_none()),
        _ => unreachable!(),
    }

    // Victim re-registers → heal → back to optimistic ADCNet with 3 relays.
    core.on_registration(Registration::relay(&relays[1], xkw(&relays[1])));
    let body = staged_body(&core.tick(4, 0)).expect("heal proposal staged");
    assert_eq!(proto_name(&body), "adcnet");
    assert_eq!(body.subnets[0].relays.len(), 3);

    // Pinned core: proposes Panetiere from round 0 with zero faults, and a
    // liveness fault still sidelines the culprit — escalation bookkeeping keeps
    // running underneath the pin, only the protocol *choice* is fixed.
    let pinned_committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut sorted = pinned_committee.clone();
    sorted.sort_by_key(|i| i.pubkey());
    let pinned_pks: Vec<_> = pinned_committee.iter().map(|i| i.pubkey()).collect();
    let mut pinned = SchedulerCore::new(
        sorted[0].clone(),
        pinned_pks,
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: Some(anymone_core::SchedulerProtocol::Panetiere),
            vector_bytes: 0,
            aggregation: true,
        },
    );
    let pinned_relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let pinned_service = Identity::generate();
    register_relays_and_service(&mut pinned, &pinned_relays, &pinned_service);
    let body = staged_body(&pinned.tick(0, 0)).expect("pinned core stages on round 0");
    assert_eq!(
        proto_name(&body),
        "panetiere",
        "pin must hold with zero faults"
    );

    let pinned_victim = pinned_relays[1].pubkey();
    pinned.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::Peers(vec![pinned_victim]),
            evidence: Vec::new(),
        }],
        0,
    );
    let body = staged_body(&pinned.tick(1, 0)).expect("pinned core re-proposes after fault");
    assert_eq!(
        proto_name(&body),
        "panetiere",
        "pin must hold across a fault"
    );
    assert!(
        !body.subnets[0].relays.contains(&pinned_victim),
        "sidelining still runs under the pin"
    );

    // sideline: false — the same attributed fault is recorded but the roster
    // stays intact; the staged body keeps all 3 relays.
    let mut reporting = SchedulerCore::new(
        sorted[0].clone(),
        pinned_committee.iter().map(|i| i.pubkey()).collect(),
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: false,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: Some(anymone_core::SchedulerProtocol::Panetiere),
            vector_bytes: 0,
            aggregation: true,
        },
    );
    register_relays_and_service(&mut reporting, &pinned_relays, &pinned_service);
    let _ = reporting.tick(0, 0);
    reporting.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Integrity,
            attribution: Attribution::Peers(vec![pinned_victim]),
            evidence: Vec::new(),
        }],
        0,
    );
    let body = staged_body(&reporting.tick(1, 0)).expect("re-stage until published");
    assert_eq!(
        body.subnets[0].relays.len(),
        3,
        "sideline: false must not drop the culprit"
    );
}

#[test]
fn unattributable_fault_escalates_without_dropping() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);

    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let body = staged_body(&core.tick(0, 0)).expect("first proposal");
    assert_eq!(proto_name(&body), "adcnet");
    assert_eq!(body.subnets[0].relays.len(), 3);

    // General subnetwork fault (no output, all/none shares) — unattributable.
    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        }],
        0,
    );

    // Escalate to Panetiere but keep all 3 relays (nobody specific to drop).
    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(proto_name(&esc.body), "panetiere");
    assert_eq!(esc.body.subnets[0].relays.len(), 3);
    enact(&mut core, &committee, esc);

    // A relay re-announcing must NOT de-escalate: the general fault names no
    // culprit, so only a fault-free streak proves the cause is gone. Content
    // unchanged means no re-proposal at all.
    core.on_registration(Registration::relay(&relays[0], xkw(&relays[0])));
    assert!(staged_body(&core.tick(2, 0)).is_none());

    // Ticking well past the grace with the subnet fully silent must not heal
    // it — silence produces no fault either, but it isn't a clean round.
    for r in 3..10 {
        assert!(
            staged_body(&core.tick(r, 0)).is_none(),
            "silence must not heal the subnet"
        );
    }

    // Real signed Panetiere traffic for the grace period does heal it.
    let mut net = PanetiereSubnet::new(&relays, None);
    let mut healed = None;
    for r in 0..6u64 {
        let (wire, _, _) = net.round(r);
        for (from, bytes) in wire {
            core.on_subnet_message(0, from, bytes);
        }
        if let Some(b) = staged_body(&core.tick(10 + r, 0)) {
            healed = Some(proto_name(&b));
        }
    }
    assert_eq!(healed, Some("adcnet"));
}

/// An *integrity* offender is sidelined like a liveness fault but, unlike one,
/// stays barred from re-registration until the backoff elapses; only then does
/// re-registration heal it.
#[test]
fn integrity_offender_barred_until_backoff() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let first = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    assert_eq!(first.body.subnets[0].relays.len(), 3);
    enact(&mut core, &committee, first);

    let victim = relays[1].pubkey();
    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Integrity,
            attribution: Attribution::Peers(vec![victim]),
            evidence: Vec::new(),
        }],
        0,
    );

    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(proto_name(&esc.body), "panetiere");
    assert!(!esc.body.subnets[0].relays.contains(&victim));
    enact(&mut core, &committee, esc);

    // Re-registration within the backoff is refused — the offender stays out, so
    // the content is unchanged and (already enacted) nothing is re-staged.
    core.on_registration(Registration::relay(&relays[1], xkw(&relays[1])));
    assert!(
        staged_body(&core.tick(2, 60_000)).is_none(),
        "still sidelined within backoff"
    );

    // After the backoff, the offender entry expires and re-registration heals.
    let after = 6 * 60 * 1000 + 1;
    core.tick(3, after);
    core.on_registration(Registration::relay(&relays[1], xkw(&relays[1])));
    let body = staged_body(&core.tick(4, after)).expect("heal proposal after backoff");
    assert_eq!(proto_name(&body), "adcnet");
    assert_eq!(body.subnets[0].relays.len(), 3);
}

/// A member signs a decoded body (1 sig, below threshold → no config yet), then
/// a peer's signature pushes it over the threshold → the core must `Publish` a
/// verifying multisig. This is the path the canonical-bytes encoding bug broke.
#[test]
fn multisig_assembles_via_committee_sig() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut sorted = committee.clone();
    sorted.sort_by_key(|i| i.pubkey());
    let lead = sorted[0].clone();
    let peer = sorted[1].clone();
    let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
    let params = SchedulerParams {
        public_round_duration: Duration::from_millis(200),
        min_relays: 1,
        min_services: 1,
        fault_threshold: 2,
        escalation_grace: 5,
        grow_at: 31,
        message_size: 16,
        integrity_backoff_ms: 6 * 60 * 1000,
        sideline: true,
        renegotiate_on_fault: true,
        min_capacity: 8,
        pin: None,
        vector_bytes: 0,
        aggregation: true,
    };
    let mut core = SchedulerCore::new(lead.clone(), pks.clone(), 2, params.clone());

    let relay = Identity::generate();
    let service = Identity::generate();
    register_relays_and_service(&mut core, std::slice::from_ref(&relay), &service);

    let proposal = staged_proposal(&core.tick(0, 0)).expect("staged");
    // Re-staging the same logical round at a later wall clock must be
    // byte-identical, or members' signatures scatter across sig keys.
    let restaged = staged_proposal(&core.tick(1, 5_000)).expect("re-staged until published");
    assert_eq!(
        proposal.body.canonical_bytes(),
        restaged.body.canonical_bytes(),
        "re-staged proposal must have deterministic canonical bytes"
    );
    let body = proposal.body.clone();

    // A proposal signature must not double as a valid approval.
    assert!(
        !lead
            .pubkey()
            .verify(&body.approve_bytes(), &proposal.signature),
        "a proposal signature must not verify as a valid approval"
    );

    // The committee Panetiere decodes the body back to the lead → 1 sig, no config.
    let actions = core.on_decoded_body(proposal);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, SchedulerAction::Publish { topic, .. } if topic == TOPIC_CONFIG)),
        "must not assemble with a single signature"
    );

    // A peer's signature arrives → threshold reached → config published.
    let canonical = body.canonical_bytes();
    let peer_sig = CommitteeSig {
        body_bytes: canonical.clone(),
        signer: peer.pubkey(),
        signature: peer.sign(&body.approve_bytes()),
    };
    let actions = core.on_committee_sig(peer_sig);
    let cfg_bytes = actions
        .iter()
        .find_map(|a| match a {
            SchedulerAction::Publish { topic, bytes } if topic == TOPIC_CONFIG => {
                Some(bytes.clone())
            }
            _ => None,
        })
        .expect("config must be published once threshold signatures are in");
    let cfg: AnymoneRoundConfiguration = bincode::deserialize(&cfg_bytes).unwrap();
    cfg.verify_multisig(&pks, 2)
        .expect("assembled config verifies at threshold");

    // A restarted (fresh) core seeded from the published config resumes above
    // the network's round; an unverifiable config must not seed.
    let mut forged = cfg.clone();
    forged.signatures.clear();
    let mut fresh = SchedulerCore::new(lead.clone(), pks.clone(), 2, params.clone());
    assert!(
        !fresh.on_published_config(&forged),
        "unverifiable config must not seed"
    );

    // A multisig-valid but empty-relay body must be rejected, not panic in leader_of.
    let empty_relay_cfg = AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
        round: cfg.body.round,
        epoch_unix_ms: cfg.body.epoch_unix_ms,
        services: vec![],
        relay_exchange_keys: vec![],
        subnets: vec![anymone_core::config::Subnet::new(
            0,
            vec![],
            ProtocolConfig::Noop(NoopConfig {
                round_duration_ms: 1000,
                message_size: 256,
                client_set_min: 0,
                client_set_max: 8,
            }),
        )],
        relay_client_addrs: vec![],
        watchers: vec![],
    })
    .sign_with(&sorted.iter().collect::<Vec<_>>());
    let mut fresh_for_bad_cfg = SchedulerCore::new(lead.clone(), pks.clone(), 2, params.clone());
    assert!(
        !fresh_for_bad_cfg.on_published_config(&empty_relay_cfg),
        "multisig-valid but structurally broken (empty-relay) config must be rejected"
    );

    assert!(fresh.on_published_config(&cfg));
    register_relays_and_service(&mut fresh, std::slice::from_ref(&relay), &service);
    let reproposal = staged_proposal(&fresh.tick(0, 0)).expect("restarted lead proposes");
    assert!(
        reproposal.body.round > cfg.body.round,
        "restarted lead must propose above the adopted round"
    );

    // A seeded member rejects a lead-signed proposal below the adopted round.
    let mut member = SchedulerCore::new(peer.clone(), pks, 2, params);
    assert!(member.on_published_config(&cfg));
    register_relays_and_service(&mut member, std::slice::from_ref(&relay), &service);
    let mut stale_body = cfg.body.clone();
    stale_body.round -= 1;
    let signature = lead.sign(&stale_body.propose_bytes());
    let stale = SignedProposal {
        body: stale_body,
        proposer: lead.pubkey(),
        signature,
    };
    assert!(
        member.on_decoded_body(stale).is_empty(),
        "rollback below the seeded round must be rejected"
    );
}

#[test]
fn non_lead_core_never_stages() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut sorted: Vec<_> = committee.clone();
    sorted.sort_by_key(|i| i.pubkey());
    let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
    let mut core = SchedulerCore::new(
        sorted[2].clone(),
        pks,
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 1,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: None,
            vector_bytes: 0,
            aggregation: true,
        },
    );
    assert!(!core.is_lead());
    let r = Identity::generate();
    register_relays_and_service(&mut core, std::slice::from_ref(&r), &Identity::generate());
    assert!(staged_body(&core.tick(0, 0)).is_none());
}

#[test]
fn cover_rate_stamped_and_reproposed() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    // Default rate stamped onto every subnet.
    let first = staged_proposal(&core.tick(0, 0)).expect("first proposal staged");
    assert!(first.body.subnets.iter().all(|s| s.cover_rate == 1.0));
    assert_ne!(
        first.body.epoch_unix_ms, 0,
        "epoch must be a real wall-clock stamp, not 0"
    );
    enact(&mut core, &committee, first.clone());

    // Unchanged content → no re-propose.
    assert!(staged_body(&core.tick(1, 0)).is_none());

    // Epoch must carry forward unchanged across re-proposals.
    core.set_cover_rate(0.25);
    let reproposed = staged_proposal(&core.tick(2, 0)).expect("cover change re-proposes");
    assert!(reproposed.body.subnets.iter().all(|s| s.cover_rate == 0.25));
    assert_eq!(
        reproposed.body.epoch_unix_ms, first.body.epoch_unix_ms,
        "epoch must stay fixed across re-proposals of the same network"
    );
}

/// A live ADCNet subnet (clients + relays, relay 0 the leader) over a
/// synchronous bus, returning every wire message so it can be fed to the
/// committee core via `on_subnet_message`, exactly as the runtime would.
struct Subnet {
    clients: Vec<AdcnetClientSession>,
    client_pks: Vec<Pubkey>,
    relays: Vec<AdcnetServerSession>,
    relay_pks: Vec<Pubkey>,
    bus: Vec<(Pubkey, Vec<u8>)>,
    now: Instant,
}

impl Subnet {
    fn new(cfg: &AdcnetConfig, relay_ids: &[Identity], client_ids: &[Identity]) -> Self {
        let one_round = OneRoundConfig {
            iblt: IbltMsgParamsOwned {
                estimated_messages: cfg.estimated_messages,
                max_payload_bytes: cfg.max_payload_bytes,
            },
        };
        let mut sorted = relay_ids.to_vec();
        sorted.sort_by_key(|i| i.pubkey());
        let relay_pks: Vec<Pubkey> = sorted.iter().map(|i| i.pubkey()).collect();
        let leader_pk = relay_pks[0];

        let clients: Vec<AdcnetClientSession> = client_ids
            .iter()
            .enumerate()
            .map(|(ci, client_id)| {
                let mut client_shared: HashMap<ServerId, SharedKey> = HashMap::new();
                for (i, relay) in sorted.iter().enumerate() {
                    let xk = relay.exchange_pubkey();
                    client_shared.insert(ServerId(i as u32), client_id.exchange().ecdh(&xk));
                }
                let mut seed = [3u8; 32];
                seed[..8].copy_from_slice(&(ci as u64).to_le_bytes());
                AdcnetClientSession::new(
                    one_round.clone(),
                    client_id.to_adcnet_signing_key(),
                    client_shared,
                    client_id.exchange_pubkey(),
                    seed,
                )
            })
            .collect();
        let client_pks: Vec<Pubkey> = client_ids.iter().map(|i| i.pubkey()).collect();
        let relays: Vec<AdcnetServerSession> = (0..sorted.len())
            .map(|i| {
                AdcnetServerSession::new(
                    one_round.clone(),
                    ServerId(i as u32),
                    sorted[i].to_adcnet_signing_key(),
                    sorted[i].exchange().clone(),
                    sorted.len(),
                    relay_pks.clone(),
                    0,
                    usize::MAX,
                    i == 0,
                    leader_pk,
                    None,
                )
            })
            .collect();
        Subnet {
            clients,
            client_pks,
            relays,
            relay_pks,
            bus: Vec::new(),
            now: Instant::now(),
        }
    }

    /// Run one round; return all wire messages produced. `alive` lists
    /// participating relay indices.
    fn round(&mut self, r: u64, alive: &[usize]) -> Vec<(Pubkey, Vec<u8>)> {
        let mut produced = Vec::new();
        for (ci, client) in self.clients.iter_mut().enumerate() {
            let pk = self.client_pks[ci];
            for m in client.begin_round(r, self.now) {
                self.bus.push((pk, m.clone()));
                produced.push((pk, m));
            }
        }
        for (from, msg) in self.bus.drain(..).collect::<Vec<_>>() {
            for relay in self.relays.iter_mut() {
                relay.on_inbound(from, msg.clone());
            }
        }
        for i in 0..self.relays.len() {
            if !alive.contains(&i) {
                continue;
            }
            let out = self.relays[i].end_round(r, self.now);
            let pk = self.relay_pks[i];
            for m in out.outbound {
                self.bus.push((pk, m.clone()));
                produced.push((pk, m));
            }
        }
        for (from, msg) in self.bus.drain(..).collect::<Vec<_>>() {
            for relay in self.relays.iter_mut() {
                relay.on_inbound(from, msg.clone());
            }
        }
        produced
    }
}

fn live_core(committee: &[Identity]) -> SchedulerCore {
    let mut sorted_c = committee.to_vec();
    sorted_c.sort_by_key(|i| i.pubkey());
    let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
    SchedulerCore::new(
        sorted_c[0].clone(),
        pks,
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(80),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: None,
            vector_bytes: 0,
            aggregation: true,
        },
    )
}

fn adcnet_cfg_of(body: &AnymoneRoundConfigurationBody) -> AdcnetConfig {
    match &body.subnets[0].protocol {
        ProtocolConfig::Adcnet(c) => c.clone(),
        other => panic!("expected ADCNet subnet 0, got {other:?}"),
    }
}

/// Reproduces the demo bug: clients past the grow mark on a single subnet must
/// drive the committee to schedule a second subnet (grow at 31). Drives the same
/// sans-IO path the daemon uses — feed live wire traffic into the core, then `tick`.
#[test]
fn committee_schedules_second_subnet_when_one_nears_capacity() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = live_core(&committee);
    // A second core, identically registered and fed the same traffic, but with
    // aggregation disabled — proves the gate actually suppresses the layer
    // rather than it just never crossing the threshold.
    let mut core_no_agg = {
        let mut sorted_c = committee.clone();
        sorted_c.sort_by_key(|i| i.pubkey());
        let pks: Vec<_> = committee.iter().map(|i| i.pubkey()).collect();
        SchedulerCore::new(
            sorted_c[0].clone(),
            pks,
            2,
            SchedulerParams {
                public_round_duration: Duration::from_millis(80),
                min_relays: 2,
                min_services: 1,
                fault_threshold: 2,
                escalation_grace: 5,
                grow_at: 31,
                message_size: 16,
                integrity_backoff_ms: 6 * 60 * 1000,
                sideline: true,
                renegotiate_on_fault: true,
                min_capacity: 8,
                pin: None,
                vector_bytes: 0,
                aggregation: false,
            },
        )
    };

    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);
    register_relays_and_service(&mut core_no_agg, &relays, &service);

    let proposal = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    let body = proposal.body.clone();
    assert_eq!(body.subnets.len(), 1, "v0 starts with a single subnet");
    let cfg = adcnet_cfg_of(&body);
    core.on_decoded_body(proposal);
    let proposal_no_agg =
        staged_proposal(&core_no_agg.tick(0, 0)).expect("first proposal (no-agg)");
    core_no_agg.on_decoded_body(proposal_no_agg);

    let clients: Vec<Identity> = (0..32).map(|_| Identity::generate()).collect();
    let mut net = Subnet::new(&cfg, &relays, &clients);

    // Resizes are damped (`CAPACITY_RESIZE_GRACE` ticks): drive through the
    // window and keep the last staged body, which carries the settled capacity.
    let mut grown: Option<AnymoneRoundConfigurationBody> = None;
    let mut grown_no_agg: Option<AnymoneRoundConfigurationBody> = None;
    for round in 0..12u64 {
        for (from, msg) in net.round(round, &[0, 1, 2]) {
            core.on_subnet_message(0, from, msg.clone());
            core_no_agg.on_subnet_message(0, from, msg);
        }
        if let Some(b) = staged_body(&core.tick(round, 0)) {
            grown = Some(b);
        }
        if let Some(b) = staged_body(&core_no_agg.tick(round, 0)) {
            grown_no_agg = Some(b);
        }
    }

    let body = grown.expect("committee must schedule a second subnet once a subnet nears capacity");
    assert_eq!(
        proto_name(&body),
        "adcnet",
        "scaling stays on ADCNet (not a fault escalation)"
    );
    assert!(
        body.subnets.len() >= 2,
        "expected ≥2 subnets, got {}",
        body.subnets.len()
    );
    let grown_no_agg = grown_no_agg.expect("no-agg core must also schedule a second subnet");
    assert!(
        grown_no_agg
            .subnets
            .iter()
            .all(|s| s.protocol.aggregation().is_none()),
        "aggregation: false must suppress the layer even above the capacity threshold"
    );

    // Per-subnet escalation (#19/#21): an unattributable fault on subnet 1
    // escalates only subnet 1 to Panetiere; subnet 0 stays optimistic ADCNet.
    let count = body.subnets.len();
    core.apply_observed_faults(
        1,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        }],
        0,
    );
    let mixed = staged_body(&core.tick(9, 0)).expect("re-propose after per-subnet fault");
    assert_eq!(
        mixed.subnets.len(),
        count,
        "a fault must not change the subnet count"
    );
    assert!(
        matches!(mixed.subnets[0].protocol, ProtocolConfig::Adcnet(_)),
        "unfaulted subnet 0 stays ADCNet"
    );
    assert!(
        matches!(mixed.subnets[1].protocol, ProtocolConfig::Panetiere(_)),
        "faulted subnet 1 escalates to Panetiere"
    );
    assert!(
        mixed.subnets[1].protocol.aggregation().is_some(),
        "capacity above threshold should aggregate by default"
    );
}

/// Reproduces the demo's subnet *flapping*: after growing to two subnets and
/// clients re-home, the new subnet hasn't announced its set yet, so the observed
/// total momentarily undercounts and `total / subnet_count` dips below the
/// shrink mark. The committee must hold the subnet through `SUBNET_SHRINK_GRACE`
/// ticks, not drop it on the transient.
#[test]
fn committee_holds_new_subnet_through_rehome_transient() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = live_core(&committee);

    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let v0_proposal = staged_proposal(&core.tick(0, 0)).expect("v0");
    let cfg = adcnet_cfg_of(&v0_proposal.body);
    core.on_decoded_body(v0_proposal);

    // 32 clients on one subnet → grow to two subnets.
    let busy: Vec<Identity> = (0..32).map(|_| Identity::generate()).collect();
    let mut net_busy = Subnet::new(&cfg, &relays, &busy);
    for (from, msg) in net_busy.round(5, &[0, 1, 2]) {
        core.on_subnet_message(0, from, msg);
    }
    let grown_proposal = staged_proposal(&core.tick(5, 0)).expect("grow proposal");
    assert_eq!(grown_proposal.body.subnets.len(), 2, "grew to two subnets");
    core.on_decoded_body(grown_proposal);

    // Re-home transient: only the old subnet reports, having shed clients to the
    // new one (which hasn't announced yet), so per-subnet load dips below shrink.
    let few: Vec<Identity> = (0..15).map(|_| Identity::generate()).collect();
    let mut net_few = Subnet::new(&cfg, &relays, &few);
    for (from, msg) in net_few.round(6, &[0, 1, 2]) {
        core.on_subnet_message(0, from, msg);
    }

    // First ticks under the transient must NOT shrink.
    for r in 6..8u64 {
        if let Some(b) = staged_body(&core.tick(r, 0)) {
            assert!(
                b.subnets.len() >= 2,
                "subnet dropped during the re-home transient (round {r})"
            );
        }
    }
    // Once the low load has held for the full grace window, one subnet is removed.
    let shrunk = staged_body(&core.tick(8, 0)).expect("shrink proposal after the grace window");
    assert_eq!(
        shrunk.subnets.len(),
        1,
        "removes a subnet only after the grace window"
    );

    // Convergent: the same low load must not oscillate back up after shrinking.
    for r in 9..12u64 {
        if let Some(b) = staged_body(&core.tick(r, 0)) {
            assert_eq!(
                b.subnets.len(),
                1,
                "must not re-grow after shrinking (round {r})"
            );
        }
    }
}

/// Below the grow mark ADCNet stays one subnet but sizes its `client_set_max` to
/// the observed load (like Panetiere), resizing back down when load falls.
#[test]
fn adcnet_capacity_resizes_to_observed_load() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = live_core(&committee);
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let v0 = staged_proposal(&core.tick(0, 0)).expect("v0");
    let cfg = adcnet_cfg_of(&v0.body);
    let floor = cfg.client_set_max;
    core.on_decoded_body(v0);

    let mut round = 1u64;
    // Resizes are damped (`CAPACITY_RESIZE_GRACE` ticks), so drive through the
    // window and keep the last staged body.
    let mut drive = |core: &mut SchedulerCore, n: usize| -> AnymoneRoundConfigurationBody {
        let clients: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let mut net = Subnet::new(&cfg, &relays, &clients);
        let mut last = None;
        for _ in 0..12 {
            for (from, msg) in net.round(round, &[0, 1, 2]) {
                core.on_subnet_message(0, from, msg);
            }
            let staged = staged_proposal(&core.tick(round, 0));
            round += 1;
            if let Some(p) = staged {
                last = Some(p.body.clone());
                core.on_decoded_body(p);
            }
        }
        last.expect("capacity never resized")
    };

    // 30 clients (below the grow mark) → one subnet, capacity grows to fit.
    let grown = drive(&mut core, 30);
    assert_eq!(grown.subnets.len(), 1);
    let grown_cap = adcnet_cfg_of(&grown).client_set_max;
    assert!(
        grown_cap > floor,
        "capacity grew from {floor} to {grown_cap}"
    );

    // Load collapses → capacity resizes back down. Sparse traffic over the
    // (longer, damped) drive can trip a low-load escalation to Panetiere; this
    // test is about capacity, so read it regardless of the ladder state.
    let shrunk_cap = subnet_capacity(&drive(&mut core, 1).subnets[0].protocol);
    assert!(
        shrunk_cap < grown_cap,
        "capacity shrank from {grown_cap} to {shrunk_cap}"
    );
}

fn subnet_capacity(p: &ProtocolConfig) -> u32 {
    match p {
        ProtocolConfig::Adcnet(c) => c.client_set_max,
        ProtocolConfig::Panetiere(c) => c.client_set_max,
        ProtocolConfig::ScheduledPanetiere(c) => c.client_set_max,
        ProtocolConfig::Noop(c) => c.client_set_max,
        _ => unreachable!("scheduler emits only adcnet/panetiere/noop"),
    }
}

/// `sorted(committee)[0]` — the only member whose proposals are signable.
fn lead_of(committee: &[Identity]) -> Identity {
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    sorted[0].clone()
}

fn sign_proposal(id: &Identity, body: AnymoneRoundConfigurationBody) -> SignedProposal {
    let signature = id.sign(&body.propose_bytes());
    SignedProposal {
        body,
        proposer: id.pubkey(),
        signature,
    }
}

/// A body decoded from the committee Panetiere that wasn't signed by the lead —
/// the governance-takeover vector — must never be signed by a member. Only the
/// lead's genuinely-signed proposal is.
#[test]
fn outsider_proposal_is_rejected() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let genuine = staged_proposal(&core.tick(0, 0)).expect("staged");
    let body = genuine.body.clone();

    // An outside peer re-signs the same body with its own (non-committee) key.
    let outsider = Identity::generate();
    assert!(
        core.on_decoded_body(sign_proposal(&outsider, body.clone()))
            .is_empty(),
        "a proposal from a non-lead key must be ignored"
    );

    // A garbage signature carrying the lead's pubkey must also be rejected.
    let bad = SignedProposal {
        body: body.clone(),
        proposer: genuine.proposer,
        signature: vec![0u8; 64],
    };
    assert!(
        core.on_decoded_body(bad).is_empty(),
        "a bad lead signature must be ignored"
    );

    // The genuine lead proposal is accepted (the member signs + gossips).
    assert!(
        !core.on_decoded_body(genuine).is_empty(),
        "the lead's own signed proposal must be accepted"
    );
}

/// Even with valid proposer auth, a malicious lead can't insert relays the
/// member never saw register — restoring genuine t-of-n (a forged config needs
/// `threshold` colluding members, not one bad lead).
#[test]
fn malicious_lead_cannot_insert_unregistered_relay() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let mut proposal = staged_proposal(&core.tick(0, 0)).expect("staged");
    // The lead splices in a relay nobody registered, then re-signs as the lead.
    let attacker_relay = Identity::generate();
    proposal.body.subnets[0]
        .relays
        .push(attacker_relay.pubkey());
    let forged = sign_proposal(&lead_of(&committee), proposal.body);

    assert!(
        core.on_decoded_body(forged).is_empty(),
        "a relay never registered must be rejected even from a correctly-signed lead"
    );
}

/// A genuine, lead-signed proposal at a strictly older round is a stale
/// rollback replay and must be rejected — the round is covered by the signature.
#[test]
fn stale_proposal_replay_is_rejected() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let template = staged_proposal(&core.tick(0, 0)).expect("staged").body;

    // Accept a proposal at round 5 → advances the accepted-round frontier.
    let mut newer = template.clone();
    newer.round = 5;
    assert!(
        !core
            .on_decoded_body(sign_proposal(&lead_of(&committee), newer))
            .is_empty(),
        "the newer proposal is accepted"
    );

    // Replaying a genuine, lead-signed proposal at a strictly older round is a
    // rollback and must be rejected.
    let mut stale = template.clone();
    stale.round = 4;
    assert!(
        core.on_decoded_body(sign_proposal(&lead_of(&committee), stale))
            .is_empty(),
        "a strictly older round must be rejected"
    );
}

/// Registrations are bound to the registrant's key: a tampered registration
/// fails verification, so a peer can't register a pubkey it doesn't control.
#[test]
fn registration_signature_binds_to_registrant() {
    let id = Identity::generate();
    let mut reg = Registration::relay(&id, xkw(&id));
    assert!(reg.verify(), "a freshly-signed registration verifies");
    if let Registration::Relay { signature, .. } = &mut reg {
        signature[0] ^= 0xff;
    }
    assert!(!reg.verify(), "a tampered signature must not verify");

    let mut watcher = Registration::watcher(&id);
    assert!(watcher.verify());
    if let Registration::Watcher { signature, .. } = &mut watcher {
        signature[0] ^= 0xff;
    }
    assert!(!watcher.verify());

    // The advertised client address is signed, so it can't be swapped to
    // redirect a relay's clients elsewhere.
    let mut at = Registration::relay_at(&id, xkw(&id), Some("10.0.0.1:9000".into()));
    assert!(at.verify());
    if let Registration::Relay { client_addr, .. } = &mut at {
        *client_addr = Some("10.0.0.2:9000".into());
    }
    assert!(!at.verify(), "a rewritten client address must not verify");
    // An absent address is distinct from an empty one.
    let empty = Registration::relay_at(&id, xkw(&id), Some(String::new()));
    let absent = Registration::relay(&id, xkw(&id));
    let (Registration::Relay { signature: a, .. }, Registration::Relay { signature: b, .. }) =
        (&empty, &absent)
    else {
        unreachable!()
    };
    assert_ne!(a, b, "absent and empty addresses must sign differently");
}

/// Watchers reach the config as secondary peers and placed relays carry their
/// client address, so a client can find a relay without joining the p2p network.
#[test]
fn config_carries_watchers_and_relay_client_addrs() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let watcher = Identity::generate();

    for r in &relays {
        core.on_registration(Registration::relay_at(
            r,
            xkw(r),
            Some(format!("127.0.0.1:{}", 9000 + r.pubkey().0[0] as u16)),
        ));
    }
    core.on_registration(Registration::service(
        &service,
        ServiceTag::from_label("anymone.echo"),
        xkw(&service),
    ));
    core.on_registration(Registration::watcher(&watcher));

    let body = staged_body(&core.tick(1, anymone_core::config::now_unix_ms()))
        .expect("lead stages a proposal once it has relays and a service");
    assert_eq!(body.watchers, vec![watcher.pubkey()]);
    let placed: Vec<Pubkey> = body.subnets.iter().flat_map(|s| s.relays.clone()).collect();
    assert!(!placed.is_empty());
    for (pk, addr) in &body.relay_client_addrs {
        assert!(placed.contains(pk), "only placed relays are listed");
        assert!(addr.starts_with("127.0.0.1:"));
    }
    assert_eq!(body.relay_client_addrs.len(), placed.len());

    let (primary, secondary) = anymone_core::governance::tracked_peers(&body, &pks);
    assert!(secondary.contains(&watcher.pubkey()), "watchers are secondary");
    assert!(secondary.contains(&service.pubkey()));
    assert!(!primary.contains(&watcher.pubkey()));
    for r in &relays {
        assert!(primary.contains(&r.pubkey()), "relays are primary");
    }
}

/// A live Panetiere subnet (one client + 3 relays, relay 0 the decoding leader,
/// relay 2 corrupting its shares) over a synchronous bus, returning every wire
/// message so it can be fed to the committee core via `on_subnet_message` — the
/// same path the daemon uses. Built from the same relay identities the core
/// registered, so each `server_id` (the sorted-roster index) lines up with the
/// config roster the core's observer learned.
struct PanetiereSubnet {
    client: PanetiereClientSession,
    client_pk: Pubkey,
    servers: Vec<PanetiereServerSession>,
    server_pks: Vec<Pubkey>,
    monitor: PanetiereObserverSession,
    share_bus: Vec<(Pubkey, Vec<u8>)>,
    now: Instant,
    seq: u64,
}

impl PanetiereSubnet {
    fn new(relay_ids: &[Identity], server2_misbehavior: Option<Misbehavior>) -> Self {
        let n = relay_ids.len();
        let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
        // One real sender per round (the rest of the demo's clients re-home
        // elsewhere); MSE sized to that.
        let mse = ChannelParams::from_mse(MseParams::new(4, 1, 32, [0xAA; 32]));
        let n_polys = mse.n_polys();
        let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(
            &mut setup_rng,
            n,
            n_polys,
        ));
        let server_ids: Vec<PanServerId> = (0..n as u32).map(PanServerId).collect();

        let mut sorted = relay_ids.to_vec();
        sorted.sort_by_key(|i| i.pubkey());
        let server_pks: Vec<Pubkey> = sorted.iter().map(|i| i.pubkey()).collect();
        let server_pubkeys: HashMap<PanServerId, Pubkey> = server_pks
            .iter()
            .enumerate()
            .map(|(i, pk)| (PanServerId(i as u32), *pk))
            .collect();

        let xpubs: Vec<(PanServerId, panetiere::pke::PublicKey)> = sorted
            .iter()
            .enumerate()
            .map(|(i, id)| (PanServerId(i as u32), id.exchange().pke().public()))
            .collect();

        let client_id = Identity::generate();
        let client =
            PanetiereClientSession::new(pp.clone(), mse.clone(), client_id.clone(), xpubs, [42u8; 32]);
        let mut servers: Vec<PanetiereServerSession> = server_ids
            .iter()
            .map(|sid| {
                PanetiereServerSession::new(
                    pp.clone(),
                    mse.clone(),
                    *sid,
                    sorted[sid.0 as usize].clone(),
                    if sid.0 == 0 {
                        SetMode::Leader
                    } else {
                        SetMode::SelfDerived
                    },
                    0,
                    server_pubkeys.clone(),
                    None,
                )
            })
            .collect();
        servers[2].set_misbehavior(server2_misbehavior);

        let monitor = PanetiereObserverSession::new(server_pks.clone(), Some(server_pks[0]), 2);

        PanetiereSubnet {
            client,
            client_pk: client_id.pubkey(),
            servers,
            server_pks,
            monitor,
            share_bus: Vec::new(),
            now: Instant::now(),
            seq: 0,
        }
    }

    /// Run one round. Returns (every wire message produced, the leader's faults,
    /// the number of payloads the leader decoded this round). Server shares reach
    /// peers with a one-round delay, exactly as gossip delivers them.
    fn round(&mut self, r: u64) -> (Vec<(Pubkey, Vec<u8>)>, Vec<Fault>, usize) {
        let mut produced = Vec::new();
        for (from, m) in std::mem::take(&mut self.share_bus) {
            for s in self.servers.iter_mut() {
                s.on_inbound(from, m.clone());
            }
        }
        // A distinct real payload every round so the leader emits a `Decoded`.
        self.client
            .stage(format!("payload-{:02}", self.seq).into_bytes());
        self.seq += 1;
        let client_out = self.client.begin_round(r, self.now);
        for s in self.servers.iter_mut() {
            for m in &client_out {
                s.on_inbound(self.client_pk, m.clone());
            }
        }
        for m in &client_out {
            produced.push((self.client_pk, m.clone()));
        }

        let mut decoded = 0usize;
        for i in 0..self.servers.len() {
            let out = self.servers[i].end_round(r, self.now);
            let pk = self.server_pks[i];
            if i == 0 {
                decoded = out.decoded.len();
            }
            for m in out.outbound {
                self.share_bus.push((pk, m.clone()));
                produced.push((pk, m));
            }
        }
        for (from, m) in &produced {
            self.monitor.on_inbound(*from, m.clone());
        }
        let faults = self.monitor.end_round(r, self.now).faults;
        (produced, faults, decoded)
    }
}

/// A relay that corrupts its Panetiere shares is tolerated by t-of-n decode, so
/// the subnet keeps producing output (liveness met) and the leader attributes
/// an `Integrity` fault every round. The committee must not de-escalate back to
/// optimistic ADCNet while that fault keeps recurring, even though its liveness
/// observer alone would see nothing wrong. (This is not a stall: the subnet
/// decodes fine; the signal that must be honored is the integrity fault, not
/// missing output.)
#[test]
fn corrupt_panetiere_keeps_escalation() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = lead_core(&committee, 2);
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    // Optimistic ADCNet baseline.
    let first = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    assert_eq!(proto_name(&first.body), "adcnet");
    enact(&mut core, &committee, first);

    // An ADCNet corrupt share fails decode without attribution → unattributable
    // fault → escalate to Panetiere keeping all 3 relays (the corrupt one rides in).
    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        }],
        0,
    );
    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(proto_name(&esc.body), "panetiere");
    assert_eq!(esc.body.subnets[0].relays.len(), 3);
    let corrupt_pk = {
        let mut sorted: Vec<Pubkey> = relays.iter().map(|i| i.pubkey()).collect();
        sorted.sort();
        sorted[2]
    };
    assert!(esc.body.subnets[0].relays.contains(&corrupt_pk));
    enact(&mut core, &committee, esc);

    // Run the corrupt Panetiere subnet into the committee observer well past the
    // escalation grace, ticking the core each round as the daemon would.
    let mut net = PanetiereSubnet::new(&relays, Some(Misbehavior::CorruptShare));
    let mut saw_integrity = false;
    let mut total_output = 0usize;
    let mut deescalated = false;
    for r in 0..9u64 {
        let (wire, faults, decoded) = net.round(r);
        for (from, bytes) in wire {
            core.on_subnet_message(0, from, bytes);
        }
        total_output += decoded;
        if faults.iter().any(|f| {
            f.kind == FaultKind::Integrity && f.attribution == Attribution::Peers(vec![corrupt_pk])
        }) {
            saw_integrity = true;
        }
        if let Some(b) = staged_body(&core.tick(2 + r, 0)) {
            if proto_name(&b) == "adcnet" {
                deescalated = true;
            }
        }
    }

    // Preconditions — not a stall: the subnet kept producing output AND the
    // leader raised the integrity fault.
    assert!(
        total_output > 0,
        "subnet must keep producing output (liveness met)"
    );
    assert!(
        saw_integrity,
        "leader must attribute an integrity fault to the corrupt relay"
    );

    // The ongoing integrity fault must keep the subnet escalated; it must NOT
    // fall back to ADCNet with the offender re-included.
    assert!(
        !deescalated,
        "subnet de-escalated to ADCNet despite an ongoing integrity fault \
         from {corrupt_pk:?}; the offender is back in the optimistic roster"
    );
}

/// A core escalated to a 3-relay Panetiere subnet 0 (via an unattributable fault,
/// so no relay is dropped), ready to receive integrity fault reports.
fn escalated_panetiere_core(
    committee: &[Identity],
    relays: &[Identity],
    service: &Identity,
) -> SchedulerCore {
    let mut core = lead_core(committee, 2);
    register_relays_and_service(&mut core, relays, service);
    let first = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    enact(&mut core, committee, first);
    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        }],
        0,
    );
    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation");
    assert_eq!(proto_name(&esc.body), "panetiere");
    enact(&mut core, committee, esc);
    core
}

/// Approach B: the committee acts on a leader's integrity `FaultReport` only when
/// it comes from the subnet leader AND the committee re-verifies the evidence
/// itself — so a corrupt-share relay is sidelined, but a lying leader can't frame
/// an honest one.
#[test]
fn committee_acts_on_verified_leader_integrity_report() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();

    let mut sorted = relays.clone();
    sorted.sort_by_key(|i| i.pubkey());
    let leader_pk = sorted[0].pubkey();
    let honest_pk = sorted[1].pubkey();
    let corrupt_pk = sorted[2].pubkey();

    // Run the corrupt subnet to capture the leader's integrity fault (evidence =
    // the offending ServerPublic) and an honest relay's consistent ServerPublic.
    let mut net = PanetiereSubnet::new(&relays, Some(Misbehavior::CorruptShare));
    let mut integrity: Option<Fault> = None;
    let mut honest_sp: Option<Vec<u8>> = None;
    let mut corrupt_sp: Option<Vec<u8>> = None;
    for r in 0..4u64 {
        let (wire, faults, _) = net.round(r);
        if honest_sp.is_none() {
            honest_sp = wire
                .iter()
                .find(|(from, _)| *from == honest_pk)
                .map(|(_, b)| b.clone());
        }
        if corrupt_sp.is_none() {
            corrupt_sp = wire
                .iter()
                .find(|(from, _)| *from == corrupt_pk)
                .map(|(_, b)| b.clone());
        }
        if integrity.is_none() {
            integrity = faults.into_iter().find(|f| f.kind == FaultKind::Integrity);
        }
        if integrity.is_some() && honest_sp.is_some() && corrupt_sp.is_some() {
            break;
        }
    }
    let fault = integrity.expect("leader emits an integrity fault");
    assert_eq!(fault.attribution, Attribution::Peers(vec![corrupt_pk]));
    let honest_sp = honest_sp.expect("captured an honest ServerPublic");
    let corrupt_sp = corrupt_sp.expect("captured the corrupt ServerPublic");

    // Verified report from the leader sidelines the offender; subnet stays Panetiere.
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        leader_pk,
        FaultReport {
            round: 5,
            subnet: 0,
            reporter: leader_pk,
            fault: fault.clone(),
        },
        0,
    );
    let body = staged_body(&core.tick(2, 0)).expect("re-propose after integrity report");
    assert_eq!(proto_name(&body), "panetiere");
    assert!(!body.subnets[0].relays.contains(&corrupt_pk));

    // A replayed report must not refresh the offender's backoff timer.
    core.on_fault_report(
        leader_pk,
        FaultReport {
            round: 5,
            subnet: 0,
            reporter: leader_pk,
            fault: fault.clone(),
        },
        6 * 60 * 1000 - 1,
    );
    core.tick(3, 6 * 60 * 1000 + 1);
    core.on_registration(Registration::relay(&sorted[2], xkw(&sorted[2])));
    core.set_cover_rate(0.9);
    let body = staged_body(&core.tick(4, 6 * 60 * 1000 + 1)).expect("heal proposal after backoff");
    assert!(
        body.subnets[0].relays.contains(&corrupt_pk),
        "a replayed fault report must not refresh the offender's backoff timer"
    );

    // A report from a non-leader is ignored (forced re-propose keeps all 3 relays).
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        honest_pk,
        FaultReport {
            round: 5,
            subnet: 0,
            reporter: honest_pk,
            fault: fault.clone(),
        },
        0,
    );
    core.set_cover_rate(0.5);
    let body = staged_body(&core.tick(2, 0)).expect("cover change re-proposes");
    assert!(body.subnets[0].relays.contains(&corrupt_pk));

    // Evidence that re-verifies as consistent can't frame an honest relay.
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        leader_pk,
        FaultReport {
            round: 5,
            subnet: 0,
            reporter: leader_pk,
            fault: Fault {
                kind: FaultKind::Integrity,
                attribution: Attribution::Peers(vec![honest_pk]),
                evidence: honest_sp,
            },
        },
        0,
    );
    core.set_cover_rate(0.7);
    let body = staged_body(&core.tick(2, 0)).expect("cover change re-proposes");
    assert!(body.subnets[0].relays.contains(&honest_pk));

    // Genuine (signed, inconsistent) evidence attributes only its signer: a
    // report pairing it with a different relay is ignored entirely.
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        leader_pk,
        FaultReport {
            round: 5,
            subnet: 0,
            reporter: leader_pk,
            fault: Fault {
                kind: FaultKind::Integrity,
                attribution: Attribution::Peers(vec![honest_pk]),
                evidence: corrupt_sp,
            },
        },
        0,
    );
    core.set_cover_rate(0.9);
    let body = staged_body(&core.tick(2, 0)).expect("cover change re-proposes");
    assert!(body.subnets[0].relays.contains(&honest_pk));
    assert!(
        body.subnets[0].relays.contains(&corrupt_pk),
        "mis-attributed report must be ignored entirely"
    );
}

/// A fresh escalation always starts one-round Panetiere; sustained real
/// traffic then upgrades the subnet to scheduled mode, and steady traffic
/// afterwards re-proposes nothing (content key stable).
#[test]
fn sustained_traffic_upgrades_to_scheduled_panetiere() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    // message_size=4 -> upgrade at >=8 decoded bytes/round, downgrade at <=2;
    // the harness's real ~10-byte payload sits above the upgrade bar.
    let mut core = lead_core_msg_size(&committee, 2, 4);
    register_relays_and_service(&mut core, &relays, &service);

    let first = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    assert_eq!(proto_name(&first.body), "adcnet");
    enact(&mut core, &committee, first);

    core.apply_observed_faults(
        0,
        vec![Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        }],
        0,
    );
    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(
        proto_name(&esc.body),
        "panetiere",
        "a fresh escalation always starts one-round"
    );
    enact(&mut core, &committee, esc);

    let mut net = PanetiereSubnet::new(&relays, None);
    let mut upgraded_body = None;
    for r in 0..6u64 {
        let (wire, _, _) = net.round(r);
        for (from, bytes) in wire {
            core.on_subnet_message(0, from, bytes);
        }
        if let Some(body) = staged_body(&core.tick(2 + r, 0)) {
            if proto_name(&body) == "scheduled-panetiere" {
                upgraded_body = Some(body.clone());
            }
            enact(
                &mut core,
                &committee,
                sign_proposal(&lead_of(&committee), body),
            );
            if upgraded_body.is_some() {
                break;
            }
        }
    }
    let upgraded = upgraded_body.expect("sustained real traffic must upgrade the subnet");
    let ProtocolConfig::ScheduledPanetiere(cfg) = &upgraded.subnets[0].protocol else {
        panic!("expected ScheduledPanetiere");
    };
    assert!(
        cfg.vector_bytes > 0,
        "scheduled subnet must get a sized message vector"
    );

    // Steady traffic afterwards must not keep re-proposing (content key stable).
    let mut restaged = false;
    for r in 6..10u64 {
        let (wire, _, _) = net.round(r);
        for (from, bytes) in wire {
            core.on_subnet_message(0, from, bytes);
        }
        if staged_body(&core.tick(2 + r, 0)).is_some() {
            restaged = true;
        }
    }
    assert!(
        !restaged,
        "steady scheduled-mode traffic must not keep re-proposing"
    );

    // Pinned deployment shapes: "scheduled-panetiere" forces the mode from the
    // first proposal, no traffic needed.
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    let mut pinned = SchedulerCore::new(
        sorted[0].clone(),
        committee.iter().map(|i| i.pubkey()).collect(),
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 2,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 4,
            integrity_backoff_ms: 6 * 60 * 1000,
            sideline: true,
            renegotiate_on_fault: true,
            min_capacity: 8,
            pin: Some(anymone_core::scheduling::SchedulerProtocol::ScheduledPanetiere),
            vector_bytes: 0,
            aggregation: true,
        },
    );
    register_relays_and_service(&mut pinned, &relays, &service);
    let body = staged_body(&pinned.tick(0, 0)).expect("pinned core proposes");
    assert_eq!(
        proto_name(&body),
        "scheduled-panetiere",
        "pin forces scheduled mode outright"
    );
    let ProtocolConfig::ScheduledPanetiere(cfg) = &body.subnets[0].protocol else {
        panic!("expected ScheduledPanetiere");
    };
    assert!(
        cfg.vector_bytes > 0,
        "pinned scheduled subnet gets the default vector sizing"
    );
}
