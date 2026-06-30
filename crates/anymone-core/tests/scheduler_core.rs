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
    ProtocolConfig,
};
use anymone_core::scheduler_core::{
    CommitteeSig, SchedulerAction, SchedulerCore, SchedulerParams, SignedProposal,
};
use anymone_core::faults::{Attribution, Fault, FaultKind};
use anymone_core::identity::ExchangeIdentity;
use anymone_core::panetiere::{PanetiereClientSession, PanetiereServerSession};
use anymone_core::session::{Misbehavior, Session};
use anymone_core::{FaultReport, Identity, Pubkey, Registration, ServiceTag, TOPIC_CONFIG};

use adcnet::crypto::{ExchangePublicKey, ServerId, SharedKey};
use adcnet::protocol::session::one_round::{IbltMsgParamsOwned, OneRoundConfig};
use panetiere::mse::{MseEncoding, MseParams};
use panetiere::protocol::{ClientId, ProtocolParams, ServerId as PanServerId};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn xkw(id: &Identity) -> ExchangePublicKeyWire {
    ExchangePublicKeyWire::from_key(&id.exchange_pubkey())
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
    core.on_decoded_body(proposal);
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    let peer = &sorted[1];
    let actions = core.on_committee_sig(CommitteeSig {
        body_bytes: canonical.clone(),
        signer: peer.pubkey(),
        signature: peer.sign(&canonical),
    });
    assert!(
        actions.iter().any(|a| matches!(a, SchedulerAction::Publish { topic, .. } if topic == TOPIC_CONFIG)),
        "enact: proposal must publish a config at threshold"
    );
}

fn proto_name(body: &AnymoneRoundConfigurationBody) -> &'static str {
    match &body.subnets[0].protocol {
        ProtocolConfig::Adcnet(_) => "adcnet",
        ProtocolConfig::Panetiere(_) => "panetiere",
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
    core.apply_observed_faults(0, vec![Fault {
        kind: FaultKind::Liveness,
        attribution: Attribution::Peers(vec![victim]),
        evidence: Vec::new(),
    }], 0);

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
    core.apply_observed_faults(0, vec![Fault {
        kind: FaultKind::Liveness,
        attribution: Attribution::None,
        evidence: Vec::new(),
    }], 0);

    // Escalate to Panetiere but keep all 3 relays (nobody specific to drop).
    let body = staged_body(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(proto_name(&body), "panetiere");
    assert_eq!(body.subnets[0].relays.len(), 3);

    // A relay re-announcing must NOT de-escalate: the general fault names no
    // culprit, so only a fault-free streak proves the cause is gone.
    core.on_registration(Registration::relay(&relays[0], xkw(&relays[0])));
    assert_eq!(proto_name(&staged_body(&core.tick(2, 0)).expect("still escalated")), "panetiere");

    // After ESCALATION_GRACE (5) fault-free rounds, de-escalate to ADCNet.
    for r in 3..5 {
        assert_eq!(proto_name(&staged_body(&core.tick(r, 0)).expect("still escalated")), "panetiere");
    }
    assert_eq!(proto_name(&staged_body(&core.tick(5, 0)).expect("de-escalation")), "adcnet");
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
    core.apply_observed_faults(0, vec![Fault {
        kind: FaultKind::Integrity,
        attribution: Attribution::Peers(vec![victim]),
        evidence: Vec::new(),
    }], 0);

    let esc = staged_proposal(&core.tick(1, 0)).expect("escalation proposal");
    assert_eq!(proto_name(&esc.body), "panetiere");
    assert!(!esc.body.subnets[0].relays.contains(&victim));
    enact(&mut core, &committee, esc);

    // Re-registration within the backoff is refused — the offender stays out, so
    // the content is unchanged and (already enacted) nothing is re-staged.
    core.on_registration(Registration::relay(&relays[1], xkw(&relays[1])));
    assert!(staged_body(&core.tick(2, 60_000)).is_none(), "still sidelined within backoff");

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
    let mut core = SchedulerCore::new(
        lead.clone(),
        pks.clone(),
        2,
        SchedulerParams {
            public_round_duration: Duration::from_millis(200),
            min_relays: 1,
            min_services: 1,
            fault_threshold: 2,
            escalation_grace: 5,
            grow_at: 31,
            message_size: 16,
        },
    );

    let relay = Identity::generate();
    let service = Identity::generate();
    register_relays_and_service(&mut core, std::slice::from_ref(&relay), &service);

    let proposal = staged_proposal(&core.tick(0, 0)).expect("staged");
    let body = proposal.body.clone();

    // The committee Panetiere decodes the body back to the lead → 1 sig, no config.
    let actions = core.on_decoded_body(proposal);
    assert!(
        !actions.iter().any(|a| matches!(a, SchedulerAction::Publish { topic, .. } if topic == TOPIC_CONFIG)),
        "must not assemble with a single signature"
    );

    // A peer's signature arrives → threshold reached → config published.
    let canonical = body.canonical_bytes();
    let peer_sig = CommitteeSig {
        body_bytes: canonical.clone(),
        signer: peer.pubkey(),
        signature: peer.sign(&canonical),
    };
    let actions = core.on_committee_sig(peer_sig);
    let cfg_bytes = actions
        .iter()
        .find_map(|a| match a {
            SchedulerAction::Publish { topic, bytes } if topic == TOPIC_CONFIG => Some(bytes.clone()),
            _ => None,
        })
        .expect("config must be published once threshold signatures are in");
    let cfg: AnymoneRoundConfiguration = bincode::deserialize(&cfg_bytes).unwrap();
    cfg.verify_multisig(&pks, 2).expect("assembled config verifies at threshold");
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
    enact(&mut core, &committee, first);

    // Unchanged content → no re-propose.
    assert!(staged_body(&core.tick(1, 0)).is_none());

    // A cover change re-proposes with the new rate.
    core.set_cover_rate(0.25);
    let reproposed = staged_proposal(&core.tick(2, 0)).expect("cover change re-proposes");
    assert!(reproposed.body.subnets.iter().all(|s| s.cover_rate == 0.25));
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

        let xk_by_pk: HashMap<Pubkey, ExchangePublicKeyWire> =
            cfg.relay_exchange_keys.iter().cloned().collect();
        let clients: Vec<AdcnetClientSession> = client_ids
            .iter()
            .enumerate()
            .map(|(ci, client_id)| {
                let mut client_shared: HashMap<ServerId, SharedKey> = HashMap::new();
                for (i, pk) in relay_pks.iter().enumerate() {
                    let xk = xk_by_pk.get(pk).unwrap().to_key().unwrap();
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
                    i == 0,
                    leader_pk,
                    None,
                )
            })
            .collect();
        Subnet { clients, client_pks, relays, relay_pks, bus: Vec::new(), now: Instant::now() }
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
            for relay in self.relays.iter_mut() { relay.on_inbound(from, msg.clone()); }
        }
        for i in 0..self.relays.len() {
            if !alive.contains(&i) { continue; }
            let out = self.relays[i].end_round(r, self.now);
            let pk = self.relay_pks[i];
            for m in out.outbound {
                self.bus.push((pk, m.clone()));
                produced.push((pk, m));
            }
        }
        for (from, msg) in self.bus.drain(..).collect::<Vec<_>>() {
            for relay in self.relays.iter_mut() { relay.on_inbound(from, msg.clone()); }
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
        },
    )
}

fn adcnet_cfg_of(body: &AnymoneRoundConfigurationBody) -> AdcnetConfig {
    match &body.subnets[0].protocol {
        ProtocolConfig::Adcnet(c) => c.clone(),
        _ => unreachable!(),
    }
}

/// Reproduces the demo bug: clients past the grow mark on a single subnet must
/// drive the committee to schedule a second subnet (grow at 31). Drives the same
/// sans-IO path the daemon uses — feed live wire traffic into the core, then `tick`.
#[test]
fn committee_schedules_second_subnet_when_one_nears_capacity() {
    let committee: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let mut core = live_core(&committee);

    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    register_relays_and_service(&mut core, &relays, &service);

    let proposal = staged_proposal(&core.tick(0, 0)).expect("first proposal");
    let body = proposal.body.clone();
    assert_eq!(body.subnets.len(), 1, "v0 starts with a single subnet");
    let cfg = adcnet_cfg_of(&body);
    core.on_decoded_body(proposal);

    let clients: Vec<Identity> = (0..32).map(|_| Identity::generate()).collect();
    let mut net = Subnet::new(&cfg, &relays, &clients);

    let mut grown: Option<AnymoneRoundConfigurationBody> = None;
    for round in 0..8u64 {
        for (from, msg) in net.round(round, &[0, 1, 2]) {
            core.on_subnet_message(0, from, msg);
        }
        if let Some(b) = staged_body(&core.tick(round, 0)) {
            grown = Some(b);
            break;
        }
    }

    let body = grown.expect("committee must schedule a second subnet once a subnet nears capacity");
    assert_eq!(proto_name(&body), "adcnet", "scaling stays on ADCNet (not a fault escalation)");
    assert!(body.subnets.len() >= 2, "expected ≥2 subnets, got {}", body.subnets.len());

    // Per-subnet escalation (#19/#21): an unattributable fault on subnet 1
    // escalates only subnet 1 to Panetiere; subnet 0 stays optimistic ADCNet.
    let count = body.subnets.len();
    core.apply_observed_faults(1, vec![Fault {
        kind: FaultKind::Liveness,
        attribution: Attribution::None,
        evidence: Vec::new(),
    }], 0);
    let mixed = staged_body(&core.tick(9, 0)).expect("re-propose after per-subnet fault");
    assert_eq!(mixed.subnets.len(), count, "a fault must not change the subnet count");
    assert!(matches!(mixed.subnets[0].protocol, ProtocolConfig::Adcnet(_)), "unfaulted subnet 0 stays ADCNet");
    assert!(matches!(mixed.subnets[1].protocol, ProtocolConfig::Panetiere(_)), "faulted subnet 1 escalates to Panetiere");
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
            assert!(b.subnets.len() >= 2, "subnet dropped during the re-home transient (round {r})");
        }
    }
    // Once the low load has held for the full grace window, one subnet is removed.
    let shrunk = staged_body(&core.tick(8, 0)).expect("shrink proposal after the grace window");
    assert_eq!(shrunk.subnets.len(), 1, "removes a subnet only after the grace window");
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
    let mut drive = |core: &mut SchedulerCore, n: usize| -> AnymoneRoundConfigurationBody {
        let clients: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
        let mut net = Subnet::new(&cfg, &relays, &clients);
        for _ in 0..8 {
            for (from, msg) in net.round(round, &[0, 1, 2]) {
                core.on_subnet_message(0, from, msg);
            }
            let staged = staged_proposal(&core.tick(round, 0));
            round += 1;
            if let Some(p) = staged {
                let body = p.body.clone();
                core.on_decoded_body(p);
                return body;
            }
        }
        panic!("capacity never resized");
    };

    // 30 clients (below the grow mark) → one subnet, capacity grows to fit.
    let grown = drive(&mut core, 30);
    assert_eq!(grown.subnets.len(), 1);
    let grown_cap = adcnet_cfg_of(&grown).client_set_max;
    assert!(grown_cap > floor, "capacity grew from {floor} to {grown_cap}");

    // Load collapses → capacity resizes back down.
    let shrunk_cap = adcnet_cfg_of(&drive(&mut core, 1)).client_set_max;
    assert!(shrunk_cap < grown_cap, "capacity shrank from {grown_cap} to {shrunk_cap}");
}

/// `sorted(committee)[0]` — the only member whose proposals are signable.
fn lead_of(committee: &[Identity]) -> Identity {
    let mut sorted = committee.to_vec();
    sorted.sort_by_key(|i| i.pubkey());
    sorted[0].clone()
}

fn sign_proposal(id: &Identity, body: AnymoneRoundConfigurationBody) -> SignedProposal {
    let signature = id.sign(&body.canonical_bytes());
    SignedProposal { body, proposer: id.pubkey(), signature }
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
        core.on_decoded_body(sign_proposal(&outsider, body.clone())).is_empty(),
        "a proposal from a non-lead key must be ignored"
    );

    // A garbage signature carrying the lead's pubkey must also be rejected.
    let bad = SignedProposal { body: body.clone(), proposer: genuine.proposer, signature: vec![0u8; 64] };
    assert!(core.on_decoded_body(bad).is_empty(), "a bad lead signature must be ignored");

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
    proposal.body.subnets[0].relays.push(attacker_relay.pubkey());
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
        !core.on_decoded_body(sign_proposal(&lead_of(&committee), newer)).is_empty(),
        "the newer proposal is accepted"
    );

    // Replaying a genuine, lead-signed proposal at a strictly older round is a
    // rollback and must be rejected.
    let mut stale = template.clone();
    stale.round = 4;
    assert!(
        core.on_decoded_body(sign_proposal(&lead_of(&committee), stale)).is_empty(),
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
    share_bus: Vec<(Pubkey, Vec<u8>)>,
    now: Instant,
    seq: u64,
}

impl PanetiereSubnet {
    fn new(relay_ids: &[Identity]) -> Self {
        let n = relay_ids.len();
        let mut setup_rng = ChaCha20Rng::from_seed([7u8; 32]);
        // One real sender per round (the rest of the demo's clients re-home
        // elsewhere); MSE sized to that.
        let mse = MseParams::new(4, 1, 32, [0xAA; 32]);
        let n_polys = MseEncoding::n_polys(&mse);
        let pp = Arc::new(ProtocolParams::setup_with_kahe_dims(&mut setup_rng, n, n_polys, 1));
        let server_ids: Vec<PanServerId> = (0..n as u32).map(PanServerId).collect();

        let mut sorted = relay_ids.to_vec();
        sorted.sort_by_key(|i| i.pubkey());
        let server_pks: Vec<Pubkey> = sorted.iter().map(|i| i.pubkey()).collect();
        let server_pubkeys: HashMap<PanServerId, Pubkey> = server_pks
            .iter()
            .enumerate()
            .map(|(i, pk)| (PanServerId(i as u32), *pk))
            .collect();

        let exchanges: Vec<ExchangeIdentity> =
            (0..n).map(|_| ExchangeIdentity::generate()).collect();
        let xpubs: HashMap<PanServerId, ExchangePublicKey> = exchanges
            .iter()
            .enumerate()
            .map(|(i, e)| (PanServerId(i as u32), e.public()))
            .collect();

        let client_id = Identity::generate();
        let client = PanetiereClientSession::new(
            pp.clone(), mse.clone(), ClientId(0), server_ids.clone(), xpubs, [42u8; 32]);
        let mut servers: Vec<PanetiereServerSession> = server_ids
            .iter()
            .map(|sid| {
                PanetiereServerSession::new(
                    pp.clone(),
                    mse.clone(),
                    *sid,
                    8,
                    exchanges[sid.0 as usize].clone(),
                    sid.0 == 0,
                    server_pubkeys.clone(),
                    None,
                )
            })
            .collect();
        servers[2].set_misbehavior(Some(Misbehavior::CorruptShare));

        PanetiereSubnet {
            client,
            client_pk: client_id.pubkey(),
            servers,
            server_pks,
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
        self.client.stage(format!("payload-{:02}", self.seq).into_bytes());
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

        let mut faults = Vec::new();
        let mut decoded = 0usize;
        for i in 0..self.servers.len() {
            let out = self.servers[i].end_round(r, self.now);
            let pk = self.server_pks[i];
            if i == 0 {
                decoded = out.decoded.len();
                faults = out.faults;
            }
            for m in out.outbound {
                self.share_bus.push((pk, m.clone()));
                produced.push((pk, m));
            }
        }
        (produced, faults, decoded)
    }
}

/// RED repro — fails until the integrity-fault path is fixed. A relay that
/// corrupts its Panetiere shares is tolerated by t-of-n decode, so the subnet
/// keeps producing output (liveness met) and the leader attributes an
/// `Integrity` fault every round. But the committee's only fault source is its
/// liveness observer, which never sees integrity faults — so after
/// `escalation_grace` "clean" ticks it silently de-escalates back to optimistic
/// ADCNet with the corrupt relay still in the roster. Correct behaviour: stay
/// escalated and sideline the offender. (This is not a stall: the subnet decodes
/// fine; the ignored signal is the integrity fault, not missing output.)
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
    core.apply_observed_faults(0, vec![Fault {
        kind: FaultKind::Liveness,
        attribution: Attribution::None,
        evidence: Vec::new(),
    }], 0);
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
    let mut net = PanetiereSubnet::new(&relays);
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
            f.kind == FaultKind::Integrity
                && f.attribution == Attribution::Peers(vec![corrupt_pk])
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
    assert!(total_output > 0, "subnet must keep producing output (liveness met)");
    assert!(saw_integrity, "leader must attribute an integrity fault to the corrupt relay");

    // Desired behaviour (fails today): the ongoing integrity fault keeps the
    // subnet escalated; it must NOT fall back to ADCNet with the offender re-included.
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
    core.apply_observed_faults(0, vec![Fault {
        kind: FaultKind::Liveness,
        attribution: Attribution::None,
        evidence: Vec::new(),
    }], 0);
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
    let mut net = PanetiereSubnet::new(&relays);
    let mut integrity: Option<Fault> = None;
    let mut honest_sp: Option<Vec<u8>> = None;
    for r in 0..4u64 {
        let (wire, faults, _) = net.round(r);
        if honest_sp.is_none() {
            honest_sp = wire.iter().find(|(from, _)| *from == honest_pk).map(|(_, b)| b.clone());
        }
        if integrity.is_none() {
            integrity = faults.into_iter().find(|f| f.kind == FaultKind::Integrity);
        }
        if integrity.is_some() && honest_sp.is_some() {
            break;
        }
    }
    let fault = integrity.expect("leader emits an integrity fault");
    assert_eq!(fault.attribution, Attribution::Peers(vec![corrupt_pk]));
    let honest_sp = honest_sp.expect("captured an honest ServerPublic");

    // Verified report from the leader sidelines the offender; subnet stays Panetiere.
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        leader_pk,
        FaultReport { round: 5, subnet: 0, reporter: leader_pk, fault: fault.clone() },
        0,
    );
    let body = staged_body(&core.tick(2, 0)).expect("re-propose after integrity report");
    assert_eq!(proto_name(&body), "panetiere");
    assert!(!body.subnets[0].relays.contains(&corrupt_pk));

    // A report from a non-leader is ignored (forced re-propose keeps all 3 relays).
    let mut core = escalated_panetiere_core(&committee, &relays, &service);
    core.on_fault_report(
        honest_pk,
        FaultReport { round: 5, subnet: 0, reporter: honest_pk, fault: fault.clone() },
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
}
