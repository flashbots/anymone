//! The runtime no longer drops `outcome.faults`: a subnet leader runs a
//! liveness monitor, gossips observed faults on `anymone/faults` as
//! `FaultReport`s, and surfaces them on `Anymone::events()`. Here a live ADCNet
//! echo subnet has a non-leader relay misbehave (in-band, via
//! `Anymone::set_misbehavior`, so the node stays up). The leader's monitor
//! reports a `Liveness` fault: *attributed* to a relay that withholds its share,
//! *unattributable* for one that contributes a corrupt-but-signed share (a
//! non-threshold DC-net can't pin corruption on a relay). No committee — only the
//! runtime monitor is in play.

use std::sync::Arc;
use std::time::Duration;

use anymone_core::config::{AdcnetConfig, ExchangePublicKeyWire, PanetiereConfig};
use anymone_core::transport::Transport;
use anymone_core::{
    Anymone, AnymoneRoundConfiguration, Attribution, Event, FaultKind, FaultReport, Identity,
    InMemoryNetwork, Misbehavior, ProtocolConfig, Pubkey, ServiceEntry, ServiceTag, TOPIC_FAULTS,
};

fn echo_tag() -> ServiceTag {
    ServiceTag::from_label("anymone.echo")
}

fn xkw(id: &Identity) -> ExchangePublicKeyWire {
    id.exchange_keys()
}

/// Outcome of one fault scenario: the leader's gossiped `FaultReport`, the
/// victim/leader pubkeys, and whether the same fault also surfaced on the
/// leader's `events()` stream.
struct Reported {
    report: FaultReport,
    victim: Pubkey,
    leader_pk: Pubkey,
    saw_event: bool,
    dup_count: usize,
}

/// Stand up a live ADCNet echo subnet, make the chosen non-leader relay adopt
/// `mode` after a few healthy rounds, and collect the leader's reported fault
/// from both `anymone/faults` and its `events()` stream.
async fn fault_for(mode: Misbehavior, panetiere: bool, want: FaultKind) -> Reported {
    let net = InMemoryNetwork::new();
    let committee = Identity::generate();
    let relays: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let service = Identity::generate();
    let client = Identity::generate();

    let mut relay_pks: Vec<_> = relays.iter().map(|i| i.pubkey()).collect();
    relay_pks.sort();
    let mut relay_xk: Vec<_> = relays.iter().map(|i| (i.pubkey(), xkw(i))).collect();
    relay_xk.sort_by_key(|(p, _)| *p);

    let protocol = if panetiere {
        ProtocolConfig::Panetiere(PanetiereConfig {
            round_duration_ms: 200,
            message_size: 256,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [7u8; 32],
            encoding: anymone_core::config::Encoding::default(),
        })
    } else {
        ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: 200,
            max_payload_bytes: 256,
            estimated_messages: 8,
            client_set_min: 0,
            client_set_max: 8,
            aggregation: None,
        })
    };
    let cfg = AnymoneRoundConfiguration::singleton_subnet(
        0,
        protocol,
        relay_pks.clone(),
        relay_xk,
        vec![ServiceEntry {
            tag: echo_tag(),
            pubkey: service.pubkey(),
        }],
    )
    .sign_with(&[&committee]);

    // Subnet 0's leader is sorted_relays[0]; its monitor is the fault reporter.
    let leader_pk = relay_pks[0];

    let mut relay_nodes: Vec<(Identity, Anymone)> = Vec::new();
    for id in relays.into_iter() {
        let a =
            Anymone::start_with_config(id.clone(), Arc::new(net.handle(id.pubkey())), cfg.clone())
                .await;
        relay_nodes.push((id, a));
    }
    let mut leader_events = relay_nodes
        .iter()
        .find(|(id, _)| id.pubkey() == leader_pk)
        .map(|(_, a)| a.events())
        .expect("leader is among the relays");

    let service_anymone = Anymone::start_with_config(
        service.clone(),
        Arc::new(net.handle(service.pubkey())),
        cfg.clone(),
    )
    .await;
    let client_anymone = Anymone::start_with_config(
        client.clone(),
        Arc::new(net.handle(client.pubkey())),
        cfg.clone(),
    )
    .await;

    let mut svc_pipe = service_anymone.bind(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        while let Some(req) = svc_pipe.recv().await {
            let _ = svc_pipe.send_to(req.return_tag, req.payload).await;
        }
    });

    // Keep a client sending every round so the subnet keeps running rounds (and
    // producing shares) throughout, before and after the misbehavior starts.
    let pipe = client_anymone.open(echo_tag()).await.unwrap();
    tokio::spawn(async move {
        let _keep = client_anymone;
        loop {
            let _ = pipe.send(b"ping".to_vec()).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });

    let mut faults_sub = net
        .handle(Identity::generate().pubkey())
        .subscribe(TOPIC_FAULTS)
        .await;

    // Rounds up to the newest decoded one are warm-up, so an injected fault must
    // be reported for a later one. This ADCNet channel routinely peel-stalls, so
    // requiring health there would be flaky.
    let mut healthy_through = 0;
    let mut decoded = 0;
    let reached = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match leader_events.recv().await {
                Ok(Event::RoundDecoded { round, subnet: 0, .. }) => {
                    healthy_through = healthy_through.max(round);
                    decoded += 1;
                    if decoded >= 3 {
                        return;
                    }
                }
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(
        !panetiere || reached.is_ok(),
        "Panetiere subnet never decoded three healthy rounds before injection"
    );

    let victim = relay_pks.iter().copied().find(|p| *p != leader_pk).unwrap();
    relay_nodes
        .iter()
        .find(|(id, _)| id.pubkey() == victim)
        .map(|(_, a)| a.set_misbehavior(Some(mode)))
        .expect("victim is among the relays");

    // Warm-up stalls each gossip a Liveness fault; discard that backlog.
    let mut last_healthy_round = healthy_through;
    while let Some(msg) = faults_sub.try_recv() {
        if let Some(r) = FaultReport::decode(&msg.payload) {
            last_healthy_round = last_healthy_round.max(r.round);
        }
    }

    let report = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let msg = faults_sub.recv().await.expect("faults topic closed");
            if let Some(r) = FaultReport::decode(&msg.payload) {
                // A corrupt share both fails verification (Integrity) and can cost
                // the round its decode margin (Liveness); which fires first varies.
                if r.round > last_healthy_round && r.fault.kind == want {
                    return r;
                }
            }
        }
    })
    .await
    .expect("no fault was ever gossiped after the relay started misbehaving");

    // The same fault is surfaced locally on the leader's events() stream.
    let saw_event = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match leader_events.recv().await {
                Ok(Event::Fault { subnet: 0, .. }) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);

    let mut dup_count = 0usize;
    let _ = tokio::time::timeout(Duration::from_millis(600), async {
        loop {
            let msg = faults_sub.recv().await.expect("faults topic closed");
            if let Some(r) = FaultReport::decode(&msg.payload) {
                // Any relay may report the fault it decoded; what must not happen
                // is one node reporting it twice.
                if r.round == report.round
                    && r.fault.kind == report.fault.kind
                    && r.reporter == report.reporter
                {
                    dup_count += 1;
                }
            }
        }
    })
    .await;

    drop(relay_nodes);
    Reported {
        report,
        victim,
        leader_pk,
        saw_event,
        dup_count,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn misbehaving_relay_is_reported_as_a_liveness_fault() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    // Withhold: the relay's share never appears, so the leader attributes the
    // stall to it — and the fault reaches both the gossip topic and events().
    let r = fault_for(Misbehavior::Withhold, false, FaultKind::Liveness).await;
    assert_eq!(r.report.subnet, 0);
    assert_eq!(r.report.fault.kind, FaultKind::Liveness);
    assert_eq!(
        r.report.reporter, r.leader_pk,
        "the leader is the subnet's fault reporter"
    );
    assert_eq!(
        r.report.fault.attribution,
        Attribution::Peers(vec![r.victim]),
        "a withheld share is attributable to the silent relay"
    );
    assert!(
        r.saw_event,
        "leader's events() never yielded the Liveness fault"
    );

    // Corrupt-share under ADCNet: every relay's (validly signed) share is
    // present, but the leader can't combine — an unattributable fault.
    let r = fault_for(Misbehavior::CorruptShare, false, FaultKind::Liveness).await;
    assert_eq!(r.report.fault.kind, FaultKind::Liveness);
    assert_eq!(r.report.reporter, r.leader_pk);
    assert_eq!(
        r.report.fault.attribution,
        Attribution::None,
        "a corrupt-but-signed share can't be pinned on a relay without validation gadgets"
    );
}

/// Under Panetiere the HVC verifier names the relay whose share fails its
/// opening, so a corrupt share is an *attributed* `Integrity` fault — and the
/// subnet still decodes from the honest shares (t-of-n).
#[tokio::test(flavor = "multi_thread")]
async fn panetiere_corrupt_share_is_attributed_integrity() {
    let r = fault_for(Misbehavior::CorruptShare, true, FaultKind::Integrity).await;
    assert_eq!(r.report.subnet, 0);
    assert_eq!(r.report.fault.kind, FaultKind::Integrity);
    assert_eq!(r.report.reporter, r.leader_pk);
    assert_eq!(
        r.report.fault.attribution,
        Attribution::Peers(vec![r.victim]),
        "Panetiere attributes a bad share to its relay"
    );
    assert!(
        !r.report.fault.evidence.is_empty(),
        "evidence is the offending ServerPublic bytes"
    );
    assert!(
        r.saw_event,
        "leader's events() never yielded the Integrity fault"
    );
    assert_eq!(
        r.dup_count, 0,
        "a node must report a given round's fault once, however many of its checks caught it"
    );
}
