//! Reconstructed network state, assembled from gossip + scraped peer lists,
//! serialised to the dashboard `/state` contract (see `static/dashboard.html`).
//!
//! The observer never participates. It learns the network from four sources:
//!   - `anymone/config`        → subnets, rosters, services, config history
//!   - `anymone/registration`  → candidate pool (registered-but-unplaced relays)
//!   - per-subnet topics        → live round / goodput / health, via the same
//!                                watch + observer sessions a real node runs
//!   - scraped `/state/peers`   → the p2p mesh (gossip can't expose topology)

use std::collections::{BTreeMap, HashMap, HashSet};

use anymone_core::config::{
    AnymoneRoundConfiguration, ProtocolConfig, ServiceEntry, Subnet, SubnetId,
};
use anymone_core::faults::{Attribution, Fault};
use anymone_core::{Pubkey, ServiceTag};
use serde_json::{json, Value};

/// Cap on the fault feed and config-history vecs, so a long-running demo can't
/// grow them without bound. The dashboard only renders recent entries anyway.
const FEED_CAP: usize = 64;

#[derive(Default, Clone)]
pub struct SubnetLive {
    /// Highest round observed on the wire; `None` until real traffic is seen
    /// (never a synthesized/local value).
    pub round: Option<u64>,
    pub decoded: u64,
    pub share_frontier: Option<u64>,
    pub output_frontier: Option<u64>,
    pub status: String,
    /// Live anonymity set: size of the latest observed canonical client set
    /// (actual submitters this round), not the `client_set_max` config cap.
    pub anon_set: u64,
    /// Ids in that canonical set. The participant count is the union of these
    /// across subnets: a client announced on two subnets is one participant.
    pub clients: Vec<u32>,
    /// Relays observed broadcasting a share recently (on the subnet's shares
    /// topic). Relays in the roster but absent here render as "missing" on the
    /// dashboard. Empty ⇒ no share seen yet (treat all roster relays as live).
    pub live_relays: Vec<Pubkey>,
    /// Bytes seen on the topics the observer watches (broadcast + shares) and
    /// the useful decoded payload bytes, for the wire-overhead ratio. Both
    /// CUMULATIVE; the high-volume client ingress isn't observable.
    pub raw_bytes: u64,
    pub goodput_bytes: u64,
}

/// One subnet round's headline numbers, for the card's per-round breakdown.
#[derive(Clone)]
struct RoundStat {
    round: u64,
    anon_set: u64,
    /// Messages decoded this round (delta of the cumulative counter).
    msgs: u64,
}

struct HistEntry {
    version: u64,
    diff: String,
}

struct FaultEntry {
    round: u64,
    subnet: u32,
    kind: String,
    attribution: Option<Pubkey>,
    /// Observed committee response: the diff of the config that followed.
    action: Option<String>,
}

struct ScrapeInfo {
    role: String,
    live: bool,
}

pub struct Observatory {
    committee: Vec<Pubkey>,
    threshold: u32,
    /// Human-readable description of how this observer sees the network
    /// (e.g. "scraping 4 nodes" or "in-process demo · in-memory gossip").
    vantage: String,
    /// The committee's internal-Panetiere round cadence, for the committee
    /// card's phase ring. Not observable from gossip, so it's supplied at
    /// construction (the demo knows it; `run` mode uses a sensible default).
    committee_round_ms: u64,

    config: Option<AnymoneRoundConfiguration>,
    history: Vec<HistEntry>,
    candidate_relays: HashSet<Pubkey>,
    placed_relays: HashSet<Pubkey>,
    faulted: HashSet<Pubkey>,
    faults: Vec<FaultEntry>,
    /// True from an observed fault or committee signature over a not-yet-current
    /// body, until the next config version lands. Drives the committee card's
    /// "renegotiating" pulse.
    renegotiating: bool,
    live: BTreeMap<SubnetId, SubnetLive>,
    /// Short per-subnet ring of recent round stats (newest at the back).
    recent: BTreeMap<SubnetId, std::collections::VecDeque<RoundStat>>,
    /// Goodput is CUMULATIVE and must never go backwards, but a watcher restart
    /// (e.g. a protocol flip respawns the subnet's watch session) resets its
    /// raw counter to 0. Per subnet we keep the last raw value and an offset
    /// (sum of retired watchers' finals) so the reported total stays monotonic
    /// — otherwise the dashboard's windowed rate goes negative at escalation.
    decoded_raw: HashMap<SubnetId, u64>,
    decoded_offset: HashMap<SubnetId, u64>,
    escalated_at: HashMap<SubnetId, u64>,

    scraped: HashMap<Pubkey, ScrapeInfo>,

    committee_round: u64,
    /// Live anonymity set of the committee's own internal Panetiere — observed
    /// from its `ServerPublic.clients`, same as any subnet.
    committee_anon_set: u64,
    /// Relay the demo's `fault` knob is currently poisoning (demo only), so the
    /// dashboard can mark which chip is under attack. `None` when off.
    fault_target: Option<Pubkey>,
    chat_endpoint: Option<String>,
    tx_endpoint: Option<String>,
}

impl Observatory {
    pub fn new(
        committee: Vec<Pubkey>,
        threshold: u32,
        vantage: String,
        committee_round_ms: u64,
    ) -> Self {
        Observatory {
            committee,
            threshold,
            vantage,
            committee_round_ms,
            config: None,
            history: Vec::new(),
            candidate_relays: HashSet::new(),
            placed_relays: HashSet::new(),
            faulted: HashSet::new(),
            faults: Vec::new(),
            renegotiating: false,
            live: BTreeMap::new(),
            recent: BTreeMap::new(),
            decoded_raw: HashMap::new(),
            decoded_offset: HashMap::new(),
            escalated_at: HashMap::new(),
            scraped: HashMap::new(),
            committee_round: 0,
            committee_anon_set: 0,
            fault_target: None,
            chat_endpoint: None,
            tx_endpoint: None,
        }
    }

    /// Mark (or clear) the relay the demo's `fault` knob is poisoning.
    pub fn set_fault_target(&mut self, pk: Option<Pubkey>) {
        self.fault_target = pk;
    }

    pub fn set_chat_endpoint(&mut self, url: Option<String>) {
        self.chat_endpoint = url;
    }

    /// Tx-bus gateway whose `/tx/feed` the dashboard reads for the bus feed.
    pub fn set_tx_endpoint(&mut self, url: Option<String>) {
        self.tx_endpoint = url;
    }

    /// Ingest a verified config. Returns `true` if it's a new version (so the
    /// caller should (re)spawn per-subnet watchers).
    pub fn on_config(&mut self, cfg: AnymoneRoundConfiguration) -> bool {
        let version = cfg.body.round;
        let is_new = self
            .config
            .as_ref()
            .map_or(true, |c| c.body.round != version);
        if !is_new {
            return false;
        }
        let diff = self.diff_against_current(&cfg);
        // Record protocol escalations (e.g. ADCNet→Panetiere) per subnet.
        if let Some(prev) = &self.config {
            for s in &cfg.body.subnets {
                let was = prev
                    .body
                    .subnets
                    .iter()
                    .find(|p| p.id == s.id)
                    .map(|p| proto_name(&p.protocol));
                if let Some(w) = was {
                    if w != proto_name(&s.protocol) {
                        // Record the real wire round of the escalation if one's been
                        // observed; never a synthesized stand-in.
                        if let Some(r) = self.live.get(&s.id).and_then(|l| l.round) {
                            self.escalated_at.insert(s.id, r);
                        }
                    }
                }
            }
        }
        for f in self.faults.iter_mut().filter(|f| f.action.is_none()) {
            f.action = Some(format!("cfg v{version}: {diff}"));
        }
        self.history.push(HistEntry { version, diff });
        let overflow = self.history.len().saturating_sub(FEED_CAP);
        if overflow > 0 {
            self.history.drain(0..overflow);
        }
        // This config version is the result of (or supersedes) any in-flight
        // renegotiation, so the committee is no longer deliberating.
        self.renegotiating = false;
        self.placed_relays = cfg
            .body
            .subnets
            .iter()
            .flat_map(|s| s.relays.iter().copied())
            .collect();
        // A relay that reappears in a config has healed.
        for pk in &self.placed_relays {
            self.faulted.remove(pk);
        }
        // Seed live entries so cards render before the first watcher tick.
        for s in &cfg.body.subnets {
            self.live.entry(s.id).or_default();
        }
        self.config = Some(cfg);
        true
    }

    fn diff_against_current(&self, next: &AnymoneRoundConfiguration) -> String {
        let Some(prev) = &self.config else {
            let protos: Vec<String> = next
                .body
                .subnets
                .iter()
                .map(|s| format!("subnet{} {}", s.id, proto_name(&s.protocol)))
                .collect();
            return format!("genesis · {}", protos.join(", "));
        };
        let mut parts = Vec::new();
        let prev_relays: HashSet<Pubkey> = prev
            .body
            .subnets
            .iter()
            .flat_map(|s| s.relays.iter().copied())
            .collect();
        let next_relays: HashSet<Pubkey> = next
            .body
            .subnets
            .iter()
            .flat_map(|s| s.relays.iter().copied())
            .collect();
        for pk in prev_relays.difference(&next_relays) {
            parts.push(format!("−{}", short(pk)));
        }
        for pk in next_relays.difference(&prev_relays) {
            parts.push(format!("+{}", short(pk)));
        }
        for s in &next.body.subnets {
            if let Some(p) = prev.body.subnets.iter().find(|p| p.id == s.id) {
                let (a, b) = (proto_name(&p.protocol), proto_name(&s.protocol));
                if a != b {
                    parts.push(format!("subnet{} {}→{}", s.id, a, b));
                }
            }
        }
        if parts.is_empty() {
            "roster refresh".into()
        } else {
            parts.join(" · ")
        }
    }

    pub fn on_relay_registration(&mut self, pk: Pubkey) {
        self.candidate_relays.insert(pk);
        self.faulted.remove(&pk);
    }

    pub fn update_live(&mut self, id: SubnetId, mut live: SubnetLive) {
        // Keep cumulative goodput monotonic across watcher restarts. A protocol
        // flip respawns the subnet's watch session, resetting its raw counter to
        // 0; carry the retired watcher's final count forward as an offset so the
        // reported total never drops (which would make the windowed rate go
        // negative at the escalation moment).
        let raw = live.decoded;
        let prev_raw = self.decoded_raw.get(&id).copied().unwrap_or(0);
        if raw < prev_raw {
            *self.decoded_offset.entry(id).or_default() += prev_raw;
        }
        self.decoded_raw.insert(id, raw);
        live.decoded = self.decoded_offset.get(&id).copied().unwrap_or(0) + raw;

        // msgs this round = delta of the monotonic decoded counter. Only record a
        // per-round stat once a real wire round is known — never a fabricated one.
        let prev_decoded = self.live.get(&id).map(|l| l.decoded).unwrap_or(0);
        let msgs = live.decoded.saturating_sub(prev_decoded);
        if let Some(r) = live.round {
            let ring = self.recent.entry(id).or_default();
            match ring.back_mut() {
                Some(last) if last.round == r => {
                    last.anon_set = live.anon_set;
                    last.msgs = msgs;
                }
                _ => {
                    ring.push_back(RoundStat {
                        round: r,
                        anon_set: live.anon_set,
                        msgs,
                    });
                    while ring.len() > 5 {
                        ring.pop_front();
                    }
                }
            }
        }
        self.live.insert(id, live);
    }

    /// Record an observer-detected fault (deduped by round+subnet+kind).
    pub fn record_fault(&mut self, round: u64, subnet: SubnetId, fault: &Fault) {
        let kind = format!("{:?}", fault.kind);
        if self
            .faults
            .iter()
            .any(|f| f.round == round && f.subnet == subnet && f.kind == kind)
        {
            return;
        }
        let attribution = match &fault.attribution {
            Attribution::Peers(p) => p.first().copied(),
            Attribution::None => None,
        };
        if let Some(pk) = attribution {
            self.faulted.insert(pk);
        }
        self.faults.push(FaultEntry {
            round,
            subnet,
            kind,
            attribution,
            action: None,
        });
        // Bound the feed: a long-running demo would otherwise grow it without
        // limit. Keep the most recent entries.
        let overflow = self.faults.len().saturating_sub(FEED_CAP);
        if overflow > 0 {
            self.faults.drain(0..overflow);
        }
        // The committee is now renegotiating in response; the card pulses until
        // the new config version lands.
        self.renegotiating = true;
    }

    /// A member signed a body that isn't the current config ⇒ a deliberation is
    /// in progress, whatever triggered it (fault, capacity, subnet growth).
    pub fn on_committee_sig(&mut self, body_bytes: &[u8]) {
        let is_current = self
            .config
            .as_ref()
            .is_some_and(|c| c.body.canonical_bytes() == body_bytes);
        if !is_current {
            self.renegotiating = true;
        }
    }

    /// Set the committee round, observed from its Panetiere traffic.
    pub fn set_committee_round(&mut self, round: u64) {
        self.committee_round = self.committee_round.max(round);
    }

    /// Set the committee's live anonymity set, observed from its Panetiere.
    pub fn set_committee_anon_set(&mut self, n: u64) {
        self.committee_anon_set = n;
    }

    /// Apply a scrape of one node's `/state/peers`.
    pub fn apply_scrape(&mut self, pubkey: Pubkey, role: String, _peers: Vec<Pubkey>) {
        self.scraped.insert(pubkey, ScrapeInfo { role, live: true });
    }

    /// Role of a pubkey, from config (committee/relay/service) else scrape, else client.
    fn role_of(&self, pk: &Pubkey) -> &'static str {
        if self.committee.contains(pk) {
            return "committee";
        }
        if let Some(cfg) = &self.config {
            if cfg.body.services.iter().any(|svc| svc.pubkey == *pk) {
                return "service";
            }
            for s in &cfg.body.subnets {
                if s.relays.contains(pk) {
                    return "relay";
                }
            }
        }
        match self.scraped.get(pk).map(|s| s.role.as_str()) {
            Some("committee") => "committee",
            Some("relay") => "relay",
            Some("service") => "service",
            _ => "client",
        }
    }

    /// Known participants with role + liveness. Anonymous clients can't be
    /// identified, so each subnet's observed anonymity set becomes that many
    /// anonymous client entries.
    fn participants(&self) -> Vec<Value> {
        let mut nodes: HashSet<Pubkey> = HashSet::new();
        nodes.extend(self.committee.iter().copied());
        nodes.extend(self.scraped.keys().copied());
        nodes.extend(self.candidate_relays.iter().copied());
        if let Some(cfg) = &self.config {
            for s in &cfg.body.subnets {
                nodes.extend(s.relays.iter().copied());
            }
            nodes.extend(cfg.body.services.iter().map(|svc| svc.pubkey));
        }

        let mut nodes: Vec<Pubkey> = nodes.into_iter().collect();
        nodes.sort();
        let mut out: Vec<Value> = nodes
            .iter()
            .map(|pk| {
                json!({
                    "pk": pk,
                    "role": self.role_of(pk),
                    "live": !self.faulted.contains(pk)
                        && self.scraped.get(pk).map(|s| s.live).unwrap_or(true),
                })
            })
            .collect();

        if let Some(cfg) = &self.config {
            // Keyed by announced client id, so the same client seen on two
            // subnets counts once. Ids are unavailable until a canonical set is
            // observed; fall back to the per-subnet count then.
            let mut ids: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            let mut unnamed = 0u64;
            for s in &cfg.body.subnets {
                match self.live.get(&s.id) {
                    Some(l) if !l.clients.is_empty() => ids.extend(l.clients.iter().copied()),
                    Some(l) => unnamed += l.anon_set,
                    None => {}
                }
            }
            for id in ids {
                out.push(
                    json!({ "pk": format!("client:{id:08x}"), "role": "client", "live": true }),
                );
            }
            for i in 0..unnamed {
                out.push(json!({ "pk": format!("client:?:{i}"), "role": "client", "live": true }));
            }
        }
        out
    }

    pub fn to_json(&self) -> Value {
        let participants = self.participants();
        let version = self.config.as_ref().map(|c| c.body.round).unwrap_or(0);

        let subnets: Vec<Value> = self
            .config
            .as_ref()
            .map(|cfg| {
                cfg.body
                    .subnets
                    .iter()
                    .map(|s| self.subnet_json(s, &cfg.body.services))
                    .collect()
            })
            .unwrap_or_default();

        let faults: Vec<Value> = self
            .faults
            .iter()
            .map(|f| {
                json!({
                    "round": f.round, "subnet": f.subnet, "kind": f.kind,
                    "attribution": f.attribution,
                    "action": f.action.clone().unwrap_or_else(|| "renegotiating…".into()),
                })
            })
            .collect();

        let history: Vec<Value> = self
            .history
            .iter()
            .map(|h| json!({ "version": h.version, "diff": h.diff }))
            .collect();

        let candidate_pool: Vec<&Pubkey> = self
            .candidate_relays
            .difference(&self.placed_relays)
            .collect();

        let committee = if self.committee.is_empty() {
            Value::Null
        } else {
            let leader = self.committee.iter().min().copied();
            json!({
                "round": self.committee_round,
                "round_duration_ms": if self.committee_round_ms == 0 {
                    Value::Null
                } else {
                    json!(self.committee_round_ms)
                },
                "members": self.committee,
                "leader": leader,
                "threshold": self.threshold,
                "deliberating": self.renegotiating,
                "anon_set": self.committee_anon_set,
                // Each published config is one completed committee decision.
                "decoded": self.history.len(),
            })
        };

        json!({
            "observer": {
                "vantage": self.vantage.clone(),
                "config_version": version,
                "threshold": self.threshold,
                "participants": participants.len(),
            },
            "participants": participants,
            "committee": committee,
            "subnets": subnets,
            "faults": faults,
            "candidate_pool": candidate_pool,
            "config": { "version": version, "history": history },
            "fault_target": self.fault_target,
            "chat_endpoint": self.chat_endpoint,
            "tx_endpoint": self.tx_endpoint,
        })
    }

    fn subnet_json(&self, s: &Subnet, all_services: &[ServiceEntry]) -> Value {
        let live = self.live.get(&s.id).cloned().unwrap_or_default();
        // ADCNet's canonical-set leader is sorted_relays[id % n] (spread across
        // subnets so each has a distinct leader — see runtime::adcnet_leader_pk),
        // not the sorted-first relay. Panetiere/Noop have no single leader.
        let leader = {
            let mut r = s.relays.clone();
            r.sort();
            match s.protocol {
                ProtocolConfig::Adcnet(_) | ProtocolConfig::ScheduledAdcnet(_) if !r.is_empty() => {
                    Some(r[(s.id as usize) % r.len()])
                }
                _ => r.first().copied(),
            }
        };
        // Per-round breakdown (newest first) + the latest round's msg count.
        let ring = self.recent.get(&s.id);
        let recent_rounds: Vec<Value> = ring
            .map(|r| {
                r.iter()
                    .rev()
                    .take(3)
                    .map(
                        |st| json!({ "round": st.round, "anon_set": st.anon_set, "msgs": st.msgs }),
                    )
                    .collect()
            })
            .unwrap_or_default();
        let msgs_round = ring.and_then(|r| r.back()).map(|st| st.msgs).unwrap_or(0);
        let services: Vec<Value> = all_services
            .iter()
            .map(|svc| json!({ "tag": tag_label(&svc.tag), "pubkey": svc.pubkey }))
            .collect();
        // Per-relay state: a relay with an attributed fault renders "sidelined"
        // (flagged, on its way out of the roster); a relay that simply hasn't
        // shared recently — once any share has been seen — renders "missing".
        // Before the first share, only "sidelined" can show; everything else is
        // "live" (absent from the map). A relay already dropped from the roster
        // isn't iterated here — its exit shows in the fault feed + config diff.
        let mut relay_states = serde_json::Map::new();
        let live_set: HashSet<Pubkey> = live.live_relays.iter().copied().collect();
        let have_liveness = !live.live_relays.is_empty();
        for pk in &s.relays {
            let state = if self.faulted.contains(pk) {
                Some("sidelined")
            } else if have_liveness && !live_set.contains(pk) {
                Some("missing")
            } else {
                None
            };
            if let Some(state) = state {
                if let Ok(Value::String(key)) = serde_json::to_value(pk) {
                    relay_states.insert(key, json!(state));
                }
            }
        }
        json!({
            "id": s.id,
            "protocol": proto_name(&s.protocol),
            "round": live.round,
            "round_duration_ms": s.protocol.round_duration().as_millis() as u64,
            // Live anonymity set (observed submitters); `capacity` is the subnet's
            // config capacity, kept separate so the dashboard never conflates them.
            "anon_set": live.anon_set,
            "capacity": s.protocol.client_set_max(),
            // Aggregator groups (null = direct flow); each group lists its
            // single aggregator.
            "aggregators": s.protocol.aggregation().map(|a| {
                a.groups.iter().map(|g| vec![g.aggregator]).collect::<Vec<_>>()
            }),
            "decoded": live.decoded,
            "msgs_round": msgs_round,
            // Observed wire overhead: bytes on the topics the observer watches
            // (broadcast + relay shares) per useful decoded payload byte. `null`
            // until something has decoded. Excludes the unobservable client
            // ingress, so it's a lower bound on the true link overhead.
            "wire_overhead": if live.goodput_bytes > 0 {
                Some((live.raw_bytes as f64 / live.goodput_bytes as f64 * 10.0).round() / 10.0)
            } else {
                None
            },
            "recent_rounds": recent_rounds,
            "leader": leader,
            "relays": s.relays,
            "relay_states": relay_states,
            "services": services,
            "status": if self.faults.iter().any(|f| f.subnet == s.id && f.action.is_none()) {
                "renegotiating".to_string()
            } else if live.status.is_empty() {
                "healthy".into()
            } else {
                live.status.clone()
            },
            "share_frontier": live.share_frontier,
            "output_frontier": live.output_frontier,
            "escalated_at": self.escalated_at.get(&s.id),
        })
    }
}

fn proto_name(p: &ProtocolConfig) -> &'static str {
    match p {
        ProtocolConfig::Noop(_) => "Noop",
        ProtocolConfig::Panetiere(_) => "Panetiere",
        ProtocolConfig::ScheduledPanetiere(_) => "Panetiere",
        ProtocolConfig::Adcnet(_) => "Adcnet",
        ProtocolConfig::ScheduledAdcnet(_) => "Adcnet",
    }
}

/// Demo/dashboard service labels — `ServiceTag::from_label` hashes the label,
/// so display can't recover it from the tag bytes; matching against this known
/// set is what makes the dashboard show "anymone.echo" instead of raw hex.
const KNOWN_LABELS: &[&str] = &["anymone.echo", "anymone.chat"];

/// Render a service tag as its label if it matches a known demo service,
/// else hex.
fn tag_label(tag: &ServiceTag) -> String {
    KNOWN_LABELS
        .iter()
        .find(|label| ServiceTag::from_label(label) == *tag)
        .map(|label| label.to_string())
        .unwrap_or_else(|| hex::encode(tag.0))
}

fn short(pk: &Pubkey) -> String {
    let h = hex::encode(pk.0);
    format!("{}…", &h[..h.len().min(6)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use anymone_core::config::AnymoneRoundConfigurationBody;
    use anymone_core::faults::FaultKind;

    fn obs() -> Observatory {
        Observatory::new(vec![], 1, "test".into(), 1000)
    }

    fn cfg(round: u64) -> AnymoneRoundConfiguration {
        AnymoneRoundConfiguration::new(AnymoneRoundConfigurationBody {
            endpoints: Default::default(),
            round,
            epoch_unix_ms: 0,
            services: vec![],
            relay_exchange_keys: vec![],
            subnets: vec![],
            relay_client_addrs: vec![],
            watchers: vec![],
            attestation: Default::default(),
        })
    }

    #[test]
    fn goodput_stays_monotonic_across_watcher_restart() {
        let mut o = obs();
        let mut reported = Vec::new();
        for d in [5u64, 10, 15] {
            o.update_live(
                0,
                SubnetLive {
                    decoded: d,
                    round: Some(d),
                    ..Default::default()
                },
            );
            reported.push(o.live.get(&0).unwrap().decoded);
        }
        // A watcher restart (e.g. protocol flip) resets the raw counter to 0.
        for d in [3u64, 6, 9] {
            o.update_live(
                0,
                SubnetLive {
                    decoded: d,
                    round: Some(100 + d),
                    ..Default::default()
                },
            );
            reported.push(o.live.get(&0).unwrap().decoded);
        }
        for w in reported.windows(2) {
            assert!(w[1] >= w[0], "goodput went backwards: {reported:?}");
        }
        // The retired watcher's final (15) is carried forward as an offset.
        assert_eq!(reported, vec![5, 10, 15, 18, 21, 24]);
        // And no round records a negative delta.
        assert!(o.recent.get(&0).unwrap().iter().all(|r| r.msgs <= 9));
    }

    #[test]
    fn renegotiating_flag_tracks_fault_then_config() {
        let mut o = obs();
        assert!(!o.renegotiating);
        let fault = Fault {
            kind: FaultKind::Liveness,
            attribution: Attribution::None,
            evidence: Vec::new(),
        };
        o.record_fault(1, 0, &fault);
        assert!(
            o.renegotiating,
            "a fault starts the committee renegotiating"
        );
        assert!(o.faults[0].action.is_none(), "no action observed yet");
        assert!(o.on_config(cfg(1)), "first config is a new version");
        assert!(
            !o.renegotiating,
            "the resulting config ends the renegotiation"
        );
        assert!(
            o.faults[0].action.as_deref().unwrap().starts_with("cfg v1"),
            "the config that followed becomes the fault's action"
        );
    }

    #[test]
    fn committee_sig_for_new_body_marks_deliberation() {
        let mut o = obs();
        o.on_config(cfg(1));
        let current = o.config.as_ref().unwrap().body.canonical_bytes();
        o.on_committee_sig(&current);
        assert!(
            !o.renegotiating,
            "sig over the current config is not a deliberation"
        );
        o.on_committee_sig(&cfg(2).body.canonical_bytes());
        assert!(o.renegotiating);
        o.on_config(cfg(2));
        assert!(!o.renegotiating);
    }
}
