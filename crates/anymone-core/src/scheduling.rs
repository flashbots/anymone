//! Committee scheduling routine + registration plumbing.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::config::{
    AdcnetConfig, AnymoneRoundConfiguration, ExchangePublicKeyWire, NoopConfig, PanetiereConfig,
    ProtocolConfig, ServiceEntry,
};
use crate::governance::{TOPIC_CONFIG, TOPIC_REGISTRATION};
use crate::identity::{Identity, Pubkey};
use crate::transport::Transport;
use crate::wire::ServiceTag;

/// What relays and services publish on `anymone/registration` once they're
/// alive and want to be considered by the committee for the next config.
/// **Clients do not register** — they're permissionless and dynamic, exchanging keys
/// directly with relays on the subnet (a signed `ClientKey`), never via the committee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Registration {
    Relay {
        pubkey: Pubkey,
        exchange_pubkey: ExchangePublicKeyWire,
        signature: Vec<u8>, // must match pubkey
    },
    Service {
        tag: ServiceTag,
        pubkey: Pubkey,
        exchange_pubkey: ExchangePublicKeyWire,
        signature: Vec<u8>, // must match pubkey
    },
}

/// Domain-tagged message a relay signs to register: `"anymone-relay" || pubkey
/// || exchange_pubkey`.
fn relay_sign_msg(pubkey: &Pubkey, xk: &ExchangePublicKeyWire) -> Vec<u8> {
    let mut msg = b"anymone-relay".to_vec();
    msg.extend_from_slice(&pubkey.0);
    msg.extend_from_slice(&xk.0);
    msg
}

/// Domain-tagged message a service signs: `"anymone-service" || tag || pubkey
/// || exchange_pubkey`.
fn service_sign_msg(tag: &ServiceTag, pubkey: &Pubkey, xk: &ExchangePublicKeyWire) -> Vec<u8> {
    let mut msg = b"anymone-service".to_vec();
    msg.extend_from_slice(&tag.0);
    msg.extend_from_slice(&pubkey.0);
    msg.extend_from_slice(&xk.0);
    msg
}

impl Registration {
    /// Build a relay registration signed by `identity`.
    pub fn relay(identity: &Identity, exchange_pubkey: ExchangePublicKeyWire) -> Self {
        let pubkey = identity.pubkey();
        let signature = identity.sign(&relay_sign_msg(&pubkey, &exchange_pubkey));
        Registration::Relay {
            pubkey,
            exchange_pubkey,
            signature,
        }
    }

    /// Build a service registration signed by `identity`.
    pub fn service(
        identity: &Identity,
        tag: ServiceTag,
        exchange_pubkey: ExchangePublicKeyWire,
    ) -> Self {
        let pubkey = identity.pubkey();
        let signature = identity.sign(&service_sign_msg(&tag, &pubkey, &exchange_pubkey));
        Registration::Service {
            tag,
            pubkey,
            exchange_pubkey,
            signature,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Registration serialises")
    }

    /// True if the embedded `pubkey` produced the embedded signature over the
    /// registration's domain-tagged fields. Ingestion points drop registrations
    /// that fail this check.
    pub fn verify(&self) -> bool {
        match self {
            Registration::Relay {
                pubkey,
                exchange_pubkey,
                signature,
            } => pubkey.verify(&relay_sign_msg(pubkey, exchange_pubkey), signature),
            Registration::Service {
                tag,
                pubkey,
                exchange_pubkey,
                signature,
            } => pubkey.verify(&service_sign_msg(tag, pubkey, exchange_pubkey), signature),
        }
    }
}

const REGISTRATION_REANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

/// Re-broadcast a relay registration until this relay appears in a config (placement
/// is the accept signal), then stop. Closes the gossipsub no-replay race that a single
/// publish loses. Returns the background task's handle.
pub async fn announce_relay_registration(
    transport: Arc<dyn Transport>,
    identity: &Identity,
    exchange_pubkey: ExchangePublicKeyWire,
) -> JoinHandle<()> {
    let pubkey = identity.pubkey();
    let reg = Registration::relay(identity, exchange_pubkey).encode();
    let config_sub = transport.subscribe(TOPIC_CONFIG).await;
    spawn_reannounce(transport, reg, config_sub, move |cfg| {
        cfg.body.subnets.iter().any(|s| s.relays.contains(&pubkey))
    })
}

/// Re-broadcast a service registration until it appears in a config, then stop.
pub async fn announce_service_registration(
    transport: Arc<dyn Transport>,
    identity: &Identity,
    tag: ServiceTag,
    exchange_pubkey: ExchangePublicKeyWire,
) -> JoinHandle<()> {
    let pubkey = identity.pubkey();
    let reg = Registration::service(identity, tag, exchange_pubkey).encode();
    let config_sub = transport.subscribe(TOPIC_CONFIG).await;
    spawn_reannounce(transport, reg, config_sub, move |cfg| {
        cfg.body.subnets.iter().any(|s| {
            s.services
                .iter()
                .any(|e| e.tag == tag && e.pubkey == pubkey)
        })
    })
}

fn spawn_reannounce(
    transport: Arc<dyn Transport>,
    reg: Vec<u8>,
    mut config_sub: crate::transport::Subscription,
    placed: impl Fn(&AnymoneRoundConfiguration) -> bool + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            transport.publish(TOPIC_REGISTRATION, reg.clone()).await;
            tokio::select! {
                _ = tokio::time::sleep(REGISTRATION_REANNOUNCE_INTERVAL) => {}
                msg = config_sub.recv() => {
                    let Some(msg) = msg else { return };
                    if bincode::deserialize::<AnymoneRoundConfiguration>(&msg.payload)
                        .is_ok_and(|cfg| placed(&cfg))
                    {
                        return;
                    }
                }
            }
        }
    })
}

/// Which protocol the committee schedules in the public subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerProtocol {
    /// Noop vector-append. Trivial; for bring-up and CI.
    Noop,
    /// ADCNet 1-round IBLT-message flow. Non-threshold; optimistic default.
    Adcnet,
    /// Real Panetiere threshold ABC. Strict mode on fault.
    Panetiere,
}

/// Configuration knobs for the single-committee scheduler.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Minimum number of relays before the committee builds + publishes
    /// the first configuration.
    pub min_relays: usize,
    /// Minimum number of services before the committee builds + publishes.
    pub min_services: usize,
    /// Round duration the committee uses for the subnets it produces.
    pub subnet_round_duration: Duration,
    /// Which protocol to schedule in the public subnet.
    pub protocol: SchedulerProtocol,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            min_relays: 1,
            min_services: 1,
            subnet_round_duration: Duration::from_secs(1),
            protocol: SchedulerProtocol::Noop,
        }
    }
}

/// Build a `ProtocolConfig` from the scheduler's choice and the subnet's
/// duration. Panetiere's `setup_seed` is derived deterministically from the
/// relay set so every relay (and every late-joining watcher) agrees on the
/// shared parameters without a separate round of out-of-band negotiation.
/// Bundle the rosters the committee observed for a subnet, threaded into
/// `build_protocol_config`. `relays` is the source of truth for the public
/// roster; `relay_exchange_keys` carries each relay's ADCNet exchange pubkey.
pub(crate) struct RegistrationBundle<'a> {
    pub relays: &'a [Pubkey],
    pub relay_exchange_keys: &'a [(Pubkey, ExchangePublicKeyWire)],
}

pub(crate) fn build_protocol_config(
    proto: SchedulerProtocol,
    round_duration: Duration,
    bundle: &RegistrationBundle<'_>,
) -> ProtocolConfig {
    let dur_ms = round_duration.as_millis() as u64;
    match proto {
        SchedulerProtocol::Noop => ProtocolConfig::Noop(NoopConfig {
            round_duration_ms: dur_ms,
            message_size: 1024,
            client_set_min: 0,
            client_set_max: 256,
        }),
        SchedulerProtocol::Adcnet => ProtocolConfig::Adcnet(AdcnetConfig {
            round_duration_ms: dur_ms,
            // Knapsack quantises to KNAPSACK_CHUNK_BYTES (1 KiB); use one
            // chunk per slot for the demo.
            max_payload_bytes: 1024,
            // IBLT sized to the active half; cover (zero) vanishes from it.
            estimated_messages: 16,
            client_set_min: 0,
            client_set_max: 32,
            relay_exchange_keys: bundle.relay_exchange_keys.to_vec(),
            aggregation: None,
        }),
        SchedulerProtocol::Panetiere => {
            let setup_seed = derive_setup_seed(bundle.relays);
            let n = bundle.relays.len() as u32;
            ProtocolConfig::Panetiere(PanetiereConfig {
                round_duration_ms: dur_ms,
                message_size: 1024,
                client_set_min: 0,
                client_set_max: 32,
                threshold: (n / 2 + 1).max(n.saturating_sub(2)),
                setup_seed,
                relay_exchange_keys: bundle.relay_exchange_keys.to_vec(),
                aggregation: None,
            })
        }
    }
}

/// Deterministic 32-byte seed derived from the sorted relay roster. Stable
/// across every committee member and every late joiner: same relays in →
/// same seed out, regardless of insertion order.
fn derive_setup_seed(relays: &[Pubkey]) -> [u8; 32] {
    use std::hash::Hasher;
    let mut sorted = relays.to_vec();
    sorted.sort();
    // Lightweight non-cryptographic mix; the seed is public anyway.
    let mut state = [0u8; 32];
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for pk in &sorted {
        h.write(&pk.0);
    }
    let lo = h.finish().to_le_bytes();
    state[..8].copy_from_slice(&lo);
    // Spread it: hash again with a salt for the next 8 bytes, etc.
    for chunk in 1..4 {
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        h2.write(&state[..chunk * 8]);
        h2.write_u8(chunk as u8);
        state[chunk * 8..(chunk + 1) * 8].copy_from_slice(&h2.finish().to_le_bytes());
    }
    state
}

/// Subscribe to `anymone/registration` synchronously, then spawn the
/// event-driven scheduling task. Returning the `JoinHandle` only after the
/// subscription is in place ensures callers can publish registrations
/// straight after this call without losing them to a sub/publish race.
pub async fn spawn_committee_scheduler(
    transport: Arc<dyn Transport>,
    committee: Identity,
    config: SchedulerConfig,
) -> JoinHandle<()> {
    let mut sub = transport.subscribe(TOPIC_REGISTRATION).await;
    tokio::spawn(async move {
        let mut relays: HashSet<Pubkey> = HashSet::new();
        let mut services: Vec<ServiceEntry> = Vec::new();
        let mut relay_xpubs: std::collections::HashMap<Pubkey, ExchangePublicKeyWire> =
            std::collections::HashMap::new();
        let mut published = false;

        while let Some(msg) = sub.recv().await {
            let Ok(reg) = bincode::deserialize::<Registration>(&msg.payload) else {
                continue;
            };
            if !reg.verify() {
                continue;
            }
            match reg {
                Registration::Relay {
                    pubkey,
                    exchange_pubkey,
                    ..
                } => {
                    relays.insert(pubkey);
                    relay_xpubs.insert(pubkey, exchange_pubkey);
                }
                Registration::Service {
                    tag,
                    pubkey,
                    exchange_pubkey: _,
                    ..
                } => {
                    if !services.iter().any(|s| s.tag == tag) {
                        services.push(ServiceEntry { tag, pubkey });
                    }
                }
            }
            if !published
                && relays.len() >= config.min_relays
                && services.len() >= config.min_services
            {
                let mut relays_vec: Vec<Pubkey> = relays.iter().copied().collect();
                relays_vec.sort();
                let mut services_sorted = services.clone();
                services_sorted.sort_by_key(|s| s.tag.0);
                let relay_xk: Vec<(Pubkey, ExchangePublicKeyWire)> = relays_vec
                    .iter()
                    .filter_map(|pk| relay_xpubs.get(pk).map(|xk| (*pk, xk.clone())))
                    .collect();
                let bundle = RegistrationBundle {
                    relays: &relays_vec,
                    relay_exchange_keys: &relay_xk,
                };
                let protocol =
                    build_protocol_config(config.protocol, config.subnet_round_duration, &bundle);
                let signed = AnymoneRoundConfiguration::singleton_subnet(
                    0,
                    protocol,
                    relays_vec,
                    services_sorted,
                )
                .sign_with(&[&committee]);

                let bytes = bincode::serialize(&signed).expect("config encodes");
                transport.publish(TOPIC_CONFIG, bytes).await;
                published = true;
            }
        }
    })
}
