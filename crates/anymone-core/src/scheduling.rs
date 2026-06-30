//! Committee scheduling routine + registration plumbing.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::config::{AnymoneRoundConfiguration, ExchangePublicKeyWire};
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

/// Which protocol a subnet runs. The committee's `SchedulerCore` picks this
/// per subnet (ADCNet optimistic, Panetiere when escalated); it is not a global
/// knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchedulerProtocol {
    /// ADCNet 1-round IBLT-message flow. Non-threshold; optimistic default.
    Adcnet,
    /// Real Panetiere threshold ABC. Strict mode on fault.
    Panetiere,
}

