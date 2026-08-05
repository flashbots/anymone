//! Committee scheduling routine + registration plumbing.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::config::ExchangePublicKeyWire;
use crate::governance::TOPIC_REGISTRATION;
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
        /// `host:port` clients dial to reach this relay off-network. Signed, so
        /// a peer can't redirect another relay's clients.
        #[serde(default)]
        client_addr: Option<String>,
        signature: Vec<u8>, // must match pubkey
    },
    Service {
        tag: ServiceTag,
        pubkey: Pubkey,
        exchange_pubkey: ExchangePublicKeyWire,
        signature: Vec<u8>, // must match pubkey
    },
    /// A node that only follows the network (observers, dashboards). Carries no
    /// exchange key: it never takes part in a protocol round, it just needs to
    /// be reachable, so the committee lists it as a secondary peer.
    Watcher {
        pubkey: Pubkey,
        signature: Vec<u8>, // must match pubkey
    },
}

/// Domain-tagged message a relay signs to register: `"anymone-relay" || pubkey
/// || ecdh_pubkey || kem_pubkey || set_sig_pubkey`.
fn relay_sign_msg(
    pubkey: &Pubkey,
    xk: &ExchangePublicKeyWire,
    client_addr: Option<&str>,
) -> Vec<u8> {
    let mut msg = b"anymone-relay".to_vec();
    msg.extend_from_slice(&pubkey.0);
    msg.extend_from_slice(&xk.ecdh);
    msg.extend_from_slice(&xk.kem);
    msg.extend_from_slice(&xk.set_sig);
    // Tagged, so an absent address can't be confused with an empty one.
    match client_addr {
        Some(a) => {
            msg.push(1);
            msg.extend_from_slice(a.as_bytes());
        }
        None => msg.push(0),
    }
    msg
}

/// `"anymone-watcher" || pubkey`.
fn watcher_sign_msg(pubkey: &Pubkey) -> Vec<u8> {
    let mut msg = b"anymone-watcher".to_vec();
    msg.extend_from_slice(&pubkey.0);
    msg
}

/// Domain-tagged message a service signs: `"anymone-service" || tag || pubkey
/// || ecdh_pubkey || kem_pubkey`.
fn service_sign_msg(tag: &ServiceTag, pubkey: &Pubkey, xk: &ExchangePublicKeyWire) -> Vec<u8> {
    let mut msg = b"anymone-service".to_vec();
    msg.extend_from_slice(&tag.0);
    msg.extend_from_slice(&pubkey.0);
    msg.extend_from_slice(&xk.ecdh);
    msg.extend_from_slice(&xk.kem);
    msg.extend_from_slice(&xk.set_sig);
    msg
}

impl Registration {
    /// Build a relay registration signed by `identity`.
    pub fn relay(identity: &Identity, exchange_pubkey: ExchangePublicKeyWire) -> Self {
        Self::relay_at(identity, exchange_pubkey, None)
    }

    /// As [`Self::relay`], advertising an address clients dial to reach it.
    pub fn relay_at(
        identity: &Identity,
        exchange_pubkey: ExchangePublicKeyWire,
        client_addr: Option<String>,
    ) -> Self {
        let pubkey = identity.pubkey();
        let signature = identity.sign(&relay_sign_msg(
            &pubkey,
            &exchange_pubkey,
            client_addr.as_deref(),
        ));
        Registration::Relay {
            pubkey,
            exchange_pubkey,
            client_addr,
            signature,
        }
    }

    /// Build a watcher registration signed by `identity`.
    pub fn watcher(identity: &Identity) -> Self {
        let pubkey = identity.pubkey();
        Registration::Watcher {
            pubkey,
            signature: identity.sign(&watcher_sign_msg(&pubkey)),
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
                client_addr,
                signature,
            } => pubkey.verify(
                &relay_sign_msg(pubkey, exchange_pubkey, client_addr.as_deref()),
                signature,
            ),
            Registration::Service {
                tag,
                pubkey,
                exchange_pubkey,
                signature,
            } => pubkey.verify(&service_sign_msg(tag, pubkey, exchange_pubkey), signature),
            Registration::Watcher { pubkey, signature } => {
                pubkey.verify(&watcher_sign_msg(pubkey), signature)
            }
        }
    }
}

const REGISTRATION_REANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);

/// Re-broadcast a relay registration on `TOPIC_REGISTRATION` every
/// [`REGISTRATION_REANNOUNCE_INTERVAL`] for the node's lifetime. The single
/// announce mechanism: re-announcing is idempotent (the committee dedups relays),
/// and continuing past placement lets a sidelined relay re-register and heal.
/// The task ends when the transport — held by the running node — is dropped.
pub async fn announce_relay_registration(
    transport: Arc<dyn Transport>,
    identity: &Identity,
    exchange_pubkey: ExchangePublicKeyWire,
) -> JoinHandle<()> {
    announce_relay_registration_at(transport, identity, exchange_pubkey, None).await
}

/// As [`announce_relay_registration`], advertising a client-facing address.
pub async fn announce_relay_registration_at(
    transport: Arc<dyn Transport>,
    identity: &Identity,
    exchange_pubkey: ExchangePublicKeyWire,
    client_addr: Option<String>,
) -> JoinHandle<()> {
    spawn_reannounce(
        transport,
        Registration::relay_at(identity, exchange_pubkey, client_addr).encode(),
    )
}

/// Re-broadcast a watcher registration for the node's lifetime (see
/// [`announce_relay_registration`]).
pub async fn announce_watcher_registration(
    transport: Arc<dyn Transport>,
    identity: &Identity,
) -> JoinHandle<()> {
    spawn_reannounce(transport, Registration::watcher(identity).encode())
}

/// Re-broadcast a service registration for the node's lifetime (see
/// [`announce_relay_registration`]).
pub async fn announce_service_registration(
    transport: Arc<dyn Transport>,
    identity: &Identity,
    tag: ServiceTag,
    exchange_pubkey: ExchangePublicKeyWire,
) -> JoinHandle<()> {
    spawn_reannounce(
        transport,
        Registration::service(identity, tag, exchange_pubkey).encode(),
    )
}

fn spawn_reannounce(transport: Arc<dyn Transport>, reg: Vec<u8>) -> JoinHandle<()> {
    tokio::spawn(async move {
        // `interval`, not a `sleep` loop: a `sleep` restarts its countdown after
        // each publish completes, so cadence skews forward by however long the
        // publish itself takes; `interval` ticks on a fixed schedule regardless.
        let mut tick = tokio::time::interval(REGISTRATION_REANNOUNCE_INTERVAL);
        loop {
            tick.tick().await;
            transport.publish(TOPIC_REGISTRATION, reg.clone()).await;
        }
    })
}

/// Which protocol a subnet runs. The committee's `SchedulerCore` picks this
/// per subnet (ADCNet optimistic, Panetiere when escalated); it is not a global
/// knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerProtocol {
    /// ADCNet 1-round IBLT-message flow. Non-threshold; optimistic default.
    Adcnet,
    /// Real Panetiere threshold ABC. Strict mode on fault.
    Panetiere,
    /// Panetiere's staggered two-phase mode, layered onto a `Panetiere`-family
    /// subnet once its observed traffic passes the scheduled-mode threshold
    /// (see `SchedulerCore::apply_sched_mode`); not chosen by the escalation
    /// ladder itself.
    ScheduledPanetiere,
    /// Crypto-free broadcast, pin-only (`protocol = "noop"`): isolates the
    /// scheduling/runtime control loop from protocol cost in load tests.
    Noop,
}
