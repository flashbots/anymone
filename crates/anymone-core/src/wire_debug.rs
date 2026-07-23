//! Protocol-aware transport tracing.
//!
//! Every transport (in-memory and libp2p) routes each published message
//! through [`trace`], which — when the `ANYMONE_TRACE` env var is set —
//! prints a decoded one-line summary keyed off the topic. This makes it easy
//! to see exactly what's on the wire (which relay shared, when output stops,
//! what config the committee published) without scattering `eprintln`s through
//! the protocol code. Set `ANYMONE_TRACE=1` (or a comma-separated topic
//! substring filter, e.g. `ANYMONE_TRACE=subnet,config`) to enable.
//!
//! Gated behind the `wire-debug` cargo feature (off by default) so a release
//! build can't be made to dump decoded plaintext.

#[cfg(feature = "wire-debug")]
use crate::governance::{TOPIC_CONFIG, TOPIC_FAULTS, TOPIC_REGISTRATION};
#[cfg(feature = "wire-debug")]
use crate::identity::Pubkey;

/// Decode `bytes` on `topic` into a short human-readable description.
#[cfg(feature = "wire-debug")]
pub fn describe(topic: &str, bytes: &[u8]) -> String {
    if topic == TOPIC_CONFIG {
        return describe_config(bytes);
    }
    if topic == TOPIC_REGISTRATION {
        return describe_registration(bytes);
    }
    if topic == TOPIC_FAULTS {
        return "fault".to_string();
    }
    if topic.starts_with("anymone/subnet/") || topic == crate::committee::TOPIC_COMMITTEE_PANETIERE
    {
        // Subnet topics carry whichever protocol the committee scheduled; the
        // committee's internal topic carries Panetiere. Try both decoders.
        if let Some(d) = crate::adcnet::describe(bytes) {
            return d;
        }
        if let Some(d) = crate::panetiere::describe(bytes) {
            return d;
        }
        return format!("subnet? {}B", bytes.len());
    }
    if topic == crate::committee::TOPIC_COMMITTEE_SIGS {
        return "committee-sig".to_string();
    }
    format!("{}B", bytes.len())
}

#[cfg(feature = "wire-debug")]
fn describe_config(bytes: &[u8]) -> String {
    match bincode::deserialize::<crate::config::AnymoneRoundConfiguration>(bytes) {
        Ok(cfg) => {
            let s = cfg.body.subnets.first();
            let proto = s
                .map(|s| match &s.protocol {
                    crate::config::ProtocolConfig::Adcnet(_) => "adcnet",
                    crate::config::ProtocolConfig::Panetiere(_) => "panetiere",
                    crate::config::ProtocolConfig::Noop(_) => "noop",
                    crate::config::ProtocolConfig::ScheduledAdcnet(_) => "scheduled-adcnet",
                    crate::config::ProtocolConfig::ScheduledPanetiere(_) => "scheduled-panetiere",
                    crate::config::ProtocolConfig::Nym(_) => "nym",
                })
                .unwrap_or("none");
            let relays = s.map(|s| s.relays.len()).unwrap_or(0);
            format!(
                "config round={} proto={proto} relays={relays} sigs={}",
                cfg.body.round,
                cfg.signatures.len()
            )
        }
        Err(_) => "config <undecodable>".to_string(),
    }
}

#[cfg(feature = "wire-debug")]
fn describe_registration(bytes: &[u8]) -> String {
    match bincode::deserialize::<crate::scheduling::Registration>(bytes) {
        Ok(crate::scheduling::Registration::Relay { pubkey, .. }) => {
            format!("register relay {}", short(&pubkey))
        }
        Ok(crate::scheduling::Registration::Service { tag, .. }) => {
            format!("register service tag={}", hex::encode(&tag.0[..4]))
        }
        Err(_) => "register <undecodable>".to_string(),
    }
}

#[cfg(feature = "wire-debug")]
fn short(pk: &Pubkey) -> String {
    hex::encode(&pk.0[..4])
}

/// Trace one message if `ANYMONE_TRACE` is set. `from` is the publisher.
/// No-op unless built with the `wire-debug` feature.
#[cfg(feature = "wire-debug")]
pub fn trace(topic: &str, from: &Pubkey, bytes: &[u8]) {
    emit("send", topic, from, bytes);
}

/// Trace a received message (off the wire), distinct from a local publish.
/// No-op unless built with the `wire-debug` feature.
#[cfg(feature = "wire-debug")]
pub fn trace_in(topic: &str, from: &Pubkey, bytes: &[u8]) {
    emit("recv", topic, from, bytes);
}

#[cfg(not(feature = "wire-debug"))]
pub fn trace(_topic: &str, _from: &crate::identity::Pubkey, _bytes: &[u8]) {}

#[cfg(not(feature = "wire-debug"))]
pub fn trace_in(_topic: &str, _from: &crate::identity::Pubkey, _bytes: &[u8]) {}

#[cfg(feature = "wire-debug")]
fn emit(dir: &str, topic: &str, from: &Pubkey, bytes: &[u8]) {
    let Ok(filter) = std::env::var("ANYMONE_TRACE") else {
        return;
    };
    // A non-"1" value is a comma-separated set of topic substrings to include.
    if filter != "1" && !filter.split(',').any(|f| topic.contains(f)) {
        return;
    }
    eprintln!(
        "[{dir}] {} from={} {}B :: {}",
        topic,
        short(from),
        bytes.len(),
        describe(topic, bytes)
    );
}
