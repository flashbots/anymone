//! Scheduling-committee output and per-protocol configs.
//!
//! `AnymoneRoundConfiguration` is the cross-protocol contract:
//! signed by the committee, gossiped on `anymone/config`, consumed by
//! every node. `ProtocolConfig` is a tagged enum — each protocol's own
//! config type lives inside its variant. The scheduler reads the top-level
//! fields it needs; protocol-internal bucket counts, KAHE dims, etc. stay
//! inside their variants and never leak out.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bincode::Options as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::{Identity, Pubkey};
use crate::wire::ServiceTag;

pub type SubnetId = u32;
pub type Round = u64;

/// Current wall-clock in unix milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Body that the multisig signs. Kept separate from `signatures` so the
/// canonical bytes are easy to derive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnymoneRoundConfigurationBody {
    pub round: Round,
    #[serde(default)]
    pub endpoints: crate::discovery::Endpoints,
    /// Round-clock epoch (unix ms). The scheduler stamps the fixed genesis 0;
    /// `round` is the config version, not the clock.
    pub epoch_unix_ms: u64,
    /// Every service is carried on every subnet, so services are a single
    /// global list rather than per-subnet.
    pub services: Vec<ServiceEntry>,
    /// Exchange pubkey per relay, once for the whole config; subnets look
    /// their relays up here (per-subnet copies blew the committee channel).
    pub relay_exchange_keys: Vec<(crate::identity::Pubkey, ExchangePublicKeyWire)>,
    pub subnets: Vec<Subnet>,
    /// Where clients dial each relay, for backends whose clients don't join the
    /// p2p network. Only relays that advertised one appear.
    #[serde(default)]
    pub relay_client_addrs: Vec<(crate::identity::Pubkey, String)>,
    /// Registered follow-only nodes, tracked as secondary peers.
    #[serde(default)]
    pub watchers: Vec<crate::identity::Pubkey>,
    /// What an attested subnet's relays accept as proof of a client's platform.
    #[serde(default)]
    pub attestation: AttestationPolicy,
}

/// What relays on an attested subnet demand of a client before it may submit.
///
/// Every relay must screen by the same rule or they disagree on the canonical
/// client set, so this travels in the signed config rather than node-local
/// files. A scheme with no entry here is refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub tdx_images: Vec<TdxImage>,
    /// Committee rounds an enrolment stays valid for. Clients re-attest before
    /// it lapses.
    pub validity_rounds: Round,
    pub play_integrity: Option<PlayIntegrityPolicy>,
    pub app_attest: Option<AppAttestPolicy>,
    pub android_key: Option<AndroidKeyPolicy>,
}

/// One accepted client image, as `attest measure` emits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxImage {
    pub image: attest_types::PortableMeasurements,
    /// Required for a bare-metal client and unused for a GCP one, which
    /// rebuilds these from its own quote.
    pub firmware: Option<FirmwareRegisters>,
}

/// Registers a firmware fixes. Pinned as values because rebuilding them needs
/// the firmware binary, which no relay should have to hold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirmwareRegisters {
    pub mrtd: serde_bytes::ByteArray<48>,
    /// Also covers RAM size, disk count and ACPI tables, so pinning it fixes
    /// the VM shape.
    pub rtmr0: serde_bytes::ByteArray<48>,
}

/// `PortableMeasurements` carries no `PartialEq`, so images compare on the two
/// halves that do.
impl PartialEq for AttestationPolicy {
    fn eq(&self, other: &Self) -> bool {
        let images = |p: &Self| {
            p.tdx_images
                .iter()
                .map(|i| {
                    (
                        i.image.azure.clone(),
                        i.image.dcap.clone(),
                        i.firmware.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        self.validity_rounds == other.validity_rounds
            && self.play_integrity == other.play_integrity
            && self.app_attest == other.app_attest
            && self.android_key == other.android_key
            && images(self) == images(other)
    }
}

/// Google's verdict token is decrypted and checked locally, so the Play Console
/// keys live here. Anyone holding the config can read verdict tokens — that is
/// inherent to local verification, not an accident of this layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlayIntegrityPolicy {
    /// Play Console response-decryption key (AES-256).
    pub decryption_key: [u8; 32],
    /// Play Console verification key, SEC1 P-256 point.
    #[serde(with = "serde_bytes")]
    pub verification_key: Vec<u8>,
    pub package_name: String,
    /// Accepted app signing certificates, SHA-256 of the DER.
    pub certificate_digests: Vec<[u8; 32]>,
    /// Demand MEETS_STRONG_INTEGRITY; otherwise MEETS_DEVICE_INTEGRITY passes.
    pub require_strong_integrity: bool,
    pub max_token_age_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AndroidKeyPolicy {
    pub package_name: String,
    pub certificate_digests: Vec<[u8; 32]>,
    pub require_strongbox: bool,
    #[serde(with = "serde_bytes")]
    pub root_ca_der: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAttestPolicy {
    pub team_id: String,
    pub bundle_id: String,
    /// Production builds carry the `appattest` aaguid, development
    /// `appattestdevelop`.
    pub production: bool,
    /// Apple's App Attest root, DER. Tests pin their own root here.
    #[serde(with = "serde_bytes")]
    pub root_ca_der: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnymoneRoundConfiguration {
    pub body: AnymoneRoundConfigurationBody,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    pub signer: Pubkey,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Subnet {
    pub id: SubnetId,
    pub relays: Vec<Pubkey>,
    pub protocol: ProtocolConfig,
    /// Probability an idle client sends a cover (zero) message each round.
    pub cover_rate: f32,
    /// Only clients that enrolled an accepted platform attestation may submit.
    #[serde(default)]
    pub attested: bool,
}

impl Subnet {
    /// Subnet with the default cover rate (1.0), open to any client.
    pub fn new(id: SubnetId, relays: Vec<Pubkey>, protocol: ProtocolConfig) -> Self {
        Subnet {
            id,
            relays,
            protocol,
            cover_rate: 1.0,
            attested: false,
        }
    }

    pub fn attested(mut self, attested: bool) -> Self {
        self.attested = attested;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEntry {
    pub tag: ServiceTag,
    pub pubkey: Pubkey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolConfig {
    /// Trivial vector-append broadcast. No crypto. For bring-up and debugging.
    Noop(NoopConfig),
    Panetiere(PanetiereConfig),
    /// Panetiere staggered flow: each round's ciphertext both reserves
    /// message-vector slots for itself and carries the vector payloads for an
    /// earlier round's reservations (fixed round gap, see
    /// `panetiere_scheduled::RESERVATION_TO_MSG_GAP`).
    ScheduledPanetiere(ScheduledPanetiereConfig),
    /// ADCNet 1-round flow: payload rides directly in the IBLT, no auction.
    Adcnet(AdcnetConfig),
    /// ADCNet 2-round flow: auction round allocates message-vector slots,
    /// next round carries the actual payloads.
    ScheduledAdcnet(ScheduledAdcnetConfig),
}

impl ProtocolConfig {
    pub fn round_duration(&self) -> Duration {
        match self {
            ProtocolConfig::Noop(c) => Duration::from_millis(c.round_duration_ms),
            ProtocolConfig::Panetiere(c) => Duration::from_millis(c.round_duration_ms),
            ProtocolConfig::ScheduledPanetiere(c) => Duration::from_millis(c.round_duration_ms),
            ProtocolConfig::Adcnet(c) => Duration::from_millis(c.round_duration_ms),
            ProtocolConfig::ScheduledAdcnet(c) => Duration::from_millis(c.round_duration_ms),
        }
    }

    pub fn message_size(&self) -> usize {
        match self {
            ProtocolConfig::Noop(c) => c.message_size,
            ProtocolConfig::Panetiere(c) => c.message_size,
            ProtocolConfig::ScheduledPanetiere(c) => c.message_size,
            ProtocolConfig::Adcnet(c) => c.max_payload_bytes,
            ProtocolConfig::ScheduledAdcnet(c) => c.message_length,
        }
    }

    pub fn client_set_min(&self) -> u32 {
        match self {
            ProtocolConfig::Noop(c) => c.client_set_min,
            ProtocolConfig::Panetiere(c) => c.client_set_min,
            ProtocolConfig::ScheduledPanetiere(c) => c.client_set_min,
            ProtocolConfig::Adcnet(c) => c.client_set_min,
            ProtocolConfig::ScheduledAdcnet(c) => c.client_set_min,
        }
    }

    pub fn client_set_max(&self) -> u32 {
        match self {
            ProtocolConfig::Noop(c) => c.client_set_max,
            ProtocolConfig::Panetiere(c) => c.client_set_max,
            ProtocolConfig::ScheduledPanetiere(c) => c.client_set_max,
            ProtocolConfig::Adcnet(c) => c.client_set_max,
            ProtocolConfig::ScheduledAdcnet(c) => c.client_set_max,
        }
    }

    pub fn aggregation(&self) -> Option<&Aggregation> {
        match self {
            ProtocolConfig::Adcnet(c) => c.aggregation.as_ref(),
            _ => None,
        }
    }

    /// How the subnet fixes its canonical client set; only the Panetiere family
    /// offers a choice.
    pub fn set_formation(&self) -> SetFormation {
        match self {
            ProtocolConfig::Panetiere(c) => c.set_formation,
            ProtocolConfig::ScheduledPanetiere(c) => c.set_formation,
            _ => SetFormation::Leader,
        }
    }
}

/// Trivial protocol: every client message becomes part of the round output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoopConfig {
    pub round_duration_ms: u64,
    pub message_size: usize,
    pub client_set_min: u32,
    pub client_set_max: u32,
}

impl Default for NoopConfig {
    fn default() -> Self {
        NoopConfig {
            round_duration_ms: 1000,
            message_size: 1024,
            client_set_min: 1,
            client_set_max: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    Prony,
    Mse,
}

/// How a Panetiere subnet fixes the round's canonical client set.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SetFormation {
    /// The subnet leader derives the set and announces it; relays adopt it.
    #[default]
    Leader,
    /// Receipts and coded evidence agreed over Dolev–Strong rounds, so every
    /// relay derives the same set. Needs a round long enough for the phases.
    Consensus,
}

/// Panetiere subnet config. `setup_seed` must be identical across every node
/// in the subnet — it deterministically drives `ProtocolParams::setup` so all
/// participants agree on the public KAHE / CS / Shamir parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PanetiereConfig {
    pub round_duration_ms: u64,
    pub message_size: usize,
    pub estimated_messages: u32,
    pub client_set_min: u32,
    pub client_set_max: u32,
    pub threshold: u32,
    #[serde(with = "serde_bytes_array")]
    pub setup_seed: [u8; 32],
    /// Fixes the KAHE width and plaintext modulus, so it must match subnet-wide.
    #[serde(default)]
    pub encoding: Encoding,
    #[serde(default)]
    pub set_formation: SetFormation,
}

impl Default for PanetiereConfig {
    fn default() -> Self {
        PanetiereConfig {
            round_duration_ms: 1000,
            message_size: 1024,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [0u8; 32],
            encoding: Encoding::default(),
            set_formation: SetFormation::default(),
        }
    }
}

/// Scheduled Panetiere subnet config. Each round's ciphertext carries a tiny
/// MSE reserving `(rand, size)` slots in a `vector_bytes`-wide vector, plus
/// that vector fulfilling an earlier round's reservations (fixed gap, see
/// `panetiere_scheduled::RESERVATION_TO_MSG_GAP`).
/// `setup_seed` plays the same deterministic-setup role as in `PanetiereConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledPanetiereConfig {
    pub round_duration_ms: u64,
    /// Largest single framed message; must fit in `u16` (reservation size).
    pub message_size: usize,
    /// Total width of the message-section vector carried each round.
    pub vector_bytes: usize,
    /// Expected reservations per round (ρ); sizes the reservation MSE.
    pub estimated_messages: u32,
    pub client_set_min: u32,
    pub client_set_max: u32,
    pub threshold: u32,
    #[serde(with = "serde_bytes_array")]
    pub setup_seed: [u8; 32],
    #[serde(default)]
    pub set_formation: SetFormation,
}

impl Default for ScheduledPanetiereConfig {
    fn default() -> Self {
        ScheduledPanetiereConfig {
            round_duration_ms: 1000,
            message_size: 1024,
            vector_bytes: 8192,
            estimated_messages: 4,
            client_set_min: 0,
            client_set_max: 8,
            threshold: 2,
            setup_seed: [0u8; 32],
            set_formation: SetFormation::default(),
        }
    }
}

/// ADCNet aggregator groups: each sums its clients' blinded contributions. Each
/// group has one aggregator; clients map to
/// `hash(client) % groups.len()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Aggregation {
    pub groups: Vec<AggregatorGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregatorGroup {
    pub aggregator: crate::identity::Pubkey,
}

mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(b))
        } else {
            b.serialize(s)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            v.as_slice()
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected 32-byte seed"))
        } else {
            <[u8; 32]>::deserialize(d)
        }
    }
}

/// ADCNet 1-round (IBLT-message) config. Each round carries an IBLT sized
/// for `estimated_messages` distinct payloads of up to `max_payload_bytes`.
/// Clients are **not** listed — they're permissionless and dynamic: a client announces its own
/// exchange pubkey on the subnet, and relays derive the matching secret on the fly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdcnetConfig {
    pub round_duration_ms: u64,
    pub max_payload_bytes: usize,
    pub estimated_messages: u32,
    pub client_set_min: u32,
    pub client_set_max: u32,
    /// `None` = direct flow (every client sends its contribution to the leader).
    #[serde(default)]
    pub aggregation: Option<Aggregation>,
}

pub use crate::keys::ExchangePublicKeyWire;

/// ADCNet auction-then-broadcast config. `message_length` is the total
/// message-vector capacity, in multiples of the auction's 1 KiB allocation
/// unit. `min_message_size` pads each submitted message before bidding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledAdcnetConfig {
    pub round_duration_ms: u64,
    pub message_length: usize,
    pub auction_slots: u32,
    pub min_message_size: u32,
    pub client_set_min: u32,
    pub client_set_max: u32,
}

impl AnymoneRoundConfigurationBody {
    /// Canonical bytes the multisig signs. Bincode with fixint encoding so
    /// the encoding is deterministic on the same input.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        bincode::DefaultOptions::default()
            .with_fixint_encoding()
            .with_big_endian()
            .serialize(self)
            .expect("body is always serialisable")
    }

    /// Inverse of [`Self::canonical_bytes`] — decode a body from the exact
    /// canonical encoding (fixint, big-endian). Use this, not plain
    /// `bincode::deserialize`, when round-tripping `canonical_bytes` (e.g. the
    /// committee-signature body bytes); the default bincode options differ.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::DefaultOptions::default()
            .with_fixint_encoding()
            .with_big_endian()
            .deserialize(bytes)
    }

    /// Bytes the committee lead signs when proposing this body — domain-tagged
    /// separately from [`Self::approve_bytes`] so a proposal signature can't
    /// double as an approval.
    pub fn propose_bytes(&self) -> Vec<u8> {
        tagged_bytes(b"anymone/config/propose", self)
    }

    /// Bytes every committee member signs to approve this body.
    pub fn approve_bytes(&self) -> Vec<u8> {
        tagged_bytes(b"anymone/config/approve", self)
    }
}

fn tagged_bytes(tag: &[u8], body: &AnymoneRoundConfigurationBody) -> Vec<u8> {
    let mut m = tag.to_vec();
    m.extend_from_slice(&body.canonical_bytes());
    m
}

impl AnymoneRoundConfiguration {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::DefaultOptions::new().with_fixint_encoding()
            .with_limit(crate::transport::MAX_TRANSMIT_SIZE as u64)
            .reject_trailing_bytes().deserialize(bytes).ok()
    }

    pub fn new(body: AnymoneRoundConfigurationBody) -> Self {
        AnymoneRoundConfiguration {
            body,
            signatures: Vec::new(),
        }
    }

    /// Append signatures from the given identities. Each identity signs the
    /// approve-tagged body bytes (matching `verify_multisig`). Duplicate
    /// signers are not added.
    pub fn sign_with(mut self, identities: &[&Identity]) -> Self {
        let msg = self.body.approve_bytes();
        for id in identities {
            let pk = id.pubkey();
            if self.signatures.iter().any(|s| s.signer == pk) {
                continue;
            }
            let bytes = id.sign(&msg);
            self.signatures.push(Signature { signer: pk, bytes });
        }
        self
    }

    /// Verify that ≥ threshold distinct signatures from the committee cover
    /// the body. Unknown signers are ignored.
    pub fn verify_multisig(&self, committee: &[Pubkey], threshold: u32) -> Result<(), ConfigError> {
        if threshold == 0 || threshold as usize > committee.len() {
            return Err(ConfigError::BadThreshold {
                threshold,
                committee: committee.len() as u32,
            });
        }
        let msg = self.body.approve_bytes();
        let mut seen: Vec<Pubkey> = Vec::with_capacity(self.signatures.len());
        for sig in &self.signatures {
            if !committee.contains(&sig.signer) {
                continue;
            }
            if seen.contains(&sig.signer) {
                continue;
            }
            if !sig.signer.verify(&msg, &sig.bytes) {
                continue;
            }
            seen.push(sig.signer);
        }
        if (seen.len() as u32) < threshold {
            return Err(ConfigError::InsufficientSignatures {
                got: seen.len() as u32,
                need: threshold,
            });
        }
        Ok(())
    }

    /// Helper for tests and static publishing: one subnet with the
    /// given protocol, relays, and services. SubnetId = 0.
    pub fn singleton_subnet(
        round: Round,
        protocol: ProtocolConfig,
        relays: Vec<Pubkey>,
        relay_exchange_keys: Vec<(Pubkey, ExchangePublicKeyWire)>,
        services: Vec<ServiceEntry>,
    ) -> Self {
        let body = AnymoneRoundConfigurationBody {
            endpoints: Default::default(),
            round,
            epoch_unix_ms: now_unix_ms(),
            services,
            relay_exchange_keys,
            subnets: vec![Subnet::new(0, relays, protocol)],
            relay_client_addrs: Vec::new(),
            watchers: Vec::new(),
            attestation: AttestationPolicy::default(),
        };
        AnymoneRoundConfiguration::new(body)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("threshold {threshold} invalid for committee size {committee}")]
    BadThreshold { threshold: u32, committee: u32 },
    #[error("insufficient signatures: got {got}, need {need}")]
    InsufficientSignatures { got: u32, need: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> AnymoneRoundConfigurationBody {
        AnymoneRoundConfigurationBody {
            endpoints: Default::default(),
            round: 42,
            epoch_unix_ms: 0,
            services: vec![ServiceEntry {
                tag: ServiceTag::from_label("anymone.echo"),
                pubkey: Identity::generate().pubkey(),
            }],
            relay_exchange_keys: vec![],
            subnets: vec![Subnet::new(
                0,
                (0..3).map(|_| Identity::generate().pubkey()).collect(),
                ProtocolConfig::Noop(NoopConfig::default()),
            )],
            relay_client_addrs: vec![],
            watchers: vec![],
            attestation: AttestationPolicy::default(),
        }
    }

    #[test]
    fn canonical_bytes_are_stable() {
        let b = body();
        let a = b.canonical_bytes();
        let b2 = b.canonical_bytes();
        assert_eq!(a, b2);
    }

    #[test]
    fn sign_and_verify_at_threshold() {
        let committee = [
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        ];
        let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
        let cfg = AnymoneRoundConfiguration::new(body()).sign_with(&[&committee[0], &committee[1]]);
        cfg.verify_multisig(&pks, 2)
            .expect("two of three should verify");
    }

    #[test]
    fn one_short_signatures_rejected() {
        let committee = [
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        ];
        let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
        let cfg = AnymoneRoundConfiguration::new(body()).sign_with(&[&committee[0]]);
        let err = cfg.verify_multisig(&pks, 2).unwrap_err();
        assert!(matches!(err, ConfigError::InsufficientSignatures { .. }));
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let committee = [Identity::generate(), Identity::generate()];
        let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
        // Sign once, then manually duplicate the signature.
        let mut cfg = AnymoneRoundConfiguration::new(body()).sign_with(&[&committee[0]]);
        let dup = cfg.signatures[0].clone();
        cfg.signatures.push(dup);
        // Still only one distinct valid signer ⇒ doesn't reach threshold 2.
        let err = cfg.verify_multisig(&pks, 2).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InsufficientSignatures { got: 1, need: 2 }
        ));
    }

    #[test]
    fn unknown_signer_ignored() {
        let committee = [Identity::generate(), Identity::generate()];
        let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
        let outsider = Identity::generate();
        // Sign with the outsider plus one committee member.
        let cfg = AnymoneRoundConfiguration::new(body()).sign_with(&[&committee[0], &outsider]);
        // Outsider does not count; threshold 2 should fail.
        let err = cfg.verify_multisig(&pks, 2).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InsufficientSignatures { got: 1, need: 2 }
        ));
        // Threshold 1 should succeed.
        cfg.verify_multisig(&pks, 1).unwrap();
    }

    #[test]
    fn tampered_body_invalidates_signatures() {
        let committee = [Identity::generate(), Identity::generate()];
        let pks: Vec<Pubkey> = committee.iter().map(|i| i.pubkey()).collect();
        let mut cfg =
            AnymoneRoundConfiguration::new(body()).sign_with(&[&committee[0], &committee[1]]);
        cfg.verify_multisig(&pks, 2).unwrap();
        // Mutate the body.
        cfg.body.round = 99;
        let err = cfg.verify_multisig(&pks, 2).unwrap_err();
        assert!(matches!(err, ConfigError::InsufficientSignatures { .. }));
    }

    #[test]
    fn sign_with_skips_duplicate_signer() {
        let id = Identity::generate();
        let cfg = AnymoneRoundConfiguration::new(body()).sign_with(&[&id, &id]);
        assert_eq!(cfg.signatures.len(), 1);
    }
}
