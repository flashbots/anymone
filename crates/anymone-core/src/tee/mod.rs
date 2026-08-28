//! Platform attestation for clients of an attested subnet.
//!
//! A client proves once per validity window that its signing key lives in an
//! attested platform, and the relay remembers the key until the window lapses.
//! Everything after that is the per-round signature check the protocols already
//! do, so a quote never rides the protocol wire. The proof binds the key the
//! stream handshake authenticated and a committee round — without the round a
//! captured quote would enrol its key forever.

#[cfg(feature = "tdx-attest")]
pub mod tdx;

#[cfg(feature = "mobile-attest")]
pub mod android_key;
#[cfg(feature = "mobile-attest")]
pub mod app_attest;
#[cfg(feature = "mobile-attest")]
pub mod play_integrity;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{AttestationPolicy, Round};
use crate::identity::Pubkey;

#[cfg(feature = "tdx-attest")]
pub use tdx::{TdxProver, TdxVerifier};

#[cfg(feature = "mobile-attest")]
pub use android_key::AndroidKeyVerifier;
#[cfg(feature = "mobile-attest")]
pub use app_attest::AppAttestVerifier;
#[cfg(feature = "mobile-attest")]
pub use play_integrity::PlayIntegrityVerifier;

pub(crate) const TEE: &str = "anymone::tee";

pub const MAX_ATTESTATION_BYTES: usize = 24 * 1024;

pub const DEFAULT_VALIDITY_ROUNDS: Round = 100;

/// Clients and relays adopt a new config at slightly different times.
const ROUND_SLACK: Round = 2;

const MAX_ENROLLED: usize = 1 << 16;

#[derive(Debug, Error)]
pub enum TeeError {
    #[error("no attestation platform available: {0}")]
    PlatformUnavailable(String),
    #[error("fetching attestation: {0}")]
    Fetch(String),
    #[error("encoding attestation: {0}")]
    Encode(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationScheme {
    Tdx,
    PlayIntegrity,
    AppAttest,
    AndroidKeyAttestation,
}

impl AttestationScheme {
    fn tag(self) -> &'static [u8] {
        match self {
            AttestationScheme::Tdx => b"tdx",
            AttestationScheme::PlayIntegrity => b"play-integrity",
            AttestationScheme::AppAttest => b"app-attest",
            AttestationScheme::AndroidKeyAttestation => b"android-key-attestation",
        }
    }
}

impl std::fmt::Display for AttestationScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AttestationScheme::Tdx => "tdx",
            AttestationScheme::PlayIntegrity => "play-integrity",
            AttestationScheme::AppAttest => "app-attest",
            AttestationScheme::AndroidKeyAttestation => "android-key-attestation",
        })
    }
}

/// A client's platform proof, as it travels on the client plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub scheme: AttestationScheme,
    pub round: Round,
    /// TDX: SCALE-encoded `AttestationEvidence`. Play Integrity: the verdict
    /// token. App Attest: `key_id ‖ CBOR attestation object`.
    #[serde(with = "serde_bytes")]
    pub evidence: Vec<u8>,
}

/// `requestHash` for Play Integrity, `clientDataHash` for App Attest. TDX lays
/// the same commitment out in its 64 report-data bytes, see [`tdx::report_data`].
pub fn challenge(scheme: AttestationScheme, statement: &[u8], round: Round) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"anymone/attest/v0");
    h.update(scheme.tag());
    h.update(statement);
    h.update(round.to_le_bytes());
    h.finalize().into()
}

pub trait TeeProver: Send + Sync {
    /// Evidence binding `statement` — the client's own pubkey — and `round`.
    /// Re-asked until it answers, so an implementation that fetches
    /// asynchronously must drop completions for a round it is no longer asked for.
    fn attest(&self, statement: &[u8], round: Round) -> Result<Attestation, TeeError>;
}

pub trait TeeVerifier: Send + Sync {
    /// Whether `att` proves an accepted platform holds `statement` at
    /// `att.round`. Freshness of the round is [`AttestedClients`]' job.
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool;
}

pub struct MultiVerifier {
    #[cfg(feature = "tdx-attest")]
    tdx: Option<TdxVerifier>,
    #[cfg(feature = "mobile-attest")]
    play_integrity: Option<PlayIntegrityVerifier>,
    #[cfg(feature = "mobile-attest")]
    app_attest: Option<AppAttestVerifier>,
    #[cfg(feature = "mobile-attest")]
    android_key: Option<AndroidKeyVerifier>,
}

impl MultiVerifier {
    pub fn from_policy(policy: &AttestationPolicy) -> Self {
        #[cfg(not(feature = "tdx-attest"))]
        if !policy.tdx_images.is_empty() {
            tracing::warn!(
                target: TEE,
                images = policy.tdx_images.len(),
                "policy lists TDX images but this build lacks `tdx-attest`; \
                 those enrolments are refused while peer relays accept them"
            );
        }

        #[cfg(not(feature = "mobile-attest"))]
        if policy.play_integrity.is_some()
            || policy.app_attest.is_some()
            || policy.android_key.is_some()
        {
            tracing::warn!(
                target: TEE,
                "policy demands a mobile scheme but this build lacks `mobile-attest`; \
                 those enrolments are refused while peer relays accept them"
            );
        }

        MultiVerifier {
            #[cfg(feature = "tdx-attest")]
            tdx: None,
            #[cfg(feature = "mobile-attest")]
            play_integrity: policy
                .play_integrity
                .clone()
                .map(PlayIntegrityVerifier::new),
            #[cfg(feature = "mobile-attest")]
            app_attest: policy.app_attest.clone().map(AppAttestVerifier::new),
            #[cfg(feature = "mobile-attest")]
            android_key: policy.android_key.clone().map(AndroidKeyVerifier::new),
        }
    }

    /// `pccs` must be prewarmed; without one the policy's images are unusable.
    #[cfg(feature = "tdx-attest")]
    pub fn with_tdx(mut self, policy: &AttestationPolicy, pccs: Option<attest_pccs::Pccs>) -> Self {
        self.tdx = match (policy.tdx_images.is_empty(), pccs) {
            (false, Some(pccs)) => Some(TdxVerifier::new(policy.tdx_images.clone(), pccs)),
            (false, None) => {
                tracing::warn!(
                    target: TEE,
                    images = policy.tdx_images.len(),
                    "policy lists TDX images but no PCCS is configured; TDX enrolment refused"
                );
                None
            }
            (true, _) => None,
        };
        self
    }
}

impl TeeVerifier for MultiVerifier {
    #[cfg_attr(
        not(any(feature = "tdx-attest", feature = "mobile-attest")),
        allow(unused_variables)
    )]
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
        match att.scheme {
            #[cfg(feature = "tdx-attest")]
            AttestationScheme::Tdx => self.tdx.as_ref().is_some_and(|v| v.verify(statement, att)),
            #[cfg(feature = "mobile-attest")]
            AttestationScheme::PlayIntegrity => self
                .play_integrity
                .as_ref()
                .is_some_and(|v| v.verify(statement, att)),
            #[cfg(feature = "mobile-attest")]
            AttestationScheme::AppAttest => self
                .app_attest
                .as_ref()
                .is_some_and(|v| v.verify(statement, att)),
            #[cfg(feature = "mobile-attest")]
            AttestationScheme::AndroidKeyAttestation => self
                .android_key
                .as_ref()
                .is_some_and(|v| v.verify(statement, att)),
            #[cfg(not(all(feature = "tdx-attest", feature = "mobile-attest")))]
            _ => false,
        }
    }
}

/// Which client keys a relay has seen prove an accepted platform, and until
/// which round each one holds. One table per node, filled by the client plane
/// at enrolment and read by every attested subnet's session screen.
pub struct AttestedClients {
    verifier: RwLock<Option<Arc<dyn TeeVerifier>>>,
    /// The policy `verifier` was built from, so an unchanged one is kept and
    /// the clients it admitted stay admitted.
    policy: Mutex<Option<AttestationPolicy>>,
    enrolled: Mutex<HashMap<Pubkey, Round>>,
    round: AtomicU64,
    validity_rounds: AtomicU64,
}

impl Default for AttestedClients {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestedClients {
    /// Fail-closed until a verifier is set.
    pub fn new() -> Self {
        AttestedClients {
            verifier: RwLock::new(None),
            policy: Mutex::new(None),
            enrolled: Mutex::new(HashMap::new()),
            round: AtomicU64::new(0),
            validity_rounds: AtomicU64::new(DEFAULT_VALIDITY_ROUNDS),
        }
    }

    /// Rebuilds only on a changed policy, since that drops every client already
    /// admitted. Returns whether the policy changed — a node's own evidence was
    /// judged against the outgoing one too, so it has to be presented again.
    pub fn adopt_policy(
        &self,
        policy: &AttestationPolicy,
        build: impl FnOnce(&AttestationPolicy) -> Arc<dyn TeeVerifier>,
    ) -> bool {
        let mut held = self.policy.lock().expect("attested clients lock");
        if held.as_ref() == Some(policy) {
            return false;
        }
        *held = Some(policy.clone());
        drop(held);
        self.set_verifier(Some(build(policy)), policy.validity_rounds);
        true
    }

    /// Swapping the verifier drops every enrolment: the old evidence was judged
    /// against a policy that no longer holds.
    pub fn set_verifier(&self, verifier: Option<Arc<dyn TeeVerifier>>, validity_rounds: Round) {
        let validity = if validity_rounds == 0 {
            DEFAULT_VALIDITY_ROUNDS
        } else {
            validity_rounds
        };
        self.validity_rounds.store(validity, Ordering::Relaxed);
        *self.verifier.write().expect("attested clients lock") = verifier;
        self.enrolled.lock().expect("attested clients lock").clear();
    }

    pub fn set_round(&self, round: Round) {
        self.round.store(round, Ordering::Relaxed);
        self.enrolled
            .lock()
            .expect("attested clients lock")
            .retain(|_, expiry| *expiry > round);
    }

    pub fn round(&self) -> Round {
        self.round.load(Ordering::Relaxed)
    }

    pub fn validity_rounds(&self) -> Round {
        self.validity_rounds.load(Ordering::Relaxed)
    }

    /// `client` is the key the transport authenticated, never one the message
    /// names: an attestation is only good for the channel it arrives on.
    pub fn enroll(&self, client: &Pubkey, att: &Attestation) -> bool {
        if att.evidence.len() > MAX_ATTESTATION_BYTES {
            tracing::debug!(
                target: TEE,
                %client,
                len = att.evidence.len(),
                "attestation too large, dropped"
            );
            return false;
        }
        let now = self.round();
        let validity = self.validity_rounds();
        // `att.round` is whatever the wire said, so the window arithmetic has to
        // survive `u64::MAX` without wrapping into a valid-looking range.
        let expiry = att.round.saturating_add(validity);
        if expiry <= now || att.round > now.saturating_add(ROUND_SLACK) {
            tracing::debug!(
                target: TEE,
                %client,
                round = att.round,
                now,
                validity,
                "attestation round outside the accepted window, dropped"
            );
            return false;
        }

        let verifier = self.verifier.read().expect("attested clients lock").clone();
        let Some(verifier) = verifier else {
            tracing::debug!(target: TEE, %client, "no attestation verifier configured, dropped");
            return false;
        };
        if !verifier.verify(&client.0, att) {
            tracing::debug!(
                target: TEE,
                %client,
                scheme = %att.scheme,
                round = att.round,
                "attestation did not verify, dropped"
            );
            return false;
        }

        let mut enrolled = self.enrolled.lock().expect("attested clients lock");
        if enrolled.len() >= MAX_ENROLLED && !enrolled.contains_key(client) {
            enrolled.retain(|_, e| *e > now);
            if enrolled.len() >= MAX_ENROLLED {
                tracing::warn!(target: TEE, %client, "enrolment table full, dropped");
                return false;
            }
        }
        let entry = enrolled.entry(*client).or_insert(expiry);
        *entry = (*entry).max(expiry);
        tracing::debug!(
            target: TEE,
            %client,
            scheme = %att.scheme,
            round = att.round,
            expiry,
            "client attested"
        );
        true
    }

    pub fn contains(&self, client: &Pubkey) -> bool {
        let now = self.round();
        self.enrolled
            .lock()
            .expect("attested clients lock")
            .get(client)
            .is_some_and(|expiry| *expiry > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct YesVerifier;
    impl TeeVerifier for YesVerifier {
        fn verify(&self, _statement: &[u8], _att: &Attestation) -> bool {
            true
        }
    }

    fn att(round: Round) -> Attestation {
        Attestation {
            scheme: AttestationScheme::Tdx,
            round,
            evidence: vec![1, 2, 3],
        }
    }

    fn pk(b: u8) -> Pubkey {
        Pubkey([b; 32])
    }

    #[test]
    fn enrolment_holds_for_the_window_then_lapses() {
        let gate = AttestedClients::new();
        assert!(!gate.enroll(&pk(1), &att(0)), "fail-closed before a policy");

        gate.set_verifier(Some(Arc::new(YesVerifier)), 10);
        gate.set_round(5);
        assert!(gate.enroll(&pk(1), &att(5)));
        assert!(gate.contains(&pk(1)));

        gate.set_round(14);
        assert!(gate.contains(&pk(1)));
        gate.set_round(15);
        assert!(!gate.contains(&pk(1)));

        assert!(!gate.enroll(&pk(1), &att(5)), "evidence already expired");
        assert!(!gate.enroll(&pk(1), &att(18)), "beyond the config we hold");
        assert!(
            !gate.enroll(&pk(1), &att(Round::MAX)),
            "a wire round that overflows the window is refused, not wrapped"
        );
        assert!(gate.enroll(&pk(1), &att(16)), "slack covers a config skew");

        gate.set_verifier(Some(Arc::new(YesVerifier)), 10);
        assert!(!gate.contains(&pk(1)), "new policy re-judges everyone");
    }

    #[test]
    fn oversized_evidence_is_refused_before_verifying() {
        let gate = AttestedClients::new();
        gate.set_verifier(Some(Arc::new(YesVerifier)), 10);
        let mut a = att(0);
        a.evidence = vec![0u8; MAX_ATTESTATION_BYTES + 1];
        assert!(!gate.enroll(&pk(2), &a));
    }

    #[test]
    fn challenge_separates_schemes_keys_and_rounds() {
        let s = [7u8; 32];
        let base = challenge(AttestationScheme::Tdx, &s, 1);
        assert_ne!(base, challenge(AttestationScheme::PlayIntegrity, &s, 1));
        assert_ne!(base, challenge(AttestationScheme::Tdx, &s, 2));
        assert_ne!(base, challenge(AttestationScheme::Tdx, &[8u8; 32], 1));
    }
}
