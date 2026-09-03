//! Bridge from the platform attestation SDKs to `TeeProver`.
//!
//! The SDK calls only exist in Kotlin/Swift and are async, while `attest` is
//! synchronous and runs on a runtime worker under a lock. So `attest` never
//! waits: it serves a cached token, or kicks off a fetch and reports that none
//! is ready yet. The node treats that as "stay off attested subnets this
//! round" and asks again on the next config adoption.

use std::sync::{Arc, Mutex};

use anymone_core::tee::{self, Attestation, AttestationScheme, TeeError, TeeProver};

/// Refetch this many rounds into the window, mirroring the halfway reissue the
/// runtime applies to an attestation it already holds.
const MAX_AGE_ROUNDS: u64 = tee::DEFAULT_VALIDITY_ROUNDS / 2;

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum MobileScheme {
    PlayIntegrity,
    AppAttest,
    AndroidKeyAttestation,
}

impl From<MobileScheme> for AttestationScheme {
    fn from(s: MobileScheme) -> Self {
        match s {
            MobileScheme::PlayIntegrity => AttestationScheme::PlayIntegrity,
            MobileScheme::AppAttest => AttestationScheme::AppAttest,
            MobileScheme::AndroidKeyAttestation => AttestationScheme::AndroidKeyAttestation,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FetchError {
    /// No attestation on this device: an emulator, a simulator, or a build
    /// without the entitlement.
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("fetch failed: {0}")]
    Failed(String),
}

/// What the shells implement.
///
/// `challenge` is 32 bytes committing to this client's key and the committee
/// round. Return the platform's evidence for it:
/// - Play Integrity: the verdict token bytes, requested with
///   `requestHash = base64url-nopad(challenge)`.
/// - App Attest: `key_id (32 bytes) ‖ CBOR attestation object`, attested with
///   `clientDataHash = challenge` under a freshly generated key.
/// - Android key attestation: the DER certificates of a key generated with
///   `setAttestationChallenge(challenge)`, leaf first, concatenated.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait AttestationTokenFetcher: Send + Sync {
    async fn fetch(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FetchError>;
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum AttestationStatus {
    /// No prover wired: the client only uses open subnets.
    Unattested,
    /// Nothing fetched yet.
    Cold,
    Pending {
        round: u64,
    },
    Ready {
        round: u64,
        evidence_bytes: u64,
    },
    Failed {
        detail: String,
    },
}

enum State {
    Cold,
    Pending(u64),
    Ready(Attestation),
    Failed(String),
}

struct Shared {
    state: State,
    /// Fetches started. Rounds advance while a platform call is outstanding, so
    /// a completion from an older generation is dropped rather than applied.
    generation: u64,
}

pub(crate) struct BridgeProver {
    scheme: AttestationScheme,
    fetcher: Arc<dyn AttestationTokenFetcher>,
    shared: Arc<Mutex<Shared>>,
}

impl BridgeProver {
    pub(crate) fn new(scheme: MobileScheme, fetcher: Arc<dyn AttestationTokenFetcher>) -> Self {
        BridgeProver {
            scheme: scheme.into(),
            fetcher,
            shared: Arc::new(Mutex::new(Shared {
                state: State::Cold,
                generation: 0,
            })),
        }
    }

    pub(crate) fn status(&self) -> AttestationStatus {
        match &self.shared.lock().unwrap().state {
            State::Cold => AttestationStatus::Cold,
            State::Pending(round) => AttestationStatus::Pending { round: *round },
            State::Ready(a) => AttestationStatus::Ready {
                round: a.round,
                evidence_bytes: a.evidence.len() as u64,
            },
            State::Failed(detail) => AttestationStatus::Failed {
                detail: detail.clone(),
            },
        }
    }

    fn spawn_fetch(&self, statement: &[u8], round: u64, generation: u64) {
        let challenge = tee::challenge(self.scheme, statement, round).to_vec();
        let (fetcher, scheme, shared) = (self.fetcher.clone(), self.scheme, self.shared.clone());
        crate::RUNTIME.spawn(async move {
            let next = match fetcher.fetch(challenge).await {
                Ok(evidence) if evidence.len() > tee::MAX_ATTESTATION_BYTES => State::Failed(
                    format!("evidence is {} bytes, over the limit", evidence.len()),
                ),
                Ok(evidence) => State::Ready(Attestation {
                    scheme,
                    round,
                    evidence,
                }),
                Err(e) => State::Failed(e.to_string()),
            };
            let mut shared = shared.lock().unwrap();
            if shared.generation == generation {
                shared.state = next;
            }
        });
    }
}

impl TeeProver for BridgeProver {
    fn attest(&self, statement: &[u8], round: u64) -> Result<Attestation, TeeError> {
        let mut shared = self.shared.lock().unwrap();
        match &shared.state {
            // Subtracted, not summed: `round` is wire-provided and the sum can overflow.
            State::Ready(a) if a.round <= round && round - a.round < MAX_AGE_ROUNDS => {
                return Ok(a.clone())
            }
            State::Pending(r) if *r == round => {
                return Err(TeeError::Fetch("token fetch in flight".into()))
            }
            _ => {}
        }
        shared.state = State::Pending(round);
        shared.generation += 1;
        let generation = shared.generation;
        drop(shared);
        self.spawn_fetch(statement, round, generation);
        Err(TeeError::Fetch("no token yet for this round".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Canned(Result<Vec<u8>, FetchError>);

    #[async_trait::async_trait]
    impl AttestationTokenFetcher for Canned {
        async fn fetch(&self, _challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
            match &self.0 {
                Ok(v) => Ok(v.clone()),
                Err(FetchError::Unavailable(m)) => Err(FetchError::Unavailable(m.clone())),
                Err(FetchError::Failed(m)) => Err(FetchError::Failed(m.clone())),
            }
        }
    }

    /// Records the challenge it was handed, so the test can check the binding.
    struct Recording(Mutex<Vec<Vec<u8>>>);

    #[async_trait::async_trait]
    impl AttestationTokenFetcher for Recording {
        async fn fetch(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
            self.0.lock().unwrap().push(challenge);
            Ok(vec![7u8; 16])
        }
    }

    /// Polls rather than sleeping a fixed span: the fetch completes on another
    /// runtime, so any fixed wait is a flake on a loaded runner.
    async fn wait_for(mut done: impl FnMut() -> bool) {
        for _ in 0..300 {
            if done() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("condition never held");
    }

    fn is_ready(s: AttestationStatus) -> bool {
        matches!(s, AttestationStatus::Ready { .. })
    }

    #[tokio::test]
    async fn cold_then_pending_then_ready() {
        let prover =
            BridgeProver::new(MobileScheme::AppAttest, Arc::new(Canned(Ok(vec![1, 2, 3]))));
        let pk = [9u8; 32];

        assert!(matches!(prover.status(), AttestationStatus::Cold));
        assert!(
            prover.attest(&pk, 5).is_err(),
            "first call only starts a fetch"
        );
        wait_for(|| is_ready(prover.status())).await;

        let att = prover.attest(&pk, 5).expect("token cached after the fetch");
        assert_eq!(att.round, 5);
        assert_eq!(att.scheme, AttestationScheme::AppAttest);
        assert_eq!(att.evidence, vec![1, 2, 3]);
        assert!(matches!(
            prover.status(),
            AttestationStatus::Ready { round: 5, .. }
        ));
    }

    #[tokio::test]
    async fn cached_token_serves_the_rest_of_its_window_then_refetches() {
        let prover = BridgeProver::new(MobileScheme::PlayIntegrity, Arc::new(Canned(Ok(vec![4]))));
        let pk = [1u8; 32];
        let _ = prover.attest(&pk, 10);
        wait_for(|| is_ready(prover.status())).await;

        // Inside the window the same evidence is reused, so a client does not
        // spend a platform request every round.
        assert_eq!(
            prover.attest(&pk, 10 + MAX_AGE_ROUNDS - 1).unwrap().round,
            10
        );
        // At the edge it refetches instead of handing back a stale round.
        assert!(prover.attest(&pk, 10 + MAX_AGE_ROUNDS).is_err());
    }

    /// Counts attempts, so a fresh fetch is distinguishable from a latched
    /// failure without racing the spawned task for a transient `Pending`.
    struct CountingFail(Mutex<u32>);

    #[async_trait::async_trait]
    impl AttestationTokenFetcher for CountingFail {
        async fn fetch(&self, _challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
            *self.0.lock().unwrap() += 1;
            Err(FetchError::Unavailable("simulator".into()))
        }
    }

    #[tokio::test]
    async fn failure_is_reported_and_retried() {
        let fetcher = Arc::new(CountingFail(Mutex::new(0)));
        let prover = BridgeProver::new(MobileScheme::AppAttest, fetcher.clone());
        let pk = [2u8; 32];
        assert!(prover.attest(&pk, 1).is_err());
        wait_for(|| matches!(prover.status(), AttestationStatus::Failed { .. })).await;
        match prover.status() {
            AttestationStatus::Failed { detail } => assert!(detail.contains("simulator")),
            other => panic!("expected a failed status, got {other:?}"),
        }
        // A later round starts a fresh attempt rather than latching the failure.
        assert!(prover.attest(&pk, 2).is_err());
        wait_for(|| *fetcher.0.lock().unwrap() == 2).await;
    }

    /// Stalls the one challenge it is given, so completions arrive in the
    /// reverse of the request order. `done` marks the stalled one landing.
    struct SlowFor {
        stalled: Vec<u8>,
        done: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl AttestationTokenFetcher for SlowFor {
        async fn fetch(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
            if challenge == self.stalled {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                self.done.store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(vec![1]);
            }
            Ok(vec![2])
        }
    }

    #[tokio::test]
    async fn a_late_fetch_does_not_clobber_a_newer_round() {
        let pk = [4u8; 32];
        let fetcher = Arc::new(SlowFor {
            stalled: tee::challenge(AttestationScheme::AppAttest, &pk, 1).to_vec(),
            done: std::sync::atomic::AtomicBool::new(false),
        });
        let prover = BridgeProver::new(MobileScheme::AppAttest, fetcher.clone());

        assert!(prover.attest(&pk, 1).is_err());
        assert!(prover.attest(&pk, 2).is_err());
        wait_for(|| is_ready(prover.status())).await;
        assert!(matches!(
            prover.status(),
            AttestationStatus::Ready { round: 2, .. }
        ));

        // The round-1 fetch resolves last; without the generation guard its
        // write lands here, within microseconds of `done`.
        wait_for(|| fetcher.done.load(std::sync::atomic::Ordering::SeqCst)).await;
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let att = prover.attest(&pk, 2).expect("round 2 token still held");
            assert_eq!(att.round, 2);
            assert_eq!(
                att.evidence,
                vec![2],
                "a stale fetch overwrote a newer round"
            );
        }
    }

    #[tokio::test]
    async fn challenge_binds_the_key_and_the_round() {
        let fetcher = Arc::new(Recording(Mutex::new(Vec::new())));
        let prover = BridgeProver::new(MobileScheme::AppAttest, fetcher.clone());
        let pk = [3u8; 32];
        let _ = prover.attest(&pk, 42);
        wait_for(|| fetcher.0.lock().unwrap().len() == 1).await;

        let seen = fetcher.0.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            tee::challenge(AttestationScheme::AppAttest, &pk, 42).to_vec()
        );
        assert_ne!(
            seen[0],
            tee::challenge(AttestationScheme::AppAttest, &pk, 43).to_vec()
        );
        assert_ne!(
            seen[0],
            tee::challenge(AttestationScheme::PlayIntegrity, &pk, 42).to_vec()
        );
    }

    /// The framing this crate ships has to satisfy the verifier a relay runs, so
    /// this goes through the genuine Android key verifier and enrolment path
    /// rather than a stand-in. Minted evidence stands in for KeyMint's, which
    /// only a device's secure hardware can produce.
    #[tokio::test]
    async fn android_key_evidence_enrols_against_the_real_verifier() {
        use anymone_core::config::AttestationPolicy;
        use anymone_core::tee::android_key::AndroidKeyMinter;
        use anymone_core::tee::{AttestedClients, MultiVerifier};

        const PACKAGE: &str = "net.flashbots.anymone";
        let minter = Arc::new(AndroidKeyMinter::new(PACKAGE));
        let identity = anymone_core::Identity::generate();
        let pk = identity.pubkey();

        // What the Kotlin fetcher does: hand the challenge to the platform and
        // return the certificate chain it signs.
        struct Keystore(Arc<AndroidKeyMinter>, anymone_core::Pubkey, u64);
        #[async_trait::async_trait]
        impl AttestationTokenFetcher for Keystore {
            async fn fetch(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
                let minted = self.0.mint(&self.1 .0, self.2);
                assert_eq!(
                    challenge,
                    tee::challenge(AttestationScheme::AndroidKeyAttestation, &self.1 .0, self.2)
                        .to_vec()
                );
                Ok(minted)
            }
        }

        let round = 9;
        let prover = BridgeProver::new(
            MobileScheme::AndroidKeyAttestation,
            Arc::new(Keystore(minter.clone(), pk, round)),
        );
        let _ = prover.attest(&pk.0, round);
        wait_for(|| is_ready(prover.status())).await;
        let att = prover.attest(&pk.0, round).expect("chain ready");
        assert_eq!(att.scheme, AttestationScheme::AndroidKeyAttestation);

        let policy = AttestationPolicy {
            android_key: Some(minter.policy()),
            ..Default::default()
        };
        let gate = AttestedClients::new();
        gate.adopt_policy(&policy, |p| Arc::new(MultiVerifier::from_policy(p)));
        gate.set_round(round);

        assert!(gate.enroll(&pk, &att));
        assert!(gate.contains(&pk));

        // The evidence is bound to the key that enrolled it.
        let other = anymone_core::Identity::generate().pubkey();
        assert!(!gate.enroll(&other, &att));
    }

    /// A relay accepts the evidence this prover produces: same challenge
    /// derivation on both sides, checked through the real enrolment path.
    #[tokio::test]
    async fn enrolment_accepts_what_the_prover_produces() {
        use anymone_core::tee::{AttestedClients, TeeVerifier};

        struct ChallengeChecking(AttestationScheme);
        impl TeeVerifier for ChallengeChecking {
            fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
                att.scheme == self.0
                    && att.evidence == tee::challenge(self.0, statement, att.round).to_vec()
            }
        }

        struct EchoChallenge;
        #[async_trait::async_trait]
        impl AttestationTokenFetcher for EchoChallenge {
            async fn fetch(&self, challenge: Vec<u8>) -> Result<Vec<u8>, FetchError> {
                Ok(challenge)
            }
        }

        let prover = BridgeProver::new(MobileScheme::AppAttest, Arc::new(EchoChallenge));
        let identity = anymone_core::Identity::generate();
        let pk = identity.pubkey();
        let _ = prover.attest(&pk.0, 3);
        wait_for(|| is_ready(prover.status())).await;
        let att = prover.attest(&pk.0, 3).expect("token ready");

        let gate = AttestedClients::new();
        gate.set_verifier(
            Some(Arc::new(ChallengeChecking(AttestationScheme::AppAttest))),
            100,
        );
        gate.set_round(3);
        assert!(gate.enroll(&pk, &att));
        assert!(gate.contains(&pk));

        // The statement is the handshake key: another client cannot replay it.
        let other = anymone_core::Identity::generate().pubkey();
        assert!(!gate.enroll(&other, &att));
    }
}
