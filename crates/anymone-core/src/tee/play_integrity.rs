//! Play Integrity enrolment.
//!
//! The verdict token is decrypted and checked here rather than at Google's
//! decode endpoint, so enrolment costs no network round trip and every relay
//! reaches the same verdict from the same signed policy.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_kw::KekAes256;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

use super::{challenge, Attestation, AttestationScheme, TeeVerifier, TEE};
use crate::config::{now_unix_ms, PlayIntegrityPolicy};

const STRONG: &str = "MEETS_STRONG_INTEGRITY";
const DEVICE: &str = "MEETS_DEVICE_INTEGRITY";

pub struct PlayIntegrityVerifier {
    policy: PlayIntegrityPolicy,
}

impl PlayIntegrityVerifier {
    pub fn new(policy: PlayIntegrityPolicy) -> Self {
        PlayIntegrityVerifier { policy }
    }

    fn decrypt(&self, token: &[u8]) -> Option<Vec<u8>> {
        let token = std::str::from_utf8(token).ok()?;
        let mut parts = token.split('.');
        let (header, key, iv, ciphertext, tag) = (
            parts.next()?,
            parts.next()?,
            parts.next()?,
            parts.next()?,
            parts.next()?,
        );
        if parts.next().is_some() {
            return None;
        }

        let hdr: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
        if hdr.get("alg")?.as_str()? != "A256KW" || hdr.get("enc")?.as_str()? != "A256GCM" {
            return None;
        }

        let cek = KekAes256::new(&self.policy.decryption_key.into())
            .unwrap_vec(&URL_SAFE_NO_PAD.decode(key).ok()?)
            .ok()?;
        let iv = URL_SAFE_NO_PAD.decode(iv).ok()?;
        if iv.len() != 12 {
            return None;
        }
        let mut sealed = URL_SAFE_NO_PAD.decode(ciphertext).ok()?;
        sealed.extend_from_slice(&URL_SAFE_NO_PAD.decode(tag).ok()?);

        Aes256Gcm::new_from_slice(&cek)
            .ok()?
            .decrypt(
                Nonce::from_slice(&iv),
                aes_gcm::aead::Payload {
                    msg: &sealed,
                    aad: header.as_bytes(),
                },
            )
            .ok()
    }

    fn open_jws(&self, jws: &[u8]) -> Option<Value> {
        let jws = std::str::from_utf8(jws).ok()?;
        let mut parts = jws.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }

        let hdr: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
        if hdr.get("alg")?.as_str()? != "ES256" {
            return None;
        }

        let key = VerifyingKey::from_sec1_bytes(&self.policy.verification_key).ok()?;
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?).ok()?;
        key.verify(format!("{header}.{payload}").as_bytes(), &sig)
            .ok()?;

        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
    }

    fn check_verdict(&self, verdict: &Value, expected_hash: &str) -> bool {
        let details = &verdict["requestDetails"];
        if details["requestHash"].as_str() != Some(expected_hash) {
            tracing::debug!(target: TEE, "play integrity: requestHash does not bind this enrolment");
            return false;
        }
        if details["requestPackageName"].as_str() != Some(self.policy.package_name.as_str()) {
            tracing::debug!(target: TEE, "play integrity: token was issued to another package");
            return false;
        }

        let age = details["timestampMillis"]
            .as_str()
            .and_then(|t| t.parse::<u64>().ok())
            .map(|t| now_unix_ms().saturating_sub(t));
        match age {
            Some(age) if age <= self.policy.max_token_age_ms => {}
            _ => {
                tracing::debug!(target: TEE, ?age, "play integrity: token too old or undated");
                return false;
            }
        }

        let app = &verdict["appIntegrity"];
        if app["appRecognitionVerdict"].as_str() != Some("PLAY_RECOGNIZED") {
            tracing::debug!(target: TEE, "play integrity: app not recognised by Play");
            return false;
        }
        if app["packageName"].as_str() != Some(self.policy.package_name.as_str()) {
            return false;
        }

        let signed_by_us = app["certificateSha256Digest"]
            .as_array()
            .is_some_and(|digests| {
                digests.iter().filter_map(Value::as_str).any(|d| {
                    URL_SAFE_NO_PAD
                        .decode(d)
                        .or_else(|_| STANDARD.decode(d))
                        .is_ok_and(|raw| {
                            self.policy
                                .certificate_digests
                                .iter()
                                .any(|want| want.as_slice() == raw)
                        })
                })
            });
        if !signed_by_us {
            tracing::debug!(target: TEE, "play integrity: unknown app signing certificate");
            return false;
        }

        let device = verdict["deviceIntegrity"]["deviceRecognitionVerdict"].as_array();
        let met = device.is_some_and(|labels| {
            labels.iter().filter_map(Value::as_str).any(|l| {
                l == STRONG || (!self.policy.require_strong_integrity && l == DEVICE)
            })
        });
        if !met {
            tracing::debug!(target: TEE, "play integrity: device integrity not met");
            return false;
        }
        true
    }
}

impl TeeVerifier for PlayIntegrityVerifier {
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
        if att.scheme != AttestationScheme::PlayIntegrity {
            return false;
        }
        let Some(jws) = self.decrypt(&att.evidence) else {
            tracing::debug!(target: TEE, "play integrity: token did not decrypt");
            return false;
        };
        let Some(verdict) = self.open_jws(&jws) else {
            tracing::debug!(target: TEE, "play integrity: verdict signature invalid");
            return false;
        };
        let expected =
            URL_SAFE_NO_PAD.encode(challenge(att.scheme, statement, att.round));
        self.check_verdict(&verdict, &expected)
    }
}

/// Mints the tokens Google would mint, for tests: production tokens are only
/// obtainable from Play services on a real device.
#[cfg(any(test, feature = "test-util"))]
pub struct PlayIntegrityMinter {
    decryption_key: [u8; 32],
    signing: p256::ecdsa::SigningKey,
}

#[cfg(any(test, feature = "test-util"))]
impl PlayIntegrityMinter {
    pub fn new(seed: u8) -> Self {
        let signing = p256::ecdsa::SigningKey::from_bytes(&[seed.max(1); 32].into())
            .expect("valid scalar");
        PlayIntegrityMinter {
            decryption_key: [seed; 32],
            signing,
        }
    }

    pub fn policy(&self, package_name: &str, cert: [u8; 32]) -> PlayIntegrityPolicy {
        PlayIntegrityPolicy {
            decryption_key: self.decryption_key,
            verification_key: self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            package_name: package_name.to_string(),
            certificate_digests: vec![cert],
            require_strong_integrity: true,
            max_token_age_ms: 60_000,
        }
    }

    pub fn mint(&self, verdict: &Value) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;

        let jws_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(verdict).expect("verdict json"));
        let signing_input = format!("{jws_header}.{payload}");
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        let jws = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );

        let jwe_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"A256KW","enc":"A256GCM"}"#);
        let cek = [0x2bu8; 32];
        let wrapped = KekAes256::new(&self.decryption_key.into())
            .wrap_vec(&cek)
            .expect("wrap cek");
        let iv = [0x17u8; 12];
        let sealed = Aes256Gcm::new_from_slice(&cek)
            .expect("cek")
            .encrypt(
                Nonce::from_slice(&iv),
                aes_gcm::aead::Payload {
                    msg: jws.as_bytes(),
                    aad: jwe_header.as_bytes(),
                },
            )
            .expect("seal verdict");
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        format!(
            "{jwe_header}.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(wrapped),
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(ciphertext),
            URL_SAFE_NO_PAD.encode(tag)
        )
        .into_bytes()
    }
}

/// A verdict a genuine device would produce for this enrolment.
#[cfg(any(test, feature = "test-util"))]
pub fn verdict_for(
    statement: &[u8],
    round: crate::config::Round,
    package_name: &str,
    cert: [u8; 32],
) -> Value {
    serde_json::json!({
        "requestDetails": {
            "requestPackageName": package_name,
            "requestHash": URL_SAFE_NO_PAD
                .encode(challenge(AttestationScheme::PlayIntegrity, statement, round)),
            "timestampMillis": now_unix_ms().to_string(),
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": package_name,
            "certificateSha256Digest": [URL_SAFE_NO_PAD.encode(cert)],
            "versionCode": "42",
        },
        "deviceIntegrity": { "deviceRecognitionVerdict": [STRONG] },
        "accountDetails": { "appLicensingVerdict": "LICENSED" },
    })
}

#[cfg(any(test, feature = "test-util"))]
pub fn cert_digest(tag: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    Sha256::digest(tag.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKG: &str = "net.flashbots.anymone";

    fn setup() -> (PlayIntegrityMinter, PlayIntegrityVerifier, [u8; 32]) {
        let minter = PlayIntegrityMinter::new(9);
        let cert = cert_digest("release");
        let verifier = PlayIntegrityVerifier::new(minter.policy(PKG, cert));
        (minter, verifier, cert)
    }

    fn att(minter: &PlayIntegrityMinter, verdict: &Value, round: u64) -> Attestation {
        Attestation {
            scheme: AttestationScheme::PlayIntegrity,
            round,
            evidence: minter.mint(verdict),
        }
    }

    #[test]
    fn accepts_a_genuine_verdict_for_this_key_and_round() {
        let (minter, verifier, cert) = setup();
        let pk = [3u8; 32];
        let verdict = verdict_for(&pk, 5, PKG, cert);
        assert!(verifier.verify(&pk, &att(&minter, &verdict, 5)));
    }

    #[test]
    fn rejects_a_verdict_bound_to_another_key_or_round() {
        let (minter, verifier, cert) = setup();
        let pk = [3u8; 32];
        let verdict = verdict_for(&pk, 5, PKG, cert);
        assert!(!verifier.verify(&pk, &att(&minter, &verdict, 6)));
        assert!(!verifier.verify(&[4u8; 32], &att(&minter, &verdict, 5)));
    }

    #[test]
    fn rejects_wrong_package_unrecognised_app_and_weak_device() {
        let (minter, verifier, cert) = setup();
        let pk = [3u8; 32];

        let other = verdict_for(&pk, 5, "com.example.other", cert);
        assert!(!verifier.verify(&pk, &att(&minter, &other, 5)));

        let mut unrecognised = verdict_for(&pk, 5, PKG, cert);
        unrecognised["appIntegrity"]["appRecognitionVerdict"] = "UNRECOGNIZED_VERSION".into();
        assert!(!verifier.verify(&pk, &att(&minter, &unrecognised, 5)));

        let mut weak = verdict_for(&pk, 5, PKG, cert);
        weak["deviceIntegrity"]["deviceRecognitionVerdict"] = serde_json::json!([DEVICE]);
        assert!(!verifier.verify(&pk, &att(&minter, &weak, 5)));

        let mut other_cert = verdict_for(&pk, 5, PKG, cert);
        other_cert["appIntegrity"]["certificateSha256Digest"] =
            serde_json::json!([URL_SAFE_NO_PAD.encode(cert_digest("debug"))]);
        assert!(!verifier.verify(&pk, &att(&minter, &other_cert, 5)));
    }

    #[test]
    fn rejects_stale_tokens_and_foreign_signers() {
        let (minter, verifier, cert) = setup();
        let pk = [3u8; 32];

        let mut stale = verdict_for(&pk, 5, PKG, cert);
        stale["requestDetails"]["timestampMillis"] =
            (now_unix_ms() - 3_600_000).to_string().into();
        assert!(!verifier.verify(&pk, &att(&minter, &stale, 5)));

        let forged = PlayIntegrityMinter::new(11);
        let verdict = verdict_for(&pk, 5, PKG, cert);
        assert!(!verifier.verify(&pk, &att(&forged, &verdict, 5)));
    }

    #[test]
    fn rejects_a_tampered_token() {
        let (minter, verifier, cert) = setup();
        let pk = [3u8; 32];
        let mut a = att(&minter, &verdict_for(&pk, 5, PKG, cert), 5);
        let last = a.evidence.len() - 1;
        a.evidence[last] ^= 0x01;
        assert!(!verifier.verify(&pk, &a));
    }
}
