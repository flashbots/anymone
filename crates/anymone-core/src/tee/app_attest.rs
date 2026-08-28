//! App Attest enrolment.
//!
//! Enrolment uses the attestation object alone. Assertions and their counter
//! would only matter if the key kept proving itself per message, which the
//! validity window replaces.

use ciborium::Value as Cbor;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::{challenge, Attestation, AttestationScheme, TeeVerifier, TEE};
use crate::config::AppAttestPolicy;

/// Apple's nonce extension, holding SHA256(authData ‖ clientDataHash).
const NONCE_OID: &str = "1.2.840.113635.100.8.2";

const AAGUID_PROD: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEV: &[u8; 16] = b"appattestdevelop";

const KEY_ID_LEN: usize = 32;

pub struct AppAttestVerifier {
    policy: AppAttestPolicy,
}

struct AttestationObject {
    x5c: Vec<Vec<u8>>,
    auth_data: Vec<u8>,
}

impl AppAttestVerifier {
    pub fn new(policy: AppAttestPolicy) -> Self {
        AppAttestVerifier { policy }
    }

    fn parse(evidence: &[u8]) -> Option<(&[u8], AttestationObject)> {
        let (key_id, cbor) = evidence.split_at_checked(KEY_ID_LEN)?;
        let Cbor::Map(entries) = ciborium::from_reader::<Cbor, _>(cbor).ok()? else {
            return None;
        };
        let field = |name: &str| {
            entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        if field("fmt")?.as_text()? != "apple-appattest" {
            return None;
        }
        let auth_data = field("authData")?.as_bytes()?.clone();
        let Cbor::Map(stmt) = field("attStmt")? else {
            return None;
        };
        let x5c = stmt
            .iter()
            .find(|(k, _)| k.as_text() == Some("x5c"))
            .map(|(_, v)| v)?
            .as_array()?
            .iter()
            .map(|c| c.as_bytes().cloned())
            .collect::<Option<Vec<_>>>()?;
        if x5c.is_empty() {
            return None;
        }
        Some((key_id, AttestationObject { x5c, auth_data }))
    }

    /// Leaf up to the policy's root, each link checked against the next.
    fn chain_reaches_root(&self, x5c: &[Vec<u8>]) -> bool {
        let mut ders: Vec<&[u8]> = x5c.iter().map(Vec::as_slice).collect();
        ders.push(&self.policy.root_ca_der);

        for pair in ders.windows(2) {
            let (Ok((_, child)), Ok((_, issuer))) = (
                X509Certificate::from_der(pair[0]),
                X509Certificate::from_der(pair[1]),
            ) else {
                return false;
            };
            if child.verify_signature(Some(issuer.public_key())).is_err() {
                tracing::debug!(target: TEE, "app attest: broken certificate chain");
                return false;
            }
            if !child.validity().is_valid() {
                tracing::debug!(target: TEE, "app attest: certificate outside its validity");
                return false;
            }
        }
        true
    }
}

impl TeeVerifier for AppAttestVerifier {
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
        if att.scheme != AttestationScheme::AppAttest {
            return false;
        }
        let Some((key_id, obj)) = Self::parse(&att.evidence) else {
            tracing::debug!(target: TEE, "app attest: undecodable attestation object");
            return false;
        };
        if !self.chain_reaches_root(&obj.x5c) {
            return false;
        }

        let Ok((_, cred_cert)) = X509Certificate::from_der(&obj.x5c[0]) else {
            return false;
        };

        let client_data_hash = challenge(att.scheme, statement, att.round);
        let mut h = Sha256::new();
        h.update(&obj.auth_data);
        h.update(client_data_hash);
        let nonce: [u8; 32] = h.finalize().into();

        let carries_nonce = cred_cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == NONCE_OID)
            .is_some_and(|e| e.value.windows(nonce.len()).any(|w| w == nonce));
        if !carries_nonce {
            tracing::debug!(target: TEE, "app attest: certificate does not bind this enrolment");
            return false;
        }

        let pubkey = cred_cert.public_key().subject_public_key.data.as_ref();
        if Sha256::digest(pubkey).as_slice() != key_id {
            tracing::debug!(target: TEE, "app attest: key id is not this certificate's key");
            return false;
        }

        // rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credentialIdLength ‖ credentialId
        if obj.auth_data.len() < 55 {
            return false;
        }
        let app_id = format!("{}.{}", self.policy.team_id, self.policy.bundle_id);
        if obj.auth_data[..32] != Sha256::digest(app_id.as_bytes())[..] {
            tracing::debug!(target: TEE, "app attest: attested app is not ours");
            return false;
        }
        if obj.auth_data[33..37] != [0, 0, 0, 0] {
            tracing::debug!(target: TEE, "app attest: counter is not a fresh key's");
            return false;
        }
        let aaguid = &obj.auth_data[37..53];
        let expected: &[u8; 16] = if self.policy.production {
            AAGUID_PROD
        } else {
            AAGUID_DEV
        };
        if aaguid != expected {
            tracing::debug!(target: TEE, "app attest: wrong attestation environment");
            return false;
        }
        if &obj.auth_data[55..55 + KEY_ID_LEN.min(obj.auth_data.len() - 55)] != key_id {
            tracing::debug!(target: TEE, "app attest: credential id does not match the key id");
            return false;
        }
        true
    }
}

#[cfg(any(test, feature = "test-util"))]
pub use minter::AppAttestMinter;

#[cfg(any(test, feature = "test-util"))]
mod minter {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::config::Round;

    /// Stands in for Apple's attestation CA. Production objects are only
    /// mintable by the Secure Enclave.
    pub struct AppAttestMinter {
        root: Certificate,
        root_key: KeyPair,
        policy: AppAttestPolicy,
    }

    impl AppAttestMinter {
        pub fn new(team_id: &str, bundle_id: &str) -> Self {
            let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
            let mut params = CertificateParams::new(vec!["anymone test app attest root".into()])
                .expect("root params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root = params.self_signed(&root_key).expect("self-signed root");
            let policy = AppAttestPolicy {
                team_id: team_id.to_string(),
                bundle_id: bundle_id.to_string(),
                production: false,
                root_ca_der: root.der().to_vec(),
            };
            AppAttestMinter {
                root,
                root_key,
                policy,
            }
        }

        pub fn policy(&self) -> AppAttestPolicy {
            self.policy.clone()
        }

        pub fn mint(&self, statement: &[u8], round: Round) -> Vec<u8> {
            self.mint_with(
                statement,
                round,
                &self.policy.team_id,
                &self.policy.bundle_id,
            )
        }

        /// `team_id`/`bundle_id` are separate so a test can attest the wrong app.
        pub fn mint_with(
            &self,
            statement: &[u8],
            round: Round,
            team_id: &str,
            bundle_id: &str,
        ) -> Vec<u8> {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("credential key");
            let key_id: [u8; 32] = Sha256::digest(public_point(&key)).into();

            let mut auth_data = Vec::new();
            auth_data
                .extend_from_slice(&Sha256::digest(format!("{team_id}.{bundle_id}").as_bytes()));
            auth_data.push(0x40);
            auth_data.extend_from_slice(&0u32.to_be_bytes());
            auth_data.extend_from_slice(AAGUID_DEV);
            auth_data.extend_from_slice(&(KEY_ID_LEN as u16).to_be_bytes());
            auth_data.extend_from_slice(&key_id);

            let mut h = Sha256::new();
            h.update(&auth_data);
            h.update(challenge(AttestationScheme::AppAttest, statement, round));
            let nonce: [u8; 32] = h.finalize().into();

            let mut params =
                CertificateParams::new(vec!["anymone test credential".into()]).expect("params");
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 2, 840, 113635, 100, 8, 2],
                nonce.to_vec(),
            )];
            let cred = params
                .signed_by(&key, &self.root, &self.root_key)
                .expect("credential cert");

            let text = |s: &str| Cbor::Text(s.to_string());
            let obj = Cbor::Map(vec![
                (text("fmt"), text("apple-appattest")),
                (
                    text("attStmt"),
                    Cbor::Map(vec![(
                        text("x5c"),
                        Cbor::Array(vec![Cbor::Bytes(cred.der().to_vec())]),
                    )]),
                ),
                (text("authData"), Cbor::Bytes(auth_data)),
            ]);

            let mut out = key_id.to_vec();
            ciborium::into_writer(&obj, &mut out).expect("cbor");
            out
        }
    }

    fn public_point(key: &KeyPair) -> Vec<u8> {
        let spki = key.public_key_der();
        let (_, parsed) =
            x509_parser::prelude::SubjectPublicKeyInfo::from_der(&spki).expect("spki");
        parsed.subject_public_key.data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "ABCDE12345";
    const BUNDLE: &str = "net.flashbots.anymone";

    fn att(evidence: Vec<u8>, round: u64) -> Attestation {
        Attestation {
            scheme: AttestationScheme::AppAttest,
            round,
            evidence,
        }
    }

    #[test]
    fn accepts_an_object_bound_to_this_key_round_and_app() {
        let minter = AppAttestMinter::new(TEAM, BUNDLE);
        let verifier = AppAttestVerifier::new(minter.policy());
        let pk = [5u8; 32];
        assert!(verifier.verify(&pk, &att(minter.mint(&pk, 3), 3)));
    }

    #[test]
    fn rejects_other_keys_rounds_and_apps() {
        let minter = AppAttestMinter::new(TEAM, BUNDLE);
        let verifier = AppAttestVerifier::new(minter.policy());
        let pk = [5u8; 32];

        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 3), 4)));
        assert!(!verifier.verify(&[6u8; 32], &att(minter.mint(&pk, 3), 3)));

        let other_app = minter.mint_with(&pk, 3, TEAM, "com.example.other");
        assert!(!verifier.verify(&pk, &att(other_app, 3)));
    }

    #[test]
    fn rejects_a_chain_that_does_not_reach_the_pinned_root() {
        let minter = AppAttestMinter::new(TEAM, BUNDLE);
        let foreign = AppAttestMinter::new(TEAM, BUNDLE);
        let verifier = AppAttestVerifier::new(minter.policy());
        let pk = [5u8; 32];
        assert!(!verifier.verify(&pk, &att(foreign.mint(&pk, 3), 3)));
    }

    #[test]
    fn rejects_a_production_policy_for_a_development_object() {
        let minter = AppAttestMinter::new(TEAM, BUNDLE);
        let mut policy = minter.policy();
        policy.production = true;
        let verifier = AppAttestVerifier::new(policy);
        let pk = [5u8; 32];
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 3), 3)));
    }

    #[test]
    fn rejects_a_key_id_that_is_not_the_certificate_key() {
        let minter = AppAttestMinter::new(TEAM, BUNDLE);
        let verifier = AppAttestVerifier::new(minter.policy());
        let pk = [5u8; 32];
        let mut evidence = minter.mint(&pk, 3);
        evidence[0] ^= 0xff;
        assert!(!verifier.verify(&pk, &att(evidence, 3)));
    }
}
