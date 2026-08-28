//! Android hardware key attestation.
//!
//! KeyMint signs a certificate for a key it generated, carrying the challenge we
//! chose plus what the device knows about itself: which secure hardware holds
//! the key, whether the bootloader is locked and running vendor-signed software,
//! and which app asked. The chain ends at a root Google publishes, so a relay
//! verifies it offline — no Play Console, no Google round trip, and nothing the
//! app has to be distributed through.
//!
//! What it does not say is where the app came from. Play Integrity attests "the
//! build Play shipped"; this attests "this package, signed by this key, on a
//! stock-booted device". A sideloaded build signed by a debug key attests just
//! as well, so `certificate_digests` is what separates a real client from a
//! rebuilt one.

use asn1_rs::{Any, Class, FromDer, Tag};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::{challenge, Attestation, AttestationScheme, TeeVerifier, TEE};
use crate::config::AndroidKeyPolicy;

/// `KeyDescription`, the extension KeyMint puts the attestation in.
const KEY_DESCRIPTION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// `AuthorizationList` context tags.
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;

/// `SecurityLevel`: where the key lives.
const LEVEL_TRUSTED_ENVIRONMENT: u64 = 1;
const LEVEL_STRONGBOX: u64 = 2;

/// `VerifiedBootState::Verified` — a locked bootloader running vendor-signed
/// software.
const BOOT_VERIFIED: u64 = 0;

/// Long enough for leaf, intermediates and root; a longer one is malformed.
const MAX_CHAIN: usize = 8;

pub struct AndroidKeyVerifier {
    policy: AndroidKeyPolicy,
}

struct KeyDescription<'a> {
    /// Where the attestation itself was produced.
    attestation_security_level: u64,
    /// Where the attested key lives — the one that decides whether the signing
    /// key can leave the device.
    keymaster_security_level: u64,
    attestation_challenge: &'a [u8],
    software_enforced: Any<'a>,
    tee_enforced: Any<'a>,
}

impl AndroidKeyVerifier {
    pub fn new(policy: AndroidKeyPolicy) -> Self {
        AndroidKeyVerifier { policy }
    }

    /// DER certificates back to back, leaf first — what
    /// `KeyStore.getCertificateChain` hands the app, concatenated.
    fn certs(evidence: &[u8]) -> Option<Vec<&[u8]>> {
        let mut out: Vec<&[u8]> = Vec::new();
        let mut rest = evidence;
        while !rest.is_empty() {
            if out.len() == MAX_CHAIN {
                return None;
            }
            let before = rest.len();
            let (after, _) = X509Certificate::from_der(rest).ok()?;
            out.push(&rest[..before - after.len()]);
            rest = after;
        }
        (!out.is_empty()).then_some(out)
    }

    fn chain_reaches_root(&self, chain: &[&[u8]]) -> bool {
        let mut ders = chain.to_vec();
        // The device chain already ends at Google's root; a chain that stops
        // earlier still has to reach the pinned one.
        if ders.last() != Some(&self.policy.root_ca_der.as_slice()) {
            ders.push(&self.policy.root_ca_der);
        }
        if ders.len() < 2 {
            return false;
        }

        for pair in ders.windows(2) {
            let (Ok((_, child)), Ok((_, issuer))) = (
                X509Certificate::from_der(pair[0]),
                X509Certificate::from_der(pair[1]),
            ) else {
                return false;
            };
            if child.verify_signature(Some(issuer.public_key())).is_err() {
                tracing::debug!(target: TEE, "android key: broken certificate chain");
                return false;
            }
            if !in_validity_period(&child) || !in_validity_period(&issuer) {
                return false;
            }
            if !may_issue(&issuer) {
                return false;
            }
        }
        true
    }

    fn app_is_ours(&self, software_enforced: &Any) -> bool {
        let Some(id) = tagged(software_enforced, TAG_ATTESTATION_APPLICATION_ID)
            .as_ref()
            .and_then(octets)
            .and_then(|der| Any::from_der(der).ok().map(|(_, a)| a))
        else {
            tracing::debug!(target: TEE, "android key: no attested application id");
            return false;
        };
        // AttestationApplicationId ::= SEQUENCE {
        //     package_infos      SET OF SEQUENCE { name OCTET STRING, version INTEGER },
        //     signature_digests  SET OF OCTET STRING }
        let Some(fields) = items(&id) else {
            return false;
        };
        let [packages, digests] = fields.as_slice() else {
            return false;
        };

        let named_ours = items(packages).is_some_and(|infos| {
            infos.iter().any(|info| {
                items(info)
                    .and_then(|f| f.first().and_then(octets))
                    .is_some_and(|name| name == self.policy.package_name.as_bytes())
            })
        });
        if !named_ours {
            tracing::debug!(target: TEE, "android key: attested app is not ours");
            return false;
        }

        let signed_by_ours = items(digests).is_some_and(|ds| {
            ds.iter().filter_map(octets).any(|d| {
                self.policy
                    .certificate_digests
                    .iter()
                    .any(|allowed| allowed == d)
            })
        });
        if !signed_by_ours {
            tracing::debug!(target: TEE, "android key: app signing key is not accepted");
            return false;
        }
        true
    }

    fn boot_is_trustworthy(&self, tee_enforced: &Any) -> bool {
        // RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING,
        //     deviceLocked BOOLEAN, verifiedBootState ENUMERATED, .. }
        let Some(root_of_trust) = tagged(tee_enforced, TAG_ROOT_OF_TRUST) else {
            tracing::debug!(target: TEE, "android key: no root of trust");
            return false;
        };
        let Some(fields) = items(&root_of_trust) else {
            return false;
        };
        if fields.len() < 3 {
            return false;
        }
        if boolean(&fields[1]) != Some(true) {
            tracing::debug!(target: TEE, "android key: bootloader is unlocked");
            return false;
        }
        if uint(&fields[2]) != Some(BOOT_VERIFIED) {
            tracing::debug!(target: TEE, "android key: boot state is not verified");
            return false;
        }
        true
    }
}

impl TeeVerifier for AndroidKeyVerifier {
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
        if att.scheme != AttestationScheme::AndroidKeyAttestation {
            return false;
        }
        let Some(chain) = Self::certs(&att.evidence) else {
            tracing::debug!(target: TEE, "android key: undecodable certificate chain");
            return false;
        };
        if !self.chain_reaches_root(&chain) {
            return false;
        }

        let Ok((_, leaf)) = X509Certificate::from_der(chain[0]) else {
            return false;
        };
        let Some(extension) = leaf
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == KEY_DESCRIPTION_OID)
        else {
            tracing::debug!(target: TEE, "android key: leaf carries no key description");
            return false;
        };
        let Some(description) = parse_key_description(extension.value) else {
            tracing::debug!(target: TEE, "android key: unparseable key description");
            return false;
        };

        if description.attestation_challenge != challenge(att.scheme, statement, att.round) {
            tracing::debug!(target: TEE, "android key: challenge does not bind this enrolment");
            return false;
        }

        let floor = if self.policy.require_strongbox {
            LEVEL_STRONGBOX
        } else {
            LEVEL_TRUSTED_ENVIRONMENT
        };
        if description.keymaster_security_level < floor
            || description.attestation_security_level < floor
        {
            tracing::debug!(
                target: TEE,
                key_level = description.keymaster_security_level,
                attestation_level = description.attestation_security_level,
                floor,
                "android key: key is not in secure-enough hardware"
            );
            return false;
        }

        self.boot_is_trustworthy(&description.tee_enforced)
            && self.app_is_ours(&description.software_enforced)
    }
}

fn in_validity_period(cert: &X509Certificate) -> bool {
    if cert.validity().is_valid() {
        return true;
    }
    tracing::debug!(
        target: TEE,
        subject = %cert.subject(),
        "android key: certificate is outside its validity period"
    );
    false
}

/// A signature only means something if the issuer was allowed to sign
/// certificates: a leaf reused as an issuer would otherwise mint its own chain.
fn may_issue(cert: &X509Certificate) -> bool {
    let ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca);
    // Absent key usage leaves the certificate unconstrained, which the CA bit
    // already covers.
    let can_sign_certs = cert
        .key_usage()
        .ok()
        .flatten()
        .is_none_or(|ku| ku.value.key_cert_sign());
    if !ca || !can_sign_certs {
        tracing::debug!(
            target: TEE,
            subject = %cert.subject(),
            ca,
            can_sign_certs,
            "android key: issuer is not a certificate authority"
        );
        return false;
    }
    true
}

/// KeyDescription ::= SEQUENCE { attestationVersion INTEGER,
///     attestationSecurityLevel ENUMERATED, keymasterVersion INTEGER,
///     keymasterSecurityLevel ENUMERATED, attestationChallenge OCTET STRING,
///     uniqueId OCTET STRING, softwareEnforced AuthorizationList,
///     teeEnforced AuthorizationList }
fn parse_key_description(der: &[u8]) -> Option<KeyDescription<'_>> {
    let (_, any) = Any::from_der(der).ok()?;
    let fields = items(&any)?;
    if fields.len() < 8 {
        return None;
    }
    Some(KeyDescription {
        attestation_security_level: uint(&fields[1])?,
        keymaster_security_level: uint(&fields[3])?,
        attestation_challenge: octets(&fields[4])?,
        software_enforced: fields[6].clone(),
        tee_enforced: fields[7].clone(),
    })
}

/// The TLVs inside a constructed value.
fn items<'a>(any: &Any<'a>) -> Option<Vec<Any<'a>>> {
    if !any.header.is_constructed() {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = any.data;
    while !rest.is_empty() {
        let (after, item) = Any::from_der(rest).ok()?;
        out.push(item);
        rest = after;
    }
    Some(out)
}

/// An `AuthorizationList` entry, unwrapped from its explicit context tag.
fn tagged<'a>(list: &Any<'a>, tag: u32) -> Option<Any<'a>> {
    items(list)?
        .into_iter()
        .find(|item| item.header.class() == Class::ContextSpecific && item.header.tag().0 == tag)
        .and_then(|item| Any::from_der(item.data).ok().map(|(_, a)| a))
}

/// INTEGER or ENUMERATED, both non-negative here.
fn uint(any: &Any) -> Option<u64> {
    match any.header.tag() {
        Tag::Integer | Tag::Enumerated => {
            let bytes = any.data;
            (!bytes.is_empty() && bytes.len() <= 8)
                .then(|| bytes.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
        }
        _ => None,
    }
}

fn octets<'a>(any: &Any<'a>) -> Option<&'a [u8]> {
    (any.header.tag() == Tag::OctetString).then_some(any.data)
}

fn boolean(any: &Any) -> Option<bool> {
    (any.header.tag() == Tag::Boolean).then(|| any.data != [0x00])
}

/// SHA-256 of an APK signing certificate, which is how the digests in the
/// attestation are computed — `apksigner verify --print-certs` prints the same
/// value.
pub fn signing_cert_digest(cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(cert_der).into()
}

#[cfg(any(test, feature = "test-util"))]
pub use minter::AndroidKeyMinter;

#[cfg(any(test, feature = "test-util"))]
mod minter {
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };

    use super::*;
    use crate::config::Round;

    /// Stands in for Google's attestation CA and KeyMint. A real chain is only
    /// mintable inside a device's secure hardware.
    pub struct AndroidKeyMinter {
        root: Certificate,
        root_key: KeyPair,
        policy: AndroidKeyPolicy,
        /// What the fake KeyMint claims about the device.
        pub attestation_security_level: u64,
        pub keymaster_security_level: u64,
        pub device_locked: bool,
        pub boot_state: u64,
    }

    impl AndroidKeyMinter {
        pub fn new(package_name: &str) -> Self {
            let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
            let mut params = CertificateParams::new(vec!["anymone test attestation root".into()])
                .expect("root params");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let root = params.self_signed(&root_key).expect("self-signed root");
            let policy = AndroidKeyPolicy {
                package_name: package_name.to_string(),
                certificate_digests: vec![signing_cert_digest(b"test signing certificate")],
                require_strongbox: false,
                root_ca_der: root.der().to_vec(),
            };
            AndroidKeyMinter {
                root,
                root_key,
                policy,
                attestation_security_level: LEVEL_TRUSTED_ENVIRONMENT,
                keymaster_security_level: LEVEL_TRUSTED_ENVIRONMENT,
                device_locked: true,
                boot_state: BOOT_VERIFIED,
            }
        }

        pub fn policy(&self) -> AndroidKeyPolicy {
            self.policy.clone()
        }

        pub fn mint(&self, statement: &[u8], round: Round) -> Vec<u8> {
            self.mint_for_app(
                statement,
                round,
                &self.policy.package_name,
                self.policy.certificate_digests[0],
            )
        }

        /// Package and digest are separate so a test can attest another app.
        pub fn mint_for_app(
            &self,
            statement: &[u8],
            round: Round,
            package_name: &str,
            digest: [u8; 32],
        ) -> Vec<u8> {
            let challenge = challenge(AttestationScheme::AndroidKeyAttestation, statement, round);

            let app_id = der::seq(&[
                der::set(&[der::seq(&[
                    der::octets(package_name.as_bytes()),
                    der::uint(1),
                ])]),
                der::set(&[der::octets(&digest)]),
            ]);
            let software_enforced = der::seq(&[der::context(
                TAG_ATTESTATION_APPLICATION_ID,
                &der::octets(&app_id),
            )]);
            let root_of_trust = der::seq(&[
                der::octets(&[0u8; 32]),
                der::boolean(self.device_locked),
                der::enumerated(self.boot_state),
                der::octets(&[0u8; 32]),
            ]);
            let tee_enforced = der::seq(&[der::context(TAG_ROOT_OF_TRUST, &root_of_trust)]);
            let key_description = der::seq(&[
                der::uint(4),
                der::enumerated(self.attestation_security_level),
                der::uint(4),
                der::enumerated(self.keymaster_security_level),
                der::octets(&challenge),
                der::octets(&[]),
                software_enforced,
                tee_enforced,
            ]);

            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("attested key");
            let mut params =
                CertificateParams::new(vec!["anymone test attested key".into()]).expect("params");
            params.custom_extensions = vec![CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                key_description,
            )];
            let leaf = params
                .signed_by(&key, &self.root, &self.root_key)
                .expect("leaf cert");

            let mut out = leaf.der().to_vec();
            out.extend_from_slice(self.root.der());
            out
        }
    }

    /// Just enough DER to build a KeyDescription; KeyMint does this in firmware.
    mod der {
        pub fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
            let mut out = tag.to_vec();
            match content.len() {
                n if n < 0x80 => out.push(n as u8),
                n => {
                    let bytes = n.to_be_bytes();
                    let bytes = &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(7)..];
                    out.push(0x80 | bytes.len() as u8);
                    out.extend_from_slice(bytes);
                }
            }
            out.extend_from_slice(content);
            out
        }

        pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
            tlv(&[0x30], &parts.concat())
        }

        pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
            tlv(&[0x31], &parts.concat())
        }

        pub fn octets(bytes: &[u8]) -> Vec<u8> {
            tlv(&[0x04], bytes)
        }

        pub fn uint(v: u64) -> Vec<u8> {
            tlv(&[0x02], &trim(v))
        }

        pub fn enumerated(v: u64) -> Vec<u8> {
            tlv(&[0x0a], &trim(v))
        }

        pub fn boolean(v: bool) -> Vec<u8> {
            tlv(&[0x01], &[if v { 0xff } else { 0x00 }])
        }

        /// Explicit context tag; over 30 the number spills into base-128 bytes.
        pub fn context(tag: u32, inner: &[u8]) -> Vec<u8> {
            let mut header = Vec::new();
            if tag < 31 {
                header.push(0xa0 | tag as u8);
            } else {
                header.push(0xbf);
                let mut digits = Vec::new();
                let mut n = tag;
                while n > 0 {
                    digits.push((n & 0x7f) as u8);
                    n >>= 7;
                }
                digits.reverse();
                let last = digits.len() - 1;
                for (i, d) in digits.iter().enumerate() {
                    header.push(if i == last { *d } else { d | 0x80 });
                }
            }
            tlv(&header, inner)
        }

        fn trim(v: u64) -> Vec<u8> {
            let bytes = v.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            let mut out = bytes[start..].to_vec();
            // A leading high bit would read as negative.
            if out[0] & 0x80 != 0 {
                out.insert(0, 0);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGE: &str = "net.flashbots.anymone";

    fn att(evidence: Vec<u8>, round: u64) -> Attestation {
        Attestation {
            scheme: AttestationScheme::AndroidKeyAttestation,
            round,
            evidence,
        }
    }

    #[test]
    fn accepts_a_chain_bound_to_this_key_round_and_app() {
        let minter = AndroidKeyMinter::new(PACKAGE);
        let verifier = AndroidKeyVerifier::new(minter.policy());
        let pk = [5u8; 32];
        assert!(verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));
    }

    #[test]
    fn rejects_other_keys_and_rounds() {
        let minter = AndroidKeyMinter::new(PACKAGE);
        let verifier = AndroidKeyVerifier::new(minter.policy());
        let pk = [5u8; 32];
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 8)));
        assert!(!verifier.verify(&[6u8; 32], &att(minter.mint(&pk, 7), 7)));
    }

    #[test]
    fn rejects_another_app_or_signing_key() {
        let minter = AndroidKeyMinter::new(PACKAGE);
        let verifier = AndroidKeyVerifier::new(minter.policy());
        let pk = [5u8; 32];
        let digest = minter.policy().certificate_digests[0];

        let other_package = minter.mint_for_app(&pk, 7, "com.example.other", digest);
        assert!(!verifier.verify(&pk, &att(other_package, 7)));

        let other_signer = minter.mint_for_app(&pk, 7, PACKAGE, [0xab; 32]);
        assert!(!verifier.verify(&pk, &att(other_signer, 7)));
    }

    #[test]
    fn rejects_an_unlocked_or_unverified_device() {
        let pk = [5u8; 32];

        let mut minter = AndroidKeyMinter::new(PACKAGE);
        minter.device_locked = false;
        let verifier = AndroidKeyVerifier::new(minter.policy());
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));

        let mut minter = AndroidKeyMinter::new(PACKAGE);
        minter.boot_state = 2; // Unverified
        let verifier = AndroidKeyVerifier::new(minter.policy());
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));
    }

    #[test]
    fn rejects_a_key_outside_secure_hardware() {
        let pk = [5u8; 32];
        let mut minter = AndroidKeyMinter::new(PACKAGE);
        minter.attestation_security_level = 0; // Software
        minter.keymaster_security_level = 0;
        let verifier = AndroidKeyVerifier::new(minter.policy());
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));

        // A TEE-signed description over a software-held key: the key is what
        // the floor is about.
        let mut minter = AndroidKeyMinter::new(PACKAGE);
        minter.keymaster_security_level = 0;
        let verifier = AndroidKeyVerifier::new(minter.policy());
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));
    }

    /// Most non-Pixel handsets only have a TEE, so this is the knob that decides
    /// how much of the fleet can enrol.
    #[test]
    fn strongbox_policy_refuses_a_tee_only_key() {
        let pk = [5u8; 32];
        let minter = AndroidKeyMinter::new(PACKAGE);
        let mut policy = minter.policy();
        policy.require_strongbox = true;
        let verifier = AndroidKeyVerifier::new(policy);
        assert!(!verifier.verify(&pk, &att(minter.mint(&pk, 7), 7)));

        let mut strongbox = AndroidKeyMinter::new(PACKAGE);
        strongbox.attestation_security_level = LEVEL_STRONGBOX;
        strongbox.keymaster_security_level = LEVEL_STRONGBOX;
        let mut policy = strongbox.policy();
        policy.require_strongbox = true;
        let verifier = AndroidKeyVerifier::new(policy);
        assert!(verifier.verify(&pk, &att(strongbox.mint(&pk, 7), 7)));
    }

    #[test]
    fn rejects_a_chain_that_does_not_reach_the_pinned_root() {
        let minter = AndroidKeyMinter::new(PACKAGE);
        let foreign = AndroidKeyMinter::new(PACKAGE);
        let verifier = AndroidKeyVerifier::new(minter.policy());
        let pk = [5u8; 32];
        assert!(!verifier.verify(&pk, &att(foreign.mint(&pk, 7), 7)));
    }

    #[test]
    fn rejects_a_leaf_without_the_attestation_extension() {
        let minter = AndroidKeyMinter::new(PACKAGE);
        let verifier = AndroidKeyVerifier::new(minter.policy());
        // The root alone: a well-formed chain carrying no key description.
        let evidence = minter.policy().root_ca_der.clone();
        assert!(!verifier.verify(&[5u8; 32], &att(evidence, 7)));
    }
}
