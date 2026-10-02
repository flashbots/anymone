//! Test against fixutres captured on an android device.
//! See tests/fixtures/android-key/README.md
use super::*;

#[derive(serde::Deserialize)]
struct Metadata {
    statement_hex: String,
    round: u64,
    challenge_hex: String,
    package_name: String,
    certificate_digests_hex: Vec<String>,
    captured_at_unix_seconds: i64,
    require_strongbox: bool,
}

fn fixture() -> (AndroidKeyVerifier, Vec<u8>, Attestation, ASN1Time) {
    let metadata: Metadata = serde_json::from_str(include_str!(
        "../../tests/fixtures/android-key/pixel7pro/metadata.json"
    ))
    .unwrap();
    let statement = hex::decode(metadata.statement_hex).unwrap();
    let att = Attestation {
        scheme: AttestationScheme::AndroidKeyAttestation,
        round: metadata.round,
        evidence: include_bytes!("../../tests/fixtures/android-key/pixel7pro/chain.der").to_vec(),
    };
    assert_eq!(
        hex::encode(challenge(att.scheme, &statement, att.round)),
        metadata.challenge_hex,
    );
    let verifier = AndroidKeyVerifier::new(AndroidKeyPolicy {
        package_name: metadata.package_name,
        certificate_digests: metadata
            .certificate_digests_hex
            .iter()
            .map(|d| hex::decode(d).unwrap().try_into().unwrap())
            .collect(),
        require_strongbox: metadata.require_strongbox,
        // Downloaded independently from Google's published roots, not trusted
        // merely because the device included it in its certificate chain.
        root_ca_der: include_bytes!("../../tests/fixtures/android-key/google-root.der").to_vec(),
    });
    (
        verifier,
        statement,
        att,
        ASN1Time::from_timestamp(metadata.captured_at_unix_seconds).unwrap(),
    )
}

fn description<'a>(leaf: &X509Certificate<'a>) -> KeyDescription<'a> {
    let extension = leaf
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == KEY_DESCRIPTION_OID)
        .unwrap();
    parse_key_description(extension.value).unwrap()
}

#[test]
fn real_pixel7pro_chain_and_app_identity_are_authentic() {
    let (verifier, statement, att, now) = fixture();
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    assert!(verifier.chain_reaches_root(&chain, now));
    let leaf = X509Certificate::from_der(chain[0]).unwrap().1;
    let description = description(&leaf);
    assert_eq!(
        description.attestation_challenge,
        challenge(att.scheme, &statement, att.round)
    );
    assert_eq!(
        description.attestation_security_level,
        LEVEL_TRUSTED_ENVIRONMENT
    );
    assert_eq!(
        description.keymaster_security_level,
        LEVEL_TRUSTED_ENVIRONMENT
    );
    assert!(verifier.app_is_ours(&description.software_enforced));
}

#[test]
fn real_pixel7pro_is_rejected_for_unlocked_unverified_boot() {
    let (verifier, statement, att, now) = fixture();
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    assert!(verifier.chain_reaches_root(&chain, now));
    let leaf = X509Certificate::from_der(chain[0]).unwrap().1;
    let description = description(&leaf);
    let root = tagged(&description.tee_enforced, TAG_ROOT_OF_TRUST).unwrap();
    let fields = items(&root).unwrap();
    assert_eq!(boolean(&fields[1]), Some(false));
    assert_eq!(uint(&fields[2]), Some(2)); // Unverified
    assert!(!verifier.boot_is_trustworthy(&description.tee_enforced));
    assert!(!verifier.verify_at(&statement, &att, now));
}

#[test]
fn real_app_identity_rejects_other_package_and_signer() {
    let (mut verifier, _, att, _) = fixture();
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    let leaf = X509Certificate::from_der(chain[0]).unwrap().1;
    let description = description(&leaf);
    // Exercise app checks directly: full verification already fails on boot state.
    assert!(verifier.app_is_ours(&description.software_enforced));
    let package = verifier.policy.package_name.clone();
    verifier.policy.package_name = "com.example.other".into();
    assert!(!verifier.app_is_ours(&description.software_enforced));
    verifier.policy.package_name = package;
    verifier.policy.certificate_digests = vec![[0xab; 32]];
    assert!(!verifier.app_is_ours(&description.software_enforced));
}

#[test]
fn real_chain_rejects_tampered_signature() {
    let (verifier, _, mut att, now) = fixture();
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    assert!(verifier.chain_reaches_root(&chain, now));
    let leaf_len = chain[0].len();
    att.evidence[leaf_len - 1] ^= 1;
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    assert!(!verifier.chain_reaches_root(&chain, now));
}

#[test]
fn real_chain_rejects_outside_certificate_validity() {
    let (verifier, _, att, now) = fixture();
    let chain = AndroidKeyVerifier::certs(&att.evidence).unwrap();
    assert!(verifier.chain_reaches_root(&chain, now));
    let certificates: Vec<_> = chain
        .iter()
        .map(|der| X509Certificate::from_der(der).unwrap().1)
        .collect();
    let earliest_expiry = certificates
        .iter()
        .map(|cert| cert.validity().not_after.timestamp())
        .min()
        .unwrap();
    let latest_start = certificates
        .iter()
        .map(|cert| cert.validity().not_before.timestamp())
        .max()
        .unwrap();
    for timestamp in [latest_start - 1, earliest_expiry + 1] {
        assert!(!verifier.chain_reaches_root(&chain, ASN1Time::from_timestamp(timestamp).unwrap(),));
    }
}
