use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::RemoteTransportError;

pub(crate) const EXPORTER_LABEL: &[u8] = b"anymone/remote-pairing/0";
pub(crate) const DESKTOP: &[u8] = b"anymone/remote-pairing/0/desktop";
pub(crate) const PHONE: &[u8] = b"anymone/remote-pairing/0/phone";

pub(crate) fn start(code: &str, desktop: bool) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let password = Password::new(code.as_bytes());
    let a = Identity::new(DESKTOP);
    let b = Identity::new(PHONE);
    if desktop {
        Spake2::start_a(&password, &a, &b)
    } else {
        Spake2::start_b(&password, &a, &b)
    }
}

fn confirmation(key: &[u8], role: &[u8], binding: &[u8; 32], controller: &[u8; 32]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(role);
    mac.update(binding);
    mac.update(controller);
    mac
}

pub(crate) fn proof(key: &[u8], role: &[u8], binding: &[u8; 32], controller: &[u8; 32]) -> [u8; 32] {
    confirmation(key, role, binding, controller).finalize().into_bytes().into()
}

pub(crate) fn verify(key: &[u8], role: &[u8], binding: &[u8; 32], controller: &[u8; 32], proof: &[u8; 32]) -> Result<(), RemoteTransportError> {
    confirmation(key, role, binding, controller).verify_slice(proof)
        .map_err(|_| RemoteTransportError::PairingFailed)
}

// Only the PAKE bootstrap uses this verifier. The code authenticates the TLS
// exporter before protocol actions are allowed; reconnects pin the certificate.
#[derive(Debug)]
pub(crate) struct BootstrapVerifier;

impl rustls::client::danger::ServerCertVerifier for BootstrapVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_binds_role_channel_and_controller() {
        let proof = proof(&[1; 32], DESKTOP, &[2; 32], &[3; 32]);
        assert!(verify(&[1; 32], DESKTOP, &[2; 32], &[3; 32], &proof).is_ok());
        assert!(verify(&[1; 32], PHONE, &[2; 32], &[3; 32], &proof).is_err());
        assert!(verify(&[1; 32], DESKTOP, &[4; 32], &[3; 32], &proof).is_err());
        assert!(verify(&[1; 32], DESKTOP, &[2; 32], &[4; 32], &proof).is_err());
    }
}
