//! Intel TDX enrolment, over the `attest` crates.
//!
//! Only portable measurements are accepted: `attest` rebuilds the platform's
//! expected registers from the image plus the quote's platform metadata, where
//! pinning registers directly would leave the firmware registers unchecked.

use attest_types::AttestationEvidence;
use parity_scale_codec::{Decode, Encode};

use super::{Attestation, AttestationScheme, TeeError, TeeProver, TeeVerifier, TEE};
use crate::config::{Round, TdxImage};

/// `pk ‖ round`, zero-padded to the 64 bytes TDX reserves.
pub fn report_data(statement: &[u8], round: Round) -> [u8; 64] {
    let mut out = [0u8; 64];
    let n = statement.len().min(32);
    out[..n].copy_from_slice(&statement[..n]);
    out[32..40].copy_from_slice(&round.to_le_bytes());
    out
}

pub struct TdxProver;

impl TeeProver for TdxProver {
    fn attest(&self, statement: &[u8], round: Round) -> Result<Attestation, TeeError> {
        let evidence = attest_prove::prove(report_data(statement, round))
            .map_err(|e| TeeError::PlatformUnavailable(e.to_string()))?;
        Ok(Attestation {
            scheme: AttestationScheme::Tdx,
            round,
            evidence: evidence.encode(),
        })
    }
}

pub struct TdxVerifier {
    approved: Vec<TdxImage>,
    pccs: attest_pccs::Pccs,
}

impl TdxVerifier {
    /// `pccs` must be prewarmed: verification is synchronous and reads
    /// collateral from its cache.
    pub fn new(approved: Vec<TdxImage>, pccs: attest_pccs::Pccs) -> Self {
        TdxVerifier { approved, pccs }
    }

    /// Bare metal: upstream would need the firmware binary to rebuild MRTD and
    /// RTMR0, so those come from the policy and only the image half is rebuilt.
    fn bare_metal_report_data(
        &self,
        image: &TdxImage,
        evidence: &AttestationEvidence,
    ) -> Option<[u8; 64]> {
        let firmware = image.firmware.as_ref()?;
        let quote = match attest_verify::dcap::validate_quote(&evidence.quote, &self.pccs) {
            Ok(q) => q,
            Err(e) => {
                tracing::debug!(target: TEE, error = %e, "TDX quote did not validate");
                return None;
            }
        };
        let expected = match attest_measure::dcap::expected_dcap_registers(
            &image.image.dcap,
            &evidence.platform,
            None,
        ) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(target: TEE, error = %e, "could not rebuild image registers");
                return None;
            }
        };
        (quote.mrtd == *firmware.mrtd
            && quote.rtmr0 == *firmware.rtmr0
            && quote.rtmr1 == expected.rtmr1
            && quote.rtmr2 == expected.rtmr2)
            .then_some(quote.report_data)
    }
}

impl TeeVerifier for TdxVerifier {
    fn verify(&self, statement: &[u8], att: &Attestation) -> bool {
        let evidence = match AttestationEvidence::decode(&mut att.evidence.as_slice()) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(target: TEE, error = %e, "undecodable TDX evidence");
                return false;
            }
        };
        let expected = report_data(statement, att.round);
        let bound = |data: [u8; 64]| {
            if data == expected {
                return true;
            }
            tracing::debug!(target: TEE, "TDX quote verified but binds other report data");
            false
        };
        for image in &self.approved {
            match evidence.platform.attestation_type {
                attest_types::AttestationType::GcpTdx => {
                    let measurement = attest_types::MeasurementOutput::Portable(Box::new(
                        image.image.clone(),
                    ));
                    match attest_verify::verify(&measurement, &evidence, &self.pccs, None) {
                        Ok(data) => return bound(data),
                        Err(e) => {
                            tracing::trace!(target: TEE, error = %e, "TDX image did not match")
                        }
                    }
                }
                _ => {
                    if let Some(data) = self.bare_metal_report_data(image, &evidence) {
                        return bound(data);
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_binds_key_and_round() {
        let pk = [9u8; 32];
        let a = report_data(&pk, 7);
        assert_eq!(&a[..32], &pk);
        assert_eq!(&a[32..40], &7u64.to_le_bytes());
        assert_ne!(a, report_data(&pk, 8));
        assert_ne!(a, report_data(&[10u8; 32], 7));
    }
}
