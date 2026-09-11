//! Unused integrity-proof interfaces. The crate loads `tee/mod.rs` instead.

pub trait TeeProver: Send + Sync {
    /// Produce an opaque attestation over `statement`.
    fn attest(&self, statement: &[u8]) -> Vec<u8>;
}

pub trait TeeVerifier: Send + Sync {
    /// Verify an attestation over `statement`.
    fn verify(&self, statement: &[u8], proof: &[u8]) -> bool;
}

/// Empty attestations with unconditional verification; provides no integrity.
pub struct NoopProver;

impl TeeProver for NoopProver {
    fn attest(&self, _statement: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

impl TeeVerifier for NoopProver {
    fn verify(&self, _statement: &[u8], _proof: &[u8]) -> bool {
        true
    }
}
