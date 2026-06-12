//! Integrity-proof hooks for sessions.
//!
//! Each protocol's session module wires integrity proofs internally — the
//! runtime doesn't see them. The traits here are the lowest common
//! denominator: attest some bytes, verify some bytes. The real TDX-based
//! prover lands in M6; for now `NoopProver` is enough to compile sessions
//! that take `Option<&dyn TeeProver>`.

pub trait TeeProver: Send + Sync {
    /// Produce an opaque attestation over `statement`.
    fn attest(&self, statement: &[u8]) -> Vec<u8>;
}

pub trait TeeVerifier: Send + Sync {
    /// Verify an attestation over `statement`.
    fn verify(&self, statement: &[u8], proof: &[u8]) -> bool;
}

/// Trivial prover: empty attestations, always verifies. Use only for tests
/// and for subnets configured with integrity mode `None`.
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
