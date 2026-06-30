//! Long-lived Ed25519 identity per node.
//!
//! The same public key is used for libp2p PeerId derivation, governance
//! signatures, and fault attribution. The keypair never touches subnet
//! traffic directly — per-subnet keys are bound to this one via signature.
//! Key/wire formats live in [`crate::keys`].

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use libp2p_identity::ed25519;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

pub use crate::keys::{ExchangeIdentity, IdentityError, Pubkey};

/// A node's long-lived keypair. Persisted as the raw 32-byte Ed25519 seed.
///
/// Carries an associated [`ExchangeIdentity`] (P-256, used by ADCNet's ECDH
/// layer). The exchange key is persisted at `identity_path.with_extension("exchange")`
/// so it survives restarts without changing the Ed25519 PeerId.
pub struct Identity {
    keypair: ed25519::Keypair,
    exchange: ExchangeIdentity,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = ed25519::SecretKey::try_from_bytes(&mut seed)
            .expect("32 bytes is a valid Ed25519 secret");
        seed.zeroize();
        Identity {
            keypair: secret.into(),
            exchange: ExchangeIdentity::generate(),
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        Pubkey(self.keypair.public().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(msg)
    }

    pub fn exchange(&self) -> &ExchangeIdentity {
        &self.exchange
    }

    pub fn exchange_pubkey(&self) -> adcnet::crypto::ExchangePublicKey {
        self.exchange.public()
    }

    fn exchange_path(path: &Path) -> PathBuf {
        path.with_extension("exchange")
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = self.keypair.secret().as_ref().to_vec();
        fs::write(path, &bytes)?;
        self.exchange.save(&Self::exchange_path(path))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let mut bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(IdentityError::BadSeedLength(bytes.len()));
        }
        let secret = ed25519::SecretKey::try_from_bytes(&mut bytes)
            .map_err(|e| IdentityError::Decode(e.to_string()))?;
        bytes.zeroize();
        let exchange = ExchangeIdentity::load_or_generate(&Self::exchange_path(path))?;
        Ok(Identity {
            keypair: secret.into(),
            exchange,
        })
    }

    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        if path.exists() {
            Self::load(path)
        } else {
            let id = Self::generate();
            id.save(path)?;
            Ok(id)
        }
    }

    /// Reconstruct a libp2p [`Keypair`](libp2p_identity::Keypair) backed by
    /// the same Ed25519 seed as this identity. The two derive identical
    /// public keys, so PeerId-from-libp2p matches `Pubkey` from anymone.
    pub fn to_libp2p_keypair(&self) -> libp2p_identity::Keypair {
        let mut secret_bytes: Vec<u8> = self.keypair.secret().as_ref().to_vec();
        let secret = libp2p_identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes)
            .expect("valid ed25519 secret");
        secret_bytes.zeroize();
        let pair: libp2p_identity::ed25519::Keypair = secret.into();
        libp2p_identity::Keypair::from(pair)
    }

    /// Build the 64-byte expanded form of the Ed25519 signing key that
    /// `adcnet::crypto::PrivateKey` expects (`[seed (32) || pub (32)]`).
    /// adcnet uses `ed25519_dalek::SigningKey`; we go via the same standard
    /// Ed25519 derivation, so the resulting key signs over identical bytes.
    pub fn to_adcnet_signing_key(&self) -> adcnet::crypto::PrivateKey {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.keypair.secret().as_ref());
        bytes.extend_from_slice(&self.keypair.public().to_bytes());
        adcnet::crypto::PrivateKey::from_bytes(&bytes)
    }

    /// The Ed25519 public key in adcnet's `PublicKey` wrapper (32 bytes).
    /// Same bytes as [`Self::pubkey`] but wrapped for ADCNet APIs.
    pub fn to_adcnet_public_key(&self) -> adcnet::crypto::PublicKey {
        adcnet::crypto::PublicKey::from_bytes(&self.keypair.public().to_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("pubkey", &self.pubkey())
            .finish()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        let mut bytes: Vec<u8> = self.keypair.secret().as_ref().to_vec();
        let secret = ed25519::SecretKey::try_from_bytes(&mut bytes)
            .expect("existing identity has a valid secret");
        bytes.zeroize();
        Identity {
            keypair: secret.into(),
            exchange: self.exchange.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn identity_roundtrip_persists_pubkey() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id");

        let id1 = Identity::generate();
        let pk1 = id1.pubkey();
        id1.save(&path).unwrap();

        let id2 = Identity::load(&path).unwrap();
        assert_eq!(id2.pubkey(), pk1);

        let msg = b"hello";
        let sig = id2.sign(msg);
        assert!(pk1.verify(msg, &sig));
    }

    #[test]
    fn identity_load_or_generate_creates_then_loads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id");

        let id1 = Identity::load_or_generate(&path).unwrap();
        let id2 = Identity::load_or_generate(&path).unwrap();
        assert_eq!(id1.pubkey(), id2.pubkey());
    }
}
