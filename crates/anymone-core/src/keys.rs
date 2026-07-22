//! Key and key-wire formats shared across the node: the ed25519 `Pubkey`, the
//! P-256 `ExchangeIdentity` used by the ADCNet/Panetiere ECDH layer, and the
//! `ExchangePublicKeyWire` wire form. One home for the representations so
//! conversions aren't re-derived per call site.

use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use libp2p_identity::ed25519;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Write `bytes` to `path` at mode 0600 — key material must never be group/world-readable.
pub(crate) fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// 32-byte Ed25519 public key. Serialised as `"ed25519:<hex>"` (human-readable)
/// or the raw array (bincode).
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match ed25519::PublicKey::try_from_bytes(&self.0) {
            Ok(pk) => pk.verify(msg, sig),
            Err(_) => false,
        }
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey(ed25519:{})", hex::encode(self.0))
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519:{}", hex::encode(self.0))
    }
}

impl Serialize for Pubkey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            parse_pubkey_str(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; 32]>::deserialize(d)?;
            Ok(Pubkey(bytes))
        }
    }
}

fn parse_pubkey_str(s: &str) -> Result<Pubkey, String> {
    let rest = s
        .strip_prefix("ed25519:")
        .ok_or_else(|| format!("pubkey missing `ed25519:` prefix: {s}"))?;
    let bytes = hex::decode(rest).map_err(|e| format!("pubkey hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("pubkey expected 32 bytes, got {}", bytes.len()))?;
    Ok(Pubkey(arr))
}

/// SEC1-encoded P-256 public key, the wire form of an exchange pubkey. Hex in
/// human-readable formats, `serde_bytes` in bincode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangePublicKeyWire(pub Vec<u8>);

impl ExchangePublicKeyWire {
    pub fn from_key(k: &adcnet::crypto::ExchangePublicKey) -> Self {
        ExchangePublicKeyWire(k.to_sec1_bytes())
    }
    pub fn to_key(&self) -> Result<adcnet::crypto::ExchangePublicKey, String> {
        adcnet::crypto::ExchangePublicKey::from_sec1_bytes(&self.0).map_err(|e| format!("{e:?}"))
    }
}

impl Serialize for ExchangePublicKeyWire {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(&self.0))
        } else {
            serde_bytes::Bytes::new(&self.0).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for ExchangePublicKeyWire {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            Ok(ExchangePublicKeyWire(v))
        } else {
            let v: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(d)?;
            Ok(ExchangePublicKeyWire(v.into_vec()))
        }
    }
}

impl PartialOrd for ExchangePublicKeyWire {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ExchangePublicKeyWire {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// The sorted relay roster paired with each relay's exchange pubkey looked up
/// from `exchange_keys`, indexed 0-based — the per-protocol `ServerId`. Relays
/// missing or with an undecodable key are skipped. Both protocols derive their
/// server keying from this (ADCNet then ECDHs each; Panetiere seals to each).
pub fn roster_exchange_pubkeys(
    relays: &[Pubkey],
    exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
) -> Vec<(usize, adcnet::crypto::ExchangePublicKey)> {
    let mut sorted = relays.to_vec();
    sorted.sort();
    let by_pk: std::collections::HashMap<Pubkey, &ExchangePublicKeyWire> =
        exchange_keys.iter().map(|(p, x)| (*p, x)).collect();
    sorted
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| Some((i, by_pk.get(pk)?.to_key().ok()?)))
        .collect()
}

/// Version-stable 32-byte seed over `domain` and a sorted roster (SHA-256).
pub fn derive_seed(domain: &[u8], pubkeys: &[Pubkey]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted = pubkeys.to_vec();
    sorted.sort();
    let mut h = Sha256::new();
    h.update(domain);
    for pk in &sorted {
        h.update(pk.0);
    }
    h.finalize().into()
}

/// Long-lived P-256 keypair for the ADCNet ECDH layer and the Panetiere ECIES
/// (`panetiere::pke`) sealing layer — one scalar, both protocol-native key
/// types. Held alongside the Ed25519 [`crate::identity::Identity`] and
/// persisted next to it so a node keeps one stable exchange pubkey across
/// restarts.
pub struct ExchangeIdentity {
    key: adcnet::crypto::ExchangePrivateKey,
    pke: panetiere::pke::PrivateKey,
}

impl ExchangeIdentity {
    fn from_adcnet_key(key: adcnet::crypto::ExchangePrivateKey) -> Self {
        let pke = panetiere::pke::PrivateKey::from_bytes(&key.to_bytes())
            .expect("same P-256 scalar");
        ExchangeIdentity { key, pke }
    }

    pub fn generate() -> Self {
        Self::from_adcnet_key(adcnet::crypto::ExchangePrivateKey::generate())
    }

    pub fn public(&self) -> adcnet::crypto::ExchangePublicKey {
        self.key.public()
    }

    pub fn ecdh(&self, other: &adcnet::crypto::ExchangePublicKey) -> adcnet::crypto::SharedKey {
        self.key.ecdh(other)
    }

    /// The key ECIES envelopes (`panetiere::pke`) are opened with.
    pub fn pke(&self) -> &panetiere::pke::PrivateKey {
        &self.pke
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_secret(path, &self.key.to_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = fs::read(path)?;
        let key = adcnet::crypto::ExchangePrivateKey::from_bytes(&bytes)
            .map_err(|e| IdentityError::Decode(e.to_string()))?;
        Ok(Self::from_adcnet_key(key))
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
}

impl Clone for ExchangeIdentity {
    fn clone(&self) -> Self {
        Self::from_adcnet_key(
            adcnet::crypto::ExchangePrivateKey::from_bytes(&self.key.to_bytes())
                .expect("ExchangePrivateKey round-trips its own bytes"),
        )
    }
}

impl fmt::Debug for ExchangeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeIdentity").finish()
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("seed must be exactly 32 bytes, got {0}")]
    BadSeedLength(usize),
    #[error("ed25519 decode: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn pubkey_string_roundtrip() {
        let pk = Identity::generate().pubkey();
        let s = pk.to_string();
        let pk2 = parse_pubkey_str(&s).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn derive_seed_stable_and_domain_separated() {
        // Fixed vector: version-stable across builds, independent of roster order.
        let a = Pubkey([1u8; 32]);
        let b = Pubkey([2u8; 32]);
        let s1 = derive_seed(b"dom", &[a, b]);
        assert_eq!(s1, derive_seed(b"dom", &[b, a]), "order must not matter");
        assert_eq!(
            hex::encode(s1),
            "2bb5cb3b560c75dd86e1f2adf912d289d555680a4bf29d36ee57936fec8611c5",
            "seed must be byte-stable"
        );
        assert_ne!(s1, derive_seed(b"other", &[a, b]), "domain must separate");
    }
}
