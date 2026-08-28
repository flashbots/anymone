//! Key and key-wire formats shared across the node: the ed25519 `Pubkey`, the
//! `ExchangeIdentity` holding ADCNet's P-256 ECDH key and Panetiere's ML-KEM
//! sealing key, and the `ExchangePublicKeyWire` wire form. One home for the
//! representations so conversions aren't re-derived per call site.

use std::fmt;
use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use commonware_codec::DecodeExt;
use commonware_cryptography::{ed25519, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Domain tag over every governance signature. The same key authenticates
/// backbone connections, so tagging keeps the two uses from validating in each
/// other's context.
pub(crate) const SIGN_NAMESPACE: &[u8] = b"anymone";

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
        let (Ok(pk), Ok(sig)) = (
            ed25519::PublicKey::decode(&self.0[..]),
            ed25519::Signature::decode(sig),
        ) else {
            return false;
        };
        pk.verify(SIGN_NAMESPACE, msg, &sig)
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

impl std::str::FromStr for Pubkey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_pubkey_str(s)
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

/// The public halves of an [`ExchangeIdentity`], as published in a registration
/// and carried in a config: the SEC1 P-256 point ADCNet ECDHs against, the
/// ML-KEM-768 encapsulation key Panetiere clients seal openings to, and the
/// P-256 verifying key its client-set receipts are checked under. Hex strings
/// in human-readable formats, `serde_bytes` in bincode.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExchangePublicKeyWire {
    pub ecdh: Vec<u8>,
    pub kem: Vec<u8>,
    /// Compressed SEC1 P-256 point, [`panetiere::sig`]'s format.
    pub set_sig: Vec<u8>,
}

impl ExchangePublicKeyWire {
    pub fn from_identity(id: &ExchangeIdentity) -> Self {
        ExchangePublicKeyWire {
            ecdh: id.public().to_sec1_bytes(),
            kem: id.pke().public().to_bytes(),
            set_sig: id.set_verifying_key().to_sec1_bytes().to_vec(),
        }
    }

    pub fn to_key(&self) -> Result<adcnet::crypto::ExchangePublicKey, String> {
        adcnet::crypto::ExchangePublicKey::from_sec1_bytes(&self.ecdh).map_err(|e| format!("{e:?}"))
    }

    pub fn to_seal_key(&self) -> Result<panetiere::pke::PublicKey, String> {
        panetiere::pke::PublicKey::from_bytes(&self.kem).map_err(|e| format!("{e:?}"))
    }

    /// The key a client-set certificate from this relay verifies under.
    pub fn to_set_key(&self) -> Result<panetiere::sig::VerifyingKey, String> {
        panetiere::sig::VerifyingKey::from_sec1_bytes(&self.set_sig).map_err(|e| format!("{e:?}"))
    }
}

/// Human-readable form: one hex string per key.
#[derive(Serialize, Deserialize)]
struct ExchangeKeysHex {
    ecdh: String,
    kem: String,
    #[serde(default)]
    set_sig: String,
}

impl Serialize for ExchangePublicKeyWire {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            ExchangeKeysHex {
                ecdh: hex::encode(&self.ecdh),
                kem: hex::encode(&self.kem),
                set_sig: hex::encode(&self.set_sig),
            }
            .serialize(s)
        } else {
            (
                serde_bytes::Bytes::new(&self.ecdh),
                serde_bytes::Bytes::new(&self.kem),
                serde_bytes::Bytes::new(&self.set_sig),
            )
                .serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for ExchangePublicKeyWire {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let h = ExchangeKeysHex::deserialize(d)?;
            Ok(ExchangePublicKeyWire {
                ecdh: hex::decode(&h.ecdh).map_err(serde::de::Error::custom)?,
                kem: hex::decode(&h.kem).map_err(serde::de::Error::custom)?,
                set_sig: hex::decode(&h.set_sig).map_err(serde::de::Error::custom)?,
            })
        } else {
            let (ecdh, kem, set_sig): (
                serde_bytes::ByteBuf,
                serde_bytes::ByteBuf,
                serde_bytes::ByteBuf,
            ) = Deserialize::deserialize(d)?;
            Ok(ExchangePublicKeyWire {
                ecdh: ecdh.into_vec(),
                kem: kem.into_vec(),
                set_sig: set_sig.into_vec(),
            })
        }
    }
}

/// The sorted relay roster paired with each relay's key looked up from
/// `exchange_keys` and decoded by `decode`, indexed 0-based — the per-protocol
/// `ServerId`. Relays missing or with an undecodable key are skipped.
fn roster_keys<K>(
    relays: &[Pubkey],
    exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
    decode: impl Fn(&ExchangePublicKeyWire) -> Result<K, String>,
) -> Vec<(usize, K)> {
    let mut sorted = relays.to_vec();
    sorted.sort();
    let by_pk: std::collections::HashMap<Pubkey, &ExchangePublicKeyWire> =
        exchange_keys.iter().map(|(p, x)| (*p, x)).collect();
    sorted
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| Some((i, decode(by_pk.get(pk)?).ok()?)))
        .collect()
}

/// Server roster for ADCNet, which ECDHs against each relay's P-256 point.
pub fn roster_exchange_pubkeys(
    relays: &[Pubkey],
    exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
) -> Vec<(usize, adcnet::crypto::ExchangePublicKey)> {
    roster_keys(relays, exchange_keys, ExchangePublicKeyWire::to_key)
}

/// Server roster for Panetiere, whose clients seal one opening to each relay's
/// ML-KEM encapsulation key.
pub fn roster_seal_pubkeys(
    relays: &[Pubkey],
    exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
) -> Vec<(usize, panetiere::pke::PublicKey)> {
    roster_keys(relays, exchange_keys, ExchangePublicKeyWire::to_seal_key)
}

/// Server roster for client-set consensus: the key each relay's certificates
/// and Dolev–Strong chain signatures verify under, indexed by `ServerId`.
pub fn roster_set_pubkeys(
    relays: &[Pubkey],
    exchange_keys: &[(Pubkey, ExchangePublicKeyWire)],
) -> Vec<(usize, panetiere::sig::VerifyingKey)> {
    roster_keys(relays, exchange_keys, ExchangePublicKeyWire::to_set_key)
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

/// Long-lived exchange key material: the P-256 keypair the ADCNet ECDH layer
/// uses, the ML-KEM-768 key the Panetiere sealing layer (`panetiere::pke`)
/// opens envelopes with, and the P-256 signing key this relay issues
/// client-set receipts under. No two schemes share key material, so both are
/// derived from the persisted P-256 scalar — one secret on disk, every public
/// key stable across restarts. Held alongside the Ed25519
/// [`crate::identity::Identity`] and persisted next to it.
pub struct ExchangeIdentity {
    key: adcnet::crypto::ExchangePrivateKey,
    pke: panetiere::pke::PrivateKey,
    set_sig: panetiere::sig::SigningKey,
}

impl ExchangeIdentity {
    fn from_adcnet_key(key: adcnet::crypto::ExchangePrivateKey) -> Self {
        use rand::SeedableRng;
        use sha2::{Digest, Sha256, Sha512};
        let mut h = Sha512::new();
        h.update(b"anymone/exchange/mlkem768/v1");
        h.update(key.to_bytes());
        let pke = panetiere::pke::PrivateKey::from_bytes(&h.finalize())
            .expect("Sha512 output is the 64-byte ML-KEM seed");
        let mut s = Sha256::new();
        s.update(b"anymone/client-set/sig/v1");
        s.update(key.to_bytes());
        let seed: [u8; 32] = s.finalize().into();
        let set_sig =
            panetiere::sig::SigningKey::generate(&mut rand_chacha::ChaCha20Rng::from_seed(seed));
        ExchangeIdentity { key, pke, set_sig }
    }

    pub fn generate() -> Self {
        Self::from_adcnet_key(adcnet::crypto::ExchangePrivateKey::generate())
    }

    pub fn from_scalar(bytes: &[u8]) -> Result<Self, IdentityError> {
        let key = adcnet::crypto::ExchangePrivateKey::from_bytes(bytes)
            .map_err(|e| IdentityError::Decode(e.to_string()))?;
        Ok(Self::from_adcnet_key(key))
    }

    pub fn scalar_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.key.to_bytes().to_vec())
    }

    pub fn public(&self) -> adcnet::crypto::ExchangePublicKey {
        self.key.public()
    }

    pub fn ecdh(&self, other: &adcnet::crypto::ExchangePublicKey) -> adcnet::crypto::SharedKey {
        self.key.ecdh(other)
    }

    /// The key sealed envelopes (`panetiere::pke`) are opened with.
    pub fn pke(&self) -> &panetiere::pke::PrivateKey {
        &self.pke
    }

    /// Signs this relay's client-set receipts and Dolev–Strong chain links.
    pub fn set_signing_key(&self) -> &panetiere::sig::SigningKey {
        &self.set_sig
    }

    pub fn set_verifying_key(&self) -> panetiere::sig::VerifyingKey {
        self.set_sig.verifying_key()
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_secret(path, &self.key.to_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::from_scalar(&fs::read(path)?)
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
    #[error("secrets must be exactly {expected} bytes, got {got}")]
    BadSecretsLength { expected: usize, got: usize },
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
