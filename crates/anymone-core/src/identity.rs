//! Long-lived Ed25519 identity per node, plus `anymone.toml` parsing.
//!
//! The same public key is used for libp2p PeerId derivation (M3), governance
//! signatures, and fault attribution. The keypair never touches subnet
//! traffic directly — per-subnet keys are bound to this one via signature.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use libp2p_identity::ed25519;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zeroize::Zeroize;

/// 32-byte Ed25519 public key. Serialised as `"ed25519:<hex>"`.
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
            // default array encoding so serialize/deserialize match under bincode
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

/// Long-lived P-256 keypair used for the ADCNet ECDH layer. Held alongside
/// the Ed25519 [`Identity`] so PeerId derivation stays unchanged. Persisted
/// next to the Ed25519 file (`identity_path.with_extension("exchange")`)
/// so a node has one stable exchange pubkey across restarts.
pub struct ExchangeIdentity {
    key: adcnet::crypto::ExchangePrivateKey,
}

impl ExchangeIdentity {
    pub fn generate() -> Self {
        ExchangeIdentity {
            key: adcnet::crypto::ExchangePrivateKey::generate(),
        }
    }

    pub fn public(&self) -> adcnet::crypto::ExchangePublicKey {
        self.key.public()
    }

    pub fn ecdh(&self, other: &adcnet::crypto::ExchangePublicKey) -> adcnet::crypto::SharedKey {
        self.key.ecdh(other)
    }

    /// Open an ECIES envelope sealed to this key (`adcnet::crypto::encrypt`).
    pub fn unseal(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        let msg = adcnet::crypto::parse_encrypted_message(sealed).ok()?;
        adcnet::crypto::decrypt(&self.key, &msg).ok()
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.key.to_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = fs::read(path)?;
        let key = adcnet::crypto::ExchangePrivateKey::from_bytes(&bytes)
            .map_err(|e| IdentityError::Decode(e.to_string()))?;
        Ok(ExchangeIdentity { key })
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
        // P-256 secrets clone via byte round-trip — same Drop semantics as
        // the Ed25519 Identity::clone above.
        ExchangeIdentity {
            key: adcnet::crypto::ExchangePrivateKey::from_bytes(&self.key.to_bytes())
                .expect("ExchangePrivateKey round-trips its own bytes"),
        }
    }
}

impl fmt::Debug for ExchangeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeIdentity").finish()
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

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("seed must be exactly 32 bytes, got {0}")]
    BadSeedLength(usize),
    #[error("ed25519 decode: {0}")]
    Decode(String),
}

/// Static bootstrap configuration, loaded from `anymone.toml` at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    pub identity_path: PathBuf,
    pub network: NetworkConfig,
    pub governance: GovernanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen: String,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    pub committee: Vec<CommitteeMember>,
    pub threshold: u32,
}

/// A committee member as configured: its identity pubkey plus the exchange
/// pubkey the internal committee Panetiere needs to seal openings to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub pubkey: Pubkey,
    pub exchange_pubkey: crate::config::ExchangePublicKeyWire,
}

impl BootstrapConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, BootstrapError> {
        let cfg: BootstrapConfig = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self, BootstrapError> {
        let s = fs::read_to_string(path)?;
        Self::from_toml_str(&s)
    }

    pub fn write_to(&self, path: &Path) -> Result<(), BootstrapError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(BootstrapError::Encode)?;
        fs::write(path, s)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), BootstrapError> {
        if self.governance.committee.is_empty() {
            return Err(BootstrapError::EmptyCommittee);
        }
        let n = self.governance.committee.len() as u32;
        if self.governance.threshold == 0 || self.governance.threshold > n {
            return Err(BootstrapError::BadThreshold {
                threshold: self.governance.threshold,
                committee: n,
            });
        }
        // Reject duplicate committee entries.
        let mut sorted: Vec<Pubkey> = self.governance.committee.iter().map(|m| m.pubkey).collect();
        sorted.sort();
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(BootstrapError::DuplicateCommitteeMember(w[0]));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("toml decode: {0}")]
    Decode(#[from] toml::de::Error),
    #[error("toml encode: {0}")]
    Encode(toml::ser::Error),
    #[error("committee is empty")]
    EmptyCommittee,
    #[error("threshold {threshold} not in 1..={committee}")]
    BadThreshold { threshold: u32, committee: u32 },
    #[error("duplicate committee member: {0}")]
    DuplicateCommitteeMember(Pubkey),
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

    #[test]
    fn pubkey_string_roundtrip() {
        let pk = Identity::generate().pubkey();
        let s = pk.to_string();
        let pk2 = parse_pubkey_str(&s).unwrap();
        assert_eq!(pk, pk2);
    }

    /// A `[[governance.committee]]` table for a fresh identity.
    fn member_table(id: &Identity) -> String {
        let xpub = crate::config::ExchangePublicKeyWire::from_key(&id.exchange_pubkey());
        format!(
            "[[governance.committee]]\npubkey = \"{}\"\nexchange_pubkey = \"{}\"\n",
            id.pubkey(),
            hex::encode(&xpub.0),
        )
    }

    #[test]
    fn bootstrap_parses_valid_toml() {
        let members: String = (0..3)
            .map(|_| member_table(&Identity::generate()))
            .collect();
        let toml = format!(
            r#"
identity_path = "/tmp/identity"

[network]
listen = "/ip4/0.0.0.0/tcp/7100"
bootstrap_peers = ["/dns4/seed/tcp/7100/p2p/12D3KooW..."]

[governance]
threshold = 2
{members}"#
        );
        let cfg = BootstrapConfig::from_toml_str(&toml).unwrap();
        assert_eq!(cfg.governance.committee.len(), 3);
        assert_eq!(cfg.governance.threshold, 2);
        assert_eq!(cfg.network.bootstrap_peers.len(), 1);
        assert!(cfg.governance.committee[0].exchange_pubkey.to_key().is_ok());
    }

    #[test]
    fn bootstrap_rejects_threshold_too_high() {
        let member = member_table(&Identity::generate());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 2
{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::BadThreshold { .. }));
    }

    #[test]
    fn bootstrap_rejects_zero_threshold() {
        let member = member_table(&Identity::generate());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 0
{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::BadThreshold { .. }));
    }

    #[test]
    fn bootstrap_rejects_duplicate_committee() {
        let id = Identity::generate();
        let member = member_table(&id);
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 1
{member}{member}"#
        );
        let err = BootstrapConfig::from_toml_str(&toml).unwrap_err();
        assert!(matches!(err, BootstrapError::DuplicateCommitteeMember(_)));
    }

    #[test]
    fn bootstrap_rejects_malformed_pubkey() {
        let xpub =
            crate::config::ExchangePublicKeyWire::from_key(&Identity::generate().exchange_pubkey());
        let toml = format!(
            r#"
identity_path = "/tmp/identity"
[network]
listen = "/ip4/0.0.0.0/tcp/7100"
[governance]
threshold = 1
[[governance.committee]]
pubkey = "not-a-key"
exchange_pubkey = "{}"
"#,
            hex::encode(&xpub.0),
        );
        assert!(BootstrapConfig::from_toml_str(&toml).is_err());
    }
}
