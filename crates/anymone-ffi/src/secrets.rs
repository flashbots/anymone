//! Where the client's long-lived keys live.
//!
//! The identity is the client's whole standing in the network: it authenticates
//! the stream handshake, signs every round, and is what an attestation enrols.
//! On a phone that makes a file the wrong place for it — app-private storage is
//! readable off a rooted or jailbroken device and can ride out in a backup. So
//! the Rust side never writes key material to disk; it asks the shell, which
//! puts it in the Keychain or wraps it with a Keystore key.

use anymone_core::identity::Identity;

use crate::AnymoneError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SecretStoreError {
    /// Nothing readable in the store yet — not an error at first launch.
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("failed: {0}")]
    Failed(String),
}

/// Implemented by the shells over the iOS Keychain and the Android Keystore.
/// Both calls are synchronous and expected to be fast; they happen once at
/// startup.
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    /// The blob a previous `store` was given, or `None` on a first launch.
    fn load(&self) -> Result<Option<Vec<u8>>, SecretStoreError>;
    /// Persist so that only this app on this device can read it back, and so it
    /// stays out of backups.
    fn store(&self, secrets: Vec<u8>) -> Result<(), SecretStoreError>;
}

/// Restore the identity the store holds, minting one on first launch.
pub(crate) fn identity(store: &dyn SecretStore) -> Result<Identity, AnymoneError> {
    match store.load() {
        Ok(Some(bytes)) => Ok(Identity::from_secrets(&bytes)?),
        Ok(None) => {
            let identity = Identity::generate();
            // The copy handed across the FFI cannot be zeroized from here, so
            // the shell should hold it no longer than the write takes.
            store.store(identity.secrets().to_vec())?;
            Ok(identity)
        }
        Err(e) => Err(e.into()),
    }
}

impl From<SecretStoreError> for AnymoneError {
    fn from(e: SecretStoreError) -> Self {
        AnymoneError::SecretStore(e.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Stands in for the platform stores.
    pub(crate) struct InMemoryStore(pub Mutex<Option<Vec<u8>>>);

    impl InMemoryStore {
        pub(crate) fn empty() -> Self {
            InMemoryStore(Mutex::new(None))
        }
    }

    impl SecretStore for InMemoryStore {
        fn load(&self) -> Result<Option<Vec<u8>>, SecretStoreError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn store(&self, secrets: Vec<u8>) -> Result<(), SecretStoreError> {
            *self.0.lock().unwrap() = Some(secrets);
            Ok(())
        }
    }

    struct Broken;
    impl SecretStore for Broken {
        fn load(&self) -> Result<Option<Vec<u8>>, SecretStoreError> {
            Err(SecretStoreError::Failed("keystore is locked".into()))
        }
        fn store(&self, _secrets: Vec<u8>) -> Result<(), SecretStoreError> {
            unreachable!("load fails first")
        }
    }

    #[test]
    fn first_launch_mints_and_later_launches_restore() {
        let store = InMemoryStore::empty();
        let first = identity(&store).expect("mints on first launch");
        let second = identity(&store).expect("restores afterwards");

        assert_eq!(first.pubkey(), second.pubkey());
        assert_eq!(first.exchange_keys(), second.exchange_keys());
    }

    /// A locked or wiped keystore must not silently mint a new identity: that
    /// would look like a different client to every relay and drop the enrolment.
    #[test]
    fn a_failing_store_is_an_error_not_a_fresh_identity() {
        assert!(matches!(
            identity(&Broken),
            Err(AnymoneError::SecretStore(_))
        ));
    }
}
