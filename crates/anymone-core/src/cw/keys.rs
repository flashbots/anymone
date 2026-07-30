//! `Pubkey` ↔ commonware ed25519 public key. Both are RFC8032 over the same
//! 32 bytes, so this is a re-decode, not a re-derivation.

use commonware_codec::DecodeExt;
use commonware_cryptography::ed25519;

use crate::identity::Pubkey;

/// `None` for bytes off the curve — peer keys arrive from config and the wire.
pub(crate) fn to_cw(pk: &Pubkey) -> Option<ed25519::PublicKey> {
    ed25519::PublicKey::decode(&pk.0[..]).ok()
}

pub(crate) fn from_cw(pk: &ed25519::PublicKey) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(pk.as_ref());
    Pubkey::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use commonware_cryptography::Signer;

    #[test]
    fn identity_maps_to_the_same_commonware_key() {
        let id = Identity::generate();
        let derived = from_cw(&id.to_commonware_signer().public_key());
        assert_eq!(
            derived,
            id.pubkey(),
            "commonware must derive the same public key from anymone's seed"
        );
        assert_eq!(to_cw(&id.pubkey()).unwrap().as_ref(), &id.pubkey().0[..]);
        assert!(
            to_cw(&Pubkey::from_bytes([0x02; 32])).is_none(),
            "a key that is not a curve point must be rejected, not carried"
        );
    }
}
