use chacha20poly1305::{aead::Aead, aead::KeyInit, aead::Payload, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::{decode, encode, Error, MAX_MESSAGE_BYTES, VERSION, digest};
use std::collections::HashMap;

type RequestKem = hpke::kem::X25519HkdfSha256;
type RequestAead = hpke::aead::ChaCha20Poly1305;
type RequestKdf = hpke::kdf::HkdfSha256;
const REQUEST_DOMAIN: &[u8] = b"anymone.ethereum.request.v0";
const RESPONSE_DOMAIN: &[u8] = b"anymone.ethereum.response.v0";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ResponseSecret(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseKeyContext {
    pub version: u16,
    pub network: [u8; 32],
    pub service: [u8; 32],
    pub chain: u64,
    pub operation: [u8; 32],
    pub request_digest: [u8; 32],
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliverySpec {
    pub feed: [u8; 32],
    pub first_epoch: u64,
    pub last_epoch: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCapability {
    pub secret: ResponseSecret,
    pub context: ResponseKeyContext,
    pub delivery: DeliverySpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryBinding {
    pub feed: [u8; 32],
    pub epoch: u64,
    pub locator: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedResponse {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedResponse {
    content: Vec<u8>,
    signature: Vec<u8>,
}

impl ResponseCapability {
    pub fn generate(context: ResponseKeyContext, delivery: DeliverySpec) -> Self {
        let mut secret = [0; 32];
        rand::rng().fill_bytes(&mut secret);
        Self { secret: ResponseSecret(secret), context, delivery }
    }

    fn derive(&self, label: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut key = Zeroizing::new([0; 32]);
        let mut info = label.to_vec();
        info.extend(encode(&self.context)?);
        Hkdf::<Sha256>::new(Some(RESPONSE_DOMAIN), &self.secret.0)
            .expand(&info, key.as_mut()).map_err(|_| Error::Authentication)?;
        Ok(key)
    }

    pub fn locator(&self, epoch: u64) -> Result<[u8; 32], Error> {
        let DeliverySpec { feed, first_epoch, last_epoch } = &self.delivery;
        if epoch < *first_epoch || epoch > *last_epoch {
            return Err(Error::Context);
        }
        let key = self.derive(b"lookup")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref())
            .map_err(|_| Error::Authentication)?;
        mac.update(feed);
        mac.update(&epoch.to_be_bytes());
        Ok(mac.finalize().into_bytes().into())
    }

    fn aad(&self, binding: &DeliveryBinding, now: u64) -> Result<Vec<u8>, Error> {
        if self.context.version != VERSION || now >= self.context.expires_at {
            return Err(Error::Context);
        }
        if self.delivery.feed != binding.feed
            || self.locator(binding.epoch)? != binding.locator
        {
            return Err(Error::Context);
        }
        encode(&(RESPONSE_DOMAIN, &self.context, binding))
    }

    pub fn seal(&self, binding: &DeliveryBinding, content: &[u8],
                signer: &SigningKey, now: u64) -> Result<SealedResponse, Error> {
        if signer.verifying_key().to_bytes() != self.context.service {
            return Err(Error::Authentication);
        }
        if content.len() > MAX_MESSAGE_BYTES { return Err(Error::Limit); }
        let aad = self.aad(binding, now)?;
        let signed_bytes = encode(&(&aad, content))?;
        let signature = signer.sign(&signed_bytes).to_bytes().to_vec();
        let plaintext = Zeroizing::new(encode(&SignedResponse { content: content.to_vec(), signature })?);
        let key = self.derive(b"encryption")?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Authentication)?;
        let mut nonce = [0; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce),
            Payload { msg: plaintext.as_ref(), aad: &aad }).map_err(|_| Error::Authentication)?;
        Ok(SealedResponse { nonce, ciphertext })
    }

    pub fn open(&self, binding: &DeliveryBinding, sealed: &SealedResponse,
                now: u64) -> Result<Vec<u8>, Error> {
        if sealed.ciphertext.len() > MAX_MESSAGE_BYTES + 96 {
            return Err(Error::Limit);
        }
        let aad = self.aad(binding, now)?;
        let key = self.derive(b"encryption")?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Authentication)?;
        let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&sealed.nonce),
            Payload { msg: &sealed.ciphertext, aad: &aad }).map_err(|_| Error::Authentication)?);
        let signed: SignedResponse = decode(&plaintext)?;
        let public = VerifyingKey::from_bytes(&self.context.service).map_err(|_| Error::Authentication)?;
        let signature = Signature::from_slice(&signed.signature).map_err(|_| Error::Authentication)?;
        public.verify_strict(&encode(&(&aad, &signed.content))?, &signature)
            .map_err(|_| Error::Authentication)?;
        if signed.content.len() > MAX_MESSAGE_BYTES { return Err(Error::Limit); }
        Ok(signed.content)
    }
}

pub fn request_keypair() -> ([u8; 32], [u8; 32]) {
    let (private, public) = RequestKem::gen_keypair(&mut rand::rng());
    (private.to_bytes().into(), public.to_bytes().into())
}

pub fn request_public_key(private: &[u8; 32]) -> Result<[u8; 32], Error> {
    let private = <RequestKem as Kem>::PrivateKey::from_bytes(private).map_err(|_| Error::Authentication)?;
    Ok(RequestKem::sk_to_pk(&private).to_bytes().into())
}

pub fn seal_request(public: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let public = <RequestKem as Kem>::PublicKey::from_bytes(public).map_err(|_| Error::Authentication)?;
    let (enc, mut sender) = hpke::setup_sender::<RequestAead, RequestKdf, RequestKem, _>(
        &OpModeS::Base, &public, REQUEST_DOMAIN, &mut rand::rng()).map_err(|_| Error::Authentication)?;
    let mut wire = enc.to_bytes().to_vec();
    wire.extend(sender.seal(plaintext, REQUEST_DOMAIN).map_err(|_| Error::Authentication)?);
    Ok(wire)
}

pub fn open_request(private: &[u8; 32], wire: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if wire.len() < 48 || wire.len() > MAX_MESSAGE_BYTES + 48 {
        return Err(Error::Limit);
    }
    let private = <RequestKem as Kem>::PrivateKey::from_bytes(private).map_err(|_| Error::Authentication)?;
    let enc = <RequestKem as Kem>::EncappedKey::from_bytes(&wire[..32]).map_err(|_| Error::Authentication)?;
    let mut receiver = hpke::setup_receiver::<RequestAead, RequestKdf, RequestKem>(
        &OpModeR::Base, &private, &enc, REQUEST_DOMAIN).map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(receiver.open(&wire[32..], REQUEST_DOMAIN).map_err(|_| Error::Authentication)?))
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    use crate::digest;

    fn capability() -> (SigningKey, ResponseCapability) {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let cap = ResponseCapability::generate(ResponseKeyContext {
            version: VERSION, network: [1; 32], service: signer.verifying_key().to_bytes(),
            chain: 1, operation: [2; 32], request_digest: digest(b"request"), expires_at: 100,
        }, DeliverySpec { feed: [3; 32], first_epoch: 1, last_epoch: 9 });
        (signer, cap)
    }

    fn binding(cap: &ResponseCapability) -> DeliveryBinding {
        DeliveryBinding { feed: [3; 32], epoch: 1, locator: cap.locator(1).unwrap() }
    }

    #[test]
    fn whole_responses_are_portable_and_context_bound() {
        let (signer, cap) = capability();
        let content = vec![42; 65536];
        let sealed = cap.seal(&binding(&cap), &content, &signer, 1).unwrap();
        let mut delegate: ResponseCapability = serde_json::from_slice(&serde_json::to_vec(&cap).unwrap()).unwrap();
        assert_eq!(delegate.open(&binding(&cap), &sealed, 1).unwrap(), content);
        assert!(delegate.open(&binding(&cap), &sealed, 100).is_err());
        let mut truncated = sealed.clone();
        truncated.ciphertext.pop();
        assert!(delegate.open(&binding(&cap), &truncated, 1).is_err());
        delegate.context.chain = 2;
        assert!(delegate.open(&binding(&cap), &sealed, 1).is_err());
    }

    #[test]
    fn independent_providers_can_return_conflicting_answers() {
        let (first_key, first_cap) = capability();
        let second_key = SigningKey::from_bytes(&[8;32]);
        let mut context = first_cap.context.clone();
        context.service = second_key.verifying_key().to_bytes();
        let second_cap = ResponseCapability::generate(context, first_cap.delivery.clone());
        let a = first_cap.seal(&binding(&first_cap), b"first result", &first_key, 1).unwrap();
        let b = second_cap.seal(&binding(&second_cap), b"different result", &second_key, 1).unwrap();
        assert_eq!(first_cap.open(&binding(&first_cap), &a, 1).unwrap(), b"first result");
        assert_eq!(second_cap.open(&binding(&second_cap), &b, 1).unwrap(), b"different result");
        assert!(first_cap.open(&binding(&first_cap), &b, 1).is_err());
        assert!(second_cap.open(&binding(&second_cap), &a, 1).is_err());
    }

    #[test]
    fn symmetric_key_holder_cannot_forge_service_provenance() {
        let (_, cap) = capability();
        let aad = cap.aad(&binding(&cap), 1).unwrap();
        let key = cap.derive(b"encryption").unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let forged = encode(&SignedResponse { content: b"forged".to_vec(), signature: vec![0; 64] }).unwrap();
        let nonce = [3; 24];
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &forged, aad: &aad }).unwrap();
        assert!(cap.open(&binding(&cap), &SealedResponse { nonce, ciphertext }, 1).is_err());
    }

    #[test]
    fn hpke_uploads_are_randomized_and_authenticated() {
        let (private, public) = request_keypair();
        let a = seal_request(&public, b"private request").unwrap();
        let mut b = seal_request(&public, b"private request").unwrap();
        assert_ne!(a, b);
        assert_eq!(&**open_request(&private, &a).unwrap(), b"private request");
        b[33] ^= 1;
        assert!(open_request(&private, &b).is_err());
    }
}

const HEADER: usize = 76;
const HPKE_OVERHEAD: usize = 48;
const MAX_FRAGMENTS: usize = 4096;

pub fn seal_fragments(public: &[u8; 32], operation: [u8; 32], expires_at: u64,
                      message: &[u8], carrier_bytes: usize) -> Result<Vec<Vec<u8>>, Error> {
    let capacity = carrier_bytes.checked_sub(HEADER + HPKE_OVERHEAD)
        .filter(|n| *n > 0).ok_or(Error::Limit)?;
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    let count = message.len().div_ceil(capacity);
    if count > MAX_FRAGMENTS {
        return Err(Error::Limit);
    }
    let hash = digest(message);
    message.chunks(capacity).enumerate().map(|(index, content)| {
        let mut plaintext = Vec::with_capacity(HEADER + content.len());
        plaintext.extend(operation);
        plaintext.extend(hash);
        plaintext.extend(expires_at.to_be_bytes());
        plaintext.extend((index as u16).to_be_bytes());
        plaintext.extend((count as u16).to_be_bytes());
        plaintext.extend(content);
        seal_request(public, &plaintext)
    }).collect()
}

struct Pending {
    digest: [u8; 32],
    expires_at: u64,
    bytes: usize,
    parts: Vec<Option<Vec<u8>>>,
}

pub struct Reassembler {
    pending: HashMap<[u8; 32], Pending>,
    max_pending: usize,
    max_total_bytes: usize,
    max_lifetime: u64,
}

impl Reassembler {
    pub fn new(max_pending: usize, max_total_bytes: usize, max_lifetime: u64) -> Self {
        Self { pending: HashMap::new(), max_pending, max_total_bytes, max_lifetime }
    }

    pub fn receive(&mut self, private: &[u8; 32], wire: &[u8], now: u64)
        -> Result<Option<([u8; 32], Vec<u8>)>, Error>
    {
        self.pending.retain(|_, p| p.expires_at > now);
        let plaintext = open_request(private, wire)?;
        if plaintext.len() <= HEADER {
            return Err(Error::Context);
        }
        let operation: [u8; 32] = plaintext[..32].try_into().map_err(|_| Error::Context)?;
        let hash = plaintext[32..64].try_into().map_err(|_| Error::Context)?;
        let expires_at = u64::from_be_bytes(plaintext[64..72].try_into().map_err(|_| Error::Context)?);
        let index = u16::from_be_bytes(plaintext[72..74].try_into().map_err(|_| Error::Context)?) as usize;
        let count = u16::from_be_bytes(plaintext[74..76].try_into().map_err(|_| Error::Context)?) as usize;
        if expires_at <= now || expires_at - now > self.max_lifetime
            || count == 0 || count > MAX_FRAGMENTS || index >= count
        {
            return Err(Error::Context);
        }
        let content = &plaintext[HEADER..];
        if let Some(pending) = self.pending.get(&operation) {
            if pending.digest != hash || pending.expires_at != expires_at || pending.parts.len() != count {
                return Err(Error::Context);
            }
            if let Some(existing) = &pending.parts[index] {
                return if existing == content { Ok(None) } else { Err(Error::Context) };
            }
            if pending.bytes.saturating_add(content.len()) > MAX_MESSAGE_BYTES {
                return Err(Error::Limit);
            }
        } else if self.pending.len() >= self.max_pending {
            return Err(Error::Limit);
        }
        let total: usize = self.pending.values().map(|p| p.bytes).sum();
        if total.saturating_add(content.len()) > self.max_total_bytes {
            return Err(Error::Limit);
        }
        let pending = self.pending.entry(operation).or_insert_with(|| Pending {
            digest: hash, expires_at, bytes: 0, parts: vec![None; count],
        });
        pending.bytes += content.len();
        pending.parts[index] = Some(content.to_vec());
        if pending.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let pending = self.pending.remove(&operation).ok_or(Error::Context)?;
        let mut message = Vec::with_capacity(pending.bytes);
        for part in pending.parts {
            message.extend(part.ok_or(Error::Context)?);
        }
        if digest(&message) != hash {
            return Err(Error::Authentication);
        }
        Ok(Some((operation, message)))
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;
    use crate::crypto::request_keypair;

    #[test]
    fn reversed_duplicate_fragments_and_capacity() {
        let (private, public) = request_keypair();
        let message = vec![3; 1024];
        let fragments = seal_fragments(&public, [5; 32], 10, &message, 256).unwrap();
        assert!(fragments.iter().all(|f| f.len() <= 256));
        let mut receiver = Reassembler::new(2, 4096, 10);
        assert!(receiver.receive(&private, &fragments[0], 1).unwrap().is_none());
        assert!(receiver.receive(&private, &fragments[0], 1).unwrap().is_none());
        let mut result = None;
        for fragment in fragments.iter().skip(1).rev() {
            result = receiver.receive(&private, fragment, 1).unwrap();
        }
        assert_eq!(result, Some(([5; 32], message)));
        assert!(receiver.receive(&private, &fragments[0], 10).is_err());
    }

    #[test]
    fn partial_uploads_are_bounded_and_expire() {
        let (private, public) = request_keypair();
        let a = seal_fragments(&public, [1; 32], 3, &[1; 300], 256).unwrap();
        let b = seal_fragments(&public, [2; 32], 5, &[2; 300], 256).unwrap();
        let mut receiver = Reassembler::new(1, 512, 10);
        receiver.receive(&private, &a[0], 1).unwrap();
        assert!(receiver.receive(&private, &b[0], 1).is_err());
        assert!(receiver.receive(&private, &b[0], 3).is_ok());
    }
}
