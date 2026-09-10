use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{Identity, Pubkey, Round, SubnetId};

const MANIFEST_DOMAIN: &[u8] = b"anymone/contribution-manifest/v1";
const ENROLMENT_DOMAIN: &[u8] = b"anymone/session-enrolment/v1";
const MAX_PAYLOADS: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolId {
    Noop,
    Panetiere,
    ScheduledPanetiere,
    Adcnet,
    ScheduledAdcnet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteSessionPolicy {
    pub enabled: bool,
    pub allow_developer: bool,
    pub developer_keys: Vec<Pubkey>,
    pub allowed_protocols: Vec<ProtocolId>,
    pub max_lease_rounds: Round,
}

impl Default for RemoteSessionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_developer: false,
            developer_keys: Vec::new(),
            allowed_protocols: Vec::new(),
            max_lease_rounds: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolmentStatement {
    pub lease_id: [u8; 32],
    pub config_hash: [u8; 32],
    pub subnet: SubnetId,
    pub protocol: ProtocolId,
    pub participant: Pubkey,
    pub forwarder: Pubkey,
    pub platform_key: Pubkey,
    pub process_nonce: [u8; 32],
    pub valid_from: Round,
    pub valid_until: Round,
}

impl EnrolmentStatement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(213);
        out.extend_from_slice(ENROLMENT_DOMAIN);
        out.extend_from_slice(&self.lease_id);
        out.extend_from_slice(&self.config_hash);
        out.extend_from_slice(&self.subnet.to_be_bytes());
        out.push(self.protocol as u8);
        out.extend_from_slice(&self.participant.0);
        out.extend_from_slice(&self.forwarder.0);
        out.extend_from_slice(&self.platform_key.0);
        out.extend_from_slice(&self.process_nonce);
        out.extend_from_slice(&self.valid_from.to_be_bytes());
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionEnrolment {
    Developer {
        statement: EnrolmentStatement,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    AppAttest {
        statement: EnrolmentStatement,
        #[serde(with = "serde_bytes")]
        evidence: Vec<u8>,
    },
    Android {
        statement: EnrolmentStatement,
        certificate_chain: Vec<Vec<u8>>,
        #[serde(with = "serde_bytes")]
        play_token: Vec<u8>,
        #[serde(with = "serde_bytes")]
        possession_signature: Vec<u8>,
    },
}

impl SessionEnrolment {
    pub fn statement(&self) -> &EnrolmentStatement {
        match self {
            Self::Developer { statement, .. }
            | Self::AppAttest { statement, .. }
            | Self::Android { statement, .. } => statement,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContributionRecipient {
    Broadcast,
    Relay(Pubkey),
    Peer(Pubkey),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadDigest {
    pub recipient: ContributionRecipient,
    pub kind: u16,
    pub length: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContributionManifest {
    pub lease_id: [u8; 32],
    pub config_hash: [u8; 32],
    pub protocol: ProtocolId,
    pub subnet: SubnetId,
    pub round: Round,
    pub phase: u16,
    pub sequence: u64,
    pub origin: Option<[u8; 32]>,
    pub payloads: Vec<PayloadDigest>,
}

impl ContributionManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContributionError> {
        if self.payloads.len() > MAX_PAYLOADS {
            return Err(ContributionError::TooManyPayloads(self.payloads.len()));
        }
        let mut out = Vec::with_capacity(160 + self.payloads.len() * 72);
        out.extend_from_slice(MANIFEST_DOMAIN);
        out.extend_from_slice(&self.lease_id);
        out.extend_from_slice(&self.config_hash);
        out.push(self.protocol as u8);
        out.extend_from_slice(&self.subnet.to_be_bytes());
        out.extend_from_slice(&self.round.to_be_bytes());
        out.extend_from_slice(&self.phase.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        match self.origin {
            Some(origin) => {
                out.push(1);
                out.extend_from_slice(&origin);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.payloads.len() as u16).to_be_bytes());
        for payload in &self.payloads {
            match payload.recipient {
                ContributionRecipient::Broadcast => out.push(0),
                ContributionRecipient::Relay(pk) => {
                    out.push(1);
                    out.extend_from_slice(&pk.0);
                }
                ContributionRecipient::Peer(pk) => {
                    out.push(2);
                    out.extend_from_slice(&pk.0);
                }
            }
            out.extend_from_slice(&payload.kind.to_be_bytes());
            out.extend_from_slice(&payload.length.to_be_bytes());
            out.extend_from_slice(&payload.hash);
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], ContributionError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContributionPayload {
    pub recipient: ContributionRecipient,
    pub kind: u16,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

impl ContributionPayload {
    pub fn digest(&self) -> Result<PayloadDigest, ContributionError> {
        let length = u32::try_from(self.bytes.len()).map_err(|_| ContributionError::PayloadTooLarge)?;
        Ok(PayloadDigest {
            recipient: self.recipient.clone(),
            kind: self.kind,
            length,
            hash: Sha256::digest(&self.bytes).into(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContributionEvidence {
    DevEd25519 {
        key: Pubkey,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    AppAttestAssertion {
        #[serde(with = "serde_bytes")]
        assertion: Vec<u8>,
    },
    AndroidP256Signature {
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestedContribution {
    pub manifest: ContributionManifest,
    pub evidence: ContributionEvidence,
    pub payloads: Vec<ContributionPayload>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplayDecision {
    Fresh,
    Duplicate,
}

#[derive(Debug, Clone)]
pub struct VerifiedContribution {
    contribution: AttestedContribution,
    replay: ReplayDecision,
}

impl VerifiedContribution {
    pub fn contribution(&self) -> &AttestedContribution {
        &self.contribution
    }

    pub fn replay(&self) -> ReplayDecision {
        self.replay
    }

    pub fn into_contribution(self) -> AttestedContribution {
        self.contribution
    }
}

#[async_trait::async_trait]
pub trait ContributionSigner: Send + Sync {
    fn public_key(&self) -> Pubkey;
    async fn sign_manifest(&self, manifest: &ContributionManifest) -> Result<ContributionEvidence, ContributionError>;
}

pub struct DeveloperSigner {
    identity: Identity,
}

impl DeveloperSigner {
    pub fn new(identity: Identity) -> Self {
        Self { identity }
    }

    pub fn enrol(&self, statement: EnrolmentStatement) -> Result<SessionEnrolment, ContributionError> {
        if statement.platform_key != self.public_key() {
            return Err(ContributionError::WrongPlatformKey);
        }
        let signature = self.identity.sign(&statement.canonical_bytes());
        Ok(SessionEnrolment::Developer { statement, signature })
    }
}

#[async_trait::async_trait]
impl ContributionSigner for DeveloperSigner {
    fn public_key(&self) -> Pubkey {
        self.identity.pubkey()
    }

    async fn sign_manifest(&self, manifest: &ContributionManifest) -> Result<ContributionEvidence, ContributionError> {
        Ok(ContributionEvidence::DevEd25519 {
            key: self.public_key(),
            signature: self.identity.sign(&manifest.canonical_bytes()?),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReplaySnapshot {
    accepted: BTreeMap<([u8; 32], u64), [u8; 32]>,
    highest: BTreeMap<[u8; 32], u64>,
}

#[derive(Clone, Default)]
pub struct ReplayStore(Arc<Mutex<ReplaySnapshot>>);

impl ReplayStore {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContributionError> {
        let snapshot = bincode::deserialize(bytes).map_err(|e| ContributionError::ReplayStore(e.to_string()))?;
        Ok(Self(Arc::new(Mutex::new(snapshot))))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ContributionError> {
        bincode::serialize(&*self.0.lock().expect("replay store lock"))
            .map_err(|e| ContributionError::ReplayStore(e.to_string()))
    }

    fn accept(&self, lease: [u8; 32], sequence: u64, digest: [u8; 32]) -> Result<ReplayDecision, ContributionError> {
        let mut held = self.0.lock().expect("replay store lock");
        if let Some(existing) = held.accepted.get(&(lease, sequence)) {
            return if *existing == digest {
                Ok(ReplayDecision::Duplicate)
            } else {
                Err(ContributionError::ReplayConflict)
            };
        }
        if held.highest.get(&lease).is_some_and(|highest| sequence <= *highest) {
            return Err(ContributionError::OutOfOrderSequence);
        }
        held.accepted.insert((lease, sequence), digest);
        held.highest.insert(lease, sequence);
        Ok(ReplayDecision::Fresh)
    }
}

pub struct ContributionVerifier {
    policy: RemoteSessionPolicy,
    replay: ReplayStore,
}

impl ContributionVerifier {
    pub fn new(policy: RemoteSessionPolicy, replay: ReplayStore) -> Self {
        Self { policy, replay }
    }

    pub fn verify_enrolment(&self, enrolment: &SessionEnrolment, now: Round) -> Result<EnrolmentStatement, ContributionError> {
        if !self.policy.enabled {
            return Err(ContributionError::RemoteSessionsDisabled);
        }
        let statement = enrolment.statement();
        if statement.valid_until <= statement.valid_from
            || statement.valid_until.saturating_sub(statement.valid_from) > self.policy.max_lease_rounds
            || now < statement.valid_from
            || now >= statement.valid_until
        {
            return Err(ContributionError::LeaseInvalid);
        }
        if !self.policy.allowed_protocols.contains(&statement.protocol) {
            return Err(ContributionError::ProtocolNotAllowed);
        }
        match enrolment {
            SessionEnrolment::Developer { statement, signature } => {
                if !self.policy.allow_developer || !self.policy.developer_keys.contains(&statement.platform_key) {
                    return Err(ContributionError::DeveloperEvidenceRejected);
                }
                if !statement.platform_key.verify(&statement.canonical_bytes(), signature) {
                    return Err(ContributionError::BadSignature);
                }
            }
            _ => return Err(ContributionError::UnsupportedEvidence),
        }
        Ok(statement.clone())
    }

    pub fn verify(
        &self,
        lease: &EnrolmentStatement,
        contribution: AttestedContribution,
        now: Round,
    ) -> Result<VerifiedContribution, ContributionError> {
        let manifest = &contribution.manifest;
        if now < lease.valid_from || now >= lease.valid_until || manifest.round < lease.valid_from || manifest.round >= lease.valid_until {
            return Err(ContributionError::LeaseExpired);
        }
        if manifest.lease_id != lease.lease_id
            || manifest.config_hash != lease.config_hash
            || manifest.protocol != lease.protocol
            || manifest.subnet != lease.subnet
        {
            return Err(ContributionError::ContextMismatch);
        }
        if contribution.payloads.len() != manifest.payloads.len() || contribution.payloads.len() > MAX_PAYLOADS {
            return Err(ContributionError::PayloadMismatch);
        }
        let total = contribution.payloads.iter().try_fold(0usize, |sum, p| sum.checked_add(p.bytes.len()).ok_or(ContributionError::PayloadTooLarge))?;
        if total > MAX_PAYLOAD_BYTES {
            return Err(ContributionError::PayloadTooLarge);
        }
        let actual = contribution.payloads.iter().map(ContributionPayload::digest).collect::<Result<Vec<_>, _>>()?;
        if actual != manifest.payloads {
            return Err(ContributionError::PayloadMismatch);
        }
        let manifest_bytes = manifest.canonical_bytes()?;
        match &contribution.evidence {
            ContributionEvidence::DevEd25519 { key, signature } => {
                if !self.policy.allow_developer || *key != lease.platform_key || !self.policy.developer_keys.contains(key) {
                    return Err(ContributionError::DeveloperEvidenceRejected);
                }
                if !key.verify(&manifest_bytes, signature) {
                    return Err(ContributionError::BadSignature);
                }
            }
            _ => return Err(ContributionError::UnsupportedEvidence),
        }
        let replay = self.replay.accept(lease.lease_id, manifest.sequence, manifest.digest()?)?;
        Ok(VerifiedContribution { contribution, replay })
    }

    pub fn replay_snapshot(&self) -> Result<Vec<u8>, ContributionError> {
        self.replay.to_bytes()
    }
}

pub fn freeze_manifest(
    lease: &EnrolmentStatement,
    round: Round,
    phase: u16,
    sequence: u64,
    origin: Option<[u8; 32]>,
    payloads: Vec<ContributionPayload>,
) -> Result<(ContributionManifest, Vec<ContributionPayload>), ContributionError> {
    let mut seen = HashSet::new();
    let digests = payloads
        .iter()
        .map(ContributionPayload::digest)
        .collect::<Result<Vec<_>, _>>()?;
    for digest in &digests {
        if !seen.insert((digest.recipient.clone(), digest.kind)) {
            return Err(ContributionError::DuplicateDestination);
        }
    }
    let manifest = ContributionManifest {
        lease_id: lease.lease_id,
        config_hash: lease.config_hash,
        protocol: lease.protocol,
        subnet: lease.subnet,
        round,
        phase,
        sequence,
        origin,
        payloads: digests,
    };
    manifest.canonical_bytes()?;
    Ok((manifest, payloads))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContributionError {
    #[error("remote sessions are disabled")]
    RemoteSessionsDisabled,
    #[error("developer evidence is not accepted")]
    DeveloperEvidenceRejected,
    #[error("this evidence scheme is unavailable in this build")]
    UnsupportedEvidence,
    #[error("protocol is not allowed")]
    ProtocolNotAllowed,
    #[error("lease is invalid")]
    LeaseInvalid,
    #[error("lease is expired")]
    LeaseExpired,
    #[error("contribution context does not match its lease")]
    ContextMismatch,
    #[error("platform key does not match the signer")]
    WrongPlatformKey,
    #[error("signature did not verify")]
    BadSignature,
    #[error("payloads do not match the signed manifest")]
    PayloadMismatch,
    #[error("payload collection is too large")]
    PayloadTooLarge,
    #[error("manifest contains {0} payloads")]
    TooManyPayloads(usize),
    #[error("manifest repeats a destination and message kind")]
    DuplicateDestination,
    #[error("sequence was already accepted with different contents")]
    ReplayConflict,
    #[error("sequence precedes an already accepted contribution")]
    OutOfOrderSequence,
    #[error("replay store: {0}")]
    ReplayStore(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DeveloperSigner, EnrolmentStatement, RemoteSessionPolicy) {
        let signer = DeveloperSigner::new(Identity::generate());
        let statement = EnrolmentStatement {
            lease_id: [1; 32],
            config_hash: [2; 32],
            subnet: 4,
            protocol: ProtocolId::Panetiere,
            participant: Identity::generate().pubkey(),
            forwarder: Identity::generate().pubkey(),
            platform_key: signer.public_key(),
            process_nonce: [3; 32],
            valid_from: 10,
            valid_until: 20,
        };
        let policy = RemoteSessionPolicy {
            enabled: true,
            allow_developer: true,
            developer_keys: vec![signer.public_key()],
            allowed_protocols: vec![ProtocolId::Panetiere],
            max_lease_rounds: 10,
        };
        (signer, statement, policy)
    }

    async fn signed(signer: &DeveloperSigner, lease: &EnrolmentStatement, sequence: u64, bytes: &[u8]) -> AttestedContribution {
        let payload = ContributionPayload {
            recipient: ContributionRecipient::Broadcast,
            kind: 7,
            bytes: bytes.to_vec(),
        };
        let (manifest, payloads) = freeze_manifest(lease, 12, 1, sequence, None, vec![payload]).unwrap();
        let evidence = signer.sign_manifest(&manifest).await.unwrap();
        AttestedContribution { manifest, evidence, payloads }
    }

    #[tokio::test]
    async fn developer_enrolment_and_contribution_verify() {
        let (signer, statement, policy) = fixture();
        let verifier = ContributionVerifier::new(policy, ReplayStore::default());
        let lease = verifier.verify_enrolment(&signer.enrol(statement).unwrap(), 11).unwrap();
        let contribution = signed(&signer, &lease, 1, b"hello").await;
        assert_eq!(verifier.verify(&lease, contribution.clone(), 12).unwrap().replay(), ReplayDecision::Fresh);
        assert_eq!(verifier.verify(&lease, contribution, 12).unwrap().replay(), ReplayDecision::Duplicate);
    }

    #[tokio::test]
    async fn alteration_conflict_and_production_policy_fail_closed() {
        let (signer, statement, policy) = fixture();
        let enrolment = signer.enrol(statement).unwrap();
        let verifier = ContributionVerifier::new(policy.clone(), ReplayStore::default());
        let lease = verifier.verify_enrolment(&enrolment, 11).unwrap();
        let mut altered = signed(&signer, &lease, 1, b"hello").await;
        altered.payloads[0].bytes[0] ^= 1;
        assert_eq!(verifier.verify(&lease, altered, 12).unwrap_err(), ContributionError::PayloadMismatch);
        verifier.verify(&lease, signed(&signer, &lease, 1, b"first").await, 12).unwrap();
        assert_eq!(verifier.verify(&lease, signed(&signer, &lease, 1, b"second").await, 12).unwrap_err(), ContributionError::ReplayConflict);

        let mut production = policy;
        production.allow_developer = false;
        assert_eq!(ContributionVerifier::new(production, ReplayStore::default()).verify_enrolment(&enrolment, 11).unwrap_err(), ContributionError::DeveloperEvidenceRejected);
    }

    #[tokio::test]
    async fn replay_state_survives_restart() {
        let (signer, lease, policy) = fixture();
        let verifier = ContributionVerifier::new(policy.clone(), ReplayStore::default());
        verifier.verify(&lease, signed(&signer, &lease, 3, b"saved").await, 12).unwrap();
        let restored = ReplayStore::from_bytes(&verifier.replay_snapshot().unwrap()).unwrap();
        let verifier = ContributionVerifier::new(policy, restored);
        assert_eq!(verifier.verify(&lease, signed(&signer, &lease, 3, b"saved").await, 12).unwrap().replay(), ReplayDecision::Duplicate);
        assert_eq!(verifier.verify(&lease, signed(&signer, &lease, 2, b"old").await, 12).unwrap_err(), ContributionError::OutOfOrderSequence);
    }
}
