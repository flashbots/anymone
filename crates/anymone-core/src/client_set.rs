//! Canonical client-set selection, over panetiere's rs-mode primitives.
//!
//! Client c — a TEE with an ephemeral per-boot signing key — sends server j
//! one signed bundle (lane j's ciphertext share and server j's sealed opening)
//! and collects a certificate from every server that answers; certificates
//! sign the boot pubkey, so one package can never mix two boots' data. The
//! certificates plus an erasure coding of the uncertified lanes' bundles form
//! the client's evidence package: every lane is covered by a receipt or by
//! recoverable data. After the client window closes, servers run `n − k + 1`
//! Dolev–Strong relay rounds — an item is accepted at round r iff it carries r
//! distinct server chain signatures, and acceptance means one signed forward —
//! so every honest server decides over the same pool no matter how delivery
//! was timed. Inclusion is a pure function of that agreed pool: a client with
//! one complete package is in everywhere, a client whose host booted twice
//! and finished two packages is out everywhere, and a censoring server's
//! withheld receipt merely moves its lane into the coded detour.

use std::collections::{BTreeMap, BTreeSet};

use chipmunk_code::{DgtNTTPoly, N};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use panetiere::bulletin::{RsClientBulletinEntry, ServerBulletinEntry};
use panetiere::kahe::{Kahe, KaheScheme};
use panetiere::pke;
use panetiere::protocol::client::run_client_round_rs;
use panetiere::protocol::server::{unseal_opening, RsNodeInbox, ServerInbox};
use panetiere::protocol::{ClientId, NodeId, ProtocolParams, ServerId, SessionId};
use panetiere::rs::{Rs, RsParams, Share};
use panetiere::sig;

fn code(pp: &ProtocolParams) -> &RsParams {
    let rs = pp.rs.as_ref().expect("RS mode params");
    assert_eq!(rs.n, pp.cs.n_servers, "one lane per server");
    rs
}

/// One Dolev–Strong round more than the `n − k` misbehaving-server budget.
pub fn relay_rounds(pp: &ProtocolParams) -> usize {
    let rs = code(pp);
    rs.n - rs.k + 1
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hash_share(share: &[DgtNTTPoly]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in share {
        for c in p.coeffs() {
            h.update(c.to_le_bytes());
        }
    }
    h.finalize().into()
}

pub fn bundle_signing_bytes(
    sid: &SessionId,
    client_id: ClientId,
    lane: usize,
    share: &[DgtNTTPoly],
    envelope: &[u8],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/bundle/v2";
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 8 + 64);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&client_id.0.to_le_bytes());
    out.extend_from_slice(&(lane as u32).to_le_bytes());
    out.extend_from_slice(&hash_share(share));
    out.extend_from_slice(&sha(&[envelope]));
    out
}

#[derive(Clone)]
pub struct Bundle {
    pub client_id: ClientId,
    pub lane: usize,
    pub share: Share,
    pub envelope: Vec<u8>,
    pub pubkey: [u8; sig::PUBKEY_LEN],
    pub sig: [u8; sig::SIG_LEN],
}

impl Bundle {
    pub fn wire_len(&self) -> usize {
        self.share.len() * N * 8 + self.envelope.len() + sig::PUBKEY_LEN + sig::SIG_LEN + 8
    }

    fn hash(&self) -> [u8; 32] {
        sha(&[
            &hash_share(&self.share),
            &self.envelope,
            &self.pubkey,
            &self.sig,
        ])
    }

    fn verify(&self, sid: &SessionId, n_lanes: usize) -> bool {
        if self.lane >= n_lanes {
            return false;
        }
        let Ok(vk) = sig::VerifyingKey::from_sec1_bytes(&self.pubkey) else {
            return false;
        };
        vk.verify(
            &bundle_signing_bytes(sid, self.client_id, self.lane, &self.share, &self.envelope),
            &self.sig,
        )
        .is_ok()
    }

    fn pack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.lane as u32).to_le_bytes());
        out.extend_from_slice(&(self.share.len() as u32).to_le_bytes());
        for p in &self.share {
            for c in p.coeffs() {
                out.extend_from_slice(&c.to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.envelope.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.envelope);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.sig);
        out
    }

    fn unpack(client_id: ClientId, bytes: &[u8]) -> Option<(Self, usize)> {
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let lane = word(0)?;
        let n_polys = word(4)?;
        // Bound the allocation by the bytes actually present.
        if n_polys > bytes.len().saturating_sub(8) / (N * 8) {
            return None;
        }
        let mut at = 8;
        let mut share = Vec::with_capacity(n_polys);
        for _ in 0..n_polys {
            let mut coeffs = [0u64; N];
            for c in coeffs.iter_mut() {
                *c = u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?);
                at += 8;
            }
            share.push(DgtNTTPoly::from_raw(&coeffs));
        }
        let env_len = word(at)?;
        at += 4;
        let envelope = bytes.get(at..at + env_len)?.to_vec();
        at += env_len;
        let pubkey: [u8; sig::PUBKEY_LEN] = bytes.get(at..at + sig::PUBKEY_LEN)?.try_into().ok()?;
        at += sig::PUBKEY_LEN;
        let sig: [u8; sig::SIG_LEN] = bytes.get(at..at + sig::SIG_LEN)?.try_into().ok()?;
        at += sig::SIG_LEN;
        Some((
            Bundle {
                client_id,
                lane,
                share,
                envelope,
                pubkey,
                sig,
            },
            at,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Certificate {
    pub client_id: ClientId,
    pub server_id: ServerId,
    pub bundle_hash: [u8; 32],
    pub sig: [u8; sig::SIG_LEN],
}

/// Certificates sign the boot pubkey: certs from two boots can never validate
/// inside one package, so mixed-run evidence dies uniformly at every server.
pub fn cert_signing_bytes(
    sid: &SessionId,
    client_id: ClientId,
    server_id: ServerId,
    client_pubkey: &[u8; sig::PUBKEY_LEN],
    bundle_hash: &[u8; 32],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/cert/v2";
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 8 + sig::PUBKEY_LEN + 32);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&client_id.0.to_le_bytes());
    out.extend_from_slice(&server_id.0.to_le_bytes());
    out.extend_from_slice(client_pubkey);
    out.extend_from_slice(bundle_hash);
    out
}

/// One coded piece of the uncertified lanes' bundles, client-signed so relays
/// are self-authenticating.
#[derive(Clone)]
pub struct Fragment {
    pub client_id: ClientId,
    pub idx: usize,
    pub data: Share,
    pub sig: [u8; sig::SIG_LEN],
}

pub fn fragment_signing_bytes(
    sid: &SessionId,
    client_id: ClientId,
    idx: usize,
    data: &[DgtNTTPoly],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/fragment/v1";
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 8 + 32);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&client_id.0.to_le_bytes());
    out.extend_from_slice(&(idx as u32).to_le_bytes());
    out.extend_from_slice(&hash_share(data));
    out
}

fn fragment_item_hash(sid: &SessionId, f: &Fragment) -> [u8; 32] {
    sha(&[
        b"panetiere/client-set/fragment-id/v1",
        &fragment_signing_bytes(sid, f.client_id, f.idx, &f.data),
    ])
}

/// The client's inclusion ticket: certificates for the lanes that answered,
/// erasure-coded bundles for the lanes that did not.
#[derive(Clone, PartialEq)]
pub struct Evidence {
    pub client_id: ClientId,
    pub certs: Vec<Certificate>,
    /// Lanes without a certificate, sorted; what the fragments encode.
    pub missing: Vec<usize>,
    pub blob_len: usize,
    pub pubkey: [u8; sig::PUBKEY_LEN],
    pub sig: [u8; sig::SIG_LEN],
}

pub fn evidence_signing_bytes(
    sid: &SessionId,
    client_id: ClientId,
    missing: &[usize],
    blob_len: usize,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/evidence/v2";
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 4 * missing.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&client_id.0.to_le_bytes());
    out.extend_from_slice(&(blob_len as u64).to_le_bytes());
    out.extend_from_slice(&(missing.len() as u32).to_le_bytes());
    for m in missing {
        out.extend_from_slice(&(*m as u32).to_le_bytes());
    }
    out
}

impl Evidence {
    /// Boot-scoped identity: the signed content plus the boot pubkey, no
    /// signature bytes — ECDSA malleability would otherwise let any relayer
    /// mint a "distinct" package and frame the client as an equivocator.
    pub fn identity(&self, sid: &SessionId) -> [u8; 32] {
        sha(&[
            b"panetiere/client-set/evidence-id/v1",
            &evidence_signing_bytes(sid, self.client_id, &self.missing, self.blob_len),
            &self.pubkey,
        ])
    }
}

pub fn relay_signing_bytes(sid: &SessionId, item_hash: &[u8; 32]) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/relay/v1";
    let mut out = Vec::with_capacity(DOMAIN.len() + 64);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(item_hash);
    out
}

#[derive(Clone)]
pub enum RelayItem {
    Evidence(Evidence),
    Fragment(Fragment),
}

impl RelayItem {
    fn hash(&self, sid: &SessionId) -> [u8; 32] {
        match self {
            RelayItem::Evidence(e) => e.identity(sid),
            RelayItem::Fragment(f) => fragment_item_hash(sid, f),
        }
    }
}

/// One relayed item and its Dolev–Strong signature chain: accepted at round r
/// iff the chain holds r distinct valid server signatures.
#[derive(Clone)]
pub struct Relay {
    pub item: RelayItem,
    pub chain: Vec<(ServerId, [u8; sig::SIG_LEN])>,
}

const BYTES_PER_COEFF: usize = 7;

fn blob_to_polys(blob: &[u8]) -> Vec<DgtNTTPoly> {
    let coeffs = blob.len().div_ceil(BYTES_PER_COEFF).max(1);
    (0..coeffs.div_ceil(N))
        .map(|p| {
            let mut arr = [0u64; N];
            for (i, a) in arr.iter_mut().enumerate() {
                let at = (p * N + i) * BYTES_PER_COEFF;
                let mut word = [0u8; 8];
                for (w, b) in word.iter_mut().zip(blob.iter().skip(at).take(BYTES_PER_COEFF)) {
                    *w = *b;
                }
                *a = u64::from_le_bytes(word);
            }
            DgtNTTPoly::from_raw(&arr)
        })
        .collect()
}

fn polys_to_blob(polys: &[DgtNTTPoly], blob_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(polys.len() * N * BYTES_PER_COEFF);
    for p in polys {
        for c in p.coeffs() {
            out.extend_from_slice(&c.to_le_bytes()[..BYTES_PER_COEFF]);
        }
    }
    out.truncate(blob_len);
    out
}

fn fragment_params(pp: &ProtocolParams, n_responders: usize) -> RsParams {
    let rs = code(pp);
    RsParams::new(rs.n - rs.k, n_responders)
}

pub struct ClientSetRound {
    pub client_id: ClientId,
    pub bulletin: RsClientBulletinEntry,
    pub bundles: Vec<Bundle>,
}

pub fn run_client_round_set<R: rand::CryptoRng + rand::Rng>(
    rng: &mut R,
    pp: &ProtocolParams,
    sid: &SessionId,
    client_id: ClientId,
    message: <Kahe as KaheScheme>::Message,
    servers: &[(ServerId, pke::PublicKey)],
    signing_key: &sig::SigningKey,
) -> ClientSetRound {
    let rs = code(pp);
    let round = run_client_round_rs(rng, pp, sid, client_id, message, servers, signing_key);
    assert_eq!(round.sealed_openings.len(), rs.n);

    let pubkey = signing_key.verifying_key().to_sec1_bytes();
    let bundles = (0..rs.n)
        .map(|lane| {
            let share = round.rs_shares[lane].clone();
            let envelope = round.sealed_openings[lane].1.clone();
            let sig =
                signing_key.sign(&bundle_signing_bytes(sid, client_id, lane, &share, &envelope));
            Bundle {
                client_id,
                lane,
                share,
                envelope,
                pubkey,
                sig,
            }
        })
        .collect();

    ClientSetRound {
        client_id,
        bulletin: round.bulletin,
        bundles,
    }
}

/// Certificates in hand, package the uncertified lanes: one fragment per
/// certifying server, any `n − k` of which rebuild every withheld bundle.
pub fn build_evidence(
    pp: &ProtocolParams,
    sid: &SessionId,
    round: &ClientSetRound,
    certs: Vec<Certificate>,
    signing_key: &sig::SigningKey,
) -> (Evidence, Vec<Fragment>) {
    let rs = code(pp);
    let cid = round.client_id;
    let certified: Vec<usize> = certs.iter().map(|c| c.server_id.0 as usize).collect();
    let missing: Vec<usize> = (0..rs.n).filter(|l| !certified.contains(l)).collect();
    assert!(
        missing.is_empty() || certs.len() >= rs.n - rs.k,
        "too few certifiers to code around the gap"
    );

    let blob: Vec<u8> = missing
        .iter()
        .flat_map(|&l| round.bundles[l].pack())
        .collect();
    let fragments = if missing.is_empty() {
        Vec::new()
    } else {
        Rs::encode(&fragment_params(pp, certs.len()), &blob_to_polys(&blob))
            .into_iter()
            .enumerate()
            .map(|(idx, data)| {
                let sig = signing_key.sign(&fragment_signing_bytes(sid, cid, idx, &data));
                Fragment {
                    client_id: cid,
                    idx,
                    data,
                    sig,
                }
            })
            .collect()
    };

    let evidence = Evidence {
        client_id: cid,
        certs,
        missing: missing.clone(),
        blob_len: blob.len(),
        pubkey: signing_key.verifying_key().to_sec1_bytes(),
        sig: signing_key.sign(&evidence_signing_bytes(sid, cid, &missing, blob.len())),
    };
    (evidence, fragments)
}

/// Two distinct packages already prove a conflict; a third adds nothing, so
/// storage stops there. Same bound for bundles against a rebooting host.
const MAX_EVIDENCE: usize = 2;
const MAX_BUNDLES: usize = 4;

struct Accepted {
    evidence: Evidence,
    fragments: BTreeMap<usize, Fragment>,
}

struct Entry {
    /// Every certified bundle, keyed by the hash its certificate binds.
    bundles: BTreeMap<[u8; 32], Bundle>,
    /// Accepted packages by identity; more than one is a boot conflict.
    evidence: BTreeMap<[u8; 32], Accepted>,
}

pub struct SetServer {
    server_id: ServerId,
    n_lanes: usize,
    k: usize,
    signer: sig::SigningKey,
    server_pks: Vec<sig::VerifyingKey>,
    /// Client-direct input closes when the relay opens.
    relaying: bool,
    /// Item hashes accepted — each was validated, chain-signed and forwarded
    /// exactly once.
    accepted: BTreeSet<[u8; 32]>,
    pool: BTreeMap<ClientId, Entry>,
}

pub struct SetRound {
    pub set: Vec<ClientId>,
    pub inbox: ServerInbox,
    pub lane_inbox: RsNodeInbox,
    /// Rejected on evidence grounds — uniform, since the pool is agreed.
    pub excluded: Vec<ClientId>,
    /// Excluded because two boots both finished a package.
    pub conflicted: Vec<ClientId>,
    /// Included with this lane's bundle rebuilt from fragments.
    pub repaired: Vec<ClientId>,
}

impl SetServer {
    pub fn new(
        pp: &ProtocolParams,
        server_id: ServerId,
        signer: sig::SigningKey,
        server_pks: Vec<sig::VerifyingKey>,
    ) -> Self {
        let rs = code(pp);
        assert_eq!(server_pks.len(), rs.n);
        assert!((server_id.0 as usize) < rs.n, "server id must name a lane");
        Self {
            server_id,
            n_lanes: rs.n,
            k: rs.k,
            signer,
            server_pks,
            relaying: false,
            accepted: BTreeSet::new(),
            pool: BTreeMap::new(),
        }
    }

    /// Accept a direct delivery and issue the receipt the client will show
    /// everyone else. A censoring server withholds exactly this.
    pub fn receive(&mut self, sid: &SessionId, b: &Bundle) -> Option<Certificate> {
        if self.relaying || b.lane != self.server_id.0 as usize || !b.verify(sid, self.n_lanes) {
            return None;
        }
        let hash = b.hash();
        let bundles = &mut self.entry(b.client_id).bundles;
        if bundles.len() >= MAX_BUNDLES && !bundles.contains_key(&hash) {
            return None;
        }
        bundles.insert(hash, b.clone());
        Some(Certificate {
            client_id: b.client_id,
            server_id: self.server_id,
            bundle_hash: hash,
            sig: self.signer.sign(&cert_signing_bytes(
                sid,
                b.client_id,
                self.server_id,
                &b.pubkey,
                &hash,
            )),
        })
    }

    /// Take a client-direct evidence package before the relay opens.
    /// Certificates and fragments carry their own signatures, checked in one
    /// parallel batch; a package already stored is recognized and skipped.
    pub fn submit(&mut self, sid: &SessionId, e: &Evidence, fragments: &[Fragment]) -> bool {
        if self.relaying || !self.accept_evidence(sid, e) {
            return false;
        }
        self.accept_fragments(sid, e.client_id, fragments);
        true
    }

    fn accept_evidence(&mut self, sid: &SessionId, e: &Evidence) -> bool {
        let id = e.identity(sid);
        if self.accepted.contains(&id) {
            return true;
        }
        if !self.evidence_ok(sid, e) {
            return false;
        }
        let entry = self.entry(e.client_id);
        if entry.evidence.len() >= MAX_EVIDENCE {
            return false;
        }
        entry.evidence.insert(
            id,
            Accepted {
                evidence: e.clone(),
                fragments: BTreeMap::new(),
            },
        );
        self.accepted.insert(id);
        true
    }

    /// Store the fragments that verify under an accepted package's boot key,
    /// deduped by index; returns the fresh ones for forwarding.
    fn accept_fragments(
        &mut self,
        sid: &SessionId,
        cid: ClientId,
        fragments: &[Fragment],
    ) -> Vec<Fragment> {
        let Some(entry) = self.pool.get_mut(&cid) else {
            return Vec::new();
        };
        let mut jobs: Vec<([u8; 32], &Fragment, sig::VerifyingKey)> = Vec::new();
        for f in fragments {
            if f.client_id != cid {
                continue;
            }
            for (id, acc) in &entry.evidence {
                if f.idx >= acc.evidence.certs.len() || acc.fragments.contains_key(&f.idx) {
                    continue;
                }
                let Ok(vk) = sig::VerifyingKey::from_sec1_bytes(&acc.evidence.pubkey) else {
                    continue;
                };
                jobs.push((*id, f, vk));
            }
        }
        let ok: Vec<([u8; 32], Fragment)> = jobs
            .into_par_iter()
            .filter_map(|(id, f, vk)| {
                vk.verify(
                    &fragment_signing_bytes(sid, f.client_id, f.idx, &f.data),
                    &f.sig,
                )
                .ok()
                .map(|_| (id, f.clone()))
            })
            .collect();
        let mut fresh = Vec::new();
        for (id, f) in ok {
            let acc = entry.evidence.get_mut(&id).expect("job came from this map");
            let hash = fragment_item_hash(sid, &f);
            if acc.fragments.insert(f.idx, f.clone()).is_none() && self.accepted.insert(hash) {
                fresh.push(f);
            }
        }
        fresh
    }

    fn evidence_ok(&self, sid: &SessionId, e: &Evidence) -> bool {
        let Ok(vk) = sig::VerifyingKey::from_sec1_bytes(&e.pubkey) else {
            return false;
        };
        if vk
            .verify(
                &evidence_signing_bytes(sid, e.client_id, &e.missing, e.blob_len),
                &e.sig,
            )
            .is_err()
        {
            return false;
        }
        // Below n − k certifiers the fragment code cannot exist; such a
        // package can only be fabricated, and would panic the RS params.
        if e.certs.len() < self.n_lanes - self.k {
            return false;
        }
        // Exact sorted coverage: every lane once, no duplicate server ids.
        // Load-bearing — it pins the fragment count and idx range per package.
        let mut covered: Vec<usize> = e
            .certs
            .iter()
            .map(|c| c.server_id.0 as usize)
            .chain(e.missing.iter().copied())
            .collect();
        covered.sort_unstable();
        if covered != (0..self.n_lanes).collect::<Vec<_>>() {
            return false;
        }
        e.certs.par_iter().all(|c| {
            c.client_id == e.client_id
                && self.server_pks[c.server_id.0 as usize]
                    .verify(
                        &cert_signing_bytes(sid, c.client_id, c.server_id, &e.pubkey, &c.bundle_hash),
                        &c.sig,
                    )
                    .is_ok()
        })
    }

    /// Close the client window and open the relay: everything accepted so far
    /// goes out under this server's first chain signature.
    pub fn echo(&mut self, sid: &SessionId) -> Vec<Relay> {
        self.relaying = true;
        let mut items = Vec::new();
        for entry in self.pool.values() {
            for acc in entry.evidence.values() {
                items.push(RelayItem::Evidence(acc.evidence.clone()));
                for f in acc.fragments.values() {
                    items.push(RelayItem::Fragment(f.clone()));
                }
            }
        }
        items
            .into_iter()
            .map(|item| {
                let hash = item.hash(sid);
                let sig = self.signer.sign(&relay_signing_bytes(sid, &hash));
                Relay {
                    item,
                    chain: vec![(self.server_id, sig)],
                }
            })
            .collect()
    }

    /// One Dolev–Strong round, processed as a batch with evidence ahead of
    /// fragments so a fragment never waits on its own package. An item is
    /// accepted iff it validates and its chain holds at least `round` distinct
    /// valid server signatures; fresh acceptances come back chain-extended for
    /// the next round's broadcast. Rejection is stateless — a variant that
    /// fails here never poisons its identity for a later valid copy.
    pub fn absorb(&mut self, sid: &SessionId, round: usize, incoming: &[Relay]) -> Vec<Relay> {
        let (evidence, fragments): (Vec<&Relay>, Vec<&Relay>) = incoming
            .iter()
            .partition(|r| matches!(r.item, RelayItem::Evidence(_)));
        let mut out = Vec::new();
        for r in evidence.into_iter().chain(fragments) {
            let hash = r.item.hash(sid);
            if self.accepted.contains(&hash) || self.chain_len(sid, &hash, &r.chain) < round {
                continue;
            }
            match &r.item {
                RelayItem::Evidence(e) => {
                    self.accept_evidence(sid, e);
                }
                RelayItem::Fragment(f) => {
                    self.accept_fragments(sid, f.client_id, std::slice::from_ref(f));
                }
            }
            if self.accepted.contains(&hash) {
                let mut chain = r.chain.clone();
                chain.retain(|(id, _)| *id != self.server_id);
                chain.push((
                    self.server_id,
                    self.signer.sign(&relay_signing_bytes(sid, &hash)),
                ));
                out.push(Relay {
                    item: r.item.clone(),
                    chain,
                });
            }
        }
        out
    }

    /// Distinct server ids with a valid chain signature — malleated or
    /// duplicated signatures never inflate the count.
    fn chain_len(
        &self,
        sid: &SessionId,
        item_hash: &[u8; 32],
        chain: &[(ServerId, [u8; sig::SIG_LEN])],
    ) -> usize {
        let msg = relay_signing_bytes(sid, item_hash);
        let mut seen = BTreeSet::new();
        for (id, s) in chain {
            let j = id.0 as usize;
            if j < self.server_pks.len()
                && !seen.contains(&j)
                && self.server_pks[j].verify(&msg, s).is_ok()
            {
                seen.insert(j);
            }
        }
        seen.len()
    }

    /// Fix the set from the agreed pool: exactly one package whose coded lanes
    /// (if any) rebuild and verify. Membership is uniform by construction;
    /// only serving can fail locally, and then this server abstains from
    /// publishing instead of splitting the set.
    pub fn finalize(&self, pp: &ProtocolParams, key: &pke::PrivateKey, sid: &SessionId) -> SetRound {
        let me = self.server_id.0 as usize;
        let mut out = SetRound {
            set: Vec::new(),
            inbox: ServerInbox {
                server_id: self.server_id,
                items: Vec::new(),
            },
            lane_inbox: RsNodeInbox {
                node_id: NodeId(me as u32),
                items: Vec::new(),
            },
            excluded: Vec::new(),
            conflicted: Vec::new(),
            repaired: Vec::new(),
        };

        for (cid, entry) in &self.pool {
            let mut packages = entry.evidence.values();
            let acc = match (packages.next(), packages.next()) {
                (Some(acc), None) => acc,
                (None, _) => {
                    out.excluded.push(*cid);
                    continue;
                }
                (Some(_), Some(_)) => {
                    out.conflicted.push(*cid);
                    out.excluded.push(*cid);
                    continue;
                }
            };
            let e = &acc.evidence;
            let rebuilt = if e.missing.is_empty() {
                None
            } else {
                // Every server rebuilds and checks the coded lanes; the
                // fragment pool is agreed, so the verdict is uniform.
                match self.rebuild(pp, sid, e, &acc.fragments) {
                    Some(bundles) => Some(bundles),
                    None => {
                        out.excluded.push(*cid);
                        continue;
                    }
                }
            };
            out.set.push(*cid);

            let mine_coded = e.missing.contains(&me);
            let bundle = if mine_coded {
                rebuilt.and_then(|bs| bs.into_iter().find(|b| b.lane == me))
            } else {
                // A valid certificate under my key means I issued it and hold
                // the matching bundle.
                e.certs
                    .iter()
                    .find(|c| c.server_id == self.server_id)
                    .and_then(|c| entry.bundles.get(&c.bundle_hash).cloned())
            };
            let Some(b) = bundle else {
                continue;
            };
            if mine_coded {
                out.repaired.push(*cid);
            }
            if let Some(opening) = unseal_opening(key, sid, *cid, self.server_id, &b.envelope) {
                out.inbox.items.push((*cid, opening));
            }
            out.lane_inbox.items.push((*cid, b.share));
        }
        out
    }

    /// Reconstruct the coded lanes; every rebuilt bundle must verify under the
    /// package's boot key. Sample selection is `BTreeMap` order, first k —
    /// deterministic, so every server decodes the same blob.
    fn rebuild(
        &self,
        pp: &ProtocolParams,
        sid: &SessionId,
        e: &Evidence,
        fragments: &BTreeMap<usize, Fragment>,
    ) -> Option<Vec<Bundle>> {
        let params = fragment_params(pp, e.certs.len());
        if fragments.len() < params.k {
            return None;
        }
        let n_polys = e.blob_len.div_ceil(BYTES_PER_COEFF).max(1).div_ceil(N);
        // The blob cannot outgrow what k real fragments encode; a bigger
        // blob_len is fabricated and only angles for a huge allocation.
        if n_polys > params.k * fragments.values().next()?.data.len() {
            return None;
        }
        let samples: Vec<(usize, &[DgtNTTPoly])> = fragments
            .values()
            .map(|f| (f.idx, f.data.as_slice()))
            .take(params.k)
            .collect();
        let blob = polys_to_blob(&Rs::reconstruct(&params, n_polys, &samples).ok()?, e.blob_len);

        let mut out = Vec::with_capacity(e.missing.len());
        let mut at = 0;
        for &lane in &e.missing {
            let (b, used) = Bundle::unpack(e.client_id, &blob[at..])?;
            if b.lane != lane || b.pubkey != e.pubkey || !b.verify(sid, self.n_lanes) {
                return None;
            }
            at += used;
            out.push(b);
        }
        Some(out)
    }

    fn entry(&mut self, cid: ClientId) -> &mut Entry {
        self.pool.entry(cid).or_insert_with(|| Entry {
            bundles: BTreeMap::new(),
            evidence: BTreeMap::new(),
        })
    }
}

/// The set the most servers published; ties go to the larger, then the
/// lexicographically greater, so every recipient anchors on the same one.
pub fn plurality_set(outputs: &[ServerBulletinEntry]) -> Vec<ClientId> {
    let mut counts: BTreeMap<Vec<ClientId>, usize> = BTreeMap::new();
    for o in outputs {
        *counts.entry(o.clients.clone()).or_default() += 1;
    }
    counts
        .iter()
        .max_by(|(sa, na), (sb, nb)| (*na, sa.len(), *sa).cmp(&(*nb, sb.len(), *sb)))
        .map(|(set, _)| set.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn blob_codec_round_trips() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        for len in [0usize, 1, 6, 7, 8, N * BYTES_PER_COEFF - 1, N * BYTES_PER_COEFF + 13] {
            let blob: Vec<u8> = (0..len).map(|_| rand::Rng::gen(&mut rng)).collect();
            let polys = blob_to_polys(&blob);
            assert_eq!(polys_to_blob(&polys, len), blob, "len {len}");
        }
    }
}
