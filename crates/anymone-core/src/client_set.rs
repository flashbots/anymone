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

use panetiere::bulletin::{dgt_packed_len, RsClientBulletinEntry, ServerBulletinEntry};
use panetiere::kahe::{Kahe, KaheScheme};
use panetiere::pke;
use panetiere::protocol::client::run_client_round_rs;
use panetiere::protocol::server::{unseal_opening, RsNodeInbox, ServerInbox};
use panetiere::protocol::{ClientId, NodeId, ProtocolParams, ServerId, SessionId};
use panetiere::rs::{pack_share, unpack_share, Rs, RsParams, Share};
use panetiere::share_commitment::{fresh_path_packed_len, ShareCommitmentParams, SharePath};
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

fn hash_path(path: &SharePath) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((path.lane_index as u32).to_le_bytes());
    for p in path.nodes.iter() {
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
    path: &SharePath,
    envelope: &[u8],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/bundle/v3";
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 8 + 96);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&client_id.0.to_le_bytes());
    out.extend_from_slice(&(lane as u32).to_le_bytes());
    out.extend_from_slice(&hash_share(share));
    out.extend_from_slice(&hash_path(path));
    out.extend_from_slice(&sha(&[envelope]));
    out
}

#[derive(Clone)]
pub struct Bundle {
    pub client_id: ClientId,
    pub lane: usize,
    pub share: Share,
    /// Lane `lane`'s opening of the client's share commitment; the lane needs it
    /// to prove its summed share against `Σ share_root`.
    pub path: SharePath,
    pub envelope: Vec<u8>,
    pub pubkey: [u8; sig::PUBKEY_LEN],
    pub sig: [u8; sig::SIG_LEN],
}

impl Bundle {
    /// Exact packed size under `scp`'s geometry — the share and path lengths are
    /// fixed by it, so only the envelope varies.
    pub fn packed_len(scp: &ShareCommitmentParams, envelope_len: usize) -> usize {
        8 + scp.block_len * dgt_packed_len()
            + fresh_path_packed_len(scp.n_lanes)
            + envelope_len
            + sig::PUBKEY_LEN
            + sig::SIG_LEN
    }

    /// What a certificate binds.
    pub fn hash(&self) -> [u8; 32] {
        sha(&[
            &hash_share(&self.share),
            &hash_path(&self.path),
            &self.envelope,
            &self.pubkey,
            &self.sig,
        ])
    }

    fn verify(&self, sid: &SessionId, n_lanes: usize) -> bool {
        if self.lane >= n_lanes || self.path.lane_index != self.lane {
            return false;
        }
        let Ok(vk) = sig::VerifyingKey::from_sec1_bytes(&self.pubkey) else {
            return false;
        };
        vk.verify(
            &bundle_signing_bytes(
                sid,
                self.client_id,
                self.lane,
                &self.share,
                &self.path,
                &self.envelope,
            ),
            &self.sig,
        )
        .is_ok()
    }

    /// `None` when the path digits are past ζ, which `SharePath::from_bytes`
    /// would refuse anyway.
    pub fn pack(&self, scp: &ShareCommitmentParams) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::packed_len(scp, self.envelope.len()));
        out.extend_from_slice(&(self.lane as u32).to_le_bytes());
        pack_share(&self.share, &mut out);
        out.extend_from_slice(&self.path.to_bytes()?);
        out.extend_from_slice(&(self.envelope.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.envelope);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.sig);
        Some(out)
    }

    /// Reads one bundle from the front of `bytes`, returning it and the length
    /// consumed. Every field but the envelope is fixed-width under `scp`, so a
    /// fabricated blob cannot inflate an allocation.
    pub fn unpack(
        scp: &ShareCommitmentParams,
        client_id: ClientId,
        bytes: &[u8],
    ) -> Option<(Self, usize)> {
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let lane = word(0)?;
        let mut at = 4;
        let share_len = scp.block_len * dgt_packed_len();
        let share = unpack_share(bytes.get(at..at + share_len)?, scp.block_len)?;
        at += share_len;
        let path_len = fresh_path_packed_len(scp.n_lanes);
        let path = SharePath::from_bytes(scp, lane, bytes.get(at..at + path_len)?)?;
        at += path_len;
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
                path,
                envelope,
                pubkey,
                sig,
            },
            at,
        ))
    }
}

/// One lane's record that it holds client `client_id`'s bundle for the round.
/// `pk_c` is the boot key the bundle was signed under: two boots of one host
/// report different keys for the same client, which is how the matrix catches
/// them.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub client_id: ClientId,
    pub pk_c: [u8; sig::PUBKEY_LEN],
    pub bundle_hash: [u8; 32],
}

impl Receipt {
    pub const PACKED_LEN: usize = 4 + sig::PUBKEY_LEN + 32;

    fn pack_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.client_id.0.to_le_bytes());
        out.extend_from_slice(&self.pk_c);
        out.extend_from_slice(&self.bundle_hash);
    }

    fn unpack(bytes: &[u8]) -> Option<Self> {
        Some(Receipt {
            client_id: ClientId(u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?)),
            pk_c: bytes.get(4..4 + sig::PUBKEY_LEN)?.try_into().ok()?,
            bundle_hash: bytes
                .get(4 + sig::PUBKEY_LEN..Self::PACKED_LEN)?
                .try_into()
                .ok()?,
        })
    }
}

/// Everything lane `server_id` accepted this round, signed once. This is the
/// only thing relays agree on: the set is a function of the batches.
#[derive(Clone, Debug, PartialEq)]
pub struct ReceiptBatch {
    pub server_id: ServerId,
    pub receipts: Vec<Receipt>,
    pub sig: [u8; sig::SIG_LEN],
}

pub fn batch_signing_bytes(
    sid: &SessionId,
    server_id: ServerId,
    receipts: &[Receipt],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"panetiere/client-set/batch/v1";
    let mut out =
        Vec::with_capacity(DOMAIN.len() + 40 + receipts.len() * Receipt::PACKED_LEN);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&sid.0);
    out.extend_from_slice(&server_id.0.to_le_bytes());
    out.extend_from_slice(&(receipts.len() as u32).to_le_bytes());
    for r in receipts {
        r.pack_into(&mut out);
    }
    out
}

impl ReceiptBatch {
    pub fn packed_len(n_receipts: usize) -> usize {
        8 + sig::SIG_LEN + n_receipts * Receipt::PACKED_LEN
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::packed_len(self.receipts.len()));
        out.extend_from_slice(&self.server_id.0.to_le_bytes());
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&(self.receipts.len() as u32).to_le_bytes());
        for r in &self.receipts {
            r.pack_into(&mut out);
        }
        out
    }

    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        let server_id = ServerId(u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?));
        let sig: [u8; sig::SIG_LEN] = bytes.get(4..4 + sig::SIG_LEN)?.try_into().ok()?;
        let mut at = 4 + sig::SIG_LEN;
        let n = u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4;
        if n > bytes.len().saturating_sub(at) / Receipt::PACKED_LEN {
            return None;
        }
        let mut receipts = Vec::with_capacity(n);
        for _ in 0..n {
            receipts.push(Receipt::unpack(bytes.get(at..at + Receipt::PACKED_LEN)?)?);
            at += Receipt::PACKED_LEN;
        }
        (at == bytes.len()).then_some(ReceiptBatch {
            server_id,
            receipts,
            sig,
        })
    }

    fn verify(&self, sid: &SessionId, pks: &[sig::VerifyingKey]) -> bool {
        pks.get(self.server_id.0 as usize).is_some_and(|vk| {
            vk.verify(
                &batch_signing_bytes(sid, self.server_id, &self.receipts),
                &self.sig,
            )
            .is_ok()
        })
    }
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

impl Fragment {
    pub fn pack(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(12 + self.data.len() * dgt_packed_len() + sig::SIG_LEN);
        out.extend_from_slice(&self.client_id.0.to_le_bytes());
        out.extend_from_slice(&(self.idx as u32).to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        pack_share(&self.data, &mut out);
        out.extend_from_slice(&self.sig);
        out
    }

    /// Consumes `bytes` exactly; the poly count is bounded by the bytes present
    /// before anything is allocated.
    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let client_id = ClientId(word(0)? as u32);
        let idx = word(4)?;
        let n_polys = word(8)?;
        let body = 12 + n_polys * dgt_packed_len();
        if n_polys > bytes.len().saturating_sub(12) / dgt_packed_len()
            || bytes.len() != body + sig::SIG_LEN
        {
            return None;
        }
        let data = unpack_share(bytes.get(12..body)?, n_polys)?;
        Some(Fragment {
            client_id,
            idx,
            data,
            sig: bytes.get(body..)?.try_into().ok()?,
        })
    }
}

fn fragment_item_hash(sid: &SessionId, f: &Fragment) -> [u8; 32] {
    sha(&[
        b"panetiere/client-set/fragment-id/v1",
        &fragment_signing_bytes(sid, f.client_id, f.idx, &f.data),
    ])
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
    Batch(ReceiptBatch),
    Fragment(Fragment),
}

impl RelayItem {
    fn hash(&self, sid: &SessionId) -> [u8; 32] {
        match self {
            // Signature-free, so a re-signed batch is the same item and dedupes
            // rather than counting twice.
            RelayItem::Batch(b) => sha(&[
                b"panetiere/client-set/batch-id/v1",
                &batch_signing_bytes(sid, b.server_id, &b.receipts),
            ]),
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

impl Relay {
    const CHAIN_ENTRY: usize = 4 + sig::SIG_LEN;

    pub fn pack(&self) -> Vec<u8> {
        let (tag, item) = match &self.item {
            RelayItem::Batch(b) => (0u8, b.pack()),
            RelayItem::Fragment(f) => (1u8, f.pack()),
        };
        let mut out =
            Vec::with_capacity(9 + item.len() + self.chain.len() * Self::CHAIN_ENTRY);
        out.push(tag);
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(&item);
        out.extend_from_slice(&(self.chain.len() as u32).to_le_bytes());
        for (s, sg) in &self.chain {
            out.extend_from_slice(&s.0.to_le_bytes());
            out.extend_from_slice(sg);
        }
        out
    }

    pub fn unpack(bytes: &[u8]) -> Option<Self> {
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let tag = *bytes.first()?;
        let item_len = word(1)?;
        let body = bytes.get(5..5 + item_len)?;
        let item = match tag {
            0 => RelayItem::Batch(ReceiptBatch::unpack(body)?),
            1 => RelayItem::Fragment(Fragment::unpack(body)?),
            _ => return None,
        };
        let mut at = 5 + item_len;
        let n_chain = word(at)?;
        at += 4;
        if n_chain > bytes.len().saturating_sub(at) / Self::CHAIN_ENTRY {
            return None;
        }
        let mut chain = Vec::with_capacity(n_chain);
        for _ in 0..n_chain {
            chain.push((
                ServerId(word(at)? as u32),
                bytes.get(at + 4..at + Self::CHAIN_ENTRY)?.try_into().ok()?,
            ));
            at += Self::CHAIN_ENTRY;
        }
        if at != bytes.len() {
            return None;
        }
        Some(Relay { item, chain })
    }
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

/// One share per lane, any `n − k` of which rebuild.
fn fragment_params(pp: &ProtocolParams) -> RsParams {
    let rs = code(pp);
    RsParams::new(rs.n - rs.k, rs.n)
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
            let path = round.share_paths[lane].clone();
            let envelope = round.sealed_openings[lane].1.clone();
            let sig = signing_key.sign(&bundle_signing_bytes(
                sid, client_id, lane, &share, &path, &envelope,
            ));
            Bundle {
                client_id,
                lane,
                share,
                path,
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

/// Code the lanes that never acked, one fragment per lane that did. Sending
/// these to the *other* servers is the point: they check the bundle's own TEE
/// signature, so they can hand it to the lane that denies holding it and, if it
/// still refuses, conclude the client was censored rather than absent.
///
/// One fragment per lane, indexed by lane; the caller sends fragment `j` to
/// lane `j` for the lanes that acked.
pub fn build_fragments(
    pp: &ProtocolParams,
    sid: &SessionId,
    round: &ClientSetRound,
    covered: &[usize],
    signing_key: &sig::SigningKey,
) -> Vec<Fragment> {
    let rs = code(pp);
    let cid = round.client_id;
    let missing: Vec<usize> = (0..rs.n).filter(|l| !covered.contains(l)).collect();
    if missing.is_empty() || covered.len() < rs.n - rs.k {
        return Vec::new();
    }
    let scp = pp.share_comm.as_ref().expect("RS mode params");
    let blob: Vec<u8> = missing
        .iter()
        .flat_map(|&l| {
            round.bundles[l]
                .pack(scp)
                .expect("own fresh path digits within ζ")
        })
        .collect();
    Rs::encode(&fragment_params(pp), &blob_to_polys(&blob))
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
}

/// Bundles kept per client, against a host that reboots to grind hashes.
const MAX_BUNDLES: usize = 4;

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
    /// This lane's own bundles, keyed by the hash its receipt binds.
    held: BTreeMap<ClientId, BTreeMap<[u8; 32], Bundle>>,
    /// The agreed matrix: one batch per lane that published one.
    batches: BTreeMap<ServerId, ReceiptBatch>,
    fragments: BTreeMap<ClientId, BTreeMap<usize, Fragment>>,
    /// Boot keys seen in signed bulletins; more than one is a reboot.
    bulletins: BTreeMap<ClientId, BTreeSet<[u8; sig::PUBKEY_LEN]>>,
}

pub struct SetRound {
    pub set: Vec<ClientId>,
    pub inbox: ServerInbox,
    pub lane_inbox: RsNodeInbox,
    /// Left out: no lane reported it, or it cost more abstentions than the
    /// round can absorb.
    pub excluded: Vec<ClientId>,
    /// Excluded because two boots reported different keys for one client.
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
            held: BTreeMap::new(),
            batches: BTreeMap::new(),
            fragments: BTreeMap::new(),
            bulletins: BTreeMap::new(),
        }
    }

    /// Take a bundle and record a receipt for it. A censoring lane simply omits
    /// the client from the batch it publishes later.
    pub fn receive(&mut self, sid: &SessionId, b: &Bundle) -> bool {
        if self.relaying || b.lane != self.server_id.0 as usize || !b.verify(sid, self.n_lanes) {
            return false;
        }
        let hash = b.hash();
        let held = self.held.entry(b.client_id).or_default();
        if held.len() >= MAX_BUNDLES && !held.contains_key(&hash) {
            return false;
        }
        held.insert(hash, b.clone());
        true
    }

    /// This lane's record of the round, signed once.
    pub fn batch(&self, sid: &SessionId) -> ReceiptBatch {
        let receipts: Vec<Receipt> = self
            .held
            .iter()
            .filter_map(|(cid, bundles)| {
                // One boot per client is servable; a host that sent two leaves
                // this lane reporting whichever it kept, and the mismatch with
                // its peers is what the matrix catches.
                let (hash, b) = bundles.iter().next()?;
                Some(Receipt {
                    client_id: *cid,
                    pk_c: b.pubkey,
                    bundle_hash: *hash,
                })
            })
            .collect();
        ReceiptBatch {
            sig: self
                .signer
                .sign(&batch_signing_bytes(sid, self.server_id, &receipts)),
            server_id: self.server_id,
            receipts,
        }
    }

    /// Take repair fragments straight from the client and chain-sign the fresh
    /// ones for forwarding. Unlike bundles these are accepted after the batch is
    /// out: the client only learns it needs to repair by reading that batch.
    pub fn submit(&mut self, sid: &SessionId, fragments: &[Fragment]) -> Vec<Relay> {
        let fresh = self.accept_fragments(sid, fragments);
        fresh
            .into_iter()
            .map(|f| {
                let hash = fragment_item_hash(sid, &f);
                let sig = self.signer.sign(&relay_signing_bytes(sid, &hash));
                Relay {
                    item: RelayItem::Fragment(f),
                    chain: vec![(self.server_id, sig)],
                }
            })
            .collect()
    }

    fn accept_batch(&mut self, sid: &SessionId, b: &ReceiptBatch) -> bool {
        if !b.verify(sid, &self.server_pks) {
            return false;
        }
        // One batch per lane per round; a second is a lane trying to show two
        // faces, and the first is the one its peers already chained.
        self.batches.entry(b.server_id).or_insert_with(|| b.clone());
        true
    }

    /// Store fragments whose signature matches the key the matrix reports for
    /// their client, deduped by index; returns the fresh ones for forwarding.
    /// Verification is stateless, so one that arrives before its client's
    /// receipts is dropped and re-accepted from a later copy.
    fn accept_fragments(&mut self, sid: &SessionId, fragments: &[Fragment]) -> Vec<Fragment> {
        let jobs: Vec<(&Fragment, sig::VerifyingKey)> = fragments
            .iter()
            .filter(|f| {
                f.idx < self.n_lanes
                    && !self
                        .fragments
                        .get(&f.client_id)
                        .is_some_and(|held| held.contains_key(&f.idx))
            })
            .filter_map(|f| {
                let pk = self.reported_key(f.client_id)?;
                Some((f, sig::VerifyingKey::from_sec1_bytes(&pk).ok()?))
            })
            .collect();
        let ok: Vec<Fragment> = jobs
            .into_par_iter()
            .filter(|(f, vk)| {
                vk.verify(
                    &fragment_signing_bytes(sid, f.client_id, f.idx, &f.data),
                    &f.sig,
                )
                .is_ok()
            })
            .map(|(f, _)| f.clone())
            .collect();
        let mut fresh = Vec::new();
        for f in ok {
            let hash = fragment_item_hash(sid, &f);
            if self
                .fragments
                .entry(f.client_id)
                .or_default()
                .insert(f.idx, f.clone())
                .is_none()
                && self.accepted.insert(hash)
            {
                fresh.push(f);
            }
        }
        fresh
    }

    /// The boot key `cid` posted, from its own signed bulletin — a lane naming
    /// any other key is discarded rather than believed, so one of them cannot
    /// evict a client by claiming a conflict. Two bulletins is a real reboot.
    fn reported_key(&self, cid: ClientId) -> Option<[u8; sig::PUBKEY_LEN]> {
        let posted = self.bulletins.get(&cid)?;
        (posted.len() == 1).then(|| *posted.iter().next().expect("checked above"))
    }

    /// A boot key `cid` signed a bulletin under. Every lane reads these off
    /// ingress, so they are not a lane's word for anything.
    pub fn note_bulletin(&mut self, cid: ClientId, pk: [u8; sig::PUBKEY_LEN]) {
        self.bulletins.entry(cid).or_default().insert(pk);
    }

    /// Close the client window and open the relay: everything accepted so far
    /// goes out under this server's first chain signature.
    pub fn originate(&mut self, sid: &SessionId) -> Vec<Relay> {
        self.relaying = true;
        // Its own row is part of the matrix it will finalize over, and marking
        // it accepted stops a peer's echo coming back around.
        let own = self.batch(sid);
        self.batches.insert(self.server_id, own.clone());
        let mut items = vec![RelayItem::Batch(own)];
        for held in self.fragments.values() {
            items.extend(held.values().cloned().map(RelayItem::Fragment));
        }
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let hash = item.hash(sid);
            self.accepted.insert(hash);
            let sig = self.signer.sign(&relay_signing_bytes(sid, &hash));
            out.push(Relay {
                item,
                chain: vec![(self.server_id, sig)],
            });
        }
        out
    }

    /// One Dolev–Strong round, processed as a batch with the receipt batches
    /// ahead of the fragments so a fragment never waits on the matrix that
    /// names its key. An item is accepted iff it validates and its chain holds
    /// at least `round` distinct valid server signatures; fresh acceptances come
    /// back chain-extended for the next round. Rejection is stateless — a copy
    /// that fails here never poisons the item for a later one.
    pub fn absorb(&mut self, sid: &SessionId, round: usize, incoming: &[Relay]) -> Vec<Relay> {
        let (batches, fragments): (Vec<&Relay>, Vec<&Relay>) = incoming
            .iter()
            .partition(|r| matches!(r.item, RelayItem::Batch(_)));
        let mut out = Vec::new();
        for r in batches.into_iter().chain(fragments) {
            let hash = r.item.hash(sid);
            if self.accepted.contains(&hash) || self.chain_len(sid, &hash, &r.chain) < round {
                continue;
            }
            match &r.item {
                RelayItem::Batch(b) => {
                    if self.accept_batch(sid, b) {
                        self.accepted.insert(hash);
                    }
                }
                RelayItem::Fragment(f) => {
                    self.accept_fragments(sid, std::slice::from_ref(f));
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

        // Every client any lane reported, in id order so the budget below is
        // spent identically everywhere.
        let mut clients: Vec<ClientId> = self
            .batches
            .values()
            .flat_map(|b| b.receipts.iter().map(|r| r.client_id))
            .collect();
        clients.sort_unstable();
        clients.dedup();

        // Lanes already unable to serve someone in the set. A lane short of one
        // member publishes nothing for anyone, so this is the round's budget.
        let mut abstaining: BTreeSet<usize> = BTreeSet::new();
        let mut rebuilt_for: BTreeMap<ClientId, Bundle> = BTreeMap::new();
        let mut admitted: Vec<(ClientId, Vec<usize>)> = Vec::new();

        for cid in clients {
            let Some(pk_c) = self.reported_key(cid) else {
                // Two bulletins is a reboot; none means no lane can serve it.
                if self.bulletins.get(&cid).is_some_and(|p| p.len() > 1) {
                    out.conflicted.push(cid);
                }
                out.excluded.push(cid);
                continue;
            };
            let covered = self.covered(cid, &pk_c);
            let missing: Vec<usize> = (0..self.n_lanes).filter(|l| !covered.contains(l)).collect();
            if missing.is_empty() {
                admitted.push((cid, Vec::new()));
                continue;
            }
            match self.rebuild(pp, sid, cid, &pk_c, &covered, &missing) {
                Some(bundles) => {
                    if let Some(mine) = bundles.into_iter().find(|b| b.lane == me) {
                        rebuilt_for.insert(cid, mine);
                    }
                    admitted.push((cid, Vec::new()));
                }
                // Unrepaired: the lanes without it must sit the round out, and
                // only so many can.
                None => {
                    let mut cost = abstaining.clone();
                    cost.extend(missing.iter().copied());
                    if cost.len() <= self.n_lanes - self.k {
                        abstaining = cost;
                        admitted.push((cid, missing));
                    } else {
                        out.excluded.push(cid);
                    }
                }
            }
        }

        for (cid, unrepaired) in admitted {
            out.set.push(cid);
            let bundle = match rebuilt_for.remove(&cid) {
                Some(b) => {
                    out.repaired.push(cid);
                    Some(b)
                }
                None => self.own_bundle(cid),
            };
            // No bundle means this lane is one of `unrepaired`'s abstainers, or
            // could not open what it holds; either way it contributes nothing
            // and the publication path will defer.
            let Some(b) = bundle else {
                debug_assert!(unrepaired.contains(&me) || !unrepaired.is_empty());
                continue;
            };
            if let Some(opening) = unseal_opening(key, sid, cid, self.server_id, &b.envelope) {
                out.inbox.items.push((cid, opening));
            }
            out.lane_inbox.items.push((cid, b.share, b.path));
        }
        out
    }

    /// Lanes that reported `cid` under the key it actually posted, sorted.
    fn covered(&self, cid: ClientId, pk_c: &[u8; sig::PUBKEY_LEN]) -> Vec<usize> {
        let mut lanes: Vec<usize> = self
            .batches
            .values()
            .filter(|b| {
                b.receipts
                    .iter()
                    .any(|r| r.client_id == cid && r.pk_c == *pk_c)
            })
            .map(|b| b.server_id.0 as usize)
            .collect();
        lanes.sort_unstable();
        lanes
    }

    /// The bundle this lane holds for `cid`, matching the hash it reported.
    fn own_bundle(&self, cid: ClientId) -> Option<Bundle> {
        let hash = self
            .batches
            .get(&self.server_id)?
            .receipts
            .iter()
            .find(|r| r.client_id == cid)?
            .bundle_hash;
        self.held.get(&cid)?.get(&hash).cloned()
    }

    /// Reconstruct the lanes no one reported; each rebuilt bundle must verify
    /// under the key the matrix agreed on. Sample selection is `BTreeMap` order,
    /// first k — deterministic over an agreed fragment set, so every server
    /// decodes the same blob. Trailing padding is ignored: each bundle is
    /// fixed-width under `scp`, so `unpack` reads exactly what it needs.
    fn rebuild(
        &self,
        pp: &ProtocolParams,
        sid: &SessionId,
        cid: ClientId,
        pk_c: &[u8; sig::PUBKEY_LEN],
        covered: &[usize],
        missing: &[usize],
    ) -> Option<Vec<Bundle>> {
        if covered.len() < self.n_lanes - self.k {
            return None;
        }
        let params = fragment_params(pp);
        let held = self.fragments.get(&cid)?;
        if held.len() < params.k {
            return None;
        }
        let samples: Vec<(usize, &[DgtNTTPoly])> = held
            .values()
            .map(|f| (f.idx, f.data.as_slice()))
            .take(params.k)
            .collect();
        let n_polys = params.k * samples.first()?.1.len();
        let recovered = Rs::reconstruct(&params, n_polys, &samples).ok()?;
        let blob = polys_to_blob(&recovered, recovered.len() * N * BYTES_PER_COEFF);

        let scp = pp.share_comm.as_ref()?;
        let mut out = Vec::with_capacity(missing.len());
        let mut at = 0;
        for &lane in missing {
            let (b, used) = Bundle::unpack(scp, cid, blob.get(at..)?)?;
            if b.lane != lane || b.pubkey != *pk_c || !b.verify(sid, self.n_lanes) {
                return None;
            }
            at += used;
            out.push(b);
        }
        Some(out)
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
