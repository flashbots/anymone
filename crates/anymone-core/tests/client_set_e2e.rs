//! Canonical client-set selection end to end: lanes publish what they took,
//! Dolev–Strong agrees the matrix, and every honest lane fixes the same set —
//! absorbing small gaps as abstentions, repairing large ones from fragments,
//! and excluding a host that booted twice.

use anymone_core::client_set::{
    batch_signing_bytes, build_fragments, plurality_set, relay_rounds, run_client_round_set,
    ClientSetRound, ReceiptBatch, Relay, RelayItem, SetRound, SetServer,
};
use panetiere::bulletin::{RsClientBulletinEntry, RsNodeBulletinEntry, ServerBulletinEntry};
use panetiere::kahe::T_MODULUS_DEFAULT;
use panetiere::pke;
use panetiere::protocol::server::{run_rs_node_round, run_server_round};
use panetiere::protocol::verify::{aggregate_and_decrypt_rs, VerifyError};
use panetiere::protocol::{ClientId, ProtocolParams, ServerId, SessionId};
use panetiere::sig::{self, SigningKey};
use panetiere::{HVCPoly, KahePoly, N};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SESSION: SessionId = SessionId([0x91; 32]);
/// Servers, each also a lane — the bundle carries both duties.
const S: usize = 8;
/// k = t: two lanes may abstain, three halt the round.
const K: usize = 6;
const RHO: usize = 8;
const PAYLOAD_POLYS: usize = 4;
const RHO_MAX: usize = 32;

fn rand_message_poly<R: Rng>(rng: &mut R, t: u64) -> KahePoly {
    let half = t as i64 / 2;
    let mut coeffs = [0i64; N];
    for c in coeffs.iter_mut() {
        *c = rng.gen_range(0..t) as i64 - half;
    }
    KahePoly::from_coeffs(coeffs)
}

fn reduce_centered_mod_t(poly: KahePoly, t: u64) -> KahePoly {
    let mut p = poly;
    p.normalize();
    let t_i = t as i64;
    let half = t_i / 2;
    let mut coeffs = [0i64; N];
    for (out, &c) in coeffs.iter_mut().zip(p.coeffs().iter()) {
        let r = c.rem_euclid(t_i);
        *out = if r >= half { r - t_i } else { r };
    }
    KahePoly::from_coeffs(coeffs)
}

struct Round {
    pp: ProtocolParams,
    server_keys: Vec<pke::PrivateKey>,
    server_sig: Vec<SigningKey>,
    client_sig: Vec<SigningKey>,
    rounds: Vec<ClientSetRound>,
    entries: Vec<(ClientId, RsClientBulletinEntry)>,
    messages: Vec<Vec<KahePoly>>,
    s: usize,
    rho: usize,
}

/// One client's outcome across every publishing lane.
struct Outcome {
    sets: Vec<Option<SetRound>>,
}

impl Outcome {
    fn published(&self) -> impl Iterator<Item = &SetRound> {
        self.sets.iter().flatten()
    }

    fn agreed_set(&self) -> Vec<ClientId> {
        let sets: Vec<&Vec<ClientId>> = self.published().map(|sr| &sr.set).collect();
        assert!(
            sets.windows(2).all(|w| w[0] == w[1]),
            "lanes disagreed on the set: {sets:?}"
        );
        sets.first().map(|s| (*s).clone()).unwrap_or_default()
    }
}

impl Round {
    fn build() -> Self {
        Self::build_dims(S, K, RHO)
    }

    fn build_dims(s: usize, k: usize, rho: usize) -> Self {
        let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
        let pp = ProtocolParams::setup_rs_mode(
            &mut rng,
            s,
            PAYLOAD_POLYS,
            k,
            s,
            T_MODULUS_DEFAULT,
            RHO_MAX,
            [0x42; 32],
        );
        let server_keys: Vec<pke::PrivateKey> = (0..s)
            .map(|_| pke::PrivateKey::generate(&mut rng))
            .collect();
        let server_sig: Vec<SigningKey> = (0..s).map(|_| SigningKey::generate(&mut rng)).collect();
        let servers = roster(&server_keys);

        let mut client_sig = Vec::with_capacity(rho);
        let mut rounds = Vec::with_capacity(rho);
        let mut entries = Vec::with_capacity(rho);
        let mut messages = Vec::with_capacity(rho);
        for i in 0..rho {
            let cid = ClientId(i as u32);
            let m: Vec<KahePoly> = (0..PAYLOAD_POLYS)
                .map(|_| rand_message_poly(&mut rng, pp.kahe.t_modulus))
                .collect();
            let sk = SigningKey::generate(&mut rng);
            let r = run_client_round_set(&mut rng, &pp, &SESSION, cid, m.clone(), &servers, &sk);
            client_sig.push(sk);
            entries.push((cid, r.bulletin.clone()));
            rounds.push(r);
            messages.push(m);
        }
        Round {
            pp,
            server_keys,
            server_sig,
            client_sig,
            rounds,
            entries,
            messages,
            s,
            rho,
        }
    }

    fn set_pks(&self) -> Vec<sig::VerifyingKey> {
        self.server_sig.iter().map(|k| k.verifying_key()).collect()
    }

    fn servers(&self) -> Vec<SetServer> {
        let pks = self.set_pks();
        (0..self.s)
            .map(|j| {
                SetServer::new(
                    &self.pp,
                    ServerId(j as u32),
                    self.server_sig[j].clone(),
                    pks.clone(),
                )
            })
            .collect()
    }

    /// One full formation on the real cadence: bundles, each lane's batch,
    /// client repair, then the Dolev–Strong rounds and set fixing.
    ///
    /// `deliver` decides whether a client's bundle reaches a lane — a lane that
    /// never takes it simply omits the client from its batch, which is exactly
    /// what a censoring lane does. `repairs` decides whether the client answers
    /// the gap with fragments.
    fn run_round(
        &self,
        deliver: impl Fn(ClientId, usize) -> bool,
        repairs: impl Fn(ClientId) -> bool,
        publishes: &[bool],
    ) -> Outcome {
        assert_eq!(publishes.len(), self.s);
        let mut servers = self.servers();
        self.deliver(&mut servers, deliver);
        let bus = self.exchange(&mut servers, repairs);
        self.settle(&mut servers, bus);
        Outcome {
            sets: servers
                .iter()
                .enumerate()
                .map(|(j, s)| {
                    publishes[j].then(|| s.finalize(&self.pp, &self.server_keys[j], &SESSION))
                })
                .collect(),
        }
    }

    fn deliver(&self, servers: &mut [SetServer], deliver: impl Fn(ClientId, usize) -> bool) {
        // Every lane reads every bulletin off ingress; the boot key comes from
        // there, never from a lane's word for it.
        for (cid, entry) in &self.entries {
            for s in servers.iter_mut() {
                s.note_bulletin(*cid, entry.pubkey);
            }
        }
        for r in &self.rounds {
            for lane in 0..self.s {
                if deliver(r.client_id, lane) {
                    assert!(
                        servers[lane].receive(&SESSION, &r.bundles[lane]),
                        "lane {lane} rejected a valid bundle"
                    );
                }
            }
        }
    }

    /// Publish every lane's batch, then let each client read the matrix off
    /// those batches and repair if a lane is missing. Returns the relay items
    /// waiting for the first Dolev–Strong round, tagged with their origin.
    fn exchange(
        &self,
        servers: &mut [SetServer],
        repairs: impl Fn(ClientId) -> bool,
    ) -> Vec<(usize, Relay)> {
        let batches: Vec<ReceiptBatch> = servers.iter().map(|s| s.batch(&SESSION)).collect();
        let mut bus: Vec<(usize, Relay)> = Vec::new();
        for (j, s) in servers.iter_mut().enumerate() {
            bus.extend(s.originate(&SESSION).into_iter().map(|r| (j, r)));
        }
        for (i, r) in self.rounds.iter().enumerate() {
            let covered = covered_lanes(&batches, r.client_id);
            if covered.len() == self.s || !repairs(r.client_id) {
                continue;
            }
            let frags = build_fragments(&self.pp, &SESSION, r, &covered, &self.client_sig[i]);
            for (lane, f) in covered.iter().zip(frags) {
                let out = servers[*lane].submit(&SESSION, std::slice::from_ref(&f));
                bus.extend(out.into_iter().map(|rel| (*lane, rel)));
            }
        }
        bus
    }

    /// `relay_rounds` exchanges, each delivering the previous round's fresh
    /// acceptances to every other lane.
    fn settle(&self, servers: &mut [SetServer], mut bus: Vec<(usize, Relay)>) {
        for round in 1..=relay_rounds(&self.pp) {
            let batch = std::mem::take(&mut bus);
            for (j, s) in servers.iter_mut().enumerate() {
                let incoming: Vec<Relay> = batch
                    .iter()
                    .filter(|(from, _)| *from != j)
                    .map(|(_, r)| r.clone())
                    .collect();
                bus.extend(
                    s.absorb(&SESSION, round, &incoming)
                        .into_iter()
                        .map(|r| (j, r)),
                );
            }
        }
    }

    fn publish(&self, sets: &[&SetRound]) -> (Vec<ServerBulletinEntry>, Vec<RsNodeBulletinEntry>) {
        let scp = self
            .pp
            .share_comm
            .as_ref()
            .expect("share-commitment params");
        let roots: Vec<(ClientId, HVCPoly)> = self
            .entries
            .iter()
            .map(|(cid, e)| (*cid, e.share_root))
            .collect();
        // A lane short of a canonical member publishes nothing at all — that is
        // the abstention the set rule budgets for, so it is skipped, not fatal.
        let servers = sets
            .iter()
            .filter_map(|sr| run_server_round(&sr.inbox, &sr.set).ok())
            .collect();
        let lanes = sets
            .iter()
            .filter_map(|sr| run_rs_node_round(scp, &sr.lane_inbox, &sr.set, &roots).ok())
            .collect();
        (servers, lanes)
    }

    fn recover(&self, sets: &[&SetRound]) -> Result<(Vec<ClientId>, Vec<KahePoly>), VerifyError> {
        let (servers, lanes) = self.publish(sets);
        let anchor = plurality_set(&servers);
        let agreeing: Vec<ServerBulletinEntry> = servers
            .into_iter()
            .filter(|sp| sp.clients == anchor)
            .collect();
        let agreeing_lanes: Vec<RsNodeBulletinEntry> = lanes
            .into_iter()
            .filter(|np| np.clients == anchor)
            .collect();
        aggregate_and_decrypt_rs(
            &self.pp,
            &SESSION,
            &anchor,
            &self.entries,
            &agreeing,
            &agreeing_lanes,
        )
        .map(|(plain, _)| (anchor, plain))
    }

    fn expected_sum(&self, set: &[ClientId]) -> Vec<KahePoly> {
        (0..PAYLOAD_POLYS)
            .map(|pos| {
                let acc = set.iter().fold(KahePoly::default(), |a, c| {
                    a + self.messages[c.0 as usize][pos]
                });
                reduce_centered_mod_t(acc, self.pp.kahe.t_modulus)
            })
            .collect()
    }

    fn all_clients(&self) -> Vec<ClientId> {
        (0..self.rho as u32).map(ClientId).collect()
    }
}

fn roster(keys: &[pke::PrivateKey]) -> Vec<(ServerId, pke::PublicKey)> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| (ServerId(i as u32), k.public()))
        .collect()
}

/// The lanes whose batch reports `cid`, sorted — the client's own view of the
/// matrix, identical to what every lane computes.
fn covered_lanes(batches: &[ReceiptBatch], cid: ClientId) -> Vec<usize> {
    let mut lanes: Vec<usize> = batches
        .iter()
        .filter(|b| b.receipts.iter().any(|r| r.client_id == cid))
        .map(|b| b.server_id.0 as usize)
        .collect();
    lanes.sort_unstable();
    lanes
}

const ALL: [bool; S] = [true; S];
const EVERY: fn(ClientId, usize) -> bool = |_, _| true;
const NEVER: fn(ClientId) -> bool = |_| false;
const ALWAYS: fn(ClientId) -> bool = |_| true;

#[test]
fn happy_path_recovers_the_sum_over_every_client() {
    let r = Round::build();
    let out = r.run_round(EVERY, NEVER, &ALL);
    for sr in out.published() {
        assert_eq!(sr.set, r.all_clients());
        assert!(sr.excluded.is_empty());
        assert!(sr.conflicted.is_empty());
        assert!(sr.repaired.is_empty(), "nothing to repair");
    }
    let published: Vec<&SetRound> = out.published().collect();
    let (anchor, plain) = r.recover(&published).expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// A gap inside the budget needs no repair at all: the victim stays in the set
/// and the lane that missed it simply abstains, costing only itself.
#[test]
fn a_gap_within_the_budget_is_absorbed() {
    let r = Round::build();
    let victim = ClientId(5);
    let blind = S - 1;
    let out = r.run_round(|c, lane| !(c == victim && lane == blind), NEVER, &ALL);

    assert_eq!(out.agreed_set(), r.all_clients(), "the victim stays in");
    for sr in out.published() {
        assert!(sr.repaired.is_empty(), "no fragments were sent");
    }
    let blind_lane = out.sets[blind].as_ref().expect("finalized");
    assert!(
        !blind_lane
            .lane_inbox
            .items
            .iter()
            .any(|(c, _, _)| *c == victim),
        "the blind lane cannot serve the victim, so it must abstain"
    );

    let published: Vec<&SetRound> = out.published().collect();
    let (anchor, plain) = r.recover(&published).expect("the round still recovers");
    assert!(anchor.contains(&victim));
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// Past the budget the client answers with fragments, and the lanes that never
/// took the bundle rebuild it rather than abstaining.
#[test]
fn a_gap_past_the_budget_is_repaired() {
    let r = Round::build();
    let victim = ClientId(3);
    let blind = [S - 3, S - 2, S - 1];
    let deliver = |c: ClientId, lane: usize| !(c == victim && blind.contains(&lane));

    let out = r.run_round(deliver, ALWAYS, &ALL);
    assert_eq!(out.agreed_set(), r.all_clients());
    for (j, sr) in out.sets.iter().enumerate() {
        let sr = sr.as_ref().expect("finalized");
        let expect = if blind.contains(&j) {
            vec![victim]
        } else {
            vec![]
        };
        assert_eq!(sr.repaired, expect, "lane {j}");
    }
    let published: Vec<&SetRound> = out.published().collect();
    let (anchor, plain) = r.recover(&published).expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));

    // Without the fragments the same gap exceeds what abstention can absorb.
    let bare = r.run_round(deliver, NEVER, &ALL);
    assert!(
        !bare.agreed_set().contains(&victim),
        "three blind lanes is past the budget; unrepaired the victim is out"
    );
}

/// Two boots of one host report different keys for the same client, and the
/// disagreement is visible in the matrix at every lane.
#[test]
fn a_double_boot_is_excluded_everywhere() {
    let r = Round::build();
    let twice = ClientId(2);
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let sk2 = SigningKey::generate(&mut rng);
    let boot2 = run_client_round_set(
        &mut rng,
        &r.pp,
        &SESSION,
        twice,
        r.messages[twice.0 as usize].clone(),
        &roster(&r.server_keys),
        &sk2,
    );

    let mut servers = r.servers();
    for (cid, entry) in &r.entries {
        for s in servers.iter_mut() {
            s.note_bulletin(*cid, entry.pubkey);
        }
    }
    // Both boots post a bulletin, which is what makes the reboot visible.
    for s in servers.iter_mut() {
        s.note_bulletin(twice, boot2.bulletin.pubkey);
    }
    // The first half of the lanes take boot one, the rest take boot two.
    for cr in &r.rounds {
        for lane in 0..S {
            if cr.client_id == twice && lane >= S / 2 {
                continue;
            }
            servers[lane].receive(&SESSION, &cr.bundles[lane]);
        }
    }
    for lane in S / 2..S {
        assert!(servers[lane].receive(&SESSION, &boot2.bundles[lane]));
    }
    let bus = r.exchange(&mut servers, NEVER);
    r.settle(&mut servers, bus);

    let expected: Vec<ClientId> = r
        .all_clients()
        .into_iter()
        .filter(|c| *c != twice)
        .collect();
    for (j, s) in servers.iter().enumerate() {
        let sr = s.finalize(&r.pp, &r.server_keys[j], &SESSION);
        assert_eq!(sr.set, expected, "lane {j}");
        assert_eq!(sr.conflicted, vec![twice], "lane {j}");
    }
}

/// A lane whose batch reaches only one peer is still agreed by everyone: the
/// peer forwards it chain-extended, and the remaining rounds carry it the rest
/// of the way.
#[test]
fn a_batch_reaching_one_lane_still_agrees() {
    let r = Round::build();
    let mut servers = r.servers();
    r.deliver(&mut servers, EVERY);

    let mut bus: Vec<(usize, Relay)> = Vec::new();
    for (j, s) in servers.iter_mut().enumerate() {
        bus.extend(s.originate(&SESSION).into_iter().map(|rel| (j, rel)));
    }
    for round in 1..=relay_rounds(&r.pp) {
        let batch = std::mem::take(&mut bus);
        for (j, s) in servers.iter_mut().enumerate() {
            let incoming: Vec<Relay> = batch
                .iter()
                .filter(|(from, _)| *from != j)
                // Lane 0's own broadcast is seen by lane 1 alone; every other
                // lane can only learn it from lane 1's forward next round.
                .filter(|(from, _)| !(round == 1 && *from == 0 && j != 1))
                .map(|(_, rel)| rel.clone())
                .collect();
            bus.extend(
                s.absorb(&SESSION, round, &incoming)
                    .into_iter()
                    .map(|rel| (j, rel)),
            );
        }
    }

    let sets: Vec<Vec<ClientId>> = servers
        .iter()
        .enumerate()
        .map(|(j, s)| s.finalize(&r.pp, &r.server_keys[j], &SESSION).set)
        .collect();
    assert!(
        sets.windows(2).all(|w| w[0] == w[1]),
        "a batch delivered to one lane must still reach every set: {sets:?}"
    );
    assert_eq!(sets[0], r.all_clients());
}

/// A lane that names a key its victim never posted is ignored, not believed:
/// the boot key comes from the client's own signed bulletin, so one lane cannot
/// manufacture a conflict and evict anyone.
#[test]
fn a_lane_naming_a_bogus_key_evicts_nobody() {
    let r = Round::build();
    let victim = ClientId(4);
    let liar = 0usize;
    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);
    let bogus = SigningKey::generate(&mut rng)
        .verifying_key()
        .to_sec1_bytes();

    let mut servers = r.servers();
    r.deliver(&mut servers, EVERY);

    let mut bus: Vec<(usize, Relay)> = Vec::new();
    for (j, s) in servers.iter_mut().enumerate() {
        for rel in s.originate(&SESSION) {
            // The liar swaps the victim's key in its own published batch.
            let rel = match (&rel.item, j == liar) {
                (RelayItem::Batch(b), true) => {
                    let mut forged = b.clone();
                    for receipt in forged.receipts.iter_mut() {
                        if receipt.client_id == victim {
                            receipt.pk_c = bogus;
                        }
                    }
                    forged.sig = r.server_sig[liar].sign(&batch_signing_bytes(
                        &SESSION,
                        forged.server_id,
                        &forged.receipts,
                    ));
                    Relay {
                        item: RelayItem::Batch(forged),
                        chain: rel.chain.clone(),
                    }
                }
                _ => rel,
            };
            bus.push((j, rel));
        }
    }
    r.settle(&mut servers, bus);

    for (j, s) in servers.iter().enumerate() {
        let sr = s.finalize(&r.pp, &r.server_keys[j], &SESSION);
        assert!(
            sr.conflicted.is_empty(),
            "lane {j} was talked into a conflict"
        );
        assert!(sr.set.contains(&victim), "lane {j} dropped the victim");
    }
}

#[test]
fn plurality_prefers_the_most_published_then_the_larger_set() {
    let r = Round::build();
    let out = r.run_round(EVERY, NEVER, &ALL);
    let published: Vec<&SetRound> = out.published().collect();
    let (mut servers, _) = r.publish(&published);
    let full = r.all_clients();
    let short: Vec<ClientId> = full.iter().copied().take(RHO - 1).collect();

    servers[0].clients = short.clone();
    assert_eq!(plurality_set(&servers), full, "7 votes beat 1");

    for s in servers.iter_mut().take(4) {
        s.clients = short.clone();
    }
    assert_eq!(
        plurality_set(&servers),
        full,
        "a 4–4 tie goes to the larger"
    );

    servers[4].clients = short.clone();
    assert_eq!(plurality_set(&servers), short, "5 votes the other way");
}
