//! Canonical client-set selection end-to-end: receipts on delivery, evidence
//! packages that route around withheld receipts, unanimous verdicts on
//! malicious clients, and a loud halt — never an exclusion — past `n − k`
//! censoring servers.

use chipmunk_code::{KahePoly, N};
use panetiere::bulletin::{RsClientBulletinEntry, RsNodeBulletinEntry, ServerBulletinEntry};
use panetiere::kahe::T_MODULUS_DEFAULT;
use panetiere::pke;
use anymone_core::client_set::{
    build_evidence, fragment_signing_bytes, plurality_set, relay_rounds, relay_signing_bytes,
    run_client_round_set, Certificate, ClientSetRound, Evidence, Fragment, Relay, RelayItem,
    SetRound, SetServer,
};
use panetiere::protocol::server::{run_rs_node_round, run_server_round};
use panetiere::protocol::verify::{aggregate_and_decrypt_rs, VerifyError};
use panetiere::protocol::{ClientId, ProtocolParams, ServerId, SessionId};
use panetiere::sig::{self, SigningKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

const SESSION: SessionId = SessionId([0x91; 32]);
/// Servers, each also a lane — the bundle carries both duties.
const S: usize = 8;
/// k = t: two censors absorbed, three halt the round.
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
        let server_keys: Vec<pke::PrivateKey> =
            (0..s).map(|_| pke::PrivateKey::generate(&mut rng)).collect();
        let server_sig: Vec<SigningKey> = (0..s).map(|_| SigningKey::generate(&mut rng)).collect();
        let servers: Vec<(ServerId, pke::PublicKey)> = (0..s)
            .map(|i| (ServerId(i as u32), server_keys[i].public()))
            .collect();

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

    fn servers(&self) -> Vec<SetServer> {
        let pks: Vec<sig::VerifyingKey> =
            self.server_sig.iter().map(|k| k.verifying_key()).collect();
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

    /// One full formation: delivery with per-lane receipt withholding, evidence
    /// from every opted-in client to its certifiers, the relay rounds, then
    /// set fixing at the publishing servers.
    fn run_round(
        &self,
        deliver: impl Fn(ClientId, usize) -> bool,
        withhold_cert: impl Fn(ClientId, usize) -> bool,
        with_evidence: impl Fn(ClientId) -> bool,
        publishes: &[bool],
    ) -> Vec<Option<SetRound>> {
        assert_eq!(publishes.len(), self.s);
        let mut servers = self.servers();
        let certs = self.deliver(&mut servers, deliver, withhold_cert);

        for (i, r) in self.rounds.iter().enumerate() {
            if !with_evidence(r.client_id) {
                continue;
            }
            let (e, frags) =
                build_evidence(&self.pp, &SESSION, r, certs[i].clone(), &self.client_sig[i]);
            for (fi, c) in e.certs.iter().enumerate() {
                let own = frags.get(fi).map(|f| vec![f.clone()]).unwrap_or_default();
                assert!(servers[c.server_id.0 as usize].submit(&SESSION, &e, &own));
            }
        }

        relay_all(&mut servers, &self.pp);

        servers
            .iter()
            .enumerate()
            .map(|(j, s)| publishes[j].then(|| s.finalize(&self.pp, &self.server_keys[j], &SESSION)))
            .collect()
    }

    fn deliver(
        &self,
        servers: &mut [SetServer],
        deliver: impl Fn(ClientId, usize) -> bool,
        withhold_cert: impl Fn(ClientId, usize) -> bool,
    ) -> Vec<Vec<Certificate>> {
        let mut certs: Vec<Vec<Certificate>> = vec![Vec::new(); self.rho];
        for r in &self.rounds {
            for lane in 0..self.s {
                if !deliver(r.client_id, lane) {
                    continue;
                }
                let cert = servers[lane]
                    .receive(&SESSION, &r.bundles[lane])
                    .expect("valid bundle");
                if !withhold_cert(r.client_id, lane) {
                    certs[r.client_id.0 as usize].push(cert);
                }
            }
        }
        certs
    }

    fn publish(&self, sets: &[SetRound]) -> (Vec<ServerBulletinEntry>, Vec<RsNodeBulletinEntry>) {
        let servers = sets
            .iter()
            .map(|sr| run_server_round(&sr.inbox, &sr.set).expect("openings for the set"))
            .collect();
        let lanes = sets
            .iter()
            .map(|sr| run_rs_node_round(&sr.lane_inbox, &sr.set).expect("shares for the set"))
            .collect();
        (servers, lanes)
    }

    /// Anchor on the plurality set, keep only what was published over it, decode.
    fn recover(&self, sets: &[SetRound]) -> Result<(Vec<ClientId>, Vec<KahePoly>), VerifyError> {
        let (servers, lanes) = self.publish(sets);
        let anchor = plurality_set(&servers);
        let agreeing: Vec<ServerBulletinEntry> = servers
            .into_iter()
            .filter(|sp| sp.clients == anchor)
            .collect();
        let agreeing_lanes: Vec<RsNodeBulletinEntry> =
            lanes.into_iter().filter(|np| np.clients == anchor).collect();
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

    fn recover_published(
        &self,
        sets: Vec<Option<SetRound>>,
    ) -> (Vec<SetRound>, Result<(Vec<ClientId>, Vec<KahePoly>), VerifyError>) {
        let published: Vec<SetRound> = sets.into_iter().flatten().collect();
        let out = self.recover(&published);
        (published, out)
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

    fn without(&self, c: ClientId) -> Vec<ClientId> {
        self.all_clients().into_iter().filter(|x| *x != c).collect()
    }
}

const ALL: [bool; S] = [true; S];
const EVERY: fn(ClientId, usize) -> bool = |_, _| true;
const NONE: fn(ClientId, usize) -> bool = |_, _| false;

/// The full Dolev–Strong schedule: every server's fresh acceptances go to
/// every other server in the next round.
fn relay_all(servers: &mut [SetServer], pp: &ProtocolParams) {
    let mut pending: Vec<Vec<Relay>> = servers.iter_mut().map(|s| s.echo(&SESSION)).collect();
    for round in 1..=relay_rounds(pp) {
        pending = servers
            .iter_mut()
            .enumerate()
            .map(|(j, s)| {
                let incoming: Vec<Relay> = pending
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != j)
                    .flat_map(|(_, batch)| batch.iter().cloned())
                    .collect();
                s.absorb(&SESSION, round, &incoming)
            })
            .collect();
    }
}

/// `(r, s) → (r, n − s)`: the other valid ECDSA signature for the same bytes.
fn flip_s(sig: &[u8; 64]) -> [u8; 64] {
    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];
    let mut out = *sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = ORDER[i] as i16 - out[32 + i] as i16 - borrow;
        borrow = i16::from(d < 0);
        out[32 + i] = (d + 256 * borrow) as u8;
    }
    out
}

#[test]
fn happy_path_recovers_the_sum_over_every_client() {
    let r = Round::build();
    let sets = r.run_round(EVERY, NONE, |_| true, &ALL);
    for sr in sets.iter().flatten() {
        assert_eq!(sr.set, r.all_clients());
        assert!(sr.repaired.is_empty(), "nothing to repair");
        assert!(sr.excluded.is_empty());
    }
    let (_, out) = r.recover_published(sets);
    let (anchor, plain) = out.expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// Withholding the receipt achieves nothing: the victim codes the silent lane
/// to its certifiers, every server — the censor included — can rebuild it, and
/// the round completes with the victim in whether the censor publishes or not.
#[test]
fn a_censored_client_routes_around_the_censor() {
    let r = Round::build();
    let victim = ClientId(5);
    let censor = S - 1;
    let withhold = |c: ClientId, lane: usize| c == victim && lane == censor;

    let sets = r.run_round(EVERY, withhold, |_| true, &ALL);
    for (j, sr) in sets.iter().flatten().enumerate() {
        assert_eq!(sr.set, r.all_clients(), "server {j}");
        let expect = if j == censor { vec![victim] } else { vec![] };
        assert_eq!(sr.repaired, expect, "server {j}");
    }
    let (_, out) = r.recover_published(sets);
    let (anchor, plain) = out.expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));

    // The censor abstaining changes the server count, not the set.
    let mut publishes = ALL;
    publishes[censor] = false;
    let sets = r.run_round(EVERY, withhold, |_| true, &publishes);
    let (published, out) = r.recover_published(sets);
    assert_eq!(published.len(), S - 1);
    let (anchor, _) = out.expect("recover");
    assert!(anchor.contains(&victim));
}

/// No evidence, no membership: bundles alone don't admit, so a client that
/// skips the package is excluded by every server and the round proceeds.
#[test]
fn a_client_without_evidence_is_excluded_unanimously() {
    let r = Round::build();
    let rogue = ClientId(3);
    let sets = r.run_round(EVERY, NONE, |c| c != rogue, &ALL);
    for (j, sr) in sets.iter().flatten().enumerate() {
        assert_eq!(sr.set, r.without(rogue), "server {j}");
        assert_eq!(sr.excluded, vec![rogue], "server {j}");
    }
    let (_, out) = r.recover_published(sets);
    let (anchor, plain) = out.expect("the round proceeds");
    assert_eq!(anchor, r.without(rogue));
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// A client claiming censorship that never happened: it skips a server,
/// codes the "missing" lane, and is included — the skipped server rebuilds its
/// bundle from the fragments and serves. False accusations are free and inert.
#[test]
fn a_false_censorship_claim_changes_nothing() {
    let r = Round::build();
    let rogue = ClientId(3);
    let skipped = 3usize;
    let sets = r.run_round(
        |c, lane| !(c == rogue && lane == skipped),
        NONE,
        |_| true,
        &ALL,
    );
    for (j, sr) in sets.iter().flatten().enumerate() {
        assert_eq!(sr.set, r.all_clients(), "server {j}");
        let expect = if j == skipped { vec![rogue] } else { vec![] };
        assert_eq!(sr.repaired, expect, "server {j}");
    }
    let (_, out) = r.recover_published(sets);
    let (anchor, plain) = out.expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// Complete evidence makes any delivery pattern servable: a client feeding
/// only `t` servers is still included by all, the unfed servers rebuilding
/// their bundles from the coded lanes.
#[test]
fn skipping_many_lanes_still_includes_and_serves() {
    let r = Round::build();
    let rogue = ClientId(3);
    let fed = r.pp.shamir.t;
    let sets = r.run_round(|c, lane| c != rogue || lane < fed, NONE, |_| true, &ALL);
    for (j, sr) in sets.iter().flatten().enumerate() {
        assert_eq!(sr.set, r.all_clients(), "server {j}");
        let expect = if j >= fed { vec![rogue] } else { vec![] };
        assert_eq!(sr.repaired, expect, "server {j}");
    }
    let (_, out) = r.recover_published(sets);
    let (anchor, plain) = out.expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// Evidence whose coded lanes rebuild into garbage is rejected by every
/// server, not just the ones that needed the data — every server rebuilds and
/// checks whenever a lane is coded.
#[test]
fn a_garbage_blob_is_excluded_unanimously() {
    let r = Round::build();
    let rogue = ClientId(3);
    let skipped = 3usize;

    let mut servers = r.servers();
    let certs = r.deliver(
        &mut servers,
        |c, lane| !(c == rogue && lane == skipped),
        NONE,
    );

    for (i, cr) in r.rounds.iter().enumerate() {
        let round = if cr.client_id == rogue {
            // The coded copy of the skipped bundle is corrupted; its signature
            // inside the blob no longer verifies.
            let mut bundles = cr.bundles.clone();
            bundles[skipped].envelope[0] ^= 1;
            &ClientSetRound {
                client_id: cr.client_id,
                bulletin: cr.bulletin.clone(),
                bundles,
            }
        } else {
            cr
        };
        let (e, frags) =
            build_evidence(&r.pp, &SESSION, round, certs[i].clone(), &r.client_sig[i]);
        for (fi, c) in e.certs.iter().enumerate() {
            let own = frags.get(fi).map(|f| vec![f.clone()]).unwrap_or_default();
            assert!(servers[c.server_id.0 as usize].submit(&SESSION, &e, &own));
        }
    }
    relay_all(&mut servers, &r.pp);

    let sets: Vec<SetRound> = servers
        .iter()
        .enumerate()
        .map(|(j, s)| s.finalize(&r.pp, &r.server_keys[j], &SESSION))
        .collect();
    for (j, sr) in sets.iter().enumerate() {
        assert_eq!(sr.set, r.without(rogue), "server {j}");
        assert_eq!(sr.excluded, vec![rogue], "server {j}");
    }
    let (anchor, plain) = r.recover(&sets).expect("the round proceeds");
    assert_eq!(anchor, r.without(rogue));
    assert_eq!(plain, r.expected_sum(&anchor));
}

#[test]
fn receipts_and_evidence_reject_forgery() {
    let r = Round::build();
    let mut servers = r.servers();
    let good = &r.rounds[0].bundles[0];

    let mut tampered = good.clone();
    tampered.envelope[0] ^= 1;
    assert!(servers[0].receive(&SESSION, &tampered).is_none());

    let wrong_lane = &r.rounds[0].bundles[1];
    assert!(servers[0].receive(&SESSION, wrong_lane).is_none());

    assert!(servers[0].receive(&SessionId([0x00; 32]), good).is_none());

    let certs: Vec<Certificate> = (0..S)
        .map(|j| {
            servers[j]
                .receive(&SESSION, &r.rounds[0].bundles[j])
                .expect("valid bundle")
        })
        .collect();
    let (e, frags) = build_evidence(&r.pp, &SESSION, &r.rounds[0], certs, &r.client_sig[0]);
    assert!(frags.is_empty(), "nothing withheld, nothing coded");

    // A certificate reassigned to another server fails its signature check.
    let mut forged = e.clone();
    forged.certs[1].server_id = ServerId(2);
    assert!(!servers[0].submit(&SESSION, &forged, &[]));

    // Evidence that does not cover every lane is rejected outright.
    let mut short = e.clone();
    short.certs.pop();
    assert!(!servers[0].submit(&SESSION, &short, &[]));

    assert!(servers[0].submit(&SESSION, &e, &frags));

    // ECDSA malleability mints no second package: the flipped signature is
    // the same identity, so it dedupes instead of counting as equivocation.
    let mut malleated = e.clone();
    malleated.sig = flip_s(&e.sig);
    assert_eq!(malleated.identity(&SESSION), e.identity(&SESSION));
    assert!(servers[0].submit(&SESSION, &malleated, &[]));
    let sr = servers[0].finalize(&r.pp, &r.server_keys[0], &SESSION);
    assert!(sr.conflicted.is_empty());
    assert_eq!(sr.set, vec![ClientId(0)]);
}

/// Two censors — the full `n − k` budget — abstain after withholding
/// receipts: the round still completes and still includes their victims.
#[test]
fn censors_at_the_budget_cost_only_themselves() {
    let r = Round::build();
    let censors = [S - 2, S - 1];
    let mut publishes = ALL;
    for j in censors {
        publishes[j] = false;
    }
    let sets = r.run_round(
        EVERY,
        |c, lane| censors.contains(&lane) && c == ClientId(lane as u32 - 2),
        |_| true,
        &publishes,
    );
    let (published, out) = r.recover_published(sets);
    assert_eq!(published.len(), r.pp.shamir.t, "exactly the threshold remains");
    let (anchor, plain) = out.expect("recover");
    assert_eq!(anchor, r.all_clients());
    assert_eq!(plain, r.expected_sum(&anchor));
}

/// Past the budget the failure is a loud halt: three abstaining censors leave
/// fewer than `t` shares and `k` lanes. The victim is still in every honest
/// set — exclusion is never the outcome.
#[test]
fn three_censoring_servers_halt_the_round() {
    let r = Round::build();
    let victim = ClientId(4);
    let censors = [S - 3, S - 2, S - 1];
    let mut publishes = ALL;
    for j in censors {
        publishes[j] = false;
    }
    let sets = r.run_round(
        EVERY,
        |c, lane| censors.contains(&lane) && c == victim,
        |_| true,
        &publishes,
    );
    for sr in sets.iter().flatten() {
        assert_eq!(sr.set, r.all_clients());
        assert!(sr.set.contains(&victim));
    }
    let (published, out) = r.recover_published(sets);
    assert!(published.len() < r.pp.shamir.t);
    assert_eq!(out, Err(VerifyError::BadServerCoverage));
}

/// The paper numbers: at 14-of-16 two censors are absorbed, three halt.
#[test]
fn the_budget_at_14_of_16_is_two_censors() {
    let r = Round::build_dims(16, 14, 6);
    assert_eq!(r.pp.shamir.t, 14);
    let victim = ClientId(2);

    let mut publishes = vec![true; 16];
    publishes[14] = false;
    publishes[15] = false;
    let sets = r.run_round(
        |_, _| true,
        |c, lane| lane >= 14 && c == victim,
        |_| true,
        &publishes,
    );
    let (published, out) = r.recover_published(sets);
    assert_eq!(published.len(), 14);
    let (anchor, plain) = out.expect("two censors are absorbed");
    assert!(anchor.contains(&victim));
    assert_eq!(plain, r.expected_sum(&anchor));

    let mut publishes = vec![true; 16];
    for j in 13..16 {
        publishes[j] = false;
    }
    let sets = r.run_round(
        |_, _| true,
        |c, lane| lane >= 13 && c == victim,
        |_| true,
        &publishes,
    );
    for sr in sets.iter().flatten() {
        assert!(sr.set.contains(&victim), "the victim is never excluded");
    }
    let (published, out) = r.recover_published(sets);
    assert!(published.len() < r.pp.shamir.t);
    assert_eq!(out, Err(VerifyError::BadServerCoverage));
}

/// The relay closes every delivery-timing and double-boot hole: a package
/// handed to a single server before the cutoff lands everywhere, one injected
/// in the last round with a short chain lands nowhere, a host that boots twice
/// and finishes two packages is a conflict everywhere, and a package mixing
/// two boots' certificates cannot even be formed.
#[test]
fn relay_agrees_on_late_and_equivocating_packages() {
    let r = Round::build();
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let lone = ClientId(2);
    let late = ClientId(5);
    let twice = ClientId(4);

    let mut servers = r.servers();
    let certs = r.deliver(&mut servers, EVERY, NONE);

    // Second boot of `twice`: fresh key, fresh bundles, full cert set.
    let roster: Vec<(ServerId, pke::PublicKey)> = (0..r.s)
        .map(|j| (ServerId(j as u32), r.server_keys[j].public()))
        .collect();
    let sk2 = SigningKey::generate(&mut rng);
    let boot2 = run_client_round_set(
        &mut rng,
        &r.pp,
        &SESSION,
        twice,
        r.messages[twice.0 as usize].clone(),
        &roster,
        &sk2,
    );
    let certs2: Vec<Certificate> = (0..r.s)
        .map(|j| {
            servers[j]
                .receive(&SESSION, &boot2.bundles[j])
                .expect("valid bundle")
        })
        .collect();

    // Certificates sign the boot key, so a mixed-run package dies on arrival.
    let mut mixed = certs[twice.0 as usize].clone();
    mixed.splice(..r.s / 2, certs2[..r.s / 2].iter().cloned());
    let (bad, _) = build_evidence(&r.pp, &SESSION, &boot2, mixed, &sk2);
    assert!(!servers[0].submit(&SESSION, &bad, &[]));

    let (e2, _) = build_evidence(&r.pp, &SESSION, &boot2, certs2, &sk2);
    let mut late_package: Option<Evidence> = None;
    for (i, cr) in r.rounds.iter().enumerate() {
        let (e, frags) = build_evidence(&r.pp, &SESSION, cr, certs[i].clone(), &r.client_sig[i]);
        assert!(frags.is_empty());
        if cr.client_id == lone {
            assert!(servers[0].submit(&SESSION, &e, &[]));
        } else if cr.client_id == late {
            late_package = Some(e);
        } else if cr.client_id == twice {
            for j in 0..r.s / 2 {
                assert!(servers[j].submit(&SESSION, &e, &[]));
            }
            for j in r.s / 2..r.s {
                assert!(servers[j].submit(&SESSION, &e2, &[]));
            }
        } else {
            for c in &e.certs {
                assert!(servers[c.server_id.0 as usize].submit(&SESSION, &e, &[]));
            }
        }
    }

    // Manual schedule so the final round can carry the injection: one
    // colluding signature is far short of the required chain.
    let rounds = relay_rounds(&r.pp);
    let mut pending: Vec<Vec<Relay>> = servers.iter_mut().map(|s| s.echo(&SESSION)).collect();
    for round in 1..=rounds {
        let inject = (round == rounds).then(|| {
            let e = late_package.clone().expect("held back above");
            let sig = r.server_sig[r.s - 1]
                .sign(&relay_signing_bytes(&SESSION, &e.identity(&SESSION)));
            Relay {
                item: RelayItem::Evidence(e),
                chain: vec![(ServerId((r.s - 1) as u32), sig)],
            }
        });
        pending = servers
            .iter_mut()
            .enumerate()
            .map(|(j, s)| {
                let mut incoming: Vec<Relay> = pending
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != j)
                    .flat_map(|(_, batch)| batch.iter().cloned())
                    .collect();
                if j < r.s / 2 {
                    incoming.extend(inject.iter().cloned());
                }
                s.absorb(&SESSION, round, &incoming)
            })
            .collect();
    }

    let expected: Vec<ClientId> = r
        .all_clients()
        .into_iter()
        .filter(|c| *c != late && *c != twice)
        .collect();
    for (j, s) in servers.iter().enumerate() {
        let sr = s.finalize(&r.pp, &r.server_keys[j], &SESSION);
        assert_eq!(sr.set, expected, "server {j}");
        assert!(sr.excluded.contains(&late), "server {j}");
        assert_eq!(sr.conflicted, vec![twice], "server {j}");
    }
}

/// The fragment pool is part of the agreement: a quorum reached anywhere
/// reaches everyone, a quorum short anywhere is short everywhere, and a
/// correctly signed fragment with a fabricated index never counts toward it.
#[test]
fn fragment_quorum_is_agreed_and_bounded() {
    let r = Round::build();
    let claimant = ClientId(3);
    let skipped = [r.s - 2, r.s - 1];
    let deliver = |c: ClientId, lane: usize| !(c == claimant && skipped.contains(&lane));

    for (keep, included) in [(1usize, false), (2, true)] {
        let mut servers = r.servers();
        let certs = r.deliver(&mut servers, deliver, NONE);
        for (i, cr) in r.rounds.iter().enumerate() {
            let (e, frags) =
                build_evidence(&r.pp, &SESSION, cr, certs[i].clone(), &r.client_sig[i]);
            if cr.client_id == claimant {
                let mut give: Vec<Fragment> = frags[..keep].to_vec();
                let data = frags[0].data.clone();
                let sig = r.client_sig[i]
                    .sign(&fragment_signing_bytes(&SESSION, claimant, 99, &data));
                give.push(Fragment {
                    client_id: claimant,
                    idx: 99,
                    data,
                    sig,
                });
                assert!(servers[e.certs[0].server_id.0 as usize].submit(&SESSION, &e, &give));
            } else {
                for (fi, c) in e.certs.iter().enumerate() {
                    let own = frags.get(fi).map(|f| vec![f.clone()]).unwrap_or_default();
                    assert!(servers[c.server_id.0 as usize].submit(&SESSION, &e, &own));
                }
            }
        }
        relay_all(&mut servers, &r.pp);
        for (j, s) in servers.iter().enumerate() {
            let sr = s.finalize(&r.pp, &r.server_keys[j], &SESSION);
            assert_eq!(
                sr.set.contains(&claimant),
                included,
                "server {j}, {keep} fragments"
            );
            if included && skipped.contains(&j) {
                assert_eq!(sr.repaired, vec![claimant], "server {j}");
            }
        }
    }
}

#[test]
fn plurality_prefers_the_most_published_then_the_larger_set() {
    let r = Round::build();
    let sets: Vec<SetRound> = r
        .run_round(EVERY, NONE, |_| true, &ALL)
        .into_iter()
        .flatten()
        .collect();
    let (mut servers, _) = r.publish(&sets);
    let full = r.all_clients();
    let short: Vec<ClientId> = full.iter().copied().take(RHO - 1).collect();

    servers[0].clients = short.clone();
    assert_eq!(plurality_set(&servers), full, "7 votes beat 1");

    for s in servers.iter_mut().take(4) {
        s.clients = short.clone();
    }
    assert_eq!(plurality_set(&servers), full, "a 4–4 tie goes to the larger");

    servers[4].clients = short.clone();
    assert_eq!(plurality_set(&servers), short, "5 votes the other way");
}
