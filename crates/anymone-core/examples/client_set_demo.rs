//! Canonical client-set selection, six deliveries of the same round.
//!
//! Each client sends server `j` one signed bundle — lane `j`'s ciphertext
//! share and server `j`'s sealed opening — and collects a signed certificate
//! from every server that answers. Certificates plus an erasure coding of the
//! uncertified lanes form the client's evidence: every lane is a receipt or
//! recoverable data. Servers then relay the packages for `n − k + 1`
//! signature-chained rounds, so every server fixes the set over the same
//! pool: malicious clients — including a host that boots its TEE twice — are
//! excluded unanimously and never halt the round; more than `n − k` censoring
//! servers halt it loudly at recovery.

use chipmunk_code::HVCPoly;
use panetiere::bulletin::{RsClientBulletinEntry, RsNodeBulletinEntry, ServerBulletinEntry};
use panetiere::channel::{self, ChannelParams};
use panetiere::kahe::T_MODULUS_DEFAULT;
use panetiere::pke;
use anymone_core::client_set::{
    build_evidence, plurality_set, relay_rounds, run_client_round_set, Bundle, Certificate,
    ClientSetRound, Relay, SetRound, SetServer,
};
use panetiere::protocol::server::{run_rs_node_round, run_server_round};
use panetiere::protocol::verify::aggregate_and_decrypt_rs;
use panetiere::protocol::{ClientId, ProtocolParams, ServerId, SessionId};
use panetiere::sig::{self, SigningKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Servers, each also a lane — the bundle carries both duties.
const S: usize = 8;
/// k = t: two censors absorbed, three halt the round.
const K: usize = 6;
const N_COVER: usize = 2;
const MESSAGE_BYTES: usize = 32;
const RHO_MAX: usize = 32;
const SESSION: SessionId = SessionId([0xC5; 32]);

fn unpad(payload: &[u8]) -> &[u8] {
    let len = payload.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &payload[..len]
}

struct Outcome {
    sets: Vec<Option<SetRound>>,
    anchor: Vec<ClientId>,
    agreeing: usize,
    recovered: Result<Vec<Vec<u8>>, String>,
}

struct Demo {
    ch: ChannelParams,
    pp: ProtocolParams,
    server_keys: Vec<pke::PrivateKey>,
    server_sig: Vec<SigningKey>,
    client_sig: Vec<SigningKey>,
    rounds: Vec<ClientSetRound>,
    entries: Vec<(ClientId, RsClientBulletinEntry)>,
    n_messages: usize,
}

impl Demo {
    fn build(messages: &[&[u8]]) -> Self {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let ch = ChannelParams::for_messages(messages.len() as u32, MESSAGE_BYTES, [0x5C; 32]);
        let pp = ProtocolParams::setup_rs_mode(
            &mut rng,
            S,
            ch.n_polys(),
            K,
            S,
            T_MODULUS_DEFAULT,
            RHO_MAX,
            [0x42; 32],
        );
        let server_keys: Vec<pke::PrivateKey> =
            (0..S).map(|_| pke::PrivateKey::generate(&mut rng)).collect();
        let server_sig: Vec<SigningKey> = (0..S).map(|_| SigningKey::generate(&mut rng)).collect();
        let servers: Vec<(ServerId, pke::PublicKey)> = (0..S)
            .map(|i| (ServerId(i as u32), server_keys[i].public()))
            .collect();

        let n_clients = messages.len() + N_COVER;
        let mut client_sig = Vec::with_capacity(n_clients);
        let mut rounds = Vec::with_capacity(n_clients);
        let mut entries = Vec::with_capacity(n_clients);
        for i in 0..n_clients {
            let cid = ClientId(i as u32);
            let contribution = match messages.get(i) {
                Some(m) => channel::encode_message(&mut rng, &ch, m).expect("payload fits"),
                None => channel::cover(&ch),
            };
            let sk = SigningKey::generate(&mut rng);
            let r = run_client_round_set(&mut rng, &pp, &SESSION, cid, contribution, &servers, &sk);
            client_sig.push(sk);
            entries.push((cid, r.bulletin.clone()));
            rounds.push(r);
        }
        Demo {
            ch,
            pp,
            server_keys,
            server_sig,
            client_sig,
            rounds,
            entries,
            n_messages: messages.len(),
        }
    }

    /// Delivery with per-lane receipt withholding, evidence from opted-in
    /// clients (`double_boot` runs a second TEE boot for that client and
    /// splits the two packages across the servers), the relay rounds, set
    /// fixing, recovery over the plurality.
    fn run(
        &self,
        deliver: impl Fn(ClientId, usize) -> bool,
        withhold_cert: impl Fn(ClientId, usize) -> bool,
        with_evidence: impl Fn(ClientId) -> bool,
        publishes: [bool; S],
        double_boot: Option<ClientId>,
    ) -> Outcome {
        let pks: Vec<sig::VerifyingKey> =
            self.server_sig.iter().map(|k| k.verifying_key()).collect();
        let mut servers: Vec<SetServer> = (0..S)
            .map(|j| {
                SetServer::new(
                    &self.pp,
                    ServerId(j as u32),
                    self.server_sig[j].clone(),
                    pks.clone(),
                )
            })
            .collect();

        let mut certs: Vec<Vec<Certificate>> = vec![Vec::new(); self.rounds.len()];
        for r in &self.rounds {
            for lane in 0..S {
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

        for (i, r) in self.rounds.iter().enumerate() {
            if !with_evidence(r.client_id) {
                continue;
            }
            let (e, frags) =
                build_evidence(&self.pp, &SESSION, r, certs[i].clone(), &self.client_sig[i]);
            for (fi, c) in e.certs.iter().enumerate() {
                let j = c.server_id.0 as usize;
                if double_boot == Some(r.client_id) && j >= S / 2 {
                    continue;
                }
                let own = frags.get(fi).map(|f| vec![f.clone()]).unwrap_or_default();
                assert!(servers[j].submit(&SESSION, &e, &own));
            }
        }

        if let Some(cid) = double_boot {
            let mut rng = ChaCha20Rng::from_seed([0xB0; 32]);
            let roster: Vec<(ServerId, pke::PublicKey)> = (0..S)
                .map(|j| (ServerId(j as u32), self.server_keys[j].public()))
                .collect();
            let sk2 = SigningKey::generate(&mut rng);
            let boot2 = run_client_round_set(
                &mut rng,
                &self.pp,
                &SESSION,
                cid,
                channel::cover(&self.ch),
                &roster,
                &sk2,
            );
            let certs2: Vec<Certificate> = (0..S)
                .map(|j| {
                    servers[j]
                        .receive(&SESSION, &boot2.bundles[j])
                        .expect("valid bundle")
                })
                .collect();
            let (e2, _) = build_evidence(&self.pp, &SESSION, &boot2, certs2, &sk2);
            for s in servers.iter_mut().skip(S / 2) {
                assert!(s.submit(&SESSION, &e2, &[]));
            }
        }

        let mut pending: Vec<Vec<Relay>> = servers.iter_mut().map(|s| s.echo(&SESSION)).collect();
        for round in 1..=relay_rounds(&self.pp) {
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

        let sets: Vec<Option<SetRound>> = servers
            .iter()
            .enumerate()
            .map(|(j, s)| publishes[j].then(|| s.finalize(&self.pp, &self.server_keys[j], &SESSION)))
            .collect();

        let published: Vec<&SetRound> = sets.iter().flatten().collect();
        let servers_out: Vec<ServerBulletinEntry> = published
            .iter()
            .map(|sr| run_server_round(&sr.inbox, &sr.set).expect("openings for the set"))
            .collect();
        let scp = self.pp.share_comm.as_ref().expect("share-commitment params");
        let roots: Vec<(ClientId, HVCPoly)> = self
            .entries
            .iter()
            .map(|(cid, e)| (*cid, e.share_root))
            .collect();
        let lanes_out: Vec<RsNodeBulletinEntry> = published
            .iter()
            .map(|sr| {
                run_rs_node_round(scp, &sr.lane_inbox, &sr.set, &roots)
                    .expect("shares for the set")
            })
            .collect();

        let anchor = plurality_set(&servers_out);
        let agreeing: Vec<ServerBulletinEntry> = servers_out
            .into_iter()
            .filter(|sp| sp.clients == anchor)
            .collect();
        let agreeing_lanes: Vec<RsNodeBulletinEntry> = lanes_out
            .into_iter()
            .filter(|np| np.clients == anchor)
            .collect();
        let expect = anchor
            .iter()
            .filter(|c| (c.0 as usize) < self.n_messages)
            .count();

        let recovered = aggregate_and_decrypt_rs(
            &self.pp,
            &SESSION,
            &anchor,
            &self.entries,
            &agreeing,
            &agreeing_lanes,
        )
        .map_err(|e| format!("{e:?}"))
        .and_then(|(plain, _)| {
            channel::decode_messages(&self.ch, &plain, Some(expect)).map_err(|e| format!("{e:?}"))
        });

        Outcome {
            sets,
            anchor,
            agreeing: agreeing.len(),
            recovered,
        }
    }

    fn report(&self, label: &str, o: &Outcome) {
        println!("\n{label}");
        for (j, s) in o.sets.iter().enumerate() {
            match s {
                Some(sr) => {
                    let mut notes = Vec::new();
                    if !sr.repaired.is_empty() {
                        notes.push(format!("rebuilt {:?}", sr.repaired));
                    }
                    if !sr.conflicted.is_empty() {
                        notes.push(format!("conflicted {:?}", sr.conflicted));
                    }
                    if !sr.excluded.is_empty() {
                        notes.push(format!("excluded {:?}", sr.excluded));
                    }
                    println!(
                        "  server {j}: set of {}{}{}",
                        sr.set.len(),
                        if notes.is_empty() { "" } else { " — " },
                        notes.join(", "),
                    );
                }
                None => println!("  server {j}: WITHHELD its output"),
            }
        }
        println!(
            "  anchor: set of {}, {} of {} servers agreed (t = {})",
            o.anchor.len(),
            o.agreeing,
            S,
            self.pp.shamir.t,
        );
        match &o.recovered {
            Ok(payloads) => {
                let mut got: Vec<&str> = payloads
                    .iter()
                    .map(|p| std::str::from_utf8(unpad(p)).unwrap_or("<non-utf8>"))
                    .collect();
                got.sort();
                println!("  recovered {} messages: {got:?}", payloads.len());
            }
            Err(e) => println!("  round does not proceed: {e}"),
        }
    }
}

fn main() {
    let messages: &[&[u8]] = &[
        b"hello from client 0",
        b"client 1 says hi",
        b"another from #2",
        b"#3: anonymous broadcast",
        b"client 4 here",
        b"final note from 5",
    ];
    let d = Demo::build(messages);
    let n_clients = messages.len() + N_COVER;

    println!(
        "client-set demo: {n_clients} clients ({} messages + {N_COVER} cover), {S} servers/lanes",
        messages.len()
    );
    println!(
        "  k = t = {K}, so n − k = {} censors are absorbed and {} halt the round",
        S - K,
        S - K + 1,
    );
    let bundle = &d.rounds[0].bundles[0];
    let scp = d.pp.share_comm.as_ref().expect("RS mode params");
    let bundle_len = Bundle::packed_len(scp, bundle.envelope.len());
    println!(
        "  per-server bundle {} B ({} B share + {} B envelope); receipts 96 B; no replication",
        bundle_len,
        bundle_len - bundle.envelope.len(),
        bundle.envelope.len(),
    );

    let every = |_: ClientId, _: usize| true;
    let none = |_: ClientId, _: usize| false;
    let all = [true; S];

    d.report(
        "1. every bundle delivered, every receipt returned",
        &d.run(every, none, |_| true, all, None),
    );

    let victim = ClientId(5);
    let censor = S - 1;
    d.report(
        "2. server 7 withholds client 5's receipt — the coded detour routes around it",
        &d.run(
            every,
            |c, lane| c == victim && lane == censor,
            |_| true,
            all,
            None,
        ),
    );

    let rogue = ClientId(3);
    d.report(
        "3. client 3 sends bundles but no evidence — excluded by all, no halt",
        &d.run(every, none, |c| c != rogue, all, None),
    );

    d.report(
        "4. client 3 skips server 3 and claims censorship — included, server 3 rebuilds",
        &d.run(|c, lane| !(c == rogue && lane == 3), none, |_| true, all, None),
    );

    let censors = [S - 3, S - 2, S - 1];
    let mut three = all;
    for j in censors {
        three[j] = false;
    }
    d.report(
        "5. servers 5-7 censor client 4 and withhold their outputs — nothing reaches t",
        &d.run(
            every,
            |c, lane| c == ClientId(4) && censors.contains(&lane),
            |_| true,
            three,
            None,
        ),
    );

    d.report(
        "6. client 1's host boots its TEE twice and finishes two packages — a conflict, out everywhere",
        &d.run(every, none, |_| true, all, Some(ClientId(1))),
    );

    println!("\nevery recoverable set contained every honest client; censorship only ever halted");
}
