//! Canonical client-set selection, five deliveries of the same round.
//!
//! Each client sends every lane one signed bundle. Each lane publishes a signed
//! batch of what it took, the batches are agreed over Dolev–Strong rounds, and
//! every lane reads the same matrix to fix the same set: a gap inside the
//! abstention budget costs only the lane that missed it, a gap past the budget
//! is repaired from the client's fragments, and a host that boots twice reports
//! two keys and is excluded everywhere.

use anymone_core::client_set::{
    build_fragments, plurality_set, relay_rounds, run_client_round_set, ClientSetRound,
    ReceiptBatch, Relay, SetRound, SetServer,
};
use panetiere::HVCPoly;
use panetiere::bulletin::{RsClientBulletinEntry, RsNodeBulletinEntry, ServerBulletinEntry};
use panetiere::channel::{self, ChannelParams};
use panetiere::kahe::T_MODULUS_DEFAULT;
use panetiere::pke;
use panetiere::protocol::server::{run_rs_node_round, run_server_round};
use panetiere::protocol::verify::aggregate_and_decrypt_rs;
use panetiere::protocol::{ClientId, ProtocolParams, ServerId, SessionId};
use panetiere::sig::{self, SigningKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Servers, each also a lane — the bundle carries both duties.
const S: usize = 8;
/// k = t: two lanes may abstain, three halt the round.
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

fn roster(keys: &[pke::PrivateKey]) -> Vec<(ServerId, pke::PublicKey)> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| (ServerId(i as u32), k.public()))
        .collect()
}

fn covered_lanes(batches: &[ReceiptBatch], cid: ClientId) -> Vec<usize> {
    let mut lanes: Vec<usize> = batches
        .iter()
        .filter(|b| b.receipts.iter().any(|r| r.client_id == cid))
        .map(|b| b.server_id.0 as usize)
        .collect();
    lanes.sort_unstable();
    lanes
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
        let servers = roster(&server_keys);

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

    fn servers(&self) -> Vec<SetServer> {
        let pks: Vec<sig::VerifyingKey> =
            self.server_sig.iter().map(|k| k.verifying_key()).collect();
        (0..S)
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

    /// `double_boot` runs a second boot for that client and splits the two
    /// across the lanes, so they report different keys.
    fn run(
        &self,
        deliver: impl Fn(ClientId, usize) -> bool,
        repairs: impl Fn(ClientId) -> bool,
        publishes: [bool; S],
        double_boot: Option<ClientId>,
    ) -> Outcome {
        let mut servers = self.servers();
        for (cid, entry) in &self.entries {
            for s in servers.iter_mut() {
                s.note_bulletin(*cid, entry.pubkey);
            }
        }
        for r in &self.rounds {
            for lane in 0..S {
                let second = double_boot == Some(r.client_id) && lane >= S / 2;
                if deliver(r.client_id, lane) && !second {
                    servers[lane].receive(&SESSION, &r.bundles[lane]);
                }
            }
        }
        if let Some(cid) = double_boot {
            let mut rng = ChaCha20Rng::from_seed([0xB0; 32]);
            let sk2 = SigningKey::generate(&mut rng);
            let boot2 = run_client_round_set(
                &mut rng,
                &self.pp,
                &SESSION,
                cid,
                channel::cover(&self.ch),
                &roster(&self.server_keys),
                &sk2,
            );
            for lane in S / 2..S {
                servers[lane].receive(&SESSION, &boot2.bundles[lane]);
            }
            for s in servers.iter_mut() {
                s.note_bulletin(cid, boot2.bulletin.pubkey);
            }
        }

        let batches: Vec<ReceiptBatch> = servers.iter().map(|s| s.batch(&SESSION)).collect();
        let mut bus: Vec<(usize, Relay)> = Vec::new();
        for (j, s) in servers.iter_mut().enumerate() {
            bus.extend(s.originate(&SESSION).into_iter().map(|r| (j, r)));
        }
        for (i, r) in self.rounds.iter().enumerate() {
            let covered = covered_lanes(&batches, r.client_id);
            if covered.len() == S || !repairs(r.client_id) {
                continue;
            }
            let frags = build_fragments(&self.pp, &SESSION, r, &covered, &self.client_sig[i]);
            for (lane, f) in covered.iter().zip(frags) {
                let out = servers[*lane].submit(&SESSION, std::slice::from_ref(&f));
                bus.extend(out.into_iter().map(|rel| (*lane, rel)));
            }
        }
        for round in 1..=relay_rounds(&self.pp) {
            let batch = std::mem::take(&mut bus);
            for (j, s) in servers.iter_mut().enumerate() {
                let incoming: Vec<Relay> = batch
                    .iter()
                    .filter(|(from, _)| *from != j)
                    .map(|(_, rel)| rel.clone())
                    .collect();
                bus.extend(
                    s.absorb(&SESSION, round, &incoming)
                        .into_iter()
                        .map(|rel| (j, rel)),
                );
            }
        }

        let sets: Vec<Option<SetRound>> = servers
            .iter()
            .enumerate()
            .map(|(j, s)| publishes[j].then(|| s.finalize(&self.pp, &self.server_keys[j], &SESSION)))
            .collect();

        let published: Vec<&SetRound> = sets.iter().flatten().collect();
        let scp = self.pp.share_comm.as_ref().expect("share-commitment params");
        let roots: Vec<(ClientId, HVCPoly)> = self
            .entries
            .iter()
            .map(|(cid, e)| (*cid, e.share_root))
            .collect();
        // A lane short of a canonical member publishes nothing — the abstention
        // the set rule budgets for.
        let servers_out: Vec<ServerBulletinEntry> = published
            .iter()
            .filter_map(|sr| run_server_round(&sr.inbox, &sr.set).ok())
            .collect();
        let lanes_out: Vec<RsNodeBulletinEntry> = published
            .iter()
            .filter_map(|sr| run_rs_node_round(scp, &sr.lane_inbox, &sr.set, &roots).ok())
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
                    let served = sr.lane_inbox.items.len();
                    if served < sr.set.len() {
                        notes.push(format!("abstains, serves {served}/{}", sr.set.len()));
                    }
                    println!(
                        "  lane {j}: set of {}{}{}",
                        sr.set.len(),
                        if notes.is_empty() { "" } else { " — " },
                        notes.join(", "),
                    );
                }
                None => println!("  lane {j}: WITHHELD its output"),
            }
        }
        println!(
            "  anchor: set of {}, {} of {} lanes agreed (t = {})",
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
        "client-set demo: {n_clients} clients ({} messages + {N_COVER} cover), {S} lanes",
        messages.len()
    );
    println!(
        "  k = t = {K}, so {} lanes may abstain and {} halt the round",
        S - K,
        S - K + 1,
    );
    let scp = d.pp.share_comm.as_ref().expect("share-commitment params");
    let bundle = &d.rounds[0].bundles[0];
    println!(
        "  per-lane bundle {} B; receipt 69 B, so a lane's batch is {} B",
        anymone_core::client_set::Bundle::packed_len(scp, bundle.envelope.len()),
        ReceiptBatch::packed_len(n_clients),
    );
    println!(
        "  {} Dolev-Strong rounds after the batches",
        relay_rounds(&d.pp)
    );

    let every = |_: ClientId, _: usize| true;
    let never = |_: ClientId| false;
    let always = |_: ClientId| true;
    let all = [true; S];

    d.report(
        "1. every bundle delivered — one set, nothing repaired",
        &d.run(every, never, all, None),
    );

    let victim = ClientId(5);
    d.report(
        "2. lane 7 never took client 5's bundle — absorbed, lane 7 abstains",
        &d.run(
            |c, lane| !(c == victim && lane == S - 1),
            never,
            all,
            None,
        ),
    );

    let blind = [S - 3, S - 2, S - 1];
    let cut = ClientId(4);
    d.report(
        "3. three lanes miss client 4 — past the budget, so it repairs",
        &d.run(
            |c, lane| !(c == cut && blind.contains(&lane)),
            always,
            all,
            None,
        ),
    );

    d.report(
        "4. same gap, client offline for the repair — excluded, round proceeds",
        &d.run(
            |c, lane| !(c == cut && blind.contains(&lane)),
            never,
            all,
            None,
        ),
    );

    d.report(
        "5. client 1's host boots twice — two keys reported, out everywhere",
        &d.run(every, never, all, Some(ClientId(1))),
    );

    let mut three = all;
    for j in blind {
        three[j] = false;
    }
    d.report(
        "6. lanes 5-7 withhold their output — nothing reaches t",
        &d.run(every, never, three, None),
    );

    println!("\nevery lane fixed the same set; censorship cost the censor, never the client");
}
