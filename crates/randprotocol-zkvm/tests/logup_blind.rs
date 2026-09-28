//! INT-2 / GV-1 (the 2026-09-27 zkVM review): a proof's per-instance LogUp terminals must not be a
//! function of the private witness.
//!
//! Every batch-STARK proof publishes one LogUp terminal per table (`BatchProof::lookup_terminals`):
//! the sum, over the table's rows, of each message's multiplicity over `(bus_prefix − fingerprint)`.
//! The lookup challenges `(α, β)` are Fiat–Shamir draws from public transcript data — the instance
//! bindings, the main-trace commitment, the public values, the preprocessed commitment — so anyone
//! holding a proof can replay them (`lookup_challenges` below does, with `p3-batch-stark`'s own
//! `BatchTranscript`), take a *candidate* witness, build its trace and compute the terminals that
//! candidate would publish (`predicted_terminals`, with `p3-lookup`'s own `LogUpGadget` — the
//! prover's code, not a restatement). Before constraint set 7 the published terminals equal the true
//! witness's prediction exactly and differ from any other candidate's: the terminals are an
//! unsalted, checkable commitment to the input table's words, the program table's per-instruction
//! fetch counts and every other table's value histogram, whatever `H_IN`'s salt hides. On a
//! bundle that tells an observer which input slots are dummies (the guest skips a dummy's Merkle
//! walk, so the program table's fetch counts differ) — the GV-1 case, the last test here.
//!
//! Constraint set 7 blinds every terminal (`tables::blind`): each instance carries a fresh,
//! uniformly random extension-field element on the `BLIND` bus, sent by itself and received by the
//! next instance in a fixed cycle, so each terminal is shifted by a uniform element while their sum
//! stays exactly zero. The tests here are what that has to achieve, stated against the observer
//! above: (1) no published terminal equals the true witness's prediction, nor another candidate's;
//! (2) the difference between the published and the predicted terminals sums to zero over the batch
//! — the shift is a balanced bus, not a soundness hole, and the prediction is otherwise exact; (3) a
//! second proof of the *same* witness is shifted differently — the shift is fresh, not a function of
//! the witness either.
use p3_air::BaseAir;
use p3_batch_stark::{BatchTranscript, CommonData};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{LogUpGadget, LookupProtocol};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::StarkGenericConfig;
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{build_traces_salted, build_traces_salted_with, chips, Challenge, Config, FriProfile, Machine, Proof, Tier, Traces, Val};

/// A trace widened with zero columns to its chip's width. The blinding columns are the chip's last
/// ones and `Traces` does not carry them (`Machine::prove_traces` appends them), so this is exactly
/// the observer's best guess at them: nothing. Before constraint set 7 the widths agree and this is
/// the identity.
fn pad_to(m: &RowMajorMatrix<Val>, w: usize) -> RowMajorMatrix<Val> {
    let (h, w0) = (m.height(), m.width());
    assert!(w >= w0);
    let mut v = Val::zero_vec(h * w);
    for r in 0..h {
        v[r * w..r * w + w0].copy_from_slice(&m.values[r * w0..(r + 1) * w0]);
    }
    RowMajorMatrix::new(v, w)
}

fn key(m: &Machine, p: &Proof) -> std::sync::Arc<CommonData<Config>> {
    m.verifier_key(p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height, p.sha256_log_height, p.public_log_height)
}

/// The per-instance lookup challenges of `proof`, replayed from public data alone —
/// `verify_batch`'s transcript steps up to `sample_perm_challenges`, in its order.
fn lookup_challenges(m: &Machine, proof: &Proof) -> Vec<Vec<Challenge>> {
    let airs = chips(proof.tier, proof.keccak_log_height, proof.sha256_log_height);
    let common = key(m, proof);
    let is_zk = m.config.is_zk();
    let b = &proof.batch;
    let mut t = BatchTranscript::<Config>::new(m.config.initialise_challenger());
    t.observe_instance_count(airs.len());
    for (i, air) in airs.iter().enumerate() {
        let chunks = b.opened_values.instances[i].base_opened_values.quotient_chunks.len();
        t.observe_instance_binding(b.degree_bits[i], b.degree_bits[i] - is_zk, BaseAir::<Val>::width(air), chunks);
    }
    let pv: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
    let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == 1 { pv.clone() } else { vec![] }).collect();
    t.observe_main(&b.commitments.main, &pvs);
    let pre = common.preprocessed.as_ref();
    let widths: Vec<usize> = (0..airs.len())
        .map(|i| pre.and_then(|g| g.instances[i].as_ref().map(|x| x.width)).unwrap_or(0))
        .collect();
    t.observe_preprocessed(&widths, pre);
    t.sample_perm_challenges(&common.lookups, &LogUpGadget::new())
}

/// The terminals a candidate witness's traces would publish under `proof`'s challenges.
fn predicted_terminals(m: &Machine, proof: &Proof, traces: &Traces) -> Vec<Option<Challenge>> {
    let airs = chips(proof.tier, proof.keccak_log_height, proof.sha256_log_height);
    let common = key(m, proof);
    let challenges = lookup_challenges(m, proof);
    airs.iter()
        .zip(traces.as_slice())
        .enumerate()
        .map(|(i, (air, mat))| {
            let wide = pad_to(mat, BaseAir::<Val>::width(air));
            let pv = if i == 1 { traces.public_values.clone() } else { vec![] };
            let (_, term) = LogUpGadget::new().generate_permutation::<Config>(
                &wide,
                &BaseAir::<Val>::preprocessed_trace(air),
                &pv,
                common.lookups[i].as_ref(),
                &challenges[i],
            );
            term.map(|t| t.0)
        })
        .collect()
}

fn published(proof: &Proof) -> Vec<Option<Challenge>> { proof.batch.lookup_terminals.iter().map(|t| t.as_ref().map(|t| t.0)).collect() }

const SALT: [u32; 4] = [0x51, 0x52, 0x53, 0x54];

/// A proof of `(p, inputs)` and the exact (unblinded) traces it proved.
fn prove(m: &Machine, p: &Program, inputs: &[u32]) -> (Proof, Traces) {
    let (proof, exec) = m.prove_salted(p, inputs, &[], SALT, None).expect("proves");
    m.verify(&p.digest(), &proof).expect("an honest proof verifies");
    let t = build_traces_salted(p, inputs, &[], SALT, &exec, proof.tier, randprotocol_zkvm::gas::gas_max(proof.tier, proof.keccak_log_height, proof.sha256_log_height)).expect("builds");
    (proof, t)
}

/// A candidate witness's traces at `tier`: what the observer builds for a guess.
fn candidate(p: &Program, inputs: &[u32], tier: Tier) -> Traces {
    let exec = execute(p, inputs, &[], 1 << 22).expect("runs");
    build_traces_salted_with(p, inputs, &[], SALT, &exec, tier, randprotocol_zkvm::machine::ProveOptions::default()).expect("builds")
}

/// `published − predicted`, per instance with a terminal.
fn shift(obs: &[Option<Challenge>], pred: &[Option<Challenge>]) -> Vec<Challenge> {
    assert_eq!(obs.len(), pred.len());
    obs.iter()
        .zip(pred)
        .map(|(o, p)| match (o, p) {
            (Some(o), Some(p)) => *o - *p,
            (None, None) => Challenge::ZERO,
            _ => panic!("terminal presence differs between the proof and its prediction"),
        })
        .collect()
}

/// The three properties of the module comment, for a proof of witness `a` observed against its own
/// traces and a second candidate's `b` of the same shape, and a re-proof `a2` of the same witness.
fn assert_blinded(name: &str, m: &Machine, (pa, ta): (&Proof, &Traces), tb: &Traces, (pa2, ta2): (&Proof, &Traces)) {
    let obs = published(pa);
    let pred_a = predicted_terminals(m, pa, ta);
    let pred_b = predicted_terminals(m, pa, tb);
    let n = obs.iter().filter(|t| t.is_some()).count();
    let match_a: Vec<usize> = (0..obs.len()).filter(|&i| obs[i].is_some() && obs[i] == pred_a[i]).collect();
    let match_b: Vec<usize> = (0..obs.len()).filter(|&i| obs[i].is_some() && obs[i] == pred_b[i]).collect();
    let differ_ab: Vec<usize> = (0..obs.len()).filter(|&i| pred_a[i] != pred_b[i]).collect();
    eprintln!(
        "{name}: {n} terminals; equal to the true witness's prediction at instances {match_a:?}, to the other candidate's at {match_b:?}; the two candidates' predictions differ at {differ_ab:?}"
    );
    assert!(!differ_ab.is_empty(), "{name}: the two candidates are not distinguishable by their terminals at all — a vacuous test");
    // (2) first: it is what shows the prediction is the prover's own computation, so that (1) is a
    // statement about hiding and not about a broken replay.
    let s = shift(&obs, &pred_a);
    assert_eq!(s.iter().copied().sum::<Challenge>(), Challenge::ZERO, "{name}: the shift is not balanced over the batch");
    // (1) the leak: a terminal the true witness predicts identifies it.
    assert!(match_a.is_empty(), "{name}: instances {match_a:?}' published LogUp terminals are exactly what the true witness's trace predicts — the terminals identify the witness (INT-2)");
    assert!(match_b.is_empty(), "{name}: instances {match_b:?}' terminals equal the other candidate's prediction");
    // (3) fresh per proof: a re-proof of the same witness is shifted by different amounts.
    let s2 = shift(&published(pa2), &predicted_terminals(m, pa2, ta2));
    let same: Vec<usize> = (0..s.len()).filter(|&i| obs[i].is_some() && s[i] == s2[i]).collect();
    assert!(same.is_empty(), "{name}: instances {same:?} are shifted identically in two proofs of one witness");
}

/// Two calls of one guest with different private inputs of the same shape and the same output —
/// the pair `tests/zk.rs` already shows indistinguishable in the public values.
#[test]
fn a_calls_terminals_do_not_identify_its_private_inputs() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let (a, b) = ([400u32, 250, 300, 75], [1000u32, 0, 0, 0]);
    let (pa, ta) = prove(&m, &p, &a);
    let tb = candidate(&p, &b, pa.tier);
    let (pa2, ta2) = prove(&m, &p, &a);
    assert_blinded("balance_check", &m, (&pa, &ta), &tb, (&pa2, &ta2));
}

/// GV-1: the 2-in/2-out bundle guest with two real inputs against one real input and a dummy. The
/// guest skips a dummy's Merkle walk, so the program table's fetch counts — and before constraint
/// set 7 its terminal — say which slots are real. Tier 14; run it on a machine with the room.
#[test]
fn a_bundles_terminals_do_not_say_which_slots_are_dummies() {
    use randprotocol_zkvm::ledger::CommitmentTree;
    use randprotocol_zkvm::notes::{self, Note, SpendKey, Word8, DEPTH};
    let m = Machine::new(FriProfile::Test);
    let sk = SpendKey::random();
    let vk = sk.viewing_key();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let mut tree = CommitmentTree::new();
    let real: Vec<Note> = [1_000u64, 2_000].iter().map(|&amt| Note::new(vk.pk(), vk.pk(), amt, asset, time)).collect();
    for n in &real {
        tree.append(n.commitment());
    }
    let anchor = tree.root();
    let path = |n: &Note| -> (Note, [Word8; DEPTH], u32) {
        let (p, idx) = tree.path_for(&n.commitment()).unwrap();
        (*n, p, idx)
    };
    let dummy = (Note::new([0; 8], [0; 8], 0, asset, time), [[0; 8]; DEPTH], 0u32);
    let program = guests::bundle();
    // Two real inputs (1 000 + 2 000) against one real input (1 000) and a dummy, each balanced.
    let outs_two = [Note::new(vk.pk(), vk.pk(), 2_900, asset, time), Note::new(vk.pk(), vk.pk(), 0, asset, time)];
    let outs_one = [Note::new(vk.pk(), vk.pk(), 900, asset, time), Note::new(vk.pk(), vk.pk(), 0, asset, time)];
    let two = notes::bundle_inputs(&sk, &[path(&real[0]), path(&real[1])], &outs_two, anchor, 100, 0, asset, time);
    let one = notes::bundle_inputs(&sk, &[path(&real[0]), dummy], &outs_one, anchor, 100, 0, asset, time);
    assert_eq!(two.len(), one.len(), "the two witnesses have one input shape");
    let (pa, ta) = prove(&m, &program, &two);
    let tb = candidate(&program, &one, pa.tier);
    let (pa2, ta2) = prove(&m, &program, &two);
    assert_blinded("bundle, two real inputs vs one real and a dummy", &m, (&pa, &ta), &tb, (&pa2, &ta2));
}
