//! The hidden-asset bundle guest (`guests::bundle_hidden`, spec
//! `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md` §3): four input and four
//! output slots, slots 0–1 carrying a PRIVATE asset `A`, slots 2–3 carrying RAND.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes it, like `tests/shielded.rs`).
//!
//! Three groups of tests:
//! - **honest shapes, emulated** (milliseconds): every shape a wallet builds — RAND-only,
//!   token-only with a RAND fee, mixed, `A = 0`, a token burn, a RAND burn — publishes exactly
//!   `hidden::hidden_bundle_digest(..)` of the plaintext the ledger will see, and every shape
//!   lands on the same tier with the same table heights (a shape the proof could reveal is a
//!   shape an observer could read).
//! - **dishonest witnesses, emulated**: for every check of spec §3.3, a witness that would
//!   pass if the check were missing. An *arithmetic* check must taint — the emulated output is
//!   the claimed plaintext's digest with `bad = 1`, exactly, which shows it was that taint and
//!   nothing else that moved the digest. A *structural* check (an output's asset, `burn_asset`)
//!   leaves the claimed plaintext's digest unreachable. The real-proof cheating suite is H2.
//! - **real proofs** (minutes): one mixed transfer at the Production FRI profile — tier 14,
//!   verifies with its transaction binding, refused with any other — and one proved against the
//!   empty public segment, refused.

use randprotocol_core::confidential::ConfidentialError;
use randprotocol_zkvm::emulator::{execute, HashRow};
use randprotocol_zkvm::executor::{prove_hidden_bundle, ZkExecutor};
use randprotocol_zkvm::hidden::{self, hidden_input as hi, HiddenDigestInput, HiddenOutput, HIDDEN_BUNDLE_DOMAIN};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::machine::{build_traces, Backend, FriProfile, Machine, Tier};
use randprotocol_zkvm::notes::{self, Note, SpendKey, Word8, DEPTH};

/// Two transactions' bindings (`Transaction::binding`), as in `tests/shielded.rs`.
const BINDING_A: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
const BINDING_B: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_fffe];

/// The token id the non-RAND tests use (any nonzero `u32`: the guest never learns which asset
/// ids exist).
const TOKEN: u32 = 7;
const TIME: u32 = 5;
const MAX_CYCLES: usize = 1 << 20;

/// One input slot of a test witness: `Real` notes are appended to the tree and spent with their
/// real path; a `Dummy` is a fresh zero-value note, never in the tree, with a zero path.
#[derive(Clone, Copy)]
enum In {
    Real(u64, u32),
    Dummy,
}

/// A complete witness: the plaintext a wallet would build, before the guest sees it.
#[derive(Clone)]
struct Case {
    sk: SpendKey,
    ins: [(Note, [Word8; DEPTH], u32); 4],
    outs: [Note; 4],
    anchor: Word8,
    fee: u64,
    burn_a: u64,
    burn_r: u64,
    asset_a: u32,
    time: u32,
}

impl Case {
    /// `ins` are the four input slots; `outs` the four output amounts, each output note built with
    /// its slot's asset (`asset_a` for 0–1, 0 for 2–3), `from = pk_self` and the bundle's time —
    /// what the guest commits to structurally. Five unrelated leaves precede the spent notes so
    /// every path is non-trivial.
    fn new(ins: [In; 4], outs: [u64; 4], fee: u64, burn_a: u64, burn_r: u64, asset_a: u32) -> Case {
        let sk = SpendKey::random();
        let me = sk.viewing_key().pk();
        let mut tree = CommitmentTree::new();
        for _ in 0..5 {
            tree.append(Note::new([9; 8], [0; 8], 1, 0, 1).commitment());
        }
        let notes: Vec<Note> = ins
            .iter()
            .enumerate()
            .map(|(k, i)| match *i {
                In::Real(amount, asset) => Note::new(me, [k as u32 + 3; 8], amount, asset, 2),
                In::Dummy => Note::new(me, [0; 8], 0, 0, TIME),
            })
            .collect();
        for (n, i) in notes.iter().zip(ins.iter()) {
            if matches!(i, In::Real(..)) {
                tree.append(n.commitment());
            }
        }
        let anchor = tree.root();
        let ins = std::array::from_fn(|k| match ins[k] {
            In::Real(..) => {
                let (p, i) = tree.path_for(&notes[k].commitment()).unwrap();
                (notes[k], p, i)
            }
            In::Dummy => (notes[k], [[0; 8]; DEPTH], 0),
        });
        let outs = std::array::from_fn(|k| {
            let asset = if k < 2 { asset_a } else { 0 };
            Note::new([k as u32 + 20; 8], me, outs[k], asset, TIME)
        });
        Case { sk, ins, outs, anchor, fee, burn_a, burn_r, asset_a, time: TIME }
    }

    /// The witness. The outputs go in as the sender's choices only (`pk`, `amount`, `r`); the
    /// test keeps whole notes in `outs` to model what a wallet believes it is committing to.
    fn inputs(&self) -> Vec<u32> {
        let outs = self.outs.map(|o| HiddenOutput { pk: o.pk, amount: o.amount, r: o.r });
        hidden::hidden_bundle_inputs(
            &self.sk, &self.ins, &outs, self.anchor, self.fee, self.burn_a, self.burn_r, self.asset_a, self.time,
        )
    }

    /// What the chain sees, computed here independently of the guest: nullifiers of the spent
    /// notes under the spender's key, the output commitments, and `burn_asset` as spec §3.3 has it.
    fn claimed(&self) -> HiddenDigestInput {
        let vk = self.sk.viewing_key();
        HiddenDigestInput {
            anchor: self.anchor,
            nullifiers: std::array::from_fn(|k| vk.nullifier(&self.ins[k].0.commitment())),
            commitments: std::array::from_fn(|k| self.outs[k].commitment()),
            fee: self.fee,
            burn_a: self.burn_a,
            burn_r: self.burn_r,
            burn_asset: if self.burn_a != 0 { self.asset_a } else { 0 },
            time: self.time,
        }
    }
}

fn emulate(inputs: &[u32]) -> Word8 {
    execute(ZkExecutor::hidden_bundle_program(), inputs, &BINDING_A, MAX_CYCLES).unwrap().outputs
}

/// The claimed plaintext's digest with the guest's `bad` word set — what a tainted run publishes.
fn tainted(di: &HiddenDigestInput) -> Word8 {
    let mut msg = hidden::hidden_bundle_preimage(di);
    *msg.last_mut().unwrap() = 1;
    notes::hash(HIDDEN_BUNDLE_DOMAIN, &msg)
}

fn assert_honest(c: &Case, what: &str) {
    assert_eq!(emulate(&c.inputs()), hidden::hidden_bundle_digest(&c.claimed()), "{what}: an honest witness tainted, or the digest preimage disagrees");
}

/// The witness taints `bad` and changes nothing else about the digest.
fn assert_taints(inputs: &[u32], claimed: &HiddenDigestInput, what: &str) {
    let out = emulate(inputs);
    assert_ne!(out, hidden::hidden_bundle_digest(claimed), "{what}: a cheating witness published the honest digest");
    assert_eq!(out, tainted(claimed), "{what}: expected exactly the bad = 1 digest");
}

// ───────────────────────────── shapes ─────────────────────────────

fn rand_only() -> Case {
    Case::new([In::Dummy, In::Dummy, In::Real(1_000, 0), In::Dummy], [0, 0, 600, 390], 10, 0, 0, 0)
}
fn token_only() -> Case {
    Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(50, 0), In::Dummy], [600, 200, 40, 0], 10, 0, 0, TOKEN)
}
fn mixed() -> Case {
    Case::new(
        [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)],
        [600, 200, 900, 140],
        10,
        0,
        0,
        TOKEN,
    )
}
fn a_is_rand() -> Case {
    Case::new([In::Real(500, 0), In::Real(300, 0), In::Real(1_000, 0), In::Dummy], [700, 100, 990, 0], 10, 0, 0, 0)
}
fn token_burn() -> Case {
    Case::new([In::Real(500, TOKEN), In::Dummy, In::Real(100, 0), In::Dummy], [200, 0, 90, 0], 10, 300, 0, TOKEN)
}
fn rand_burn() -> Case {
    Case::new([In::Dummy, In::Dummy, In::Real(1_000, 0), In::Dummy], [0, 0, 400, 0], 10, 0, 590, 0)
}

fn shapes() -> Vec<(&'static str, Case)> {
    vec![
        ("RAND-only (A slots dummy)", rand_only()),
        ("RAND-only, A slots dummy under a nonzero A", Case::new([In::Dummy, In::Dummy, In::Real(1_000, 0), In::Dummy], [0, 0, 600, 390], 10, 0, 0, TOKEN)),
        ("token-only with a RAND fee", token_only()),
        ("mixed", mixed()),
        ("A = 0 in slots 0-1", a_is_rand()),
        ("token burn (burn_a > 0)", token_burn()),
        ("RAND burn (burn_r > 0)", rand_burn()),
        ("RAND burn beside a token transfer (burn_asset stays 0)", Case::new([In::Real(500, TOKEN), In::Dummy, In::Real(1_000, 0), In::Dummy], [500, 0, 400, 0], 10, 0, 590, TOKEN)),
        ("a dummy's asset is free (value 0)", Case::new([In::Real(500, TOKEN), In::Dummy, In::Real(100, 0), In::Dummy], [500, 0, 90, 0], 10, 0, 0, TOKEN).with_dummy_asset(1, 99).with_dummy_asset(3, 42)),
    ]
}

impl Case {
    fn with_dummy_asset(mut self, k: usize, asset: u32) -> Case {
        assert_eq!(self.ins[k].0.amount, 0);
        self.ins[k].0.asset = asset;
        self
    }
}

#[test]
fn every_honest_shape_publishes_the_host_digest() {
    for (what, c) in shapes() {
        assert_honest(&c, what);
    }
}

/// The tier (hard requirement: 14 at the transaction binding's public height) and the headroom,
/// for the worst case — four real inputs, so four Merkle loops — and every other shape: all land
/// on the same tier with identical table heights, so nothing in a proof's declared shape tells a
/// RAND payment from a token transfer. The tier does not depend on the FRI profile.
#[test]
fn every_shape_lands_at_tier_14_with_identical_table_heights() {
    let program = ZkExecutor::hidden_bundle_program();
    let mut heights = None;
    // The worst case for cycles over *any* witness, honest or not: the only data-dependent costs
    // are the dummy skip and the Merkle bit branch (bit 1 costs one `jal` more per level), so
    // four real inputs whose leaf indices are all ones. Tainted (no such leaves), but a cheating
    // prover's witness must still fit the tier the verifier key is built for.
    let mut worst = mixed().inputs();
    for k in 0..4 {
        worst[hi::in_slot(k) + hi::S_INDEX] = u32::MAX;
    }
    let mut runs: Vec<(&str, Vec<u32>)> = shapes().into_iter().map(|(w, c)| (w, c.inputs())).collect();
    runs.push(("worst case: four real inputs, every index bit 1", worst));
    for (what, inputs) in runs {
        assert_eq!(inputs.len(), hi::COUNT);
        let exec = execute(program, &inputs, &BINDING_A, MAX_CYCLES).unwrap();
        let fixed = program.digest_rows()
            + randprotocol_zkvm::hash::input_digest_row_count(inputs.len())
            + randprotocol_zkvm::hash::public_digest_row_count(BINDING_A.len());
        let absorb = exec.events.iter().filter(|e| matches!(e.hash_row, Some(HashRow::Absorb { .. }))).count();
        let cycles = exec.cycles() + fixed;
        let perms = fixed + absorb;
        let tier = Tier::for_workload(cycles, perms).unwrap();
        println!(
            "{what}: program {} words, {} input words, {} executed + {fixed} digest rows = {cycles} cycles \
             (tier-14 cap {}, headroom {}), {perms} permutations (cap {}, headroom {}), tier {}",
            program.words.len(),
            inputs.len(),
            exec.cycles(),
            Tier(14).max_cycles(),
            Tier(14).max_cycles() as i64 - cycles as i64,
            Tier(14).poseidon2_height() / 32,
            (Tier(14).poseidon2_height() / 32) as i64 - perms as i64,
            tier.0
        );
        assert_eq!(tier, Tier(14), "{what}");
        let traces = build_traces(program, &inputs, &BINDING_A, &exec, tier).unwrap();
        let h: Vec<usize> = traces.as_slice().iter().map(|m| p3_matrix::Matrix::height(*m)).collect();
        match &heights {
            None => {
                println!("table heights: {h:?}");
                heights = Some(h);
            }
            Some(first) => assert_eq!(first, &h, "{what}: table heights differ from the first shape's"),
        }
    }
}

/// The digest excludes `A` (its preimage is 81 message words, 82 with the tag, and has no
/// field for it), carries its own domain tag, and is a different value from today's
/// `bundle_digest` for comparable fields.
#[test]
fn the_digest_is_domain_separated_and_has_no_asset_field() {
    assert_eq!(HIDDEN_BUNDLE_DOMAIN, 64);
    // Outside the range upstream's `notes::domain` allocates sequentially (1, 2, …; 16 upstream
    // already) and not its TEST tag, so a tag a future resync brings in cannot equal it silently.
    assert!(HIDDEN_BUNDLE_DOMAIN > 0x3f && HIDDEN_BUNDLE_DOMAIN != 0xff && HIDDEN_BUNDLE_DOMAIN != notes::domain::TEST);
    assert!(randprotocol_zkvm::hash::HC_DOMAIN <= 0x3f && randprotocol_zkvm::hash::IN_DOMAIN <= 0x3f && randprotocol_zkvm::hash::PUB_DOMAIN <= 0x3f);
    for tag in [
        notes::domain::NK, notes::domain::PK, notes::domain::NF, notes::domain::CM, notes::domain::OVK,
        notes::domain::KEM_SEED, notes::domain::NODE, notes::domain::HC, notes::domain::OUT, notes::domain::IN,
        notes::domain::BUNDLE, notes::domain::STORAGE_LEAF, notes::domain::EVM_OUT, notes::domain::SBPF_OUT,
        notes::domain::PUB, notes::domain::TEST,
    ] {
        assert_ne!(tag, HIDDEN_BUNDLE_DOMAIN, "domain tag {tag} collides");
    }
    let di = mixed().claimed();
    assert_eq!(hidden::hidden_bundle_preimage(&di).len(), 81);
    // Comparable fields: the same anchor, the first two nullifiers/commitments, the same fee
    // and time, the burns zero, and the old digest's public asset 0.
    let old = notes::bundle_digest(&di.anchor, &di.nullifiers[0], &di.nullifiers[1], &di.commitments[0], &di.commitments[1], di.fee, 0, 0, di.time);
    let two_slot = HiddenDigestInput {
        nullifiers: [di.nullifiers[0], di.nullifiers[1], [0; 8], [0; 8]],
        commitments: [di.commitments[0], di.commitments[1], [0; 8], [0; 8]],
        ..di
    };
    assert_ne!(hidden::hidden_bundle_digest(&di), old);
    assert_ne!(hidden::hidden_bundle_digest(&two_slot), old);
    // And the same message under the old tag is not the new digest either.
    assert_ne!(notes::hash(notes::domain::BUNDLE, &hidden::hidden_bundle_preimage(&di)), hidden::hidden_bundle_digest(&di));
    // Every published field moves the digest.
    let base = hidden::hidden_bundle_digest(&di);
    let moved = [
        HiddenDigestInput { anchor: [1; 8], ..di },
        HiddenDigestInput { nullifiers: [di.nullifiers[1], di.nullifiers[0], di.nullifiers[2], di.nullifiers[3]], ..di },
        HiddenDigestInput { commitments: [di.commitments[0], di.commitments[1], di.commitments[3], di.commitments[2]], ..di },
        HiddenDigestInput { fee: di.fee + (1 << 32), ..di },
        HiddenDigestInput { burn_a: 1, ..di },
        HiddenDigestInput { burn_r: 1 << 32, ..di },
        HiddenDigestInput { burn_asset: 1, ..di },
        HiddenDigestInput { time: di.time + 1, ..di },
    ];
    for (i, m) in moved.iter().enumerate() {
        assert_ne!(hidden::hidden_bundle_digest(m), base, "field {i}");
    }
}

/// The witness builder puts every field where `hidden_input` says it is.
#[test]
fn the_witness_builder_follows_the_layout() {
    assert_eq!(hi::COUNT, 1_204);
    assert_eq!(hi::IN_SLOT_WORDS, 8 + 4 + 8 + DEPTH * 8 + 1);
    let c = mixed();
    let v = c.inputs();
    assert_eq!(&v[hi::SK..hi::SK + 8], &c.sk.0);
    for k in 0..4 {
        let (note, path, index) = &c.ins[k];
        let b = hi::in_slot(k);
        assert_eq!(&v[b + hi::S_FROM..b + hi::S_FROM + 8], &note.from);
        assert_eq!(v[b + hi::S_AMOUNT_LO] as u64 | (v[b + hi::S_AMOUNT_HI] as u64) << 32, note.amount);
        assert_eq!(v[b + hi::S_ASSET], note.asset);
        assert_eq!(v[b + hi::S_TIME], note.time);
        assert_eq!(&v[b + hi::S_R..b + hi::S_R + 8], &note.r);
        for (l, sib) in path.iter().enumerate() {
            assert_eq!(&v[b + hi::S_PATH + 8 * l..b + hi::S_PATH + 8 * l + 8], sib);
        }
        assert_eq!(v[b + hi::S_INDEX], *index);
        let o = hi::out(k);
        assert_eq!(&v[o + hi::O_PK..o + hi::O_PK + 8], &c.outs[k].pk);
        assert_eq!(v[o + hi::O_AMOUNT_LO] as u64 | (v[o + hi::O_AMOUNT_HI] as u64) << 32, c.outs[k].amount);
        assert_eq!(&v[o + hi::O_R..o + hi::O_R + 8], &c.outs[k].r);
    }
    assert_eq!(&v[hi::ANCHOR..hi::ANCHOR + 8], &c.anchor);
    assert_eq!((v[hi::FEE_LO], v[hi::FEE_HI]), (10, 0));
    assert_eq!(v[hi::ASSET_A], TOKEN);
    assert_eq!(v[hi::TIME], TIME);
    assert_eq!(hi::TIME + 1, hi::COUNT);
}

// ───────────────────────────── dishonest witnesses ─────────────────────────────

/// §3.3: a real input's root must equal `anchor` — a witness whose claimed anchor is some other
/// root (an old one, a made-up one) taints.
#[test]
fn a_real_input_under_another_root_taints() {
    let mut c = mixed();
    c.anchor = [0xabc; 8];
    assert_taints(&c.inputs(), &c.claimed(), "anchor mismatch");
    // One real input's path tampered with at one level: its root is no longer the anchor.
    for k in 0..4 {
        let c = mixed();
        let mut v = c.inputs();
        v[hi::in_slot(k) + hi::S_PATH + 8 * 17 + 3] ^= 1;
        assert_taints(&v, &c.claimed(), &format!("path of slot {k}"));
        let mut v = c.inputs();
        v[hi::in_slot(k) + hi::S_INDEX] ^= 1 << 9;
        assert_taints(&v, &c.claimed(), &format!("index of slot {k}"));
    }
}

/// §3.3: every input is staged with owner `pk_self` — a note in the tree owned by someone else
/// is committed under the spender's own key, which is not in the tree.
#[test]
fn a_note_owned_by_another_key_taints() {
    let other = SpendKey::random().viewing_key().pk();
    let mut tree = CommitmentTree::new();
    let theirs = Note::new(other, [3; 8], 1_000, 0, 2);
    tree.append(theirs.commitment());
    let (p, i) = tree.path_for(&theirs.commitment()).unwrap();
    let mut c = rand_only();
    c.anchor = tree.root();
    // The witness words of `theirs` (the builder refuses a foreign owner, so the cheat relabels
    // it): the guest stages it under the spender's own key, a note that is not in the tree, and
    // nullifies that one.
    c.ins[2] = (Note { pk: c.sk.viewing_key().pk(), ..theirs }, p, i);
    assert_taints(&c.inputs(), &c.claimed(), "another owner's note");
}

/// The builder refuses an input note owned by another key: the guest would stage it under the
/// spender's own key, so the proof would nullify a note the caller does not hold.
#[test]
#[should_panic(expected = "input 2 is not owned by this spend key")]
fn the_builder_refuses_an_input_owned_by_another_key() {
    let mut c = rand_only();
    c.ins[2].0.pk = [1; 8];
    let _ = c.inputs();
}

/// `HiddenOutput::note` is the note the guest commits: the wallet's envelope and the chain's
/// commitment agree.
#[test]
fn hidden_output_note_is_what_the_guest_commits() {
    let c = mixed();
    let me = c.sk.viewing_key().pk();
    for k in 0..4 {
        let o = HiddenOutput { pk: c.outs[k].pk, amount: c.outs[k].amount, r: c.outs[k].r };
        assert_eq!(o.note(k, me, c.asset_a, c.time), c.outs[k], "slot {k}");
    }
}

/// §3.3: a dummy (amount 0) skips Merkle/anchor/asset but cannot carry value — a note not in
/// the tree that claims a nonzero amount is a real input that fails its Merkle check, whichever
/// of its two amount words is nonzero.
#[test]
fn a_dummy_cannot_carry_value() {
    for (k, amount) in [(0usize, 100u64), (1, 1 << 32), (2, 100), (3, 1 << 40)] {
        let mut ins = [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)];
        let held = [500u64, 300, 1_000, 50];
        ins[k] = In::Dummy;
        let a_total = held[0] + held[1] - if k < 2 { held[k] } else { 0 };
        let r_total = held[2] + held[3] - if k >= 2 { held[k] } else { 0 };
        let mut c = Case::new(ins, [a_total, 0, r_total - 10, 0], 10, 0, 0, TOKEN);
        // The dummy claims `amount` of its slot's asset, and the group's first output absorbs it,
        // so both sums balance and the Merkle check is the only one left to fire.
        c.ins[k].0.amount = amount;
        c.ins[k].0.asset = if k < 2 { TOKEN } else { 0 };
        c.outs[if k < 2 { 0 } else { 2 }].amount += amount;
        assert_taints(&c.inputs(), &c.claimed(), &format!("dummy slot {k} carrying {amount}"));
    }
}

/// §3.3: a real input's asset equals its slot's — `A` in slots 0–1, 0 in slots 2–3.
#[test]
fn an_input_of_the_wrong_asset_taints() {
    // An A-slot note whose asset is not A (the forged A matches the output side).
    let c = Case::new([In::Real(500, TOKEN + 1), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "A slot, asset != A");
    // Two A-inputs of different assets, under either choice of A.
    for a in [TOKEN, TOKEN + 1] {
        let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN + 1), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, a);
        assert_taints(&c.inputs(), &c.claimed(), &format!("two A-slot assets, A = {a}"));
    }
    // An R-slot note that is a token note: value moved from a token into RAND.
    for k in [2, 3] {
        let mut ins = [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)];
        ins[k] = In::Real(if k == 2 { 1_000 } else { 50 }, TOKEN);
        let c = Case::new(ins, [600, 200, 900, 140], 10, 0, 0, TOKEN);
        assert_taints(&c.inputs(), &c.claimed(), &format!("R slot {k} holding a token note"));
    }
    // A RAND note in an A slot under a nonzero A: RAND moved into the token.
    let c = Case::new([In::Real(500, 0), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "A slot holding a RAND note");
}

/// §3.3: the two groups conserve separately — value cannot move between the token and RAND.
#[test]
fn value_cannot_cross_between_the_asset_groups() {
    // Token in, RAND out: group A short by 100, group R over by 100.
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [500, 200, 1_000, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "token -> RAND");
    // RAND in, token out.
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [700, 200, 800, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "RAND -> token");
    // The fee paid out of the token group.
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [590, 200, 910, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "fee from the token group");
    // Plain imbalance in each group.
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [601, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "group A minted one");
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 141], 10, 0, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "group R minted one");
    // burn_a counted in group R, burn_r in group A.
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 800, 140], 10, 100, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "burn_a paid from RAND");
    let c = Case::new([In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [500, 200, 900, 140], 10, 0, 100, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "burn_r paid from the token");
}

/// §3.3: all 6 nullifier pairs differ — the same note spent in two slots. `A = 0`, so any slot
/// may hold a RAND note, and the fee is 0, so each group's first output absorbs exactly what its
/// inputs hold and the duplicate check is the only one that fires.
#[test]
fn every_duplicated_nullifier_pair_taints() {
    for i in 0..4 {
        for j in (i + 1)..4 {
            let mut ins = [In::Dummy; 4];
            ins[i] = In::Real(100, 0);
            let mut outs = [0u64; 4];
            for k in [i, j] {
                outs[if k < 2 { 0 } else { 2 }] += 100;
            }
            let mut c = Case::new(ins, outs, 0, 0, 0, 0);
            c.ins[j] = c.ins[i];
            assert_taints(&c.inputs(), &c.claimed(), &format!("nullifier pair ({i}, {j})"));
        }
    }
}

/// §3.3: all 6 output-commitment pairs differ — the same note minted twice. `A = 0` so a note
/// may sit in any output slot with the same commitment.
#[test]
fn every_duplicated_output_pair_taints() {
    for i in 0..4 {
        for j in (i + 1)..4 {
            let mut outs = [0u64; 4];
            outs[i] = 100;
            outs[j] = 100;
            let a_in: u64 = [i, j].iter().filter(|&&k| k < 2).count() as u64 * 100;
            let r_in: u64 = [i, j].iter().filter(|&&k| k >= 2).count() as u64 * 100 + 10;
            let ins = [
                if a_in > 0 { In::Real(a_in, 0) } else { In::Dummy },
                In::Dummy,
                In::Real(r_in, 0),
                In::Dummy,
            ];
            let mut c = Case::new(ins, outs, 10, 0, 0, 0);
            c.outs[j] = c.outs[i];
            assert_taints(&c.inputs(), &c.claimed(), &format!("output pair ({i}, {j})"));
        }
    }
    // Two identical dummy outputs collide too: a wallet must draw a fresh `r` for each.
    let mut c = rand_only();
    c.outs[1] = c.outs[0];
    assert_taints(&c.inputs(), &c.claimed(), "two identical dummy outputs");
}

/// §3.3: `< 2^63` on each of the 11 amounts, one at a time, every sum balanced and carry-free, so
/// only the range check fires.
#[test]
fn each_of_the_eleven_range_checks_taints() {
    const BIG: u64 = 1 << 63;
    // (what, inputs, outputs, fee, burn_a, burn_r)
    type Row = (&'static str, [In; 4], [u64; 4], u64, u64, u64);
    let rows: [Row; 11] = [
        ("in0", [In::Real(BIG, 0), In::Dummy, In::Real(10, 0), In::Dummy], [BIG / 2, BIG / 2, 0, 0], 10, 0, 0),
        ("in1", [In::Dummy, In::Real(BIG, 0), In::Real(10, 0), In::Dummy], [BIG / 2, BIG / 2, 0, 0], 10, 0, 0),
        ("in2", [In::Dummy, In::Dummy, In::Real(BIG, 0), In::Dummy], [0, 0, BIG / 2, BIG / 2 - 10], 10, 0, 0),
        ("in3", [In::Dummy, In::Dummy, In::Dummy, In::Real(BIG, 0)], [0, 0, BIG / 2, BIG / 2 - 10], 10, 0, 0),
        ("out0", [In::Real(BIG - 1, 0), In::Real(1, 0), In::Real(10, 0), In::Dummy], [BIG, 0, 0, 0], 10, 0, 0),
        ("out1", [In::Real(BIG - 1, 0), In::Real(1, 0), In::Real(10, 0), In::Dummy], [0, BIG, 0, 0], 10, 0, 0),
        ("out2", [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(11, 0)], [0, 0, BIG, 0], 10, 0, 0),
        ("out3", [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(11, 0)], [0, 0, 0, BIG], 10, 0, 0),
        ("fee", [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(1, 0)], [0, 0, 0, 0], BIG, 0, 0),
        ("burn_a", [In::Real(BIG - 1, 0), In::Real(1, 0), In::Real(10, 0), In::Dummy], [0, 0, 0, 0], 10, BIG, 0),
        ("burn_r", [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(11, 0)], [0, 0, 0, 0], 10, 0, BIG),
    ];
    for (what, ins, outs, fee, burn_a, burn_r) in rows {
        let c = Case::new(ins, outs, fee, burn_a, burn_r, 0);
        assert_taints(&c.inputs(), &c.claimed(), what);
    }
    // The classic negative amount: an output of 2^64 - 5 "pays" 5 back, and the sum wraps.
    let c = Case::new([In::Dummy, In::Dummy, In::Real(20, 0), In::Dummy], [0, 0, 15, u64::MAX - 4], 10, 0, 0, 0);
    assert_taints(&c.inputs(), &c.claimed(), "a negative output");
}

/// §3.3: each sum is carry-checked — every term `< 2^63` (no range check fires) but the outputs
/// wrap past 2^64 to exactly the inputs' total.
#[test]
fn a_wrapping_sum_taints_in_either_group() {
    const M: u64 = (1 << 63) - 1;
    // Group R: 5 in, (2^63 - 1) * 2 + 7 = 2^64 + 5 out, which wraps to 5.
    let c = Case::new([In::Dummy, In::Dummy, In::Real(5, 0), In::Dummy], [0, 0, M, M], 7, 0, 0, 0);
    assert_taints(&c.inputs(), &c.claimed(), "group R wraps");
    let c = Case::new([In::Dummy, In::Dummy, In::Real(5, 0), In::Dummy], [0, 0, M, 0], M, 0, 7, 0);
    assert_taints(&c.inputs(), &c.claimed(), "group R wraps through fee and burn_r");
    // Group A: the same through out0 + out1 + burn_a.
    let c = Case::new([In::Real(5, TOKEN), In::Dummy, In::Real(10, 0), In::Dummy], [M, M, 0, 0], 10, 7, 0, TOKEN);
    assert_taints(&c.inputs(), &c.claimed(), "group A wraps");
}

/// §3.3: an output's asset is its slot's — structural, so an output note built with any other
/// asset has a commitment the guest never produces. No taint: the claimed digest is simply
/// unreachable, and the published one commits to the slot's asset.
#[test]
fn an_outputs_asset_is_its_slots() {
    for (k, forged) in [(0usize, 0u32), (1, TOKEN + 1), (2, TOKEN), (3, 1)] {
        let honest = mixed();
        let mut c = honest.clone();
        c.outs[k].asset = forged;
        let out = emulate(&c.inputs());
        assert_ne!(out, hidden::hidden_bundle_digest(&c.claimed()), "output {k} with asset {forged}");
        assert_ne!(out, tainted(&c.claimed()));
        // The builder never writes an output's asset: the witness is the honest one.
        assert_eq!(c.inputs(), honest.inputs());
        assert_eq!(out, hidden::hidden_bundle_digest(&honest.claimed()));
    }
    // Likewise an output's `from` (always pk_self) and `time` (always the bundle's), one at a time.
    let honest = mixed();
    let mut from = honest.clone();
    from.outs[2].from = [1; 8];
    let out = emulate(&from.inputs());
    assert_ne!(out, hidden::hidden_bundle_digest(&from.claimed()), "output 2 with another from");
    assert_eq!(out, hidden::hidden_bundle_digest(&honest.claimed()), "the guest committed from = pk_self");
    let mut time = honest.clone();
    time.outs[3].time = TIME + 1;
    let out = emulate(&time.inputs());
    assert_ne!(out, hidden::hidden_bundle_digest(&time.claimed()), "output 3 with another time");
    assert_eq!(out, hidden::hidden_bundle_digest(&honest.claimed()), "the guest committed the bundle's time");
}

/// §3.3: `burn_asset = A if burn_a != 0 else 0` — computed, never a witness word, so a burn cannot
/// name another asset, and a non-burn cannot name one at all.
#[test]
fn burn_asset_is_a_exactly_when_burn_a_is_nonzero() {
    let c = token_burn();
    let out = emulate(&c.inputs());
    assert_eq!(out, hidden::hidden_bundle_digest(&c.claimed()));
    for forged in [0, TOKEN + 1] {
        assert_ne!(out, hidden::hidden_bundle_digest(&HiddenDigestInput { burn_asset: forged, ..c.claimed() }), "burn names {forged}");
    }
    let c = mixed();
    let out = emulate(&c.inputs());
    assert_ne!(out, hidden::hidden_bundle_digest(&HiddenDigestInput { burn_asset: TOKEN, ..c.claimed() }), "a transfer names its asset");
    // burn_a's high word alone counts as nonzero.
    let c = Case::new([In::Real(1 << 32, TOKEN), In::Dummy, In::Real(10, 0), In::Dummy], [0, 0, 0, 0], 10, 1 << 32, 0, TOKEN);
    assert_eq!(c.claimed().burn_asset, TOKEN);
    assert_honest(&c, "burn_a = 2^32");
}

// ───────────────────────────── real proofs ─────────────────────────────

/// The hard requirement, measured: a mixed transfer (four real inputs, the worst case) proves at
/// tier 14 with the Production FRI profile the chain pins, publishes the host digest, and
/// verifies only against its own transaction binding — not another transaction's and not under
/// another guest's `hc`. Since H3 the chain's `ConfidentialExecutor` entry points
/// (`bundle_digest`, `bundle_proof_digest`, `verify_bundle`) *are* this guest's, so the proof is
/// checked through them too, exactly as `Ledger::check_bundle_proof` calls them.
#[test]
fn a_mixed_hidden_bundle_proves_at_tier_14_and_verifies_only_against_its_binding() {
    let c = mixed();
    let inputs = c.inputs();
    let di = c.claimed();
    assert_eq!(emulate(&inputs), hidden::hidden_bundle_digest(&di), "tainted witness");
    let started = std::time::Instant::now();
    let (proof, digest, tier) = prove_hidden_bundle(FriProfile::Production, &inputs, &BINDING_A, Backend::Cpu).unwrap();
    println!(
        "hidden bundle proved at tier {tier} in {:.1?} ({} proof bytes, Production FRI, CPU)",
        started.elapsed(),
        proof.len()
    );
    assert_eq!(tier, 14);
    assert_eq!(digest, hidden::hidden_bundle_digest(&di));
    let ex = ZkExecutor::new(FriProfile::Production);
    assert_eq!(ex.hidden_bundle_proof_digest(&proof).unwrap(), digest);
    let hc = ZkExecutor::hc_hidden_bundle();
    let started = std::time::Instant::now();
    ex.verify_hidden_bundle(&hc, &proof, &BINDING_A).unwrap();
    println!("verified (cold) in {:.1?}", started.elapsed());
    assert_eq!(
        ex.verify_hidden_bundle(&hc, &proof, &BINDING_B),
        Err(ConfidentialError::InvalidBundleProof("PublicValues".into())),
        "a proof bound to one transaction is refused for any other"
    );
    assert!(ex.verify_hidden_bundle(&ZkExecutor::hc_legacy_bundle(), &proof, &BINDING_A).is_err(), "another guest's hc");
    // The chain path (H3): the trait methods the ledger calls are the hidden guest's, against
    // the genesis `hc_bundle` (which is this guest's digest).
    use randprotocol_core::confidential::ConfidentialExecutor;
    assert_eq!(ZkExecutor::hc_bundle(), hc, "the chain pins the hidden guest");
    let core = randprotocol_zkvm::address::digest_input_of(
        di.anchor, di.nullifiers, di.commitments, di.fee, di.burn_a, di.burn_r, di.burn_asset, di.time,
    );
    assert_eq!(ex.bundle_digest(&core), digest, "the ledger recomputes the published digest");
    assert_eq!(ex.bundle_proof_digest(&proof).unwrap(), digest);
    assert_eq!(ex.verify_bundle(&ZkExecutor::hc_bundle(), &proof, &BINDING_A), Ok(()));
    assert_eq!(
        ex.verify_bundle(&ZkExecutor::hc_bundle(), &proof, &BINDING_B),
        Err(ConfidentialError::InvalidBundleProof("PublicValues".into())),
        "and through the trait a proof bound to one transaction is refused for any other"
    );
    let decoded = randprotocol_zkvm::executor::decode_canonical(&proof).unwrap();
    assert_eq!(decoded.public_log_height, ZkExecutor::hidden_bundle_heights().2);
    let mut trailing = proof.clone();
    trailing.push(0);
    assert_eq!(ex.verify_hidden_bundle(&hc, &trailing, &BINDING_A), Err(ConfidentialError::MalformedProof));
}

/// Proved the pre-binding way — against the empty public segment — the proof is refused whatever
/// binding it is checked against (Test profile: the refusal is on the declared height).
#[test]
fn a_hidden_bundle_proved_against_the_empty_segment_is_refused() {
    let c = token_only();
    let inputs = c.inputs();
    let (proof, exec) = Machine::new(FriProfile::Test)
        .prove_with(Backend::Cpu, ZkExecutor::hidden_bundle_program(), &inputs, &[], None)
        .unwrap();
    assert_eq!(exec.outputs, hidden::hidden_bundle_digest(&c.claimed()), "an honest witness: only the segment is wrong");
    let bytes = proof.to_bytes();
    let ex = ZkExecutor::new(FriProfile::Test);
    let refused = ConfidentialError::InvalidProof("public height not the transaction binding's".into());
    assert_eq!(ex.hidden_bundle_proof_digest(&bytes), Err(refused.clone()));
    for binding in [BINDING_A, [0; 8]] {
        assert_eq!(ex.verify_hidden_bundle(&ZkExecutor::hc_hidden_bundle(), &bytes, &binding), Err(refused.clone()));
        // …and through the trait the ledger calls (H3: the chain's bundle is this guest).
        use randprotocol_core::confidential::ConfidentialExecutor;
        assert_eq!(ex.verify_bundle(&ZkExecutor::hc_bundle(), &bytes, &binding), Err(refused.clone()));
    }
    use randprotocol_core::confidential::ConfidentialExecutor;
    assert_eq!(ex.bundle_proof_digest(&bytes), Err(refused));
}
