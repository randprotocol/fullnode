//! The hidden-asset bundle guest's cheating suite (spec
//! `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md` §6, task H2). `tests/
//! hidden_bundle.rs` shows, in the emulator, that each §3.3 check fires on a witness built to need
//! it; this file adds what the emulator alone cannot:
//!
//! - **Real proofs of each cheat** (`real_proof_*`, Production FRI, CPU, ~100 s and ~5.7 GB
//!   each). The guest *taints* rather than traps, so a dishonest witness still proves: each test
//!   asserts that the proof is produced and verifies against its transaction binding, and that
//!   the digest it publishes is **not** `hidden_bundle_digest` of the plaintext the cheat would
//!   claim — the ledger recomputes that digest with `bad = 0` and refuses the bundle. Where the
//!   check is a taint, the published digest is asserted to be exactly the claimed plaintext's
//!   `bad = 1` digest (the taint and nothing else moved it). One honest proof is the control.
//! - **A mutation fuzz** (`mutation_fuzz_*`, emulator only, ~60 s): random honest witnesses of
//!   every shape, each mutated — one word anywhere in the 1 204-word private input, two words, an
//!   amount moved between fields, a whole slot copied over another, two input slots swapped (a real
//!   note moved into the other asset group, membership intact), two output-side terms of one
//!   group pushed into `[2^62, 2^63)` — optionally rebalanced so the conservation sums do not
//!   mask the other checks. Every run is compared with an independent
//!   host model of spec §3.3 (`model`): the guest must publish exactly the honest digest of the
//!   mutated witness's own plaintext when the model finds the witness valid (the mutation made a
//!   different, legitimate transaction — a new output `r`, an unread dummy path word), and exactly
//!   its `bad = 1` digest otherwise. So no mutated run ever publishes an honest digest the model
//!   does not endorse.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes it, like `tests/hidden_bundle.rs`).
//!
//! Running: the real proofs are told apart by name. Fast only (the fuzz and the emulator
//! companions, ~60 s in `--release`):
//!
//! ```text
//! cargo test --release -p randprotocol-zkvm --test hidden_cheating -- --skip real_proof_
//! ```
//!
//! The real proofs only (thirteen, ~22 min). Each takes the workspace proving slot — the file
//! lock `<target-dir>/tmp/rand-proving-slot.lock` the node and client test binaries take — so they
//! run one at a time, within this binary and against every other session's proofs:
//!
//! ```text
//! cargo test --release -p randprotocol-zkvm --test hidden_cheating real_proof_
//! ```
//!
//! The fuzz's seed and iteration count: `HIDDEN_FUZZ_SEED` / `HIDDEN_FUZZ_ITERS` (a failure
//! prints both, and the iteration, so it replays exactly).

use std::sync::Mutex;

use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::executor::{prove_hidden_bundle, ZkExecutor};
use randprotocol_zkvm::hidden::{self, hidden_input as hi, slot_asset, HiddenDigestInput, HiddenOutput, HIDDEN_BUNDLE_DOMAIN, SLOTS};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{self, domain, Note, SpendKey, Word8, DEPTH};

/// The transaction binding every proof here is made against (`Transaction::binding`).
const BINDING_A: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
const TOKEN: u32 = 7;
const TIME: u32 = 5;
const MAX_CYCLES: usize = 1 << 20;
const BIG: u64 = 1 << 63;

/// One real proof at a time in this binary (~5.7 GB each): the default `cargo test` runs tests
/// on parallel threads, and thirteen concurrent Production proofs would not fit a shared machine.
/// Taken before the file lock below, so this binary's own tests queue here rather than each
/// holding a descriptor on the lock file.
static PROVING: Mutex<()> = Mutex::new(());

/// The workspace's proving slot: the same lock file `crates/randprotocol-node/tests/proving_slot/`
/// and its client twin take (`CARGO_TARGET_TMPDIR` is `<target-dir>/tmp`, one directory for every
/// crate), so a proof here never runs beside another session's bundle proofs. The only thing
/// this copy must agree on with those two is the path. The kernel drops the lock when the process
/// exits, so a killed run frees the slot.
struct ProvingSlot(std::fs::File);

impl Drop for ProvingSlot {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn proving_slot() -> ProvingSlot {
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("rand-proving-slot.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("opening the proving slot at {}: {e}", path.display()));
    let started = std::time::Instant::now();
    file.lock().expect("taking the proving slot");
    if started.elapsed() > std::time::Duration::from_secs(1) {
        println!("waited {:.1?} for the proving slot", started.elapsed());
    }
    ProvingSlot(file)
}

// ───────────────────────────── a seeded RNG ─────────────────────────────

/// SplitMix64: deterministic from its seed, so a failing fuzz iteration replays exactly.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
    /// Uniform in `0..n` (`n > 0`; the modulo bias is irrelevant here).
    fn below(&mut self, n: u64) -> u64 { self.next_u64() % n }
    /// Uniform in `0..=n`.
    fn upto(&mut self, n: u64) -> u64 { if n == u64::MAX { self.next_u64() } else { self.below(n + 1) } }
    fn chance(&mut self, percent: u64) -> bool { self.below(100) < percent }
    fn word8(&mut self) -> Word8 { std::array::from_fn(|_| self.next_u32()) }
}

// ───────────────────────────── witnesses ─────────────────────────────

/// An input slot of a test witness: a `Real` note is appended to the tree and spent with its
/// real path; a `Dummy` is a zero-value note, never in the tree, with a zero path.
#[derive(Clone, Copy)]
enum In {
    Real(u64, u32),
    Dummy,
}

/// A complete witness as a wallet builds it, plus the claimed plaintext's parts the tests need.
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
    /// Every note field and key drawn from `rng`; `filler` unrelated leaves precede the spent
    /// notes so every path is non-trivial. Output `k` is built with its slot's asset,
    /// `from = pk_self` and the bundle's time — what the guest commits to structurally.
    #[allow(clippy::too_many_arguments)]
    fn build(rng: &mut Rng, filler: usize, ins: [In; 4], outs: [u64; 4], fee: u64, burn_a: u64, burn_r: u64, asset_a: u32) -> Case {
        let sk = SpendKey(rng.word8());
        let me = sk.viewing_key().pk();
        let mut tree = CommitmentTree::new();
        for _ in 0..filler {
            tree.append(Note { pk: rng.word8(), from: rng.word8(), amount: rng.upto(1 << 40), asset: rng.next_u32(), time: 1, r: rng.word8() }.commitment());
        }
        let notes: Vec<Note> = ins
            .iter()
            .map(|i| match *i {
                In::Real(amount, asset) => Note { pk: me, from: rng.word8(), amount, asset, time: rng.upto(TIME as u64) as u32, r: rng.word8() },
                // A dummy's asset, sender and time are free (it carries no value).
                In::Dummy => Note { pk: me, from: rng.word8(), amount: 0, asset: rng.next_u32() % 4, time: rng.next_u32(), r: rng.word8() },
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
        let outs = std::array::from_fn(|k| Note { pk: rng.word8(), from: me, amount: outs[k], asset: slot_asset(k, asset_a), time: TIME, r: rng.word8() });
        Case { sk, ins, outs, anchor, fee, burn_a, burn_r, asset_a, time: TIME }
    }

    /// A fixed-seed build, for the real-proof cases.
    #[allow(clippy::too_many_arguments)]
    fn new(seed: u64, ins: [In; 4], outs: [u64; 4], fee: u64, burn_a: u64, burn_r: u64, asset_a: u32) -> Case {
        Case::build(&mut Rng(seed), 5, ins, outs, fee, burn_a, burn_r, asset_a)
    }

    fn inputs(&self) -> Vec<u32> {
        let outs = self.outs.map(|o| HiddenOutput { pk: o.pk, amount: o.amount, r: o.r });
        hidden::hidden_bundle_inputs(&self.sk, &self.ins, &outs, self.anchor, self.fee, self.burn_a, self.burn_r, self.asset_a, self.time)
    }

    /// The plaintext this witness claims — what a cheater would put on chain — computed from the
    /// notes the test holds, independently of the guest.
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
    emulate_or(inputs, || "emulating a fixed witness".into())
}

/// `emulate`, naming the run in the panic if the guest traps (a fuzz run: seed, base, mutation).
fn emulate_or(inputs: &[u32], ctx: impl FnOnce() -> String) -> Word8 {
    match execute(ZkExecutor::hidden_bundle_program(), inputs, &BINDING_A, MAX_CYCLES) {
        Ok(exec) => exec.outputs,
        Err(e) => panic!("{}: the guest trapped instead of tainting: {e:?}", ctx()),
    }
}

/// The claimed plaintext's digest with the guest's `bad` word set — what a tainted run publishes.
fn tainted(di: &HiddenDigestInput) -> Word8 {
    let mut msg = hidden::hidden_bundle_preimage(di);
    *msg.last_mut().unwrap() = 1;
    notes::hash(HIDDEN_BUNDLE_DOMAIN, &msg)
}

// ───────────────────────────── the reference model ─────────────────────────────

fn w8(v: &[u32], at: usize) -> Word8 { v[at..at + 8].try_into().unwrap() }
fn u64_at(v: &[u32], lo: usize, hi_at: usize) -> u64 { v[lo] as u64 | (v[hi_at] as u64) << 32 }

/// The root a leaf, its sibling path and its leaf index produce: `H(NODE, left, right)` per
/// level, the index consumed one bit per level from the bottom (`CommitmentTree`'s layout).
fn merkle_root(leaf: Word8, v: &[u32], path_at: usize, mut index: u32) -> Word8 {
    let mut node = leaf;
    for level in 0..DEPTH {
        let sib = w8(v, path_at + 8 * level);
        let mut msg = [0u32; 16];
        if index & 1 == 1 {
            msg[..8].copy_from_slice(&sib);
            msg[8..].copy_from_slice(&node);
        } else {
            msg[..8].copy_from_slice(&node);
            msg[8..].copy_from_slice(&sib);
        }
        node = notes::hash(domain::NODE, &msg);
        index >>= 1;
    }
    node
}

/// What a private-input vector means under spec §3.3, written from the spec rather than from the
/// guest: the plaintext it publishes and every §3.3 check it fails (empty = valid).
struct Model {
    claimed: HiddenDigestInput,
    fails: Vec<&'static str>,
}

impl Model {
    /// What the guest must publish for this vector: the honest digest if valid, else `bad = 1`.
    fn expected(&self) -> Word8 {
        if self.fails.is_empty() { hidden::hidden_bundle_digest(&self.claimed) } else { tainted(&self.claimed) }
    }
}

fn model(v: &[u32]) -> Model {
    assert_eq!(v.len(), hi::COUNT);
    let vk = SpendKey(w8(v, hi::SK)).viewing_key();
    let pk_self = vk.pk();
    let anchor = w8(v, hi::ANCHOR);
    let a = v[hi::ASSET_A];
    let time = v[hi::TIME];
    let mut fails = Vec::new();
    let mut nullifiers = [[0; 8]; SLOTS];
    let mut ins = [0u64; SLOTS];
    for k in 0..SLOTS {
        let b = hi::in_slot(k);
        // Every input is owned by pk_self: the guest never reads an owner word.
        let note = Note {
            pk: pk_self,
            from: w8(v, b + hi::S_FROM),
            amount: u64_at(v, b + hi::S_AMOUNT_LO, b + hi::S_AMOUNT_HI),
            asset: v[b + hi::S_ASSET],
            time: v[b + hi::S_TIME],
            r: w8(v, b + hi::S_R),
        };
        let cm = note.commitment();
        if note.amount != 0 {
            if merkle_root(cm, v, b + hi::S_PATH, v[b + hi::S_INDEX]) != anchor {
                fails.push("membership: root != anchor");
            }
            if note.asset != slot_asset(k, a) {
                fails.push(if k < 2 { "input asset != slot asset (A slot)" } else { "input asset != slot asset (R slot)" });
            }
        }
        nullifiers[k] = vk.nullifier(&cm);
        ins[k] = note.amount;
    }
    let mut outs = [0u64; SLOTS];
    let commitments = std::array::from_fn(|k| {
        let o = hi::out(k);
        outs[k] = u64_at(v, o + hi::O_AMOUNT_LO, o + hi::O_AMOUNT_HI);
        Note { pk: w8(v, o + hi::O_PK), from: pk_self, amount: outs[k], asset: slot_asset(k, a), time, r: w8(v, o + hi::O_R) }.commitment()
    });
    for i in 0..SLOTS {
        for j in (i + 1)..SLOTS {
            if nullifiers[i] == nullifiers[j] {
                fails.push("duplicate nullifier");
            }
            if commitments[i] == commitments[j] {
                fails.push("duplicate output commitment");
            }
        }
    }
    let fee = u64_at(v, hi::FEE_LO, hi::FEE_HI);
    let burn_a = u64_at(v, hi::BURN_A_LO, hi::BURN_A_HI);
    let burn_r = u64_at(v, hi::BURN_R_LO, hi::BURN_R_HI);
    for x in ins.iter().chain(outs.iter()).chain([fee, burn_a, burn_r].iter()) {
        if *x >= BIG {
            fails.push("amount >= 2^63");
        }
    }
    // Exact (non-wrapping) sums: a side that passes 2^64 is a carry failure, a mismatch of two
    // exact totals an imbalance.
    let total = |xs: &[u64]| xs.iter().try_fold(0u64, |s, x| s.checked_add(*x));
    for (ins, outs, carry, imbalance) in [
        (total(&ins[..2]), total(&[outs[0], outs[1], burn_a]), "asset-A sum passes 2^64", "asset-A conservation"),
        (total(&ins[2..]), total(&[outs[2], outs[3], fee, burn_r]), "RAND sum passes 2^64", "RAND conservation"),
    ] {
        match (ins, outs) {
            (Some(i), Some(o)) if i != o => fails.push(imbalance),
            (Some(_), Some(_)) => {}
            _ => fails.push(carry),
        }
    }
    let claimed = HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset: if burn_a != 0 { a } else { 0 }, time };
    Model { claimed, fails }
}

// ───────────────────────────── real proofs ─────────────────────────────

/// Proves `inputs` for real (Production FRI, CPU) under the file's lock and checks what every
/// case shares: a proof is produced at tier 14, it verifies under the hidden guest's `hc` with its
/// binding, the verifier reads back the digest the prover reported, and that digest is the
/// emulator's. Returns the published digest.
fn prove_and_verify(inputs: &[u32], what: &str) -> Word8 {
    let _in_binary = PROVING.lock().unwrap_or_else(|e| e.into_inner());
    let _slot = proving_slot();
    let started = std::time::Instant::now();
    let (proof, digest, tier) = prove_hidden_bundle(FriProfile::Production, inputs, &BINDING_A, Backend::Cpu)
        .unwrap_or_else(|e| panic!("{what}: the guest must taint, not trap — no proof: {e}"));
    let proved = started.elapsed();
    let ex = ZkExecutor::new(FriProfile::Production);
    let started = std::time::Instant::now();
    ex.verify_hidden_bundle(&ZkExecutor::hc_hidden_bundle(), &proof, &BINDING_A)
        .unwrap_or_else(|e| panic!("{what}: the proof must verify against its binding: {e:?}"));
    println!(
        "{what}: proved at tier {tier} in {proved:.1?}, {} proof bytes, verified in {:.1?} (Production FRI, CPU)",
        proof.len(),
        started.elapsed()
    );
    assert_eq!(tier, 14, "{what}");
    assert_eq!(ex.hidden_bundle_proof_digest(&proof).unwrap(), digest, "{what}: the verifier reads another digest");
    assert_eq!(emulate(inputs), digest, "{what}: prover and emulator disagree");
    digest
}

/// A cheat that the guest taints: the proof verifies, and its digest is exactly the claimed
/// plaintext's `bad = 1` digest — not the honest one the ledger recomputes, so the ledger refuses.
fn assert_real_proof_taints(inputs: &[u32], claimed: &HiddenDigestInput, what: &str) {
    let digest = prove_and_verify(inputs, what);
    let honest = hidden::hidden_bundle_digest(claimed);
    println!("{what}: published {:08x?}…, the ledger recomputes {:08x?}…", &digest[..2], &honest[..2]);
    assert_ne!(digest, honest, "{what}: a cheating proof published the digest the ledger accepts");
    assert_eq!(digest, tainted(claimed), "{what}: expected exactly the claimed plaintext's bad = 1 digest");
    assert_eq!(model(inputs).expected(), digest, "{what}: the reference model disagrees");
}

/// The mixed transfer every cheat below departs from: four real inputs, 800 of the token in
/// slots 0–1, 1 050 RAND in slots 2–3, a fee of 10.
fn mixed(seed: u64) -> Case {
    Case::new(seed, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN)
}

/// The control: an honest witness proves, verifies, and publishes exactly the digest the ledger
/// recomputes from its plaintext.
#[test]
fn real_proof_honest_control_publishes_the_ledgers_digest() {
    let c = mixed(1);
    let digest = prove_and_verify(&c.inputs(), "honest control");
    assert_eq!(digest, hidden::hidden_bundle_digest(&c.claimed()));
    assert!(model(&c.inputs()).fails.is_empty());
}

/// Value moved from the token group into RAND: A-inputs 500, A-outputs 400, and the 100 appear
/// as extra RAND. Both groups' sums fail.
#[test]
fn real_proof_value_moved_from_an_a_slot_into_an_r_slot() {
    let c = Case::new(2, [In::Real(300, TOKEN), In::Real(200, TOKEN), In::Real(1_000, 0), In::Dummy], [300, 100, 990, 100], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["asset-A conservation", "RAND conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "value A -> R");
}

/// A real note of another token (TOKEN + 1) spent in an A slot of a bundle whose `A` is TOKEN:
/// the note is in the tree and the sums balance, so the asset check alone fires.
#[test]
fn real_proof_an_a_slot_input_of_another_asset() {
    let c = Case::new(3, [In::Real(500, TOKEN + 1), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["input asset != slot asset (A slot)"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "A-slot input of another asset");
}

/// A real token note (TOKEN, the bundle's own `A`) spent in R slot 2 and counted as RAND: the note
/// is in the tree, its nullifier is unique and both sums balance, so the R-slot asset check (the
/// note's asset against the guest-zeroed word) alone fires — spec §6's "an R-slot input whose
/// asset is not 0".
#[test]
fn real_proof_an_r_slot_input_whose_asset_is_not_0() {
    let c = Case::new(13, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, TOKEN), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["input asset != slot asset (R slot)"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "R-slot input of the token");
}

/// The reverse of the A -> R case: RAND in, token out — 100 RAND disappear from group R and
/// reappear as 100 of the token. Both groups' comparisons fail.
#[test]
fn real_proof_value_moved_from_an_r_slot_into_an_a_slot() {
    let c = Case::new(14, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [700, 200, 800, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["asset-A conservation", "RAND conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "value R -> A");
}

/// Group A mints one unit of the token and group R balances: only the asset-A comparison fires, so
/// this proof is what stands if that comparison alone were removed (a cross-group move trips both).
#[test]
fn real_proof_group_a_alone_mints_one() {
    let c = Case::new(15, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [601, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["asset-A conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "group A mints one");
}

/// Group R mints one RAND and group A balances: only the RAND comparison fires.
#[test]
fn real_proof_group_r_alone_mints_one() {
    let c = Case::new(16, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 141], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["RAND conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "group R mints one");
}

/// A dummy slot (a note never in the tree) claiming value that its group's first output absorbs,
/// so both sums balance and only the membership check is left to fire.
fn dummy_carrying(seed: u64, k: usize, amount: u64) -> Case {
    let mut ins = [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)];
    let held = [500u64, 300, 1_000, 50];
    ins[k] = In::Dummy;
    let a_total = held[0] + held[1] - if k < 2 { held[k] } else { 0 };
    let r_total = held[2] + held[3] - if k >= 2 { held[k] } else { 0 };
    let mut c = Case::new(seed, ins, [a_total, 0, r_total - 10, 0], 10, 0, 0, TOKEN);
    c.ins[k].0.amount = amount;
    c.ins[k].0.asset = slot_asset(k, TOKEN);
    c.outs[if k < 2 { 0 } else { 2 }].amount += amount;
    assert_eq!(model(&c.inputs()).fails, ["membership: root != anchor"], "slot {k} carrying {amount}");
    c
}

/// A dummy carrying value in its high amount word only (`amount_lo = 0`, `amount_hi = 1`): a skip
/// that read only the low word would let it through.
#[test]
fn real_proof_a_dummy_carrying_value_in_its_high_word() {
    let c = dummy_carrying(4, 1, 1 << 32);
    assert_eq!(c.inputs()[hi::in_slot(1) + hi::S_AMOUNT_LO], 0);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "dummy, amount_lo = 0, amount_hi = 1");
}

/// The reverse: a dummy carrying value in its low word only (`amount_lo = 100`, `amount_hi = 0`).
#[test]
fn real_proof_a_dummy_carrying_value_in_its_low_word() {
    let c = dummy_carrying(5, 3, 100);
    assert_eq!(c.inputs()[hi::in_slot(3) + hi::S_AMOUNT_HI], 0);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "dummy, amount_lo = 100, amount_hi = 0");
}

/// A forged note (10 000 of the token, never minted) spent in slot 0 with the path and index of a
/// real leaf — slot 1's note — under the real anchor: the path proves a different leaf.
#[test]
fn real_proof_a_path_that_proves_a_different_leaf() {
    let honest = mixed(6);
    let mut c = honest.clone();
    c.ins[0].0.amount = 10_000;
    c.ins[0].1 = honest.ins[1].1;
    c.ins[0].2 = honest.ins[1].2;
    c.outs[0].amount += 10_000 - 500;
    assert_eq!(model(&c.inputs()).fails, ["membership: root != anchor"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "path of another leaf");
}

/// A forged note that *is* a leaf — of a tree the cheater built — with its genuine path in that
/// tree, while the published anchor is the real tree's root: the path's root is not `anchor`.
/// (Publishing the fake tree's own root instead is untainted, and refused by the ledger's
/// known-root check, which is not the guest's job.)
#[test]
fn real_proof_a_path_to_a_root_other_than_the_anchor() {
    let mut c = mixed(7);
    let forged = Note { amount: 10_000, ..c.ins[0].0 };
    let mut fake = CommitmentTree::new();
    fake.append(forged.commitment());
    let (path, index) = fake.path_for(&forged.commitment()).unwrap();
    assert_ne!(fake.root(), c.anchor);
    c.ins[0] = (forged, path, index);
    c.outs[0].amount += 10_000 - 500;
    assert_eq!(model(&c.inputs()).fails, ["membership: root != anchor"]);
    // (Emulated, before the proof.) Had the cheater put all four spent notes in the fake tree and
    // published *its* root, nothing would taint: the guest proves membership under the published
    // anchor, whatever tree it is. What refuses that bundle is the ledger's known-root check.
    let mut whole = CommitmentTree::new();
    for (n, ..) in &c.ins {
        whole.append(n.commitment());
    }
    let mut own = c.clone();
    own.anchor = whole.root();
    for k in 0..4 {
        let (p, i) = whole.path_for(&own.ins[k].0.commitment()).unwrap();
        own.ins[k] = (own.ins[k].0, p, i);
    }
    assert!(model(&own.inputs()).fails.is_empty());
    assert_eq!(emulate(&own.inputs()), hidden::hidden_bundle_digest(&own.claimed()));
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "path to another root");
}

/// A token burn (`burn_a = 300`, `A` = TOKEN) whose claimed plaintext names another burn asset —
/// 0 (a RAND burn) or TOKEN + 1. `burn_asset` is not a witness word, it is `A` masked by
/// `burn_a != 0`: the proof publishes TOKEN, the one honest value, and no forged plaintext
/// reproduces its digest. Structural rather than a taint, so the published digest is the honest
/// digest of the true plaintext.
#[test]
fn real_proof_a_burn_claiming_another_asset() {
    let c = Case::new(8, [In::Real(500, TOKEN), In::Dummy, In::Real(100, 0), In::Dummy], [200, 0, 90, 0], 10, 300, 0, TOKEN);
    let digest = prove_and_verify(&c.inputs(), "burn naming another asset");
    assert_eq!(c.claimed().burn_asset, TOKEN);
    assert_eq!(digest, hidden::hidden_bundle_digest(&c.claimed()), "the true plaintext");
    // What pins the mask is the equality just above (the published digest is the honest digest of
    // the plaintext with burn_asset = A) together with the control: the loop below holds for any
    // guest whatsoever — two different preimages hash apart — so it only states what a forged
    // claim meets on the ledger, it is not the evidence.
    for forged in [0, TOKEN + 1] {
        let claim = HiddenDigestInput { burn_asset: forged, ..c.claimed() };
        let recomputed = hidden::hidden_bundle_digest(&claim);
        println!("burn claimed as asset {forged}: published {:08x?}…, the ledger recomputes {:08x?}…", &digest[..2], &recomputed[..2]);
        assert_ne!(digest, recomputed, "burn claimed as asset {forged}");
        assert_ne!(digest, tainted(&claim));
    }
    // And the witness that *sets* A to the forged asset while spending TOKEN notes taints on the
    // input asset check (emulated: the same guest the proof above ran).
    let mut v = c.inputs();
    v[hi::ASSET_A] = TOKEN + 1;
    let m = model(&v);
    assert_eq!(m.fails, ["input asset != slot asset (A slot)"]);
    assert_eq!(m.claimed.burn_asset, TOKEN + 1);
    assert_eq!(emulate(&v), tainted(&m.claimed));
}

/// A 2^63 RAND output paid for by 2^63 + 10 of real RAND inputs: no sum carries and both balance,
/// so the range check on `out2` is the only barrier to a note at or above 2^63.
#[test]
fn real_proof_an_r_output_at_2_63_with_only_the_range_check_to_stop_it() {
    let c = Case::new(9, [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(11, 0)], [0, 0, BIG, 0], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs()).fails, ["amount >= 2^63"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "RAND output of 2^63");
}

/// The RAND sum wrapping past 2^64 with every term below 2^63: 5 in, `(2^63 - 1) · 2 + 7` out,
/// which is 5 mod 2^64. No range check fires; the carry check is the only barrier.
#[test]
fn real_proof_an_r_sum_that_wraps_with_only_the_carry_check_to_stop_it() {
    const M: u64 = BIG - 1;
    let c = Case::new(10, [In::Dummy, In::Dummy, In::Real(5, 0), In::Dummy], [0, 0, M, M], 7, 0, 0, 0);
    assert_eq!(model(&c.inputs()).fails, ["RAND sum passes 2^64"]);
    assert_eq!(c.outs[2].amount.wrapping_add(c.outs[3].amount).wrapping_add(7), 5, "the sum wraps to exactly the input");
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "RAND sum wrapping");
}

// ───────────────────────────── the mutation fuzz ─────────────────────────────

/// Splits `total` into `n` parts, each below 2^63 (`total` must fit: at most `n · (2^63 − 1)`).
fn split(rng: &mut Rng, total: u64, n: usize) -> Vec<u64> {
    let mut rest = total;
    let mut parts = Vec::with_capacity(n);
    for i in 0..n - 1 {
        // The least this part can take so the remaining parts still fit below 2^63 each.
        let room = (n - 1 - i) as u128 * (BIG - 1) as u128;
        let lo = (rest as u128).saturating_sub(room) as u64;
        let hi_part = rest.min(BIG - 1);
        let part = lo + rng.upto(hi_part - lo);
        parts.push(part);
        rest -= part;
    }
    parts.push(rest);
    parts
}

/// A random honest witness: each input slot a dummy or a real note of its slot's asset; `A` zero
/// a quarter of the time; amounts small, large, up to 2^62, or in `[2^62, 2^63)` (so a group's
/// total can pass 2^63 and the range and carry checks meet outputs near their bounds); each
/// group's total split at random, every part below 2^63, between its outputs, its burn (a quarter
/// of the time) and, for RAND, the fee (often small).
fn random_honest(rng: &mut Rng) -> Case {
    let asset_a = match rng.below(4) {
        0 => 0,
        1 => TOKEN,
        _ => rng.next_u32() | 1,
    };
    let amount = |rng: &mut Rng| match rng.below(4) {
        0 => 1 + rng.below(1_000_000),
        1 => 1 + rng.below(1 << 40),
        2 => 1 + rng.below((1 << 62) - 1),
        _ => (1 << 62) + rng.below(1 << 62),
    };
    let ins: [In; 4] = std::array::from_fn(|k| if rng.chance(30) { In::Dummy } else { In::Real(amount(rng), slot_asset(k, asset_a)) });
    let held = |k: usize| if let In::Real(x, _) = ins[k] { x } else { 0 };
    let (ta, tr) = (held(0) + held(1), held(2) + held(3));
    // Group A: out0, out1, burn_a.
    let a = if rng.chance(25) { split(rng, ta, 3) } else { [split(rng, ta, 2), vec![0]].concat() };
    // Group R: out2, out3, fee, burn_r — the fee small half the time.
    let fee = if rng.chance(50) { rng.upto(tr.min(1_000)) } else { u64::MAX };
    let r = match (fee, rng.chance(25)) {
        (u64::MAX, true) => split(rng, tr, 4),
        (u64::MAX, false) => [split(rng, tr, 3), vec![0]].concat(),
        (fee, true) => { let p = split(rng, tr - fee, 3); vec![p[0], p[1], fee, p[2]] }
        (fee, false) => { let p = split(rng, tr - fee, 2); vec![p[0], p[1], fee, 0] }
    };
    let filler = rng.below(7) as usize;
    Case::build(rng, filler, ins, [a[0], a[1], r[0], r[1]], r[2], a[2], r[3], asset_a)
}

/// The eleven 64-bit amount fields, as (lo, hi) word indices: in0..3, out0..3, fee, burn_a, burn_r.
fn amount_fields() -> [(usize, usize); 11] {
    let i = |k: usize| (hi::in_slot(k) + hi::S_AMOUNT_LO, hi::in_slot(k) + hi::S_AMOUNT_HI);
    let o = |k: usize| (hi::out(k) + hi::O_AMOUNT_LO, hi::out(k) + hi::O_AMOUNT_HI);
    [i(0), i(1), i(2), i(3), o(0), o(1), o(2), o(3), (hi::FEE_LO, hi::FEE_HI), (hi::BURN_A_LO, hi::BURN_A_HI), (hi::BURN_R_LO, hi::BURN_R_HI)]
}

fn set_u64(v: &mut [u32], (lo, hi_at): (usize, usize), x: u64) {
    v[lo] = x as u32;
    v[hi_at] = (x >> 32) as u32;
}

/// The word indices that are not Merkle path words (sk, note words, indices, anchor, outputs,
/// fee, burns, `A`, time — 180 of the 1 204): paths are 85 % of the vector, and a uniform pick
/// would spend most of the budget on them.
fn non_path_words() -> Vec<usize> {
    (0..hi::COUNT)
        .filter(|&i| !(0..SLOTS).any(|k| (hi::in_slot(k) + hi::S_PATH..hi::in_slot(k) + hi::S_INDEX).contains(&i)))
        .collect()
}

/// One word changed: a bit flipped, ±1, a random value, zero, or all ones.
fn mutate_word(rng: &mut Rng, v: &mut [u32], i: usize) -> String {
    let old = v[i];
    v[i] = match rng.below(6) {
        0 => old ^ (1 << rng.below(32)),
        1 => old.wrapping_add(1),
        2 => old.wrapping_sub(1),
        3 => rng.next_u32(),
        4 => 0,
        _ => u32::MAX,
    };
    if v[i] == old {
        v[i] ^= 1;
    }
    format!("word {i}: {old:#x} -> {:#x}", v[i])
}

/// Sets out0 and out2 so both groups' wrapping sums balance again — so a mutation of an amount is
/// judged by the checks the conservation sums would otherwise mask (membership, asset, range,
/// carry, duplicates).
fn rebalance(v: &mut [u32]) {
    let f = amount_fields();
    let get = |v: &[u32], n: usize| u64_at(v, f[n].0, f[n].1);
    let a_in = get(v, 0).wrapping_add(get(v, 1));
    set_u64(v, f[4], a_in.wrapping_sub(get(v, 5)).wrapping_sub(get(v, 9)));
    let r_in = get(v, 2).wrapping_add(get(v, 3));
    set_u64(v, f[6], r_in.wrapping_sub(get(v, 7)).wrapping_sub(get(v, 8)).wrapping_sub(get(v, 10)));
}

/// One mutation of an honest vector, described for a failure message.
fn mutate(rng: &mut Rng, v: &mut [u32], non_path: &[usize]) -> String {
    let what = match rng.below(13) {
        // One word anywhere in the whole private input.
        0..=2 => {
            let i = rng.below(hi::COUNT as u64) as usize;
            mutate_word(rng, v, i)
        }
        // One word that is not a path word.
        3..=5 => {
            let i = non_path[rng.below(non_path.len() as u64) as usize];
            mutate_word(rng, v, i)
        }
        // Two words: one anywhere, one that is not a path word.
        6 => {
            let (i, j) = (rng.below(hi::COUNT as u64) as usize, non_path[rng.below(non_path.len() as u64) as usize]);
            format!("{}; {}", mutate_word(rng, v, i), mutate_word(rng, v, j))
        }
        // Value moved between two amount fields, by a small, a huge or a 2^63-straddling delta.
        7 => {
            let f = amount_fields();
            let (x, y) = (rng.below(11) as usize, rng.below(11) as usize);
            let (vx, vy) = (u64_at(v, f[x].0, f[x].1), u64_at(v, f[y].0, f[y].1));
            let d = match rng.below(5) {
                0 => 1 + rng.below(1_000),
                1 => BIG,
                2 => BIG - 1 - rng.below(1_000),
                // Any part of y's own value: y stays in range, x may cross 2^63 while every sum
                // still balances and carries nothing — the range check alone stands in the way.
                3 => rng.upto(vy),
                _ => rng.next_u64(),
            };
            set_u64(v, f[x], vx.wrapping_add(d));
            let vy = if x == y { vx.wrapping_add(d) } else { vy };
            set_u64(v, f[y], vy.wrapping_sub(d));
            format!("amount field {x} += {d:#x}, field {y} -= it")
        }
        // A whole input slot (note, path, index) copied over another: the same note twice.
        8 => {
            let (i, j) = (rng.below(4) as usize, rng.below(4) as usize);
            let (bi, bj) = (hi::in_slot(i), hi::in_slot(j));
            let src: Vec<u32> = v[bi..bi + hi::IN_SLOT_WORDS].to_vec();
            v[bj..bj + hi::IN_SLOT_WORDS].copy_from_slice(&src);
            format!("input slot {i} copied over slot {j}")
        }
        // A whole output copied over another: the same note minted twice.
        9 => {
            let (i, j) = (rng.below(4) as usize, rng.below(4) as usize);
            let src: Vec<u32> = v[hi::out(i)..hi::out(i) + hi::OUT_WORDS].to_vec();
            v[hi::out(j)..hi::out(j) + hi::OUT_WORDS].copy_from_slice(&src);
            format!("output {i} copied over output {j}")
        }
        // Two output-side terms of one group set in `[2^62, 2^63)`, then the group's first
        // output rebalanced (wrapping): every term stays below 2^63, the sum wraps past 2^64 to
        // exactly the inputs' total — the carry check alone stands in the way.
        10 => {
            let f = amount_fields();
            let (first, others): (usize, &[usize]) = if rng.chance(50) { (4, &[5, 9]) } else { (6, &[7, 8, 10]) };
            let mut picked = others.to_vec();
            if picked.len() == 3 {
                picked.remove(rng.below(3) as usize);
            }
            for &n in &picked {
                set_u64(v, f[n], (1 << 62) + rng.below(1 << 62));
            }
            rebalance(v);
            return format!("fields {picked:?} set in [2^62, 2^63), field {first} rebalanced");
        }
        // Two input slots swapped, whole (note, path, index): every real note keeps its
        // membership and every nullifier stays distinct, but a note that crosses between slots
        // 0–1 and 2–3 now sits in the other asset group — with `A != 0`, a token note in an R
        // slot or a RAND note in an A slot, which only the per-slot asset check stops. Usually
        // then re-split so both groups balance with every term small (each group's whole input
        // to its first output, the fee kept when it fits), so no other check fires.
        _ => {
            let i = rng.below(4) as usize;
            let j = (i + 1 + rng.below(3) as usize) % 4;
            let (bi, bj) = (hi::in_slot(i), hi::in_slot(j));
            let (si, sj): (Vec<u32>, Vec<u32>) = (v[bi..bi + hi::IN_SLOT_WORDS].to_vec(), v[bj..bj + hi::IN_SLOT_WORDS].to_vec());
            v[bi..bi + hi::IN_SLOT_WORDS].copy_from_slice(&sj);
            v[bj..bj + hi::IN_SLOT_WORDS].copy_from_slice(&si);
            let what = format!("input slots {i} and {j} swapped");
            match rng.below(4) {
                0 => return what,
                1 => {
                    rebalance(v);
                    return format!("{what}, then rebalanced");
                }
                _ => {
                    let f = amount_fields();
                    let get = |v: &[u32], n: usize| u64_at(v, f[n].0, f[n].1);
                    let (a_in, r_in) = (get(v, 0).wrapping_add(get(v, 1)), get(v, 2).wrapping_add(get(v, 3)));
                    let fee = if get(v, 8) <= r_in { get(v, 8) } else { 0 };
                    for (n, x) in [(4, a_in), (5, 0), (9, 0), (6, r_in - fee), (7, 0), (8, fee), (10, 0)] {
                        set_u64(v, f[n], x);
                    }
                    return format!("{what}, then re-split (each group's input to its first output)");
                }
            }
        }
    };
    if rng.chance(50) {
        rebalance(v);
        format!("{what}, then rebalanced")
    } else {
        what
    }
}

/// Per-check run counts, keyed by the model's label.
type Counts = std::collections::BTreeMap<&'static str, usize>;

/// The fuzz itself; returns (valid runs, tainted runs, how many runs failed each check, how many
/// failed that check *and no other* — the runs where it alone stood between the witness and an
/// honest digest).
fn run_fuzz(seed: u64, bases: usize, per_base: usize) -> (usize, usize, Counts, Counts) {
    let mut rng = Rng(seed);
    let non_path = non_path_words();
    let (mut valid, mut tainted_runs) = (0, 0);
    let mut by_check = Counts::new();
    let mut alone = Counts::new();
    for base in 0..bases {
        let c = random_honest(&mut rng);
        let honest = c.inputs();
        let m = model(&honest);
        assert!(m.fails.is_empty(), "seed {seed:#x}, base {base}: the generator built a dishonest witness: {:?}", m.fails);
        assert_eq!(m.claimed, c.claimed(), "seed {seed:#x}, base {base}: the model reads another plaintext than the builder wrote");
        assert_eq!(emulate_or(&honest, || format!("seed {seed:#x}, base {base}, honest")), hidden::hidden_bundle_digest(&m.claimed), "seed {seed:#x}, base {base}: an honest witness did not publish its honest digest");
        for n in 0..per_base {
            let mut v = honest.clone();
            let what = mutate(&mut rng, &mut v, &non_path);
            let m = model(&v);
            let out = emulate_or(&v, || format!("seed {seed:#x} (HIDDEN_FUZZ_SEED), base {base}, mutation {n}: {what}"));
            let expected = m.expected();
            assert_eq!(
                out, expected,
                "seed {seed:#x} (HIDDEN_FUZZ_SEED), base {base}, mutation {n}: {what}. Model failures: {:?}. The guest published \
                 {} — expected {}",
                m.fails,
                if out == hidden::hidden_bundle_digest(&m.claimed) { "the HONEST digest" } else if out == tainted(&m.claimed) { "the tainted digest" } else { "neither the honest nor the tainted digest" },
                if m.fails.is_empty() { "the honest digest" } else { "the tainted digest" },
            );
            if m.fails.is_empty() {
                valid += 1;
            } else {
                // The brief's property, stated directly: a mutation the model rejects never
                // publishes the honest digest of the plaintext it would claim.
                assert_ne!(out, hidden::hidden_bundle_digest(&m.claimed), "seed {seed:#x}, base {base}, mutation {n}: {what}");
                tainted_runs += 1;
                let seen: std::collections::BTreeSet<&'static str> = m.fails.iter().copied().collect();
                if seen.len() == 1 {
                    *alone.entry(*seen.first().unwrap()).or_insert(0) += 1;
                }
                for f in seen {
                    *by_check.entry(f).or_insert(0) += 1;
                }
            }
        }
    }
    (valid, tainted_runs, by_check, alone)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().map(|s| {
        let s = s.trim();
        s.strip_prefix("0x").map_or_else(|| s.parse().unwrap(), |h| u64::from_str_radix(h, 16).unwrap())
    }).unwrap_or(default)
}

/// The mutation fuzz: `HIDDEN_FUZZ_ITERS` mutated runs (default 25 000, about a minute in
/// `--release`) over random honest bases (twenty mutations each), seed `HIDDEN_FUZZ_SEED`
/// (default fixed). Every run must publish exactly what the reference model says — the honest
/// digest of a valid witness's own plaintext, or the `bad = 1` digest of an invalid one's.
#[test]
fn mutation_fuzz_every_mutated_witness_publishes_the_honest_digest_only_when_valid() {
    const PER_BASE: usize = 20;
    let seed = env_u64("HIDDEN_FUZZ_SEED", 0x4832_6675_7a7a_0001);
    let iters = env_u64("HIDDEN_FUZZ_ITERS", 25_000) as usize;
    let started = std::time::Instant::now();
    let (valid, tainted_runs, by_check, alone) = run_fuzz(seed, iters.div_ceil(PER_BASE), PER_BASE);
    println!(
        "mutation fuzz, seed {seed:#x}: {} runs over {} bases in {:.1?} — {valid} valid (a different legitimate transaction), \
         {tainted_runs} tainted; runs failing each check: {by_check:?}; failing it and nothing else: {alone:?}",
        valid + tainted_runs,
        iters.div_ceil(PER_BASE),
        started.elapsed()
    );
    // Every §3.3 check was exercised as the ONLY failure of some run — so removing any one of them
    // from the guest makes some run publish an honest digest the model rejects — and some
    // mutations were legitimate: the fuzz is neither all-taint nor all-valid.
    for check in [
        "membership: root != anchor",
        "input asset != slot asset (A slot)",
        "input asset != slot asset (R slot)",
        "duplicate nullifier",
        "duplicate output commitment",
        "amount >= 2^63",
        "asset-A conservation",
        "RAND conservation",
        "asset-A sum passes 2^64",
        "RAND sum passes 2^64",
    ] {
        assert!(alone.get(check).copied().unwrap_or(0) > 0, "no mutation failed {check:?} alone (in any company: {:?})", by_check.get(check));
    }
    assert!(valid > 0);
}

/// The model itself is checked against hand-made witnesses (both kinds of result), so a model bug
/// cannot hide a guest bug by agreeing with it.
#[test]
fn mutation_fuzz_the_model_agrees_with_hand_built_cases() {
    let c = mixed(11);
    let m = model(&c.inputs());
    assert!(m.fails.is_empty());
    assert_eq!(m.claimed, c.claimed());
    // A new output r: a different, legitimate transaction.
    let mut v = c.inputs();
    v[hi::out(1) + hi::O_R] ^= 1;
    assert!(model(&v).fails.is_empty());
    assert_ne!(model(&v).claimed, c.claimed());
    // A dummy's path words are never read.
    let d = Case::new(12, [In::Real(500, TOKEN), In::Dummy, In::Real(100, 0), In::Dummy], [500, 0, 90, 0], 10, 0, 0, TOKEN);
    let mut v = d.inputs();
    v[hi::in_slot(1) + hi::S_PATH + 40] = 0xdead;
    assert!(model(&v).fails.is_empty());
    assert_eq!(emulate(&v), emulate(&d.inputs()));
    // A real input's path word is.
    let mut v = c.inputs();
    v[hi::in_slot(2) + hi::S_PATH + 40] ^= 4;
    assert_eq!(model(&v).fails, ["membership: root != anchor"]);
    // The eleven fields `amount_fields` names are the builder's.
    let f = amount_fields();
    let v = c.inputs();
    for k in 0..4 {
        assert_eq!(u64_at(&v, f[k].0, f[k].1), c.ins[k].0.amount);
        assert_eq!(u64_at(&v, f[4 + k].0, f[4 + k].1), c.outs[k].amount);
    }
    assert_eq!(u64_at(&v, f[8].0, f[8].1), 10);
    assert_eq!(non_path_words().len(), hi::COUNT - SLOTS * DEPTH * 8);
}
