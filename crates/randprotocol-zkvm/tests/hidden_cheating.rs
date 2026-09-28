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
//! - **A mutation fuzz** (`mutation_fuzz_*`, emulator only, ~185 s): random honest witnesses of
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
//! - **Split authorisation** (delegated proving, Phase 2, spec
//!   `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.4): bundle guest v3 runs
//!   under the same model and fuzz — `emulate_or` runs every v1/v2 witness's v3 twin (`to_v3`)
//!   and holds it to the model's v3 expectation, and a second fuzz mutates the v3-only words
//!   (`nk`, the salt). The six §4.4 cases (an auth proof for another `nk`, for another binding,
//!   with another salt; a third `auth_commit`; an auth proof replayed onto another transaction;
//!   both guests against the empty segment) each have an emulator companion naming the one half
//!   of Task 4's rule that stands, and a `real_proof_` twin (three v3 bundle proofs and four auth
//!   proofs in all, each made once per run). `tests/auth_cheating.rs` has the auth guest alone.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes it, like `tests/hidden_bundle.rs`).
//!
//! Running: the real proofs are told apart by name. Fast only (the fuzz and the emulator
//! companions, ~185 s in `--release`):
//!
//! ```text
//! cargo test --release -p randprotocol-zkvm --test hidden_cheating -- --skip real_proof_
//! ```
//!
//! The real proofs only (twenty-six: the nineteen v1/v2 cheats, ~32 min, and the seven split-
//! authorisation cases, ~6 min — `real_proof_split_`, `real_proof_an_auth_`,
//! `real_proof_a_bundle_whose_`, `real_proof_auth_commit_`, `real_proof_both_guests_`). Each takes the workspace proving slot — the file
//! lock `<target-dir>/tmp/rand-proving-slot.lock` the node and client test binaries take — so they
//! run one at a time, within this binary and against every other session's proofs:
//!
//! ```text
//! cargo test --release -p randprotocol-zkvm --test hidden_cheating real_proof_
//! ```
//!
//! The fuzz's seed and iteration count: `HIDDEN_FUZZ_SEED` / `HIDDEN_FUZZ_ITERS` (a failure
//! prints both, and the iteration, so it replays exactly).

use std::sync::{Mutex, OnceLock};

use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::executor::{prove_bundle_for, ZkExecutor};
use randprotocol_zkvm::auth;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::hash::public_digest;
use randprotocol_zkvm::tables::cpu::pv;
use randprotocol_zkvm::hidden::{self, hidden_input as hi, hidden_input_v3 as hi3, slot_asset, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput, HIDDEN_BUNDLE_DOMAIN, SLOTS};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::machine::{Backend, FriProfile, Machine, Proof};
use randprotocol_zkvm::notes::{self, domain, Note, SpendKey, ViewingKey, Word8, DEPTH};

/// The transaction binding every proof here is made against (`Transaction::binding`).
const BINDING_A: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
const TOKEN: u32 = 7;
const TIME: u32 = 5;
const MAX_CYCLES: usize = 1 << 20;
const BIG: u64 = 1 << 63;

/// One real proof at a time in this binary (~5.7 GB each): the default `cargo test` runs tests
/// on parallel threads, and nineteen concurrent Production proofs would not fit a shared machine.
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
///
/// On a v1/v2-layout vector, runs **both** hidden guests — v1 (`guests::bundle_hidden`, chains 14
/// and 15) and the branch-free v2 (`guests::bundle_hidden_v2`, INT-2 / GV-1) — and insists they
/// publish the same digest, so the whole suite (every hand-built cheat, the model cross-checks,
/// and every fuzz mutation) holds v2 to v1's relation exactly: a branch-free guest that masks a
/// check instead of jumping over it must not have lost one (a cheat v1 taints that v2 does not) or
/// gained one (an honest or merely unusual witness — a dummy's path word, an unread one in v1 —
/// that v2 taints). The dummy rule, the membership and ownership taints and the asset checks are
/// the ones v2 rewrote; they are exactly where the two runs would part.
///
/// It then runs bundle guest v3 (split authorisation) on the vector's v3 twin (`to_v3`, under
/// `EMULATE_SALT`) and insists it publishes exactly what the model expects of that twin — the v3
/// honest digest (with `c = H(AUTH, nk, salt)`) when valid, its `bad = 1` twin otherwise — so
/// every cheat and fuzz mutation holds v3 to the same relation. Returns v1's digest.
///
/// On a v3-layout vector (1 212 words), runs v3 alone and returns its digest.
fn emulate_or(inputs: &[u32], ctx: impl FnOnce() -> String) -> Word8 {
    let run = |program, inputs: &[u32]| match execute(program, inputs, &BINDING_A, MAX_CYCLES) {
        Ok(exec) => Ok(exec.outputs),
        Err(e) => Err(format!("{e:?}")),
    };
    if inputs.len() == hi3::COUNT {
        return run(ZkExecutor::hidden_bundle_v3_program(), inputs).unwrap_or_else(|e| panic!("{}: v3 trapped instead of tainting: {e}", ctx()));
    }
    let v1 = match (run(ZkExecutor::hidden_bundle_program(), inputs), run(ZkExecutor::hidden_bundle_v2_program(), inputs)) {
        (Ok(v1), Ok(v2)) if v1 == v2 => v1,
        (Ok(v1), Ok(v2)) => panic!("{}: v1 and the branch-free v2 publish different digests: {v1:08x?} vs {v2:08x?}", ctx()),
        (e1, e2) => panic!("{}: a guest trapped instead of tainting: v1 {e1:?}, v2 {e2:?}", ctx()),
    };
    let twin = to_v3(inputs, &EMULATE_SALT);
    let m = model(&twin, Guest::V3);
    match run(ZkExecutor::hidden_bundle_v3_program(), &twin) {
        Ok(v3) if v3 == m.expected() => {}
        Ok(v3) => panic!(
            "{}: v3 on the v3 twin published {v3:08x?} — the model expects the {} digest {:08x?} (failures {:?})",
            ctx(),
            if m.fails.is_empty() { "honest" } else { "tainted" },
            m.expected(),
            m.fails
        ),
        Err(e) => panic!("{}: v3 trapped instead of tainting: {e}", ctx()),
    }
    v1
}

/// The guest the real proofs below prove: v1 by default, the branch-free v2 with
/// `HIDDEN_BUNDLE_GUEST=v2` — the nineteen real-proof cheats then run against v2 end to end
/// (`cargo test --release -p randprotocol-zkvm --test hidden_cheating real_proof_` with the
/// variable set, ~32 min).
fn proved_guest() -> Word8 {
    match std::env::var("HIDDEN_BUNDLE_GUEST").as_deref() {
        Ok("v2") => ZkExecutor::hc_hidden_bundle_v2(),
        Ok("v1") | Err(_) => ZkExecutor::hc_hidden_bundle(),
        Ok(other) => panic!("HIDDEN_BUNDLE_GUEST={other}: expected v1 or v2"),
    }
}

/// The claimed plaintext's digest with the guest's `bad` word set — what a tainted run publishes.
fn tainted(di: &HiddenDigestInput) -> Word8 {
    let mut msg = hidden::hidden_bundle_preimage(di);
    *msg.last_mut().unwrap() = 1;
    notes::hash(HIDDEN_BUNDLE_DOMAIN, &msg)
}

/// `tainted`'s v3 twin: the v3 digest with `bad = 1`.
fn tainted_v3(di: &HiddenDigestInputV3) -> Word8 {
    let mut msg = hidden::hidden_bundle_preimage_v3(di);
    *msg.last_mut().unwrap() = 1;
    notes::hash(HIDDEN_BUNDLE_DOMAIN, &msg)
}

/// The v3 witness of a v1/v2 witness — dishonest ones included (`tests/hidden_bundle.rs`'s
/// helper): the same words at the same indices, `nk = H(NK, sk)` in place of `sk`, and `salt`
/// appended. So every witness this file builds for v1 and v2 runs on v3 too.
fn to_v3(inputs: &[u32], salt: &Word8) -> Vec<u32> {
    assert_eq!(inputs.len(), hi::COUNT);
    let sk = SpendKey(w8(inputs, hi::SK));
    let mut v = inputs.to_vec();
    v[hi3::NK..hi3::NK + 8].copy_from_slice(&sk.viewing_key().nk);
    v.extend_from_slice(salt);
    v
}

/// The salt `emulate_or` runs a v1 witness's v3 twin under.
const EMULATE_SALT: Word8 = [0xe3u32, 0x5a17_0001, 2, 3, 4, 5, 6, 0x8000_0000];

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
    /// A v3 vector's `c = H(AUTH, nk, salt)`; `None` for the v1/v2 layout.
    auth_commit: Option<Word8>,
}

impl Model {
    /// What the guest must publish for this vector: the honest digest if valid, else `bad = 1` —
    /// v1's digest for the v1/v2 layout, v3's (with `c`) for v3's.
    fn expected(&self) -> Word8 {
        match self.claimed_v3() {
            None if self.fails.is_empty() => hidden::hidden_bundle_digest(&self.claimed),
            None => tainted(&self.claimed),
            Some(di) if self.fails.is_empty() => hidden::hidden_bundle_digest_v3(&di),
            Some(di) => tainted_v3(&di),
        }
    }

    /// The plaintext a v3 chain holds for this vector (`None` for the v1/v2 layout).
    fn claimed_v3(&self) -> Option<HiddenDigestInputV3> {
        self.auth_commit.map(|auth_commit| HiddenDigestInputV3 { base: self.claimed, auth_commit })
    }
}

/// Which witness layout a vector is: v1's (`hidden_input`, 1 204 words, `sk` at 0 — the layout
/// v2 shares) or v3's (`hidden_input_v3`, 1 212 words, `nk` at 0 and the salt appended).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Guest {
    V1,
    V3,
}

fn model(v: &[u32], guest: Guest) -> Model {
    // Every offset but words 0..8 and the appended salt is shared (`hidden_input_v3` re-exports
    // `hidden_input`'s), so the checks below read both layouts alike; only the key differs: v1/v2
    // derive `nk` from the spend key, v3 is handed `nk` itself — and publishes
    // `c = H(AUTH, nk, salt)` in its digest.
    let (vk, auth_commit) = match guest {
        Guest::V1 => {
            assert_eq!(v.len(), hi::COUNT);
            (SpendKey(w8(v, hi::SK)).viewing_key(), None)
        }
        Guest::V3 => {
            assert_eq!(v.len(), hi3::COUNT);
            let vk = ViewingKey { nk: w8(v, hi3::NK) };
            (vk, Some(auth::auth_commit(&vk.nk, &w8(v, hi3::SALT))))
        }
    };
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
    Model { claimed, fails, auth_commit }
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
    let hc = proved_guest();
    let (proof, digest, tier) = prove_bundle_for(&hc, FriProfile::Production, inputs, &BINDING_A, Backend::Cpu)
        .unwrap_or_else(|e| panic!("{what}: the guest must taint, not trap — no proof: {e}"));
    let proved = started.elapsed();
    let ex = ZkExecutor::new(FriProfile::Production);
    let started = std::time::Instant::now();
    ex.verify_hidden_bundle(&hc, &proof, &BINDING_A)
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
    assert_eq!(model(inputs, Guest::V1).expected(), digest, "{what}: the reference model disagrees");
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
    assert!(model(&c.inputs(), Guest::V1).fails.is_empty());
}

/// Value moved from the token group into RAND: A-inputs 500, A-outputs 400, and the 100 appear
/// as extra RAND. Both groups' sums fail.
#[test]
fn real_proof_value_moved_from_an_a_slot_into_an_r_slot() {
    let c = Case::new(2, [In::Real(300, TOKEN), In::Real(200, TOKEN), In::Real(1_000, 0), In::Dummy], [300, 100, 990, 100], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["asset-A conservation", "RAND conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "value A -> R");
}

/// A real note of another token (TOKEN + 1) spent in an A slot of a bundle whose `A` is TOKEN:
/// the note is in the tree and the sums balance, so the asset check alone fires.
#[test]
fn real_proof_an_a_slot_input_of_another_asset() {
    let c = Case::new(3, [In::Real(500, TOKEN + 1), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["input asset != slot asset (A slot)"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "A-slot input of another asset");
}

/// A real token note (TOKEN, the bundle's own `A`) spent in R slot 2 and counted as RAND: the note
/// is in the tree, its nullifier is unique and both sums balance, so the R-slot asset check (the
/// note's asset against the guest-zeroed word) alone fires — spec §6's "an R-slot input whose
/// asset is not 0".
#[test]
fn real_proof_an_r_slot_input_whose_asset_is_not_0() {
    let c = Case::new(13, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, TOKEN), In::Real(50, 0)], [600, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["input asset != slot asset (R slot)"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "R-slot input of the token");
}

/// The reverse of the A -> R case: RAND in, token out — 100 RAND disappear from group R and
/// reappear as 100 of the token. Both groups' comparisons fail.
#[test]
fn real_proof_value_moved_from_an_r_slot_into_an_a_slot() {
    let c = Case::new(14, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [700, 200, 800, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["asset-A conservation", "RAND conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "value R -> A");
}

/// Group A mints one unit of the token and group R balances: only the asset-A comparison fires, so
/// this proof is what stands if that comparison alone were removed (a cross-group move trips both).
#[test]
fn real_proof_group_a_alone_mints_one() {
    let c = Case::new(15, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [601, 200, 900, 140], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["asset-A conservation"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "group A mints one");
}

/// Group R mints one RAND and group A balances: only the RAND comparison fires.
#[test]
fn real_proof_group_r_alone_mints_one() {
    let c = Case::new(16, [In::Real(500, TOKEN), In::Real(300, TOKEN), In::Real(1_000, 0), In::Real(50, 0)], [600, 200, 900, 141], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["RAND conservation"]);
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
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["membership: root != anchor"], "slot {k} carrying {amount}");
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
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["membership: root != anchor"]);
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
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["membership: root != anchor"]);
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
    assert!(model(&own.inputs(), Guest::V1).fails.is_empty());
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
    let m = model(&v, Guest::V1);
    assert_eq!(m.fails, ["input asset != slot asset (A slot)"]);
    assert_eq!(m.claimed.burn_asset, TOKEN + 1);
    assert_eq!(emulate(&v), tainted(&m.claimed));
}

/// A 2^63 RAND output paid for by 2^63 + 10 of real RAND inputs: no sum carries and both balance,
/// so the range check on `out2` is the only barrier to a note at or above 2^63.
#[test]
fn real_proof_an_r_output_at_2_63_with_only_the_range_check_to_stop_it() {
    let c = Case::new(9, [In::Dummy, In::Dummy, In::Real(BIG - 1, 0), In::Real(11, 0)], [0, 0, BIG, 0], 10, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["amount >= 2^63"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "RAND output of 2^63");
}

/// The RAND sum wrapping past 2^64 with every term below 2^63: 5 in, `(2^63 - 1) · 2 + 7` out,
/// which is 5 mod 2^64. No range check fires; the carry check is the only barrier.
#[test]
fn real_proof_an_r_sum_that_wraps_with_only_the_carry_check_to_stop_it() {
    const M: u64 = BIG - 1;
    let c = Case::new(10, [In::Dummy, In::Dummy, In::Real(5, 0), In::Dummy], [0, 0, M, M], 7, 0, 0, 0);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["RAND sum passes 2^64"]);
    assert_eq!(c.outs[2].amount.wrapping_add(c.outs[3].amount).wrapping_add(7), 5, "the sum wraps to exactly the input");
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "RAND sum wrapping");
}

/// The A side of the 2^63 barrier: a token output of exactly 2^63 paid for by 2^63 of real
/// token inputs (2^63 − 1 and 1) — no sum carries and both balance, so the range check on
/// `out0` is the only barrier to a private-asset note at or above 2^63, the twin of the RAND
/// output case above.
#[test]
fn real_proof_an_a_output_at_2_63_with_only_the_range_check_to_stop_it() {
    let c = Case::new(17, [In::Real(BIG - 1, TOKEN), In::Real(1, TOKEN), In::Dummy, In::Dummy], [BIG, 0, 0, 0], 0, 0, 0, TOKEN);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["amount >= 2^63"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "token output of 2^63");
}

/// Two real inputs whose paths are each genuine — but against different roots of the one
/// growing tree: slot 0's witness was taken against an EARLIER root (the tree grew after: the
/// stale-anchor race a wallet hits when it builds a witness per note), slot 1's against the
/// published anchor. `real_proof_a_path_to_a_root_other_than_the_anchor` moves one input to a
/// foreign tree; here every spent note sits in the one real tree and both paths verify, each
/// against its own root — and the guest admits exactly one anchor.
#[test]
fn real_proof_two_real_inputs_whose_paths_reach_different_roots() {
    let mut rng = Rng(18);
    let sk = SpendKey(rng.word8());
    let me = sk.viewing_key().pk();
    let note = |rng: &mut Rng, amount: u64, asset: u32| Note { pk: me, from: rng.word8(), amount, asset, time: rng.upto(TIME as u64) as u32, r: rng.word8() };
    let mut tree = CommitmentTree::new();
    for _ in 0..3 {
        tree.append(Note { pk: rng.word8(), from: rng.word8(), amount: rng.upto(1 << 40), asset: rng.next_u32(), time: 1, r: rng.word8() }.commitment());
    }
    let n0 = note(&mut rng, 500, TOKEN);
    tree.append(n0.commitment());
    // Slot 0's witness, against the root of the tree as it then was.
    let (p0, i0) = tree.path_for(&n0.commitment()).unwrap();
    let root_old = tree.root();
    // The tree grows: two unrelated leaves, then the bundle's other three notes.
    for _ in 0..2 {
        tree.append(Note { pk: rng.word8(), from: rng.word8(), amount: rng.upto(1 << 40), asset: rng.next_u32(), time: 1, r: rng.word8() }.commitment());
    }
    let n1 = note(&mut rng, 300, TOKEN);
    let n2 = note(&mut rng, 1_000, 0);
    let n3 = note(&mut rng, 50, 0);
    for n in [&n1, &n2, &n3] {
        tree.append(n.commitment());
    }
    let anchor = tree.root();
    assert_ne!(root_old, anchor);
    let (p1, i1) = tree.path_for(&n1.commitment()).unwrap();
    let (p2, i2) = tree.path_for(&n2.commitment()).unwrap();
    let (p3, i3) = tree.path_for(&n3.commitment()).unwrap();
    let o = [600, 200, 900, 140];
    let outs = std::array::from_fn(|k| Note { pk: rng.word8(), from: me, amount: o[k], asset: slot_asset(k, TOKEN), time: TIME, r: rng.word8() });
    let c = Case { sk, ins: [(n0, p0, i0), (n1, p1, i1), (n2, p2, i2), (n3, p3, i3)], outs, anchor, fee: 10, burn_a: 0, burn_r: 0, asset_a: TOKEN, time: TIME };
    let v = c.inputs();
    // Each path is genuine — against its own root.
    assert_eq!(merkle_root(n0.commitment(), &v, hi::in_slot(0) + hi::S_PATH, i0), root_old, "slot 0's path must reach the older root");
    assert_eq!(merkle_root(n1.commitment(), &v, hi::in_slot(1) + hi::S_PATH, i1), anchor, "slot 1's path must reach the anchor");
    assert_eq!(model(&v, Guest::V1).fails, ["membership: root != anchor"]);
    assert_real_proof_taints(&v, &c.claimed(), "two inputs, two roots");
}

/// A note owned by another key, spent under the key that does not own it. The victim's note is
/// a genuine leaf of the one real tree; the cheater stages its fields in slot 0 with the victim
/// leaf's genuine path — but the guest derives every input's owner from the proven spend key
/// (structural binding: the witness carries no owner word), so the commitment it recomputes is
/// not the victim's leaf and the membership check taints, and the nullifier it publishes never
/// names the victim's note.
#[test]
fn real_proof_spending_a_note_owned_by_another_key() {
    let mut rng = Rng(19);
    let cheater = SpendKey(rng.word8());
    let victim = SpendKey(rng.word8());
    let me = cheater.viewing_key().pk();
    let note = |rng: &mut Rng, amount: u64, asset: u32| Note { pk: me, from: rng.word8(), amount, asset, time: rng.upto(TIME as u64) as u32, r: rng.word8() };
    let mut tree = CommitmentTree::new();
    for _ in 0..3 {
        tree.append(Note { pk: rng.word8(), from: rng.word8(), amount: rng.upto(1 << 40), asset: rng.next_u32(), time: 1, r: rng.word8() }.commitment());
    }
    // The victim's note, genuinely in the tree: 10 000 of the token.
    let victim_note = Note { pk: victim.viewing_key().pk(), from: rng.word8(), amount: 10_000, asset: TOKEN, time: rng.upto(TIME as u64) as u32, r: rng.word8() };
    tree.append(victim_note.commitment());
    let n1 = note(&mut rng, 300, TOKEN);
    let n2 = note(&mut rng, 1_000, 0);
    let n3 = note(&mut rng, 50, 0);
    for n in [&n1, &n2, &n3] {
        tree.append(n.commitment());
    }
    let anchor = tree.root();
    let (pv, iv) = tree.path_for(&victim_note.commitment()).unwrap();
    let (p1, i1) = tree.path_for(&n1.commitment()).unwrap();
    let (p2, i2) = tree.path_for(&n2.commitment()).unwrap();
    let (p3, i3) = tree.path_for(&n3.commitment()).unwrap();
    // What the cheater writes into slot 0: the victim note's fields, staged under the cheater's
    // own key (the input words carry no owner — the guest supplies pk_self).
    let stolen = Note { pk: me, ..victim_note };
    assert_ne!(stolen.commitment(), victim_note.commitment(), "ownership is structural: staging under another key commits to another leaf");
    let o = [10_300, 0, 1_040, 0];
    let outs = std::array::from_fn(|k| Note { pk: rng.word8(), from: me, amount: o[k], asset: slot_asset(k, TOKEN), time: TIME, r: rng.word8() });
    let c = Case { sk: cheater, ins: [(stolen, pv, iv), (n1, p1, i1), (n2, p2, i2), (n3, p3, i3)], outs, anchor, fee: 10, burn_a: 0, burn_r: 0, asset_a: TOKEN, time: TIME };
    let v = c.inputs();
    // The path genuinely proves the VICTIM's leaf under the anchor — membership of the attacked
    // note is fine; only the ownership substitution defeats the spend.
    assert_eq!(merkle_root(victim_note.commitment(), &v, hi::in_slot(0) + hi::S_PATH, iv), anchor);
    // And the nullifier the guest derives for slot 0 is not the victim note's: the spend would
    // not even nullify what it attacks.
    assert_ne!(c.claimed().nullifiers[0], victim.viewing_key().nullifier(&victim_note.commitment()));
    assert_eq!(model(&v, Guest::V1).fails, ["membership: root != anchor"]);
    assert_real_proof_taints(&v, &c.claimed(), "spending another key's note");
}

/// An output note whose asset or time differs from the bundle's fields — a commitment the
/// guest never produces. An output's `from`, asset and time are not witness words
/// (`hidden_input` has no field for them): the guest commits every output with `from = pk_self`,
/// its slot's asset and the bundle's (published) time, so the published digest is the honest
/// digest of the true plaintext and no forged plaintext naming a mislabelled output reproduces
/// it. Structural, like `real_proof_a_burn_claiming_another_asset` — which covers the burn
/// claim; this is the output-note side.
#[test]
fn real_proof_an_output_naming_another_asset_or_time() {
    let c = mixed(20);
    let digest = prove_and_verify(&c.inputs(), "output naming another asset or time");
    assert_eq!(digest, hidden::hidden_bundle_digest(&c.claimed()), "the true plaintext");
    // As with the burn: the equality above is the pin; the loop states what a forged claim
    // meets on the ledger (two different preimages hash apart for any guest).
    let me = c.sk.viewing_key().pk();
    for (k, asset, time, label) in [
        (0, TOKEN + 1, TIME, "A-slot output of another asset"),
        (2, TOKEN, TIME, "R-slot output of the token"),
        (1, TOKEN, TIME + 1, "A-slot output at another time"),
        (3, 0, TIME + 1, "R-slot output at another time"),
    ] {
        let o = &c.outs[k];
        let forged = Note { pk: o.pk, from: me, amount: o.amount, asset, time, r: o.r }.commitment();
        assert_ne!(forged, c.claimed().commitments[k], "{label}");
        let mut claim = c.claimed();
        claim.commitments[k] = forged;
        let recomputed = hidden::hidden_bundle_digest(&claim);
        println!("{label}: published {:08x?}…, the ledger recomputes {:08x?}…", &digest[..2], &recomputed[..2]);
        assert_ne!(digest, recomputed, "{label}");
        assert_ne!(digest, tainted(&claim), "{label}");
    }
    // The only lever over the outputs' time is the bundle's TIME word — and moving it moves the
    // published `time` field with it (emulated: the same guest the proof above ran), so an
    // output and the public field cannot disagree.
    let mut v = c.inputs();
    v[hi::TIME] = TIME + 1;
    let m = model(&v, Guest::V1);
    assert!(m.fails.is_empty());
    assert_eq!(m.claimed.time, TIME + 1);
    assert_eq!(emulate(&v), hidden::hidden_bundle_digest(&m.claimed));
}

/// Monotone taint: the guest ORs each check's failure bit into `BAD` and nothing clears it
/// (`emit_or_into` is monotone), so a violation at the program's FIRST taint point — slot 0's
/// root-vs-anchor comparison — followed by a pass at every later check (slot 0's asset, slots
/// 1–3 whole, duplicates, range, both sums) must still publish `bad = 1`. If any later pass
/// could wash the taint out, this proof would publish the honest digest.
#[test]
fn real_proof_a_taint_at_the_first_check_survives_every_later_pass() {
    let c = dummy_carrying(21, 0, 700);
    assert_eq!(model(&c.inputs(), Guest::V1).fails, ["membership: root != anchor"]);
    assert_real_proof_taints(&c.inputs(), &c.claimed(), "an early taint, all later checks passing");
}

// ─────────────── split authorisation: bundle guest v3 and the auth guest (spec §4.4) ───────────────
//
// Task 4's rule, which these cases anticipate: a v3 bundle in the transaction whose binding is
// `B` is valid iff (a) its bundle proof verifies against `B` and publishes
// `hidden_bundle_digest_v3(base, auth_commit)` with `bad = 0` — `auth_commit` being the
// transaction's field — and (b) an auth proof verifies against the SAME `B` and publishes
// `c == auth_commit`. Each case below is one the spec lists as "accepted if the check were
// missing": the emulator companion shows which half of the rule is the only thing standing, the
// `real_proof_` twin shows it on real proofs (Production FRI, CPU).
//
// The owner holds sk₁ (`split_case`'s `mixed(30)`), the transaction is `BINDING_A`, the salt
// `SALT_1`; the cheater — a delegated prover holding the owner's `nk` and salt, as every prover
// does — holds sk₂. Seven proofs serve every case (three v3 bundle proofs, ~100 s and ~5.7 GB
// each, and four auth proofs, ~7 s each), each made once per run and shared through a `OnceLock`.

/// Transaction B's binding: `BINDING_A` with one bit of its last word flipped.
const BINDING_B: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_fffe];
/// The owner's per-transaction salt, and another (as a second transaction of the owner's draws).
const SALT_1: Word8 = [0x5a17_0001, 0x0bad_cafe, 3, 4, 5, 6, 7, 0x8000_0001];
const SALT_2: Word8 = [0x5a17_0002, 0x0bad_cafe, 3, 4, 5, 6, 7, 0x8000_0001];

impl Case {
    /// The v3 witness a light client hands its prover (`hidden::hidden_bundle_inputs_v3`).
    fn inputs_v3(&self, salt: &Word8) -> Vec<u32> {
        let outs = self.outs.map(|o| HiddenOutput { pk: o.pk, amount: o.amount, r: o.r });
        let v = hidden::hidden_bundle_inputs_v3(&self.sk.viewing_key(), salt, &self.ins, &outs, self.anchor, self.fee, self.burn_a, self.burn_r, self.asset_a, self.time);
        assert_eq!(v, to_v3(&self.inputs(), salt), "the v3 builder moved a shared word");
        v
    }

    /// What a v3 chain holds for this case under `salt`: the plaintext and `c = H(AUTH, nk, salt)`.
    fn claimed_v3(&self, salt: &Word8) -> HiddenDigestInputV3 {
        HiddenDigestInputV3 { base: self.claimed(), auth_commit: auth::auth_commit(&self.sk.viewing_key().nk, salt) }
    }
}

/// Which half of Task 4's rule refuses a v3 bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    /// (a) the bundle proof does not verify against the transaction's binding.
    BundleProof,
    /// (a) its published digest is not `hidden_bundle_digest_v3(base, auth_commit)`.
    BundleDigest,
    /// (b) the auth proof does not verify against the transaction's binding.
    AuthProof,
    /// (b) its published `c` is not the transaction's `auth_commit`.
    AuthCommit,
}

/// The rule's content half — what it checks of the two published values, given that both proofs
/// verified: the bundle's digest against the recomputed v3 digest, the auth proof's `c` against the
/// transaction's field.
fn content_rule(base: &HiddenDigestInput, auth_commit: &Word8, bundle_digest: &Word8, auth_c: &Word8) -> Result<(), Refused> {
    if *bundle_digest != hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 { base: *base, auth_commit: *auth_commit }) {
        return Err(Refused::BundleDigest);
    }
    if auth_c != auth_commit {
        return Err(Refused::AuthCommit);
    }
    Ok(())
}

/// The auth guest's output on a real run (the emulator; the public segment is `binding`).
fn emulate_auth(sk: &SpendKey, salt: &Word8, binding: &[u32]) -> Word8 {
    let exec = execute(&guests::auth(), &auth::auth_inputs(sk, salt), binding, MAX_CYCLES).expect("the auth guest never traps");
    assert!(exec.halted);
    w8(&exec.outputs, 0)
}

/// The owner's transaction A, the cheater's key and the v3 witnesses the cases prove:
/// `honest` (transaction A, `SALT_1`), `redirected` (transaction B: A with output 0 paid to the
/// cheater, the same `nk` and salt — so the same `c`) and `cheater_nk` (A's witness with the
/// cheater's `nk` in the owner's place).
struct Split {
    owner: Case,
    cheater: SpendKey,
    redirected: Case,
}

fn split_case() -> Split {
    let owner = mixed(30);
    let cheater = SpendKey(Rng(31).word8());
    let mut redirected = owner.clone();
    redirected.outs[0].pk = cheater.viewing_key().pk();
    Split { owner, cheater, redirected }
}

impl Split {
    fn c1(&self) -> Word8 { auth::auth_commit(&self.owner.sk.viewing_key().nk, &SALT_1) }
    fn honest(&self) -> Vec<u32> { self.owner.inputs_v3(&SALT_1) }
    fn redirected(&self) -> Vec<u32> { self.redirected.inputs_v3(&SALT_1) }
    fn cheater_nk(&self) -> Vec<u32> {
        let mut v = self.honest();
        v[hi3::NK..hi3::NK + 8].copy_from_slice(&self.cheater.viewing_key().nk);
        v
    }
}

/// An auth proof for a different nk: the bundle is proved with the owner's `nk₁` — its digest
/// carries `c₁` — and the auth proof is made from the cheater's sk₂ with the same salt. The bundle
/// is honest in every respect, so the ONLY check that stands is (b)'s `c == auth_commit`: with the
/// field at `c₁` the auth proof's `c₂` misses it, and with the field moved to `c₂` the bundle's
/// digest misses. And the cheater cannot re-prove the bundle with its own `nk₂` either: the notes
/// are owned by `H(PK, nk₁)`, so that witness taints on membership.
#[test]
fn an_auth_proof_for_a_different_nk() {
    let s = split_case();
    let base = s.owner.claimed();
    let published = emulate(&s.honest());
    assert_eq!(published, hidden::hidden_bundle_digest_v3(&s.owner.claimed_v3(&SALT_1)), "the bundle is honest, c₁ in its digest");
    let c1 = emulate_auth(&s.owner.sk, &SALT_1, &BINDING_A);
    let c2 = emulate_auth(&s.cheater, &SALT_1, &BINDING_A);
    assert_eq!(c1, s.c1());
    assert_eq!(c2, auth::auth_commit(&s.cheater.viewing_key().nk, &SALT_1));
    assert_ne!(c2, s.c1());
    assert_eq!(content_rule(&base, &c1, &published, &c1), Ok(()), "the owner's own auth proof: the control");
    assert_eq!(content_rule(&base, &c1, &published, &c2), Err(Refused::AuthCommit), "the field at c₁: only the auth check catches it");
    assert_eq!(content_rule(&base, &c2, &published, &c2), Err(Refused::BundleDigest), "the field moved to c₂");
    // The bundle re-proved with the cheater's nk₂: tainted (membership), and its c is c₂.
    let v = s.cheater_nk();
    let m = model(&v, Guest::V3);
    assert_eq!(m.fails, ["membership: root != anchor"; 4]);
    assert_eq!(m.auth_commit, Some(c2));
    let tainted_digest = emulate(&v);
    assert_eq!(tainted_digest, tainted_v3(&m.claimed_v3().unwrap()));
    assert_eq!(content_rule(&m.claimed, &c2, &tainted_digest, &c2), Err(Refused::BundleDigest), "nk₂'s bundle: the taint");
}

/// An auth proof for a different binding. The auth guest never reads its public segment — its
/// output is the same under transaction A's binding, B's and the empty one — so all that ties an
/// auth proof to its transaction is `H_PUB`, the digest of the segment the proof was made with,
/// and those three digests differ. The real twin shows the refusal.
#[test]
fn an_auth_proof_for_a_different_binding() {
    let s = split_case();
    let c = emulate_auth(&s.owner.sk, &SALT_1, &BINDING_A);
    assert_eq!(emulate_auth(&s.owner.sk, &SALT_1, &BINDING_B), c);
    assert_eq!(emulate_auth(&s.owner.sk, &SALT_1, &[]), c);
    let (a, b, empty) = (public_digest(&BINDING_A), public_digest(&BINDING_B), public_digest(&[]));
    assert!(a != b && a != empty && b != empty, "the three segments' H_PUB");
}

/// A bundle whose `c` uses a different salt than the auth proof: the bundle with salt₁ publishes
/// `c₁ = H(AUTH, nk₁, salt₁)`, the auth proof (the owner's own key, salt₂) publishes
/// `c₃ = H(AUTH, nk₁, salt₂)` — each honest for its own inputs, and no field value satisfies both.
/// Either way round.
#[test]
fn a_bundle_whose_c_uses_a_different_salt_than_the_auth_proof() {
    let s = split_case();
    let base = s.owner.claimed();
    let nk1 = s.owner.sk.viewing_key().nk;
    for (bundle_salt, auth_salt) in [(SALT_1, SALT_2), (SALT_2, SALT_1)] {
        let published = emulate(&s.owner.inputs_v3(&bundle_salt));
        let c_bundle = auth::auth_commit(&nk1, &bundle_salt);
        assert_eq!(published, hidden::hidden_bundle_digest_v3(&s.owner.claimed_v3(&bundle_salt)), "the bundle is honest for its own salt");
        let c_auth = emulate_auth(&s.owner.sk, &auth_salt, &BINDING_A);
        assert_eq!(c_auth, auth::auth_commit(&nk1, &auth_salt), "the auth proof is honest for its own salt");
        assert_ne!(c_auth, c_bundle);
        assert_eq!(content_rule(&base, &c_bundle, &published, &c_auth), Err(Refused::AuthCommit));
        assert_eq!(content_rule(&base, &c_auth, &published, &c_auth), Err(Refused::BundleDigest));
    }
}

/// `auth_commit` in the transaction differing from either proof: a third value `x` in the field.
/// The ledger recomputes the v3 digest with `x`, which is neither the bundle proof's published
/// digest (honest or tainted) — so (a) refuses whatever the auth proof says.
#[test]
fn auth_commit_in_the_bundle_differing_from_either_proof() {
    let s = split_case();
    let base = s.owner.claimed();
    let published = emulate(&s.honest());
    let c1 = s.c1();
    let c2 = auth::auth_commit(&s.cheater.viewing_key().nk, &SALT_1);
    let mut rng = Rng(32);
    for x in [rng.word8(), [0; 8], { let mut y = c1; y[7] ^= 1; y }] {
        assert!(x != c1 && x != c2);
        let recomputed = hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 { base, auth_commit: x });
        assert_ne!(published, recomputed);
        assert_ne!(published, tainted_v3(&HiddenDigestInputV3 { base, auth_commit: x }));
        for auth_c in [c1, c2, x] {
            assert_eq!(content_rule(&base, &x, &published, &auth_c), Err(Refused::BundleDigest), "field x, auth c {auth_c:08x?}");
        }
    }
}

/// An auth proof replayed from another transaction. The owner's transaction A (its bundle and auth
/// proof, both public once gossiped); the prover — holding `nk₁` and salt₁, as every prover does
/// — builds transaction B, the same spend with output 0 paid to itself, and proves B's bundle
/// honestly: same `nk`, same salt, so B's digest carries the same `c₁` and B's field is `c₁`.
/// Every content check passes — A's auth proof publishes exactly `c₁` — so the binding alone
/// (B's `H_PUB` ≠ A's) refuses the replay, which only the real twin can show.
#[test]
fn an_auth_proof_replayed_from_another_transaction() {
    let s = split_case();
    let base_b = s.redirected.claimed();
    assert_ne!(base_b, s.owner.claimed(), "B pays another output");
    let published_b = emulate(&s.redirected());
    assert_eq!(published_b, hidden::hidden_bundle_digest_v3(&s.redirected.claimed_v3(&SALT_1)));
    let c_from_a = emulate_auth(&s.owner.sk, &SALT_1, &BINDING_A);
    assert_eq!(content_rule(&base_b, &s.c1(), &published_b, &c_from_a), Ok(()), "the content is no barrier to the replay");
    assert_ne!(public_digest(&BINDING_A), public_digest(&BINDING_B));
}

/// Task 5b's binding on both guests: neither the v3 bundle guest nor the auth guest reads its
/// public segment, so their outputs are the same under the transaction's binding and under the
/// empty segment; only the proof's `H_PUB` can refuse the empty one (the real twin).
#[test]
fn both_guests_publish_the_same_under_the_empty_segment() {
    let s = split_case();
    let v = s.honest();
    let run = |public: &[u32]| execute(ZkExecutor::hidden_bundle_v3_program(), &v, public, MAX_CYCLES).unwrap().outputs;
    assert_eq!(run(&BINDING_A), run(&[]));
    assert_eq!(run(&BINDING_A), run(&BINDING_B));
    assert_eq!(emulate_auth(&s.owner.sk, &SALT_1, &[]), s.c1());
}

// ── the real proofs ──

/// A real v3 bundle proof: its bytes and the digest it publishes.
struct V3Proof {
    bytes: Vec<u8>,
    digest: Word8,
}

/// A real auth proof: its bytes and the `c` it publishes.
struct AuthProof {
    bytes: Vec<u8>,
    c: Word8,
}

impl AuthProof {
    fn proof(&self) -> Proof { postcard::from_bytes(&self.bytes).expect("a proof this file just produced") }
}

/// Proves a v3 witness for real under `binding` (the file's lock and the proving slot), and checks
/// what every case shares: tier 14, it verifies against `binding` under v3's `hc`, the verifier
/// reads back the digest the prover reported, the emulator and the model agree with it.
fn prove_v3(inputs: &[u32], binding: &[u32; 8], what: &str) -> V3Proof {
    let _in_binary = PROVING.lock().unwrap_or_else(|e| e.into_inner());
    let _slot = proving_slot();
    let hc = ZkExecutor::hc_hidden_bundle_v3();
    let started = std::time::Instant::now();
    let (bytes, digest, tier) = prove_bundle_for(&hc, FriProfile::Production, inputs, binding, Backend::Cpu)
        .unwrap_or_else(|e| panic!("{what}: the v3 guest must taint, not trap — no proof: {e}"));
    let proved = started.elapsed();
    let ex = ZkExecutor::new(FriProfile::Production);
    ex.verify_hidden_bundle(&hc, &bytes, binding).unwrap_or_else(|e| panic!("{what}: the proof must verify against its binding: {e:?}"));
    println!("{what}: v3 bundle proved at tier {tier} in {proved:.1?}, {} proof bytes (Production FRI, CPU)", bytes.len());
    assert_eq!(tier, 14, "{what}");
    assert_eq!(ex.hidden_bundle_proof_digest_for(&hc, &bytes).unwrap(), digest, "{what}: the verifier reads another digest");
    assert_eq!(emulate(inputs), digest, "{what}: prover and emulator disagree");
    assert_eq!(model(inputs, Guest::V3).expected(), digest, "{what}: the reference model disagrees");
    V3Proof { bytes, digest }
}

/// Proves the auth guest for real for `sk` and `salt` under `binding`, and checks it verifies
/// against `binding` and publishes `auth_commit(nk, salt)` at outputs 0..8.
fn prove_auth(sk: &SpendKey, salt: &Word8, binding: &[u32; 8], what: &str) -> AuthProof {
    let _in_binary = PROVING.lock().unwrap_or_else(|e| e.into_inner());
    let _slot = proving_slot();
    let m = Machine::new(FriProfile::Production);
    let started = std::time::Instant::now();
    let (proof, exec) = m.prove_with(Backend::Cpu, &guests::auth(), &auth::auth_inputs(sk, salt), binding, None).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    println!("{what}: auth proved in {:.1?}, {} proof bytes (Production FRI, CPU)", started.elapsed(), proof.size());
    m.verify_public(&guests::auth().digest(), binding, &proof).unwrap_or_else(|e| panic!("{what}: the auth proof must verify against its binding: {e:?}"));
    let c: Word8 = std::array::from_fn(|k| u32::try_from(proof.public_values[pv::OUT0 + k]).unwrap());
    assert_eq!(c, auth::auth_commit(&sk.viewing_key().nk, salt), "{what}");
    assert_eq!(w8(&exec.outputs, 0), c, "{what}");
    AuthProof { bytes: proof.to_bytes(), c }
}

fn bundle_verifies(p: &V3Proof, binding: &[u32; 8]) -> bool {
    ZkExecutor::new(FriProfile::Production).verify_hidden_bundle(&ZkExecutor::hc_hidden_bundle_v3(), &p.bytes, binding).is_ok()
}

fn auth_verifies(p: &AuthProof, public: &[u32]) -> bool {
    Machine::new(FriProfile::Production).verify_public(&guests::auth().digest(), public, &p.proof()).is_ok()
}

/// Task 4's whole rule on real proofs, for the transaction with binding `binding`, plaintext
/// `base` and field `auth_commit`.
fn ledger_rule(binding: &[u32; 8], base: &HiddenDigestInput, auth_commit: &Word8, bundle: &V3Proof, auth: &AuthProof) -> Result<(), Refused> {
    if !bundle_verifies(bundle, binding) {
        return Err(Refused::BundleProof);
    }
    if !auth_verifies(auth, binding) {
        // (Checked before the digest only so that a verification failure is named as one; the
        // ledger's order is Task 4's.)
        return Err(Refused::AuthProof);
    }
    content_rule(base, auth_commit, &bundle.digest, &auth.c)
}

/// The seven proofs, each made once per run.
fn p_honest() -> &'static V3Proof {
    static P: OnceLock<V3Proof> = OnceLock::new();
    P.get_or_init(|| prove_v3(&split_case().honest(), &BINDING_A, "v3 bundle, transaction A (nk₁, salt₁)"))
}
fn p_redirected() -> &'static V3Proof {
    static P: OnceLock<V3Proof> = OnceLock::new();
    P.get_or_init(|| prove_v3(&split_case().redirected(), &BINDING_B, "v3 bundle, transaction B (output 0 redirected; nk₁, salt₁)"))
}
fn p_cheater_nk() -> &'static V3Proof {
    static P: OnceLock<V3Proof> = OnceLock::new();
    P.get_or_init(|| prove_v3(&split_case().cheater_nk(), &BINDING_A, "v3 bundle, transaction A with the cheater's nk₂"))
}
fn q_owner() -> &'static AuthProof {
    static Q: OnceLock<AuthProof> = OnceLock::new();
    Q.get_or_init(|| prove_auth(&split_case().owner.sk, &SALT_1, &BINDING_A, "auth sk₁ salt₁, binding A"))
}
fn q_cheater() -> &'static AuthProof {
    static Q: OnceLock<AuthProof> = OnceLock::new();
    Q.get_or_init(|| prove_auth(&split_case().cheater, &SALT_1, &BINDING_A, "auth sk₂ salt₁, binding A"))
}
fn q_other_salt() -> &'static AuthProof {
    static Q: OnceLock<AuthProof> = OnceLock::new();
    Q.get_or_init(|| prove_auth(&split_case().owner.sk, &SALT_2, &BINDING_A, "auth sk₁ salt₂, binding A"))
}
fn q_owner_for_b() -> &'static AuthProof {
    static Q: OnceLock<AuthProof> = OnceLock::new();
    Q.get_or_init(|| prove_auth(&split_case().owner.sk, &SALT_1, &BINDING_B, "auth sk₁ salt₁, binding B"))
}

/// The control: the owner's bundle and auth proof for transaction A pass the whole rule.
#[test]
fn real_proof_split_honest_control_passes_the_rule() {
    let s = split_case();
    assert_eq!(p_honest().digest, hidden::hidden_bundle_digest_v3(&s.owner.claimed_v3(&SALT_1)));
    assert_eq!(q_owner().c, s.c1());
    assert_eq!(ledger_rule(&BINDING_A, &s.owner.claimed(), &s.c1(), p_honest(), q_owner()), Ok(()));
}

#[test]
fn real_proof_an_auth_proof_for_a_different_nk() {
    let s = split_case();
    let base = s.owner.claimed();
    let (p, q2) = (p_honest(), q_cheater());
    assert_ne!(q2.c, s.c1());
    assert_eq!(ledger_rule(&BINDING_A, &base, &s.c1(), p, q2), Err(Refused::AuthCommit), "field c₁: the auth check alone");
    assert_eq!(ledger_rule(&BINDING_A, &base, &q2.c, p, q2), Err(Refused::BundleDigest), "field c₂");
    // The bundle re-proved under nk₂: it verifies, publishes the tainted digest, and the rule
    // refuses it with nk₂'s own auth proof and either plaintext.
    let t = p_cheater_nk();
    let m = model(&s.cheater_nk(), Guest::V3);
    assert_eq!(t.digest, tainted_v3(&m.claimed_v3().unwrap()));
    assert_eq!(ledger_rule(&BINDING_A, &m.claimed, &q2.c, t, q2), Err(Refused::BundleDigest));
    assert_eq!(ledger_rule(&BINDING_A, &base, &q2.c, t, q2), Err(Refused::BundleDigest));
}

#[test]
fn real_proof_an_auth_proof_for_a_different_binding() {
    let (q_a, q_b) = (q_owner(), q_owner_for_b());
    assert_eq!(q_a.c, q_b.c, "the same c: only the binding differs");
    assert!(auth_verifies(q_a, &BINDING_A) && auth_verifies(q_b, &BINDING_B));
    assert!(!auth_verifies(q_a, &BINDING_B), "A's auth proof against B's binding");
    assert!(!auth_verifies(q_b, &BINDING_A), "B's auth proof against A's binding");
    // And the bundle proof is bound the same way.
    assert!(!bundle_verifies(p_honest(), &BINDING_B));
}

#[test]
fn real_proof_a_bundle_whose_c_uses_a_different_salt_than_the_auth_proof() {
    let s = split_case();
    let base = s.owner.claimed();
    let q3 = q_other_salt();
    assert_eq!(q3.c, auth::auth_commit(&s.owner.sk.viewing_key().nk, &SALT_2), "honest for its own salt");
    assert_ne!(q3.c, s.c1());
    assert_eq!(ledger_rule(&BINDING_A, &base, &s.c1(), p_honest(), q3), Err(Refused::AuthCommit));
    assert_eq!(ledger_rule(&BINDING_A, &base, &q3.c, p_honest(), q3), Err(Refused::BundleDigest));
}

#[test]
fn real_proof_auth_commit_in_the_bundle_differing_from_either_proof() {
    let s = split_case();
    let base = s.owner.claimed();
    let mut x = s.c1();
    x[0] ^= 0x8000_0000;
    for q in [q_owner(), q_cheater()] {
        assert_eq!(ledger_rule(&BINDING_A, &base, &x, p_honest(), q), Err(Refused::BundleDigest));
    }
}

#[test]
fn real_proof_an_auth_proof_replayed_from_another_transaction() {
    let s = split_case();
    let base_b = s.redirected.claimed();
    let p_b = p_redirected();
    assert_eq!(p_b.digest, hidden::hidden_bundle_digest_v3(&s.redirected.claimed_v3(&SALT_1)), "B's bundle is honest, c₁ in its digest");
    assert_eq!(q_owner().c, s.c1());
    assert_eq!(ledger_rule(&BINDING_B, &base_b, &s.c1(), p_b, q_owner()), Err(Refused::AuthProof), "A's auth proof replayed onto B");
    // What B would need: an auth proof made for B's binding — which only sk₁'s holder can make.
    assert_eq!(ledger_rule(&BINDING_B, &base_b, &s.c1(), p_b, q_owner_for_b()), Ok(()), "the owner's own auth proof for B");
}

#[test]
fn real_proof_both_guests_refuse_the_empty_segment() {
    let hc_v3 = ZkExecutor::hc_hidden_bundle_v3();
    let bundle: Proof = postcard::from_bytes(&p_honest().bytes).unwrap();
    let m = Machine::new(FriProfile::Production);
    m.verify_public(&hc_v3, &BINDING_A, &bundle).expect("the control");
    assert!(m.verify_public(&hc_v3, &[], &bundle).is_err(), "a v3 bundle proof against the empty segment");
    assert!(auth_verifies(q_owner(), &BINDING_A), "the control");
    assert!(!auth_verifies(q_owner(), &[]), "an auth proof against the empty segment");
}

/// The v3-only words — `nk` and the salt — mutated on random honest witnesses (the main fuzz
/// reaches v3 through `to_v3`, so its `nk` only ever moves with `sk`). A salt change is always a
/// different, legitimate transaction whose `c` moves with it (so an auth proof for the old salt no
/// longer matches); an `nk` change re-owns every input, so it taints unless every input is a dummy.
/// `HIDDEN_FUZZ_V3_ITERS` runs (default 3 000), seed `HIDDEN_FUZZ_SEED`.
#[test]
fn mutation_fuzz_v3_nk_and_salt_words_publish_the_honest_digest_only_when_valid() {
    let seed = env_u64("HIDDEN_FUZZ_SEED", 0x4832_6675_7a7a_0001) ^ 0x7633;
    let iters = env_u64("HIDDEN_FUZZ_V3_ITERS", 3_000) as usize;
    let mut rng = Rng(seed);
    let non_path = non_path_words();
    let (mut valid, mut tainted_runs) = (0, 0);
    for n in 0..iters {
        let c = random_honest(&mut rng);
        let salt = rng.word8();
        let honest = c.inputs_v3(&salt);
        let c0 = auth::auth_commit(&c.sk.viewing_key().nk, &salt);
        let mut v = honest.clone();
        let (what, salt_only) = match rng.below(4) {
            0 => { let i = hi3::NK + rng.below(8) as usize; (mutate_word(&mut rng, &mut v, i), false) }
            1 => { let i = hi3::SALT + rng.below(8) as usize; (mutate_word(&mut rng, &mut v, i), true) }
            2 => { v[hi3::NK..hi3::NK + 8].copy_from_slice(&SpendKey(rng.word8()).viewing_key().nk); ("nk replaced by another key's".to_string(), false) }
            _ => {
                let i = hi3::SALT + rng.below(8) as usize;
                let j = non_path[rng.below(non_path.len() as u64) as usize];
                (format!("{}; {}", mutate_word(&mut rng, &mut v, i), mutate_word(&mut rng, &mut v, j)), false)
            }
        };
        let ctx = || format!("seed {seed:#x}, run {n}: {what}");
        let m = model(&v, Guest::V3);
        let out = emulate_or(&v, ctx);
        assert_eq!(out, m.expected(), "seed {seed:#x}, run {n}: {what}; model failures {:?}", m.fails);
        if salt_only {
            assert!(m.fails.is_empty(), "seed {seed:#x}, run {n}: a salt change must stay valid");
            assert_ne!(m.auth_commit, Some(c0), "seed {seed:#x}, run {n}: the salt moved but c did not");
            assert_ne!(out, hidden::hidden_bundle_digest_v3(&c.claimed_v3(&salt)), "seed {seed:#x}, run {n}");
        }
        if m.fails.is_empty() { valid += 1 } else { tainted_runs += 1 }
    }
    println!("v3 nk/salt fuzz, seed {seed:#x}: {iters} runs — {valid} valid, {tainted_runs} tainted");
    assert!(valid > 0 && tainted_runs > 0);
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
        let m = model(&honest, Guest::V1);
        assert!(m.fails.is_empty(), "seed {seed:#x}, base {base}: the generator built a dishonest witness: {:?}", m.fails);
        assert_eq!(m.claimed, c.claimed(), "seed {seed:#x}, base {base}: the model reads another plaintext than the builder wrote");
        assert_eq!(emulate_or(&honest, || format!("seed {seed:#x}, base {base}, honest")), hidden::hidden_bundle_digest(&m.claimed), "seed {seed:#x}, base {base}: an honest witness did not publish its honest digest");
        for n in 0..per_base {
            let mut v = honest.clone();
            let what = mutate(&mut rng, &mut v, &non_path);
            let m = model(&v, Guest::V1);
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
    let m = model(&c.inputs(), Guest::V1);
    assert!(m.fails.is_empty());
    assert_eq!(m.claimed, c.claimed());
    // A new output r: a different, legitimate transaction.
    let mut v = c.inputs();
    v[hi::out(1) + hi::O_R] ^= 1;
    assert!(model(&v, Guest::V1).fails.is_empty());
    assert_ne!(model(&v, Guest::V1).claimed, c.claimed());
    // A dummy's path words are never read.
    let d = Case::new(12, [In::Real(500, TOKEN), In::Dummy, In::Real(100, 0), In::Dummy], [500, 0, 90, 0], 10, 0, 0, TOKEN);
    let mut v = d.inputs();
    v[hi::in_slot(1) + hi::S_PATH + 40] = 0xdead;
    assert!(model(&v, Guest::V1).fails.is_empty());
    assert_eq!(emulate(&v), emulate(&d.inputs()));
    // A real input's path word is.
    let mut v = c.inputs();
    v[hi::in_slot(2) + hi::S_PATH + 40] ^= 4;
    assert_eq!(model(&v, Guest::V1).fails, ["membership: root != anchor"]);
    // The eleven fields `amount_fields` names are the builder's.
    let f = amount_fields();
    let v = c.inputs();
    for k in 0..4 {
        assert_eq!(u64_at(&v, f[k].0, f[k].1), c.ins[k].0.amount);
        assert_eq!(u64_at(&v, f[4 + k].0, f[4 + k].1), c.outs[k].amount);
    }
    assert_eq!(u64_at(&v, f[8].0, f[8].1), 10);
    assert_eq!(non_path_words().len(), hi::COUNT - SLOTS * DEPTH * 8);
    // The v3 layout: the same plaintext read from nk, and c from nk and the salt.
    let v = c.inputs_v3(&SALT_1);
    let m = model(&v, Guest::V3);
    assert!(m.fails.is_empty());
    assert_eq!(m.claimed, c.claimed());
    assert_eq!(m.claimed_v3(), Some(c.claimed_v3(&SALT_1)));
    assert_eq!(m.expected(), hidden::hidden_bundle_digest_v3(&c.claimed_v3(&SALT_1)));
    let mut v = c.inputs_v3(&SALT_1);
    v[hi3::in_slot(2) + hi3::S_PATH + 40] ^= 4;
    assert_eq!(model(&v, Guest::V3).fails, ["membership: root != anchor"]);
    assert_eq!(emulate(&v), tainted_v3(&c.claimed_v3(&SALT_1)));
}
