//! HB-4 (final security audit v6 §8.28, issue #100): forgeries of the bundle guest's **trace**.
//!
//! `tests/hidden_cheating.rs` hands a dishonest *witness* to an honest prover and shows the guest
//! taints; `tests/cheating.rs` edits *traces* of tiny hand-built programs and shows the AIR refuses
//! them. What neither did — the one class the audit lists as untested — is edit the trace of a
//! real bundle guest execution: an honest v3 bundle (`guests::bundle_hidden_v3`, the guest chains
//! 17 and 18 pin) is emulated, its traces are built exactly as `Machine::prove_salted` builds them
//! (`build_traces_salted`, tier 14), **one edit** is applied to the rows that carry the value a
//! forger would want to move, the edited traces are proved (`prove_traces`) and the chain's own
//! verifier (`ZkExecutor::verify_hidden_bundle`, the path `Ledger::check_bundle_proof` takes) must
//! refuse the proof. Every test first proves and verifies the **unedited** traces of the same run,
//! so a case cannot pass because the setup itself was broken.
//!
//! The cases, each with the constraint that is expected to refuse it:
//!
//! - **The Merkle read-index redirect** (`the_merkle_read_index_redirected_to_another_slots_path`):
//!   the guest reads slot 0's level-`L` sibling with `READ_INPUT` at the indices
//!   `in_slot(0) + S_PATH + 8L + j`, held in `a0` by `addi a0, PTR, j`. The forger rewrites those
//!   eight ecall rows to read slot 1's path at the same level — first the index alone (the
//!   `INPUT_READ` bus then carries a pair no committed row provides), then the index **and** the
//!   word, with the input table's `MULT_READ` moved along, so the input bus balances and only the
//!   register file stands: `a0` on the ecall row is a register read (`SLOT_R2`) the memory table
//!   must answer with `addi`'s write, and the word returned is a register write the following
//!   `sw` reads back. Either way the same commitment cannot be made to sit under another path.
//! - **The leaf-index bit** (`a_leaf_index_bit_flipped_in_the_merkle_loop`): the running node's
//!   side at level `L` is `andi BIT, IDX, 1`; flipping its result claims the commitment sits at
//!   the sibling leaf (index with bit `L` flipped). The ALU bus carries `(AND, IDX, 1, BIT)` and
//!   the ALU table proves it through the nibble table, which holds no `AND4` row for the flipped
//!   result; the register write of `BIT` disagrees with what `slli` reads next.
//! - **A nullifier the guest never derived** (`a_nullifier_of_a_note_the_guest_never_owned`): the
//!   digest preimage's `nf_0` is copied from `NF` to the hash buffer with `lw`/`sw` pairs; the
//!   forger replaces the copied words with another key's nullifier of the same note — a note the
//!   guest proved nothing about. The `lw` returns a word the memory table never held at that
//!   address (the memory bus), and the buffer word the digest absorbs is not what was stored.
//! - **An output amount raised** (`an_output_amount_raised_after_the_conservation_sum`): output
//!   2's `amount_lo` is loaded once for the note commitment's staging and again for the RAND
//!   sum; the forger raises the staged copy by 100 so the committed note is worth more than the
//!   sum admits. The memory bus refuses the load.
//! - **The `pk` derived from `nk`** (`the_pk_derived_from_nk_replaced_by_another_owners`): a
//!   witness spending a note owned by another key taints (its commitment is staged under
//!   `pk_self`); the forger replaces the eight words `emit_derive_pk` copies out of the Poseidon2
//!   buffer with the true owner's `pk`, so the staged note would be the owner's. The memory bus
//!   refuses the loads: the buffer holds `H(PK, nk)` and nothing else.
//! - **The ledger coupling** (`ledger_coupling_a_real_v3_proof_is_refused_under_another_binding_anchor_or_auth_commit`):
//!   a real, honest v3 bundle proof and auth proof in a real `Ledger` (a faucet-minted note spent
//!   by hand, the real `ZkExecutor`, `Ledger::validate` — the path admission and apply share):
//!   accepted as made; refused with `InvalidBundleProof(PublicValues)` under another transaction
//!   binding (an envelope byte moved: the proof's `H_PUB` is the binding's digest), with
//!   `BadDigest` under another anchor the ledger holds (the digest binds the anchor, so the
//!   window check passes and the digest compare refuses), with `AuthMismatch` under another
//!   `auth_commit` (the auth proof's `c` is the field), and with `BadDigest` when the field and
//!   the auth proof both move to another salt (the bundle proof's digest carries the first `c`).
//!
//! **Where the refusal comes from.** These run in `--release`, where Plonky3 does not check
//! constraints while proving: every edited trace *proves*, and the refusal is the verifier's
//! (`Machine::verify` — a LogUp bus that does not balance or a row constraint that does not hold
//! makes the STARK's quotient fail). In a debug build `prove_traces` would panic on the violated
//! constraint instead; `common::rejects` counts either and nothing else. No prover-side refusal
//! happened in any run recorded (the traces are well-formed; only their content is false).
//!
//! **Cost.** A tier-14 Test-profile proof is ~2 min on the laptop; each test makes two (the
//! control and the forgery; the redirect makes three) and the ledger test one bundle and two auth
//! proofs — ~25 min for the file, one proof at a time (`--test-threads=1`, the file's own lock).
//! Nightly CI only (`ci.yml`'s `nightly-zkvm` job runs the whole zkVM suite), not the fast job.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes it, like `tests/hidden_cheating.rs`).
//!
//! ```text
//! cargo test --release -p randprotocol-zkvm --test hidden_trace_forgery -- --test-threads=1
//! ```

#![allow(clippy::needless_range_loop)]

mod common;
use common::rejects;

use std::sync::Mutex;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::ledger::{Ledger, TxError};
use randprotocol_core::notes::{Bundle, Envelope};
use randprotocol_core::{gas as core_gas, Action, Keypair, Transaction, UNITS_PER_RAND};
use randprotocol_zkvm::auth;
use randprotocol_zkvm::emulator::{execute, CycleEvent, Execution, Syscall};
use randprotocol_zkvm::executor::{prove_auth, prove_bundle_for, ZkExecutor};
use randprotocol_zkvm::hidden::{self, hidden_input_v3 as hi3, slot_asset, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput, SLOTS};
use randprotocol_zkvm::isa::{AluOp, Instr, Program};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::machine::{build_traces_salted, Backend, FriProfile, Machine, Tier, Traces, VerifyError};
use randprotocol_zkvm::notes::{Note, SpendKey, Word8, DEPTH};
use randprotocol_zkvm::tables::{cpu, input, limbs, range, F};

/// The transaction binding every trace-level proof here is made against.
const BINDING: [u32; 8] = [0x4b4_0001, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
/// The `H_IN` salt: fixed, so a run's traces are reproducible from its witness.
const SALT_IN: [u32; 4] = [0x5a17, 0xb4, 0, 1];
/// The per-transaction salt of the v3 witness.
const SALT: Word8 = [0x5a17_0001, 0x0bad_cafe, 3, 4, 5, 6, 7, 0x8000_0001];
const TOKEN: u32 = 7;
const TIME: u32 = 5;
const MAX_CYCLES: usize = 1 << 20;
/// Every bundle proof is tier 14 (`executor::BUNDLE_TIER`; `tests/hidden_bundle.rs` measures it).
const TIER: Tier = Tier(14);
/// `guests.rs`'s `HEAP`: the hidden guests' RAM base.
const HEAP: u32 = 0x1000;

/// `guests::HIDDEN_LAYOUT_V3`, the byte offsets from `HEAP` the v3 guest keeps its regions at.
/// Private to `guests.rs`; copied here and checked by every locator below against the values
/// it finds in the trace (a moved region fails the locator, never silently edits the wrong row).
mod layout {
    pub const BUF: u32 = 0x000;
    pub const NOTE_STAGE: u32 = 0x170;
    pub const HDR: u32 = 0x240;
    pub const PK: u32 = 0x3e0;
    pub const NF: u32 = 0x480;
}

/// One real proof at a time in this binary — a tier-14 proof is ~5 GB — and the workspace's
/// proving slot, so a proof here never runs beside another session's (`tests/hidden_cheating.rs`
/// has the same two).
static PROVING: Mutex<()> = Mutex::new(());

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

// ───────────────────────────── witnesses ─────────────────────────────

/// SplitMix64, so every witness is a function of its seed.
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
    fn word8(&mut self) -> Word8 { std::array::from_fn(|_| self.next_u32()) }
}

/// A v3 witness as a wallet builds it, plus what the tests need to reason about it: the four
/// spent notes with their paths, the tree's root and the plaintext the ledger would hold.
struct Case {
    sk: SpendKey,
    ins: [(Note, [Word8; DEPTH], u32); SLOTS],
    outs: [Note; SLOTS],
    anchor: Word8,
    fee: u64,
    asset_a: u32,
}

impl Case {
    /// Four real inputs — 800 of the token in slots 0–1, 1 050 RAND in slots 2–3, a fee of 10
    /// (`tests/hidden_cheating.rs`'s `mixed`) — behind `filler` unrelated leaves. `owner_of_slot_0`
    /// names another key as the owner of slot 0's note: the note is in the tree under that key's
    /// `pk`, and the witness still claims it (the builder is handed the note re-owned by
    /// `pk_self`, which is the one field it does not write — the guest supplies the owner).
    fn build(seed: u64, owner_of_slot_0: Option<&SpendKey>) -> Case {
        let mut rng = Rng(seed);
        let sk = SpendKey(rng.word8());
        let me = sk.viewing_key().pk();
        let mut tree = CommitmentTree::new();
        for _ in 0..5 {
            tree.append(Note { pk: rng.word8(), from: rng.word8(), amount: rng.next_u64() >> 24, asset: rng.next_u32(), time: 1, r: rng.word8() }.commitment());
        }
        let amounts = [(500u64, TOKEN), (300, TOKEN), (1_000, 0), (50, 0)];
        let notes: Vec<Note> = amounts
            .iter()
            .enumerate()
            .map(|(k, &(amount, asset))| {
                let pk = match owner_of_slot_0 {
                    Some(other) if k == 0 => other.viewing_key().pk(),
                    _ => me,
                };
                Note { pk, from: rng.word8(), amount, asset, time: rng.next_u32() % (TIME + 1), r: rng.word8() }
            })
            .collect();
        for n in &notes {
            tree.append(n.commitment());
        }
        let anchor = tree.root();
        let ins = std::array::from_fn(|k| {
            let (p, i) = tree.path_for(&notes[k].commitment()).unwrap();
            (notes[k], p, i)
        });
        let out_amounts = [600u64, 200, 900, 140];
        let outs = std::array::from_fn(|k| Note { pk: rng.word8(), from: me, amount: out_amounts[k], asset: slot_asset(k, TOKEN), time: TIME, r: rng.word8() });
        Case { sk, ins, outs, anchor, fee: 10, asset_a: TOKEN }
    }

    fn inputs(&self) -> Vec<u32> {
        let me = self.sk.viewing_key().pk();
        // The builder refuses a note owned by another key; the owner is not a witness word, so
        // handing it the note under `pk_self` writes exactly the words a cheater would.
        let ins: [(Note, [Word8; DEPTH], u32); SLOTS] = std::array::from_fn(|k| {
            let (mut n, p, i) = self.ins[k];
            n.pk = me;
            (n, p, i)
        });
        let outs = self.outs.map(|o| HiddenOutput { pk: o.pk, amount: o.amount, r: o.r });
        hidden::hidden_bundle_inputs_v3(&self.sk.viewing_key(), &SALT, &ins, &outs, self.anchor, self.fee, 0, 0, self.asset_a, TIME)
    }

    /// The plaintext the chain would hold — what the guest's honest digest commits to.
    fn claimed(&self) -> HiddenDigestInputV3 {
        let vk = self.sk.viewing_key();
        let me = vk.pk();
        HiddenDigestInputV3 {
            base: HiddenDigestInput {
                anchor: self.anchor,
                // The guest stages every input under `pk_self`; its nullifier is of that staging.
                nullifiers: std::array::from_fn(|k| vk.nullifier(&Note { pk: me, ..self.ins[k].0 }.commitment())),
                commitments: std::array::from_fn(|k| self.outs[k].commitment()),
                fee: self.fee,
                burn_a: 0,
                burn_r: 0,
                burn_asset: 0,
                time: TIME,
            },
            auth_commit: auth::auth_commit(&vk.nk, &SALT),
        }
    }
}

// ───────────────────────────── the honest run ─────────────────────────────

/// An honest execution of the v3 guest over `inputs`, its traces as the prover builds them, and
/// where the cpu table's cycle rows start (`offset`: the program-, input- and public-digest
/// prefix rows come first — `tables::cpu::cpu_trace`).
struct Run {
    program: &'static Program,
    inputs: Vec<u32>,
    exec: Execution,
    traces: Traces,
    offset: usize,
}

fn honest_run(inputs: Vec<u32>) -> Run {
    let program = ZkExecutor::hidden_bundle_v3_program();
    let exec = execute(program, &inputs, &BINDING, MAX_CYCLES).expect("the v3 guest never traps");
    assert!(exec.halted);
    let traces = build_traces_salted(program, &inputs, &BINDING, SALT_IN, &exec, TIER, randprotocol_zkvm::gas::gas_max(TIER, 0, 0))
        .expect("an honest v3 run fits tier 14");
    let offset = program.digest_rows()
        + randprotocol_zkvm::hash::input_digest_row_count(inputs.len())
        + randprotocol_zkvm::hash::public_digest_row_count(BINDING.len());
    Run { program, inputs, exec, traces, offset }
}

impl Run {
    /// A fresh copy of the honest traces to edit (`Traces` is vendored and not `Clone`; the build
    /// is deterministic in the witness, the fixed `H_IN` salt and the run, so this is the same
    /// matrix set as `self.traces`, which the control proves).
    fn fresh_traces(&self) -> Traces {
        build_traces_salted(self.program, &self.inputs, &BINDING, SALT_IN, &self.exec, TIER, randprotocol_zkvm::gas::gas_max(TIER, 0, 0)).unwrap()
    }

    /// The cpu row of cycle event `i`.
    fn row(&self, i: usize) -> usize { self.offset + i }
    fn events(&self) -> &[CycleEvent] { &self.exec.events }

    /// Proves `traces` (Test FRI, tier 14) and verifies the proof through the chain's own path,
    /// `ZkExecutor::verify_hidden_bundle` under v3's `hc` and the binding — the call
    /// `Ledger::check_bundle_proof` makes. Returns the verifier's verdict and the proof bytes.
    fn prove_and_verify(&self, traces: &Traces, what: &str) -> (Result<(), ConfidentialError>, Vec<u8>) {
        let _in_binary = PROVING.lock().unwrap_or_else(|e| e.into_inner());
        let _slot = proving_slot();
        let started = std::time::Instant::now();
        let proof = Machine::new(FriProfile::Test).prove_traces(self.program, traces, TIER).to_bytes();
        let proved = started.elapsed();
        let started = std::time::Instant::now();
        let verdict = ZkExecutor::new(FriProfile::Test).verify_hidden_bundle(&ZkExecutor::hc_hidden_bundle_v3(), &proof, &BINDING);
        println!("{what}: proved in {proved:.1?} ({} bytes), verified in {:.1?}: {verdict:?}", proof.len(), started.elapsed());
        (verdict, proof)
    }

    /// The control every case runs first: the unedited traces prove and verify, and the proof
    /// publishes exactly the digest the emulator did.
    fn control(&self, expected_digest: Word8) {
        let (verdict, proof) = self.prove_and_verify(&self.traces, "control (unedited traces)");
        assert_eq!(verdict, Ok(()), "the honest traces must verify: the case would otherwise pass for the wrong reason");
        let ex = ZkExecutor::new(FriProfile::Test);
        let published = ex.hidden_bundle_proof_digest_for(&ZkExecutor::hc_hidden_bundle_v3(), &proof).unwrap();
        assert_eq!(published, expected_digest, "the control publishes the digest the emulator did");
        assert_eq!(&self.exec.outputs[..8], &expected_digest[..], "the emulator's own digest");
    }

    /// The forgery: the edited traces must be refused — by the verifier (release: the proof is
    /// made and fails to verify) or by the prover's constraint check (debug). `rejects` counts
    /// nothing else. The edited traces must still be well-formed enough to prove, or the panic
    /// is not a constraint's and the test fails, as it should.
    fn refused(&self, traces: &Traces, what: &str) {
        let mut printed: Option<ConfidentialError> = None;
        assert!(
            rejects(|| {
                let (verdict, _) = self.prove_and_verify(traces, what);
                verdict.map_err(|e| {
                    printed = Some(e);
                    VerifyError::PublicValues
                })
            }),
            "{what}: the edited traces were NOT refused"
        );
        if let Some(e) = printed {
            println!("{what}: refused by the verifier: {e:?}");
        }
    }
}

// ───────────────────────────── trace edits ─────────────────────────────

/// Moves one RANGE8 receipt in the range table from byte `old` to byte `new` — the exact-count
/// accounting `tests/cheating.rs`'s `shrink_declared_n_in` keeps: a forger who rewrites a
/// RANGE8-checked limb pays for the new byte and stops paying for the old, so the range bus is
/// not what refuses the edit.
fn move_byte(t: &mut Traces, old: u32, new: u32) {
    let rw = range::col::WIDTH;
    t.range.values[old as usize * rw + range::col::M_RANGE] -= F::ONE;
    t.range.values[new as usize * rw + range::col::M_RANGE] += F::ONE;
}

/// Rewrites a `lw` row so that it claims to have loaded `word`: `C` (the value written to `rd`),
/// `MEM_VAL` (the word read) and its four RANGE8-checked limbs `W0..3`, receipts moved. The
/// memory bus still carries the row's `(addr, clk)`, so the memory table — which holds what was
/// really stored there — is what refuses it.
fn forge_load(t: &mut Traces, row: usize, word: u32) {
    let w = cpu::col::WIDTH;
    let r = row * w;
    assert_eq!(t.cpu.values[r + cpu::col::IS_LW], F::ONE, "row {row} is not a lw");
    let old = t.cpu.values[r + cpu::col::MEM_VAL].as_canonical_u64() as u32;
    assert_eq!(t.cpu.values[r + cpu::col::C], F::from_u32(old), "a lw's C is its MEM_VAL");
    t.cpu.values[r + cpu::col::C] = F::from_u32(word);
    t.cpu.values[r + cpu::col::MEM_VAL] = F::from_u32(word);
    let nl = limbs(word);
    for k in 0..4 {
        t.cpu.values[r + cpu::col::W0 + k] = nl[k];
        move_byte(t, (old >> (8 * k)) & 0xff, (word >> (8 * k)) & 0xff);
    }
}

/// Rewrites a `sw` row so that it claims to have stored `word`: `B` (the value read from `rs2`),
/// its limbs `RB0..3` (receipts moved) and the merged word `MERGED0..3`. `MEM_VAL` (the word
/// before the store) is left alone. With [`forge_load`] on the `lw` that fed `rs2`, the
/// register file is consistent across the pair and the RAM side of the memory bus alone stands.
fn forge_store(t: &mut Traces, row: usize, word: u32) {
    let w = cpu::col::WIDTH;
    let r = row * w;
    assert_eq!(t.cpu.values[r + cpu::col::IS_SW], F::ONE, "row {row} is not a sw");
    let old = t.cpu.values[r + cpu::col::B].as_canonical_u64() as u32;
    t.cpu.values[r + cpu::col::B] = F::from_u32(word);
    let nl = limbs(word);
    for k in 0..4 {
        t.cpu.values[r + cpu::col::RB0 + k] = nl[k];
        t.cpu.values[r + cpu::col::MERGED0 + k] = nl[k];
        move_byte(t, (old >> (8 * k)) & 0xff, (word >> (8 * k)) & 0xff);
    }
}

/// The word address of byte offset `off` from `HEAP` (a `lw`/`sw` row's `MEM_ADDR`).
fn word_addr(off: u32) -> u32 { (HEAP + off) / 4 }

fn is_load_of(e: &CycleEvent, off: u32) -> bool {
    matches!(e.instr, Instr::Load { .. }) && e.mem_addr == word_addr(off)
}

fn is_store_to(e: &CycleEvent, off: u32) -> bool {
    matches!(e.instr, Instr::Store { .. }) && e.mem_addr == word_addr(off)
}

/// The `lw`/`sw` pairs of a `copy_word8(src, dst)` — the `i`-th pair loads `src + 4i` and stores
/// it to `dst + 4i` on the next cycle. `nth` picks the `nth` such copy in execution order (the
/// same region is copied more than once in a run). Returns the eight event indices of the loads.
fn copy_word8_loads(run: &Run, src: u32, dst: u32, nth: usize) -> [usize; 8] {
    let ev = run.events();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 1 < ev.len() {
        if is_load_of(&ev[i], src) && is_store_to(&ev[i + 1], dst) {
            // The other seven pairs follow at once.
            let ok = (1..8).all(|j| is_load_of(&ev[i + 2 * j], src + 4 * j as u32) && is_store_to(&ev[i + 2 * j + 1], dst + 4 * j as u32));
            if ok {
                found.push(i);
                i += 16;
                continue;
            }
        }
        i += 1;
    }
    let base = *found.get(nth).unwrap_or_else(|| panic!("copy_word8({src:#x} -> {dst:#x}) #{nth}: only {} found", found.len()));
    std::array::from_fn(|j| base + 2 * j)
}

/// Replaces the eight words a `copy_word8` moved: every `lw` returns `words[j]` and every `sw`
/// stores it (register file consistent; the RAM bus is what disagrees).
fn forge_copy_word8(run: &Run, t: &mut Traces, loads: [usize; 8], words: &Word8) {
    for (j, &i) in loads.iter().enumerate() {
        forge_load(t, run.row(i), words[j]);
        forge_store(t, run.row(i + 1), words[j]);
    }
}

/// The cycle event of the one `READ_INPUT` of private-input index `idx` (the v3 guest reads
/// every word exactly once).
fn read_of(run: &Run, idx: usize) -> usize {
    let hits: Vec<usize> = run
        .events()
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.sys, Some(Syscall::ReadInput { idx: i, .. }) if i as usize == idx))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "input word {idx} is read exactly once");
    hits[0]
}

// ───────────────────────────── the cases ─────────────────────────────

/// The honest mixed transfer every trace case departs from.
fn mixed() -> Case { Case::build(1, None) }

/// Level 5 of a 32-level path, for the index-bit flip: deep enough that the flip changes every
/// hash above it.
const LEVEL: usize = 5;
/// The redirect's level. Slots 0 and 1 spend adjacent leaves (5 and 6), so from level 2 up their
/// paths share every sibling and a redirect there would be no edit at all (the first run proved
/// that: the test's own `assert_ne!` caught it). At level 1 the siblings differ — `node(6, 7)` for
/// leaf 5, `node(4, 5)` for leaf 6 — and the redirected word changes every hash above it.
const REDIRECT_LEVEL: usize = 1;

#[test]
fn the_merkle_read_index_redirected_to_another_slots_path() {
    let c = mixed();
    let run = honest_run(c.inputs());
    run.control(hidden::hidden_bundle_digest_v3(&c.claimed()));
    let (own_path, own_idx) = (hi3::in_slot(0) + hi3::S_PATH + 8 * REDIRECT_LEVEL, hi3::in_slot(1) + hi3::S_PATH + 8 * REDIRECT_LEVEL);
    // The eight reads of slot 0's level-1 sibling, and what slot 1's would return.
    let reads: [usize; 8] = std::array::from_fn(|j| read_of(&run, own_path + j));
    for j in 0..8 {
        let e = &run.events()[reads[j]];
        assert_eq!(e.b, (own_path + j) as u32, "a READ_INPUT row's B is the index");
        assert_eq!(e.c, run.inputs[own_path + j], "and its C the committed word");
        assert_eq!(e.c, c.ins[0].1[REDIRECT_LEVEL][j], "which is the sibling the wallet supplied");
    }
    assert_ne!(c.ins[0].1[REDIRECT_LEVEL], c.ins[1].1[REDIRECT_LEVEL], "the two slots' level-1 siblings differ");
    let w = cpu::col::WIDTH;

    // (i) The index alone: the row still returns slot 0's word, now claimed at slot 1's index.
    // The `INPUT_READ` bus carries `(idx', word)`, a pair no input-table row provides.
    let mut t = run.fresh_traces();
    for j in 0..8 {
        t.cpu.values[run.row(reads[j]) * w + cpu::col::B] = F::from_u32((own_idx + j) as u32);
    }
    run.refused(&t, "read-index redirect, index only");

    // (ii) The index and the word, the input table's MULT_READ moved with them: the input bus
    // balances — `(idx', word')` is a committed pair, read once — and only the register file
    // stands: a0 was written by `addi a0, PTR, j` with slot 0's index, and the word returned is
    // written to a0 for the `sw` that follows.
    let mut t = run.fresh_traces();
    let iw = input::col::WIDTH;
    for j in 0..8 {
        let (from, to) = (own_path + j, own_idx + j);
        let word = run.inputs[to];
        assert_eq!(word, c.ins[1].1[REDIRECT_LEVEL][j]);
        let r = run.row(reads[j]) * w;
        t.cpu.values[r + cpu::col::B] = F::from_u32(to as u32);
        t.cpu.values[r + cpu::col::C] = F::from_u32(word);
        assert_eq!(t.input.values[from * iw + input::col::IDX], F::from_u32(from as u32), "the input table's row i is index i");
        t.input.values[from * iw + input::col::MULT_READ] -= F::ONE;
        t.input.values[to * iw + input::col::MULT_READ] += F::ONE;
    }
    run.refused(&t, "read-index redirect, index and word, input bus balanced");
}

#[test]
fn a_leaf_index_bit_flipped_in_the_merkle_loop() {
    let c = mixed();
    let run = honest_run(c.inputs());
    run.control(hidden::hidden_bundle_digest_v3(&c.claimed()));
    // `andi BIT(x26), IDX(x24), 1`: one per level per slot, slot 0's 32 first.
    const BIT: u32 = 26;
    const IDX: u32 = 24;
    let andis: Vec<usize> = run
        .events()
        .iter()
        .enumerate()
        .filter(|(_, e)| e.instr == Instr::AluImm { op: AluOp::And, rd: BIT, rs1: IDX, imm: 1 })
        .map(|(i, _)| i)
        .collect();
    assert_eq!(andis.len(), SLOTS * DEPTH, "one index-bit extraction per level per slot");
    let index0 = c.ins[0].2;
    for level in 0..DEPTH {
        let e = &run.events()[andis[level]];
        assert_eq!(e.a, index0 >> level, "slot 0's IDX at level {level}");
        assert_eq!(e.c, (index0 >> level) & 1, "and the bit it extracts");
    }
    let e = &run.events()[andis[LEVEL]];
    let flipped = e.c ^ 1;
    let w = cpu::col::WIDTH;
    let mut t = run.fresh_traces();
    let r = run.row(andis[LEVEL]) * w;
    assert_eq!(t.cpu.values[r + cpu::col::ALU_OUT], F::from_u32(e.c));
    // The commitment claimed at the sibling leaf: bit 5 of its index flipped. The ALU bus
    // carries `(AND, IDX, 1, flipped)`, which the ALU table — through the nibble table's AND4
    // rows — cannot supply; the register write of BIT disagrees with what `slli` reads next.
    t.cpu.values[r + cpu::col::C] = F::from_u32(flipped);
    t.cpu.values[r + cpu::col::ALU_OUT] = F::from_u32(flipped);
    run.refused(&t, &format!("leaf index bit {LEVEL} flipped ({} -> {flipped})", e.c));
}

#[test]
fn a_nullifier_of_a_note_the_guest_never_owned() {
    let c = mixed();
    let run = honest_run(c.inputs());
    let claimed = c.claimed();
    run.control(hidden::hidden_bundle_digest_v3(&claimed));
    // The digest staging copies `NF + 0..32` to `BUF + 36..68` — the last copy of nf_0 in the
    // run (the pairwise-distinctness checks read the region with plain loads before it).
    let loads = copy_word8_loads(&run, layout::NF, layout::BUF + 36, 0);
    let nf0 = claimed.base.nullifiers[0];
    for j in 0..8 {
        assert_eq!(run.events()[loads[j]].c, nf0[j], "the copy moves nf_0 as the host computes it");
    }
    // Another key's nullifier of the same note: what a forger who never held `nk` would want
    // the chain to record as spent.
    let other = SpendKey(Rng(77).word8()).viewing_key();
    let foreign = other.nullifier(&c.ins[0].0.commitment());
    assert_ne!(foreign, nf0);
    let mut t = run.fresh_traces();
    forge_copy_word8(&run, &mut t, loads, &foreign);
    run.refused(&t, "nf_0 replaced by another key's nullifier in the digest staging");
}

#[test]
fn an_output_amount_raised_after_the_conservation_sum() {
    let c = mixed();
    let run = honest_run(c.inputs());
    run.control(hidden::hidden_bundle_digest_v3(&c.claimed()));
    // `emit_stage_note` for output 2: `lw T0, hdr(out(2) + O_AMOUNT_LO); sw T0, NOTE_STAGE + 64`.
    let amount_lo = layout::HDR + 4 * (hi3::out(2) + hi3::O_AMOUNT_LO - hi3::ANCHOR) as u32;
    let ev = run.events();
    let staged: Vec<usize> = (0..ev.len() - 1)
        .filter(|&i| is_load_of(&ev[i], amount_lo) && is_store_to(&ev[i + 1], layout::NOTE_STAGE + 64))
        .collect();
    assert_eq!(staged.len(), 1, "output 2's amount is staged for its commitment once");
    let i = staged[0];
    let honest = c.outs[2].amount as u32;
    assert_eq!(ev[i].c, honest, "the staged low word is output 2's amount");
    // The same word is loaded again for the RAND sum, which stays balanced: only the committed
    // note would be worth 100 more.
    let sum_loads = ev.iter().filter(|e| is_load_of(e, amount_lo)).count();
    assert!(sum_loads >= 2, "the amount is read for the staging and for the sum");
    let mut t = run.fresh_traces();
    forge_load(&mut t, run.row(i), honest + 100);
    forge_store(&mut t, run.row(i + 1), honest + 100);
    run.refused(&t, "output 2's staged amount raised by 100");
}

#[test]
fn the_pk_derived_from_nk_replaced_by_another_owners() {
    // Slot 0's note belongs to `owner`; the witness is the cheater's (its `nk`), so the guest
    // stages the note under the cheater's `pk_self`, the commitment misses the leaf and the run
    // taints — the control here is that tainted run, which proves and verifies as every tainted
    // witness does (`tests/hidden_cheating.rs`), publishing the `bad = 1` digest.
    let owner = SpendKey(Rng(78).word8());
    let c = Case::build(2, Some(&owner));
    let run = honest_run(c.inputs());
    let claimed = c.claimed();
    let tainted = {
        let mut m = hidden::hidden_bundle_preimage_v3(&claimed);
        *m.last_mut().unwrap() = 1;
        randprotocol_zkvm::notes::hash(hidden::HIDDEN_BUNDLE_DOMAIN, &m)
    };
    assert_ne!(tainted, hidden::hidden_bundle_digest_v3(&claimed));
    run.control(tainted);
    // `emit_derive_pk`'s last step: `copy_word8(BUF -> PK)`, the first copy out of the buffer
    // in the run (the hash of `[PK, nk]` has just been written there).
    let loads = copy_word8_loads(&run, layout::BUF, layout::PK, 0);
    let me = c.sk.viewing_key().pk();
    for j in 0..8 {
        assert_eq!(run.events()[loads[j]].c, me[j], "the copy moves H(PK, nk) — the cheater's pk_self");
    }
    let owners_pk = owner.viewing_key().pk();
    assert_eq!(c.ins[0].0.pk, owners_pk);
    assert_ne!(owners_pk, me);
    let mut t = run.fresh_traces();
    forge_copy_word8(&run, &mut t, loads, &owners_pk);
    run.refused(&t, "pk_self replaced by the note owner's pk on the derive-pk copy");
}

// ───────────────────────────── the ledger coupling ─────────────────────────────

const CHAIN_ID: u64 = 18;

fn env() -> Envelope {
    Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
}

#[test]
fn ledger_coupling_a_real_v3_proof_is_refused_under_another_binding_anchor_or_auth_commit() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let hc = ZkExecutor::hc_hidden_bundle_v3();
    // A ledger as a v3 + hc_auth genesis builds it: one validator (the faucet's minter), the
    // faucet on, split authorisation on.
    let minter = Keypair::from_seed([9; 32]).unwrap();
    let entry = randprotocol_core::ledger::staking::ValidatorEntry {
        public_key: minter.public_key().clone(),
        stake: randprotocol_core::ledger::staking::MIN_STAKE,
        pending: Vec::new(),
        rewards: 0,
        payout: randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
        nonce: 0,
        activation_epoch: 0,
    };
    let mut l = Ledger::new(CHAIN_ID, hc, [(minter.address(), entry)].into_iter().collect(), &ex);
    l.set_faucet(true);
    l.set_confidential(true);
    l.set_hc_auth(Some(ZkExecutor::hc_auth()));
    l.set_height(1);

    // Block 1: the faucet mints a note to the wallet.
    let sk = SpendKey(Rng(5).word8());
    let vk = sk.viewing_key();
    let pk_self = vk.pk();
    let amount = 10 * UNITS_PER_RAND;
    let r = Rng(6).word8();
    let mint = Transaction::mint(CHAIN_ID, pk_self, 1, r, env(), amount, &minter, &ex);
    assert_eq!(l.validate(&mint, &ex), Ok(()));
    l.apply_tx(&mint, &minter.address(), &ex).unwrap();
    l.close_block(1, &minter.address(), 0, 0);
    l.set_height(2);
    let note = Note { pk: pk_self, from: [0; 8], amount, asset: 0, time: 1, r };
    let cm = note.commitment();
    assert!(l.commitments_set().contains(&cm), "the mint appended the note the host computes");
    let mut tree = CommitmentTree::new();
    tree.append(cm);
    let anchor = tree.root();
    assert_eq!(anchor, l.root(), "the vendored tree and the ledger's agree");
    let (path, index) = tree.path_for(&cm).unwrap();
    assert!(l.is_anchor(&anchor));

    // The v3 transaction by hand: slot 2 spends the note, slot 3 returns it less the fee.
    let time = 2u32;
    let fee = core_gas::fee_floor(&Action::None);
    let mut rng = Rng(7);
    let dummy = |k: usize, rng: &mut Rng| (Note { pk: pk_self, from: [0; 8], amount: 0, asset: slot_asset(k, 0), time, r: rng.word8() }, [[0u32; 8]; DEPTH], 0u32);
    let inputs = [dummy(0, &mut rng), dummy(1, &mut rng), (note, path, index), dummy(3, &mut rng)];
    let outs: [HiddenOutput; SLOTS] = std::array::from_fn(|k| HiddenOutput { pk: if k == 3 { pk_self } else { rng.word8() }, amount: if k == 3 { amount - fee } else { 0 }, r: rng.word8() });
    let salt: Word8 = rng.word8();
    let c = auth::auth_commit(&vk.nk, &salt);
    let nullifiers: [Word8; SLOTS] = std::array::from_fn(|k| vk.nullifier(&inputs[k].0.commitment()));
    let commitments: [Word8; SLOTS] = std::array::from_fn(|k| outs[k].note(k, pk_self, 0, time).commitment());
    let words = hidden::hidden_bundle_inputs_v3(&vk, &salt, &inputs, &outs, anchor, fee, 0, 0, 0, time);
    let bundle = Bundle {
        anchor,
        nullifiers,
        commitments,
        fee,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time,
        envelopes: [env(), env(), env(), env()],
        proof: Vec::new(),
        auth_commit: c,
        auth_proof: Vec::new(),
    };
    let mut tx = Transaction::shielded(CHAIN_ID, bundle, Action::None);
    let binding = tx.binding(l.binding_domain());

    let _in_binary = PROVING.lock().unwrap_or_else(|e| e.into_inner());
    let _slot = proving_slot();
    let started = std::time::Instant::now();
    let (bundle_proof, digest, tier) = prove_bundle_for(&hc, FriProfile::Test, &words, &binding, Backend::Cpu).unwrap();
    println!("ledger coupling: v3 bundle proved at tier {tier} in {:.1?}, {} bytes", started.elapsed(), bundle_proof.len());
    assert_eq!(tier, 14);
    let base = HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a: 0, burn_r: 0, burn_asset: 0, time };
    assert_eq!(digest, hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 { base, auth_commit: c }), "an honest witness: no taint");
    let (auth_proof, published_c, _) = prove_auth(FriProfile::Test, &sk, &salt, &binding, Backend::Cpu).unwrap();
    assert_eq!(published_c, c);
    let b = tx.bundle.as_mut().unwrap();
    b.proof = bundle_proof.clone();
    b.auth_proof = auth_proof.clone();
    assert_eq!(tx.binding(l.binding_domain()), binding, "the binding blanks both proofs");

    // The control: the ledger accepts the transaction as made, through the real executor.
    assert_eq!(l.validate(&tx, &ex), Ok(()), "the honest v3 transaction is valid");
    assert_eq!(ex.verify_bundle(&hc, &bundle_proof, &binding), Ok(()));

    // (1) Another transaction binding: one envelope byte moved. Every digest field is unchanged,
    // so the digest compare passes and the bundle proof's `H_PUB` is what refuses it — the
    // binding it was made over is not this transaction's.
    let mut other = tx.clone();
    other.bundle.as_mut().unwrap().envelopes[0].body[0] ^= 1;
    let other_binding = other.binding(l.binding_domain());
    assert_ne!(other_binding, binding);
    assert_eq!(
        l.validate(&other, &ex),
        Err(TxError::InvalidBundleProof(ConfidentialError::InvalidBundleProof("PublicValues".into()))),
        "a real proof under another binding"
    );
    assert_eq!(ex.verify_bundle(&hc, &bundle_proof, &other_binding), Err(ConfidentialError::InvalidBundleProof("PublicValues".into())));

    // (2) Another anchor the ledger holds (the empty tree's root, recorded at height 0): the
    // window check passes, and the digest the proof publishes — which commits to the anchor the
    // path was verified against — is not the one the ledger recomputes.
    let empty = CommitmentTree::new().root();
    assert!(l.is_anchor(&empty), "height 0's root is in the window");
    assert_ne!(empty, anchor);
    let mut other = tx.clone();
    other.bundle.as_mut().unwrap().anchor = empty;
    assert_eq!(l.validate(&other, &ex), Err(TxError::BadDigest), "a real proof under another anchor");

    // (3) Another `auth_commit`: the auth proof publishes `c`, the field says otherwise — the
    // cheap compare refuses before any verify.
    let mut other = tx.clone();
    other.bundle.as_mut().unwrap().auth_commit = { let mut x = c; x[0] ^= 1; x };
    assert_eq!(l.validate(&other, &ex), Err(TxError::AuthMismatch), "a real proof under another auth_commit");

    // (3b) The field AND the auth proof moved to another salt together — a prover holding `nk`
    // re-salting the transaction after the key holder authorised it: the auth check passes and
    // the bundle proof's digest, which carries the first `c`, refuses.
    let salt2: Word8 = rng.word8();
    let (auth2, c2, _) = prove_auth(FriProfile::Test, &sk, &salt2, &binding, Backend::Cpu).unwrap();
    assert_ne!(c2, c);
    let mut other = tx.clone();
    let b = other.bundle.as_mut().unwrap();
    b.auth_commit = c2;
    b.auth_proof = auth2;
    assert_eq!(l.validate(&other, &ex), Err(TxError::BadDigest), "a real proof whose auth_commit and auth proof moved to another salt");

    // And still valid as made, after every refusal.
    assert_eq!(l.validate(&tx, &ex), Ok(()));
}
