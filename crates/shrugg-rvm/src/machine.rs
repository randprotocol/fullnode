//! The rVM's batch-STARK machine: Plonky3 configuration, tiers, proof shape, the program-keyed
//! verifier-key cache (plan Task 1; the chip set and `prove`/`verify` grow per task through
//! Task 6, mirroring `research/src/machine.rs`'s structure).
//!
//! The rVM reuses the RV32 machine's exact proof-system configuration (spec §5's reuse ruling):
//! same field, extension, Poseidon2 permutation, hiding FRI profile and batch machinery. What is
//! new is the chip set and that the verifier key is **program-dependent** (plan R1/R6): the
//! program table is preprocessed, so the preprocessed cap binds every program word and there is
//! no in-circuit `hc` digest.
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, CommonData, ProverData, StarkInstance};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::HidingFriPcs;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub use shrugg_zkvm::machine::{
    Challenge, Challenger, Compress, FriProfile, Hash, Perm, ValMmcs, permutation,
};

/// The rVM's field and proof-system types are the RV32 machine's own aliases.
pub type Val = shrugg_zkvm::machine::Val;
type Dft = Radix2DitParallel<Val>;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

use crate::emulator::{execute, ExecError, Execution};
use crate::isa::{DecodeError, Instr, Op, Program, NUM_REGS};
use crate::tables::cpu::{cpu_trace, perm_events, ram_accesses, register_accesses, CpuAir};
use crate::tables::memory::{memory_trace, MemoryAir};
use crate::tables::pad_height;
use crate::tables::poseidon2::{poseidon2_log_height, poseidon2_trace, Poseidon2Air};
use crate::tables::program::{program_trace, ProgramAir};
use crate::tables::public::{public_trace, PublicAir, NUM_PUBLIC_VALUES};
use crate::tables::range::{range_trace, RangeAir, RangeCounts};
use crate::tables::reduce::{reduce_events, reduce_log_height, reduce_trace, ReduceAir};

/// Fixed seed for the rVM's `key_config` RNGs — the role of `research`'s `machine::KEY_SEED`
/// (a deterministic preprocessed commitment any verifier can recompute standalone), over a
/// different artifact family, so a different arbitrary constant: "RVM_M5_2".
const KEY_SEED: u64 = 0x5256_4d5f_4d35_5f32;

/// The alternative proving backends' Plonky3 configurations (M5.4 Task 1):
/// `research/src/machine.rs`'s `reference_cfg`/`cuda_cfg`, mirrored on the rVM's own
/// `generic_config`.
#[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
pub mod backend;

/// Builds a `Config` from two explicit RNGs: `mmcs_rng` seeds the value MMCS's per-commit
/// hiding salts (used for *every* commit through it, preprocessed traces included), `pcs_rng`
/// seeds the PCS's own random codewords/quotient blinding. Kept private: callers pick a seeding
/// strategy through `make_config` (fresh OS entropy, for proving) or `key_config`
/// (deterministic, for a preprocessed commitment any verifier can recompute).
fn build_config(profile: FriProfile, mmcs_rng: StdRng, pcs_rng: StdRng) -> Config {
    let perm = permutation();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm);
    let val_mmcs = ValMmcs::new(hash, compress, 2, mmcs_rng);
    generic_config(profile, Dft::default(), val_mmcs, pcs_rng)
}

/// The FRI/PCS setup, written once over any value-MMCS and DFT. Every backend goes through
/// here, so "the reference backend uses the same FRI parameters as the CPU one" is not a
/// comment that can drift — `build_config` is literally this function with the Plonky3
/// `ValMmcs`/`Radix2DitParallel` pair, and `backend`'s `reference_config`/`cuda_config` call it
/// with theirs (`research/src/machine.rs`'s `generic_config`, mirrored).
fn generic_config<D, M>(
    profile: FriProfile,
    dft: D,
    val_mmcs: M,
    pcs_rng: StdRng,
) -> StarkConfig<HidingFriPcs<Val, D, M, ExtensionMmcs<Val, Challenge, M>, StdRng>, Challenge, Challenger>
where
    D: p3_dft::TwoAdicSubgroupDft<Val>,
    M: p3_commit::Mmcs<Val, MultiProof: Sync, Error: Sync> + Clone,
{
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let fri = p3_fri::FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: profile.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: profile.pow_bits(),
        mmcs: challenge_mmcs,
    };
    let pcs = HidingFriPcs::new(dft, val_mmcs, fri, 4, pcs_rng);
    StarkConfig::new(pcs, Challenger::new(permutation()))
}

/// The deterministic config behind `verifier_key`: any verifier recomputes the same preprocessed
/// commitment from `(program, tier, reduce)` alone — `research`'s `key_config`, verbatim in role.
fn key_config(profile: FriProfile) -> Config {
    let (mmcs_rng, pcs_rng) = key_rngs();
    build_config(profile, mmcs_rng, pcs_rng)
}

fn key_rngs() -> (StdRng, StdRng) {
    (StdRng::seed_from_u64(KEY_SEED), StdRng::seed_from_u64(KEY_SEED ^ 0x9E37_79B9_7F4A_7C15))
}

pub fn make_config(profile: FriProfile) -> Config {
    build_config(profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()))
}

/// The rVM tier ladder (plan R2): stride 2 through the cheap-test sizes, then every rung near the
/// exit — 19 (the post-cut test-profile verifier program), 21 (the production exit), 22 (the
/// safety rung). **23 is the production N=3 aggregate rung, added with the CUDA backend (M5.4):
/// host ≥ 160 GB (M5.3's derived ~127 GB oracle), device 80 GB class (the plan's R3 device
/// model) — a rung no CPU-only box in this fleet has, pinned by `for_cycles`, not by a proof.**
pub const TIERS: [usize; 11] = [8, 10, 12, 14, 16, 18, 19, 20, 21, 22, 23];

/// Floor on every proof-declared table log-height: one padding row's worth, mirroring the RV32
/// machine's per-table `MIN_LOG_HEIGHT`s.
pub const MIN_LOG_HEIGHT: u8 = 4;
/// The public table's fixed log-height: 4 real rows (the interface digest, R5) plus the padding
/// rule, `pad_height(4 + 1, 4) = 8`.
pub const PUBLIC_LOG_HEIGHT: u8 = 3;
/// Defensive ceiling on the two memory tables' declared log-heights — the RV32
/// `MAX_MEM_LOG_HEIGHT`'s role, one rung wider because the register table carries per-row
/// register traffic the RV32 machine does not.
pub const MAX_MEM_LOG_HEIGHT: u8 = 26;
pub const POSEIDON2_MAX_LOG_HEIGHT: u8 = 20;
pub const REDUCE_MAX_LOG_HEIGHT: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tier(pub usize);
impl Tier {
    pub fn for_cycles(cycles: usize) -> Option<Tier> { TIERS.iter().copied().map(Tier).find(|t| cycles <= t.max_cycles()) }
    pub fn cpu_height(self) -> usize { 1 << self.0 }
    /// One padding row is always kept.
    pub fn max_cycles(self) -> usize { self.cpu_height() - 1 }
}

/// The program table's own floor: 4 rows (the plan's `pad_height(len + 1, 4)` rule) — smaller
/// than `MIN_LOG_HEIGHT`, which floors the *declared* tables' log-heights at 16 rows.
pub const PROGRAM_MIN_HEIGHT: usize = 4;

/// The program table's height rule: one row per instruction plus one padding row, floored — the
/// canonical definition (`tables::program`, Task 2, re-exports it).
pub fn program_log_height(len: usize) -> u8 {
    pad_height(len + 1, PROGRAM_MIN_HEIGHT).trailing_zeros() as u8
}

/// Each instance's extended trace degree bits, in the final `chips()` order — a pure function of
/// the program, the tier and the declared heights, which is why it can be a free function: the
/// batch verifier checks `proof.batch.degree_bits` against it rather than trusting the proof
/// (the RV32 `Machine::log_ext_degrees`'s role).
///
/// Order: `program, cpu, reg_memory, ram_memory, poseidon2, public, range`, plus `reduce` last
/// when the proof declares one (`reduce_log_height != 0`). The `+ 1` per entry is the ZK doubling
/// (`is_zk() == true` for every config this crate builds — they are all `HidingFriPcs`; Task 6's
/// `verify` reads the same fact off the config it uses).
pub fn log_ext_degrees(program: &Program, tier: Tier, reg_log_height: u8, ram_log_height: u8, poseidon2_log_height: u8, reduce_log_height: u8) -> Vec<usize> {
    let zk = 1usize;
    let mut v = vec![
        program_log_height(program.instrs.len()) as usize + zk,
        tier.0 + zk,
        reg_log_height as usize + zk,
        ram_log_height as usize + zk,
        poseidon2_log_height as usize + zk,
        PUBLIC_LOG_HEIGHT as usize + zk,
        crate::tables::range::HEIGHT.trailing_zeros() as usize + zk,
    ];
    if reduce_log_height != 0 {
        v.push(reduce_log_height as usize + zk);
    }
    v
}

/// Every range check on the proof's declared shape, in one place and before anything is sized
/// from it — the RV32 `check_declared_heights`'s role (cheap-before-expensive): an untrusted
/// tier outside `TIERS` or an absurd declared height must be rejected before `1usize << h` is
/// ever evaluated.
pub fn check_declared_heights(tier: Tier, reg_log_height: u8, ram_log_height: u8, poseidon2_log_height: u8, reduce_log_height: u8) -> Result<(), VerifyError> {
    if !TIERS.contains(&tier.0) { return Err(VerifyError::Tier); }
    if !(MIN_LOG_HEIGHT..=MAX_MEM_LOG_HEIGHT).contains(&reg_log_height) { return Err(VerifyError::RegHeight); }
    if !(MIN_LOG_HEIGHT..=MAX_MEM_LOG_HEIGHT).contains(&ram_log_height) { return Err(VerifyError::RamHeight); }
    if !(MIN_LOG_HEIGHT..=POSEIDON2_MAX_LOG_HEIGHT).contains(&poseidon2_log_height) { return Err(VerifyError::Poseidon2Height); }
    // The keccak pattern: 0 is the distinguished "no reduce table" value; any other value is a
    // declared height in range.
    if reduce_log_height != 0 && !(MIN_LOG_HEIGHT..=REDUCE_MAX_LOG_HEIGHT).contains(&reduce_log_height) { return Err(VerifyError::ReduceHeight); }
    Ok(())
}

#[derive(Debug)]
pub enum ProveError {
    Exec(ExecError),
    NoTier(usize),
    TooManyCycles { cycles: usize, tier: Tier },
    /// An explicit `Some(tier)` outside `TIERS` — the prove-side mirror of
    /// `check_declared_heights`' `TIERS.contains` guard (research audit ZH3).
    BadTier(usize),
    /// `check_program` found a word the emulator could never execute (R1: registration-time
    /// legality — the preprocessed table commits to the program, so its words are checked at the
    /// one place they enter the machine).
    Decode(DecodeError),
    /// An alternative proving backend failed: the device path (`Backend::Cuda`) or an engine
    /// panic inside `prove_batch` — `research`'s `ProveError::Backend`, mirrored (M5.4).
    #[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
    Backend(String),
}

/// The proving backend (M5.4 Task 1): `Cpu` is the stock Plonky3 engine pair this machine has
/// always used; `Reference` is `rand-zkvm-cuda`'s CPU-twin engines; `Cuda` is the GPU path
/// (a real device, or the mock driver under `mock-cuda`). `research`'s `Backend`, mirrored.
#[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
#[derive(Clone, Copy, Debug)]
pub enum Backend {
    Cpu,
    #[cfg(feature = "reference-backend")]
    Reference,
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    Cuda,
}

/// Best-effort text of a caught panic payload: `panic!("{e}")` and `panic!("literal")` cover
/// every panic the backend engines raise (`research`'s helper, verbatim).
#[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() { return format!("backend panicked: {s}"); }
    if let Some(s) = p.downcast_ref::<&str>() { return format!("backend panicked: {s}"); }
    "backend panicked".to_string()
}

#[derive(Debug)]
pub enum VerifyError {
    PublicValues,
    Tier,
    Batch(String),
    RegHeight,
    RamHeight,
    Poseidon2Height,    ReduceHeight,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof {
    pub tier: Tier,
    pub reg_log_height: u8,
    pub ram_log_height: u8,
    pub poseidon2_log_height: u8,
    /// 0 is "no reduce instance in this batch" (the keccak pattern), not a height.
    pub reduce_log_height: u8,
    /// Always exactly 4: the program's interface digest (R5).
    pub public_values: Vec<u64>,
    pub batch: BatchProof<Config>,
}
impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> { postcard::to_allocvec(self).expect("proof serialises") }
    pub fn size(&self) -> usize { self.to_bytes().len() }
}

/// Bound on the number of `(program, tier, reduce)` verifier keys kept in memory at once — the
/// RV32 cache's FIFO policy, over a program-keyed space instead (R6).
const KEY_CACHE_CAPACITY: usize = 64;

#[derive(Default)]
struct KeyCache {
    map: HashMap<(usize, [u64; 4], bool), Arc<CommonData<Config>>>,
    order: VecDeque<(usize, [u64; 4], bool)>,
}
impl KeyCache {
    fn get(&self, key: &(usize, [u64; 4], bool)) -> Option<Arc<CommonData<Config>>> {
        self.map.get(key).cloned()
    }
    fn insert(&mut self, key: (usize, [u64; 4], bool), value: Arc<CommonData<Config>>) {
        if self.map.contains_key(&key) { return; }
        if self.map.len() >= KEY_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() { self.map.remove(&oldest); }
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }
}

pub struct Machine { pub config: Config, pub profile: FriProfile, keys: Mutex<KeyCache> }

impl Machine {
    pub fn new(profile: FriProfile) -> Self {
        Self { config: make_config(profile), profile, keys: Mutex::new(KeyCache::default()) }
    }

    /// The preprocessed commitment for `(program, tier, reduce)` (R6), cached. The chip set
    /// grows per task toward the final eight-instance batch (Task 6); the cache key is already
    /// the final one, so no caller changes.
    pub fn verifier_key(&self, program: &Program, tier: Tier, reduce: bool) -> Arc<CommonData<Config>> {
        let digest = program.digest();
        let key = (tier.0, std::array::from_fn(|i| digest[i].as_canonical_u64()), reduce);
        if let Some(hit) = self.keys.lock().unwrap().get(&key) { return hit; }
        let arc = Arc::new(program.clone());
        let airs = chips(&arc, tier, if reduce { MIN_LOG_HEIGHT } else { 0 });
        // The declared heights the key is built with are the *floors*: no table here but
        // `program` and `range` has preprocessed columns, so `CommonData` is invariant to the
        // declared heights — the RV32 `mem_log_height` argument, verbatim (R6).
        let degrees = log_ext_degrees(program, tier, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, if reduce { MIN_LOG_HEIGHT } else { 0 });
        let common = Arc::new(ProverData::from_airs_and_degrees(&key_config(self.profile), &airs, &degrees).common);
        self.keys.lock().unwrap().insert(key, common.clone());
        common
    }

    /// Number of `(program, tier, reduce)` verifier keys currently cached.
    pub fn cached_keys(&self) -> usize { self.keys.lock().unwrap().map.len() }

    /// Registration-time legality (R1): the preprocessed program table commits to every word, so
    /// every word must be something the emulator could execute — the M3.4 invariant
    /// (`research/src/tables/program.rs`'s panic-on-undecodable), moved to the one place the
    /// words enter the machine. The same checks `emulator::execute` makes per row: register
    /// indices in range, and extension pairs not starting at `r31`.
    pub fn check_program(program: &Program) -> Result<(), DecodeError> {
        for instr in &program.instrs {
            check_instr(instr)?;
        }
        Ok(())
    }
}

fn check_instr(instr: &Instr) -> Result<(), DecodeError> {
    let reg = |idx: u8, slot: &'static str| -> Result<(), DecodeError> {
        if idx as usize >= NUM_REGS { return Err(DecodeError::Register { slot, value: idx as u64 }); }
        Ok(())
    };
    let pair = |idx: u8, slot: &'static str| -> Result<(), DecodeError> {
        if idx as usize + 1 >= NUM_REGS { return Err(DecodeError::Register { slot, value: idx as u64 + 1 }); }
        Ok(())
    };
    reg(instr.rd, "rd")?;
    reg(instr.ra, "ra")?;
    if instr.op.b_is_register() {
        reg(instr.rb(), "rb")?;
    }
    match instr.op {
        Op::Eadd | Op::Esub | Op::Emul => { pair(instr.rd, "rd")?; pair(instr.ra, "ra")?; pair(instr.rb(), "rb")?; }
        Op::Emulf | Op::Einv => { pair(instr.rd, "rd")?; pair(instr.ra, "ra")?; }
        Op::Loade | Op::Storee | Op::Hinte => { pair(instr.rd, "rd")?; }
        _ => {}
    }
    Ok(())
}


/// The traces of one proving run, in `chips()` order — the RV32 `Traces`'s role, with the
/// declared heights carried alongside so `prove_traces` and the eventual `Proof` agree on
/// exactly the values `build_traces` chose (the `program_log_height` doc comment's rule,
/// applied to every proof-declared table).
pub struct Traces {
    pub program: RowMajorMatrix<Val>,
    pub cpu: RowMajorMatrix<Val>,
    pub reg: RowMajorMatrix<Val>,
    pub ram: RowMajorMatrix<Val>,
    pub poseidon2: RowMajorMatrix<Val>,
    pub public: RowMajorMatrix<Val>,
    pub range: RowMajorMatrix<Val>,
    /// The reduce chip's trace, when this proof declares the table (Task 8, the keccak pattern):
    /// `None` for a program with no `REDUCE` row, and `reduce_log_height == 0` with it.
    pub reduce: Option<RowMajorMatrix<Val>>,
    /// Always exactly 4 (R5): the program's interface digest, `Execution::public`.
    pub public_values: Vec<Val>,
    pub reg_log_height: u8,
    pub ram_log_height: u8,
    pub poseidon2_log_height: u8,
    pub reduce_log_height: u8,
}
impl Traces {
    /// The traces in `chips()` order; the `i`-th entry pairs with the `i`-th chip, which is what
    /// keeps `PUBLIC_VALUES_INDEX` correct.
    pub fn as_slice(&self) -> Vec<&RowMajorMatrix<Val>> {
        let mut v = vec![&self.program, &self.cpu, &self.reg, &self.ram, &self.poseidon2, &self.public, &self.range];
        if let Some(reduce) = &self.reduce {
            v.push(reduce);
        }
        v
    }
    pub fn heights(&self) -> Vec<usize> { self.as_slice().iter().map(|m| m.height()).collect() }
}

/// Build every table's trace from the execution: the cpu rows, the synthesized register traffic
/// and the emulator's RAM log split across the two memory tables, the chip's permutations, the
/// program's fetch counts, the published digest, and the shared range counts. The declared
/// heights are sized from the workload itself (`pad_height(count + 1, floor)`), the RV32
/// declared-height rule.
pub fn build_traces(program: &Program, exec: &Execution, tier: Tier) -> Result<Traces, ProveError> {
    let mut counts = RangeCounts::default();
    let cpu = cpu_trace(&exec.events, tier.cpu_height(), &mut counts);
    let reg_acc = register_accesses(&exec.events);
    let reg_log_height = pad_height(reg_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let reg = memory_trace(&reg_acc, 1 << reg_log_height, &mut counts);
    let ram_acc = ram_accesses(&exec.events);
    let ram_log_height = pad_height(ram_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let ram = memory_trace(&ram_acc, 1 << ram_log_height, &mut counts);
    let perms = perm_events(&exec.events);
    let p2_log = poseidon2_log_height(perms.len());
    let poseidon2 = poseidon2_trace(&perms, 1 << p2_log);
    let program_t = program_trace(program, &exec.events, 1 << program_log_height(program.instrs.len()));
    let public = public_trace(&exec.public, crate::tables::public::HEIGHT);
    let range = range_trace(&counts);
    let reduce_evs = reduce_events(&exec.events);
    let reduce_rows: usize = reduce_evs.iter().map(|e| e.reduce.unwrap().len as usize).sum();
    let reduce_lh = reduce_log_height(reduce_rows);
    let reduce = if reduce_lh == 0 { None } else { Some(reduce_trace(&reduce_evs, 1 << reduce_lh)) };
    Ok(Traces {
        program: program_t,
        cpu,
        reg,
        ram,
        poseidon2,
        public,
        range,
        reduce,
        public_values: exec.public.clone(),
        reg_log_height,
        ram_log_height,
        poseidon2_log_height: p2_log,
        reduce_log_height: reduce_lh,
    })
}

impl Machine {
    /// Run the program and prove the run (plan Task 6). No salt, no input commitment (spec §2):
    /// the witness is a public tape — the only entropy drawn is the hiding PCS's own, inside
    /// `make_config`, per proving call.
    pub fn prove(&self, program: &Program, witness: &[Val], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        // Registration-time legality (R1): the preprocessed table commits to every word.
        Self::check_program(program).map_err(ProveError::Decode)?;
        // Run up to the largest tier's cycle budget; a program that has not halted by then can
        // never be proved, so `OutOfCycles` and `NoTier` agree on the limit.
        let exec = execute(program, witness, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            Some(t) if TIERS.contains(&t.0) => t,
            // The prove-side mirror of `check_declared_heights`' `TIERS.contains` guard.
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => Tier::for_cycles(exec.cpu_rows()).ok_or(ProveError::NoTier(exec.cpu_rows()))?,
        };
        let traces = build_traces(program, &exec, tier)?;
        Ok((self.prove_traces(program, &traces, tier), exec))
    }

    /// The body of `prove`, over already-built traces — the cheating tests' entry point, exactly
    /// the RV32 `prove_traces`'s role: a tampered trace goes in, and `prove_batch`'s debug
    /// constraint checker (or the batch verifier on the produced proof) is what must catch it.
    pub fn prove_traces(&self, program: &Program, traces: &Traces, tier: Tier) -> Proof {
        let arc = Arc::new(program.clone());
        let airs = chips(&arc, tier, traces.reduce_log_height);
        let mats = traces.as_slice();
        assert_eq!(airs.len(), mats.len(), "one trace per chip");
        let instances: Vec<StarkInstance<'_, Config, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == PUBLIC_VALUES_INDEX { traces.public_values.clone() } else { vec![] },
        }).collect();
        // Built with `key_config` so the preprocessed tree's commitment matches exactly what a
        // verifier recomputes via `verifier_key`; `prove_batch` itself runs against
        // `self.config` (fresh entropy) for the main/quotient/permutation commitments.
        let key_cfg = key_config(self.profile);
        let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &log_ext_degrees(program, tier, traces.reg_log_height, traces.ram_log_height, traces.poseidon2_log_height, traces.reduce_log_height));
        let batch = prove_batch(&self.config, &instances, &prover_data);
        Proof {
            tier,
            reg_log_height: traces.reg_log_height,
            ram_log_height: traces.ram_log_height,
            poseidon2_log_height: traces.poseidon2_log_height,
            reduce_log_height: traces.reduce_log_height,
            public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(),
            batch,
        }
    }

    /// Prove on `backend` (M5.4 Task 1). `Backend::Cpu` is exactly `prove`; the other backends
    /// run the same batch STARK with `rand-zkvm-cuda`'s engines and hand back a `Proof` that
    /// this `Machine`'s own `verify` accepts (`research/src/machine.rs`'s `prove_with`,
    /// mirrored).
    #[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
    pub fn prove_with(&self, backend: Backend, program: &Program, witness: &[Val], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError> {
        match backend {
            Backend::Cpu => self.prove(program, witness, tier),
            #[cfg(feature = "reference-backend")]
            Backend::Reference => {
                // Fresh entropy for the proving config (hiding), deterministic for the key
                // config — the same split `make_config`/`key_config` make on the CPU.
                let cfg = backend::reference_config(self.profile, StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = backend::reference_config(self.profile, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, witness, tier)
            }
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Backend::Cuda => {
                let gpu = rand_zkvm_cuda::gpu::GpuProver::probe(backend::PERM_SEED).map_err(|e| ProveError::Backend(e.to_string()))?;
                let cfg = backend::cuda_config(self.profile, gpu.clone(), StdRng::from_rng(&mut rand::rng()), StdRng::from_rng(&mut rand::rng()));
                let (mmcs_rng, pcs_rng) = key_rngs();
                let key = backend::cuda_config(self.profile, gpu, mmcs_rng, pcs_rng);
                self.prove_on(&cfg, &key, program, witness, tier)
            }
        }
    }

    /// The body of `prove` over any structurally compatible config. The proof is converted to
    /// the CPU `Config` by a postcard round trip: the alternative configs commit with the same
    /// Poseidon2 permutation, the same salt stream and the same FRI parameters, so the wire
    /// encodings of their commitments and opening proofs are byte-identical to the CPU ones and
    /// the decode is a pure retyping.
    ///
    /// `key_cfg` must be seeded from `key_rngs`: the preprocessed commitment is what the
    /// verifier recomputes on the CPU via `verifier_key`, and the backend has to reproduce it
    /// exactly or verification fails at the first check.
    ///
    /// NOTE: this body is a deliberate duplicate of `prove`/`prove_traces`'s (which cannot be
    /// generic over `SC` because `Proof` names the CPU `Config`). Instance construction, the
    /// public-values placement, and the `key_cfg`/`cfg` split must stay identical in all three,
    /// or a backend proof stops matching what the CPU verifier recomputes. Change one, change
    /// the others.
    #[cfg(any(feature = "reference-backend", feature = "cuda", feature = "mock-cuda"))]
    fn prove_on<SC>(&self, cfg: &SC, key_cfg: &SC, program: &Program, witness: &[Val], tier: Option<Tier>) -> Result<(Proof, Execution), ProveError>
    where
        SC: StarkGenericConfig<Challenge = Challenge, Challenger = Challenger>,
        // Bounds copied from `p3_batch_stark::prove_batch`'s signature, plus the pin that
        // makes this config's base field our `Val` so `Chip`'s `Air` impls apply.
        SC::Pcs: p3_commit::Pcs<Challenge, Challenger, Domain: p3_commit::PolynomialSpace<Val = Val>> + Sync,
        p3_batch_stark::Domain<SC>: Send + Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::ProverData: Sync,
        <SC::Pcs as p3_commit::Pcs<Challenge, Challenger>>::Commitment: Sync,
    {
        // Registration-time legality (R1): the preprocessed table commits to every word.
        Self::check_program(program).map_err(ProveError::Decode)?;
        // Run up to the largest tier's cycle budget, exactly as `prove` does.
        let exec = execute(program, witness, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(ProveError::Exec)?;
        let tier = match tier {
            Some(t) if TIERS.contains(&t.0) => t,
            Some(t) => return Err(ProveError::BadTier(t.0)),
            None => Tier::for_cycles(exec.cpu_rows()).ok_or(ProveError::NoTier(exec.cpu_rows()))?,
        };
        let traces = build_traces(program, &exec, tier)?;
        let arc = Arc::new(program.clone());
        let airs = chips(&arc, tier, traces.reduce_log_height);
        let mats = traces.as_slice();
        assert_eq!(airs.len(), mats.len(), "one trace per chip");
        let instances: Vec<StarkInstance<'_, SC, Chip>> = airs.iter().zip(mats.iter()).enumerate().map(|(i, (air, trace))| StarkInstance {
            air, trace, public_values: if i == PUBLIC_VALUES_INDEX { traces.public_values.clone() } else { vec![] },
        }).collect();
        let prover_data = ProverData::from_airs_and_degrees(key_cfg, &airs, &log_ext_degrees(program, tier, traces.reg_log_height, traces.ram_log_height, traces.poseidon2_log_height, traces.reduce_log_height));
        // The engines panic (rather than return) on a device failure — `CudaHashEngine::ok`
        // and friends — so a backend fault must not take the caller's process down with it.
        let batch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(cfg, &instances, &prover_data)))
            .map_err(|p| ProveError::Backend(panic_message(p)))?;
        let bytes = postcard::to_allocvec(&batch).map_err(|e| ProveError::Backend(format!("proof serialise: {e}")))?;
        let batch: BatchProof<Config> = postcard::from_bytes(&bytes).map_err(|e| ProveError::Backend(format!("proof convert: {e}")))?;
        Ok((Proof {
            tier,
            reg_log_height: traces.reg_log_height,
            ram_log_height: traces.ram_log_height,
            poseidon2_log_height: traces.poseidon2_log_height,
            reduce_log_height: traces.reduce_log_height,
            public_values: traces.public_values.iter().map(|x| x.as_canonical_u64()).collect(),
            batch,
        }, exec))
    }

    /// R6: the verifier holds the registered program; the preprocessed cap is the binding (there
    /// is no `hc` public value to check — that is what a preprocessed program table means).
    pub fn verify(&self, program: &Program, proof: &Proof) -> Result<(), VerifyError> {
        if proof.public_values.len() != NUM_PUBLIC_VALUES { return Err(VerifyError::PublicValues); }
        // `public_values` is deserialized from untrusted bytes as raw `u64`s, and
        // `Val::from_u64` does not reduce: insist on the canonical representative so a proof has
        // exactly one encoding of its interface digest.
        if proof.public_values.iter().any(|x| *x >= <Val as PrimeField64>::ORDER_U64) { return Err(VerifyError::PublicValues); }
        // Every range check on the proof's declared shape, before anything is sized from it.
        check_declared_heights(proof.tier, proof.reg_log_height, proof.ram_log_height, proof.poseidon2_log_height, proof.reduce_log_height)?;
        // A `Vec` comparison: simultaneously the batch's instance-count check and every declared
        // height's.
        if proof.batch.degree_bits != log_ext_degrees(program, proof.tier, proof.reg_log_height, proof.ram_log_height, proof.poseidon2_log_height, proof.reduce_log_height) { return Err(VerifyError::Tier); }
        let arc = Arc::new(program.clone());
        let airs = chips(&arc, proof.tier, proof.reduce_log_height);
        let pv_vals: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..airs.len()).map(|i| if i == PUBLIC_VALUES_INDEX { pv_vals.clone() } else { vec![] }).collect();
        let common = self.verifier_key(program, proof.tier, proof.reduce_log_height != 0);
        verify_batch(&self.config, &airs, &proof.batch, &pvs, &common).map_err(|e| VerifyError::Batch(format!("{e:?}")))
    }
}

/// Symbolic max constraint degree of each chip, in `chips()` order — computed the same way
/// `ProverData::from_airs_and_degrees` derives each instance's quotient-chunk count, against the
/// real, same-bus-packed lookup contexts. Exists to back the per-table degree regression tests
/// (`research`'s `max_constraint_degrees`'s role, over a program-carrying chip set).
pub fn max_constraint_degrees(program: &Program, tier: Tier) -> Vec<usize> {
    let machine = Machine::new(FriProfile::Test);
    let key_cfg = key_config(machine.profile);
    let arc = Arc::new(program.clone());
    let airs = chips(&arc, tier, 0);
    let is_zk = machine.config.is_zk();
    let ext_degrees = log_ext_degrees(program, tier, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, MIN_LOG_HEIGHT, 0); // max_constraint_degrees is reduce-free
    let prover_data = ProverData::from_airs_and_degrees(&key_cfg, &airs, &ext_degrees);
    let lookup_gadget = p3_lookup::LogUpGadget::new();
    airs.iter()
        .zip(prover_data.common.lookups.iter())
        .zip(ext_degrees.iter())
        .map(|((air, lookups), &ext_db)| {
            let trace_len = 1usize << (ext_db - is_zk);
            p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, Chip, _>(
                air,
                p3_air::symbolic::AirLayout::from_air(air),
                trace_len,
                lookups,
                &lookup_gadget,
            )
        })
        .collect()
}

/// The machine's chips, in the final `chips()` order's relative positions: `program, cpu,
/// reg_memory, ram_memory, poseidon2, public, range`, `reduce` last when declared. The set grows
/// per task (Task 2: `program` + `range`) — the order is load-bearing: the public table owns the
/// batch's public values at instance index 5, and `prove`/`verify` (Task 6) hard-code it.
pub fn chips(program: &Arc<Program>, _tier: Tier, reduce_log_height: u8) -> Vec<Chip> {
    let mut v = vec![
        Chip::Program(ProgramAir::new(program.clone())),
        Chip::Cpu(CpuAir),
        Chip::RegMemory(MemoryAir { register: true }),
        Chip::RamMemory(MemoryAir { register: false }),
        Chip::Poseidon2(Poseidon2Air),
        Chip::Public(PublicAir),
        Chip::Range(RangeAir),
    ];
    // The keccak pattern, exactly: `reduce_log_height == 0` means the batch has no reduce
    // instance at all, and the REDUCE bus then has no provider, so a `REDUCE` row cannot be
    // proved absent the table. Appended last, so it cannot disturb `PUBLIC_VALUES_INDEX`.
    if reduce_log_height != 0 {
        v.push(Chip::Reduce(ReduceAir));
    }
    v
}

/// The batch instance that owns the public values: `chips()[5]` is the public table (R5), and
/// `prove`/`verify` hard-code the slot, exactly the RV32 machine's `i == 1` discipline — Task 8's
/// reduce chip goes last, so it cannot disturb this index.
pub const PUBLIC_VALUES_INDEX: usize = 5;

/// The machine's chips. Later tables append their variants in the final `chips()` order.
#[derive(Clone, Debug)]
pub enum Chip {
    Program(ProgramAir),
    Cpu(CpuAir),
    RegMemory(MemoryAir),
    RamMemory(MemoryAir),
    Poseidon2(Poseidon2Air),
    Public(PublicAir),
    Range(RangeAir),
    Reduce(ReduceAir),
}

impl p3_air::BaseAir<Val> for Chip {
    fn width(&self) -> usize {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Cpu(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::RegMemory(a) | Chip::RamMemory(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Poseidon2(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Public(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::width(a),
            Chip::Reduce(a) => p3_air::BaseAir::<Val>::width(a),
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Cpu(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::RegMemory(a) | Chip::RamMemory(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Poseidon2(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Public(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
            Chip::Reduce(a) => p3_air::BaseAir::<Val>::preprocessed_width(a),
        }
    }
    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<Val>> {
        match self {
            Chip::Program(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Cpu(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::RegMemory(a) | Chip::RamMemory(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Poseidon2(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Public(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Range(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
            Chip::Reduce(a) => p3_air::BaseAir::<Val>::preprocessed_trace(a),
        }
    }
    /// The public table owns the batch's public values (R5); every other chip declares none.
    fn num_public_values(&self) -> usize {
        match self {
            Chip::Public(a) => p3_air::BaseAir::<Val>::num_public_values(a),
            _ => 0,
        }
    }
}

impl<AB> p3_air::Air<AB> for Chip
where
    AB: p3_air::AirBuilder<F = Val> + p3_air::PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Chip::Program(a) => p3_air::Air::eval(a, b),
            Chip::Cpu(a) => p3_air::Air::eval(a, b),
            Chip::RegMemory(a) | Chip::RamMemory(a) => p3_air::Air::eval(a, b),
            Chip::Poseidon2(a) => p3_air::Air::eval(a, b),
            Chip::Public(a) => p3_air::Air::eval(a, b),
            Chip::Range(a) => p3_air::Air::eval(a, b),
            Chip::Reduce(a) => p3_air::Air::eval(a, b),
        }
    }
}
