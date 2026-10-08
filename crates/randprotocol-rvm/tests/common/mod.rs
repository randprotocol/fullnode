//! Real bundle proofs, the only proofs this crate's tests ever verify.
//!
//! Built from `randprotocol_zkvm`'s public API the way `research/tests/bundle.rs::fixture()` does — two
//! minted input notes, an anchor, two outputs, a fee — varying the input amounts so that `n`
//! proofs are `n` genuinely different witnesses. Proofs are cached on disk
//! (`$RECURSION_FIXTURES`, default `target/recursion-fixtures`) because a production-profile one
//! costs ~95 s to prove and even a `FriProfile::Test` one costs tens of seconds.
//!
//! Nothing here builds a *synthetic* proof. A hand-made `Proof` would let the verifier port agree
//! with a second implementation of the same misunderstanding; the whole point of this crate's tests
//! is that the program accepts exactly what `Machine::verify` accepts, so the proofs have to come
//! from `Machine::prove`.
use randprotocol_zkvm::ledger::Ledger;
use randprotocol_zkvm::machine::{FriProfile, Machine, Proof};
use randprotocol_zkvm::notes::{self, Note, SpendKey, ViewingKey, Word8, DEPTH};
use randprotocol_zkvm::viewing::{Envelope, TxKey};

/// `research/tests/bundle.rs`'s own test-local `Party` (it is not public API), reproduced here so
/// the fixtures need no change in `research/`.
pub struct Party {
    pub sk: SpendKey,
    pub vk: ViewingKey,
}
impl Party {
    pub fn new() -> Party {
        let sk = SpendKey::random();
        Party { sk, vk: sk.viewing_key() }
    }
}

/// One proof and the guest digest it was proved against — everything `Machine::verify` needs.
pub struct BundleProof {
    pub proof: Proof,
    pub hc: Word8,
}

/// The aggregate-binding words the aggregate family's tests use (audit v3, AGG-2): on a chain
/// this is `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`, derived in
/// `randprotocol_core`; here it is a fixed stand-in — the rVM absorbs the eight words like any
/// other, and the tests are about position, not derivation.
pub const TEST_BINDING: [u32; 8] = [0xA662_0000, 0xA662_0001, 0xA662_0002, 0xA662_0003, 0xA662_0004, 0xA662_0005, 0xA662_0006, 0xA662_0007];

/// `$RECURSION_FIXTURES`, or `target/recursion-fixtures` under this crate.
pub fn cache_dir() -> std::path::PathBuf {
    match std::env::var_os("RECURSION_FIXTURES") {
        Some(d) => std::path::PathBuf::from(d),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/recursion-fixtures"),
    }
}

fn cache_path(profile: FriProfile, k: usize) -> std::path::PathBuf {
    cache_dir().join(format!("{profile:?}-{k}.proof"))
}

/// The cached `(hc, proof)` pair, or `None` when there is no usable file. A file that fails to
/// decode — *or that no longer verifies* — is treated as absent rather than as an error: the
/// encoding is `postcard` over a type this repository changes, so a stale cache must never be a test
/// failure, it must be a reprove.
///
/// The re-verification is the point of doing it here rather than only on the proving path
/// (`bundle_proofs` already asserts it for a freshly proved one). Every test in this crate is a
/// differential claim against `Machine::verify`, so a cached proof that the *current* machine
/// refuses would make every one of them vacuous — and the cache lives under `target/`, across
/// commits that change the constraint set or the profile. It costs ~0.2 s per proof against the
/// tens of seconds a reprove costs.
fn load_cached(m: &Machine, profile: FriProfile, k: usize) -> Option<BundleProof> {
    let bytes = std::fs::read(cache_path(profile, k)).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut hc = [0u32; 8];
    for (i, w) in hc.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    let proof: Proof = postcard::from_bytes(&bytes[32..]).ok()?;
    m.verify(&hc, &proof).ok()?;
    Some(BundleProof { proof, hc })
}

fn store_cached(profile: FriProfile, k: usize, p: &BundleProof) {
    let dir = cache_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut bytes: Vec<u8> = p.hc.iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.extend(p.proof.to_bytes());
    // A write failure is not a test failure: the cache is an optimisation.
    let _ = std::fs::write(cache_path(profile, k), bytes);
}

/// The pin file the cycle-budget test reads: written on the first run, committed, asserted after.
// `common` is compiled into every test binary; these are used only by `exit.rs` (and Task 7's
// `precompiles.rs`), so the other binaries would report them as dead.
#[allow(dead_code)]
pub struct Pins {
    pub cpu_rows: usize,
    pub permutations: usize,
    pub mem_accesses: usize,
    pub witness_words: usize,
    pub program_instrs: usize,
}

#[allow(dead_code)]
fn pins_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pins.json")
}

/// `recursion/tests/pins.json`, parsed. When the file is absent this *is* the measurement run: it
/// measures, writes the file (which the task then commits) and returns the same values, so the run
/// that produces the pin passes with it and every later run is a diff against it.
#[allow(dead_code)]
pub fn pins() -> Pins {
    if let Ok(s) = std::fs::read_to_string(pins_path()) {
        return parse_pins(&s);
    }
    let r = measure_production_inner_proof();
    let p = Pins {
        cpu_rows: r.cpu_rows,
        permutations: r.permutations,
        mem_accesses: r.mem_accesses,
        witness_words: r.witness_words,
        program_instrs: r.program_instrs,
    };
    let json = format!(
        "{{\n  \"cpu_rows\": {},\n  \"permutations\": {},\n  \"mem_accesses\": {},\n  \
         \"witness_words\": {},\n  \"program_instrs\": {}\n}}\n",
        p.cpu_rows, p.permutations, p.mem_accesses, p.witness_words, p.program_instrs
    );
    std::fs::write(pins_path(), json).expect("the pin file is writable");
    p
}

/// The five numeric fields of the hand-rolled pin JSON, in the order [`pins`] writes them.
#[allow(dead_code)]
fn parse_pins(s: &str) -> Pins {
    let get = |key: &str| -> usize {
        s.split(&format!("\"{key}\": "))
            .nth(1)
            .and_then(|rest| rest.split([',', '\n', ' ', '}']).next())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("pins.json: no numeric field {key:?}: {s}"))
    };
    Pins {
        cpu_rows: get("cpu_rows"),
        permutations: get("permutations"),
        mem_accesses: get("mem_accesses"),
        witness_words: get("witness_words"),
        program_instrs: get("program_instrs"),
    }
}

/// Task 6's measurement, reused by Task 7's re-measurement: one production-profile inner proof
/// through the shipped (`Checkpoints::Off`) program.
#[allow(dead_code)]
pub fn measure_production_inner_proof() -> randprotocol_rvm::programs::CycleReport {
    use randprotocol_rvm::dsl::Checkpoints;
    use randprotocol_rvm::programs::verify_rv32;
    use randprotocol_rvm::shape::{InnerKey, InnerShape};
    use randprotocol_rvm::witness::WitnessTape;
    let p = bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Production, &shape, &key, &p.proof).unwrap();
    let exec = randprotocol_rvm::emulator::execute(&vp.program, &tape.words, 1 << 24).unwrap();
    randprotocol_rvm::programs::cycle_report(&vp, &exec)
}

// ── M5.3's per-N aggregate pins ──────────────────────────────────────────────────────────────

/// The aggregate of `n` fixture proofs through the shipped N-generic program, returned as a
/// `CycleReport` (cpu rows, permutations, mem accesses, program instrs, witness words) — M5.3
/// Task 5's measurement.
#[allow(dead_code)]
pub fn measure_aggregate(n: usize, profile: FriProfile) -> randprotocol_rvm::programs::CycleReport {
    use randprotocol_rvm::dsl::Checkpoints;
    use randprotocol_rvm::programs::verify_rv32n;
    use randprotocol_rvm::shape::{InnerKey, InnerShape};
    use randprotocol_rvm::witness::WitnessTape;
    let proofs: Vec<Proof> = bundle_proofs(profile, n).into_iter().map(|p| p.proof).collect();
    let pr = &proofs[0];
    let shape = InnerShape::of(
        profile,
        pr.tier,
        pr.program_log_height,
        pr.input_log_height,
        pr.keccak_log_height,
        pr.sha256_log_height,
        pr.public_log_height,
        pr.mem_log_height,
    );
    let key = InnerKey::of(profile, &shape);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(profile, &shape, &key, &proofs, &TEST_BINDING).unwrap();
    let exec = randprotocol_rvm::emulator::execute(&vp.program, &tape.words, 1 << 24).unwrap();
    randprotocol_rvm::programs::cycle_report(&vp, &exec)
}

/// The per-N aggregate pins (test profile, N = 1, 2, 3), kept beside the single-proof
/// production pins in `tests/pins.json`.
#[allow(dead_code)]
pub struct AggregatePins {
    pub cpu_rows: [usize; 3],
    pub permutations: [usize; 3],
    pub mem_accesses: [usize; 3],
    pub witness_words: [usize; 3],
}

/// `tests/pins.json`'s aggregate section, parsed. When any aggregate key is absent this *is*
/// the measurement run: it measures N = 1, 2, 3 at the test profile (emulation, minutes for the
/// fixtures at worst, seconds when they are cached), rewrites the file with the legacy five
/// fields preserved, and returns the same values — [`pins`]' own discipline, so a changed
/// number is a failing diff against a committed value.
#[allow(dead_code)]
pub fn aggregate_pins() -> AggregatePins {
    let legacy = pins();
    let path = pins_path();
    let s = std::fs::read_to_string(&path).unwrap_or_default();
    let get = |key: &str| -> Option<usize> {
        s.split(&format!("\"{key}\": "))
            .nth(1)
            .and_then(|rest| rest.split([',', '\n', ' ', '}']).next())
            .and_then(|v| v.parse().ok())
    };
    let fields = ["cpu_rows", "permutations", "mem_accesses", "witness_words"];
    if fields.iter().all(|f| (1..=3).all(|n| get(&format!("aggregate_test_n{n}_{f}")).is_some())) {
        let at = |f: &str, n: usize| get(&format!("aggregate_test_n{n}_{f}")).unwrap();
        return AggregatePins {
            cpu_rows: [at("cpu_rows", 1), at("cpu_rows", 2), at("cpu_rows", 3)],
            permutations: [at("permutations", 1), at("permutations", 2), at("permutations", 3)],
            mem_accesses: [at("mem_accesses", 1), at("mem_accesses", 2), at("mem_accesses", 3)],
            witness_words: [at("witness_words", 1), at("witness_words", 2), at("witness_words", 3)],
        };
    }
    let rs = [
        measure_aggregate(1, FriProfile::Test),
        measure_aggregate(2, FriProfile::Test),
        measure_aggregate(3, FriProfile::Test),
    ];
    // Phase 3 Task 0: the hand-written `phase3_attribution` block survives a re-measure.
    let block = s.find("\"phase3_attribution\"").map(|at| {
        let close = at + s[at..].find('}').expect("the attribution block closes");
        s[at..=close].to_string()
    });
    let mut json = format!(
        "{{\n  \"cpu_rows\": {},\n  \"permutations\": {},\n  \"mem_accesses\": {},\n  \
         \"witness_words\": {},\n  \"program_instrs\": {},\n",
        legacy.cpu_rows, legacy.permutations, legacy.mem_accesses, legacy.witness_words,
        legacy.program_instrs
    );
    for (i, r) in rs.iter().enumerate() {
        let n = i + 1;
        let comma = if n == 3 && block.is_none() { "" } else { "," };
        json += &format!(
            "  \"aggregate_test_n{n}_cpu_rows\": {},\n  \"aggregate_test_n{n}_permutations\": {},\n  \
             \"aggregate_test_n{n}_mem_accesses\": {},\n  \"aggregate_test_n{n}_witness_words\": {}{comma}\n",
            r.cpu_rows, r.permutations, r.mem_accesses, r.witness_words
        );
    }
    if let Some(b) = &block {
        json += &format!("  {b}\n");
    }
    json += "}\n";
    std::fs::write(&path, json).expect("the pin file is writable");
    AggregatePins {
        cpu_rows: [rs[0].cpu_rows, rs[1].cpu_rows, rs[2].cpu_rows],
        permutations: [rs[0].permutations, rs[1].permutations, rs[2].permutations],
        mem_accesses: [rs[0].mem_accesses, rs[1].mem_accesses, rs[2].mem_accesses],
        witness_words: [rs[0].witness_words, rs[1].witness_words, rs[2].witness_words],
    }
}

/// `src/programs/verify_rv32.digest`, trimmed — written on the first measurement run and committed.
#[allow(dead_code)]
pub fn committed_digest() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/programs/verify_rv32.digest");
    if let Ok(s) = std::fs::read_to_string(&path) {
        return s.trim().to_string();
    }
    use randprotocol_rvm::dsl::Checkpoints;
    use randprotocol_rvm::programs::verify_rv32;
    use randprotocol_rvm::shape::{InnerKey, InnerShape};
    let p = bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let hex = randprotocol_rvm::programs::digest_hex(&vp.program);
    std::fs::write(&path, format!("{hex}\n")).expect("the digest file is writable");
    hex
}

#[allow(dead_code)]
pub fn random_felt(rng: &mut impl rand::Rng) -> randprotocol_rvm::isa::F {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use rand::RngExt;
    randprotocol_rvm::isa::F::from_u64(rng.random::<u64>() % randprotocol_rvm::isa::F::ORDER_U64)
}

#[allow(dead_code)]
pub fn random_ext(rng: &mut impl rand::Rng) -> randprotocol_rvm::isa::EF {
    use p3_field::BasedVectorSpace;
    let c = [random_felt(rng), random_felt(rng)];
    randprotocol_rvm::isa::EF::from_basis_coefficients_slice(&c).expect("an extension element is two coefficients")
}

/// `n` distinct honest bundle proofs at `profile`, cached on disk by `(profile, k)`.
pub fn bundle_proofs(profile: FriProfile, n: usize) -> Vec<BundleProof> {
    let m = Machine::new(profile);
    (0..n).map(|k| bundle_proof_at(&m, profile, k)).collect()
}

/// Fixture `k` alone — the cached one, or a fresh proof stored to the cache. Separate from
/// [`bundle_proofs`] so a cache can be generated `k` by `k` in parallel processes
/// (`tests/fixtures.rs`); the proof is the same one either way, fixture `k`'s witness.
pub fn bundle_proof_at(m: &Machine, profile: FriProfile, k: usize) -> BundleProof {
    if let Some(p) = load_cached(m, profile, k) {
        return p;
    }
    let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
    let (asset, mint_time) = (0u32, 1_700_000_000u32);
    let mut ledger = Ledger::new(mint_time);
    // A different witness per k, and one that still conserves value below.
    let amounts = [1_000u64 + k as u64, 2_000 + 2 * k as u64];
    let in_notes: [Note; 2] = amounts.map(|amount| {
        let n = Note::new(alice.vk.pk(), bridge.vk.pk(), amount, asset, mint_time);
        let env = Envelope::seal(&bridge.vk, &alice.vk.address(), &n, &TxKey::random());
        ledger.mint(&n, env).unwrap();
        n
    });
    ledger.advance(60);
    let (time, anchor) = (ledger.now, ledger.root());
    let inputs: [(Note, [Word8; DEPTH], u32); 2] = std::array::from_fn(|i| {
        let (path, index) = ledger.path_for(&in_notes[i].commitment()).unwrap();
        (in_notes[i], path, index)
    });
    let total = amounts[0] + amounts[1];
    let (fee, burn) = (100u64, 0u64);
    let outputs = [
        Note::new(bob.vk.pk(), alice.vk.pk(), total - fee - 500, asset, time),
        Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
    ];
    let inputs_vec =
        notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
    // The public segment is empty for bundle proofs: the chain admits only
    // `verify_public(hc, &[], _)`, so the fixtures prove with `&[]` — and `H_PUB` is then
    // the prover-computed digest of the empty segment, carried as ordinary public values.
    let (proof, _) = m.prove(&ledger.bundle_program, &inputs_vec, &[], None).unwrap();
    let hc = ledger.bundle_program.digest();
    m.verify(&hc, &proof).expect("a fixture proof must verify natively");
    let p = BundleProof { proof, hc };
    store_cached(profile, k, &p);
    p
}

// ── `rejects()`, the cheating-test discipline ────────────────────────────────────────────────
// The one definition of what counts as "the constraint system caught this", re-homed from
// `research/tests/common/mod.rs` per the M5.2 plan (its self-test lives in `tests/machine.rs`).
// Every cheating test in this crate counts a rejection through this helper and nothing else.
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint (`check_constraints.rs`'s `panic!`); matching the fixed prefix is what separates
/// "the constraint system caught this" from any other unwind. It runs per AIR instance, so it
/// catches violations local to one table's own rows.
#[allow(dead_code)]
pub const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// The panic `p3-lookup`'s debug bus-balance checker (`p3_lookup::debug_util::check_lookups`)
/// raises when a *global* lookup — provider and consumers in different AIR instances — has a
/// nonzero net multiplicity for some tuple. The only mechanism that catches an unpaid table
/// multiplicity on a table with no row-level validity marker of its own.
#[allow(dead_code)]
pub const LOOKUP_BALANCE_PANIC: &str = "Lookup mismatch (";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// one of the two constraint-system checks above. Anything else — a trace-builder `assert!`,
/// an index out of bounds — means the test tripped over something other than the constraint it
/// was written for, so it must fail rather than pass for the wrong reason.
#[allow(dead_code)]
pub fn rejects(f: impl FnOnce() -> Result<(), randprotocol_rvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC) || msg.contains(LOOKUP_BALANCE_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}

// ── Symbolic reads of an AIR (the binding tests: `tests/cpu.rs`, `tests/tables.rs`) ──────────
// The tests that check a table's soundness *rules* — every written value bound, every run row
// chained to the one before, no padding row sending anything — do not keep their own list of
// what a table's `eval` does: they run `eval` through Plonky3's own symbolic interaction builder
// and evaluate the constraints and messages it really emits at concrete rows. Deleting a
// constraint or a send changes what they see.
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};

/// Every global interaction and base constraint `air.eval` emits.
#[allow(dead_code)]
pub fn symbolic_air<A>(air: &A) -> (Vec<p3_lookup::SymbolicInteraction<randprotocol_rvm::isa::F>>, Vec<SymbolicExpression<randprotocol_rvm::isa::F>>)
where
    A: p3_air::BaseAir<randprotocol_rvm::isa::F>
        + p3_air::Air<p3_lookup::InteractionSymbolicBuilder<randprotocol_rvm::isa::F, randprotocol_rvm::isa::EF>>,
{
    let mut sb = p3_lookup::InteractionSymbolicBuilder::<randprotocol_rvm::isa::F, randprotocol_rvm::isa::EF>::new(
        AirLayout::from_air::<randprotocol_rvm::isa::F>(air),
    );
    air.eval(&mut sb);
    (sb.global_interactions().to_vec(), sb.base_constraints())
}

/// A base-field symbolic expression at one row pair (`cur`, `next`), on a transition row that is
/// neither the first nor the last — the rows every per-row rule lives on.
#[allow(dead_code)]
pub fn eval_at(e: &SymbolicExpression<randprotocol_rvm::isa::F>, cur: &[randprotocol_rvm::isa::F], next: &[randprotocol_rvm::isa::F]) -> randprotocol_rvm::isa::F {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::F;
    match e {
        SymbolicExpr::Leaf(l) => match l {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => cur[v.index],
                BaseEntry::Main { offset: 1 } => next[v.index],
                // A row outside every preprocessed region (the reduce chip's per-row rules are checked there).
                BaseEntry::Preprocessed { .. } => F::ZERO,
                other => panic!("a main-trace-only AIR read {other:?}"),
            },
            BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow => F::ZERO,
            BaseLeaf::IsTransition => F::ONE,
            BaseLeaf::Constant(c) => *c,
        },
        SymbolicExpr::Add { x, y, .. } => eval_at(x, cur, next) + eval_at(y, cur, next),
        SymbolicExpr::Sub { x, y, .. } => eval_at(x, cur, next) - eval_at(y, cur, next),
        SymbolicExpr::Neg { x, .. } => -eval_at(x, cur, next),
        SymbolicExpr::Mul { x, y, .. } => eval_at(x, cur, next) * eval_at(y, cur, next),
    }
}

/// The single current-row main column a message field is, or `None` for anything composite.
#[allow(dead_code)]
pub fn as_column(e: &SymbolicExpression<randprotocol_rvm::isa::F>) -> Option<usize> {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) if v.entry == (BaseEntry::Main { offset: 0 }) => Some(v.index),
        _ => None,
    }
}

/// Does `e` depend on column `col` of the current row (`next_row = false`) or of the next row
/// (`true`) at this row pair? Two random perturbations, so a chance cancellation cannot hide a
/// dependency.
#[allow(dead_code)]
pub fn depends(
    e: &SymbolicExpression<randprotocol_rvm::isa::F>,
    cur: &[randprotocol_rvm::isa::F],
    next: &[randprotocol_rvm::isa::F],
    col: usize,
    next_row: bool,
    rng: &mut impl rand::Rng,
) -> bool {
    use p3_field::PrimeCharacteristicRing;
    let base = eval_at(e, cur, next);
    (0..2).any(|_| {
        let delta = random_felt(rng) + randprotocol_rvm::isa::F::ONE;
        if next_row {
            let mut moved = next.to_vec();
            moved[col] += delta;
            eval_at(e, cur, &moved) != base
        } else {
            let mut moved = cur.to_vec();
            moved[col] += delta;
            eval_at(e, &moved, next) != base
        }
    })
}

/// [`eval_at`] on a boundary row: the table's first row (`is_first`) or its last (`is_last`,
/// where the transition selector is zero and `next` is the wrap-around row).
#[allow(dead_code)]
pub fn eval_at_boundary(
    e: &SymbolicExpression<randprotocol_rvm::isa::F>,
    cur: &[randprotocol_rvm::isa::F],
    next: &[randprotocol_rvm::isa::F],
    is_first: bool,
    is_last: bool,
) -> randprotocol_rvm::isa::F {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::F;
    let flag = |b: bool| if b { F::ONE } else { F::ZERO };
    match e {
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => flag(is_first),
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => flag(is_last),
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => flag(!is_last),
        SymbolicExpr::Leaf(_) => eval_at(e, cur, next),
        SymbolicExpr::Add { x, y, .. } => eval_at_boundary(x, cur, next, is_first, is_last) + eval_at_boundary(y, cur, next, is_first, is_last),
        SymbolicExpr::Sub { x, y, .. } => eval_at_boundary(x, cur, next, is_first, is_last) - eval_at_boundary(y, cur, next, is_first, is_last),
        SymbolicExpr::Neg { x, .. } => -eval_at_boundary(x, cur, next, is_first, is_last),
        SymbolicExpr::Mul { x, y, .. } => eval_at_boundary(x, cur, next, is_first, is_last) * eval_at_boundary(y, cur, next, is_first, is_last),
    }
}

/// [`eval_full`] on any row pair of a table, boundaries included: `is_first` for the pair that
/// starts at row 0, `is_last` for the one that starts at the last row (whose `next` is the
/// wrap-around row 0, and where the transition selector is zero).
#[allow(dead_code)]
pub fn eval_row(
    e: &SymbolicExpression<randprotocol_rvm::isa::F>,
    cur: &[randprotocol_rvm::isa::F],
    next: &[randprotocol_rvm::isa::F],
    pre: (&[randprotocol_rvm::isa::F], &[randprotocol_rvm::isa::F]),
    public: &[randprotocol_rvm::isa::F],
    is_first: bool,
    is_last: bool,
) -> randprotocol_rvm::isa::F {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::F;
    let flag = |b: bool| if b { F::ONE } else { F::ZERO };
    let go = |x: &SymbolicExpression<F>| eval_row(x, cur, next, pre, public, is_first, is_last);
    match e {
        SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => flag(is_first),
        SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => flag(is_last),
        SymbolicExpr::Leaf(BaseLeaf::IsTransition) => flag(!is_last),
        SymbolicExpr::Leaf(_) => eval_full(e, cur, next, pre, public),
        SymbolicExpr::Add { x, y, .. } => go(x) + go(y),
        SymbolicExpr::Sub { x, y, .. } => go(x) - go(y),
        SymbolicExpr::Neg { x, .. } => -go(x),
        SymbolicExpr::Mul { x, y, .. } => go(x) * go(y),
    }
}

/// A program that reaches every chip: registers and RAM (`STORE`, `LOAD`), a `POSEIDON2`
/// dispatch, a three-row `REDUCE` run of layout entry 0 (Cut D), an arity-2 `FOLD` (Cut E2), a
/// three-bit `POW` (Cut F), the four `PUBLIC`s, `HALT`.
/// (`tests/tables.rs`' padding-row rule and `tests/binding.rs`' binding rule both run over it.)
#[allow(dead_code)]
pub fn every_chip_program() -> randprotocol_rvm::isa::Program {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::{Instr, Op, Program, ReduceEntry, F};
    let mut v = vec![];
    // `reduce_chain_program(false)`'s thirteen cells. The key's and alpha's zero high lanes (211,
    // 213) are stored straight from `r0`: 32 instructions (a 64-row program table) and a register
    // table whose real rows stay clear of the padding row `tests/tables.rs` checks.
    let st = |v: &mut Vec<Instr>, addr: u64, val: u64| {
        v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(val) });
        v.push(Instr { op: Op::Store, rd: 1, ra: 0, b: F::from_u64(addr) });
    };
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (212, 3)] {
        st(&mut v, addr, val);
    }
    for addr in [211u64, 213] {
        v.push(Instr { op: Op::Store, rd: 0, ra: 0, b: F::from_u64(addr) });
    }
    v.push(Instr { op: Op::Load, rd: 3, ra: 0, b: F::from_u64(121) });
    v.push(Instr { op: Op::Reduce, rd: 0, ra: 0, b: F::ZERO });
    v.push(Instr { op: Op::Faddi, rd: 7, ra: 0, b: F::from_u64(64) });
    v.push(Instr { op: Op::Poseidon2, rd: 0, ra: 7, b: F::ZERO });
    // Cut E2: one arity-2 fold of the row (1, 0) (2, 0) at cells 300–303, u = 3 — the fold kind's
    // result write (cells 308–309) is then covered by the write and padding rules too.
    st(&mut v, 300, 1);
    v.push(Instr { op: Op::Store, rd: 0, ra: 0, b: F::from_u64(301) });
    st(&mut v, 302, 2);
    v.push(Instr { op: Op::Store, rd: 0, ra: 0, b: F::from_u64(303) });
    v.push(Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(3) });
    v.push(Instr { op: Op::Faddi, rd: 3, ra: 0, b: F::ZERO });
    v.push(Instr { op: Op::Faddi, rd: 4, ra: 0, b: F::from_u64(300) });
    v.push(Instr { op: Op::Fold, rd: 2, ra: 4, b: F::from_u64(2) });
    // Cut F: one three-bit POW over the bits (1, 0, 1) at cells 400–402, G = 7, base = 1 — the pow
    // kind's bit reads and output write (cell 464) are covered by the binding and padding rules.
    // Cell 401 is never written (its read is a fresh zero), which keeps the RAM table at 61 real
    // rows of 64, clear of the padding row `tests/tables.rs` checks.
    st(&mut v, 400, 1);
    st(&mut v, 402, 1);
    v.push(Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(7) });
    v.push(Instr { op: Op::Faddi, rd: 3, ra: 0, b: F::ONE });
    v.push(Instr { op: Op::Faddi, rd: 4, ra: 0, b: F::from_u64(400) });
    v.push(Instr { op: Op::Pow, rd: 2, ra: 4, b: F::from_u64(256 * 3) });
    for _ in 0..4 {
        v.push(Instr { op: Op::Public, rd: 0, ra: 0, b: F::ZERO });
    }
    v.push(Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO });
    let reduce_layout = vec![ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false }];
    Program { instrs: v, checkpoints: vec![], reduce_layout }
}

/// Cut D's honest reduce program (`tests/emulator.rs::chain`, shared): one chain over three
/// columns, as one entry or (`split`) as a carrying two-column entry plus a one-column
/// continuation. Publishes 267 = (10−4)·1 + (20−5)·3 + (30−6)·9 four times.
#[allow(dead_code)]
pub fn reduce_chain_program(split: bool) -> randprotocol_rvm::isa::Program {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::{Instr, Op, Program, ReduceEntry, F};
    let i = |op: Op, rd: u8, ra: u8, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    let mut v = vec![];
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (211, 0), (212, 3), (213, 0)] {
        v.push(i(Op::Faddi, 1, 0, val));
        v.push(i(Op::Store, 1, 0, addr));
    }
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let layout = if split {
        vec![ReduceEntry { len: 2, carry: true, ..e }, ReduceEntry { vals: 104, row: 122, len: 1, chain_start: false, ..e }]
    } else {
        vec![e]
    };
    for id in 0..layout.len() as u64 {
        v.push(i(Op::Reduce, 0, 0, id));
    }
    v.push(i(Op::Load, 3, 0, 214));
    for _ in 0..4 {
        v.push(i(Op::Public, 0, 3, 0));
    }
    v.push(i(Op::Halt, 0, 0, 0));
    Program { instrs: v, checkpoints: vec![], reduce_layout: layout }
}

/// Cut C's smallest honest `COMPRESS` program (`tests/emulator.rs`'s, reproduced for the chip and
/// soundness tests): the digest `1..=4` at cell 64, the sibling `11..=14` at cell 80, one
/// `COMPRESS` with the given bit, the four parent lanes published.
#[allow(dead_code)]
pub fn compress_program(bit: u64) -> randprotocol_rvm::isa::Program {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::{Instr, Op, Program, F};
    let i = |op: Op, rd: u8, ra: u8, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    let mut instrs = vec![i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 2, 0, 80), i(Op::Faddi, 3, 0, bit)];
    for k in 0..4 {
        instrs.push(i(Op::Faddi, 4, 0, 1 + k));
        instrs.push(i(Op::Store, 4, 1, k));
    }
    for k in 0..4 {
        instrs.push(i(Op::Faddi, 4, 0, 11 + k));
        instrs.push(i(Op::Store, 4, 2, k));
    }
    instrs.push(i(Op::Compress, 3, 1, 2));
    for k in 0..4 {
        instrs.push(i(Op::Load, 5, 1, k));
        instrs.push(i(Op::Public, 0, 5, 0));
    }
    instrs.push(i(Op::Halt, 0, 0, 0));
    Program { instrs, checkpoints: vec![], reduce_layout: vec![] }
}

/// The main columns a table range-checks: the single-column fields of its `RANGE8` lookups.
#[allow(dead_code)]
pub fn range_checked_columns(interactions: &[p3_lookup::SymbolicInteraction<randprotocol_rvm::isa::F>]) -> Vec<usize> {
    let mut cols: Vec<usize> = interactions
        .iter()
        .filter(|i| i.bus_name == randprotocol_rvm::tables::bus::RANGE8.name() && i.fields.len() == 1)
        .filter_map(|i| as_column(&i.fields[0]))
        .collect();
    cols.sort();
    cols.dedup();
    cols
}

/// Can this row pair be completed into one every constraint accepts by choosing the
/// range-checked columns (`limbs`) as *bytes*? Every other column is taken as given. The limb
/// constraints are the decomposition kind — `gate·(subject − Σ 256^j·L_j)`, linear in one group of
/// limbs — so each is solved directly: its three coefficients must be `a, 256·a, 65536·a`, and the
/// subject it demands must be below `2^24`. `Err` names the first constraint no choice of bytes
/// satisfies (or one that fails whatever the limbs are). The address range checks' soundness is
/// exactly this: a wrapped address has no three-byte decomposition, whatever the prover writes.
#[allow(dead_code)]
pub fn admits_byte_limbs(
    constraints: &[SymbolicExpression<randprotocol_rvm::isa::F>],
    cur: &[randprotocol_rvm::isa::F],
    next: &[randprotocol_rvm::isa::F],
    limbs: &[usize],
) -> Result<Vec<randprotocol_rvm::isa::F>, String> {
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
    use randprotocol_rvm::isa::F;
    let mut row = cur.to_vec();
    for &l in limbs {
        row[l] = F::ZERO;
    }
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x11b5);
    for (k, c) in constraints.iter().enumerate() {
        let group: Vec<usize> = limbs.iter().copied().filter(|&l| depends(c, &row, next, l, false, &mut rng)).collect();
        let c0 = eval_at(c, &row, next);
        if group.is_empty() {
            if c0 != F::ZERO {
                return Err(format!("constraint {k} fails whatever the limbs are"));
            }
            continue;
        }
        let coeff = |l: usize| {
            let mut r = row.clone();
            r[l] = F::ONE;
            eval_at(c, &r, next) - c0
        };
        let mut terms: Vec<(usize, F)> = group.iter().map(|&l| (l, coeff(l))).collect();
        // Order the group by its weights: the lowest limb's coefficient `a` divides the others.
        let a = terms.iter().map(|t| t.1).find(|&x| terms.iter().all(|t| (t.1 * x.inverse()).as_canonical_u64() < 1 << 24)).expect("a limb group's weights");
        terms.sort_by_key(|t| (t.1 * a.inverse()).as_canonical_u64());
        for (j, t) in terms.iter().enumerate() {
            assert_eq!(t.1, a * F::from_u64(1 << (8 * j)), "constraint {k}: a three-byte decomposition, weights 1, 256, 65536");
        }
        let want = (F::ZERO - c0) * a.inverse();
        let w = want.as_canonical_u64();
        if w >= 1 << (8 * terms.len()) {
            return Err(format!("constraint {k} needs {w:#x} in {} bytes", terms.len()));
        }
        for (j, t) in terms.iter().enumerate() {
            row[t.0] = F::from_u64((w >> (8 * j)) & 0xff);
        }
    }
    match constraints.iter().position(|c| eval_at(c, &row, next) != F::ZERO) {
        Some(k) => Err(format!("constraint {k} fails after the limbs are solved")),
        None => Ok(row),
    }
}

/// [`eval_at`] for an AIR that also reads preprocessed columns and public values (the program and
/// range tables, the public table): `pre` is the preprocessed row pair, `public` the instance's
/// public values. A transition row, like `eval_at`'s.
#[allow(dead_code)]
pub fn eval_full(
    e: &SymbolicExpression<randprotocol_rvm::isa::F>,
    cur: &[randprotocol_rvm::isa::F],
    next: &[randprotocol_rvm::isa::F],
    pre: (&[randprotocol_rvm::isa::F], &[randprotocol_rvm::isa::F]),
    public: &[randprotocol_rvm::isa::F],
) -> randprotocol_rvm::isa::F {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::F;
    match e {
        SymbolicExpr::Leaf(l) => match l {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => cur[v.index],
                BaseEntry::Main { offset: 1 } => next[v.index],
                BaseEntry::Preprocessed { offset: 0 } => pre.0[v.index],
                BaseEntry::Preprocessed { offset: 1 } => pre.1[v.index],
                BaseEntry::Public => public[v.index],
                other => panic!("an AIR here read {other:?}"),
            },
            BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow => F::ZERO,
            BaseLeaf::IsTransition => F::ONE,
            BaseLeaf::Constant(c) => *c,
        },
        SymbolicExpr::Add { x, y, .. } => eval_full(x, cur, next, pre, public) + eval_full(y, cur, next, pre, public),
        SymbolicExpr::Sub { x, y, .. } => eval_full(x, cur, next, pre, public) - eval_full(y, cur, next, pre, public),
        SymbolicExpr::Neg { x, .. } => -eval_full(x, cur, next, pre, public),
        SymbolicExpr::Mul { x, y, .. } => eval_full(x, cur, next, pre, public) * eval_full(y, cur, next, pre, public),
    }
}

/// Phase 3 Task 0: `tests/pins.json`'s `phase3_attribution` block — the REG access count and
/// the executed rows per call site, measured by `tests/profile.rs` on the production fixture.
#[allow(dead_code)]
pub struct Phase3Attribution {
    pub reg_accesses: usize,
    pub rows: Vec<(String, usize)>,
}

#[allow(dead_code)]
pub fn phase3_attribution() -> Phase3Attribution {
    let s = std::fs::read_to_string(pins_path()).expect("tests/pins.json");
    let at = s.find("\"phase3_attribution\"").expect("Task 0 wrote the phase3_attribution block");
    let block = &s[at..at + s[at..].find('}').expect("the block closes")];
    let mut out = Phase3Attribution { reg_accesses: 0, rows: Vec::new() };
    for line in block.lines().skip(1) {
        let Some((k, v)) = line.trim().trim_end_matches(',').split_once(": ") else { continue };
        let (k, v) = (k.trim_matches('"').to_string(), v.parse::<usize>().expect("a numeric field"));
        if k == "reg_accesses" {
            out.reg_accesses = v
        } else {
            out.rows.push((k, v))
        }
    }
    out
}

/// Cut E2's honest fold program: each run's row stored at its own base, `u` in r2/r3, the base in
/// r4, one `FOLD`; the first run's result published twice. Returns the program and every run's
/// expected value (`emulator::fold_dft_horner`).
#[allow(dead_code)]
pub fn fold_program(runs: &[(usize, Vec<randprotocol_rvm::isa::EF>, randprotocol_rvm::isa::EF)]) -> (randprotocol_rvm::isa::Program, Vec<randprotocol_rvm::isa::EF>) {
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use randprotocol_rvm::isa::{Instr, Op, Program, F};
    let i = |op: Op, rd: u8, ra: u8, b: F| Instr { op, rd, ra, b };
    let (mut v, mut want, mut base, mut first_res) = (vec![], vec![], 300u64, 0u64);
    for (la, ys, u) in runs {
        let a = 1u64 << la;
        for (k, y) in ys.iter().enumerate() {
            for (l, w) in y.as_basis_coefficients_slice().iter().enumerate() {
                v.push(i(Op::Faddi, 1, 0, *w));
                v.push(i(Op::Store, 1, 0, F::from_u64(base + 2 * k as u64 + l as u64)));
            }
        }
        let uc = u.as_basis_coefficients_slice();
        v.extend([i(Op::Faddi, 2, 0, uc[0]), i(Op::Faddi, 3, 0, uc[1]), i(Op::Faddi, 4, 0, F::from_u64(base)), i(Op::Fold, 2, 4, F::from_u64(a))]);
        want.push(randprotocol_rvm::emulator::fold_dft_horner(ys, *u));
        if first_res == 0 {
            first_res = base + 2 * a + 4;
        }
        base += 2 * a + 4 + 2 + 10;
    }
    v.extend([i(Op::Loade, 6, 0, F::from_u64(first_res)), i(Op::Public, 0, 6, F::ZERO), i(Op::Public, 0, 7, F::ZERO)]);
    v.extend([i(Op::Public, 0, 6, F::ZERO), i(Op::Public, 0, 7, F::ZERO), i(Op::Halt, 0, 0, F::ZERO)]);
    (Program { instrs: v, checkpoints: vec![], reduce_layout: vec![] }, want)
}

/// Cut F's honest pow program (`tests/emulator.rs::pow_prog`, shared): the 64 bits stored at cells
/// 400–463, `(G, base)` in r2/r3, the buffer in r4, one `POW`, its output (cell 464) published four
/// times.
#[allow(dead_code)]
pub fn pow_program(bits: &[u64], off: u64, len: u64, g: randprotocol_rvm::isa::F, base: randprotocol_rvm::isa::F) -> randprotocol_rvm::isa::Program {
    use p3_field::PrimeCharacteristicRing;
    use randprotocol_rvm::isa::{Instr, Op, Program, F};
    let i = |op: Op, rd: u8, ra: u8, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    let mut v = vec![];
    for (k, &bit) in bits.iter().enumerate() {
        v.push(i(Op::Faddi, 1, 0, bit));
        v.push(i(Op::Store, 1, 0, 400 + k as u64));
    }
    v.extend([Instr { op: Op::Faddi, rd: 2, ra: 0, b: g }, Instr { op: Op::Faddi, rd: 3, ra: 0, b: base }, i(Op::Faddi, 4, 0, 400)]);
    v.extend([i(Op::Pow, 2, 4, off + 256 * len), i(Op::Load, 6, 0, 464)]);
    for _ in 0..4 {
        v.push(i(Op::Public, 0, 6, 0));
    }
    v.push(i(Op::Halt, 0, 0, 0));
    Program { instrs: v, checkpoints: vec![], reduce_layout: vec![] }
}
