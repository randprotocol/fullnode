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
    let tape = WitnessTape::build_n(profile, &shape, &key, &proofs).unwrap();
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
    let mut json = format!(
        "{{\n  \"cpu_rows\": {},\n  \"permutations\": {},\n  \"mem_accesses\": {},\n  \
         \"witness_words\": {},\n  \"program_instrs\": {},\n",
        legacy.cpu_rows, legacy.permutations, legacy.mem_accesses, legacy.witness_words,
        legacy.program_instrs
    );
    for (i, r) in rs.iter().enumerate() {
        let n = i + 1;
        let comma = if n == 3 { "" } else { "," };
        json += &format!(
            "  \"aggregate_test_n{n}_cpu_rows\": {},\n  \"aggregate_test_n{n}_permutations\": {},\n  \
             \"aggregate_test_n{n}_mem_accesses\": {},\n  \"aggregate_test_n{n}_witness_words\": {}{comma}\n",
            r.cpu_rows, r.permutations, r.mem_accesses, r.witness_words
        );
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
    (0..n)
        .map(|k| {
            if let Some(p) = load_cached(&m, profile, k) {
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
        })
        .collect()
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
