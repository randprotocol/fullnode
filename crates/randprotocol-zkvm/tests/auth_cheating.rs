//! The auth guest's cheating suite (delegated proving, Phase 2, spec
//! `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.4): `guests::auth()` alone.
//! It reads `sk` and a salt and publishes `c = H(AUTH, H(NK, sk), salt)`; it checks nothing, so
//! "cheating" it means making it publish a `c` the owner's `nk` and salt commit to without the
//! owner's `sk`, or editing what a real proof publishes. `tests/hidden_cheating.rs` has the cases
//! that pair it with bundle guest v3.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes `tests/auth*.rs`).
//!
//! Fast set: `cargo test --release -p randprotocol-zkvm --test auth_cheating -- --skip real_proof_`.
//! The one real proof (~7 s, Production FRI) takes the workspace proving slot. The fuzz's seed and
//! run count: `AUTH_FUZZ_SEED` / `AUTH_FUZZ_ITERS`.

use std::sync::Mutex;

use randprotocol_zkvm::auth::{auth_commit, auth_input, auth_inputs};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{Backend, FriProfile, Machine, Proof};
use randprotocol_zkvm::notes::{self, domain, SpendKey, Word8};
use randprotocol_zkvm::tables::cpu::pv;

const BINDING_A: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
const MAX_CYCLES: usize = 1 << 20;
const SALT: Word8 = [0x5a17_0001, 0x0bad_cafe, 3, 4, 5, 6, 7, 0x8000_0001];

/// One real proof at a time in this binary; taken before the file lock below.
static PROVING: Mutex<()> = Mutex::new(());

/// The workspace's proving slot — the lock file every proving test binary takes
/// (`tests/hidden_cheating.rs` has the full note).
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

/// SplitMix64, as `tests/hidden_cheating.rs`'s: a failing fuzz run replays from its seed.
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
    fn below(&mut self, n: u64) -> u64 { self.next_u64() % n }
    fn word8(&mut self) -> Word8 { std::array::from_fn(|_| self.next_u32()) }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().map(|s| {
        let s = s.trim();
        s.strip_prefix("0x").map_or_else(|| s.parse().unwrap(), |h| u64::from_str_radix(h, 16).unwrap())
    }).unwrap_or(default)
}

/// The guest's 16 private words, run; returns its `c` (outputs 0..8) after checking it writes
/// nothing else.
fn emulate(inputs: &[u32]) -> Word8 {
    assert_eq!(inputs.len(), auth_input::COUNT);
    let exec = execute(&guests::auth(), inputs, &BINDING_A, MAX_CYCLES).expect("the auth guest never traps");
    assert!(exec.halted);
    assert!(exec.outputs[8..].iter().all(|w| *w == 0), "only outputs 0..8 are written");
    exec.outputs[..8].try_into().unwrap()
}

/// What the guest must publish for any 16 words: `H(AUTH, H(NK, words[0..8]), words[8..16])` —
/// the host twin, applied to whatever sits in the sk and salt slots.
fn expected(inputs: &[u32]) -> Word8 {
    let sk = SpendKey(inputs[auth_input::SK..auth_input::SK + 8].try_into().unwrap());
    auth_commit(&sk.viewing_key().nk, &inputs[auth_input::SALT..auth_input::SALT + 8].try_into().unwrap())
}

/// A witness with the wrong `sk` publishes another `c`: the cheater's own key gives its own `nk`'s
/// commitment, and a prover that holds only the owner's `nk` — every delegated prover does — and
/// writes it where `sk` goes gets `H(AUTH, H(NK, nk₁), salt)`, not the owner's `c`. The guest
/// derives `nk` from what it is handed, so knowing `nk` is not enough.
#[test]
fn a_witness_with_a_wrong_sk_publishes_another_c() {
    let owner = SpendKey(Rng(1).word8());
    let nk1 = owner.viewing_key().nk;
    let c1 = auth_commit(&nk1, &SALT);
    assert_eq!(emulate(&auth_inputs(&owner, &SALT)), c1, "the control");
    let cheater = SpendKey(Rng(2).word8());
    let c2 = emulate(&auth_inputs(&cheater, &SALT));
    assert_eq!(c2, auth_commit(&cheater.viewing_key().nk, &SALT));
    assert_ne!(c2, c1, "another spend key");
    let c_nk = emulate(&auth_inputs(&SpendKey(nk1), &SALT));
    assert_eq!(c_nk, auth_commit(&notes::hash(domain::NK, &nk1), &SALT));
    assert_ne!(c_nk, c1, "the owner's nk in the sk slot");
    // And the owner's pk (public) in the sk slot likewise.
    let pk1 = owner.viewing_key().pk();
    assert_ne!(emulate(&auth_inputs(&SpendKey(pk1), &SALT)), c1, "the owner's pk in the sk slot");
}

/// Every mutation of the 16 words changes `c`, and to exactly the host twin of the mutated words.
/// Exhaustively every single-bit flip of every word of one witness (512 runs), then
/// `AUTH_FUZZ_ITERS` random single- and two-word mutations (default 5 000) of random witnesses.
#[test]
fn mutation_fuzz_every_mutation_of_the_16_words_changes_c() {
    let base = auth_inputs(&SpendKey(Rng(3).word8()), &SALT);
    let c = emulate(&base);
    for i in 0..auth_input::COUNT {
        for bit in 0..32 {
            let mut v = base.clone();
            v[i] ^= 1 << bit;
            let out = emulate(&v);
            assert_ne!(out, c, "word {i} bit {bit}");
            assert_eq!(out, expected(&v), "word {i} bit {bit}");
        }
    }
    let seed = env_u64("AUTH_FUZZ_SEED", 0x4175_7468_0000_0001);
    let iters = env_u64("AUTH_FUZZ_ITERS", 5_000) as usize;
    let mut rng = Rng(seed);
    let started = std::time::Instant::now();
    for n in 0..iters {
        let honest = auth_inputs(&SpendKey(rng.word8()), &rng.word8());
        let c = emulate(&honest);
        assert_eq!(c, expected(&honest));
        let mut v = honest.clone();
        let words = if rng.below(4) == 0 { 2 } else { 1 };
        let mut what = Vec::new();
        for _ in 0..words {
            let i = rng.below(auth_input::COUNT as u64) as usize;
            let old = v[i];
            v[i] = match rng.below(6) {
                0 => old ^ (1 << rng.below(32)),
                1 => old.wrapping_add(1),
                2 => old.wrapping_sub(1),
                3 => rng.next_u32(),
                4 => 0,
                _ => u32::MAX,
            };
            what.push(format!("word {i}: {old:#x} -> {:#x}", v[i]));
        }
        if v == honest {
            continue; // two mutations that cancelled, or a no-op: not a mutation
        }
        let out = emulate(&v);
        assert_ne!(out, c, "seed {seed:#x} (AUTH_FUZZ_SEED), run {n}: {what:?} left c unchanged");
        assert_eq!(out, expected(&v), "seed {seed:#x}, run {n}: {what:?}");
    }
    println!("auth fuzz, seed {seed:#x}: 512 bit flips + {iters} runs in {:.1?}", started.elapsed());
}

/// A real auth proof whose published `c` is edited after proving: each of the eight output words
/// moved by one, and the whole of `c` replaced by another key's — every edit fails
/// `verify_public`, as does an edited `H_PUB` word; the untouched proof verifies.
#[test]
fn real_proof_a_tampered_output_word_fails_verify() {
    let _one = PROVING.lock().unwrap_or_else(|e| e.into_inner());
    let _slot = proving_slot();
    let owner = SpendKey(Rng(4).word8());
    let program = guests::auth();
    let hc = program.digest();
    let m = Machine::new(FriProfile::Production);
    let started = std::time::Instant::now();
    let (proof, _) = m.prove_with(Backend::Cpu, &program, &auth_inputs(&owner, &SALT), &BINDING_A, None).unwrap();
    println!("auth proved in {:.1?}, {} bytes (Production FRI, CPU)", started.elapsed(), proof.size());
    m.verify_public(&hc, &BINDING_A, &proof).expect("the control");
    let c1 = auth_commit(&owner.viewing_key().nk, &SALT);
    // `Proof` is not `Clone`: each edit starts from a fresh decode of the proof's bytes.
    let bytes = proof.to_bytes();
    let copy = || -> Proof { postcard::from_bytes(&bytes).unwrap() };
    for k in 0..8 {
        assert_eq!(proof.public_values[pv::OUT0 + k], c1[k] as u64);
        let mut edited = copy();
        edited.public_values[pv::OUT0 + k] = (c1[k].wrapping_add(1)) as u64;
        assert!(m.verify_public(&hc, &BINDING_A, &edited).is_err(), "output word {k} edited");
    }
    let c2 = auth_commit(&SpendKey(Rng(5).word8()).viewing_key().nk, &SALT);
    let mut edited = copy();
    for k in 0..8 {
        edited.public_values[pv::OUT0 + k] = c2[k] as u64;
    }
    assert!(m.verify_public(&hc, &BINDING_A, &edited).is_err(), "c replaced by another key's");
    let mut edited = copy();
    edited.public_values[pv::PUB0] ^= 1;
    assert!(m.verify_public(&hc, &BINDING_A, &edited).is_err(), "an H_PUB word edited");
}
