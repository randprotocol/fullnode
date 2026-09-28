//! Delegated proving, Phase 2 — task P2-0, the spike (spec
//! `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.2): what the **auth guest**
//! (`guests::auth`, `auth::auth_commit`) costs — cycles, permutations, tier — and one real proof's
//! size and time at the Test and the Production FRI profile. Task 2 extends this file with the v3
//! bundle guest's headroom at tier 14.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes `tests/auth*.rs`).

use std::sync::Mutex;

use randprotocol_zkvm::auth::{auth_commit, auth_input, auth_inputs, AUTH_DOMAIN};
use randprotocol_zkvm::emulator::{execute, Execution, HashRow};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::hidden::HIDDEN_BUNDLE_DOMAIN;
use randprotocol_zkvm::machine::{Backend, FriProfile, Machine, Tier};
use randprotocol_zkvm::notes::{self, SpendKey, Word8};

/// Two transactions' bindings (`Transaction::binding`), as in `tests/hidden_bundle.rs`.
const BINDING_A: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
const BINDING_B: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_fffe];
const MAX_CYCLES: usize = 1 << 20;
const SALT: Word8 = [0xa5a5_0001, 2, 3, 4, 5, 6, 7, 0x8000_0008];

/// One real proof at a time in this binary; taken before the file lock below.
static PROVING: Mutex<()> = Mutex::new(());

/// The workspace's proving slot — the same lock file `tests/hidden_cheating.rs`,
/// `crates/randprotocol-node/tests/proving_slot/` and its client twin take (`CARGO_TARGET_TMPDIR`
/// is `<target-dir>/tmp`, one directory for every crate), so a proof here never runs beside
/// another session's bundle proofs. The kernel drops the lock when the process exits.
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

fn emulate(inputs: &[u32]) -> Execution {
    assert_eq!(inputs.len(), auth_input::COUNT);
    execute(&guests::auth(), inputs, &BINDING_A, MAX_CYCLES).unwrap()
}

fn commit_of(exec: &Execution) -> Word8 {
    exec.outputs[0..8].try_into().unwrap()
}

/// The guest publishes `c = H(AUTH, nk ‖ salt)` for `nk` the pool's own `H(NK, sk)`, and its
/// workload — counted exactly as `executor::call_tier` and `tests/hidden_bundle.rs` count it, the
/// program, input and public digest rows included — lands on tier 10, the smallest.
#[test]
fn the_auth_guest_publishes_c_and_lands_at_tier_10() {
    let sk = SpendKey::random();
    let inputs = auth_inputs(&sk, &SALT);
    let exec = emulate(&inputs);
    assert!(exec.halted);
    assert_eq!(commit_of(&exec), auth_commit(&sk.viewing_key().nk, &SALT));
    assert!(exec.outputs[8..].iter().all(|w| *w == 0), "only outputs 0..8 are written");

    let program = guests::auth();
    let fixed = program.digest_rows()
        + randprotocol_zkvm::hash::input_digest_row_count(inputs.len())
        + randprotocol_zkvm::hash::public_digest_row_count(BINDING_A.len());
    let absorb = exec.events.iter().filter(|e| matches!(e.hash_row, Some(HashRow::Absorb { .. }))).count();
    let cycles = exec.cycles() + fixed;
    let perms = fixed + absorb;
    let tier = Tier::for_workload(cycles, perms).unwrap();
    println!(
        "auth guest: program {} words, {} input words, {} executed + {fixed} digest rows = {cycles} cycles \
         (tier-10 cap {}), {perms} permutations ({absorb} absorb; tier-10 cap {}), tier {}",
        program.words.len(),
        inputs.len(),
        exec.cycles(),
        Tier(10).max_cycles(),
        Tier(10).poseidon2_height() / randprotocol_zkvm::tables::poseidon2::BLOCK,
        tier.0
    );
    assert_eq!(tier, Tier(10));
    assert_eq!(randprotocol_zkvm::executor::call_tier(&program, &inputs, BINDING_A.len()), Ok(10));
}

/// `c` depends on both private inputs: another spend key or another salt is another `c` (and the
/// host twin agrees each time).
#[test]
fn a_different_sk_or_salt_changes_c() {
    let sk = SpendKey::random();
    let c = commit_of(&emulate(&auth_inputs(&sk, &SALT)));
    let other_sk = SpendKey::random();
    let c_sk = commit_of(&emulate(&auth_inputs(&other_sk, &SALT)));
    assert_eq!(c_sk, auth_commit(&other_sk.viewing_key().nk, &SALT));
    assert_ne!(c, c_sk, "another spend key");
    let mut salt = SALT;
    salt[3] ^= 1;
    let c_salt = commit_of(&emulate(&auth_inputs(&sk, &salt)));
    assert_eq!(c_salt, auth_commit(&sk.viewing_key().nk, &salt));
    assert_ne!(c, c_salt, "another salt");
}

/// One real auth proof per FRI profile: it verifies against the binding it was proved with and is
/// refused against another binding and against the empty segment. The Production numbers are the
/// ones spec §4.2 needs.
#[test]
fn a_real_auth_proof_verifies_against_its_binding_and_not_another() {
    let program = guests::auth();
    let hc = program.digest();
    let sk = SpendKey::random();
    let inputs = auth_inputs(&sk, &SALT);
    let want = auth_commit(&sk.viewing_key().nk, &SALT);
    for profile in [FriProfile::Test, FriProfile::Production] {
        let _one = PROVING.lock().unwrap_or_else(|e| e.into_inner());
        let _slot = proving_slot();
        let m = Machine::new(profile);
        let started = std::time::Instant::now();
        let (proof, exec) = m.prove_with(Backend::Cpu, &program, &inputs, &BINDING_A, None).unwrap();
        let proved = started.elapsed();
        let bytes = proof.to_bytes();
        let started = std::time::Instant::now();
        m.verify_public(&hc, &BINDING_A, &proof).unwrap();
        let verified = started.elapsed();
        println!(
            "auth proof, {profile:?} FRI, CPU: tier {}, {} bytes, proved in {proved:.2?}, verified in {verified:.2?}",
            proof.tier.0,
            bytes.len()
        );
        assert_eq!(proof.tier, Tier(10));
        assert_eq!(commit_of(&exec), want);
        for i in 0..8 {
            assert_eq!(proof.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0 + i], want[i] as u64, "c is the proof's output");
        }
        assert!(m.verify_public(&hc, &BINDING_B, &proof).is_err(), "another transaction's binding");
        assert!(m.verify_public(&hc, &[], &proof).is_err(), "the empty segment");
        assert!(m.verify_public(&guests::bundle_hidden().digest(), &BINDING_A, &proof).is_err(), "another guest's hc");
    }
}

/// `AUTH_DOMAIN` is node-local: outside upstream's sequential range and `TEST`, not the hidden
/// bundle's 64, and distinct from every tag this crate has (mirrors
/// `tests/hidden_bundle.rs::the_digest_is_domain_separated_and_has_no_asset_field`).
#[test]
fn the_auth_domain_tag_is_node_local() {
    assert_eq!(AUTH_DOMAIN, 65);
    assert!(!(1..=0x3f).contains(&AUTH_DOMAIN) && AUTH_DOMAIN != 0xff && AUTH_DOMAIN != notes::domain::TEST);
    assert_ne!(AUTH_DOMAIN, HIDDEN_BUNDLE_DOMAIN);
    for tag in [
        notes::domain::NK, notes::domain::PK, notes::domain::NF, notes::domain::CM, notes::domain::OVK,
        notes::domain::KEM_SEED, notes::domain::NODE, notes::domain::HC, notes::domain::OUT, notes::domain::IN,
        notes::domain::BUNDLE, notes::domain::STORAGE_LEAF, notes::domain::EVM_OUT, notes::domain::SBPF_OUT,
        notes::domain::PUB, notes::domain::KEM_SEED_VERSION, notes::domain::TEST,
        randprotocol_zkvm::hash::HC_DOMAIN, randprotocol_zkvm::hash::IN_DOMAIN, randprotocol_zkvm::hash::PUB_DOMAIN,
        HIDDEN_BUNDLE_DOMAIN,
    ] {
        assert_ne!(tag, AUTH_DOMAIN, "domain tag {tag} collides");
    }
    // The host commitment is the tagged 17-word hash, not an untagged one.
    let (nk, salt) = ([1u32; 8], [2u32; 8]);
    let mut msg = nk.to_vec();
    msg.extend_from_slice(&salt);
    assert_eq!(auth_commit(&nk, &salt), notes::hash(AUTH_DOMAIN, &msg));
    assert_ne!(auth_commit(&nk, &salt), notes::hash(HIDDEN_BUNDLE_DOMAIN, &msg));
}
