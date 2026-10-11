//! Host model of the private-multisig auth guest: policy hashes, auth
//! commitment, signing message and the fixed private-witness layout.
use crate::notes::{hash, Word8};

pub const AUTH: u32 = 65;
pub const MS_LEAF: u32 = 66;
pub const MS_NODE: u32 = 67;
pub const MS_POLICY: u32 = 68;
pub const NK_MS: u32 = 69;
pub const N_MAX: usize = 16;
pub const DEPTH: usize = 4;
pub const M_MAX: usize = 3;
pub const PK_WORDS: usize = 328;
pub const SIG_WORDS: usize = 605;
pub const SLOT_WORDS: usize = 967;
pub const MSAUTH_WORDS: usize = 17 + M_MAX * SLOT_WORDS;
const _: () = assert!(SLOT_WORDS == 2 + PK_WORDS + SIG_WORDS + 8 * DEPTH);
pub const MSG_PREFIX: &[u8; 13] = b"rand-msauth-1";

fn pack(bytes: &[u8]) -> Vec<u32> {
    debug_assert!(bytes.len() % 4 == 0);
    bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

fn cat(a: &Word8, b: &Word8) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[..8].copy_from_slice(a);
    m[8..].copy_from_slice(b);
    m
}

pub fn leaf(pk: &[u8; 1312]) -> Word8 {
    hash(MS_LEAF, &pack(pk))
}

/// Root and, per signer, the sibling path from leaf to root. Pads to 16 leaves with zero words.
pub fn signer_tree(pks: &[[u8; 1312]]) -> (Word8, Vec<[Word8; DEPTH]>) {
    assert!(!pks.is_empty() && pks.len() <= N_MAX);
    let mut level: Vec<Word8> = pks.iter().map(leaf).collect();
    level.resize(N_MAX, [0; 8]);
    let mut paths = vec![[[0u32; 8]; DEPTH]; pks.len()];
    for lvl in 0..DEPTH {
        for (i, p) in paths.iter_mut().enumerate() {
            let idx = i >> lvl;
            p[lvl] = level[idx ^ 1];
        }
        level = level.chunks(2).map(|c| hash(MS_NODE, &cat(&c[0], &c[1]))).collect();
    }
    (level[0], paths)
}

pub fn policy(threshold: u32, root: &Word8) -> Word8 {
    let mut m = [0u32; 9];
    m[0] = threshold;
    m[1..].copy_from_slice(root);
    hash(MS_POLICY, &m)
}

pub fn nk(msk: &Word8, policy: &Word8) -> Word8 {
    hash(NK_MS, &cat(msk, policy))
}

pub fn auth_commit(nk: &Word8, salt: &Word8) -> Word8 {
    hash(AUTH, &cat(nk, salt))
}

pub fn signing_message(binding: &[u32; 8]) -> [u8; 45] {
    let mut m = [0u8; 45];
    m[..13].copy_from_slice(MSG_PREFIX);
    for (i, w) in binding.iter().enumerate() {
        m[13 + 4 * i..17 + 4 * i].copy_from_slice(&w.to_le_bytes());
    }
    m
}

#[derive(Clone)]
pub struct Slot {
    pub index: u32,
    pub pk: [u8; 1312],
    pub sig: [u8; 2420],
    pub path: [Word8; DEPTH],
}

/// Fixed-length private witness: `[msk(8), salt(8), threshold, M_MAX slots]`.
/// Slot: `[active=1, index, pk(328), sig(605), path(32)]`; inactive slots are zero.
pub fn msauth_inputs(msk: &Word8, salt: &Word8, threshold: u32, active: &[Slot]) -> Vec<u32> {
    assert!(active.len() <= M_MAX);
    let mut v = Vec::with_capacity(MSAUTH_WORDS);
    v.extend_from_slice(msk);
    v.extend_from_slice(salt);
    v.push(threshold);
    for s in active {
        assert!(s.index < N_MAX as u32);
        v.push(1);
        v.push(s.index);
        v.extend(pack(&s.pk));
        v.extend(pack(&s.sig));
        for n in &s.path {
            v.extend_from_slice(n);
        }
    }
    v.resize(MSAUTH_WORDS, 0);
    debug_assert_eq!(v.len(), MSAUTH_WORDS);
    v
}

/// The tier every msauth proof declares, whatever the number of active signers (R-hide). Tier 18
/// only: `Tier::for_workload` at `M_MAX` active signers, cycles and Poseidon2 permutations both
/// counted (`tests/msauth.rs::m_max_fits_tier_18_counting_cycles_and_poseidon2_permutations`).
pub const MSAUTH_TIER: crate::machine::Tier = crate::machine::Tier(18);

/// The Poseidon2 permutations a run asks of the proof, counted as `machine::build_traces_inner`
/// counts them: the program-digest, input-digest and public-digest rows, plus one per `Absorb` row.
pub fn poseidon2_permutations(program: &crate::isa::Program, n_inputs: usize, exec: &crate::emulator::Execution) -> usize {
    let absorb = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
    program.digest_rows() + crate::hash::input_digest_row_count(n_inputs) + crate::hash::public_digest_row_count(8) + absorb
}

/// The msauth prover's options: every variable table height floored at its `M_MAX` value, so the
/// proof header is identical for every `M <= M_MAX` (R-hide), and `gas_limit: None` so the public
/// gas word is the header ceiling and does not leak `M` (R-gas). The literals are what
/// `build_traces_salted_with(.., MSAUTH_TIER, ProveOptions::default())` declares for a full
/// `M_MAX` run; `tests/msauth.rs::pinned_heights_are_what_a_full_run_declares` recomputes them.
pub fn pinned_options() -> crate::machine::ProveOptions {
    crate::machine::ProveOptions {
        min_modq_log_height: PINNED_MODQ_LOG_HEIGHT,
        min_keccak_log_height: PINNED_KECCAK_LOG_HEIGHT,
        min_mem_log_height: PINNED_MEM_LOG_HEIGHT,
        gas_limit: None,
        ..Default::default()
    }
}
/// Measured: a full M_MAX = 3 run at tier 18 with default options (Task 8): 297 keccak perms -> 14, 54 MODQ calls -> 16, memory 20 (the tier's t + 2 floor).
pub const PINNED_MODQ_LOG_HEIGHT: u8 = 16;
/// Keccak table height (297 perms at M_MAX = 3).
pub const PINNED_KECCAK_LOG_HEIGHT: u8 = 14;
/// Memory table height (the tier's own t + 2).
pub const PINNED_MEM_LOG_HEIGHT: u8 = 20;
/// Program table height (the guest's word count, fixed per image), input table height (the fixed
/// `MSAUTH_WORDS` witness) and public table height (8 binding words): not floors, but part of the
/// pinned header all the same.
pub const PINNED_PROGRAM_LOG_HEIGHT: u8 = 12;
pub const PINNED_INPUT_LOG_HEIGHT: u8 = 12;
pub const PINNED_PUBLIC_LOG_HEIGHT: u8 = 7;

/// Builds the traces under `opts` and refuses unless the declared header is exactly the pinned
/// one: tier plus all seven log heights. A hard error names the field.
pub fn check_pinned_shape_with(program: &crate::isa::Program, input: &[u32], binding: &[u32; 8], opts: crate::machine::ProveOptions) -> Result<(), String> {
    let exec = crate::emulator::execute(program, input, binding, MSAUTH_TIER.max_cycles()).map_err(|e| format!("execute: {e:?}"))?;
    let t = crate::machine::build_traces_salted_with(program, input, binding, [0; 4], &exec, MSAUTH_TIER, opts).map_err(|e| format!("build_traces: {e:?}"))?;
    let fields: [(&str, u8, u8); 7] = [
        ("program_log_height", t.program_log_height, PINNED_PROGRAM_LOG_HEIGHT),
        ("input_log_height", t.input_log_height, PINNED_INPUT_LOG_HEIGHT),
        ("keccak_log_height", t.keccak_log_height, PINNED_KECCAK_LOG_HEIGHT),
        ("sha256_log_height", t.sha256_log_height, 0),
        ("modq_log_height", t.modq_log_height, PINNED_MODQ_LOG_HEIGHT),
        ("public_log_height", t.public_log_height, PINNED_PUBLIC_LOG_HEIGHT),
        ("mem_log_height", t.mem_log_height, PINNED_MEM_LOG_HEIGHT),
    ];
    for (name, got, want) in fields {
        if got != want { return Err(format!("msauth shape mismatch: {name} = {got}, pinned {want}")); }
    }
    Ok(())
}

/// The msauth prover: refuses unless the shape is the pinned one, then proves at `MSAUTH_TIER`
/// with `pinned_options()`, then checks the returned `Proof`'s own header against the pins (a hard
/// error naming the field), so the artifact is verified, not only the pre-flight.
///
/// The tier-18 traces are built twice (once by the pre-flight, once inside `prove_with_options`):
/// `Machine` exposes no entry that proves from already-built traces under `ProveOptions`, and the
/// pre-flight is what keeps a wrong-shaped witness from reaching the (minutes-long) prover.
pub fn prove_msauth(machine: &crate::machine::Machine, program: &crate::isa::Program, input: &[u32], binding: &[u32; 8]) -> Result<crate::machine::Proof, String> {
    check_pinned_shape_with(program, input, binding, pinned_options())?;
    let proof = machine.prove_with_options(program, input, binding, Some(MSAUTH_TIER), pinned_options()).map(|(p, _)| p).map_err(|e| format!("prove: {e:?}"))?;
    check_proof_header(&proof)?;
    Ok(proof)
}

/// A proof's declared tier and seven log heights against the pins; the error names the field.
pub fn check_proof_header(proof: &crate::machine::Proof) -> Result<(), String> {
    if proof.tier != MSAUTH_TIER { return Err(format!("msauth proof header mismatch: tier = {:?}, pinned {:?}", proof.tier, MSAUTH_TIER)); }
    let fields: [(&str, u8, u8); 7] = [
        ("program_log_height", proof.program_log_height, PINNED_PROGRAM_LOG_HEIGHT),
        ("input_log_height", proof.input_log_height, PINNED_INPUT_LOG_HEIGHT),
        ("keccak_log_height", proof.keccak_log_height, PINNED_KECCAK_LOG_HEIGHT),
        ("sha256_log_height", proof.sha256_log_height, 0),
        ("modq_log_height", proof.modq_log_height, PINNED_MODQ_LOG_HEIGHT),
        ("public_log_height", proof.public_log_height, PINNED_PUBLIC_LOG_HEIGHT),
        ("mem_log_height", proof.mem_log_height, PINNED_MEM_LOG_HEIGHT),
    ];
    for (name, got, want) in fields {
        if got != want { return Err(format!("msauth proof header mismatch: {name} = {got}, pinned {want}")); }
    }
    Ok(())
}
