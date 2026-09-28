//! The chain-side verifier: implements randprotocol-core's executor trait with the zkVM.
//!
//! M3.4: the verifier no longer holds the program at all — `Machine::verify` takes `hc`, the
//! in-circuit Poseidon2 digest of the program (`isa::Program::digest`), never `words`. The
//! verifier key it needs is `(tier, program_log_height)`-keyed and program-*content*-independent
//! (`Machine::verifier_key`'s own doc comment), so `Machine` already caches it end to end; there
//! is no second, program-keyed cache to maintain here any more (see `warm`'s doc comment for
//! what "warm" means now). Since CPUV-1 (2026-09-28) the bundle guest's one key sits in a
//! `Machine` of its own (`ZkExecutor::bundle_machine`), so no program shape can evict it.
//!
//! M4.1: the verifier key grew a third key component, `input_log_height` — the input table's
//! declared height, exactly as `program_log_height` already was (`tables::input::input_log_height`'s
//! doc comment mirrors `tables::program::program_log_height`'s rule). `verify_call`'s degree-bits
//! pre-check and `warm` both bound and thread it through the same way they already did for
//! `program_log_height`.
//!
//! M4.2 (constraint set 5): a proof now declares *four* table heights, not two. The keccak
//! table's `keccak_log_height` joins the key as a fourth component — and is **optional**: `0`
//! means the proof declares no keccak table at all, an eight-instance batch. `mem_log_height`
//! is proof-declared too, but is deliberately *not* part of the verifier key (every valid
//! memory height yields the same `CommonData`; see `Machine::verifier_key`) — it only enters
//! the degree-bit vector. `decode_and_check` therefore delegates every range check on the
//! declared shape to `machine::check_declared_heights`, the exact function `Machine::verify`
//! runs, rather than restating its rules here: the chain's bound on a keccak-bearing proof
//! *is* upstream's (`klh ∈ [5, min(tier + 5, 20)]`), and what keeps an absurd declaration cheap
//! is that the degree-bits pre-check below rejects it before any verifier key is built.
//!
//! Constraint set 6: two more declared heights join the key — M4.4's `sha256_log_height`
//! (optional, on the keccak table's exact terms, `0` = no sha256 table) and the public input
//! segment's `public_log_height` (**mandatory**: every proof commits to a public segment, even
//! an empty one, which declares `tables::public::MIN_LOG_HEIGHT`). The public segment also
//! changes *what* verification means: `H_PUB` (`pv::PUB0..7`) is unsalted, so a verifier that
//! holds the words can recompute it — `Machine::verify_public`. `verify_bundle` runs
//! `verify_public(hc, &binding, proof)`, which pins `H_PUB` to `hash::public_digest(&binding)`:
//! since Task 5b (the transaction binding, a hard fork like constraint set 6) every bundle proof is
//! made over, and verified against, the eight words of `Transaction::binding` of the transaction it
//! rides in — so a proof copied onto a transaction with a changed action, changed envelopes or a
//! different companion bundle no longer verifies. The bundle guest never reads the segment
//! (`SYS_READ_PUBLIC`); it does not need to, because the public table's `PUBLIC_DIGEST` bus binds
//! the committed words into `H_PUB` whether or not the guest reads them. Since the
//! call limits (spec §5) a program may be deployed with a public input, whose digest the ledger
//! records once at deploy (`ProgramRecord::public_digest`); `verify_call` runs `verify` and then
//! compares `pv::PUB0..7` with that digest, or with `public_digest(&[])` for a program without
//! one — the same check as `verify_public`, without re-hashing the words on every call. Plain `verify` would leave `pv::PUB0..7`
//! unchecked against anything outside the proof — a guest reading a prover-chosen public
//! segment the chain never saw — and every honest proof by today's guests (none of which calls
//! `SYS_READ_PUBLIC`) has the empty segment anyway, so the stronger check costs nothing.
//!
//! Verifying a proof costs ~16-20 ms once its `(tier, program_log_height, input_log_height,
//! keccak_log_height, sha256_log_height, public_log_height)` verifier key is known; computing
//! that key (the range/nibble/Poseidon2-round-constant preprocessed commitment, FRI-expanded) is
//! the dominant cost of an uncached verify (`docs/03-privacy.md`).

use crate::isa::{Instr, Program};
use crate::machine::{check_declared_heights, Backend, FriProfile, Machine, Proof, Tier, TIERS};
use crate::tables::cpu::pv;
use crate::tables::{input, program, public};
use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::notes::{BundleDigestInput, Word8};
use randprotocol_core::program::{CallOutcome, ProgramRecord};
use randprotocol_core::types::TX_BINDING_WORDS;

/// M4.2: the `keccak_log_height` of a proof that declares no keccak table — the batch shape
/// every guest this chain deploys produces, and the only keccak class `warm`/`warm_bundle`
/// precompute a verifier key for. Named rather than inlined as `0` because `0` is a *value* of
/// that key component, not the absence of one (`Machine::verifier_key`'s doc comment).
const NO_KECCAK: u8 = 0;

/// M4.4 (arrived with constraint set 6): the sha256 table's analogue of `NO_KECCAK` — no guest
/// this chain deploys calls `SYS_SHA256`, and `warm`/`warm_bundle` precompute no sha256 class.
const NO_SHA256: u8 = 0;

/// The one tier a bundle proof may declare (zkvm I1). The hidden-asset guest has a single
/// execution shape up to the dummy skip and the Merkle bit branch, so *every* witness a prover
/// can build — the ten input shapes and the adversarial cycle-worst one — lands here, measured by
/// `tests/hidden_bundle.rs`'s `every_shape_lands_at_tier_14_with_identical_table_heights`. It is
/// a function of cycles and permutations alone (`Tier::for_workload`), so it does not vary with
/// the FRI profile: `warm_bundle` precomputes this tier's key and `decode_and_check` refuses any
/// other, which is what keeps a junk header from making a node build one.
const BUNDLE_TIER: usize = 14;

/// The one tier an auth proof (split authorisation, `guests::auth`) may declare: the guest is
/// straight-line — 250 cycles and 55 permutations for every witness (`tests/auth_spike.rs`,
/// `the_auth_guest_publishes_c_and_lands_at_tier_10`) — so, like [`BUNDLE_TIER`], it is pinned,
/// and a junk header cannot make a node build another key.
pub const AUTH_TIER: usize = 10;

/// The highest tier a *call* proof may declare (deep scan 2026-09-24, zkvm), enforced by
/// `verify_call` before any verifier key is built, so it is a validity rule (admission and block
/// apply both run `verify_call`). It is the highest tier `warm` pre-builds, and that is the
/// point: `Machine::verify` builds the key for whatever tier a header declares, the build grows
/// ~4× per tier step (production profile, `tests/executor.rs`'s
/// `measure_a_call_verifier_key_build_at_the_production_profile`: tier 14 ≈ 3.6 s / 227 MB,
/// tier 16 ≈ 13.7 s / 893 MB, tier 20 ≈ 216 s / 6.5 GB), and the validators are 2–4 GB droplets — so every tier past what is
/// warmed is a header an attacker submits for the price of one fee bundle and a node builds
/// synchronously, and the largest is an out-of-memory kill. `gas::MAX_TIER` (20) stays the
/// prover-side ceiling; a call that needs more than this tier is refused as
/// `ConfidentialError::CallTierTooHigh` with the remedy in the message. Raising it means
/// raising what `warm` covers with it (`TIERS[..N]` below) and re-measuring the worst
/// admissible shape at the new tier on a fleet droplet.
pub const MAX_CALL_TIER: u8 = 14;

/// The highest `keccak_log_height` a call proof may declare — 2^12 rows, 128 permutations
/// (deep scan 2026-09-24, zkvm: the second half of the finding, found by costing the worst
/// header `MAX_CALL_TIER` alone still admits). `check_declared_heights` bounds the keccak table
/// by the tier's honest need, `klh ≤ t + 5`, and the flat `tables::keccak::MAX_LOG_HEIGHT` of
/// 20 was chosen upstream as "unreachable-but-finite" — but the key's cost is the table's 99
/// *preprocessed* columns, FRI-expanded, and at the production profile a tier-14 key with
/// `klh = 19` (the tier's own bound) measures 128 s and 8.7 GB, worse than the tier-20 header
/// the finding started from; with the sha256 table at its 2^20 as well, 209 s and 10 GB
/// (`tests/executor.rs`'s `measure_a_call_verifier_key_build_at_the_production_profile`). The
/// program, input and public heights cost nothing by comparison (2^16/2^16/2^15 is the same
/// 3.9 s / 227 MB as the base), so the two hash tables are the whole of what is capped here.
///
/// 12 is a policy bound, not an honest-shape one: a tier-14 guest could honestly make 16 383
/// keccak calls. What real calls need is far smaller — the translated ERC-20's harness hashes
/// a handful of storage slots and ABI words, the EVM interpreter additionally binds its code
/// (136 bytes a permutation, so 128 covers a 17 KB contract), and the suite's largest is 40
/// permutations (`tests/e2e.rs`). A call past it is refused as `InvalidProof` naming the cap.
///
/// With every pin in place the worst header a call may still declare — tier 14, program and
/// input tables at 2^16, public at 2^15, both hash tables at their caps — builds in 4.7 s at
/// 312 MB peak, and eight such keys retained by `Machine`'s cache together peak at 711 MB
/// (~60 MB retained a key; the same harness, `;`-separated shapes).
pub const MAX_CALL_KECCAK_LOG_HEIGHT: u8 = 12;
/// The sha256 table's twin — 2^13 rows, 128 compressions (8 KB hashed). Its preprocessed trace
/// is ten columns to keccak's 99, so it is the cheaper of the two at equal height (2^16 costs
/// 5.1 s / 366 MB against keccak's 2^15 at 14 s / 702 MB), but 2^20 is still 48.7 s and 3.3 GB.
/// No guest this chain deploys calls `SYS_SHA256`; the sBPF interpreter's PDA derivations are
/// the intended user.
pub const MAX_CALL_SHA256_LOG_HEIGHT: u8 = 13;

/// COV-2 (2026-09-28): the smallest log height a call proof's input, keccak or sha256 table may
/// declare and keep its contents private — 128 rows. The PCS is hiding, but a table of `h` rows is
/// opened at 80 FRI queries plus two out-of-domain points, and once that is more evaluations than
/// the `h` random rows mask, the openings determine the table: at 2^3 rows (every four-word call
/// today) the proof carries its private inputs. The prover is being fixed upstream to floor all
/// three tables here. **Not a validity rule**: `verify_call` does not check it, so a block carrying
/// such a call still applies; it is the node's pool policy (`call_private_table_under_floor`,
/// `admission::call_reveals_private_inputs`), non-permanent. Bundles are exempt — their shape is
/// pinned (`decode_and_check`): a 2048-row input table and no hash tables.
pub const MIN_PRIVATE_TABLE_LOG_HEIGHT: u8 = 7;

/// The first private table a *call* proof declares under [`MIN_PRIVATE_TABLE_LOG_HEIGHT`], as
/// `(table, declared log height)` — `"input"`, then `"keccak"` and `"sha256"` when present (a `0`
/// declares no such table and nothing to leak). `None` for a header at or above the floor, and for
/// bytes that do not decode canonically — those are the ledger's to refuse (`decode_and_check`).
/// Reads the header only; nothing is verified. Next to the call caps `verify_call` enforces, but
/// policy, not one of them (see the constant's doc comment).
pub fn call_private_table_under_floor(proof: &[u8]) -> Option<(&'static str, u8)> {
    let proof = decode_canonical(proof).ok()?;
    let min = MIN_PRIVATE_TABLE_LOG_HEIGHT;
    if proof.input_log_height < min {
        return Some(("input", proof.input_log_height));
    }
    if proof.keccak_log_height != NO_KECCAK && proof.keccak_log_height < min {
        return Some(("keccak", proof.keccak_log_height));
    }
    if proof.sha256_log_height != NO_SHA256 && proof.sha256_log_height < min {
        return Some(("sha256", proof.sha256_log_height));
    }
    None
}

/// The v0.6 canonical-proof rules: the first field of a decoded bundle or call proof that is not
/// the value the honest prover writes, named — `None` for a proof the honest prover could have
/// made. Header and transcript fields only; nothing here verifies anything, and every other
/// check (`decode_and_check`, the verify) still runs.
///
/// Why it exists: a field `Machine::verify` accepts at more than one value, without the statement
/// changing, makes the proof malleable — anyone who relays the transaction can re-encode it, the
/// copy has another transaction id (`Transaction::hash` takes the proof by digest), and if it
/// commits first the sender's wallet reports its own payment as not committed. It also lets a
/// bundle take a shape the aggregate program was not built for, which no aggregate can then cover
/// (VERIFIER-2 / V-VERIFIER-1). The rules, each the honest prover's own:
///
/// - **The memory table's height** (INT-5 / HB-2). The prover declares
///   `max(t + 2, log2_ceil(accesses + 1))` (`build_traces_salted`) and the verifier only ranges it
///   (`t + 2 ≤ mem ≤ MAX_MEM_LOG_HEIGHT`, one-sidedly sound: extra rows are padding). Without a
///   keccak or sha256 table every access is one of a cpu row's four slots and a tier holds
///   `2^t − 1` rows, so `accesses + 1 ≤ 4·2^t − 3 < 2^(t+2)` and the honest height is exactly
///   `t + 2` — 16 for every bundle (tier 14, no hash tables, pinned by `decode_and_check`). A
///   bundle declaring 17 verified (the review demonstrated it); it fingerprints the wallet that
///   made it and cannot be aggregated. A proof with a hash table has a data-dependent honest
///   height, so it is capped instead, at [`hash_bearing_mem_log_height_ceiling`] of its declared
///   shape (issue #56): the verifier's range above that is no honest prover's.
/// - **The FRI folding schedule** (VERIFIER-2 / V-VERIFIER-1): the per-round `log_arity` the
///   verifier accepts at any value in `1..=max_log_arity` that folds onto every input height, so
///   any finer schedule than the prover's greedy one verifies too; pinned to
///   [`honest_fri_arities`], re-derived from the declared shape.
/// - **The random-codeword openings** (V-VERIFIER-1): the hiding PCS's count of random values
///   per opened point, which its verifier nests but does not count — four at every point of a
///   randomised round, none in the preprocessed round.
///
/// - **The commit-phase proof-of-work words** (VERIFIER-1): read and dropped at 0 grinding bits,
///   outside the Fiat-Shamir transcript, so a relayer can rewrite one and the copy verifies with
///   another transaction id — the sender's wallet then reports its own payment as not committed.
///   Pinned to zero, what `grind(0)` writes. (The *query* proof-of-work word is ground at the
///   profile's bits, observed, and has no single honest value; it is left alone.)
///
/// Which proofs this runs on, and when, is the caller's: every node's pool refuses a transaction
/// carrying such a proof (`admission::non_canonical_proofs`), and the ledger refuses it under
/// genesis `hardening_v6` (`ConfidentialExecutor::non_canonical_proof`).
pub fn non_canonical(proof: &Proof) -> Option<String> {
    if proof.keccak_log_height == NO_KECCAK
        && proof.sha256_log_height == NO_SHA256
        && TIERS.contains(&proof.tier.0)
        && proof.mem_log_height != proof.tier.min_mem_log_height()
    {
        return Some(format!(
            "memory height {} where the honest prover declares {} (tier {}, no hash table)",
            proof.mem_log_height,
            proof.tier.min_mem_log_height(),
            proof.tier.0
        ));
    }
    // INT-5 residual (issue #56): with a hash table the honest height depends on how many
    // accesses the run made, which the header does not carry, so it is capped rather than pinned
    // — at the most the declared shape can honestly need.
    if (proof.keccak_log_height != NO_KECCAK || proof.sha256_log_height != NO_SHA256) && TIERS.contains(&proof.tier.0) {
        let ceiling = hash_bearing_mem_log_height_ceiling(proof.tier, proof.keccak_log_height, proof.sha256_log_height);
        if proof.mem_log_height > ceiling {
            return Some(format!(
                "memory height {} above the {ceiling} the honest prover can need (tier {}, keccak {}, sha256 {})",
                proof.mem_log_height, proof.tier.0, proof.keccak_log_height, proof.sha256_log_height
            ));
        }
    }
    // VERIFIER-1: the commit-phase proof-of-work words. The chain's FRI parameters grind 0 bits
    // per commit round (`commit_proof_of_work_bits: 0`, `machine::build_config`), and at 0 bits
    // `GrindingChallenger::check_witness` returns `true` without even observing the word — so it
    // is outside the transcript, anyone relaying the proof can rewrite it, and the copy verifies
    // under another transaction id. The honest prover's `grind(0)` writes zero.
    let fri = &proof.batch.opening_proof.1;
    if let Some(round) = fri.commit_pow_witnesses.iter().position(|w| *w != <crate::machine::Val as p3_field::PrimeCharacteristicRing>::ZERO) {
        return Some(format!("FRI commit-phase proof-of-work word {round} is not zero, the honest prover's (0 grinding bits)"));
    }
    // VERIFIER-2 / V-VERIFIER-1: the folding schedule, re-derived from the declared shape.
    let schedule: Vec<u8> = fri.commit_phase_openings.iter().map(|step| step.log_arity).collect();
    if let Some(honest) = honest_fri_arities(proof) {
        if schedule != honest {
            return Some(format!("FRI folding schedule {schedule:?} where the honest prover folds {honest:?}"));
        }
    }
    // And the hiding PCS's random openings: `NUM_RANDOM_CODEWORDS` values at every opened point
    // of every randomised round, none in the one round that is not randomised (the preprocessed
    // traces, one matrix per chip that has any). The verifier checks only the nesting — round,
    // matrix, point — and appends whatever it finds; the count per point is the prover's to
    // choose as far as that layer is concerned.
    let preprocessed = crate::machine::chips(
        if TIERS.contains(&proof.tier.0) { proof.tier } else { Tier(TIERS[0]) },
        proof.keccak_log_height,
        proof.sha256_log_height,
    )
    .iter()
    .filter(|c| p3_air::BaseAir::<crate::machine::Val>::preprocessed_width(*c) > 0)
    .count();
    let mut unrandomised_rounds = 0;
    for round in &proof.batch.opening_proof.0 {
        let counts: Vec<usize> = round.iter().flatten().map(|point| point.len()).collect();
        if !counts.is_empty() && counts.iter().all(|&c| c == 0) && round.len() == preprocessed {
            unrandomised_rounds += 1;
        } else if let Some(bad) = counts.iter().find(|&&c| c != NUM_RANDOM_CODEWORDS) {
            return Some(format!("random-codeword opening of {bad} values where the honest prover opens {NUM_RANDOM_CODEWORDS}"));
        }
    }
    if unrandomised_rounds > 1 {
        return Some(format!("{unrandomised_rounds} unrandomised opening rounds where the honest prover has one"));
    }
    None
}

/// INT-5 residual (issue #56): the tallest memory table an honest prover declares for a proof of
/// tier `t` with keccak and sha256 tables of the declared log heights (`0` = no such table).
///
/// The prover declares `max(t + 2, log2_ceil(accesses + 1))` (`build_traces_salted`), counting
/// every row `memory_trace` pushes: at most four a cpu event (its four slots), and a tier runs at
/// most `2^t − 1` events; 100 more for each keccak permutation (`2 · keccak::WORDS`, the 50-word
/// state read and written back by the keccak chip) and 32 for each sha256 compression
/// (`sha256::WORDS` reads, `sha256::STATE_WORDS` write-backs). A keccak table of `2^klh` rows
/// holds at most `2^klh / keccak BLOCK` permutations and a sha256 table at most
/// `2^slh / sha256 BLOCK` compressions, so the sum below bounds every honest run of that shape.
///
/// **Why a ceiling, not a pin.** The declared hash heights are powers of two over the call count
/// (and floored at 2^7 for privacy, COV-2), so one shape covers runs whose access counts differ
/// by more than a factor of two, and the honest height is not a function of the header. Pinning
/// it would need the prover to declare this ceiling itself — padding the memory table to the
/// shape's worst case, one extra bit at most (tier 14 with the call keccak cap: 2^16 → 2^17) —
/// which is a prover change in the vendored machine (circuits), for the next constraint set
/// (#52). Until then the ceiling leaves at most `ceiling − (t + 2) + 1` encodings (two or three)
/// in place of the verifier's `MAX_MEM_LOG_HEIGHT − (t + 2) + 1` (up to a dozen), and the height
/// still says, to within that bit, whether the run's accesses spilled past `2^(t+2)`.
pub fn hash_bearing_mem_log_height_ceiling(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u8 {
    let rows = |log_height: u8| if log_height == 0 { 0u128 } else { 1u128 << log_height.min(63) };
    let cpu = 4 * (tier.cpu_height() as u128 - 1);
    let keccak = rows(keccak_log_height) / crate::tables::keccak::BLOCK as u128 * (2 * crate::keccak::WORDS) as u128;
    let sha256 = rows(sha256_log_height) / crate::tables::sha256::BLOCK as u128
        * (crate::sha256::WORDS + crate::sha256::STATE_WORDS) as u128;
    let needed = (cpu + keccak + sha256 + 1).next_power_of_two().trailing_zeros() as u8;
    tier.min_mem_log_height().max(needed).min(crate::machine::MAX_MEM_LOG_HEIGHT)
}

/// The FRI parameters `machine::build_config` proves and verifies with — `log_blowup`,
/// `log_final_poly_len`, `max_log_arity` — and the hiding PCS's random-codeword count
/// (`HidingFriPcs::new(.., 4, ..)`). `machine.rs` keeps them as literals inside a private
/// function; restated here for [`honest_fri_arities`], and pinned by
/// `tests::verifier2_…`, which re-derives honest proofs' schedules from them (a re-vendor that
/// moves one fails there).
const FRI_LOG_BLOWUP: usize = 3;
const FRI_LOG_FINAL_POLY_LEN: usize = 0;
const FRI_MAX_LOG_ARITY: usize = 3;
const NUM_RANDOM_CODEWORDS: usize = 4;

/// VERIFIER-2: the FRI folding schedule the honest prover writes for a proof of this declared
/// shape, or `None` for a shape that has no batch (a tier outside `TIERS`, an instance count the
/// chip set does not have — refused elsewhere).
///
/// The schedule is proof-supplied (`CommitPhaseMultiStep::log_arity`, one per round) and the FRI
/// verifier checks only that each arity is in `1..=max_log_arity`, that they sum to the global
/// height, and that every input height is folded onto exactly — so every *finer* schedule than the
/// prover's is accepted too, a second encoding of the same statement. The prover's own rule
/// (`p3_fri::prover::commit_phase` → `compute_log_arity_for_round`) is greedy: from the tallest
/// input, fold by `min(max_log_arity, to the next input height, to the final height)` each round.
/// The input heights are the batch's committed LDE heights: every instance's extended trace domain
/// (`degree_bits`, which already counts the zk doubling) plus `log_blowup` — main trace, quotient
/// chunks, permutation and randomization polynomials, and a chip's preprocessed columns, all live
/// at their instance's one height. (A first draft also placed the preprocessed traces one height
/// lower, un-extended; every call proof agreed by coincidence — range and nibble's would-be 11 was
/// the input table's own height at tier 10 — and the bundle, where it is not, showed it wrong.)
pub fn honest_fri_arities(proof: &Proof) -> Option<Vec<u8>> {
    if !TIERS.contains(&proof.tier.0) {
        return None;
    }
    let chips = crate::machine::chips(proof.tier, proof.keccak_log_height, proof.sha256_log_height);
    if chips.len() != proof.batch.degree_bits.len() {
        return None;
    }
    let heights: std::collections::BTreeSet<usize> = proof.batch.degree_bits.iter().map(|db| db + FRI_LOG_BLOWUP).collect();
    let final_height = FRI_LOG_BLOWUP + FRI_LOG_FINAL_POLY_LEN;
    let mut current = *heights.iter().next_back()?;
    let mut schedule = Vec::new();
    while current > final_height {
        let to_next = heights.range(..current).next_back().map_or(current - final_height, |next| current - next);
        let arity = FRI_MAX_LOG_ARITY.min(to_next).min(current - final_height);
        schedule.push(arity as u8);
        current -= arity;
    }
    Some(schedule)
}

/// [`non_canonical`] over proof bytes: `None` for bytes that do not decode canonically — those
/// are refused as `MalformedProof` wherever they are verified.
pub fn non_canonical_proof(bytes: &[u8]) -> Option<String> {
    non_canonical(&decode_canonical(bytes).ok()?)
}

/// The largest `input_log_height` a call at `tier` can honestly declare — the input table's
/// analogue of `Tier::max_keccak_log_height` (deep scan 2026-09-24, zkvm). Every private-input
/// word is absorbed by an `IS_INDIGEST` cpu row, four words a row plus the salt row
/// (`hash::input_digest_row_count`), and each of those rows is a cycle inside the tier's
/// `2^t − 1` budget, so `n_in ≤ 4·(2^t − 2)` and `input_log_height(n_in) ≤ t + 2`. The flat
/// 16-bit `HASH_LEFT` cap (65 535 words, `tables::input::MAX_LOG_HEIGHT`'s doc comment) is the
/// other ceiling; the bound is the smaller of the two. `verify_call` refuses a declaration past
/// it before any verifier key is built.
pub fn max_input_log_height(tier: Tier) -> u8 {
    ((tier.0 + 2) as u8).min(input::input_log_height(u16::MAX as usize))
}

/// CPU-1 (the 2026-09-27 zkVM/ISA review, medium, live): the most program words a call at
/// [`MAX_CALL_TIER`] can hold, when its public segment is `public_segment_words` long.
///
/// Every proof pays for its three digests before the guest executes a single instruction: one
/// Poseidon2 permutation per four program words (`Program::digest_rows`, at least one), one per
/// four private-input words plus the salt row (`hash::input_digest_row_count`, at least one — the
/// salt — for a call that reads nothing), and one per four public words (`hash::
/// public_digest_row_count`, at least one — the header — for an empty segment). The Poseidon2
/// table of tier `t` holds `poseidon2_height / BLOCK = 2^(t+2) / 32 = 2^(t-3)` permutations, which
/// `Machine::prove` refuses to exceed (`TooManyPoseidon2Permutations`) and `verify_call` caps `t` at
/// `MAX_CALL_TIER`. So at tier 14 there are 2 048 slots; the empty input and the empty public
/// segment take one each, and a program has at most `2 046` digest rows — **8 184 words**, the
/// report's number: `4 · (2^(14-3) − 1 − 1)`. A public segment of `n` words takes
/// `max(1, ⌈n/4⌉)` slots instead of one, and every input word a call reads lowers it further,
/// which is the caller's own affair — this is the bound for the lightest call there can be.
///
/// The cycle budget (`2^t − 1`, every digest row one cycle, plus at least the halting `ecall`) is
/// checked too, for completeness; at every tier it is the looser of the two by a factor of eight.
///
/// Nothing here is a guess at the machine: the terms are the vendored functions the prover itself
/// counts with (`build_traces_salted`), and `tests::cpu1_…` checks the bound against the prover's
/// own refusal one word either side of it. A program past it deploys and is charged `deploy_fee`
/// but no call can ever prove it — the shipped EVM interpreter (18 009 words) and sBPF interpreter
/// (8 317) among them — so a deploy past it is refused: the node's pool policy on every chain
/// (`admission::deploy_uncallable`), and a validity rule under genesis `hardening_v6`.
pub fn max_callable_program_words(public_segment_words: usize) -> usize {
    let tier = Tier(MAX_CALL_TIER as usize);
    let slots = tier.poseidon2_height() / crate::tables::poseidon2::BLOCK;
    let mandatory = crate::hash::input_digest_row_count(0) + crate::hash::public_digest_row_count(public_segment_words);
    let by_permutations = slots.saturating_sub(mandatory);
    // One executed instruction at least (the halt), on top of every digest row.
    let by_cycles = tier.max_cycles().saturating_sub(mandatory + 1);
    4 * by_permutations.min(by_cycles)
}

pub struct ZkExecutor {
    /// Every call proof's verifier keys: `warm` fills it, `verify_call` reads it (and builds a
    /// missing key into it).
    machine: Machine,
    /// The bundle guest's own `Machine` (CPUV-1 / ZKV-10, 2026-09-28), used by the bundle verify
    /// and `warm_bundle` and by nothing else. `Machine`'s key cache is a 64-entry FIFO whose
    /// `get` does not refresh an entry, and `warm` builds six keys (tiers 10/12/14 × two input
    /// heights) for every new (program height, public height) pair a deploy brings — so with one
    /// shared cache, eleven deploys of new shapes evicted the bundle key `warm_bundle` put in
    /// first at startup, and the next bundle not already in the verified set (B5) paid a tier-14
    /// key build synchronously inside consensus (3.3 s measured at the production profile, on
    /// every validator at once when a proposal carries it). `decode_and_check` pins every
    /// component of a bundle proof's key (tier, all three heights the prover chooses, both hash
    /// tables absent), so this cache only ever holds that one key and nothing a program can
    /// deploy reaches it. The vendored cache itself (FIFO, no single-flight) is upstream's.
    bundle_machine: Machine,
    /// The auth guest's own `Machine` (split authorisation), for the same reason as
    /// `bundle_machine`: `decode_and_check` pins every component of an auth proof's key
    /// ([`AUTH_TIER`], the guest's heights, no hash table), so this cache holds that one key and
    /// neither a deploy nor a bundle can evict it.
    auth_machine: Machine,
    /// Held across the whole body of `warm` and `warm_bundle` (CPUV-1): at most one warm-up
    /// builds keys at a time on this node, whoever calls it. `node::warm_new_programs` spawns a
    /// blocking task per deploy-carrying commit and the startup warm runs beside them, so before
    /// this the builds overlapped — six at once peaked at 1.58 GB against 2 GB droplets. A queued
    /// warm-up waits here holding nothing but a blocking-pool thread. It does not serialise the
    /// admission workers' own key builds on a cache miss (`Machine::verifier_key` has no
    /// single-flight); those are bounded by the four verify workers instead.
    warm_lock: std::sync::Mutex<()>,
    /// How many `warm`/`warm_bundle` bodies are running right now, and the most that ever ran at
    /// once — [`ZkExecutor::peak_concurrent_warms`], the observable CPUV-1's serialisation is
    /// tested by.
    warms_in_flight: std::sync::atomic::AtomicUsize,
    peak_warms: std::sync::atomic::AtomicUsize,
}

impl ZkExecutor {
    pub fn new(profile: FriProfile) -> ZkExecutor {
        ZkExecutor {
            machine: Machine::new(profile),
            bundle_machine: Machine::new(profile),
            auth_machine: Machine::new(profile),
            warm_lock: std::sync::Mutex::new(()),
            warms_in_flight: std::sync::atomic::AtomicUsize::new(0),
            peak_warms: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The most `warm`/`warm_bundle` bodies this executor ever ran at the same time.
    pub fn peak_concurrent_warms(&self) -> usize {
        self.peak_warms.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Runs one warm-up body under `warm_lock`, counted in [`ZkExecutor::peak_concurrent_warms`].
    /// A poisoned lock (a warm-up that panicked) still serialises: the guard is taken back
    /// rather than the panic spread to every later deploy's warm-up.
    fn warming<R>(&self, body: impl FnOnce() -> R) -> R {
        use std::sync::atomic::Ordering::SeqCst;
        let _serial = self.warm_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = self.warms_in_flight.fetch_add(1, SeqCst) + 1;
        self.peak_warms.fetch_max(now, SeqCst);
        let out = body();
        self.warms_in_flight.fetch_sub(1, SeqCst);
        out
    }

    pub fn profile(&self) -> FriProfile {
        self.machine.profile
    }

    pub fn profile_from_str(s: &str) -> Option<FriProfile> {
        match s {
            "production" => Some(FriProfile::Production),
            "test" => Some(FriProfile::Test),
            _ => None,
        }
    }

    /// Decode the `hc` (`isa::Program::digest`) a `ProgramRecord`'s `code_hash` stores — 8
    /// little-endian `u32` words, 32 bytes total (see `check_program`). Any other length means
    /// the record predates M3.4 or is otherwise corrupt; neither is a program this executor can
    /// verify a call against.
    fn hc_of(record: &ProgramRecord) -> Result<[u32; 8], ConfidentialError> {
        if record.code_hash.len() != 32 {
            return Err(ConfidentialError::WrongProgram);
        }
        let mut hc = [0u32; 8];
        for (i, word) in hc.iter_mut().enumerate() {
            *word = u32::from_le_bytes(record.code_hash[4 * i..4 * i + 4].try_into().unwrap());
        }
        Ok(hc)
    }

    /// Number of `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, public_log_height)` call verifier keys this executor's `Machine`
    /// currently has cached — `Machine`'s own cache, not a second one kept here (see the module
    /// doc comment). The bundle key is not among them: it lives in `bundle_machine` (CPUV-1),
    /// counted by [`ZkExecutor::cached_bundle_keys`].
    pub fn cached_keys(&self) -> usize {
        self.machine.cached_keys()
    }

    /// Number of verifier keys the bundle guest's own `Machine` holds: 0 before `warm_bundle` or
    /// the first bundle verify, 1 after, and never more (`decode_and_check` pins the key).
    pub fn cached_bundle_keys(&self) -> usize {
        self.bundle_machine.cached_keys()
    }

    /// Decode a proof and run every check that must precede `Machine::verify_public` — the
    /// cheap, purely structural ones, none of which touch the constraint system.
    ///
    /// The tier and all six declared table heights (`program_log_height`, `input_log_height`,
    /// `keccak_log_height`, `sha256_log_height`, `public_log_height`, `mem_log_height`) are
    /// attacker-chosen words inside the proof, and both the degree-bits comparison below and
    /// `Machine`'s verifier-key lookup shift by them, so each has to be bounded before it is
    /// used to size anything. That bounding is `machine::check_declared_heights`, called
    /// verbatim rather than restated — it is the same function `Machine::verify` runs, in the
    /// same order (tier, then program, then input, then the keccak table's flat range and
    /// keccak-vs-tier relation, then the sha256 table's pair, then the public table's plain
    /// range — mandatory, so there is no `0` escape — then memory), and the chain has no reason
    /// to want a different rule. `keccak_log_height == 0` and `sha256_log_height == 0` are
    /// legitimate and mean the proof declares no such table at all, which is every proof this
    /// chain has produced so far: neither the deployed guests nor the bundle guest uses either
    /// syscall.
    ///
    /// `exact` is what separates the two callers, and it still applies only to the program and
    /// input heights. A *call* proof's are merely range-checked here; `verify_call` then pins
    /// the program height to the deployed record's word count, bounds the input height by the
    /// tier and caps the tier itself (`MAX_CALL_TIER`), all before `Machine::verify` — which
    /// binds the heights cryptographically via the program and input digests, but only after
    /// building a key for them. A *bundle* proof is against one pinned guest with one fixed input width,
    /// so both heights are known up front and anything else is a proof for a different shape —
    /// rejected here rather than paying for a verifier key that could never match. Since zkvm I1
    /// the exact case also pins `tier` ([`BUNDLE_TIER`]) and both optional hash-table heights
    /// (`NO_KECCAK`/`NO_SHA256`), which are the *only* other prover-chosen words in a proof
    /// header that feed `Machine::verifier_key`; `mem_log_height` stays merely ranged here, since
    /// it is the one header word `verifier_key` does not key on — and pinning it here would be a
    /// validity change on every chain. Its pin (INT-5: exactly `t + 2`, 16 for a bundle) is one of
    /// the canonical-proof rules instead ([`non_canonical`]): every node's pool policy, and a
    /// validity rule under genesis `hardening_v6`.
    ///
    /// Size is no defence here and never was: chain 13 and 14 set `max_proof_bytes` to 8 MiB
    /// (`deploy/genesis-chain13.json`), and a junk header need not carry a large body at all —
    /// the key is built from the header before any proof body is looked at.
    ///
    /// The public height *is* pinned in the exact case since Task 5b: a bundle proof carries the
    /// transaction binding — always [`TX_BINDING_WORDS`] words — so its public table has exactly
    /// one honest height, `public_log_height(TX_BINDING_WORDS)` (`public_log_height`, passed in
    /// here). Any other declared height is a proof over a segment of some other length, which
    /// `verify_public` would refuse anyway, but only after building (and caching, evicting an
    /// honest one) a verifier key for the junk height; refusing it here is deterministic and costs
    /// a comparison. Since constraint set 7 floors every table at 2^7, a segment of up to 128
    /// words — the empty one of a pre-fork bundle proof among them — declares the binding's height
    /// too, and is refused by `verify_public`'s `H_PUB` comparison instead (the key it needs is the
    /// honest one, so nothing is evicted).
    fn decode_and_check(
        &self,
        proof: &[u8],
        program_log_height: u8,
        input_log_height: u8,
        public_log_height: u8,
        exact: bool,
        pinned_tier: usize,
    ) -> Result<Proof, ConfidentialError> {
        let proof = decode_canonical(proof)?;
        check_declared_heights(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.sha256_log_height,
            proof.public_log_height,
            proof.mem_log_height,
        )
        .map_err(|e| ConfidentialError::InvalidProof(format!("declared shape: {e:?}")))?;
        if exact && proof.program_log_height != program_log_height {
            return Err(ConfidentialError::InvalidProof("program height not the pinned guest's".into()));
        }
        if exact && proof.input_log_height != input_log_height {
            return Err(ConfidentialError::InvalidProof("input height not the pinned guest's".into()));
        }
        if exact && proof.public_log_height != public_log_height {
            return Err(ConfidentialError::InvalidProof("public height not the transaction binding's".into()));
        }
        // And the last three prover-chosen words of a bundle proof's header (zkvm I1). `tier`,
        // `keccak_log_height` and `sha256_log_height` were merely *ranged* by
        // `check_declared_heights`, so any of a few hundred legal triples reached
        // `Machine::verify` — which builds the verifier key for the declared shape *before*
        // verifying anything. That preprocessing pass is multi-second at the high tiers and the
        // key cache is a 64-entry FIFO, so 65 junk headers (free: no funds, no valid proof, no
        // deployed program — only a digest that matches the plaintext, which `check_bundle_proof`
        // compares cheaply) evict the honest bundle key `warm_bundle` built, and a Byzantine
        // proposer can make every validator rebuild it synchronously inside `on_proposal`.
        //
        // The hidden guest closes it because it has exactly one honest shape: every witness a
        // prover can construct lands at tier 14 — measured over all ten input shapes plus the
        // cycle-worst adversarial one in `tests/hidden_bundle.rs`
        // (`every_shape_lands_at_tier_14_with_identical_table_heights`; the lightest shape needs
        // 1 330 permutations, past tier 12's cap, and the worst fits tier 14 with 2 141 cycles
        // and 238 permutations to spare) — and it issues neither hash syscall, so both optional
        // tables are absent. `Tier::for_workload` reads cycles and permutations only, so this
        // holds at every FRI profile: the test profile's proofs are the same tier 14.
        //
        // `pinned_tier` is that one tier: [`BUNDLE_TIER`] for a bundle proof, [`AUTH_TIER`] for
        // an auth proof (split authorisation, whose guest is straight-line). Unread when `exact`
        // is false.
        if exact
            && (proof.tier != Tier(pinned_tier)
                || proof.keccak_log_height != NO_KECCAK
                || proof.sha256_log_height != NO_SHA256)
        {
            return Err(ConfidentialError::InvalidProof("tier or hash-table height not the pinned guest's".into()));
        }
        // Reproduces `Machine::verify`'s own equality check, which is simultaneously the check
        // that the batch's *instance count* matches what `chips` would build — nine mandatory
        // tables (the public table since constraint set 6), plus one per optional hash table
        // declared — so a header that claims `keccak_log_height = 0` while carrying ten
        // instances dies here, before any verifier key is built.
        if proof.batch.degree_bits
            != self.machine.log_ext_degrees_pub(
                proof.tier,
                proof.program_log_height,
                proof.input_log_height,
                proof.keccak_log_height,
                proof.sha256_log_height,
                proof.public_log_height,
                proof.mem_log_height,
            )
        {
            return Err(ConfidentialError::InvalidProof("degree bits".into()));
        }
        // The eight published output words are read as `u32`s by both callers, and since S3 so
        // are the eight `H_IN` words (`CallOutcome::h_in`, which a call receipt publishes); a
        // slot outside 32 bits cannot come from an honest trace — an output is a register word
        // and `H_IN` is a digest encoded as byte sums. The eight `H_PUB` words need no range
        // check of their own: `verify_call` and `verify_bundle` compare them against an expected
        // digest wholesale, and `Machine::verify` has already insisted every public
        // value is a canonical field element.
        if proof.public_values.len() != pv::NUM {
            return Err(ConfidentialError::MalformedProof);
        }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("output not a u32".into()));
        }
        if proof.public_values[pv::IN0..pv::IN0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("H_IN word not a u32".into()));
        }
        Ok(proof)
    }

    /// The chain's bundle guest: since chain 14 the hidden-asset guest
    /// ([`Self::hidden_bundle_program`], spec
    /// `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md` §3.10). Every
    /// shielded-pool proof on the chain is against it, and [`Self::hc_bundle`] is what a genesis
    /// pins.
    pub fn bundle_program() -> &'static Program {
        Self::hidden_bundle_program()
    }

    /// Digest of the chain's bundle guest (the hidden-asset guest) — the value a genesis pins as
    /// `hc_bundle`.
    pub fn hc_bundle() -> Word8 {
        Self::hc_hidden_bundle()
    }

    /// The `(program_log_height, input_log_height, public_log_height)` a bundle proof must
    /// declare: the hidden guest's ([`Self::hidden_bundle_heights`]). All three are fixed: the
    /// guest is one pinned program, its private-input vector is always
    /// `hidden::hidden_input::COUNT` words wide (a dummy slot is a zero-amount note, not a shorter
    /// witness — that is the whole point of the fixed 4-in-4-out shape), and its public segment
    /// is always the transaction binding, [`TX_BINDING_WORDS`] words (Task 5b). Through constraint
    /// set 6 that height, `public_log_height(8) == 4`, was not the empty segment's 2, so a
    /// pre-fork bundle proof was refused on the declared height alone; constraint set 7 floors
    /// both at `MIN_LOG_HEIGHT == 7`, and such a proof is refused at `verify_bundle`
    /// (`PublicValues`, its `H_PUB` is the empty segment's).
    pub fn bundle_heights() -> (u8, u8, u8) {
        Self::hidden_bundle_heights()
    }

    /// The retired 2-in-2-out bundle guest (`guests::bundle`), vendored verbatim from the research
    /// crate. **Off the chain path since the hidden-asset bundle** (chain 14): no executor method
    /// verifies against it. Kept only for the tests that still need it — `tests/shielded.rs` pins
    /// its digest to upstream's (`RESEARCH_HC_BUNDLE_HEX`), and `tests/hidden_bundle.rs` checks a
    /// hidden proof is refused under it. Assembled once per process.
    pub fn legacy_bundle_program() -> &'static Program {
        static BUNDLE: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        BUNDLE.get_or_init(crate::guests::bundle)
    }

    /// Digest of the retired `bundle` guest ([`Self::legacy_bundle_program`]). No chain pins it.
    pub fn hc_legacy_bundle() -> Word8 {
        Self::legacy_bundle_program().digest()
    }

    /// The hidden-asset bundle guest (`guests::bundle_hidden`, spec
    /// `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md`): four slots, the asset
    /// private. Node-local — there is no upstream copy to pin it against — and, since chain 14,
    /// the chain's one bundle guest ([`Self::bundle_program`]).
    ///
    /// Assembled once per process: `bundle_heights` calls this on every bundle admission (twice,
    /// in fact — `bundle_proof_digest` then `verify_bundle`), and re-running the assembler on
    /// each gossiped transaction is pure waste. The guest is a compile-time constant, so a
    /// `OnceLock` is the whole of the cache invalidation story.
    pub fn hidden_bundle_program() -> &'static Program {
        static HIDDEN: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        HIDDEN.get_or_init(crate::guests::bundle_hidden)
    }

    /// Digest of the hidden bundle guest — what a chain-14 genesis pins as `hc_bundle`.
    pub fn hc_hidden_bundle() -> Word8 {
        Self::hidden_bundle_program().digest()
    }

    /// The branch-free hidden-asset guest (`guests::bundle_hidden_v2`, INT-2 / GV-1): the same
    /// relation, witness layout and published digest as [`Self::hidden_bundle_program`], with an
    /// instruction trace that does not depend on the witness, so the program table's unblinded
    /// LogUp terminal no longer tells which input slots are real or how many 1 bits a spent
    /// note's leaf index has. **A genesis selects it** by naming [`Self::hc_hidden_bundle_v2`] as
    /// its `hc_bundle`; chain 15 names v1's. Assembled once per process, like v1.
    pub fn hidden_bundle_v2_program() -> &'static Program {
        static HIDDEN_V2: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        HIDDEN_V2.get_or_init(crate::guests::bundle_hidden_v2)
    }

    /// Digest of the branch-free hidden guest — what a genesis names as `hc_bundle` to run it.
    pub fn hc_hidden_bundle_v2() -> Word8 {
        Self::hidden_bundle_v2_program().digest()
    }

    /// Bundle guest v3 (`guests::bundle_hidden_v3`, delegated proving Phase 2, spec
    /// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): the branch-free
    /// relation over the v3 witness (`hidden::hidden_input_v3`: `nk` in place of the spend key,
    /// `salt` appended), publishing `hidden::hidden_bundle_digest_v3` — v2's digest with the auth
    /// commitment `c = H(AUTH, nk, salt)` before `bad`. Assembled once per process.
    pub fn hidden_bundle_v3_program() -> &'static Program {
        static HIDDEN_V3: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        HIDDEN_V3.get_or_init(crate::guests::bundle_hidden_v3)
    }

    /// Digest of bundle guest v3 — what a genesis names as `hc_bundle` to run split
    /// authorisation.
    pub fn hc_hidden_bundle_v3() -> Word8 {
        Self::hidden_bundle_v3_program().digest()
    }

    /// Every bundle guest this build carries, by the `hc_bundle` a genesis pins: the hidden guest
    /// chains 14 and 15 pin, the branch-free one, then v3 (split authorisation). A node refuses
    /// a genesis naming anything else (`node::check_build_runs_genesis`), and a wallet proves
    /// with [`Self::bundle_program_for`] the chain's own.
    pub fn known_hc_bundles() -> [Word8; 3] {
        [Self::hc_hidden_bundle(), Self::hc_hidden_bundle_v2(), Self::hc_hidden_bundle_v3()]
    }

    /// The width of the private-input vector the bundle guest `hc` reads:
    /// `hidden::hidden_input::COUNT` (1 204) for v1 and v2, `hidden::hidden_input_v3::COUNT`
    /// (1 212) for v3. Any other `hc` gets v1's width (no program of this build is proved or
    /// verified at it; the heights only have to be deterministic).
    pub fn bundle_input_words(hc: &Word8) -> usize {
        if *hc == Self::hc_hidden_bundle_v3() {
            crate::hidden::hidden_input_v3::COUNT
        } else {
            crate::hidden::hidden_input::COUNT
        }
    }

    /// The `(program_log_height, input_log_height, public_log_height)` a proof of the bundle
    /// guest `hc` must declare — its program's, its [`Self::bundle_input_words`]-wide witness',
    /// and the transaction binding's. For v1 and v2 this is [`Self::hidden_bundle_heights`];
    /// `tests/hidden_bundle.rs` measures v3's (at this build, the same three heights).
    pub fn bundle_heights_for(hc: &Word8) -> (u8, u8, u8) {
        let program = Self::bundle_program_for(hc).unwrap_or_else(Self::hidden_bundle_program);
        pinned_heights(program, Self::bundle_input_words(hc))
    }

    /// The bundle guest whose digest is `hc`, if this build carries it — what a wallet proves
    /// for a chain whose genesis pins `hc`. `None` for any other digest (the retired 2-in-2-out
    /// guest included: no executor path verifies against it).
    ///
    /// Verification needs no such lookup: the program table is a witness table digested
    /// in-circuit, so `verify_bundle` checks a proof against whatever `hc` the ledger hands it,
    /// at the pinned heights — which the two guests share (their programs pad to the same table
    /// height and read the same input vector; `tests/hidden_bundle.rs` pins it), so one verifier
    /// key and one `bundle_heights` serve both.
    pub fn bundle_program_for(hc: &Word8) -> Option<&'static Program> {
        if *hc == Self::hc_hidden_bundle() {
            Some(Self::hidden_bundle_program())
        } else if *hc == Self::hc_hidden_bundle_v2() {
            Some(Self::hidden_bundle_v2_program())
        } else if *hc == Self::hc_hidden_bundle_v3() {
            Some(Self::hidden_bundle_v3_program())
        } else {
            None
        }
    }

    /// `bundle_heights` for the hidden bundle guest: its program, its fixed
    /// `hidden::hidden_input::COUNT`-word input vector, and the transaction binding.
    pub fn hidden_bundle_heights() -> (u8, u8, u8) {
        pinned_heights(Self::hidden_bundle_program(), crate::hidden::hidden_input::COUNT)
    }

    /// The digest a hidden bundle proof publishes, after the same structural checks (exact
    /// heights, canonical encoding), at v1's heights — for a caller that does not know the
    /// chain's `hc_bundle` (the wallet's remote-prover reply check). Every guest of this build
    /// shares those heights today (`tests/hidden_bundle.rs` asserts it); the ledger's path,
    /// `ConfidentialExecutor::bundle_proof_digest`, is keyed by the chain's `hc_bundle`
    /// ([`Self::hidden_bundle_proof_digest_for`]).
    pub fn hidden_bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.pinned_proof_digest(Self::hidden_bundle_heights(), proof)
    }

    /// [`Self::hidden_bundle_proof_digest`] at the heights of the bundle guest `hc`
    /// ([`Self::bundle_heights_for`]) — `ConfidentialExecutor::bundle_proof_digest`, which the
    /// ledger hands its genesis `hc_bundle`.
    pub fn hidden_bundle_proof_digest_for(&self, hc: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.pinned_proof_digest(Self::bundle_heights_for(hc), proof)
    }

    /// The auth guest (split authorisation, `guests::auth`, spec
    /// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): `sk`, `salt` in,
    /// `c = H(AUTH, nk, salt)` out. Assembled once per process, like the bundle guests.
    pub fn auth_program() -> &'static Program {
        static AUTH: std::sync::OnceLock<Program> = std::sync::OnceLock::new();
        AUTH.get_or_init(crate::guests::auth)
    }

    /// Digest of the auth guest — what a genesis names as `hc_auth` to run split authorisation.
    pub fn hc_auth() -> Word8 {
        Self::auth_program().digest()
    }

    /// The `(program_log_height, input_log_height, public_log_height)` an auth proof must
    /// declare: the auth guest's program, its fixed `auth::auth_input::COUNT`-word witness and the
    /// transaction binding.
    pub fn auth_heights() -> (u8, u8, u8) {
        pinned_heights(Self::auth_program(), crate::auth::auth_input::COUNT)
    }

    /// `ConfidentialExecutor::auth_proof_digest`: the `c` an auth proof publishes, after the
    /// structural checks at the auth guest's pinned shape. Nothing verified.
    pub fn auth_proof_commit(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        let (plh, ilh, pubh) = Self::auth_heights();
        let p = self.decode_and_check(proof, plh, ilh, pubh, true, AUTH_TIER)?;
        published_digest(&p.public_values)
    }

    /// `ConfidentialExecutor::verify_auth`: the auth proof decoded at the pinned shape, verified
    /// against `hc_auth` with `binding` as its public segment (`verify_public`), and the `c` it
    /// publishes returned.
    pub fn verify_auth_proof(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError> {
        let (plh, ilh, pubh) = Self::auth_heights();
        let p = self.decode_and_check(proof, plh, ilh, pubh, true, AUTH_TIER)?;
        self.auth_machine
            .verify_public(hc_auth, binding, &p)
            .map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        published_digest(&p.public_values)
    }

    /// `ConfidentialExecutor::verify_bundle` for a hidden bundle proof: verified against `hc`
    /// with the transaction binding as its public segment (Task 5b), exactly as a `bundle` proof
    /// is — the empty segment and any other transaction's words are refused.
    pub fn verify_hidden_bundle(&self, hc: &Word8, proof: &[u8], binding: &[u32; TX_BINDING_WORDS]) -> Result<(), ConfidentialError> {
        self.verify_pinned_bundle(Self::bundle_heights_for(hc), hc, proof, binding)
    }

    /// `verify_call`, and under genesis `hardening_v6` `verify_call_hardened` (`segment` set — it
    /// is what "hardened" means here: the bound segment and the program-table floor below), and
    /// its decode-only twin (`verify` false: everything but `Machine::verify`).
    ///
    /// INT-4: with `segment` set, a call must carry it as its public segment — its declared public
    /// height is its length's and `pv::PUB0..7` is its digest. The ledger builds it as the
    /// program's deploy-time public words followed by the eight binding words
    /// (`Transaction::call_binding`, `program::hardened_call_segment`), so just the binding for a
    /// program without a public input, where the old rule wants the empty segment. A copy of the
    /// proof under another fee bundle then fails the digest compare. Before issue #55 a program
    /// with a public input kept its recorded digest here — the ledger held only that digest — and
    /// its calls stayed unbound. A segment of any length but `public_len + TX_BINDING_WORDS` is
    /// refused as `PublicValues`.
    fn check_call(
        &self,
        record: &ProgramRecord,
        proof: &[u8],
        segment: Option<&[u32]>,
        verify: bool,
    ) -> Result<CallOutcome, ConfidentialError> {
        // INT-4: the segment this call proves over — `public ‖ call_binding` under the hardened
        // rule; otherwise the deploy-time input, as ever.
        if segment.is_some_and(|s| s.len() != record.public_len as usize + TX_BINDING_WORDS) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        }
        let segment_len = segment.map_or(record.public_len as usize, |s| s.len());
        // `Machine::verify` runs `check_declared_heights` on the proof's tier and six declared
        // table heights before using any of them to size anything — but the degree-bits pre-check
        // inside `decode_and_check` shifts by them too, so it runs that same function in front of
        // it, to avoid panicking on an attacker-chosen out-of-range value before ever reaching
        // `verify`. `decode_and_check` only *ranges* a call's tier, program and input heights;
        // the three checks below pin them against what the chain does know, and every one of
        // them runs before `Machine::verify` builds a verifier key for the declared shape.
        let proof = self.decode_and_check(proof, 0, 0, 0, false, 0)?;
        // The tier cap (deep scan 2026-09-24, zkvm). `check_declared_heights` admits every tier
        // in `TIERS`, and `Machine::verify` builds the verifier key for the declared tier
        // *before* it looks at a byte of STARK data — every pre-check in front of that build is
        // satisfiable from public data alone (a consistent `degree_bits`, the tier's memory
        // floor, the tier public value). The tier-20 key costs 216 s and 6.5 GB at the
        // production profile, on validators that are 2–4 GB droplets, so one legal tier-20
        // header — its transaction never mined, its fee bundle's note never spent, so it can be
        // resubmitted forever — was an out-of-memory kill of the admitting node. Refused as its
        // own verdict, with the remedy in the message, so an honest prover above the cap is
        // told what to do rather than handed a `Batch(…)` failure.
        let tier = proof.tier.0 as u8;
        if tier > MAX_CALL_TIER {
            return Err(ConfidentialError::CallTierTooHigh { tier, max: MAX_CALL_TIER });
        }
        // The two optional hash tables, whose preprocessed columns are the key's real cost
        // (`MAX_CALL_KECCAK_LOG_HEIGHT`'s doc comment has the numbers): `check_declared_heights`
        // bounds them by the tier's honest need, which at tier 14 is still a 2^19-row keccak
        // table — 128 s and 8.7 GB of key. `0` declares no table and is always admitted.
        if proof.keccak_log_height > MAX_CALL_KECCAK_LOG_HEIGHT {
            return Err(ConfidentialError::InvalidProof(format!(
                "keccak height {} past the {} a call may declare",
                proof.keccak_log_height, MAX_CALL_KECCAK_LOG_HEIGHT
            )));
        }
        if proof.sha256_log_height > MAX_CALL_SHA256_LOG_HEIGHT {
            return Err(ConfidentialError::InvalidProof(format!(
                "sha256 height {} past the {} a call may declare",
                proof.sha256_log_height, MAX_CALL_SHA256_LOG_HEIGHT
            )));
        }
        // The program height is not a guess: the record holds the deployed words, and
        // `Machine::prove` declares exactly `program_log_height(program.len())` (`Program::len`
        // is `words.len()`), so any other declared height is a proof over a different program
        // table — one the `hc` compare inside `verify` would refuse, but only after a key was
        // built and cached (evicting a warmed one) for the junk height.
        //
        // PROGRAM-TABLE-LEAK: under `hardening_v6` the height is the record's floored at
        // `MIN_PRIVATE_TABLE_LOG_HEIGHT` (`hardened_program_log_height`), exactly — the hardened
        // prover declares that and nothing else, so the pin stays a single value.
        let want_program_height = match segment {
            Some(_) => hardened_program_log_height(record.words.len()),
            None => program::program_log_height(record.words.len()),
        };
        if proof.program_log_height != want_program_height {
            return Err(ConfidentialError::InvalidProof("program height not the deployed program's".into()));
        }
        // The input height is unknown but bounded by the tier, exactly as the keccak height is
        // bounded by it inside `check_declared_heights` (`max_input_log_height`).
        if proof.input_log_height > max_input_log_height(proof.tier) {
            return Err(ConfidentialError::InvalidProof("input height past what the tier can read".into()));
        }
        // A deterministic early reject, before `hc_of` and `Machine::verify`: a call against a
        // program deployed with a public input must declare exactly the public-table height the
        // prover derives from that input's length (`Machine::prove` uses
        // `public_log_height(public.len())`, and the record's `public_len` is that length). Any
        // other height is a proof over a different public segment, which the `PUB0..7` compare
        // below would refuse anyway — but only after `verify` had built (and cached, evicting an
        // honest one) a verifier key for the junk height. Same error as that compare.
        if proof.public_log_height != public::public_log_height(segment_len) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        }
        let hc = Self::hc_of(record)?;
        // The call limits (spec §5): `verify`, then `pv::PUB0..7` against the public input the
        // program was deployed with — its record's digest, computed once at deploy, so no word is
        // re-hashed here. A program deployed without one takes only `hash::public_digest(&[])`,
        // exactly `verify_public(hc, &[], proof)`, today's rule. Plain `verify` alone would
        // accept any `H_PUB`, bound in-circuit to a public segment the chain never saw (see the
        // module doc comment). A mismatch reports as `verify_public`'s own `PublicValues`.
        //
        // `verify` false is B5's decode path: admission ran `Machine::verify` over these bytes.
        if verify {
            self.machine.verify(&hc, &proof).map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        }
        let want = match segment {
            Some(words) => crate::hash::public_digest(words),
            None => record.public_digest.unwrap_or_else(|| crate::hash::public_digest(&[])),
        };
        if (0..8).any(|i| proof.public_values[pv::PUB0 + i] != want[i] as u64) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        }
        let outputs = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        // M4.1/S3: `H_IN` travels to the receipt so a call-input envelope sealed against it can
        // be opened and checked later (spec §6.1). `decode_and_check` has already refused a
        // proof whose `IN0..7` are not `u32`s, so the narrowing below cannot silently truncate.
        let h_in = std::array::from_fn(|i| proof.public_values[pv::IN0 + i] as u32);
        Ok(CallOutcome {
            tier: proof.tier.0 as u8,
            outputs,
            h_in,
            keccak_log_height: proof.keccak_log_height,
            sha256_log_height: proof.sha256_log_height,
        })
    }

    /// The body of `warm`/`warm_hardened`: every admissible tier's key for one program height and
    /// one public-segment length, at the input heights a call can still be pooled with.
    fn warm_shape(&self, log_height: u8, public_len: usize) {
        self.warming(|| {
            // The smallest input table a call can still be pooled with (COV-2 / INT-6): below
            // `MIN_PRIVATE_TABLE_LOG_HEIGHT` the pool refuses the call before any key is built
            // (`admission::call_reveals_private_inputs`), so warming `input::MIN_LOG_HEIGHT`
            // would spend a key build and a cache slot per tier on a shape no call can use. An
            // upgraded wallet's prover floors the table there too, so the floor *is* the typical
            // height of every small call.
            let smallest = input::MIN_LOG_HEIGHT.max(MIN_PRIVATE_TABLE_LOG_HEIGHT);
            let typical = input::input_log_height(4).max(MIN_PRIVATE_TABLE_LOG_HEIGHT);
            let input_heights: &[u8] = if typical == smallest { &[smallest] } else { &[smallest, typical] };
            let public_height = public::public_log_height(public_len);
            // Every tier a call may declare (`MAX_CALL_TIER` and below) — the cap and this loop
            // move together, so no admissible tier is ever an unwarmed key build at admission.
            for t in TIERS.iter().filter(|t| **t as u8 <= MAX_CALL_TIER) {
                for &in_h in input_heights {
                    self.machine.verifier_key(Tier(*t), log_height, in_h, NO_KECCAK, NO_SHA256, public_height);
                }
            }
        })
    }

    /// The published digest of a proof of a pinned bundle guest whose heights are `heights`.
    fn pinned_proof_digest(&self, heights: (u8, u8, u8), proof: &[u8]) -> Result<Word8, ConfidentialError> {
        let (plh, ilh, pubh) = heights;
        let p = self.decode_and_check(proof, plh, ilh, pubh, true, BUNDLE_TIER)?;
        published_digest(&p.public_values)
    }

    /// Verifies a proof of a pinned bundle guest (heights `heights`, digest `hc`) against the
    /// transaction binding. `verify_public` against the binding (Task 5b): `H_PUB` must be the
    /// digest of exactly the eight words of `Transaction::binding` for the transaction the bundle
    /// rides in. The empty segment (every pre-fork bundle proof) is refused on its declared
    /// height, and any other transaction's words fail as `PublicValues`.
    fn verify_pinned_bundle(
        &self,
        heights: (u8, u8, u8),
        hc: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        let (plh, ilh, pubh) = heights;
        let p = self.decode_and_check(proof, plh, ilh, pubh, true, BUNDLE_TIER)?;
        self.bundle_machine
            .verify_public(hc, binding, &p)
            .map_err(|e| ConfidentialError::InvalidBundleProof(format!("{e:?}")))
    }
}

/// The eight output words a proof publishes (`pv::OUT0..8`) as the digest they encode — each a
/// checked `u32::try_from`, never an `as` (ZKG-1, 2026-09-28). `decode_and_check` already refuses
/// a proof with an output outside 32 bits, so on today's path the narrowing could not bite; but
/// `x as u32` of `2^32 + w` is `w`, the very digest an honest proof publishing `w` carries, so a
/// silent truncation here would turn any future gap in that check into a digest match. The pruned
/// path (`Ledger::check_bundle_proof`) reads the same words with `u32::try_from` and refuses with
/// `BadDigest`; this one refuses the proof as malformed, and a vector too short to hold the eight
/// words likewise, rather than indexing past its end.
fn published_digest(public_values: &[u64]) -> Result<Word8, ConfidentialError> {
    let mut digest: Word8 = [0; 8];
    for (k, slot) in digest.iter_mut().enumerate() {
        let word = public_values.get(pv::OUT0 + k).ok_or(ConfidentialError::MalformedProof)?;
        *slot = u32::try_from(*word).map_err(|_| ConfidentialError::MalformedProof)?;
    }
    Ok(digest)
}

/// The core crate's digest record as the hidden guest's (the two are field-for-field the same;
/// core cannot name a zkvm type, so the copy happens on this side).
///
/// `auth_commit` is not a v1 field and is dropped here; [`hidden_digest_input_v3`] carries it.
pub fn hidden_digest_input(i: &BundleDigestInput) -> crate::hidden::HiddenDigestInput {
    let BundleDigestInput { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset, time, auth_commit: _ } = *i;
    crate::hidden::HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset, time }
}

/// The core crate's digest record as bundle guest v3's (split authorisation): the v1 fields and
/// the bundle's `auth_commit`.
pub fn hidden_digest_input_v3(i: &BundleDigestInput) -> crate::hidden::HiddenDigestInputV3 {
    crate::hidden::HiddenDigestInputV3 { base: hidden_digest_input(i), auth_commit: i.auth_commit }
}

/// The `(program_log_height, input_log_height, public_log_height)` every proof of a pinned bundle
/// guest must declare: its program's, its fixed `input_words`-wide private input's, and the
/// transaction binding's ([`TX_BINDING_WORDS`] words, Task 5b). Shared by `bundle` and the hidden
/// bundle so the two cannot drift.
fn pinned_heights(program: &Program, input_words: usize) -> (u8, u8, u8) {
    (
        program::program_log_height(program.words.len()),
        input::input_log_height(input_words),
        public::public_log_height(TX_BINDING_WORDS),
    )
}

/// Decode a proof and refuse it unless its bytes are the *canonical* postcard encoding of what
/// they decode to — `decode(bytes).to_bytes() == bytes`. `postcard::from_bytes` alone ignores
/// trailing bytes and accepts overlong varints, so without this a proof could be padded (riding
/// free under a byte-priced fee, since the fee is charged on the bytes the chain stores) or
/// re-encoded into a different transaction id for the same statement. Every proof the chain
/// decodes — fee bundle, burn bundle and call, all through `decode_and_check` — passes here
/// first; a non-canonical one is the same `MalformedProof` as an undecodable one. The re-encode
/// costs a linear pass over bytes that are about to be verified anyway.
///
/// A consensus tightening: a chain-12 block holding a non-canonical proof would be refused by
/// this build, which is one more reason the build is chain-13-only (CHANGELOG, v0.4).
pub fn decode_canonical(bytes: &[u8]) -> Result<Proof, ConfidentialError> {
    let proof: Proof = postcard::from_bytes(bytes).map_err(|_| ConfidentialError::MalformedProof)?;
    if proof.to_bytes() != bytes {
        return Err(ConfidentialError::MalformedProof);
    }
    Ok(proof)
}

impl ConfidentialExecutor for ZkExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        if base_pc % 4 != 0 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "base_pc not word aligned".into() });
        }
        if words.is_empty() {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "empty program".into() });
        }
        // ZH4 (2026-09-12 zk audit): a program whose `base_pc + 4·len` wraps the u32 address
        // space can never execute past the wrap (`instr_at` refuses `pc < base_pc`, and
        // `Program::pc_of` wraps in release) — reject it at admission rather than let a deployer
        // pay `deploy_fee` for a program no call could ever prove.
        if base_pc as u64 + 4 * words.len() as u64 > 1 << 32 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "program spans the u32 pc wrap".into() });
        }
        for (index, w) in words.iter().enumerate() {
            Instr::decode(*w).map_err(|e| ConfidentialError::BadInstruction { index, reason: format!("{e:?}") })?;
        }
        // M3.4: the on-chain code commitment *is* `hc` now — the exact in-circuit digest
        // `Machine::verify` checks every call's proof against, not just an informational
        // content id (`program_id`, a separate blake3 hash, already covers that role via
        // `ProgramRecord.id`). Stored as 8 little-endian `u32` words (32 bytes); `hc_of` is the
        // inverse.
        let hc = Program { base_pc, words: words.to_vec() }.digest();
        let mut out = Vec::with_capacity(32);
        for w in hc {
            out.extend_from_slice(&w.to_le_bytes());
        }
        Ok(out)
    }

    fn max_callable_program_words(&self, public_segment_words: usize) -> Option<usize> {
        Some(max_callable_program_words(public_segment_words))
    }

    /// Precompute the verifier keys a call against `record` is likely to need, off the node
    /// loop (deploy commit / startup). Since M3.4 the key is `(tier, program_log_height)` and
    /// program-content-independent, so this warms one shared key per tier for this program's
    /// declared height. The security review (a44d3f4) found that warming a single tier left the
    /// first honest call at any other tier paying the uncached key cost inline; warming every
    /// tier would build the Poseidon2 chip's preprocessed round-constant table at `2^22` rows on
    /// a 2-vCPU validator, so this warms the tiers real guests land on today (10, 12, 14 — the
    /// transfer guest proves at 14). Since the deep scan of 2026-09-24 those are also the *only*
    /// tiers a call may declare (`MAX_CALL_TIER`, enforced by `verify_call` before any key is
    /// built), so the set warmed here is exactly the set admissible, and the two are written as
    /// one expression so they cannot drift.
    ///
    /// M4.1 (ruling): the key also carries `input_log_height`, but `warm` only knows the
    /// program's word count — it has no visibility into what any future call's private-input
    /// vector will look like, so it cannot warm "the" input height the way it warms the exact
    /// program height. It warms two classes instead: `input::MIN_LOG_HEIGHT` (`input_log_height`
    /// of a 0..3-word call — the smallest class the table shape has) and
    /// `input::input_log_height(4)` (a 4-word call — what every guest this crate deploys today
    /// actually reads: `balance_check`/`private_payment` both read exactly 4 private inputs via
    /// `guests.rs`'s `read_input(0..3)` pattern), when that is a different class from the first
    /// (it is: `input_log_height(0) == MIN_LOG_HEIGHT == 2`, `input_log_height(4) == 3`). A call
    /// with a differently-sized input vector still verifies; like an unwarmed tier, it just pays
    /// the first-verify key-build cost once per (tier, program_log_height, input_log_height).
    ///
    /// M4.2: the key carries `keccak_log_height` too, and this warms exactly one value of it —
    /// `0`, "no keccak table". That is not a guess in the way the input height is: a proof only
    /// declares a keccak table if its guest actually calls `SYS_KECCAK`, no guest this chain
    /// deploys does, and at the production profile a keccak-bearing proof is ~1.91 MB larger
    /// than one without — 3 106 757 bytes at tier 10, which `randprotocol-core`'s 2 MiB
    /// `MAX_PROOF_BYTES` refuses outright (note 2026-09-28: that is the default cap; chains 13–15
    /// set genesis `max_proof_bytes` to 8 MiB, where such a proof fits and is refused only past
    /// `MAX_CALL_KECCAK_LOG_HEIGHT`). Warming the keccak classes as well would multiply
    /// this by the whole `[5, tier + 5]` range; a call that does declare one (at the `Test`
    /// profile, or once the block-space work makes such a proof admissible) pays the key-build
    /// cost once, like an unwarmed tier.
    ///
    /// Constraint set 6: the key carries `sha256_log_height` and `public_log_height` as well,
    /// and this warms exactly one value of each, on the same grounds as the keccak class —
    /// `NO_SHA256` (no deployed guest calls `SYS_SHA256` either) and
    /// `public::public_log_height(0)` (the empty public segment's declared height,
    /// `tables::public::MIN_LOG_HEIGHT`). A program deployed with a public input (the call
    /// limits, spec §5) proves at `public_log_height(record.public_len)` instead — every call
    /// against it commits to exactly that input, so that one class is warmed in place of the
    /// empty one, and its first call pays no key build.
    fn warm(&self, record: &ProgramRecord) {
        self.warm_shape(program::program_log_height(record.words.len()), record.public_len as usize)
    }

    /// `warm` under genesis `hardening_v6`: every call carries the eight call-binding words after
    /// the program's public input (INT-4 and issue #55, `check_call`), so that is the public height
    /// its keys are built for.
    fn warm_hardened(&self, record: &ProgramRecord) {
        let segment = record.public_len as usize + TX_BINDING_WORDS;
        // And the floored program table (PROGRAM-TABLE-LEAK).
        self.warm_shape(hardened_program_log_height(record.words.len()), segment)
    }


    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.check_call(record, proof, None, true)
    }

    fn verify_call_hardened(
        &self,
        record: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.check_call(record, proof, Some(segment), true)
    }

    /// Every check of [`Self::verify_call_hardened`] but `Machine::verify` itself (B5: the
    /// verified set vouches for these bytes).
    fn decode_call_hardened(
        &self,
        record: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.check_call(record, proof, Some(segment), false)
    }

    /// `H_PUB` exactly as the circuit publishes it in `pv::PUB0..7`.
    fn public_digest(&self, words: &[u32]) -> Word8 {
        crate::hash::public_digest(words)
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(left);
        msg[8..].copy_from_slice(right);
        crate::notes::hash(crate::notes::domain::NODE, &msg)
    }

    /// The vendored `Note`'s own commitment, built by fields rather than by `Note::new` (which
    /// draws `r` itself): the ledger is handed `r` on the wire precisely so it can recompute a
    /// deposit note it did not create. `tests/shielded.rs` pins the two against each other.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        crate::notes::Note { pk: *pk, from: *from, amount, asset, time, r: *r }.commitment()
    }

    /// The hidden-asset bundle digest (spec §3.4, `hidden::hidden_bundle_digest`) over the core
    /// record's fields — the same eight fields, the same order, and no asset.
    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        crate::hidden::hidden_bundle_digest(&hidden_digest_input(i))
    }

    /// Bundle guest v3's digest (`hidden::hidden_bundle_digest_v3`): v1's preimage with the
    /// bundle's `auth_commit` before the taint word.
    fn bundle_digest_v3(&self, i: &BundleDigestInput) -> Word8 {
        crate::hidden::hidden_bundle_digest_v3(&hidden_digest_input_v3(i))
    }

    fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.hidden_bundle_proof_digest_for(hc_bundle, proof)
    }

    fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.auth_proof_commit(proof)
    }

    fn verify_auth(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError> {
        self.verify_auth_proof(hc_auth, proof, binding)
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        self.verify_hidden_bundle(hc_bundle, proof, binding)
    }

    /// The bundle guest's verifier key. Unlike `warm`, this needs no guessing: the guest is
    /// pinned, so its `(tier, program_log_height, input_log_height, keccak_log_height,
    /// sha256_log_height, public_log_height)` is a single known sextuple — tier 14, which is
    /// where every witness of the hidden guest lands (`tests/hidden_bundle.rs` measures the worst
    /// case), `NO_KECCAK` and `NO_SHA256` since the guest issues neither hash syscall, and the
    /// transaction binding's public height (`bundle_heights`), since every bundle proof commits
    /// to it.
    fn non_canonical_proof(&self, proof: &[u8]) -> Option<String> {
        non_canonical_proof(proof)
    }

    fn warm_bundle(&self) {
        self.warming(|| {
            let (plh, ilh, pubh) = Self::bundle_heights();
            let _ = self.bundle_machine.verifier_key(Tier(BUNDLE_TIER), plh, ilh, NO_KECCAK, NO_SHA256, pubh);
        })
    }

    /// The auth guest's one key ([`AUTH_TIER`], its pinned heights, no hash table) — the only key
    /// `verify_auth_proof` ever asks `auth_machine` for.
    fn warm_auth(&self) {
        self.warming(|| {
            let (plh, ilh, pubh) = Self::auth_heights();
            let _ = self.auth_machine.verifier_key(Tier(AUTH_TIER), plh, ilh, NO_KECCAK, NO_SHA256, pubh);
        })
    }

    /// The bare zkVM executor cannot build or verify aggregate proofs: the rVM lives in
    /// `randprotocol-rvm`, which depends on this crate, so linking it here would be a crate cycle.
    /// `rand-node` wraps this executor with the rVM-backed aggregating one.
    fn aggregate_program_digest(
        &self,
        _shape: &randprotocol_core::types::DeclaredShape,
    ) -> Result<[u64; 4], ConfidentialError> {
        Err(ConfidentialError::AggregationUnsupported)
    }

    fn verify_aggregate(
        &self,
        _shape: &randprotocol_core::types::DeclaredShape,
        _covered: &[randprotocol_core::types::CoveredBundle],
        _proof: &[u8],
        _binding: &[u32; 8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        Err(ConfidentialError::AggregationUnsupported)
    }
}

/// The zkVM's own commitment to a program: `hc`, the in-circuit Poseidon2 digest
/// `Machine::verify` checks proofs against, as hex. M3.4: no longer `Machine`/tier-dependent —
/// `Program::code_hash` is a pure, deterministic function of `base_pc` and the program's words;
/// kept here (rather than just calling `program.code_hash()` at call sites) for API stability,
/// e.g. explorers that already import it from this module.
pub fn zk_code_hash(program: &Program) -> String {
    program.code_hash()
}

/// Prover entry point for the wallet and tests. Returns (proof bytes, outputs, tier).
///
/// `backend` picks the prover implementation: `Backend::Cpu` always exists, the GPU and
/// reference backends only in builds that enabled their feature. Every backend produces a proof
/// the ordinary CPU verifier accepts, so nothing downstream of here changes with it. There is no
/// fallback: a backend that cannot start (no driver, no PTX) is an error, not a silent CPU run.
///
/// M4.1: every path this delegates to (`Machine::prove_with` → `Machine::prove` on the CPU
/// backend, `Machine::prove_on` for the reference/CUDA backends) draws a fresh per-proof `H_IN`
/// salt from OS entropy internally — never `Machine::prove_salted`, which exists only for tests
/// that need a fixed salt to check against. This entry point must keep it that way: an unsalted
/// or reused `H_IN` is a guessable/linkable commitment to the private inputs, not a hiding one.
///
/// S3: a caller that will publish a call-input envelope needs the salt back and uses
/// [`prove_call`] instead, which draws an equally fresh one on this side of `Machine`. This
/// function stays as it is — it is the path every backend can serve.
///
/// `public` is the program's deploy-time public input (`rand_getProgramPublic`), empty for a
/// program deployed without one. The proof's `H_PUB` commits to it, and the chain checks that
/// against the program's recorded digest (`ZkExecutor::verify_call`), so a proof over any other
/// public input is refused.
pub fn prove(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    public: &[u32],
    tier: Option<u8>,
    backend: Backend,
) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let m = Machine::new(profile);
    let (proof, exec) = m
        .prove_with(backend, program, inputs, public, tier.map(|t| Tier(t as usize)))
        .map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

/// `prove` for a caller that will publish a call-input envelope: the same proof, plus the
/// `H_IN` salt that produced it (spec §6.1, S3 Task 1).
///
/// The envelope's body carries `(salt, inputs)` and is sealed against the proof's public
/// `H_IN` (`pv::IN0..7`), so whoever opens it can recompute `hash::input_digest(salt, inputs)`
/// and see that the transcript is the one the guest was actually fed
/// (`call_envelope::call_envelope_is_faithful`). That is only possible if the salt leaves the
/// prover, which `Machine::prove` — drawing it internally and dropping it — does not allow;
/// hence this entry point, which draws the same fresh OS-entropy salt itself and hands it to
/// `Machine::prove_salted`. Freshness is still this function's job: a reused or guessable salt
/// makes `H_IN` a guessable commitment to the private inputs, which is the whole reason M4.1
/// salts it (`Machine::prove_salted`'s doc comment).
///
/// Only `Backend::Cpu` can answer: the GPU and reference paths run inside the vendored
/// `Machine::prove_with`, which draws its own salt and never returns it. A caller proving on
/// one of those backends must prove without an envelope (`prove`) — the chain accepts both.
///
/// `public` is the program's deploy-time public input, as for [`prove`]. `max_input_words` is the
/// envelope's input cap (`call_envelope::CallCaps::max_input_words`, derived from the chain's
/// `max_call_envelope_bytes`).
pub fn prove_call(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    public: &[u32],
    tier: Option<u8>,
    backend: Backend,
    max_input_words: usize,
) -> Result<(Vec<u8>, [u32; 8], u8, [u32; 4]), String> {
    // The envelope this proof is for cannot carry more than the chain's input cap, and proving
    // is minutes: refuse now rather than after the work is done (`call_envelope`'s own check is
    // the same one, reached by a caller that seals without proving).
    if inputs.len() > max_input_words {
        return Err(format!("a call may prove at most {max_input_words} input words, got {}", inputs.len()));
    }
    match backend {
        Backend::Cpu => {
            use rand::RngExt;
            let salt: [u32; 4] = rand::rng().random();
            let m = Machine::new(profile);
            let (proof, exec) = m
                .prove_salted(program, inputs, public, salt, tier.map(|t| Tier(t as usize)))
                .map_err(|e| format!("{e:?}"))?;
            Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8, salt))
        }
        #[allow(unreachable_patterns)]
        other => Err(format!(
            "{other:?} draws its H_IN salt inside the prover and cannot return it; \
             prove a call that publishes an input envelope on the CPU backend"
        )),
    }
}

/// The tier `Machine::prove` would pick for a call of `program` over `inputs` with a public
/// segment of `public_segment_words` words — without proving. Under `hardening_v6` that is the
/// program's public input plus [`TX_BINDING_WORDS`] (`program::hardened_call_segment`). What a wallet needs *before* it
/// proves a call under genesis `hardening_v6` (INT-4): the call proof commits to
/// `Transaction::call_binding`, which covers the fee bundle, and the fee follows the tier, so the
/// tier has to be known first. The run uses a zero segment of that length (the binding is not
/// known yet); a guest that branches on its public words could land elsewhere with the real ones,
/// and [`prove_call_hardened`] then fails at the pinned tier rather than proving a different one.
pub fn call_tier(program: &Program, inputs: &[u32], public_segment_words: usize) -> Result<u8, String> {
    let public = vec![0u32; public_segment_words];
    let exec = crate::emulator::execute(program, inputs, &public, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(|e| format!("{e:?}"))?;
    let digests = program.digest_rows() + crate::hash::input_digest_row_count(inputs.len()) + crate::hash::public_digest_row_count(public.len());
    let absorb_rows = exec.events.iter().filter(|e| matches!(e.hash_row, Some(crate::emulator::HashRow::Absorb { .. }))).count();
    Tier::for_workload(exec.cycles() + digests, digests + absorb_rows)
        .map(|t| t.0 as u8)
        .ok_or_else(|| format!("no tier holds {} cycles", exec.cycles() + digests))
}

/// A fresh `H_IN` salt from OS entropy — the draw [`prove_call`] makes internally, for a caller
/// that has to hold the salt before proving ([`prove_call_hardened`]: the envelope sealed against
/// it is inside the call binding the proof commits to).
pub fn fresh_call_salt() -> [u32; 4] {
    use rand::RngExt;
    rand::rng().random()
}

/// The call prover for a chain whose genesis sets `hardening_v6` (INT-4): [`prove_call`]'s proof,
/// but the public segment is the program's public input followed by `binding` —
/// `Transaction::call_binding` of the transaction the call will ride in, built with both proofs
/// empty (`program::hardened_call_segment`) — so the chain can refuse a copy of the proof under
/// any other fee bundle (`ZkExecutor::verify_call_hardened`). Before issue #55 a program with a
/// public input proved over it alone, and its calls were unbound.
///
/// `salt` is the `H_IN` salt, drawn by the caller: the call-input envelope is sealed against
/// `hash::input_digest(salt, inputs)` and sits inside the binding, so the wallet seals it before
/// this proof exists (the salt's freshness is the caller's duty, exactly as `prove_call`'s doc
/// comment states it). `tier` pins the tier the fee was computed for ([`call_tier`]). CPU only,
/// for `prove_call`'s reason. Returns (proof bytes, outputs, tier).
#[allow(clippy::too_many_arguments)]
pub fn prove_call_hardened(
    profile: FriProfile,
    program: &Program,
    inputs: &[u32],
    public: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    salt: [u32; 4],
    tier: Option<u8>,
) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let segment = &randprotocol_core::program::hardened_call_segment(public, binding)[..];
    // `Machine::prove_salted`'s body, from its public parts, with one difference: the program
    // table is floored at `MIN_PRIVATE_TABLE_LOG_HEIGHT` (PROGRAM-TABLE-LEAK,
    // [`hardened_program_log_height`]). A taller program table than the program needs is sound —
    // its extra rows are padding the AIR already allows (`tables::program::program_log_height`'s
    // doc comment) — so only the declared height and the trace change, and the proof commits to
    // the same `hc`.
    let exec = crate::emulator::execute(program, inputs, segment, Tier(*TIERS.last().unwrap()).max_cycles()).map_err(|e| format!("{e:?}"))?;
    let tier = match tier {
        Some(t) if TIERS.contains(&(t as usize)) => Tier(t as usize),
        Some(t) => return Err(format!("tier {t} is not one of {TIERS:?}")),
        None => Tier(call_tier(program, inputs, segment.len())? as usize),
    };
    let mut traces = crate::machine::build_traces_salted(program, inputs, segment, salt, &exec, tier).map_err(|e| format!("{e:?}"))?;
    let floored = hardened_program_log_height(program.words.len());
    if traces.program_log_height < floored {
        traces.program = crate::tables::program::program_trace(program, &exec.events, 1usize << floored);
        traces.program_log_height = floored;
    }
    let proof = Machine::new(profile).prove_traces(program, &traces, tier);
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

/// PROGRAM-TABLE-LEAK (the INT-1 family's open member, 2026-09-27 zkVM/ISA review): the program
/// table height a call declares under genesis `hardening_v6` — the program's own
/// (`tables::program::program_log_height`), floored at [`MIN_PRIVATE_TABLE_LOG_HEIGHT`].
///
/// The program table carries each instruction's fetch count (`MULT`), i.e. the call's control
/// flow, and like every committed table it is hiding only while it has more random rows than the
/// proof opens of it (80 FRI queries plus two out-of-domain points). The input, keccak and sha256
/// tables are floored at 2^7 by the prover already (COV-2 / INT-6); the program table was not,
/// because the chain pins its height to the deployed record's — so every program under 64 words
/// (all 105 on chain 15 are 43) proves at 16 to 64 rows and publishes its fetch counts. Flooring it
/// changes what the chain pins, so it waits for the cut: the hardened prover
/// ([`prove_call_hardened`]) declares this height and `verify_call_hardened` pins exactly it;
/// without the flag both keep the record's own height. Since constraint set 7 (v0.6.1)
/// `program_log_height` is itself floored at 2^7 upstream, so this equals it for every length;
/// kept as the name the hardened rule reads.
pub fn hardened_program_log_height(len: usize) -> u8 {
    program::program_log_height(len).max(MIN_PRIVATE_TABLE_LOG_HEIGHT)
}

/// Wallet-side prover for a shielded bundle: proves the chain's bundle guest (the hidden-asset
/// guest, [`ZkExecutor::bundle_program`]) on `inputs` (built by `hidden::hidden_bundle_inputs`)
/// with `binding` as its public input segment, and returns (postcard proof bytes, the published
/// bundle digest, tier). The same as [`prove_hidden_bundle`].
///
/// `binding` is `Transaction::binding` of the transaction this bundle will ride in (Task 5b), so
/// the caller builds that transaction — every field but the proof — *before* proving. The chain
/// verifies against the binding it recomputes (`ZkExecutor::verify_bundle`), so a proof made for
/// any other transaction, or against the empty segment, is refused.
///
/// The tier is not chosen here — `Machine::prove_with` picks the smallest one the trace fits, and
/// the caller asserts what it got rather than pinning it, so a guest that grows past its tier is
/// a visible failure instead of a silent prove error. Like `prove`, every path this delegates to
/// draws a fresh per-proof `H_IN` salt from OS entropy internally; see `prove`'s doc comment for
/// why that must not be weakened.
///
/// A bundle whose witness violates the relation still *proves* — the guest taints its `bad` word
/// instead of failing — so a successful return here says nothing about admissibility. What it
/// yields is a digest the ledger can recompute from the bundle's published plaintext
/// (`ConfidentialExecutor::bundle_digest`); a tainted run's digest matches no such plaintext.
pub fn prove_bundle(
    profile: FriProfile,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    prove_hidden_bundle(profile, inputs, binding, backend)
}

/// `prove_bundle` for the hidden-asset bundle guest (`guests::bundle_hidden`): `inputs` built by
/// `hidden::hidden_bundle_inputs`, proved against the transaction's `binding`, returning (proof
/// bytes, the published digest, tier). Everything `prove_bundle`'s doc comment says holds here
/// too — the binding, the auto-picked tier (14 for every witness, honest or not: the worst case
/// is measured by `tests/hidden_bundle.rs`), the fresh `H_IN` salt, and that a tainted witness
/// still proves to a digest no plaintext matches.
pub fn prove_hidden_bundle(
    profile: FriProfile,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    prove_pinned_bundle(
        profile,
        ZkExecutor::hidden_bundle_program(),
        crate::hidden::hidden_input::COUNT,
        "hidden bundle",
        inputs,
        binding,
        backend,
    )
}

/// [`prove_bundle`] for the bundle guest a chain pins: `hc` is the chain's genesis `hc_bundle`
/// (`rand_status`'s `hc_bundle`), and the guest proved is [`ZkExecutor::bundle_program_for`] of
/// it — v1 on chains 14 and 15, the branch-free v2 on a genesis that names it. Both read the same
/// witness (`hidden::hidden_bundle_inputs`) and publish the same digest, so only the program
/// changes. v3 (split authorisation) reads its own, wider witness (`hidden::hidden_bundle_inputs_v3`,
/// [`ZkExecutor::bundle_input_words`]) and publishes `hidden::hidden_bundle_digest_v3`. An `hc` this build does not carry is refused before any proving: a proof of another
/// guest would publish the right digest and still be refused by every validator, a minute and a
/// half later.
pub fn prove_bundle_for(
    hc: &Word8,
    profile: FriProfile,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    let program = ZkExecutor::bundle_program_for(hc).ok_or_else(|| {
        format!(
            "this build cannot prove for the chain's bundle guest {}: it carries {}; update the wallet",
            randprotocol_core::notes::word8_to_hex(hc),
            ZkExecutor::known_hc_bundles().map(|h| randprotocol_core::notes::word8_to_hex(&h)).join(", ")
        )
    })?;
    prove_pinned_bundle(profile, program, ZkExecutor::bundle_input_words(hc), "hidden bundle", inputs, binding, backend)
}

/// The auth proof a wallet makes itself (split authorisation, spec
/// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): the auth guest over
/// `sk` and the per-transaction `salt` (256 fresh random bits — a repeated salt repeats `c` and
/// links two transactions; the wallet, not the guest, enforces freshness), proved against the
/// transaction's `binding`. Returns (proof bytes, the published `c`, tier) — `c` is
/// `auth::auth_commit(nk, salt)`, the bundle's `auth_commit`.
pub fn prove_auth(
    profile: FriProfile,
    sk: &crate::notes::SpendKey,
    salt: &Word8,
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    let inputs = crate::auth::auth_inputs(sk, salt);
    let m = Machine::new(profile);
    let (proof, exec) =
        m.prove_with(backend, ZkExecutor::auth_program(), &inputs, binding, None).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

fn prove_pinned_bundle(
    profile: FriProfile,
    program: &Program,
    input_words: usize,
    what: &str,
    inputs: &[u32],
    binding: &[u32; TX_BINDING_WORDS],
    backend: Backend,
) -> Result<(Vec<u8>, Word8, u8), String> {
    // The guest reads a fixed-width private-input vector; a shorter one makes the emulator read
    // past the end and a longer one silently ignores the tail, so neither is a prove request that
    // could ever produce an admissible bundle.
    if inputs.len() != input_words {
        return Err(format!("{what} inputs must be exactly {input_words} words, got {}", inputs.len()));
    }
    let m = Machine::new(profile);
    // The transaction binding as the public segment. The guest never reads it; the public
    // table's `PUBLIC_DIGEST` bus commits it into `H_PUB` regardless.
    let (proof, exec) = m.prove_with(backend, program, inputs, binding, None).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}

#[cfg(test)]
mod tests {
    /// The ledger mirrors this machine's public-value layout as `randprotocol_core::types::pv` (it
    /// cannot name a zkvm type — the dependency points this way). If a constraint-set change
    /// moves the real layout, this fails here, where both sides are visible, rather than
    /// silently desynchronising block-aggregation's admission checks.
    #[test]
    fn the_ledgers_pv_mirror_matches_the_real_layout() {
        use crate::tables::cpu::pv as real;
        use randprotocol_core::types::pv as mirror;
        assert_eq!(mirror::PC_ENTRY, real::PC_ENTRY);
        assert_eq!(mirror::TIER, real::TIER);
        assert_eq!(mirror::OUT0, real::OUT0);
        assert_eq!(mirror::HC0, real::HC0);
        assert_eq!(mirror::IN0, real::IN0);
        assert_eq!(mirror::PUB0, real::PUB0);
        assert_eq!(mirror::NUM, real::NUM);
    }

    /// ZKV-11: core's `program::program_table_rows` mirrors this crate's program-table padding
    /// (`1 << program_log_height(len)`), which core cannot call. Every length a deploy may carry
    /// (up to the 16-bit limit) and the edges past it; a re-vendor that moves the padding fails
    /// here, where both sides are visible, rather than letting the pc-window rule drift from the
    /// table the circuit builds.
    #[test]
    fn the_ledgers_program_table_rows_mirror_the_real_padding() {
        use crate::tables::program::program_log_height;
        for len in (0..=70_000usize).chain([1 << 20, (1 << 20) + 1]) {
            assert_eq!(
                randprotocol_core::program::program_table_rows(len),
                1u64 << program_log_height(len),
                "len {len}"
            );
        }
        // PCW-FLOOR: the window is taken over the floored table a hardened call declares, so the
        // floor core mirrors must be this crate's (`hardened_program_log_height`'s).
        assert_eq!(randprotocol_core::program::MIN_PRIVATE_TABLE_LOG_HEIGHT, super::MIN_PRIVATE_TABLE_LOG_HEIGHT);
        assert_eq!(super::MIN_PRIVATE_TABLE_LOG_HEIGHT, crate::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT);
        for len in [0usize, 15, 43, 127, 128, 129, 8_184] {
            assert_eq!(
                randprotocol_core::program::program_table_rows(len).max(1 << randprotocol_core::program::MIN_PRIVATE_TABLE_LOG_HEIGHT),
                1u64 << super::hardened_program_log_height(len),
                "len {len}"
            );
        }
        // The finding's shape: fib (15 words) at 0xffffffc4 passes ZH4 and not the window; at
        // 0xffffffc0 its 16 unfloored rows fit but the 128 floored ones do not (PCW-FLOOR).
        assert!(!randprotocol_core::program::pc_window_fits(0xffff_ffc4, 15));
        assert!(!randprotocol_core::program::pc_window_fits(0xffff_ffc0, 15));
        assert!(randprotocol_core::program::pc_window_fits(0xffff_fe00, 15));
    }

    /// PCW-FLOOR (the v0.6 rescan), on real proofs: the window and the hardened prover agree at the
    /// window's edge. Fib at `0xffffffc0` — admitted by the old, unfloored window — declares a
    /// 128-row program table under `hardening_v6` whose padding PCs cross 2^32, and its proof is
    /// refused (the rescan's reproduction: `OodEvaluationMismatch`); the window now refuses the
    /// deploy. At `2^32 − 512`, the highest start the window admits, the hardened call proves and
    /// verifies. Tier 10, the test profile.
    #[test]
    fn pcw_floor_the_window_and_the_hardened_prover_agree_at_the_edge() {
        use super::*;
        use crate::machine::FriProfile;
        let fib = crate::guests::fib(10);
        let zk = ZkExecutor::new(FriProfile::Test);
        let binding = [9u32; TX_BINDING_WORDS];
        let hardened = |base_pc: u32| {
            let program = crate::isa::Program::new(base_pc, fib.words.clone());
            let record = ProgramRecord {
                id: randprotocol_core::program::program_id(base_pc, &program.words),
                base_pc,
                words: program.words.clone(),
                code_hash: zk.check_program(base_pc, &program.words).unwrap(),
                deployed_at: 0,
                public_digest: None,
                public_len: 0,
            };
            let proved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_call_hardened(FriProfile::Test, &program, &[], &[], &binding, [0; 4], Some(10))
            }));
            match proved {
                Ok(Ok((bytes, _, _))) => zk.verify_call_hardened(&record, &bytes, &binding).map(|_| ()).map_err(|e| format!("{e:?}")),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("prove panicked".into()),
            }
        };
        let edge = 0xffff_fe00u32;
        assert!(randprotocol_core::program::pc_window_fits(edge, fib.words.len()));
        assert_eq!(hardened(edge), Ok(()), "the highest start the window admits proves and verifies");
        assert!(!randprotocol_core::program::pc_window_fits(0xffff_ffc0, fib.words.len()));
        assert!(hardened(0xffff_ffc0).is_err(), "past it the floored table crosses the wrap");
    }

    /// CPU-1: `max_callable_program_words` is the prover's own limit, not a restatement of it.
    /// One word either side of the bound, at `MAX_CALL_TIER`, against `build_traces_salted` —
    /// the function `Machine::prove` runs, which counts the same three digests and refuses with
    /// `TooManyPoseidon2Permutations`: 8 184 words (8 182 nops and the two-instruction halt)
    /// build, 8 185 do not; with a 9-word public segment the bound drops by eight words (three
    /// header-and-word slots for one). The shipped EVM and sBPF interpreter guests are past it —
    /// the report's finding — and the core stub restates the same numbers.
    #[test]
    fn cpu1_the_callable_program_bound_is_the_provers_own_limit() {
        use super::*;
        use crate::machine::{build_traces_salted, ProveError};
        let halting = |n: usize| {
            let halt: Vec<u32> = crate::asm::ops::halt().iter().map(|i| i.encode()).collect();
            let mut words = vec![crate::asm::ops::addi(0, 0, 0).encode(); n - halt.len()];
            words.extend(halt);
            Program::new(0, words)
        };
        let tier = Tier(MAX_CALL_TIER as usize);
        let fits = |n: usize, public: &[u32]| {
            let p = halting(n);
            let exec = crate::emulator::execute(&p, &[], public, tier.max_cycles()).expect("halts");
            match build_traces_salted(&p, &[], public, [0; 4], &exec, tier) {
                Ok(_) => true,
                Err(ProveError::TooManyPoseidon2Permutations { .. }) => false,
                Err(e) => panic!("{n} words: {e:?}"),
            }
        };
        assert_eq!(max_callable_program_words(0), 8184, "4 · (2^(14-3) − 1 − 1)");
        assert!(fits(8184, &[]), "the bound itself proves");
        assert!(!fits(8185, &[]), "one word more does not");
        let public = [5u32; 9];
        assert_eq!(max_callable_program_words(public.len()), 8176);
        assert!(fits(8176, &public));
        assert!(!fits(8177, &public));
        assert!(crate::guests::compiled::evm().words.len() > max_callable_program_words(0), "the EVM interpreter");
        assert!(crate::guests::compiled::sbpf().words.len() > max_callable_program_words(0), "the sBPF interpreter");
        for n in [0, 1, 4, 5, 8, 9, 100, 32_768] {
            assert_eq!(
                randprotocol_core::confidential::StubExecutor.max_callable_program_words(n),
                Some(max_callable_program_words(n)),
                "the stub's restatement, public {n}"
            );
        }
    }

    /// INT-5 residual (issue #56): a call proof carrying a keccak or sha256 table was only ranged
    /// (`t + 2 ≤ mem ≤ MAX_MEM_LOG_HEIGHT`, 24), so its prover could declare any of up to a dozen
    /// memory heights for one statement. The honest height is data-dependent — the access count,
    /// not the declared shape, decides it — so it cannot be pinned from the header; but the shape
    /// bounds it: [`hash_bearing_mem_log_height_ceiling`]. Above that ceiling no honest prover
    /// declares, and the proof is non-canonical; every honest hash-bearing proof here is at or
    /// under it, including traces built for workloads that pack a tier with hash calls.
    #[test]
    fn int5_a_hash_bearing_calls_memory_height_is_capped_by_its_declared_shape() {
        use super::*;
        use crate::machine::{Backend, FriProfile, MAX_MEM_LOG_HEIGHT};
        for (what, program) in [("keccak", crate::guests::keccak_demo(b"abc")), ("sha256", crate::guests::sha256_demo())] {
            let (bytes, _, _) = prove(FriProfile::Test, &program, &[], &[], None, Backend::Cpu).unwrap();
            let honest = decode_canonical(&bytes).unwrap();
            assert!(honest.keccak_log_height != NO_KECCAK || honest.sha256_log_height != NO_SHA256, "{what} declares a hash table");
            assert_eq!(non_canonical(&honest), None, "{what}: the honest proof is canonical");
            let mut tall = decode_canonical(&bytes).unwrap();
            tall.mem_log_height = MAX_MEM_LOG_HEIGHT;
            assert!(
                non_canonical(&tall).is_some_and(|w| w.starts_with("memory height")),
                "{what}: a memory height of {MAX_MEM_LOG_HEIGHT} (honest {}) is canonical: {:?}",
                honest.mem_log_height,
                non_canonical(&tall)
            );
            let ceiling = hash_bearing_mem_log_height_ceiling(honest.tier, honest.keccak_log_height, honest.sha256_log_height);
            let mut top = decode_canonical(&bytes).unwrap();
            top.mem_log_height = ceiling;
            assert!(
                non_canonical(&top).is_none_or(|w| !w.starts_with("memory height")),
                "{what}: the ceiling itself ({ceiling}) is admitted"
            );
        }
        // The ceiling is an upper bound on what the prover declares, at the far end too: a tier
        // packed with hash calls (a three-cycle loop around the ecall, up to every cycle the tier
        // has) builds traces at or under it.
        use crate::asm::ops::{addi, ecall, halt, li};
        use crate::isa::{BranchCond, REG_A0, REG_A7, SYS_KECCAK, SYS_SHA256};
        use crate::machine::{build_traces_salted, Tier};
        const COUNTER: u32 = 5;
        for tier in [Tier(10), Tier(12)] {
            for (what, sys) in [("keccak", SYS_KECCAK), ("sha256", SYS_SHA256)] {
                for fill in [1usize, 2, 3, 4] {
                    let calls = (tier.max_cycles() - 16) * fill / 4 / 3;
                    let mut a = crate::asm::Assembler::new(0);
                    a.extend(li(REG_A7, sys as i32));
                    a.extend(li(REG_A0, 0x10_0000 / 4));
                    a.extend(li(COUNTER, calls as i32));
                    a.label("again");
                    a.push(ecall());
                    a.push(addi(COUNTER, COUNTER, -1));
                    a.branch(BranchCond::Ne, COUNTER, 0, "again");
                    a.extend(halt());
                    let p = a.assemble();
                    let exec = crate::emulator::execute(&p, &[], &[], tier.max_cycles()).expect("halts");
                    let traces = build_traces_salted(&p, &[], &[], [0; 4], &exec, tier).expect("fits the tier");
                    let ceiling = hash_bearing_mem_log_height_ceiling(tier, traces.keccak_log_height, traces.sha256_log_height);
                    assert!(
                        traces.mem_log_height <= ceiling,
                        "tier {}, {calls} {what} calls: the prover declares {} above the ceiling {ceiling}",
                        tier.0,
                        traces.mem_log_height
                    );
                }
            }
        }
    }

    /// VERIFIER-2 / V-VERIFIER-1: the FRI folding schedule and the hiding PCS's random-value
    /// counts are pinned to the honest prover's. The schedule is re-derived from the declared
    /// shape alone (`honest_fri_arities`) and matches every honest proof here — calls at tiers
    /// 10, 12 and 14 and a (tainted, so any-witness) hidden-asset bundle — while a proof whose
    /// schedule is permuted, or whose random-value count is padded, is named non-canonical. None
    /// of these mutants need to verify: the rule reads the transcript's shape only.
    #[test]
    fn verifier2_the_fri_schedule_and_random_counts_are_the_honest_provers() {
        use super::*;
        use crate::machine::{Backend, FriProfile};
        let payment = crate::guests::private_payment(1000);
        let (base, _, _) = prove(FriProfile::Test, &payment, &[400, 250, 300, 75], &[], None, Backend::Cpu).unwrap();
        // The mutants first (cheap: one tier-10 proof), the sweep of honest shapes after.
        // The same arities in another order: the same total fold, a different transcript.
        let mut swapped = decode_canonical(&base).unwrap();
        let steps = &mut swapped.batch.opening_proof.1.commit_phase_openings;
        let (i, j) = (0..steps.len()).flat_map(|i| (i + 1..steps.len()).map(move |j| (i, j))).find(|&(i, j)| steps[i].log_arity != steps[j].log_arity).unwrap();
        let (a, b) = (steps[i].log_arity, steps[j].log_arity);
        (steps[i].log_arity, steps[j].log_arity) = (b, a);
        assert!(non_canonical(&swapped).is_some_and(|w| w.starts_with("FRI folding schedule")), "a permuted schedule");
        // One random value too many on one opening point.
        let mut padded = decode_canonical(&base).unwrap();
        padded.batch.opening_proof.0[0][0][0].push(Default::default());
        assert!(non_canonical(&padded).is_some_and(|w| w.starts_with("random-codeword")), "a padded random opening");
        let mut honest: Vec<(String, Vec<u8>)> = vec![("call at tier 10".into(), base)];
        for tier in [Some(12), Some(14)] {
            let (bytes, _, t) = prove(FriProfile::Test, &payment, &[400, 250, 300, 75], &[], tier, Backend::Cpu).unwrap();
            honest.push((format!("call at tier {t}"), bytes));
        }
        let (fib, _, _) = prove(FriProfile::Test, &crate::guests::fib(10), &[], &[], None, Backend::Cpu).unwrap();
        honest.push(("fib".into(), fib));
        let (bundle, _, _) =
            prove_hidden_bundle(FriProfile::Test, &vec![0; crate::hidden::hidden_input::COUNT], &[7; TX_BINDING_WORDS], Backend::Cpu).unwrap();
        honest.push(("bundle".into(), bundle));
        for (what, bytes) in &honest {
            let p = decode_canonical(bytes).unwrap();
            let got: Vec<u8> = p.batch.opening_proof.1.commit_phase_openings.iter().map(|o| o.log_arity).collect();
            assert_eq!(Some(got), honest_fri_arities(&p), "{what}: the derived schedule is the prover's");
            assert_eq!(non_canonical(&p), None, "{what}: honest is canonical");
        }
        assert_eq!(non_canonical_proof(&padded.to_bytes()), non_canonical(&padded), "the byte form reads the same");
    }

    /// VERIFIER-1: the FRI commit-phase proof-of-work words were read and dropped — the chain's
    /// FRI parameters grind 0 bits there, and `check_witness(0, _)` is `true` for any word — so
    /// anyone relaying a call or a bundle could rewrite one and hold a second valid encoding with
    /// another transaction id. This test first pinned the finding (the rewritten proof verified,
    /// and only the node's canonical check named it); since the circuits `36f07bb` re-vendor,
    /// `Machine::verify` refuses a non-zero word itself, unconditionally
    /// (`VerifyError::CommitPowWitness`), so it now pins the fix on a real call: the rewritten
    /// proof is refused by the verifier against the deployed program, and the node's canonical
    /// check refuses it too — two independent refusals, the pool's before any key is built. The
    /// honest prover writes zero and passes both. (TEST-1, the v0.6 rescan: the stale assertion
    /// was red at 06e688d.)
    #[test]
    fn verifier1_a_rewritten_commit_pow_word_is_refused_by_verify_and_is_non_canonical() {
        use super::*;
        use crate::machine::{Backend, FriProfile, Val};
        use p3_field::PrimeCharacteristicRing;
        let program = crate::guests::private_payment(1000);
        let (bytes, _, _) = prove(FriProfile::Test, &program, &[400, 250, 300, 75], &[], None, Backend::Cpu).unwrap();
        let honest = decode_canonical(&bytes).unwrap();
        assert!(honest.batch.opening_proof.1.commit_pow_witnesses.iter().all(|w| *w == Val::ZERO), "the honest prover grinds 0 bits to zero");
        let zk = ZkExecutor::new(FriProfile::Test);
        let record = ProgramRecord {
            id: randprotocol_core::program::program_id(program.base_pc, &program.words),
            base_pc: program.base_pc,
            words: program.words.clone(),
            code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
            deployed_at: 0,
            public_digest: None,
            public_len: 0,
        };
        let mut rewritten = decode_canonical(&bytes).unwrap();
        rewritten.batch.opening_proof.1.commit_pow_witnesses[0] = Val::from_u64(0xdead_beef);
        let rewritten = rewritten.to_bytes();
        assert_ne!(rewritten, bytes, "another encoding, so another transaction id");
        assert_eq!(
            zk.verify_call(&record, &rewritten),
            Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::CommitPowWitness { round: 0 }))),
            "the fix: Machine::verify refuses the rewritten word"
        );
        assert!(zk.verify_call(&record, &bytes).is_ok(), "the honest encoding verifies");
        assert_eq!(non_canonical_proof(&bytes), None);
        assert!(
            non_canonical_proof(&rewritten).is_some_and(|w| w.starts_with("FRI commit-phase proof-of-work word")),
            "{:?}",
            non_canonical_proof(&rewritten)
        );
    }

    /// INT-4 on the real executor: a call proved with the call binding as its public segment
    /// verifies under `verify_call_hardened` with that binding and no other; the old rule refuses
    /// it, and the hardened rule refuses today's unbound proof. `call_tier` predicts the tier the
    /// prover lands on.
    #[test]
    fn int4_a_bound_call_verifies_under_its_own_binding_only() {
        use super::*;
        use crate::machine::{Backend, FriProfile};
        let program = crate::guests::private_payment(1000);
        let inputs = [400, 250, 300, 75];
        let zk = ZkExecutor::new(FriProfile::Test);
        let record = ProgramRecord {
            id: randprotocol_core::program::program_id(program.base_pc, &program.words),
            base_pc: program.base_pc,
            words: program.words.clone(),
            code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
            deployed_at: 0,
            public_digest: None,
            public_len: 0,
        };
        let binding = [3u32, 1, 4, 1, 5, 9, 2, 6];
        let tier = call_tier(&program, &inputs, TX_BINDING_WORDS).unwrap();
        let (bound, outputs, t) = prove_call_hardened(FriProfile::Test, &program, &inputs, &[], &binding, [1, 2, 3, 4], Some(tier)).unwrap();
        assert_eq!(t, tier, "the wallet's tier is the prover's");
        let outcome = zk.verify_call_hardened(&record, &bound, &binding).expect("its own binding");
        assert_eq!(outcome.outputs, outputs);
        assert_eq!(zk.decode_call_hardened(&record, &bound, &binding), Ok(outcome), "the decode path agrees");
        let public_values = ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues));
        let mut other = binding;
        other[0] ^= 1;
        assert_eq!(zk.verify_call_hardened(&record, &bound, &other), Err(public_values.clone()), "another transaction's binding");
        assert_eq!(zk.decode_call_hardened(&record, &bound, &other), Err(public_values));
        // The old rule refuses it too — on its floored program table first (PROGRAM-TABLE-LEAK:
        // private_payment is under 64 words), and on the segment behind that.
        assert!(zk.verify_call(&record, &bound).is_err(), "the old rule wants the empty segment and the record's height");
        let (unbound, _, _) = prove(FriProfile::Test, &program, &inputs, &[], None, Backend::Cpu).unwrap();
        // Today's proof under the flag: refused on its record-height program table before the
        // segment is even compared (private_payment is under 64 words).
        assert!(zk.verify_call_hardened(&record, &unbound, &binding).is_err(), "today's proof under the flag");
        assert!(zk.verify_call(&record, &unbound).is_ok());
    }

    /// Issue #55 (INT-4's residual) on the real executor: a program deployed with a public input
    /// is bound too — the hardened prover proves over `public ‖ binding`, which verifies under
    /// that segment and refuses another transaction's binding, the public input alone (the copy
    /// the old hardened rule let through), and the binding alone.
    #[test]
    fn int4_a_call_to_a_program_with_a_public_input_is_bound_too() {
        use super::*;
        use crate::machine::FriProfile;
        let program = crate::guests::private_payment(1000);
        let inputs = [400, 250, 300, 75];
        let public = [7u32, 8, 9];
        let zk = ZkExecutor::new(FriProfile::Test);
        let record = ProgramRecord {
            id: randprotocol_core::program::program_id_with_public(program.base_pc, &program.words, &public),
            base_pc: program.base_pc,
            words: program.words.clone(),
            code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
            deployed_at: 0,
            public_digest: Some(crate::hash::public_digest(&public)),
            public_len: public.len() as u32,
        };
        let binding = [3u32, 1, 4, 1, 5, 9, 2, 6];
        let segment = randprotocol_core::program::hardened_call_segment(&public, &binding);
        let tier = call_tier(&program, &inputs, segment.len()).unwrap();
        let (bound, outputs, _) = prove_call_hardened(FriProfile::Test, &program, &inputs, &public, &binding, [1, 2, 3, 4], Some(tier)).unwrap();
        let outcome = zk.verify_call_hardened(&record, &bound, &segment).expect("public ‖ its own binding");
        assert_eq!(outcome.outputs, outputs);
        assert_eq!(zk.decode_call_hardened(&record, &bound, &segment), Ok(outcome), "the decode path agrees");
        let public_values = Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        let mut other = binding;
        other[0] ^= 1;
        let lifted = randprotocol_core::program::hardened_call_segment(&public, &other);
        assert_eq!(zk.verify_call_hardened(&record, &bound, &lifted), public_values, "another transaction's binding");
        assert_eq!(zk.verify_call_hardened(&record, &bound, &public), public_values, "the public input alone");
        assert_eq!(zk.verify_call_hardened(&record, &bound, &binding), public_values, "the binding alone");
    }

    /// PROGRAM-TABLE-LEAK (the INT-1 family's open member): a call's program table was as tall as
    /// its program needed — 16 rows for fib's 15 words, 64 for every 43-word program on chain 15 —
    /// and a table under 2^7 rows is opened at more points than it has random rows, so its fetch
    /// counts (the control flow) read off the proof. v0.6 floored it on this side under
    /// `hardening_v6` (the hardened prover declared `max(record height, 7)` and the executor pinned
    /// exactly that). Constraint set 7 floors every declared table upstream, so
    /// `program_log_height` itself is the floor for such a program: the vendored prover and the
    /// hardened one declare the same height, both rules pin it, and what separates them is only
    /// the public segment (the binding, INT-4).
    #[test]
    fn program_table_leak_the_hardened_call_floors_the_program_table() {
        use super::*;
        use crate::machine::FriProfile;
        let program = crate::guests::fib(10);
        assert!(program.words.len() + 1 < 1 << MIN_PRIVATE_TABLE_LOG_HEIGHT, "a program the leak reaches");
        assert_eq!(program::program_log_height(program.words.len()), MIN_PRIVATE_TABLE_LOG_HEIGHT, "cs7: the floor is upstream's");
        assert_eq!(hardened_program_log_height(program.words.len()), MIN_PRIVATE_TABLE_LOG_HEIGHT);
        let zk = ZkExecutor::new(FriProfile::Test);
        let record = ProgramRecord {
            id: randprotocol_core::program::program_id(program.base_pc, &program.words),
            base_pc: program.base_pc,
            words: program.words.clone(),
            code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
            deployed_at: 0,
            public_digest: None,
            public_len: 0,
        };
        let binding = [9u32; TX_BINDING_WORDS];
        let (bytes, _, _) = prove_call_hardened(FriProfile::Test, &program, &[], &[], &binding, [0; 4], None).unwrap();
        let proof = decode_canonical(&bytes).unwrap();
        assert_eq!(proof.program_log_height, MIN_PRIVATE_TABLE_LOG_HEIGHT, "the hardened prover floors the program table");
        assert!(zk.verify_call_hardened(&record, &bytes, &binding).is_ok(), "and the hardened rule accepts it");
        assert_eq!(non_canonical_proof(&bytes), None, "a floored proof is canonical");
        // The old rule pins the same height now; it refuses the proof on its segment, not its height.
        let public_values = Err(ConfidentialError::InvalidProof(format!("{:?}", crate::machine::VerifyError::PublicValues)));
        assert_eq!(zk.verify_call(&record, &bytes), public_values, "the old rule checks the empty segment");
        // The vendored prover over the same segment declares the floored height as well, and the
        // hardened rule accepts its proof.
        let (vendored, _) = Machine::new(FriProfile::Test).prove_salted(&program, &[], &binding, [0; 4], None).unwrap();
        assert_eq!(vendored.program_log_height, MIN_PRIVATE_TABLE_LOG_HEIGHT);
        assert!(zk.verify_call_hardened(&record, &vendored.to_bytes(), &binding).is_ok());
    }

    /// ZKG-1: an output word past 32 bits is refused, never narrowed. `x as u32` of
    /// `2^32 + w` is `w`, so a truncating read would hand back exactly the digest a proof
    /// publishing `w` does — the pruned path (`Ledger::check_bundle_proof`) already refuses the
    /// same record with `BadDigest`.
    #[test]
    fn a_published_output_word_past_32_bits_is_refused_not_truncated() {
        use super::*;
        let mut pvs = vec![0u64; pv::NUM];
        for k in 0..8 {
            pvs[pv::OUT0 + k] = 7 + k as u64;
        }
        let honest = published_digest(&pvs).expect("u32 words");
        assert_eq!(honest, std::array::from_fn(|k| 7 + k as u32));
        pvs[pv::OUT0 + 3] += 1 << 32;
        let got = published_digest(&pvs);
        assert!(
            matches!(got, Err(ConfidentialError::MalformedProof)),
            "a word past u32 read as {got:?}, the honest digest {honest:?}"
        );
        pvs.truncate(pv::OUT0 + 4);
        assert!(matches!(published_digest(&pvs), Err(ConfidentialError::MalformedProof)), "a short vector is refused too");
    }

    /// Split authorisation: the trait's v3 digest is bundle guest v3's own
    /// (`hidden::hidden_bundle_digest_v3` over the core record, `auth_commit` included), the v1
    /// digest ignores `auth_commit`, and `hc_auth` is the auth guest's digest.
    #[test]
    fn the_v3_digest_and_hc_auth_are_the_guests() {
        use super::*;
        let input = BundleDigestInput {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
            commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
            fee: 10,
            burn_a: 11,
            burn_r: 12,
            burn_asset: 13,
            time: 14,
            auth_commit: [15; 8],
        };
        let ex = ZkExecutor::new(FriProfile::Test);
        let want = crate::hidden::hidden_bundle_digest_v3(&crate::hidden::HiddenDigestInputV3 {
            base: hidden_digest_input(&input),
            auth_commit: [15; 8],
        });
        assert_eq!(ex.bundle_digest_v3(&input), want);
        let mut other = input;
        other.auth_commit[0] ^= 1;
        assert_ne!(ex.bundle_digest_v3(&other), want);
        assert_eq!(ex.bundle_digest(&other), ex.bundle_digest(&input), "v1 does not read auth_commit");
        assert_ne!(ex.bundle_digest(&input), want);
        assert_eq!(ZkExecutor::hc_auth(), crate::guests::auth().digest());
        assert!(!ZkExecutor::known_hc_bundles().contains(&ZkExecutor::hc_auth()), "not a bundle guest");
        assert_eq!(ZkExecutor::auth_heights().2, public::public_log_height(TX_BINDING_WORDS));
        // Junk is refused by the cheap reader, never read as a `c`.
        assert_eq!(ex.auth_proof_digest(b"junk"), Err(ConfidentialError::MalformedProof));
        assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), b"junk", &[0; 8]), Err(ConfidentialError::MalformedProof));
    }
}
