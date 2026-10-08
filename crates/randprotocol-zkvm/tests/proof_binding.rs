//! What one honest proof binds, probed by editing its header after the fact: every public
//! value the circuit pins (outputs, H_IN, H_PUB, the entry pc, the gas limit), every refusal
//! `verify` makes before building a key (hc, count, canonical encoding, tier echo, the pc
//! window, the commit-phase PoW words), the proof's one byte encoding, and — since the ledger's
//! admission checks need only a proof *shape* to be refused by — `Ledger::apply`/`apply_bundle`'s
//! cheapest-first order and the anchor window, all against the same proof.
//!
//! One tier-10 `fib(20)` proof (`common::fib_proof_tier_10`) is shared by every test here; each
//! test edits `public_values` (or a header field) and restores it. `Proof` is not `Clone`, so the
//! fixture lives behind a mutex and the tests run one at a time.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{check_public_values, FriProfile, Machine, Proof, Tier, Val, VerifyError};
use randprotocol_zkvm::tables::cpu::pv;
use std::sync::{Mutex, MutexGuard, OnceLock};

static FIXTURE: OnceLock<Mutex<(Program, Proof)>> = OnceLock::new();

fn fixture() -> MutexGuard<'static, (Program, Proof)> {
    FIXTURE.get_or_init(|| Mutex::new(common::fib_proof_tier_10())).lock().unwrap_or_else(|e| e.into_inner())
}

fn machine() -> Machine { Machine::new(FriProfile::Test) }

fn is_batch(e: &Result<(), VerifyError>) -> bool { matches!(e, Err(VerifyError::Batch(_))) }

/// Runs `f` with the public values edited, then restores them.
fn with_edit<R>(g: &mut (Program, Proof), edit: impl FnOnce(&mut Vec<u64>), f: impl FnOnce(&Program, &Proof) -> R) -> R {
    let saved = g.1.public_values.clone();
    edit(&mut g.1.public_values);
    let r = f(&g.0, &g.1);
    g.1.public_values = saved;
    r
}

// ─────────────────────────── bound in-circuit ───────────────────────────

#[test]
fn the_honest_proof_verifies_and_every_output_slot_is_bound_by_the_batch() {
    let mut g = fixture();
    let m = machine();
    assert_eq!(m.verify(&g.0.digest(), &g.1), Ok(()));
    assert_eq!(g.1.public_values[pv::OUT0], 6765, "fib(20)");
    for slot in 0..8 {
        let got = with_edit(&mut g, |p| p[pv::OUT0 + slot] += 1, |prog, proof| m.verify(&prog.digest(), proof));
        assert!(is_batch(&got), "slot {slot}: {got:?} — the cheap checks pass, the batch refuses");
    }
    assert_eq!(m.verify(&g.0.digest(), &g.1), Ok(()), "restored");
}

#[test]
fn the_input_and_public_digests_the_entry_pc_and_the_gas_limit_are_bound_by_the_batch() {
    let mut g = fixture();
    let m = machine();
    for (name, idx) in [("H_IN word 0", pv::IN0), ("H_IN word 7", pv::IN0 + 7), ("H_PUB word 0", pv::PUB0), ("H_PUB word 7", pv::PUB0 + 7), ("PC_ENTRY", pv::PC_ENTRY)] {
        let got = with_edit(&mut g, |p| p[idx] ^= 1, |prog, proof| m.verify(&prog.digest(), proof));
        assert!(is_batch(&got), "{name}: {got:?}");
    }
    // The declared limit is the header ceiling, so one less is still an admissible header, and
    // the HALT row's slack limbs no longer add up: refused by the batch, not by `GasLimit`.
    let got = with_edit(&mut g, |p| p[pv::GAS] -= 1, |prog, proof| m.verify(&prog.digest(), proof));
    assert!(is_batch(&got), "{got:?}");
    let got = with_edit(&mut g, |p| p[pv::GAS] += 1, |prog, proof| m.verify(&prog.digest(), proof));
    assert_eq!(got, Err(VerifyError::GasLimit));
    // `verify_public` over the empty segment accepts the honest proof and refuses a forged H_PUB
    // through the batch before it ever compares the words.
    assert_eq!(m.verify_public(&g.0.digest(), &[], &g.1), Ok(()));
    assert_eq!(m.verify_public(&g.0.digest(), &[1], &g.1), Err(VerifyError::PublicValues), "the wrong words");
    let got = with_edit(&mut g, |p| p[pv::PUB0] ^= 1, |prog, proof| m.verify_public(&prog.digest(), &[], proof));
    assert!(is_batch(&got), "{got:?}");
}

// ─────────────────────────── refused before any key ───────────────────────────

#[test]
fn a_wrong_hc_in_any_word_is_a_public_value_error_before_a_key_is_built() {
    let g = fixture();
    let hc = g.0.digest();
    for i in 0..8 {
        let mut bad = hc;
        bad[i] ^= 1;
        assert_eq!(check_public_values(&bad, &g.1), Err(VerifyError::PublicValues), "word {i}");
        let fresh = machine();
        assert_eq!(fresh.verify(&bad, &g.1), Err(VerifyError::PublicValues));
        assert_eq!(fresh.cached_keys(), 0, "word {i}: no key was built");
    }
    let other = randprotocol_zkvm::guests::fib(21).digest();
    assert_eq!(machine().verify(&other, &g.1), Err(VerifyError::PublicValues), "another program's hc");
}

#[test]
fn the_public_value_count_and_canonical_encoding_are_checked_first() {
    let mut g = fixture();
    let m = machine();
    let hc = g.0.digest();
    assert_eq!(pv::NUM, 35);
    assert_eq!(with_edit(&mut g, |p| p.push(0), |_, proof| check_public_values(&hc, proof)), Err(VerifyError::PublicValues));
    assert_eq!(with_edit(&mut g, |p| { p.pop(); }, |_, proof| check_public_values(&hc, proof)), Err(VerifyError::PublicValues));
    assert_eq!(with_edit(&mut g, |p| p.clear(), |_, proof| check_public_values(&hc, proof)), Err(VerifyError::PublicValues));
    // `p` itself is the first non-canonical value; `p − 1` is canonical and only the batch can
    // say it is wrong.
    let p = Val::ORDER_U64;
    assert_eq!(with_edit(&mut g, |v| v[pv::IN0] = p, |_, proof| check_public_values(&hc, proof)), Err(VerifyError::PublicValues));
    assert_eq!(with_edit(&mut g, |v| v[pv::IN0] = u64::MAX, |_, proof| check_public_values(&hc, proof)), Err(VerifyError::PublicValues));
    assert_eq!(with_edit(&mut g, |v| v[pv::IN0] = p - 1, |_, proof| check_public_values(&hc, proof)), Ok(()));
    let got = with_edit(&mut g, |v| v[pv::IN0] = p - 1, |_, proof| m.verify(&hc, proof));
    assert!(is_batch(&got), "{got:?}");
    // An output of exactly 2^32 − 1 is a word; 2^32 is not.
    assert_eq!(with_edit(&mut g, |v| v[pv::OUT0 + 7] = u32::MAX as u64, |_, proof| check_public_values(&hc, proof)), Ok(()));
    assert_eq!(with_edit(&mut g, |v| v[pv::OUT0 + 7] = 1 << 32, |_, proof| check_public_values(&hc, proof)), Err(VerifyError::OutputNotU32 { slot: 7 }));
}

#[test]
fn the_tier_echo_and_a_relabelled_tier_are_refused_before_a_key_is_built() {
    let mut g = fixture();
    let hc = g.0.digest();
    assert_eq!(with_edit(&mut g, |v| v[pv::TIER] = 12, |_, proof| check_public_values(&hc, proof)), Err(VerifyError::Tier), "the echo disagrees with the header");
    // Header and echo both relabelled to tier 12: the cheap checks catch it — first the memory
    // table, declared at tier 10's floor (12) and now under tier 12's (14) …
    let (tier, mlh) = (g.1.tier, g.1.mem_log_height);
    assert_eq!((tier, mlh), (Tier(10), 12));
    g.1.tier = Tier(12);
    let got = with_edit(&mut g, |v| v[pv::TIER] = 12, |_, proof| { let m = machine(); let r = m.verify(&hc, proof); assert_eq!(m.cached_keys(), 0); r });
    assert_eq!(got, Err(VerifyError::MemoryHeight));
    // … and with that patched too, the batch's degree bits no longer match the declared shape.
    g.1.mem_log_height = 14;
    let got = with_edit(&mut g, |v| v[pv::TIER] = 12, |_, proof| { let m = machine(); let r = m.verify(&hc, proof); assert_eq!(m.cached_keys(), 0); r });
    assert_eq!(got, Err(VerifyError::Tier));
    g.1.tier = tier;
    g.1.mem_log_height = mlh;
    assert_eq!(machine().verify(&hc, &g.1), Ok(()), "restored");
}

#[test]
fn an_entry_pc_whose_program_table_would_cross_the_wrap_is_refused_by_name() {
    let mut g = fixture();
    let hc = g.0.digest();
    let plh = g.1.program_log_height;
    let table_bytes = 4u64 << plh;
    let got = with_edit(&mut g, |v| v[pv::PC_ENTRY] = (1 << 32) - table_bytes + 4, |_, proof| machine().verify(&hc, proof));
    assert_eq!(got, Err(VerifyError::PcWindow { entry_pc: (1 << 32) - table_bytes + 4, program_log_height: plh }));
    // Exactly at the wrap is admitted by the window check (and then refused by the batch).
    let got = with_edit(&mut g, |v| v[pv::PC_ENTRY] = (1 << 32) - table_bytes, |_, proof| machine().verify(&hc, proof));
    assert!(is_batch(&got), "{got:?}");
}

#[test]
fn a_rewritten_commit_phase_pow_word_is_refused_by_round() {
    let mut g = fixture();
    let hc = g.0.digest();
    let words = &mut g.1.batch.opening_proof.1.commit_pow_witnesses;
    assert!(!words.is_empty(), "tier 10 at the test profile folds at least once");
    assert!(words.iter().all(|w| *w == Val::ZERO), "the honest prover grinds zero bits");
    let last = words.len() - 1;
    for round in [0, last] {
        g.1.batch.opening_proof.1.commit_pow_witnesses[round] = Val::ONE;
        let m = machine();
        assert_eq!(m.verify(&hc, &g.1), Err(VerifyError::CommitPowWitness { round }));
        assert_eq!(m.cached_keys(), 0);
        g.1.batch.opening_proof.1.commit_pow_witnesses[round] = Val::ZERO;
    }
    assert_eq!(machine().verify(&hc, &g.1), Ok(()));
}

// ─────────────────────────── the byte encoding ───────────────────────────

#[test]
fn the_proof_round_trips_through_its_bytes_and_no_single_byte_edit_verifies() {
    let g = fixture();
    let hc = g.0.digest();
    let bytes = g.1.to_bytes();
    assert_eq!(g.1.size(), bytes.len());
    assert_eq!(bytes, g.1.to_bytes(), "serialisation is deterministic");
    let back: Proof = postcard::from_bytes(&bytes).expect("deserialises");
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!((back.tier, back.public_values.clone()), (g.1.tier, g.1.public_values.clone()));
    let m = machine();
    assert_eq!(m.verify(&hc, &back), Ok(()));
    for cut in [0usize, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(postcard::from_bytes::<Proof>(&bytes[..cut]).is_err(), "truncated to {cut} bytes");
    }
    // A flipped byte either fails to deserialise or produces a proof `verify` refuses.
    let n = bytes.len();
    for k in 0..16 {
        let i = k * (n - 1) / 15;
        let mut edited = bytes.clone();
        edited[i] ^= 0x01;
        if let Ok(p) = postcard::from_bytes::<Proof>(&edited) {
            assert!(m.verify(&hc, &p).is_err(), "byte {i} of {n}: a one-bit edit still verified");
        }
    }
}

// ─────────────────────────── the ledger's free checks ───────────────────────────

mod ledger_admission {
    use super::*;
    use randprotocol_zkvm::ledger::{Bundle, Ledger, LedgerError};
    use randprotocol_zkvm::notes::{self, domain, Note, SpendKey, ViewingKey, Word8};
    use randprotocol_zkvm::viewing::{Envelope, TxKey};

    struct Party { vk: ViewingKey }
    fn party() -> Party { Party { vk: SpendKey::random().viewing_key() } }
    fn w8(seed: u32) -> Word8 { notes::hash(domain::TEST, &[seed]) }

    fn mint(ledger: &mut Ledger, minter: &Party, to: &Party, amount: u64) -> Note {
        let note = Note::new(to.vk.pk(), minter.vk.pk(), amount, 0, ledger.now);
        let env = Envelope::seal(&minter.vk, &to.vk.address(), &note, &TxKey::random());
        ledger.mint(&note, env).unwrap();
        note
    }

    fn bundle(ledger: &Ledger, anchor: Word8) -> Bundle {
        let p = party();
        let note = Note::new(p.vk.pk(), p.vk.pk(), 1, 0, ledger.now);
        let env = Envelope::seal(&p.vk, &p.vk.address(), &note, &TxKey::random());
        Bundle { anchor, nullifiers: [w8(1), w8(2)], commitments: [w8(3), w8(4)], fee: 0, burn: 0, asset: 0, time: ledger.now, envelopes: [env.clone(), env] }
    }

    /// Every refusal below leaves the ledger untouched, so one ledger serves all of them.
    #[test]
    fn apply_bundle_refuses_cheapest_first_and_reaches_the_digest_last() {
        let g = fixture();
        let m = machine();
        let mut ledger = Ledger::new(1000);
        let (bridge, bob) = (party(), party());
        let minted = mint(&mut ledger, &bridge, &bob, 5);
        let root = ledger.root();
        let honest = bundle(&ledger, root);
        // 1. shape
        let mut g2 = fixture_mut_shape_probe(&g);
        g2.public_values.pop();
        assert!(matches!(ledger.apply_bundle(&m, &g2, &honest), Err(LedgerError::Proof(VerifyError::PublicValues))));
        g2.public_values.push(0);
        g2.public_values[pv::OUT0] = 1 << 32;
        assert!(matches!(ledger.apply_bundle(&m, &g2, &honest), Err(LedgerError::BadDigest)), "a non-word output can match no digest");
        // 2. anchor
        let b = Bundle { anchor: w8(99), ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::UnknownAnchor(a)) if a == w8(99)));
        // 3. time: the future, and more than TIME_WINDOW in the past; exactly TIME_WINDOW passes on.
        for t in [1001u32, 1000 - Ledger::TIME_WINDOW - 1] {
            let b = Bundle { time: t, ..honest.clone() };
            assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::Time { claimed, now: 1000 }) if claimed == t), "time {t}");
        }
        let b = Bundle { time: 1000 - Ledger::TIME_WINDOW, ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::BadDigest)));
        // 4. a fee in a foreign asset
        let b = Bundle { asset: 1, fee: 1, ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::FeeInForeignAsset { asset: 1, fee: 1 })));
        let b = Bundle { asset: 1, fee: 0, burn: 7, ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::BadDigest)), "a foreign asset with no fee passes on");
        // 5. the nullifiers
        let b = Bundle { nullifiers: [w8(1), w8(1)], ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::DuplicateNullifierInBundle)));
        // 6. the commitments: equal, or already a leaf
        let b = Bundle { commitments: [w8(3), w8(3)], ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::DuplicateCommitmentInBundle)));
        let b = Bundle { commitments: [w8(3), minted.commitment()], ..honest.clone() };
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &b), Err(LedgerError::Duplicate(cm)) if cm == minted.commitment()));
        // 7. the digest, for a structurally perfect bundle whose proof is of another program
        assert!(matches!(ledger.apply_bundle(&m, &g.1, &honest), Err(LedgerError::BadDigest)));
        // Nothing was admitted.
        assert!(ledger.bundles.is_empty());
        assert_eq!(ledger.root(), root);
        assert!(!ledger.has_nullifier(&w8(1)));
        assert_eq!((ledger.fees_collected, ledger.burned), (0, 0));
    }

    /// `apply` recomputes its digest second, before the anchor: a proof of the wrong program is
    /// `BadDigest` whatever else is wrong with the transaction.
    #[test]
    fn apply_checks_the_digest_before_the_anchor_and_the_shape_before_that() {
        let g = fixture();
        let m = machine();
        let mut ledger = Ledger::new(5);
        let p = party();
        let note = Note::new(p.vk.pk(), p.vk.pk(), 1, 0, 5);
        let env = Envelope::seal(&p.vk, &p.vk.address(), &note, &TxKey::random());
        let got = ledger.apply(&m, &g.1, w8(1), w8(2), note.commitment(), 5, env.clone());
        assert!(matches!(got, Err(LedgerError::BadDigest)), "{got:?}");
        let mut short = fixture_mut_shape_probe(&g);
        short.public_values.truncate(3);
        assert!(matches!(ledger.apply(&m, &short, w8(1), w8(2), note.commitment(), 5, env), Err(LedgerError::Proof(VerifyError::PublicValues))));
        assert!(ledger.txs.is_empty());
    }

    #[test]
    fn the_anchor_window_keeps_exactly_the_last_64_roots() {
        let g = fixture();
        let m = machine();
        let mut ledger = Ledger::new(0);
        let (bridge, bob) = (party(), party());
        let mut roots = vec![ledger.root()];
        for i in 0..Ledger::ANCHOR_WINDOW {
            mint(&mut ledger, &bridge, &bob, 1 + i as u64);
            roots.push(ledger.root());
        }
        assert_eq!(roots.len(), 65);
        let probe = |ledger: &mut Ledger, anchor: Word8| ledger.apply_bundle(&m, &g.1, &bundle(ledger, anchor));
        assert!(matches!(probe(&mut ledger, roots[0]), Err(LedgerError::UnknownAnchor(_))), "genesis has just left the window");
        assert!(matches!(probe(&mut ledger, roots[1]), Err(LedgerError::BadDigest)), "the oldest of the last 64 is still an anchor");
        assert!(matches!(probe(&mut ledger, roots[64]), Err(LedgerError::BadDigest)));
        mint(&mut ledger, &bridge, &bob, 100);
        assert!(matches!(probe(&mut ledger, roots[1]), Err(LedgerError::UnknownAnchor(_))), "one more root pushes it out");
        assert!(matches!(probe(&mut ledger, roots[2]), Err(LedgerError::BadDigest)));
    }

    /// A second copy of the fixture's proof with the same shape, for edits to `public_values`
    /// without touching the shared one: `Proof` is not `Clone`, but it is `Serialize`.
    fn fixture_mut_shape_probe(g: &(Program, Proof)) -> Proof {
        postcard::from_bytes(&g.1.to_bytes()).unwrap()
    }
}
