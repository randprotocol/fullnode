//! ZKVM-113 item 2: a constraint-set version bound into the rVM's verifier key
//! (`machine::KeyVersion`; `docs/11-next-levers.md` §2). The acceptance line is "an rVM key
//! built at one constraint set refuses a proof made at another; a test shows it" — the third
//! test below. Live since constraint set 11: the first shows the default machine is at
//! `Set(RVM_CONSTRAINT_SET)` and its key is not the set-10 (`Unbound`) one.
//!
//! Tier 8, a fourteen-instruction program that touches every table: seconds.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::isa::{Instr, Op, Program, F};
use randprotocol_rvm::machine::{FriProfile, KeyVersion, Machine, Tier, VerifyError, LIVE_KEY_VERSION, RVM_CONSTRAINT_SET};

fn toy() -> Program {
    let i = |op, rd, ra, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),
            i(Op::Faddi, 2, 0, 5),
            i(Op::Fadd, 3, 1, 2),
            i(Op::Inv, 4, 3, 0),
            i(Op::Faddi, 7, 0, 64),
            i(Op::Store, 1, 7, 0),
            i(Op::Store, 2, 7, 1),
            i(Op::Poseidon2, 0, 7, 0),
            i(Op::Load, 8, 7, 0),
            i(Op::Public, 0, 3, 0),
            i(Op::Public, 0, 4, 0),
            i(Op::Public, 0, 8, 0),
            i(Op::Public, 0, 1, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    }
}

fn cap(m: &Machine, p: &Program) -> Vec<u64> {
    let common = m.verifier_key(p, Tier(8), 0);
    let pre = common.preprocessed.as_ref().expect("the program table is preprocessed");
    pre.commitment.roots().iter().flatten().map(|x| x.as_canonical_u64()).collect()
}

/// `Machine::new` is at `Set(RVM_CONSTRAINT_SET)` (= 11 at the cut that made it live), holds the
/// same key as an explicitly versioned machine, and not the set-10 (`Unbound`) key.
#[test]
fn the_default_machine_is_at_the_live_set_and_its_key_moved() {
    let p = toy();
    assert_eq!(RVM_CONSTRAINT_SET, 11);
    assert_eq!(LIVE_KEY_VERSION, KeyVersion::Set(RVM_CONSTRAINT_SET));
    let default = Machine::new(FriProfile::Test);
    assert_eq!(default.key_version(), LIVE_KEY_VERSION);
    let explicit = Machine::with_key_version(FriProfile::Test, KeyVersion::Set(RVM_CONSTRAINT_SET));
    assert_eq!(cap(&default, &p), cap(&explicit, &p));
    let unbound = Machine::with_key_version(FriProfile::Test, KeyVersion::Unbound);
    assert_ne!(cap(&default, &p), cap(&unbound, &p), "the live key is not the set-10 one");
}

/// The version decides the key: the same program, tier and shape under `Unbound`, set `n` and
/// set `n + 1` have three different caps, and each is reproducible.
#[test]
fn every_version_has_its_own_key() {
    let p = toy();
    let n = RVM_CONSTRAINT_SET;
    let caps: Vec<Vec<u64>> = [KeyVersion::Unbound, KeyVersion::Set(n), KeyVersion::Set(n + 1), KeyVersion::Set(0)]
        .iter()
        .map(|v| cap(&Machine::with_key_version(FriProfile::Test, *v), &p))
        .collect();
    for a in 0..caps.len() {
        for b in a + 1..caps.len() {
            assert_ne!(caps[a], caps[b], "versions {a} and {b} share a key");
        }
    }
    // Deterministic: a second machine at the same version rebuilds the same cap.
    assert_eq!(cap(&Machine::with_key_version(FriProfile::Test, KeyVersion::Set(n)), &p), caps[1]);
}

/// The acceptance test: a proof made at one version verifies at that version and is refused at
/// every other — a set-10 (unbound) key's proof by the live verifier, a live proof by a set-10
/// verifier, and one set's proof by the next set's.
#[test]
fn a_key_built_at_one_constraint_set_refuses_a_proof_made_at_another() {
    let p = toy();
    let n = RVM_CONSTRAINT_SET;
    let versions = [KeyVersion::Unbound, KeyVersion::Set(n), KeyVersion::Set(n + 1)];
    let machines: Vec<Machine> = versions.iter().map(|v| Machine::with_key_version(FriProfile::Test, *v)).collect();
    for (i, prover) in machines.iter().enumerate() {
        let (proof, _) = prover.prove(&p, &[], None).unwrap();
        for (j, verifier) in machines.iter().enumerate() {
            let got = verifier.verify(&p, &proof);
            if i == j {
                got.unwrap_or_else(|e| panic!("{:?} refused its own proof: {e:?}", versions[i]));
            } else {
                assert!(matches!(got, Err(VerifyError::Batch(_))), "a {:?} proof under a {:?} key: {got:?}", versions[i], versions[j]);
            }
        }
    }
    // And the default machine is the live one: it accepts what `machines[1]` proved and
    // refuses what the set-10 machine proved.
    let live = Machine::new(FriProfile::Test);
    let (proof, _) = machines[1].prove(&p, &[], None).unwrap();
    live.verify(&p, &proof).unwrap();
    let (old, _) = machines[0].prove(&p, &[], None).unwrap();
    assert!(matches!(live.verify(&p, &old), Err(VerifyError::Batch(_))));
}
