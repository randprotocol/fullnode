//! The chain-facing aggregate API (spec §6, amended by M5.2's R5/R6 and M5.3's R6): `aggregate`
//! turns N same-shape RV32-machine proofs into one rVM proof whose four batch public values are
//! the interface digest of `[inner_vk_digest ‖ N ‖ 34·N]`, and `verify_aggregate` checks the
//! digest the node recomputes from the covered bundles before the ordinary rVM `Machine::verify`
//! — the cs6 `verify_public` pattern: the §4.4 list travels with the transaction as auxiliary
//! data, the proof carries only its commitment.
//!
//! The registered artifact is [`aggregate_program`]'s digest: one N-generic program per inner
//! shape, built once at startup and pinned (R6).

use crate::isa::{Program, F};
use crate::machine::{Machine, ProveError, Tier, VerifyError};
use crate::public_values::{interface_words, public_digest};
use crate::shape::{InnerKey, InnerShape};
use crate::witness::{TapeError, WitnessTape};
use p3_field::PrimeField64;
use randprotocol_zkvm::tables::cpu::pv;

/// The RV32 machine's `Proof` (its 34 public values ride inside it; the empty public segment's
/// `H_PUB` is a prover-computed constant of the shape, as in M5.1's fixtures).
pub type InnerProof = randprotocol_zkvm::machine::Proof;

/// What an aggregate proves under: one inner shape and its preprocessed cap.
#[derive(Clone, Debug)]
pub struct InnerVerifierKey {
    pub shape: InnerShape,
    pub key: InnerKey,
}

/// The registered aggregate program for a key: the N-generic verifier over its shape,
/// checkpoints off — the build the fullnode runs once at startup and pins by digest (R6).
pub fn aggregate_program(vk: &InnerVerifierKey) -> Program {
    crate::programs::verify_rv32n(&vk.shape, &vk.key, crate::dsl::Checkpoints::Off).program
}

/// spec §6's `AggregateProof`, amended: the batch public values of `proof` are the four-element
/// interface digest; `public` is the §4.4 list as auxiliary data (the `verify_public` pattern).
/// (No `Clone`/`Debug` — `machine::Proof`'s `BatchProof` payload has neither; the plan's derive
/// list narrows to what compiles. A second handle is a `to_bytes` round-trip.)
pub struct AggregateProof {
    pub proof: crate::machine::Proof,
    pub public: Vec<F>,
}

/// Why a set of inner proofs could not be aggregated. (`Debug`-only: the `ProveError` payload
/// has no `Clone`/`PartialEq`, so the plan's derive list narrows to what compiles — the tests
/// match on variants.)
#[derive(Debug)]
pub enum AggregateError {
    /// An aggregate of no proofs.
    Empty,
    /// `proofs[index]`'s declared shape is not the key's — checked for the whole set, cheapest
    /// first, before any tape work.
    WrongShape { index: usize },
    /// The N-proof tape could not be built (a proof the transcript replay refuses).
    Tape(TapeError),
    /// The aggregate program's run or proof failed.
    Prove(ProveError),
    /// The executed program's published digest disagrees with the host-computed one — a
    /// tape/program mismatch caught at prove time (R6).
    DigestMismatch,
}

/// Why an aggregate proof did not verify.
#[derive(Debug)]
pub enum VerifyAggregateError {
    /// `public`'s digest does not equal the proof's batch public values — the list the node
    /// recomputed from the covered bundles is not the list the proof binds.
    DigestMismatch,
    /// The rVM's ordinary `Machine::verify` refused the proof.
    Verify(VerifyError),
}

/// spec §6's `aggregate`: shape-checks every inner proof (cheapest first), builds the N-tape,
/// proves, returns the proof and its §4.4 list.
pub fn aggregate(
    m: &Machine,
    vk: &InnerVerifierKey,
    proofs: &[InnerProof],
    tier: Option<Tier>,
) -> Result<AggregateProof, AggregateError> {
    if proofs.is_empty() {
        return Err(AggregateError::Empty);
    }
    for (index, p) in proofs.iter().enumerate() {
        if !vk.shape.matches(p) {
            return Err(AggregateError::WrongShape { index });
        }
    }
    let tape = WitnessTape::build_n(m.profile, &vk.shape, &vk.key, proofs)
        .map_err(AggregateError::Tape)?;
    let program = aggregate_program(vk);
    let (proof, _exec) = m.prove(&program, &tape.words, tier).map_err(AggregateError::Prove)?;
    // R6: the proof's published digest is the executed program's own output, committed into the
    // batch public values; it must equal the host-computed one, here, at prove time — not at the
    // chain's admission check.
    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let public = interface_words(&vk.shape, &vk.key, &pvs);
    let want: Vec<u64> = public_digest(&public).iter().map(|f| f.as_canonical_u64()).collect();
    if proof.public_values != want {
        return Err(AggregateError::DigestMismatch);
    }
    Ok(AggregateProof { proof, public })
}

/// spec §6's `verify_aggregate`: digest check, then `Machine::verify`, returning each covered
/// bundle's `OUT0..7` as `[u32; 8]`, in proof order.
pub fn verify_aggregate(
    m: &Machine,
    program: &Program,
    a: &AggregateProof,
) -> Result<Vec<[u32; 8]>, VerifyAggregateError> {
    let want: Vec<u64> = public_digest(&a.public).iter().map(|f| f.as_canonical_u64()).collect();
    if a.proof.public_values != want {
        return Err(VerifyAggregateError::DigestMismatch);
    }
    m.verify(program, &a.proof).map_err(VerifyAggregateError::Verify)?;
    // The digest committed to the list's length, so a list that passes the check is well-formed:
    // `[vk(4) ‖ N ‖ pv::NUM·N]`, and each proof's run is `pv`'s own layout.
    let n = a.public[4].as_canonical_u64() as usize;
    assert_eq!(
        a.public.len(),
        5 + pv::NUM * n,
        "a public list whose digest the proof carries is well-formed"
    );
    Ok((0..n)
        .map(|j| {
            let base = 5 + pv::NUM * j + pv::OUT0;
            std::array::from_fn(|k| {
                u32::try_from(a.public[base + k].as_canonical_u64())
                    .expect("OUT words are u32-range by the inner machine's construction")
            })
        })
        .collect())
}
