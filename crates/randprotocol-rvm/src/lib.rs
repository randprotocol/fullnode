//! The Rand recursion VM (rVM): a second machine, field-native where the RV32 machine is
//! byte-native, whose programs verify Rand zkVM proofs (`docs/superpowers/specs/
//! 2026-09-13-zkvm-m5-recursion-vm-design.md`).
//!
//! M5.1 builds the machine's *semantics* and its first program, not its AIRs:
//!
//! - [`isa`] fixes the twenty-four-instruction set, the four-field-element encoding and the
//!   program digest that binds a program (one Poseidon2 permutation per instruction, the same
//!   construction the RV32 machine's `hc` uses).
//! - [`emulator`] is the reference semantics *and* the measuring instrument: it logs one event
//!   per instruction with the memory accesses and the permutation that row dispatches, so cpu
//!   rows and permutations per verified inner proof are a byproduct of running a program.
//!
//! - [`dsl`] is the builder rVM programs are written in: typed handles over a linear register
//!   allocator that spills to memory, with named assertion traps so "the program refused at *this*
//!   step" is a checked claim.
//!
//! - [`shape`] is what a verifier program is specialised to: the inner proof's declared heights and
//!   every per-instance number the batch transcript needs, plus the inner preprocessed commitment,
//!   which the program carries as a constant rather than recomputing (3.1 M permutations).
//! - [`reference`] replays the very same transcript on the host with every intermediate exposed, so
//!   each phase of the program is checked against a value `p3-challenger`/`p3-fri` computed.
//! - [`witness`] flattens one `Proof` into the tape the program reads with `HINT`, in consumption
//!   order, with a pinned segment table.
//! - [`programs`] holds the programs themselves — in M5.1, the RV32-machine verifier.
//!
//! The rule inherited from `research/AGENTS.md` holds here too: the emulator is the reference
//! semantics — if an AIR and the emulator disagree, the AIR is wrong.

pub mod aggregate;
pub mod dsl;
pub mod emulator;
pub mod isa;
pub mod machine;
pub mod programs;
pub mod public_values;
pub mod reference;
pub mod shape;
pub mod tables;
pub mod witness;
