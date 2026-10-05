#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(debug_assertions)]
mod check_constraints;
pub mod common;
pub mod config;
pub mod error;
// RandProtocol patch (2026-10-04): quotient layout
pub mod layout;
pub mod proof;
pub mod prover;
pub mod symbolic;
pub(crate) mod transcript;
pub mod verifier;

// Re-export main types and functions for convenience
pub use common::{CommonData, ProverData, ProverOnlyData};
pub use config::{
    Challenge, Commitment, Domain, PackedChallenge, PackedVal, PcsError, PcsProof,
    StarkGenericConfig, Val,
};
pub use error::BatchVerificationError;
pub use p3_uni_stark::{OpenedValues, VerificationError};
pub use proof::{BatchCommitments, BatchOpenedValues, BatchProof};
// RandProtocol patch (2026-10-04): quotient layout
pub use layout::QuotientLayout;
pub use prover::{StarkInstance, prove_batch, prove_batch_with_layout};
pub use transcript::BatchTranscript;
pub use verifier::{
    VerifierData, commitments_with_opening_points, commitments_with_opening_points_with_layout,
    verify_batch, verify_batch_with_layout,
};
