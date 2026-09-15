pub mod actions;
pub mod block;
pub mod transaction;
pub mod validator;

pub use actions::{
    registration_message, unbond_message, withdraw_message, AggregatorRegistration, CallEnvelope, Registration,
    SignedAggregateHeader, MAX_CALL_ENVELOPE_BYTES,
};
pub use block::{Block, BlockHeader, QuorumCertificate, Vote};
pub use transaction::{
    format_amount, parse_amount, Action, AmountError, Transaction, FAUCET_MAX_UNITS, TOKEN_DECIMALS, TOKEN_SYMBOL,
    UNITS_PER_SHRUGG,
};
pub use validator::{Validator, ValidatorSet};

/// The FRI profile of a proof, mirrored in shrugg-core so the ledger never names a zkvm type
/// (R6): two variants, exactly `shrugg_zkvm::machine::FriProfile`'s, and the executor's
/// aggregate surface maps between them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum FriProfile {
    Test,
    Production,
}

/// The declared shape of a bundle proof (block aggregation, spec §0.1 finding (a)): the FRI
/// profile, the tier, and the six declared log-heights, read off the proof's stored header and
/// kept per bundle through pruning. What the admission stub's shape check (spec §4 step 6) and
/// the inner-verifier-key digest are computed from.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeclaredShape {
    pub profile: FriProfile,
    pub tier: u8,
    pub program_log_height: u8,
    pub input_log_height: u8,
    pub keccak_log_height: u8,
    pub sha256_log_height: u8,
    pub public_log_height: u8,
    pub mem_log_height: u8,
}

/// What admission needs of a covered bundle and nothing more (spec §4 steps 6–7): its 34
/// public values in `pv` order and its declared shape.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoveredBundle {
    pub public_values: [u64; 34],
    pub shape: DeclaredShape,
}
