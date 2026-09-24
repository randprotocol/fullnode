pub mod actions;
pub mod block;
pub mod transaction;
pub mod validator;

pub use actions::{
    registration_message, set_authority_message, token_mint_message, unbond_message, withdraw_message,
    AggregatorRegistration, CallEnvelope, InitialMint, Registration, SignedAggregateHeader, MAX_CALL_ENVELOPE_BYTES,
};
pub use block::{Block, BlockHeader, QuorumCertificate, Vote, SigningDomain};
pub use transaction::{
    format_amount, parse_amount, Action, AmountError, Transaction, FAUCET_MAX_UNITS, TOKEN_DECIMALS, TOKEN_SYMBOL,
    TX_BINDING_DOMAIN, TX_BINDING_WORDS, UNITS_PER_RAND,
};
pub use validator::{Validator, ValidatorSet};

/// The FRI profile of a proof, mirrored in randprotocol-core so the ledger never names a zkvm type
/// (R6): two variants, exactly `randprotocol_zkvm::machine::FriProfile`'s, and the executor's
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

/// The zkVM's public-value layout (`randprotocol_zkvm::tables::cpu::pv`), mirrored so the ledger
/// never names a zkvm type — [`FriProfile`]'s discipline, one level down. The constraint-set-6
/// values: `PC_ENTRY, TIER, OUT0..7, HC0..7, IN0..7, PUB0..7`, 34 in all. A test on the zkvm
/// side pins these to the real constants, so a constraint-set change that moves the layout
/// fails there, not silently here.
pub mod pv {
    pub const PC_ENTRY: usize = 0;
    pub const TIER: usize = 1;
    pub const OUT0: usize = 2;
    pub const HC0: usize = OUT0 + 8;
    pub const IN0: usize = HC0 + 8;
    pub const PUB0: usize = IN0 + 8;
    pub const NUM: usize = PUB0 + 8;
}
