pub mod actions;
pub mod binding;
pub mod block;
pub mod transaction;
pub mod validator;

pub use actions::{
    registration_message, registration_message_v2, set_authority_message, token_mint_message, unbond_message, withdraw_message,
    AggregatorRegistration, CallEnvelope, InitialMint, Registration, SignedAggregateHeader, MAX_CALL_ENVELOPE_BYTES,
};
pub use binding::BindingDomain;
pub use block::{Block, BlockHeader, QuorumCertificate, Vote, SigningDomain};
pub use transaction::{
    format_amount, parse_amount, Action, AmountError, Transaction, CALL_BINDING_DOMAIN, FAUCET_MAX_UNITS, TOKEN_DECIMALS,
    TOKEN_SYMBOL, TX_BINDING_DOMAIN, TX_BINDING_WORDS, UNITS_PER_RAND,
    CALL_BINDING_DOMAIN_V2, TX_BINDING_DOMAIN_V2,
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

/// The one tier a bundle proof may declare — `randprotocol_zkvm::executor`'s `BUNDLE_TIER`
/// (zkvm I1: every witness of the hidden-asset guest lands at tier 14, at every FRI profile),
/// mirrored because core cannot name the zkVM. An admitted aggregation shape must carry it
/// (the interface review's IFACE-9): no bundle a chain accepts can have another.
pub const BUNDLE_PROOF_TIER: u8 = 14;

/// The one tier an auth proof (split authorisation, v0.6.3) may declare —
/// `randprotocol_zkvm::executor`'s `AUTH_TIER`: the auth guest is straight-line, so every witness
/// lands at tier 10, and it issues no hash syscall, so neither optional table is declared
/// (`decode_and_check` pins both). Mirrored because core cannot name the zkVM; the zkvm
/// executor's tests pin mirror == the real constant.
pub const AUTH_PROOF_TIER: u8 = 10;

/// The one public-table height a bundle proof may declare: the transaction binding's
/// ([`TX_BINDING_WORDS`] words) `public_log_height`, pinned by `decode_and_check` since the
/// transaction binding (Task 5b). Mirrored like [`BUNDLE_PROOF_TIER`]; the node's
/// `agg_executor` tests pin mirror == the zkVM's own function. 7 since constraint set 7 (v0.6.1),
/// which floors every declared table at 2^7 rows; 4 through constraint set 6.
pub const BUNDLE_PUBLIC_LOG_HEIGHT: u8 = 7;

/// What admission needs of a covered bundle and nothing more (spec §4 steps 6–7): its
/// `pv::NUM` public values (35 since constraint set 8) in `pv` order and its declared shape.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoveredBundle {
    pub public_values: [u64; pv::NUM],
    pub shape: DeclaredShape,
}

/// The zkVM's public-value layout (`randprotocol_zkvm::tables::cpu::pv`), mirrored so the ledger
/// never names a zkvm type — [`FriProfile`]'s discipline, one level down. The constraint-set-8
/// values: `PC_ENTRY, TIER, OUT0..7, HC0..7, IN0..7, PUB0..7, GAS`, 35 in all (34 through
/// constraint set 7). A test on the zkvm
/// side pins these to the real constants, so a constraint-set change that moves the layout
/// fails there, not silently here.
pub mod pv {
    pub const PC_ENTRY: usize = 0;
    pub const TIER: usize = 1;
    pub const OUT0: usize = 2;
    pub const HC0: usize = OUT0 + 8;
    pub const IN0: usize = HC0 + 8;
    pub const PUB0: usize = IN0 + 8;
    /// Constraint set 8: the proof's declared gas limit (`GAS_LIMIT`), the one word after
    /// `PUB0..7`. The verifier holds the run's metered gas to it and it to `gas::gas_max` of the
    /// header (spec 2026-09-28 §4.2).
    pub const GAS: usize = PUB0 + 8;
    pub const NUM: usize = GAS + 1;
    /// The order of the field the public values live in (Goldilocks, `2^64 − 2^32 + 1`): a
    /// canonical public value is below it. Mirrored like the layout above (core cannot name the
    /// zkVM's `Val`); the node's `agg_executor` tests pin mirror == `Val::ORDER_U64`.
    pub const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;
}
