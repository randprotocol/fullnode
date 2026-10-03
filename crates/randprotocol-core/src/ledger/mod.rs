//! The shielded notes ledger and block application rules (design spec §7, §9).
//!
//! Everything common to every transaction — the size caps, the chain id, the fee floor, the
//! anchor and time windows, the bundle's nullifier/commitment uniqueness, the bundle proof —
//! lives here. The rules that belong to one feature live in a module beside this one and are
//! reached from the action step (spec §7 step 7): [`staking`] for `Bond`/`Unbond`/`Withdraw`
//! (phase S2), [`call_envelope`] and [`bridge_notes`] for `Call`'s input transcript and
//! `BridgeAttest`/`BridgeBurn` (phase S3). That split is what lets S2 and S3 be implemented in
//! parallel: each phase owns its own file.

pub mod aggregation;
mod shared_set;
pub use shared_set::SharedSet;
#[cfg(test)]
mod bind_tests;
pub mod bridge_gov;
pub mod bridge_notes;
pub mod call_envelope;
pub mod fees;
pub mod nullifier_mmr;
pub mod perps;
pub mod program_state;
pub mod staking;
pub mod supply;
pub mod tokens;
pub mod vesting;

use crate::bridge::{BridgeError, BridgeState, CheckedAttestation};
use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
use crate::crypto::{merkle_root, Address, Hash};
use crate::gas;
use crate::notes::{word8_to_bytes, Bundle, CommitmentTree, Envelope, Word8, MAX_ENVELOPE_BYTES};
use crate::program::{program_id_with_public, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Action, Block, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
pub use fees::FeesConfig;
pub use staking::{FaucetMinter, FaucetRecipient, SlashingConfig, StakingConfig};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How many block-end roots a bundle may anchor to (spec §7 item 4).
///
/// The spec proposed 64, sized for "about a minute at 1 s blocks". A tier-14 bundle proof measures
/// ~100 s on a laptop and the fleet makes a block every ~2 s, so 64 blocks expired an anchor
/// roughly halfway through proving one honest transfer. 256 blocks is ~8.5 minutes at the fleet's
/// pace and ~2 minutes even at 500 ms blocks — comfortably longer than the proof it has to outlive.
/// (At chain 18's 1.17 s blocks it is ~300 s, which a delegated proof on a slow prover missed:
/// a genesis `proof_window_blocks` replaces this and [`TIME_WINDOW`] together, issue #118; this is
/// the window without one.)
pub const ANCHOR_WINDOW: usize = 256;
/// How far behind the current height a bundle's `time` may be (spec §7 item 5). Kept equal to
/// [`ANCHOR_WINDOW`]: the two windows exist for the same reason (a prover needs the chain to still
/// accept what it started proving), and a shorter `time` window would reject bundles whose anchor
/// is still live.
pub const TIME_WINDOW: u64 = 256;
/// The bounds a genesis `proof_window_blocks` must sit inside (issue #118). The floor is today's
/// window, so no chain can make a prover's margin shorter than every chain through 19 gave it; the
/// ceiling keeps the anchor deque — one entry per block, in every speculative clone of the ledger
/// — and the age of a spendable anchor bounded: 4 096 blocks is ~80 minutes at chain 18's 1.17 s.
pub const MIN_PROOF_WINDOW_BLOCKS: u64 = TIME_WINDOW;
pub const MAX_PROOF_WINDOW_BLOCKS: u64 = 4096;

pub use staking::{QueuedStake, StakingError, ValidatorEntry};
pub use supply::{register_total, Audit, Supply};

/// A deposit note the ledger created itself while applying a transaction, rather than accepting
/// on the wire: S2's `Withdraw` publishes only a blinding and a public amount, and the owner is
/// the payout address in the register, so the commitment is computed here and is not in
/// [`Transaction::commitments`].
///
/// S3's `BridgeAttest` creates a note the wire does not carry either, and is deliberately *not*
/// on this list: its note goes into the tree through [`Ledger::deposit`], and a node that has to
/// index it rebuilds it from the transaction and the asset registry alone
/// (`bridge_notes::deposit_note`, which `storage::created_notes` calls), because every input to
/// that commitment is public. A withdraw's note cannot be rebuilt that way — only the register
/// knows who it pays — which is the whole reason this list exists. The one place the two are
/// answered together is [`Ledger::derived_commitment`], for the mempool's conflict index.
///
/// This is transient output, like a call receipt — not consensus state, not in the state root,
/// not compared by [`Ledger`]'s equality. `apply_transactions` clears the list when a block
/// starts, so after `apply_block` the ledger's [`Ledger::deposits`] are exactly that block's,
/// in the order they were appended to the tree. Storage (S2 Task 3) writes one `NoteRow` per
/// entry at `index`, beside the notes `created_notes(tx)` already yields for the bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// Leaf index the note was appended at.
    pub index: u64,
    pub cm: Word8,
    /// The envelope the action carried, stored with the note so its owner can open it.
    pub envelope: Envelope,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum TxError {
    #[error("wrong chain id: expected {expected}, got {actual}")]
    WrongChain { expected: u64, actual: u64 },
    #[error("transaction carries no bundle")]
    MissingBundle,
    /// The action rides without a bundle ([`Action::bundle_less`]) and this transaction attached
    /// one anyway. Named, so a wallet hears which of its actions was built wrong.
    #[error("a {0} must not carry a bundle")]
    ActionCarriesBundle(&'static str),
    #[error("envelope exceeds {MAX_ENVELOPE_BYTES} bytes")]
    EnvelopeTooLarge,
    /// Spec 2026-09-26 §2.4: on a chain whose genesis sets `envelope_bytes`, a note envelope of
    /// any other length. Every envelope is the same size so none tells a memo from its absence.
    #[error("envelope is {got} bytes, this chain requires exactly {expected}")]
    EnvelopeSize { expected: usize, got: usize },
    /// Spec 2026-09-28 §4.3: on a chain whose genesis carries a `gas` section, a bundle proof
    /// whose declared `GAS_LIMIT` (`pv::GAS`) is not exactly the section's `bundle_gas_limit`.
    /// `got` is `None` when the executor's proofs carry no limit at all.
    #[error("bundle proof declares gas limit {got:?}, this chain requires exactly {want}")]
    BundleGasLimit { want: u64, got: Option<u64> },
    #[error("proof too large")]
    ProofTooLarge,
    #[error("attestation exceeds {} bytes", gas::MAX_ATTESTATION_BYTES)]
    AttestationTooLarge,
    /// The whole transaction is larger than a block, so no block could ever carry it.
    ///
    /// The per-part caps above do not imply this one: a `Call` carries two proofs, each admissible
    /// at the ledger's `max_proof_bytes`, whose sum with envelopes can be over its
    /// `max_block_bytes`. `apply_block` already refuses such a transaction as part of the block's
    /// cumulative byte rule, so nothing about block validity changes here — this only stops one
    /// from being accepted for a block it can never be in. `max` is this chain's block cap.
    #[error("transaction of {size} bytes exceeds the {max} byte block limit")]
    TransactionTooLarge { size: usize, max: usize },
    #[error("program too large")]
    ProgramTooLarge,
    /// A deploy's public input is longer than the chain's `max_program_public_words` (the call
    /// limits, spec §5; 0, no public input at all, unless the genesis raises it).
    #[error("program public input too large")]
    ProgramPublicTooLarge,
    /// The bundle names a burned token (`burn_asset != 0`) on an action that burns no token:
    /// only a `TokenBurn` or a `BridgeBurn` may (the hidden-asset bundle, spec §3.7).
    #[error("the bundle burns asset {0} on an action that burns no token")]
    UnsupportedAsset(u32),
    /// A non-zero burn (`burn_a` or `burn_r`) on an action that may not burn it: `burn_r` only on
    /// a `Bond` or a `RegisterAggregator`, `burn_a` only on a `TokenBurn` or a `BridgeBurn`.
    #[error("a burn of {0} is not allowed on this action")]
    UnsupportedBurn(u64),
    /// `burn_asset == 0 && burn_a > 0`: RAND burned through the private-asset slots. The guest
    /// allows it (with `A = 0` both sums are RAND), and the chain refuses it everywhere: a RAND
    /// burn goes through `burn_r` only, so there is one canonical form of every burn (the
    /// controller's ruling on H1's review).
    #[error("RAND burned through burn_a ({0}); a RAND burn goes through burn_r")]
    NonCanonicalRandBurn(u64),
    #[error("fee {fee} below minimum {min}")]
    FeeTooLow { min: u64, fee: u64 },
    /// The anchor is not one of the chain's recorded block-end roots; `window` is how many it
    /// keeps — [`ANCHOR_WINDOW`], or genesis `proof_window_blocks` (issue #118) — so the message
    /// names the window this chain runs, not a constant.
    #[error("anchor is not one of the last {window} roots")]
    UnknownAnchor { window: u64 },
    /// A bundle's `time`, or a bundle-less `Withdraw`'s, outside the window (spec §7 item 5).
    /// `window` is the one in force ([`TIME_WINDOW`], or genesis `proof_window_blocks`).
    #[error("time {time} is outside [{}, {height}]", height.saturating_sub(*window))]
    TimeOutOfWindow { time: u32, height: u64, window: u64 },
    /// One bundle spends the same nullifier in two of its four slots — a double spend within one
    /// transaction (the guest's distinctness check, repeated here as a cheap refusal).
    #[error("the transaction spends the same nullifier twice")]
    DuplicateNullifierInBundle,
    #[error("nullifier already spent")]
    Spent(Word8),
    /// As above, for output notes: a commitment appearing twice in one transaction would be
    /// appended to the tree twice and be unspendable the second time.
    #[error("the transaction creates the same commitment twice")]
    DuplicateCommitmentInBundle,
    #[error("commitment already in the tree")]
    CommitmentExists(Word8),
    #[error("faucet is disabled on this chain")]
    FaucetDisabled,
    #[error("mint of {amount} exceeds faucet cap {cap}")]
    MintTooLarge { amount: u64, cap: u64 },
    /// A faucet `Mint` of a note worth [`crate::notes::MAX_NOTE_VALUE`] (2^63) or more — a note
    /// the hidden-asset guest's u63 range check could never spend. The ledger itself never
    /// answers it: `FAUCET_MAX_UNITS` refuses such a mint as `MintTooLarge` on every chain, a
    /// policy verdict that is deliberately not cached. This is the node's byte-level verdict for
    /// the same bytes (`admission::oversized_note`), decided before any signature work and cached
    /// for good, like a `TokenMint`'s `Token(AmountTooLarge)` and a deposit's
    /// `Bridge(AmountTooLarge)` are (deep scan 2026-09-24, ledger arithmetic).
    #[error("mint of {amount} is at or above 2^63, which no bundle proof can spend")]
    AmountTooLarge { amount: u64 },
    #[error("minter {0} is not a validator")]
    MinterNotValidator(Address),
    /// The faucet minter has a row in the validator register but is not one of the chain's faucet
    /// minters — the genesis validators, as node admission policy, or `staking.faucet_minters`
    /// where a genesis lists them (the pre-release rescan's RESCAN-LEDGER-1). The register is
    /// permissionless, and a bonded key is in the active set two epochs later, so neither a row
    /// nor set membership may make a key a minter. Never a permanent admission verdict: as node
    /// policy it is this build's rule rather than the bytes', and a forwarder running an older
    /// node must not be penalised for relaying what its own node still admits.
    #[error("minter {0} is not a faucet minter on this chain")]
    MinterNotAllowed(Address),
    /// COV-2 (2026-09-28): a call proof declaring its input, keccak or sha256 table below
    /// 2^`min` rows. Such a table is smaller than what the proof opens of it — 80 FRI queries plus
    /// two out-of-domain points against `h` random rows of the hiding commitment — so the proof
    /// reveals the table's private contents. The prover is being fixed upstream to floor the
    /// three tables at 128 rows; until every wallet runs it, a node refuses to pool such a call.
    /// **Node policy only — the ledger never raises it**: a block carrying one still applies, and
    /// the verdict is never permanent (a policy can move; the wallet that upgrades resubmits).
    #[error(
        "call proof declares a {table} table of 2^{log_height} rows, under the 2^{min} floor: a \
         table that small leaks its private contents through the proof — upgrade the wallet, \
         whose prover pads it, and prove the call again"
    )]
    CallRevealsPrivateInputs { table: &'static str, log_height: u8, min: u8 },
    /// CPU-1 (2026-09-27 zkVM/ISA review): a `Deploy` of more program words than any call can
    /// hold — the call tier cap's Poseidon2 budget less the digests every proof pays first
    /// (`ConfidentialExecutor::max_callable_program_words`). It would deploy, be charged
    /// `deploy_fee`, and never be callable. The node's pool policy on every chain, and a validity
    /// rule under genesis `hardening_v6`. Never a permanent verdict: the bound follows the build's
    /// call tier cap, which a later build may raise.
    #[error(
        "a program of {words} words (public input {public_words} words) can never be called: a call \
         proves at most {max_words} program words beside that public input at the highest tier a \
         call may use — split the program"
    )]
    ProgramUncallable { words: usize, public_words: usize, max_words: usize },
    /// The v0.6 canonical-proof rules (INT-5, VERIFIER-2, VERIFIER-1 of the 2026-09-27 reviews):
    /// a bundle or call proof carrying a header or transcript field other than the one the honest
    /// prover writes — a field the verifier accepts at any value, so a relayer could re-encode the
    /// proof into a second transaction id, or a shape no aggregate can cover
    /// (`ConfidentialExecutor::non_canonical_proof` names the field). The node's pool policy on
    /// every chain, and a validity rule under genesis `hardening_v6`. Never a permanent verdict:
    /// what the honest prover writes is the build's knowledge, which a re-vendor may move.
    #[error("non-canonical proof: {0} — re-prove with an up-to-date wallet")]
    NonCanonicalProof(String),
    #[error("bad mint signature")]
    BadMintSignature,
    #[error("the mint's commitment does not open to its published note and amount")]
    MintCommitmentMismatch,
    /// Audit v4, STAKE-2 rule 2: the epoch's faucet budget would be exceeded. State, not bytes —
    /// the next epoch admits the same transaction — so never a permanent admission verdict.
    #[error("the faucet budget of {budget} for this epoch is exhausted ({minted} minted)")]
    FaucetBudgetExhausted { budget: u64, minted: u64 },
    /// Chain 15's faucet allowlist (`staking.faucet_recipients`): the mint's note is for a spend
    /// key the genesis does not list. The list is a genesis constant and `pk` is the mint's own
    /// bytes, so this one is permanent.
    #[error("the faucet may not mint to this recipient (not in staking.faucet_recipients)")]
    FaucetRecipientNotAllowed,
    #[error("confidential computation is disabled on this chain")]
    ConfidentialDisabled,
    #[error("bad program: {0}")]
    BadProgram(ConfidentialError),
    #[error("unknown program {0}")]
    UnknownProgram(ProgramId),
    /// An action whose variant exists on the wire but whose rules have not shipped yet. The
    /// message names the phase that turns it on, so a wallet built against a newer node tells
    /// its user which upgrade it is waiting for rather than "invalid transaction".
    #[error("{0}")]
    UnsupportedAction(&'static str),
    #[error("invalid proof: {0}")]
    InvalidProof(ConfidentialError),
    #[error("the bundle's digest is not what its proof published")]
    BadDigest,
    /// Split authorisation (delegated proving Phase 2): a bundle carrying a non-zero
    /// `auth_commit` or a non-empty `auth_proof` on a chain whose genesis names no `hc_auth`.
    /// About the bundle's own bytes against a genesis constant.
    #[error("this chain has no split authorisation (genesis hc_auth): a bundle's auth_commit must be zero and its auth_proof empty")]
    AuthUnexpected,
    /// Split authorisation: a bundle without an auth proof on a chain whose genesis names
    /// `hc_auth` — every bundle there carries one, self-proved or delegated alike.
    #[error("this chain requires an auth proof on every bundle (genesis hc_auth)")]
    AuthMissing,
    /// Split authorisation: the auth proof publishes a commitment other than the bundle's
    /// `auth_commit` — the spend key holder did not authorise this bundle.
    #[error("the auth proof publishes a different commitment than the bundle's auth_commit")]
    AuthMismatch,
    /// Spec 2026-09-28 §4.3, split authorisation: on a chain with both a `gas` section and
    /// `hc_auth`, an auth proof whose declared `GAS_LIMIT` (`pv::GAS`) is not exactly
    /// [`gas::auth_gas_limit_pin`] — the auth guest's tier-10, hash-free ceiling. `got` is `None`
    /// when the executor's proofs carry no limit at all.
    #[error("auth proof declares gas limit {got:?}, this chain requires exactly {want}")]
    AuthGasLimit { want: u64, got: Option<u64> },
    /// Split authorisation: the auth proof does not decode at the auth guest's pinned shape, or
    /// does not verify against the pinned auth guest and this transaction's binding.
    #[error("auth proof: {0}")]
    InvalidAuthProof(ConfidentialError),
    /// HB-3: the commitment tree could not hold every leaf this transaction may append (its
    /// bundle's four, and a note the ledger derives). Refused before anything is applied; the
    /// tree's `append` used to `assert!` inside block application. Four billion leaves in, so
    /// unreachable in practice.
    #[error("the commitment tree is full")]
    CommitmentTreeFull,
    /// The proof verifier panicked on this transaction (the 2026-09-27 reviews' coverage gap:
    /// no `catch_unwind` around Plonky3). Raised by the node's admission workers only, which
    /// catch the panic so a malformed proof costs a refusal rather than a worker slot. Never a
    /// permanent verdict: a panic says the verifier broke, not which bytes are at fault.
    #[error("the proof verifier failed on this transaction ({0}); refused")]
    VerifierPanicked(String),
    /// INTERFACE-6: a sealed-form side-table record that does not belong to the transaction it
    /// vouches for — it names another transaction id, or its `H_PUB` words are not the digest of
    /// this transaction's binding. Only ever raised on the sealed-sync path.
    #[error("pruned bundle record: {0}")]
    PrunedRecordMismatch(&'static str),
    #[error("invalid bundle proof: {0}")]
    InvalidBundleProof(ConfidentialError),
    /// A bundle proof in the sealed (pruned) marker form outside sealed-form sync: the marker is
    /// only ever admissible inside a synced block whose side table vouches for it (spec §7).
    ///
    /// Deliberately its own variant and **not** a permanent admission verdict: the marker form
    /// hashes to the raw transaction's id by design (the pre-v0.1 review's M1), so a node that
    /// cached this refusal by `tx.hash()` would then refuse the honest raw transaction for free —
    /// a censorship lever any gossip peer could pull (Task 5b review, fix round 1).
    #[error("a pruned (marker-form) bundle proof is admissible only in sealed-form sync")]
    PrunedFormOutsideSync,
    /// The whole `Aggregate` action's encoding (block aggregation, spec §3.1's wire cap).
    /// `max` is this chain's composite cap, [`Ledger::max_aggregate_bytes`].
    #[error("the aggregate action of {size} bytes exceeds the {max} byte cap")]
    AggregateTooLarge { size: usize, max: usize },
    /// The aggregate proof failed the executor (spec §4 step 8): the interface-digest compare
    /// or the rVM's `Machine::verify`.
    #[error("invalid aggregate proof: {0}")]
    InvalidAggregateProof(ConfidentialError),
    /// `Ledger::validate`'s answer to an `Aggregate`: the covered bundles' records live in node
    /// storage, so admission runs through [`Ledger::validate_aggregate`], the covered-carrying
    /// path. Never a verdict on the transaction itself.
    #[error("an aggregate is validated on the covered-carrying path (Ledger::validate_aggregate)")]
    AggregateNeedsCovered,
    /// Everything the bridge itself refuses: an unknown guardian set, a replayed digest, a
    /// short quorum, an unregistered asset, an unusable destination (spec §10).
    #[error("bridge: {0}")]
    Bridge(BridgeError),
    /// The `BridgeAttest` carries a shielded address that is not the one the guardians signed
    /// about. Without this the submitter would choose who receives someone else's deposit.
    #[error("the attestation names a different recipient")]
    BridgeRecipientMismatch,
    /// The `BridgeAttest` names an asset index that is not the one this deposit would be given.
    /// A plain mistake now that bridged tokens are listed rather than registered by first
    /// sighting: the index a listed token deposits under is decided before any attestation of it
    /// exists and never moves, so nothing can take it from a pooled transaction and a wallet that
    /// read the registry cannot lose a race for it. Accepting a wrong one would append a note
    /// whose `asset` word is not the one the recipient's envelope was sealed against, which no
    /// key of theirs opens.
    #[error("the attestation deposits under asset {expected}, and the transaction names {actual}")]
    AttestAssetMismatch { expected: u32, actual: u32 },
    /// A `TokenBurn`'s or `BridgeBurn`'s bundle burns another asset than the action declares
    /// (`burn_asset != asset`). Caught by [`tokens::check_asset_burn`] before the proof is
    /// verified.
    #[error("the bundle burns asset {actual}, not the declared {expected}")]
    BurnAssetMismatch { expected: u32, actual: u32 },
    /// …or burns another amount of it (`burn_a != amount`).
    #[error("the bundle burns {actual}, not the {expected} the action declares")]
    BurnAmountMismatch { expected: u64, actual: u64 },
    #[error("proposer {0} is not in the validator register")]
    UnknownProposer(Address),
    /// Phase S2: a `Bond`, `Unbond` or `Withdraw` the register refused (see [`StakingError`]).
    #[error("vesting: {0}")]
    Vesting(#[from] vesting::VestingError),
    /// RPL-2: an `Invoke` the program-state module refused (see
    /// [`program_state::ProgramStateError`]) — the gate itself, a malformed transition, a cell
    /// that is no longer what the transition read, a vault that cannot pay.
    #[error("program state: {0}")]
    ProgramState(#[from] program_state::ProgramStateError),
    #[error("staking: {0}")]
    Staking(#[from] StakingError),
    /// Block aggregation: a register action or aggregate the aggregation module refused (see
    /// [`aggregation::AggregationError`]).
    #[error("aggregation: {0}")]
    Aggregation(#[from] aggregation::AggregationError),
    /// The RPL token registry refused something (see [`tokens::TokenError`]), the way `Staking`
    /// and `Aggregation` carry their own registers' verdicts: the gate itself
    /// ([`tokens::TokenError::Disabled`], a chain with no `tokens` section, which every RPL action
    /// meets before any check of its own) and everything the five RPL actions decide —
    /// a registration's metadata, identity, index, authority and fee; a mint's nonce, signature
    /// and supply bound; a holder burn's unknown index, zero amount, bridged token and supply
    /// bound. Every one of them is decided in `validate`, so `apply`
    /// cannot fail on a transaction that was admitted.
    ///
    /// The registry's *bridge*-side refusals are deliberately not here: a deposit's and a
    /// `BridgeBurn`'s supply and backing bounds are reported through
    /// [`crate::bridge::BridgeError::Token`], from both halves alike, because the action that hit
    /// them is the bridge's.
    #[error("token: {0}")]
    Token(#[from] tokens::TokenError),
    #[error("arithmetic overflow")]
    Overflow,
}

/// Why a candidate did not apply, for the proposer: refused by validation before any write
/// (the ledger is byte-identical; skip it), or failed in the action step after
/// `apply_bundle_notes` wrote (the ledger is dirty; rebuild from the pre-loop state). Returned by
/// [`Ledger::apply_tx_checked`] (final review F1 of the validator hot path, spec 2026-10-05).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ApplyFailure {
    /// Refused before the first write: the ledger is unchanged.
    Refused(TxError),
    /// Failed after the first write: the ledger holds part of the transaction.
    HalfApplied(TxError),
}

impl ApplyFailure {
    /// The error itself, whichever stage raised it.
    pub fn into_inner(self) -> TxError {
        match self {
            ApplyFailure::Refused(e) | ApplyFailure::HalfApplied(e) => e,
        }
    }
}

/// [`Ledger::bundle_fee_split`]'s result: the bundle step's arithmetic, computed before the
/// first write. `fee` is what is left after the burned registration fee; `fee_burned` is the
/// burned base (or, under `fees.burn_floor`, the burned settled floor), zero without
/// `fees.burn_base`; `kept` is the proposer's share now and `rewards` its entry once credited;
/// `base_bucketed` is the aggregator's part of the base under `fees.proposer_share_bps`
/// (`docs/compute-optimization.md` §6.2), bucketed beside the excess, zero without it.
#[derive(Clone, Copy, Debug)]
struct BundleFeeSplit {
    registration_burn: u64,
    fee: u64,
    fee_burned: u64,
    kept: u64,
    rewards: u64,
    base_bucketed: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("tx {index} invalid: {error}")]
    InvalidTx { index: usize, error: TxError },
    #[error("tx root mismatch")]
    TxRootMismatch,
    /// The block names one transaction twice (audit v6, GOSSIP-2). The transaction root
    /// duplicates the last leaf of an odd level, so such a list can carry the root — and the
    /// header, hash and signature — of the honest list it was made from. Reported by the orphan
    /// pool, which takes a block on its header; an executed block's repeat fails on its own.
    #[error("a transaction appears twice in the block")]
    RepeatedTransaction,
    #[error("state root mismatch: computed {computed}, header {header}")]
    StateRootMismatch { computed: Hash, header: Hash },
    #[error("bad proposer signature")]
    BadProposerSignature,
    #[error("proposer {0} is not a validator")]
    UnknownProposer(Address),
    #[error("too many transactions in block")]
    TooManyTransactions,
    /// A sealed-form batch's side table carries a pruned record whose public-value list is not
    /// the `pv::NUM` (35 since constraint set 8) words a covering aggregate reads (deep scan
    /// 2026-09-24): refused before any transaction of the block is applied — a peer's wire input
    /// is never indexed on trust.
    #[error("pruned record for tx {tx} carries {words} public values, not {expected}")]
    MalformedPrunedRecord { tx: Hash, words: usize, expected: usize },
    /// A side-table record carries a public value at or past the Goldilocks order (the rescan's
    /// ZKQ-4): the rVM absorbs these words unreduced, so `x + p` would pass the covering
    /// aggregate's digest in place of `x` and this node would store and re-serve the
    /// non-canonical record. Refused beside the length check, before any transaction.
    #[error("pruned record for tx {tx} carries a non-canonical public value at word {index}")]
    NonCanonicalPrunedRecord { tx: Hash, index: usize },
    /// INTERFACE-7: two side-table records under one proof hash. The table is collected into a
    /// map keyed by proof hash, so the second silently replaced the first, and which record a
    /// node stored, served and checked depended on nothing but the order a peer sent them in.
    /// Refused before any transaction is read.
    #[error("the side table carries two records for proof {proof_hash}")]
    DuplicatePrunedRecord { proof_hash: Hash },
    /// At most one `Aggregate` per block (spec §3.4) is a block-validity rule, not proposer
    /// selection alone (the pre-v0.1 review's H1): the second is refused by index.
    #[error("a block carries at most one aggregate; a second is at tx {index}")]
    SecondAggregate { index: usize },
    #[error("block transaction bytes exceed the per-block limit")]
    TooLarge,
    /// Only on a chain with a bridge, where the block timestamp is consensus input
    /// (guardian-set expiry, outbound burn message times): a leader must not be able to rewind
    /// time and keep a superseded guardian set inside its grace window. Equal timestamps are
    /// allowed — the rule forbids a rewind, not a repeat (`docs/bridge.md` §3, §8).
    #[error("block timestamp {block} is before its parent's {parent}")]
    TimestampRewind { parent: u64, block: u64 },
    /// B2 (bridge hardening spec §3): on a chain with a bridge, a block may run at most
    /// [`MAX_TIMESTAMP_STEP_MS`] past its parent, so a leader cannot jump the clock to expire a
    /// rotated guardian set's grace window or skip a mint-cap day. A validity rule — replay of
    /// committed history applies it too — and, like the rewind rule, absent on a bridge-less
    /// chain.
    #[error("block timestamp {block} is more than {max_step} ms past its parent's {parent}")]
    TimestampLeap { parent: u64, block: u64, max_step: u64 },
}

/// B2: the most a bridged chain's block timestamp may exceed its parent's, in milliseconds (a
/// validity rule, [`BlockError::TimestampLeap`]).
pub const MAX_TIMESTAMP_STEP_MS: u64 = 60_000;

/// Receipt data for a call, before it is placed in a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallReceiptData {
    pub program: ProgramId,
    pub tier: u8,
    pub outputs: [u32; 8],
    /// `H_IN`, the verified proof's public commitment to the call's private inputs — what the
    /// envelope below is sealed against (spec §6.1).
    pub h_in: Word8,
    /// The program's public-input digest the proof was checked against; `None` for a program
    /// deployed without a public input.
    pub h_pub: Option<Word8>,
    /// The call's input envelope, carried through to the receipt unread (spec §6.1); see
    /// [`call_envelope`] for the one rule the chain applies to it.
    pub input_envelope: Option<crate::types::CallEnvelope>,
    /// What this call adds to its block's `gas_used` for the Phase 2 controller
    /// ([`Ledger::call_gas_used`]: the proof's declared `GAS_LIMIT`). Not on the stored receipt.
    pub gas_used: u64,
}

/// What `validate_inner` verified that `apply_tx` would otherwise verify again: a call's
/// outcome (a STARK verification) and a `BridgeAttest`'s checked attestation (a guardian
/// quorum's worth of signature recoveries). `Ledger::validate` drops it; `apply_tx` spends it.
#[derive(Clone, Debug, Default)]
struct Verified {
    call: Option<CallOutcome>,
    attestation: Option<CheckedAttestation>,
}

/// The set of transactions whose proofs this node has already verified (audit v3, B5).
///
/// The key is the transaction hash, which binds the proof: `rand-txid-3` hashes the bundle
/// proof (and the split-authorisation auth proof) by digest, and the transaction binding the
/// proof itself is verified against covers the rest of the transaction. So "this hash verified" is a stateless fact — a hit vouches for
/// these exact bytes, never for some other transaction, however the entry came to be held. The
/// ledger consults the set at block application ([`Ledger::apply_block_with`]) and skips exactly
/// one thing on a hit: the STARK verification (`verify_bundle`, `verify_auth`, `verify_call`).
/// Everything else `validate_inner` does still runs — the digest compares, the bundle's structural checks, and
/// the whole state-dependent half (anchors, nullifiers, nonces, fee floors) — so two validators
/// holding different sets still reach byte-identical verdicts, and an entry whose transaction
/// was evicted from the pool (or never pooled: a proof verified, then lost to a conflict) costs
/// nothing but the re-verification it was meant to save.
pub trait VerifiedProofs: Send + Sync {
    fn contains(&self, tx: &Hash) -> bool;
    /// `true` when the set holds nothing and a caller can skip computing hashes to query it
    /// with. Provided, so an implementor that does not care about the hashing cost changes
    /// nothing; [`NoVerified`] takes it.
    fn is_empty(&self) -> bool {
        false
    }
}

/// The empty [`VerifiedProofs`]: what every path without an admission cache behind it passes —
/// sync, replay, `verify_chain`, tests. On those paths every proof is verified at apply, exactly
/// as before.
pub struct NoVerified;

impl VerifiedProofs for NoVerified {
    fn contains(&self, _: &Hash) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        true
    }
}

/// A locked set answers through the lock, and a poisoned one answers `false`: the cost of a
/// wrong `false` is a re-verification, where a wrong `true` does not exist (see the trait).
impl<T: VerifiedProofs + ?Sized> VerifiedProofs for std::sync::RwLock<T> {
    fn contains(&self, tx: &Hash) -> bool {
        self.read().map(|g| g.contains(tx)).unwrap_or(false)
    }
    fn is_empty(&self) -> bool {
        self.read().map(|g| g.is_empty()).unwrap_or(true)
    }
}

/// The commitment of the note a faucet mint creates: owner `pk`, no sender, `amount` of the
/// native asset, the action's `time` and blinding `r`. Admission refuses a `Mint` whose `cm` is
/// anything else; the wallet-side builder ([`Transaction::mint`]) computes it the same way.
pub fn mint_commitment(executor: &dyn ConfidentialExecutor, pk: &Word8, amount: u64, time: u32, r: &Word8) -> Word8 {
    executor.note_commitment(pk, &[0; 8], amount, 0, time, r)
}

/// Whether two of `words` are equal — the pairwise distinctness a bundle's four nullifiers and
/// four commitments each need (six pairs apiece).
/// The v0.6 canonical-proof rules over a transaction: its raw bundle proof (a pruned marker
/// carries no proof), its auth proof when it has one, then its call proof, each through `check`
/// ([`ConfidentialExecutor::non_canonical_proof`], or the zkVM's function directly in the node's
/// pool), as the one `TxError::NonCanonicalProof` naming which proof and which field. One function
/// for the pool policy and the `hardening_v6` validity rule, so the two cannot drift.
pub fn non_canonical_proofs(tx: &Transaction, check: &dyn Fn(&[u8]) -> Option<String>) -> Option<TxError> {
    if let Some(b) = &tx.bundle {
        if crate::notes::pruned_proof_hash(&b.proof).is_none() {
            if let Some(why) = check(&b.proof) {
                return Some(TxError::NonCanonicalProof(format!("bundle proof: {why}")));
            }
        }
        // Split authorisation's auth proof (never pruned), when the bundle carries one.
        if !b.auth_proof.is_empty() {
            if let Some(why) = check(&b.auth_proof) {
                return Some(TxError::NonCanonicalProof(format!("auth proof: {why}")));
            }
        }
    }
    // An RPL-2 `Invoke` carries a call proof too, and the call binding blanks it exactly as it
    // blanks a call's.
    if let Action::Call { proof, .. } | Action::Invoke { proof, .. } = &tx.action {
        if let Some(why) = check(proof) {
            return Some(TxError::NonCanonicalProof(format!("call proof: {why}")));
        }
    }
    None
}

/// HB-3: the most commitment-tree leaves one transaction can append — a bundle's four slots and
/// at most one note the ledger derives itself (a `Withdraw` or `BridgeAttest` deposit, a faucet
/// `Mint`, a `TokenMint` or `RegisterToken` initial mint, a vesting claim or revoke, an aggregate
/// payout) — or, for an RPL-2 `Invoke`, the up to [`program_state::MAX_PAYOUTS`] notes its
/// transition pays out. `validate_inner` refuses a transaction when the tree has fewer left.
pub const MAX_LEAVES_PER_TX: u64 = crate::notes::BUNDLE_SLOTS as u64 + program_state::MAX_PAYOUTS as u64;

fn has_duplicate(words: &[Word8]) -> bool {
    words.iter().enumerate().any(|(i, w)| words[i + 1..].contains(w))
}

/// In-memory chain state: the note commitment tree, the nullifier set, the validator register
/// and the deployed programs. It is cloned for speculative execution (one clone per block in the
/// consensus tree, and per trial-apply). The tree is a frontier (constant size), and
/// `commitments` and `nullifiers` are [`SharedSet`]s — a committed base shared by every clone
/// plus an owned delta — so a clone is O(delta), and the base moves only at `HotStuff` commit
/// (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §5). As history: when both
/// were plain `BTreeSet`s a clone copied every entry the chain had, which the audit-v6 review
/// measured at 1.6 ms for 100 000 leaves and nullifiers and 28 ms for 1 000 000 (its own private
/// run; not re-measured here). `AGENTS.md`, "Speculative state is capped".
#[derive(Clone, Debug)]
pub struct Ledger {
    chain_id: u64,
    /// The pinned commitment of the `bundle` guest every bundle proof must be for.
    hc_bundle: Word8,
    faucet: bool,
    confidential: bool,
    tree: CommitmentTree,
    /// Every leaf ever appended — spec §7 item 6 needs membership the frontier cannot answer.
    commitments: SharedSet,
    nullifiers: SharedSet,
    /// The incremental nullifier root (spec 2026-10-05 §4) under genesis
    /// `incremental_nullifier_root`: a range over the nullifiers in insertion order, whose root
    /// takes the sorted root's slot. `None` on every chain through 20.
    nullifier_mmr: Option<nullifier_mmr::NullifierMmr>,
    /// Block-end roots, oldest first, at most [`Ledger::proof_window`] (ANCHOR_WINDOW without a
    /// genesis `proof_window_blocks`).
    anchors: VecDeque<(u64, Word8)>,
    validators: BTreeMap<Address, ValidatorEntry>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    /// The deploy-time public words of every program deployed with a public input (issue #55,
    /// INT-4's residual): under genesis `hardening_v6` a call against such a program proves over
    /// `public ‖ call_binding`, and the chain has to hold the words to recompute that digest.
    /// Bound by the record's `public_digest` (in the state root through the program's id), so
    /// outside both the state root and `Ledger`'s equality, like the node's `program_public`
    /// column it is restored from (`Storage::load_ledger`); written at `Deploy`, so replay rebuilds
    /// it. No entry for a program without a public input.
    program_public: BTreeMap<ProgramId, Vec<u32>>,
    /// Blocks per epoch (spec §8), from genesis. Not state: like `faucet` and `confidential`,
    /// a reloading node sets it from its genesis file.
    epoch_blocks: u64,
    /// The public half of the bridge, present exactly when genesis has a `bridge` section
    /// (spec §10). `None` makes the two bridge actions inadmissible and leaves the state root
    /// with the four components a bridge-less chain has always had.
    bridge: Option<BridgeState>,
    /// The RPL token registry, present exactly when genesis has a `tokens` section. `None` makes
    /// the state root byte-for-byte what a chain without one has always committed; `Some` is
    /// consensus state, folded into the state root right after the bridge root (spec's RPL token
    /// standard).
    tokens: Option<tokens::TokenRegistry>,
    /// The aggregation section of genesis (spec §2), set from the genesis file exactly like
    /// `epoch_blocks` — a genesis parameter, not consensus state. `None` makes the five
    /// aggregation actions inadmissible and keeps the state root byte-for-byte today's.
    aggregation: Option<aggregation::AggregationConfig>,
    /// The `staking` section of genesis (audit v4, STAKE-2), a genesis parameter like
    /// `aggregation`: restored from the genesis file by `reload_ledger`, never from storage.
    /// `None` keeps the faucet unbudgeted, bonds active at the next boundary and the state root
    /// byte-for-byte today's; `Some` switches on the per-epoch budget, the activation delay,
    /// the `rand-state-5` domain and the v4 validator leaf.
    staking: Option<StakingConfig>,
    /// The epoch the faucet counter below is for, and what the faucet minted in it (STAKE-2
    /// rule 2). Consensus state on a chain with a `staking` section — folded into the state
    /// root and persisted beside `META_SUPPLY` — and always `(0, 0)` without one. The counter is
    /// reset lazily: a mint in a later epoch than `faucet_epoch` starts it from zero.
    faucet_epoch: u64,
    faucet_minted_in_epoch: u64,
    /// The bond queue (`staking::QueuedStake`): bonded stake that is not voting weight yet, in
    /// the order it was bonded. Consensus state on a chain with a `staking` section — folded
    /// into the state root and persisted beside `META_SUPPLY` — and always empty without one.
    bond_queue: Vec<staking::QueuedStake>,
    /// The admitted set (audit v6, STAKE-2; `staking.admission_by_vote`): the addresses the
    /// validator set has voted in (`Action::AdmitValidator`) that have not registered yet. A
    /// registering `Bond` is refused unless its key is here, and consumes the row. Consensus
    /// state under the flag — folded into the state root (`rand-state-admitted-1`), inside this
    /// ledger's equality, persisted beside `META_BOND_QUEUE` — and always empty without it, on
    /// every chain through 18. At most `staking::MAX_ADMITTED` rows.
    admitted: BTreeSet<Address>,
    /// The jail (audit v6, STAKE-1; `staking.slashing`): per slashed key, the first epoch it may
    /// be in a set again (`u64::MAX`: for good). `derive_next_set` leaves a jailed key out, a
    /// `Bond` top-up of one is refused, and so is a second piece of evidence against it. Rows
    /// whose epoch has come are dropped at the boundary (`close_block`). Consensus state under
    /// the section — the `rand-state-slashing-1` wrapper, inside equality, `META_JAILED` — and
    /// always empty without it, on every chain through 18.
    jailed: BTreeMap<Address, u64>,
    /// Genesis vesting (`vesting.rs`): the register a genesis `vesting` section seeds, `None`
    /// without one. Consensus state, in the state root (`rand-state-6`), persisted whole.
    vesting: Option<vesting::VestingRegister>,
    /// RPL-2 (`program_state.rs`): every program's cells and vault balances, `None` on a chain
    /// whose genesis has no `program_state` section. Consensus state, in the state root
    /// (`rand-state-8`), persisted whole.
    program_state: Option<program_state::ProgramState>,
    /// Σ of every registration fee burned under `tokens.burn_registration_fee` (audit v5,
    /// TOK-2). A supply counter in kind — derived, outside the state root and this ledger's
    /// equality, persisted beside `META_SUPPLY` and replay-audited — kept off [`Supply`] so
    /// chain 14's stored blob keeps its layout. Always 0 without the gate. The audit needs it
    /// on the right of its identity: the fee left the pool (`supply.burned`) and entered no
    /// register entry, so it is destroyed issuance like a slashed bond.
    registration_fees_burned: u64,
    /// Σ of every `BUNDLE_BASE` burned under `fees.burn_base` (`fees.rs`, `docs/fees.md` §1.3) —
    /// under `fees.burn_floor` beside it, every bundle's whole burned floor (issue #135; one
    /// counter for the whole fee burn under either flag): `registration_fees_burned`'s sibling in
    /// every respect — derived, outside the state root and this ledger's equality, persisted beside
    /// `META_SUPPLY`, replay-audited, on the right of the audit's identity — and always 0 without
    /// the flag.
    base_fees_burned: u64,
    /// The genesis `fees` section (`fees.rs`), the default (every rule off) on a chain whose file
    /// has none. A genesis parameter like `aggregation`: outside the state root and this ledger's
    /// equality, restored by `reload_ledger` on every restart.
    fees: fees::FeesConfig,
    /// The largest program a `Deploy` may carry, in words: genesis's `max_program_words`, or
    /// [`gas::MAX_PROGRAM_WORDS`] on a chain whose file does not set it. A genesis parameter like
    /// `epoch_blocks` — not state, outside the state root and `Ledger`'s equality — so a
    /// reloading node sets it from its genesis file (`reload_ledger`), or it would come back at
    /// the default and refuse deploys its peers admit.
    max_program_words: usize,
    /// The call-limits parameters (genesis `max_proof_bytes`, `max_block_bytes`,
    /// `max_call_envelope_bytes`, `max_program_public_words`), each at today's value
    /// ([`gas::MAX_PROOF_BYTES`], [`gas::MAX_BLOCK_BYTES`],
    /// [`crate::types::actions::MAX_CALL_ENVELOPE_BYTES`], [`gas::MAX_PROGRAM_PUBLIC_WORDS`]) on a
    /// chain whose file does not set it. Genesis parameters like `max_program_words`: outside the
    /// state root and `Ledger`'s equality, and restored by `reload_ledger` on every restart.
    max_proof_bytes: usize,
    max_block_bytes: usize,
    max_call_envelope_bytes: usize,
    max_program_public_words: usize,
    /// Spec 2026-09-26 §2.4: genesis `envelope_bytes` — every note envelope exactly this long;
    /// `None` keeps today's at-most-`MAX_ENVELOPE_BYTES` rule. A genesis parameter like the call
    /// limits: outside the state root and `Ledger`'s equality, restored by `reload_ledger`.
    envelope_bytes: Option<usize>,
    /// Genesis `gas` (design 2026-09-28 §4.2, §4.3, §7.1): the chain's declared prices, the
    /// bundle guest's flat gas limit, the metering scheme and (Phase 2) the dynamic price
    /// controller's parameters, `None` on a chain whose file does not set one. A genesis
    /// parameter like `max_program_words` and `envelope_bytes`: outside the state root and this
    /// ledger's equality, restored by `reload_ledger` on every restart.
    gas: Option<gas::GasConfig>,
    /// Phase 2 (spec §7.1): the live prices, once the controller has moved them or storage has
    /// restored them. `None` means "the section's own prices" — what a fresh genesis ledger, and
    /// a database written before `META_GAS_PRICES` existed, start from — so `set_gas` (which
    /// `reload_ledger` runs *after* `load_ledger` restores this) can never clobber moved prices.
    /// Read through [`Ledger::gas_prices`] only. Consensus state under `gas.dynamic`: in the
    /// state root (`rand-state-7`) and in this ledger's equality (by effective value).
    gas_prices: Option<gas::GasPrices>,
    /// Genesis `hardening_v6`, the v0.6 switch: each stricter rule below is the node's pool policy
    /// on every chain and a validity rule here only when this is set (the zkVM/ISA review's R4,
    /// one activation for all of them):
    ///
    /// - ZKV-11: a `Deploy` whose padded program table crosses the u32 pc wrap is refused
    ///   (`program::pc_window_fits`).
    /// - CPU-1: a `Deploy` of more words than any call can hold is refused
    ///   (`ConfidentialExecutor::max_callable_program_words`, `TxError::ProgramUncallable`).
    /// - INT-4: a call carries `Transaction::call_binding` as its public segment, after the
    ///   program's deploy-time public input when it has one (issue #55, `program_public`)
    ///   (`ConfidentialExecutor::verify_call_hardened`), so its proof cannot be copied under
    ///   another fee bundle; and every call's program table is floored at 2^7 rows
    ///   (PROGRAM-TABLE-LEAK), both in the executor's hardened verify.
    /// - The canonical-proof rules (INT-5 first): a bundle or call proof with a header or
    ///   transcript field the honest prover would not write is refused
    ///   (`ConfidentialExecutor::non_canonical_proof`, `TxError::NonCanonicalProof`).
    ///
    /// A genesis parameter like `max_program_words`: outside the state root and equality,
    /// restored by `reload_ledger`. `false` — every chain cut before the flag, chain 15 included —
    /// is the old rules.
    hardening_v6: bool,
    /// Genesis `hc_auth` (split authorisation, delegated proving Phase 2, spec
    /// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): the auth guest every
    /// bundle's `auth_proof` must be a proof of. `Some` makes every bundle carry an auth proof
    /// whose published `c` is its `auth_commit`, and recomputes the bundle digest with the v3
    /// preimage (`auth_commit` inside); `None` — every chain cut before it — refuses any auth
    /// field (`TxError::AuthUnexpected`) and keeps the v1 digest, byte for byte. That `hc_bundle`
    /// is a v3 guest exactly when this is set is the node's startup gate
    /// (`node::check_build_runs_genesis`): core cannot name guests. A genesis parameter like
    /// `hardening_v6`: outside the state root and equality, restored by `reload_ledger`.
    hc_auth: Option<Word8>,
    /// Audit v6, STAKE-2: the genesis `testnet` marker, what lets `faucet: true` sit beside a
    /// `bridge` section (`Genesis::validate`). No rule of this ledger reads it — it is here so
    /// the node can serve it (`rand_status`, `rand_getLimits`) from the one place every genesis
    /// parameter lives. A parameter like `hardening_v6`: outside the state root and equality,
    /// restored by `reload_ledger`; `false` on every chain through 18.
    testnet: bool,
    /// Issue #118: genesis `proof_window_blocks`, the one window that replaces both
    /// [`ANCHOR_WINDOW`] and [`TIME_WINDOW`] when set — how old a bundle's anchor and its `time`
    /// may be — read through [`Ledger::proof_window`]. `None`, every chain through 19, is today's
    /// 256/256. A genesis parameter like `max_program_words`: outside the state root (the anchor
    /// deque it sizes never entered one) and this ledger's equality, restored by `reload_ledger`
    /// on every restart — which also has to re-read the deeper anchor rows `load_ledger` stops
    /// short of, or a restarted node would refuse anchors its peers accept.
    proof_window_blocks: Option<u64>,
    /// The aggregator register, hashed into the state root (spec §2.1) when `aggregation` is
    /// set; empty otherwise and at chain-9 block 0.
    aggregators: BTreeMap<Address, aggregation::AggregatorEntry>,
    /// Per address that has withdrawn from the aggregator register, the nonce its next
    /// registration starts at (the interface review's IFACE-6): the entry is deleted at the
    /// withdraw, and without this floor a re-registration restarted at 0 and replayed its old
    /// signed actions. Consensus state, in the aggregators' state-root component only when
    /// non-empty ([`aggregation::aggregators_component`]); empty on every chain without the
    /// section.
    retired_aggregator_nonces: BTreeMap<Address, u64>,
    /// Height of the block being applied (the `time` window and `ProgramRecord::deployed_at`).
    height: u64,
    /// Timestamp of the block being applied, in unix milliseconds.
    timestamp_ms: u64,
    /// Deposit notes this block's transactions made the ledger create (see [`Deposit`]).
    deposits: Vec<Deposit>,
    /// The aggregates this block's transactions paid (see [`aggregation::PaidAggregate`]).
    /// Scratch, like `deposits`, and cleared with them.
    paid_aggregates: Vec<aggregation::PaidAggregate>,
    /// The sealed form's side table for the block being applied (spec §7), keyed by proof
    /// hash: the raw transaction hash and the `pv::NUM` (35) public values per pruned bundle. Scratch,
    /// like `deposits` — set by `apply_transactions_for_sync`, cleared with the deposits,
    /// never hashed into anything, and empty on every path but sealed-form sync.
    pruned_side: BTreeMap<Hash, (Hash, Vec<u64>)>,
    /// The public supply counters (see [`supply`]). Derived from the chain, not hashed into
    /// the state root.
    supply: Supply,
    /// The proving-share bucket (block aggregation, spec §5.2): per included bundle, the fee
    /// excess over `gas::BUNDLE_BASE`, the proposer that included it, and the height it is
    /// coverable until. Derived state like `supply` — rebuilt on replay, persisted beside it,
    /// and deliberately outside both the state root and `Ledger`'s equality: the map repeats
    /// information the chain already holds (the fee is in the bundle, the heights are the
    /// chain's), and `Ledger::from_parts` cannot know it.
    unsealed_fees: BTreeMap<Hash, (u64, Address, u64)>,
    /// What a block's proposer signature is verified under at replay (audit v4, consensus domain
    /// v1): a genesis parameter like `epoch_blocks`, set by `Genesis::build` and restored by a
    /// reloading node from its genesis file; never state, so outside equality and the root.
    signing_domain: crate::types::SigningDomain,
    /// BIND-1 (audit v6): what this chain's transaction bindings and signed action messages are
    /// over — the chain id alone, or the genesis hash too under genesis `binding_domain: 1`
    /// ([`crate::types::BindingDomain`]). A genesis parameter like `signing_domain`: set by
    /// `Genesis::build`, restored by a reloading node from its genesis file, never state, so
    /// outside equality and the root.
    binding_domain: crate::types::BindingDomain,
}

/// Equality is over consensus state only. `height` and `timestamp_ms` are the position of the
/// block being applied, and `faucet`/`confidential`/`epoch_blocks`/`max_program_words` and the
/// four call limits are genesis parameters a reloading node sets from its genesis file rather than from storage, so
/// two ledgers holding the same notes, nullifiers, anchors, validators and programs are the same
/// ledger.
///
/// The [`supply`] counters are deliberately **out**: nothing in the state root covers them, and
/// `Ledger::from_parts` cannot know them, so a rebuilt ledger would never compare equal to the
/// one it was rebuilt from. A node audits its stored copy of them separately, by replay
/// (`Storage::verify_chain`).
impl PartialEq for Ledger {
    fn eq(&self, o: &Ledger) -> bool {
        self.chain_id == o.chain_id
            && self.hc_bundle == o.hc_bundle
            && self.tree == o.tree
            && self.commitments == o.commitments
            && self.nullifiers == o.nullifiers
            && self.nullifier_mmr == o.nullifier_mmr
            && self.anchors == o.anchors
            && self.validators == o.validators
            && self.programs == o.programs
            && self.bridge == o.bridge
            && self.tokens == o.tokens
            && self.aggregators == o.aggregators
            && self.retired_aggregator_nonces == o.retired_aggregator_nonces
            // The proving-share bucket is consensus state on an aggregating chain: what it holds
            // decides who is paid and which bundles an aggregate may cover (audit v3, AGG-4). On a
            // chain without aggregation it is empty on both sides and this compares nothing.
            && self.unsealed_fees == o.unsealed_fees
            // The faucet epoch counters are consensus state on a chain with a `staking` section
            // (audit v4, STAKE-2) and `(0, 0)` on both sides without one.
            && self.faucet_epoch == o.faucet_epoch
            && self.faucet_minted_in_epoch == o.faucet_minted_in_epoch
            // The bond queue likewise: consensus state under the section, empty without one.
            && self.bond_queue == o.bond_queue
            // The admitted set (audit v6, STAKE-2): consensus state under
            // `staking.admission_by_vote`, empty on both sides without it.
            && self.admitted == o.admitted
            // The jail (audit v6, STAKE-1): consensus state under `staking.slashing`, empty on
            // both sides without it.
            && self.jailed == o.jailed
            // The vesting register: consensus state under its section, `None` on both sides
            // without one.
            && self.vesting == o.vesting
            // Program state (RPL-2): consensus state under its section, `None` on both sides
            // without one. Its two RAND counters are audit state and compared with it; a
            // rebuilt ledger restores the whole blob, counters included.
            && self.program_state == o.program_state
            // The live gas prices (Phase 2): consensus state under `gas.dynamic`, compared by
            // effective value so a restored `Some(section prices)` equals an unmoved `None`.
            && self.gas_prices() == o.gas_prices()
    }
}
impl Eq for Ledger {}

impl Ledger {
    /// An empty ledger whose only anchor is the empty tree's root at height 0, with `validators`
    /// as its register. Genesis is the one caller that seeds a register (spec §8); every later
    /// entry arrives through a `Bond`.
    pub fn new(
        chain_id: u64,
        hc_bundle: Word8,
        validators: BTreeMap<Address, ValidatorEntry>,
        executor: &dyn ConfidentialExecutor,
    ) -> Ledger {
        let tree = CommitmentTree::new(executor);
        let mut anchors = VecDeque::new();
        anchors.push_back((0, tree.root()));
        Ledger {
            chain_id,
            hc_bundle,
            faucet: false,
            confidential: true,
            tree,
            commitments: SharedSet::new(),
            nullifiers: SharedSet::new(),
            nullifier_mmr: None,
            anchors,
            validators,
            programs: BTreeMap::new(),
            program_public: BTreeMap::new(),
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            bridge: None,
            tokens: None,
            aggregation: None,
            staking: None,
            faucet_epoch: 0,
            faucet_minted_in_epoch: 0,
            bond_queue: Vec::new(),
            admitted: BTreeSet::new(),
            jailed: BTreeMap::new(),
            vesting: None,
            program_state: None,
            registration_fees_burned: 0,
            base_fees_burned: 0,
            fees: fees::FeesConfig::default(),
            max_program_words: gas::MAX_PROGRAM_WORDS,
            max_proof_bytes: gas::MAX_PROOF_BYTES,
            max_block_bytes: gas::MAX_BLOCK_BYTES,
            max_call_envelope_bytes: crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
            max_program_public_words: gas::MAX_PROGRAM_PUBLIC_WORDS,
            envelope_bytes: None,
            gas: None,
            gas_prices: None,
            hardening_v6: false,
            hc_auth: None,
            testnet: false,
            proof_window_blocks: None,
            aggregators: BTreeMap::new(),
            retired_aggregator_nonces: BTreeMap::new(),
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            paid_aggregates: Vec::new(),
            pruned_side: BTreeMap::new(),
            supply: Supply::default(),
            unsealed_fees: BTreeMap::new(),
            signing_domain: crate::types::SigningDomain::v0(Hash::ZERO),
            binding_domain: crate::types::BindingDomain::ChainId,
        }
    }

    /// Rebuild a ledger from stored state. The faucet and confidential switches come from
    /// genesis, not from storage, so the caller sets them afterwards — and so does the bridge,
    /// via [`Ledger::set_bridge`], and the token registry, via [`Ledger::set_tokens`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        chain_id: u64,
        hc_bundle: Word8,
        tree: CommitmentTree,
        commitments: BTreeSet<Word8>,
        nullifiers: BTreeSet<Word8>,
        anchors: Vec<(u64, Word8)>,
        validators: BTreeMap<Address, ValidatorEntry>,
        programs: BTreeMap<ProgramId, ProgramRecord>,
    ) -> Ledger {
        Ledger {
            chain_id,
            hc_bundle,
            faucet: false,
            confidential: true,
            tree,
            commitments: SharedSet::from_set(commitments),
            nullifiers: SharedSet::from_set(nullifiers),
            nullifier_mmr: None,
            anchors: anchors.into_iter().collect(),
            validators,
            programs,
            program_public: BTreeMap::new(),
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            bridge: None,
            tokens: None,
            aggregation: None,
            staking: None,
            faucet_epoch: 0,
            faucet_minted_in_epoch: 0,
            bond_queue: Vec::new(),
            admitted: BTreeSet::new(),
            jailed: BTreeMap::new(),
            vesting: None,
            program_state: None,
            registration_fees_burned: 0,
            base_fees_burned: 0,
            fees: fees::FeesConfig::default(),
            max_program_words: gas::MAX_PROGRAM_WORDS,
            max_proof_bytes: gas::MAX_PROOF_BYTES,
            max_block_bytes: gas::MAX_BLOCK_BYTES,
            max_call_envelope_bytes: crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
            max_program_public_words: gas::MAX_PROGRAM_PUBLIC_WORDS,
            envelope_bytes: None,
            gas: None,
            gas_prices: None,
            hardening_v6: false,
            hc_auth: None,
            testnet: false,
            proof_window_blocks: None,
            aggregators: BTreeMap::new(),
            retired_aggregator_nonces: BTreeMap::new(),
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            paid_aggregates: Vec::new(),
            pruned_side: BTreeMap::new(),
            supply: Supply::default(),
            unsealed_fees: BTreeMap::new(),
            signing_domain: crate::types::SigningDomain::v0(Hash::ZERO),
            binding_domain: crate::types::BindingDomain::ChainId,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn hc_bundle(&self) -> Word8 {
        self.hc_bundle
    }

    pub fn faucet_enabled(&self) -> bool {
        self.faucet
    }

    pub fn set_faucet(&mut self, on: bool) {
        self.faucet = on;
    }

    pub fn confidential_enabled(&self) -> bool {
        self.confidential
    }

    pub fn set_confidential(&mut self, on: bool) {
        self.confidential = on;
    }

    /// Blocks per epoch (spec §8), as genesis set it.
    pub fn epoch_blocks(&self) -> u64 {
        self.epoch_blocks
    }

    /// Set by the node from its genesis file, like the faucet and confidential switches. Zero is
    /// refused into 1 so `epoch` can never divide by zero on a malformed genesis.
    pub fn set_epoch_blocks(&mut self, n: u64) {
        self.epoch_blocks = n.max(1);
    }

    /// The epoch of the block being applied: `height / epoch_blocks`, so genesis is epoch 0.
    pub fn epoch(&self) -> u64 {
        self.height / self.epoch_blocks.max(1)
    }

    /// The validator set of `epoch`, derived from this register as if this ledger were the last
    /// block of the epoch before it (spec §8). The rule itself lives in [`staking::derive_set`];
    /// the epoch is named by the caller because, under a `staking` section, an entry's
    /// activation epoch decides whether it is in the set derived *for* that epoch (audit v4,
    /// STAKE-2 rule 3). A caller asking what the next boundary would derive passes
    /// `epoch() + 1`.
    ///
    /// Under the section's later fields the bond queue's waiting stake is not weight and the
    /// weights are capped at `max_weight_bps` (`staking::derive_set_with`); without a section
    /// the queue is empty and there is no cap, which is `staking::derive_set` exactly.
    pub fn derive_next_set(&self, epoch: u64) -> ValidatorSet {
        let cap = self.staking.as_ref().and_then(|s| s.max_weight_bps);
        // Under `staking.slashing` a jailed key is in no set (audit v6, STAKE-1); the map is
        // empty without it.
        staking::derive_set_jailed(&self.validators, &self.bond_queue, epoch, cap, &self.jailed)
    }

    /// The bond queue (`staking::QueuedStake`), oldest bond first: for the node's persistence
    /// beside `META_SUPPLY` and the replay audit.
    pub fn bond_queue(&self) -> &[staking::QueuedStake] {
        &self.bond_queue
    }

    /// Restore the bond queue a node persisted beside the state — `set_faucet_epoch_counters`'s
    /// twin: hashed into the root under a `staking` section, so a restarted node that lost it
    /// would seat stake its peers still hold back, and fork at the next boundary.
    pub fn set_bond_queue(&mut self, queue: Vec<staking::QueuedStake>) {
        self.bond_queue = queue;
    }

    /// The admitted set (audit v6, STAKE-2): keys the validator set has voted in and that have
    /// not registered yet. For the node's persistence, the replay audit and `rand_getAdmitted`.
    pub fn admitted(&self) -> &BTreeSet<Address> {
        &self.admitted
    }

    /// Restore the admitted set a node persisted beside the state — `set_bond_queue`'s twin:
    /// hashed into the root under `staking.admission_by_vote`, so a restarted node that lost it
    /// would refuse a registration its peers apply, and fork there.
    pub fn set_admitted(&mut self, admitted: BTreeSet<Address>) {
        self.admitted = admitted;
    }

    /// The admitted set as one hash: its length, then every address in the set's own (ascending)
    /// order — fixed-width rows, so the count makes the encoding unambiguous.
    pub fn admitted_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 32 * self.admitted.len());
        buf.extend_from_slice(&(self.admitted.len() as u64).to_be_bytes());
        for a in &self.admitted {
            buf.extend_from_slice(a.as_bytes());
        }
        Hash::digest_domain(b"rand-admitted-1", &buf)
    }

    /// The jail (audit v6, STAKE-1): every slashed key with the first epoch it may be in a set
    /// again, expired rows included until the next boundary drops them. For the node's
    /// persistence, the replay audit and `rand_getValidators`.
    pub fn jailed(&self) -> &BTreeMap<Address, u64> {
        &self.jailed
    }

    /// `validator`'s jail as of this ledger's epoch: the first epoch it may be in a set again,
    /// `None` when it is not jailed or its jail has ended.
    pub fn jailed_until(&self, validator: &Address) -> Option<u64> {
        self.jailed.get(validator).copied().filter(|until| *until > self.epoch())
    }

    /// Restore the jail a node persisted beside the state — `set_admitted`'s twin: hashed into
    /// the root under `staking.slashing`, so a restarted node that lost it would seat a jailed
    /// key its peers keep out, and fork at the next boundary.
    pub fn set_jailed(&mut self, jailed: BTreeMap<Address, u64>) {
        self.jailed = jailed;
    }

    /// The jail as one hash: its length, then every `(address, until)` row in address order.
    pub fn jailed_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 40 * self.jailed.len());
        buf.extend_from_slice(&(self.jailed.len() as u64).to_be_bytes());
        for (a, until) in &self.jailed {
            buf.extend_from_slice(a.as_bytes());
            buf.extend_from_slice(&until.to_be_bytes());
        }
        Hash::digest_domain(b"rand-jailed-1", &buf)
    }

    /// The `staking` section, or `None` on a chain without one — where the faucet has no
    /// per-epoch budget, a bond is weight at the next boundary and the state root is
    /// byte-for-byte today's.
    pub fn staking(&self) -> Option<&StakingConfig> {
        self.staking.as_ref()
    }

    /// Install (or clear) the `staking` section. Genesis calls this once; a reloading node calls
    /// it with what its genesis file holds (`reload_ledger`), never with what storage held —
    /// a restarted node that lost the gate would compute `rand-state-2` roots against peers on
    /// `rand-state-5` and fork at its first block.
    pub fn set_staking(&mut self, staking: Option<StakingConfig>) {
        self.staking = staking;
    }

    /// The faucet's epoch counters, `(epoch, minted_in_epoch)` (audit v4, STAKE-2 rule 2): for
    /// the node's persistence beside `META_SUPPLY`, the replay audit and `rand_getSupply`.
    pub fn faucet_epoch_counters(&self) -> (u64, u64) {
        (self.faucet_epoch, self.faucet_minted_in_epoch)
    }

    /// Restore the counters a node persisted beside the state — `set_supply`'s twin, with the
    /// difference that these are hashed into the root on a chain with a `staking` section, so
    /// a restarted node that lost them would disagree with its peers from its next block.
    pub fn set_faucet_epoch_counters(&mut self, epoch: u64, minted: u64) {
        self.faucet_epoch = epoch;
        self.faucet_minted_in_epoch = minted;
    }

    /// The public supply counters as of this ledger (see [`supply`]).
    pub fn supply(&self) -> Supply {
        self.supply
    }

    /// Restore the counters a node persisted beside the state. Like the faucet and confidential
    /// switches, they do not come out of the note, nullifier and validator families, so the
    /// loader sets them; `Ledger::from_parts` leaves them at zero.
    pub fn set_supply(&mut self, s: Supply) {
        self.supply = s;
    }

    /// The proving-share bucket (spec §5.2), for the audit, the tests and `rand_getUnsealed`.
    pub fn unsealed_fees(&self) -> &BTreeMap<Hash, (u64, Address, u64)> {
        &self.unsealed_fees
    }

    /// Restore the bucket a node persisted beside the state — `set_supply`'s twin: the payout
    /// an aggregate must pay is computed from it, so a restarted node that lost it would
    /// disagree with its peers about the very next aggregate's state root.
    pub fn set_unsealed_fees(&mut self, m: BTreeMap<Hash, (u64, Address, u64)>) {
        self.unsealed_fees = m;
    }

    /// Restore the aggregator register a node persisted beside the state: hashed into the state
    /// root whenever the chain aggregates, so a restarted node that lost it would disagree with
    /// its peers from the very next block. `from_parts` leaves it empty; the loader sets it.
    pub fn set_aggregators(&mut self, m: BTreeMap<Address, aggregation::AggregatorEntry>) {
        self.aggregators = m;
    }

    /// The part of a bundle's fee a registration burns under `tokens.burn_registration_fee`
    /// (audit v5, TOK-2): the registry's `registration_fee` for a `RegisterToken` or
    /// `RegisterBridgedToken` on a chain with the flag, 0 for every other action and chain. One
    /// function for the fee split and for everything that reports its result — the proving
    /// share a bundle is bucketed at is `fee − registration_burn − BUNDLE_BASE`, and a reporter
    /// that recomputed it as `fee − BUNDLE_BASE` paid aggregators a note the ledger never
    /// derives (the interface review's IFACE-7).
    pub fn registration_burn(&self, action: &Action) -> u64 {
        match action {
            Action::RegisterToken { .. } | Action::RegisterBridgedToken { .. } => {
                self.tokens.as_ref().filter(|r| r.burns_registration_fee()).map_or(0, |r| r.registration_fee)
            }
            _ => 0,
        }
    }

    /// The ledger's own floor for a bundle-carrying transaction, as settled once its proof is
    /// decoded (issue #135): `gas::fee_floor` for every action but a call — `BUNDLE_BASE` for a
    /// transfer, a bond, a burn's base; `BUNDLE_BASE + deploy_fee(words)` for a Deploy;
    /// `BRIDGE_BURN_FEE` for a `BridgeBurn` — and for a `Call` or `Invoke` the tier-exact floor:
    /// under a `gas` section `gas_call_floor` at the proof's declared `GAS_LIMIT` (never the
    /// pre-verify floor at a limit of 1), without one the tier schedule `BUNDLE_BASE +
    /// call_fee(tier, bytes)`, and an invoke's cell fee on top.
    ///
    /// One function for the check and the burn: `validate_inner` holds a call's fee to it after
    /// decoding, and under `fees.burn_floor` `apply_tx_with` burns `min(fee, settled_floor)` — so
    /// the burned amount can never be a figure the fee was not checked against. `call` is the
    /// decoded outcome (`Verified::call`); a call passed `None` gets its pre-verify `fee_floor`,
    /// which is not its settled floor. A registration's `registration_fee` is not part of this
    /// floor (`fee_floor` is the plain base for `RegisterToken` and `RegisterBridgedToken`): it is
    /// checked by `tokens::validate` / `bridge_gov::validate` and, under TOK-2, burned separately
    /// (`registration_burn`) before the split sees the fee. It reads the gas prices and the program
    /// cells *now*, so it is exact only against the ledger the transaction is being validated or
    /// applied on: the prices move at `close_block` under `gas.dynamic`, and an applied invoke's
    /// cells exist.
    ///
    /// On an aggregating chain under `fees.prove_base` (`docs/compute-optimization.md` §6.3) the
    /// floor is all of the above plus [`Ledger::prove_base`], and the pre-verify floor rises by the
    /// same amount. `prove_base` is proving share: it is bucketed whole and **never burned** —
    /// under `fees.burn_floor` the burned amount is this floor *without* `prove_base`
    /// (`burnable_floor`), which `fee_burn` asserts.
    pub fn settled_floor(&self, tx: &Transaction, call: Option<&crate::program::CallOutcome>) -> u64 {
        self.burnable_floor(tx, call).saturating_add(self.prove_base())
    }

    /// [`Ledger::settled_floor`] without `prove_base`: the part of the floor `fees.burn_floor`
    /// destroys.
    fn burnable_floor(&self, tx: &Transaction, call: Option<&crate::program::CallOutcome>) -> u64 {
        match (&tx.action, call) {
            (Action::Call { proof, input_envelope, .. } | Action::Invoke { proof, input_envelope, .. }, Some(outcome)) => {
                let bytes = gas::call_bytes(proof, input_envelope.as_ref());
                // Spec §4.2 (cs8): under the `gas` section the declared limit at the prices in
                // force plus the bytes — the tier floor is gone on such a chain. Without the
                // section, the tier schedule byte for byte. An invoke adds its cell fee (zero for
                // a call, and for an invoke that creates no cell).
                self.gas_call_floor(outcome.gas_limit, bytes)
                    .unwrap_or_else(|| gas::BUNDLE_BASE + gas::call_fee(outcome.tier, bytes))
                    .saturating_add(program_state::cell_fee_of(self, &tx.action))
            }
            _ => gas::fee_floor(&tx.action),
        }
    }

    /// What the fee split destroys of a bundle's fee under the genesis `fees` section, `fee`
    /// being what is left after a TOK-2 registration burn: nothing without `burn_base`;
    /// `BUNDLE_BASE` under `burn_base` alone; `min(fee, settled_floor)` under `burn_base` and
    /// `burn_floor` (issue #135). `burn_floor` without `burn_base` burns nothing — genesis refuses
    /// that section, and a ledger handed it anyway runs no rule rather than half of one.
    ///
    /// `prove_base` never burns: the full-floor burn is `min(fee, burnable_floor)`, the settled
    /// floor less `prove_base`, so what is left of the fee after the burn always covers
    /// `prove_base` for a fee that was checked against the settled floor.
    fn fee_burn(&self, tx: &Transaction, fee: u64, call: Option<&crate::program::CallOutcome>) -> u64 {
        match (self.fees.burn_base(), self.fees.burn_floor()) {
            (false, _) => 0,
            (true, false) => gas::BUNDLE_BASE,
            (true, true) => {
                let burn = fee.min(self.burnable_floor(tx, call));
                debug_assert!(
                    fee < self.settled_floor(tx, call) || fee - burn >= self.prove_base(),
                    "burn_floor must leave prove_base to the bucket"
                );
                burn
            }
        }
    }

    /// The genesis `fees.prove_base` in force (`docs/compute-optimization.md` §6.3): the units
    /// every bundle's floor rises by and that are bucketed whole as proving share — on an
    /// aggregating chain only (genesis refuses the field elsewhere), `0` without it.
    pub fn prove_base(&self) -> u64 {
        if self.aggregation.is_some() {
            self.fees.prove_base()
        } else {
            0
        }
    }

    /// What `fees.prove_base` adds to `tx`'s floor: [`Ledger::prove_base`] for a bundle-carrying
    /// transaction, `0` for a bundle-less one (which pays no fee). For the node's pool, whose
    /// selection floors must match the ledger's so `prove_base` is never read as surplus.
    pub fn prove_base_for(&self, tx: &Transaction) -> u64 {
        if tx.bundle.is_some() {
            self.prove_base()
        } else {
            0
        }
    }

    /// The genesis `fees.proposer_share_bps` in force (§6.2): on an aggregating chain only.
    fn proposer_share_bps(&self) -> Option<u32> {
        self.aggregation.as_ref().and(self.fees.proposer_share_bps())
    }

    /// The part of `fee` that never reaches the bucket: the burn when the `fees` section burns
    /// (the base, or the whole floor), else the `BUNDLE_BASE` the proposer keeps at inclusion.
    /// `fee − bucket_floor` is the bucketed excess under every rule. There is deliberately no
    /// public recomputation of that excess from a transaction: a call's floor needs its decoded
    /// proof, and the prices and cells it reads move after the block, so the bucket entry
    /// (`unsealed_fees`, served by `rand_getUnsealed`) and the ledger's own `PaidAggregate` are
    /// the only authorities (IFACE-7).
    fn bucket_floor(&self, tx: &Transaction, fee: u64, call: Option<&crate::program::CallOutcome>) -> u64 {
        if self.fees.burn_base() {
            self.fee_burn(tx, fee, call)
        } else {
            gas::BUNDLE_BASE
        }
    }

    /// Restore the withdrawn aggregators' nonce floors (IFACE-6) a node persisted beside the
    /// register: in the state root once non-empty, so the loader must set them too.
    pub fn set_retired_aggregator_nonces(&mut self, m: BTreeMap<Address, u64>) {
        self.retired_aggregator_nonces = m;
    }

    /// The withdrawn aggregators' nonce floors (IFACE-6): what each address's next registration
    /// starts its nonce at.
    pub fn retired_aggregator_nonces(&self) -> &BTreeMap<Address, u64> {
        &self.retired_aggregator_nonces
    }

    /// What genesis itself created, set once by [`crate::genesis::Genesis::build`]: the deposit
    /// notes in the pool and the stakes in the register. Neither was minted by a transaction,
    /// and together they are the whole of a chain's supply before its first block.
    pub fn set_genesis_supply(&mut self, deposited: u64, staked: u64) {
        self.supply.genesis_deposited = deposited;
        self.supply.genesis_staked = staked;
    }

    /// Σ of the registration fees burned under `tokens.burn_registration_fee` (audit v5, TOK-2):
    /// for the node's persistence beside `META_SUPPLY`, the replay audit and `rand_getSupply`.
    /// 0 without the gate.
    pub fn registration_fees_burned(&self) -> u64 {
        self.registration_fees_burned
    }

    /// Restore the counter a node persisted beside the state — `set_supply`'s twin.
    pub fn set_registration_fees_burned(&mut self, n: u64) {
        self.registration_fees_burned = n;
    }

    /// Σ of the `BUNDLE_BASE`s burned under `fees.burn_base` — the whole floors under
    /// `fees.burn_floor` (`docs/fees.md` §1.3) — for the node's persistence beside `META_SUPPLY`,
    /// the replay audit and `rand_getSupply`. 0 without the flag.
    pub fn base_fees_burned(&self) -> u64 {
        self.base_fees_burned
    }

    /// Restore the counter a node persisted beside the state — `set_registration_fees_burned`'s
    /// twin.
    pub fn set_base_fees_burned(&mut self, n: u64) {
        self.base_fees_burned = n;
    }

    /// The genesis `fees` section (every rule off on a chain without one).
    pub fn fees(&self) -> &fees::FeesConfig {
        &self.fees
    }

    /// Install the `fees` section: genesis from its file, a reloading node from the same file.
    pub fn set_fees(&mut self, fees: fees::FeesConfig) {
        self.fees = fees;
    }

    /// The supply audit against this ledger's own register.
    pub fn audit(&self) -> Audit {
        let audit = Audit::new(
            self.supply,
            register_total(&self.validators).saturating_add(supply::aggregators_total(&self.aggregators)),
            self.registration_fees_burned,
        )
        .with_base_fees_burned(self.base_fees_burned);
        let audit = match &self.vesting {
            Some(v) => audit.with_vesting(v.issued(), v.released, v.in_register()),
            None => audit,
        };
        match &self.program_state {
            Some(p) => audit.with_program_vaults(p.rand_in, p.rand_out),
            None => audit,
        }
    }

    /// Program state (RPL-2), `None` on a chain without the section.
    pub fn program_state(&self) -> Option<&program_state::ProgramState> {
        self.program_state.as_ref()
    }

    /// Install it: genesis from its section, a reloading node from what it persisted.
    pub fn set_program_state(&mut self, p: Option<program_state::ProgramState>) {
        self.program_state = p;
    }

    pub(crate) fn program_state_mut(&mut self) -> Option<&mut program_state::ProgramState> {
        self.program_state.as_mut()
    }

    /// The public segment an `Invoke`'s call proof is made over and verified against (RPL-2,
    /// spec §5): the program's deploy-time public words, this transaction's
    /// [`Transaction::call_binding`], then the transition's context with the bundle's three burn
    /// fields. Built from the transaction alone — never from this ledger's cells — so a proof's
    /// verdict is a function of the transaction's bytes. `None` for any other action or a
    /// bundle-less transaction.
    pub fn invoke_segment(&self, record: &ProgramRecord, tx: &Transaction) -> Option<Vec<u32>> {
        let Action::Invoke { transition, .. } = &tx.action else { return None };
        let b = tx.bundle.as_ref()?;
        Some(program_state::invoke_segment(
            self.program_public(&record.id).unwrap_or(&[]),
            &tx.call_binding(&self.binding_domain),
            &transition.context(b.burn_r, b.burn_asset, b.burn_a),
        ))
    }

    /// The vesting register (genesis vesting), `None` on a chain without the section.
    pub fn vesting(&self) -> Option<&vesting::VestingRegister> {
        self.vesting.as_ref()
    }

    /// Install the register: genesis from its section, a reloading node from what it persisted.
    pub fn set_vesting(&mut self, v: Option<vesting::VestingRegister>) {
        self.vesting = v;
    }

    pub(crate) fn vesting_mut(&mut self) -> Option<&mut vesting::VestingRegister> {
        self.vesting.as_mut()
    }

    /// Deposit notes this ledger created while applying the current block (see [`Deposit`]).
    pub fn deposits(&self) -> &[Deposit] {
        &self.deposits
    }

    /// Take the deposits, leaving the list empty.
    pub fn take_deposits(&mut self) -> Vec<Deposit> {
        std::mem::take(&mut self.deposits)
    }

    /// The aggregates this ledger paid while applying the current block, in transaction order
    /// (see [`aggregation::PaidAggregate`]).
    pub fn paid_aggregates(&self) -> &[aggregation::PaidAggregate] {
        &self.paid_aggregates
    }

    /// Take the paid aggregates, leaving the list empty.
    pub fn take_paid_aggregates(&mut self) -> Vec<aggregation::PaidAggregate> {
        std::mem::take(&mut self.paid_aggregates)
    }

    /// Append a note the ledger computed itself and record it for storage. Fails — before any
    /// mutation — if the commitment is already in the tree.
    pub(crate) fn append_deposit(
        &mut self,
        cm: Word8,
        envelope: Envelope,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        let index = self.tree.try_append(cm, executor).ok_or(TxError::CommitmentTreeFull)?;
        self.deposits.push(Deposit { index, cm, envelope });
        Ok(index)
    }

    /// Height of the block whose transactions are being applied.
    pub fn set_height(&mut self, h: u64) {
        self.height = h;
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    /// Timestamp of the block whose transactions are being applied, in unix milliseconds.
    pub fn set_timestamp_ms(&mut self, t: u64) {
        self.timestamp_ms = t;
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// The block time in unix seconds, which is what the bridge measures guardian-set expiry
    /// and burn message timestamps in.
    pub fn now_secs(&self) -> u64 {
        self.timestamp_ms / 1000
    }

    /// Install (or clear) the bridge state. Genesis calls this once from its `bridge` section;
    /// a reloading node calls it with what storage held.
    pub fn set_bridge(&mut self, bridge: Option<BridgeState>) {
        self.bridge = bridge;
    }

    /// The bridge state, or `None` on a chain without a `bridge` section — where the two bridge
    /// actions are inadmissible and the state root has no fifth component.
    pub fn bridge(&self) -> Option<&BridgeState> {
        self.bridge.as_ref()
    }

    pub fn bridge_mut(&mut self) -> Option<&mut BridgeState> {
        self.bridge.as_mut()
    }

    /// Install (or clear) the RPL token registry. Genesis calls this once from its `tokens`
    /// section; a reloading node calls it with what storage held.
    pub fn set_tokens(&mut self, t: Option<tokens::TokenRegistry>) {
        self.tokens = t;
    }

    /// The token registry, or `None` on a chain without a `tokens` section — where the state
    /// root has no tokens component.
    pub fn tokens(&self) -> Option<&tokens::TokenRegistry> {
        self.tokens.as_ref()
    }

    /// Audit v6 (TOK-1, issue #86): re-applies the genesis `tokens.incremental_root` flag to the
    /// registry a store gave back — a genesis parameter, so the file is the authority, like every
    /// other one `node::reload_ledger` restores. Idempotent; a no-op on a chain without a
    /// registry. A node that came back without it would hash `rand-token-registry-2`/`-3` under
    /// `rand-state-4` … against peers on `rand-state-tokens-1`: a fork at its first block.
    pub fn set_tokens_incremental_root(&mut self, on: bool) {
        if let Some(t) = &mut self.tokens {
            t.set_incremental_root(on);
        }
    }

    /// Switch the incremental nullifier root on or off. On is only ever set on an empty set —
    /// genesis — because the range needs insertion order, which the set does not have; a loaded
    /// chain restores its range with [`Self::set_nullifier_mmr`].
    pub fn set_incremental_nullifier_root(&mut self, on: bool) {
        match (on, &self.nullifier_mmr) {
            (true, None) => {
                assert!(
                    self.nullifiers.is_empty(),
                    "the incremental nullifier root needs insertion order; it can only be switched on at genesis, not over {} existing nullifiers",
                    self.nullifiers.len()
                );
                self.nullifier_mmr = Some(nullifier_mmr::NullifierMmr::new());
            }
            (false, Some(_)) => self.nullifier_mmr = None,
            _ => {}
        }
    }

    /// Install a range a store loaded (spec 2026-10-05 §4): the restore path for a chain whose
    /// genesis set `incremental_nullifier_root`.
    pub fn set_nullifier_mmr(&mut self, mmr: Option<nullifier_mmr::NullifierMmr>) {
        self.nullifier_mmr = mmr;
    }

    /// The nullifier range, when the chain keeps one.
    pub fn nullifier_mmr(&self) -> Option<&nullifier_mmr::NullifierMmr> {
        self.nullifier_mmr.as_ref()
    }

    /// Whether the nullifier slot of the state root holds the incremental range root.
    pub fn incremental_nullifier_root(&self) -> bool {
        self.nullifier_mmr.is_some()
    }

    /// The commit step of the shared sets (spec 2026-10-05 §5.2): the committed ledger's deltas
    /// become base. `HotStuff` calls it once per commit, on the committed ledger only.
    ///
    /// `Ledger` is no longer a value type across commits: a clone that shares the base sees the
    /// entries committed afterwards. Soundness needs that at commit every ledger still held
    /// either descends from the committed block or is a read-only snapshot used for membership
    /// only (admission), for which gaining the committed spends is harmless. The two bases'
    /// write locks are taken one after the other, so a reader on another thread can observe the
    /// commitments committed and the nullifiers not yet; that is harmless under the same
    /// precondition.
    pub fn commit_shared_sets(&mut self) {
        self.commitments.commit();
        self.nullifiers.commit();
    }

    /// Drop delta entries the base gained: every surviving speculative ledger, after a commit.
    pub fn absorb_shared_sets(&mut self) {
        self.commitments.absorb();
        self.nullifiers.absorb();
    }

    /// A private base for this ledger's lineage (`HotStuff::new`): a replica must not share a
    /// base with the genesis state or with another replica in the same process.
    pub fn detach_shared_sets(&mut self) {
        self.commitments.detach();
        self.nullifiers.detach();
    }

    /// The registry to write: a bridged deposit credits a token's supply and a burn debits it
    /// (`bridge_notes::apply`), and a later task's `Action::RegisterToken` and friends mint
    /// through the same handle.
    pub(crate) fn tokens_mut(&mut self) -> Option<&mut tokens::TokenRegistry> {
        self.tokens.as_mut()
    }

    /// The bridge to write *and* the registry to read, in one borrow: an outbound burn needs
    /// both at once (the wire message's `(chain, token)` comes from the token's mint authority)
    /// and `bridge_mut()` beside `tokens()` is two borrows of one `Ledger`, which the borrow
    /// checker will not have.
    ///
    /// Both sections are present together or not at all on any chain genesis builds
    /// (`GenesisError::BridgeNeedsTokens`), so the two errors here are the same "this chain has
    /// no bridge" in practice; they are kept apart so a mis-assembled ledger names which half is
    /// missing rather than blaming the other.
    pub(crate) fn bridge_and_tokens_mut(
        &mut self,
    ) -> Result<(&mut BridgeState, &tokens::TokenRegistry), TxError> {
        match (self.bridge.as_mut(), self.tokens.as_ref()) {
            (Some(bridge), Some(tokens)) => Ok((bridge, tokens)),
            (None, _) => Err(TxError::Bridge(BridgeError::Disabled)),
            (_, None) => Err(TxError::Token(tokens::TokenError::Disabled)),
        }
    }

    /// The consensus signing domain (audit v4): genesis sets it once the genesis block — whose
    /// hash it carries — exists; a reloading node sets it from its genesis file.
    pub fn set_signing_domain(&mut self, domain: crate::types::SigningDomain) {
        self.signing_domain = domain;
    }

    pub fn signing_domain(&self) -> &crate::types::SigningDomain {
        &self.signing_domain
    }

    /// BIND-1 (audit v6): the binding domain. Genesis sets it once the genesis block — whose hash
    /// it carries — exists; a reloading node sets it from its genesis file (`node::reload_ledger`),
    /// because storage does not hold it: a node that came back at `ChainId` on a `binding_domain:
    /// 1` chain would refuse every transaction its peers apply.
    pub fn set_binding_domain(&mut self, domain: crate::types::BindingDomain) {
        self.binding_domain = domain;
    }

    /// What every proof and signed action message on this chain binds ([`Self::set_binding_domain`]).
    pub fn binding_domain(&self) -> &crate::types::BindingDomain {
        &self.binding_domain
    }

    /// Install (or clear) the aggregation section. Genesis calls this once from its
    /// `aggregation` section; a reloading node calls it with what storage held. The register
    /// itself is not touched: it is consensus state, and only the five actions move it.
    pub fn set_aggregation(&mut self, aggregation: Option<aggregation::AggregationConfig>) {
        self.aggregation = aggregation;
    }

    /// The aggregation section, or `None` on a chain without one — where the five aggregation
    /// actions are inadmissible and the state root is byte-for-byte today's.
    pub fn aggregation(&self) -> Option<&aggregation::AggregationConfig> {
        self.aggregation.as_ref()
    }

    /// The largest program a `Deploy` may carry, in words, as genesis set it (default
    /// [`gas::MAX_PROGRAM_WORDS`]).
    pub fn max_program_words(&self) -> usize {
        self.max_program_words
    }

    /// Set by genesis from `max_program_words`, and by `reload_ledger` from the genesis state on
    /// every restart. The bound (`1..=gas::MAX_PROGRAM_WORDS_LIMIT`) is the genesis file's to
    /// enforce; this is only where the ledger keeps what it was told.
    pub fn set_max_program_words(&mut self, words: usize) {
        self.max_program_words = words;
    }

    /// Whether the v0.6 rules are validity rules on this chain (genesis `hardening_v6`; the list is
    /// on the field); `false` on a chain whose file does not say `true`.
    pub fn hardening_v6(&self) -> bool {
        self.hardening_v6
    }

    /// Set by genesis from `hardening_v6`, and by `reload_ledger` on every restart.
    pub fn set_hardening_v6(&mut self, on: bool) {
        self.hardening_v6 = on;
    }

    /// The pinned auth guest (genesis `hc_auth`), or `None` on a chain without split
    /// authorisation — see the field.
    pub fn hc_auth(&self) -> Option<Word8> {
        self.hc_auth
    }

    /// Set by genesis from `hc_auth`, and by `reload_ledger` on every restart.
    pub fn set_hc_auth(&mut self, hc_auth: Option<Word8>) {
        self.hc_auth = hc_auth;
    }

    /// The largest proof a transaction may carry, in bytes, as genesis set it (default
    /// [`gas::MAX_PROOF_BYTES`]).
    /// Audit v6, STAKE-2: whether the genesis says `testnet: true` — the marker a faucet beside
    /// a bridge needs. Served, never judged, here.
    pub fn testnet(&self) -> bool {
        self.testnet
    }

    pub fn set_testnet(&mut self, on: bool) {
        self.testnet = on;
    }

    /// Issue #118: the genesis `proof_window_blocks`, `None` on a chain whose file does not set
    /// it. Served as is by `rand_getLimits`; the rules read [`Ledger::proof_window`].
    pub fn proof_window_blocks(&self) -> Option<u64> {
        self.proof_window_blocks
    }

    /// The window in force, in blocks: how far behind the height a `time` may be and how many
    /// block-end roots are anchors — genesis `proof_window_blocks`, or [`TIME_WINDOW`] (=
    /// [`ANCHOR_WINDOW`]) without it.
    pub fn proof_window(&self) -> u64 {
        self.proof_window_blocks.unwrap_or(TIME_WINDOW)
    }

    /// Set by genesis from `proof_window_blocks`, and by `reload_ledger` on every restart. A
    /// narrower window drops the anchors that fell out of it at once, so the deque never holds
    /// more than the window whichever order a caller sets things in.
    pub fn set_proof_window_blocks(&mut self, window: Option<u64>) {
        self.proof_window_blocks = window;
        self.trim_anchors();
    }

    /// Put back the newest stored block-end roots, oldest first (`reload_ledger`, issue #118):
    /// `Storage::load_ledger` reads [`ANCHOR_WINDOW`] rows, because it does not know the genesis,
    /// so a chain with a wider window re-reads the rest here. Trimmed to the window in force.
    pub fn restore_anchors(&mut self, anchors: Vec<(u64, Word8)>) {
        self.anchors = anchors.into_iter().collect();
        self.trim_anchors();
    }

    fn trim_anchors(&mut self) {
        let window = self.proof_window() as usize;
        while self.anchors.len() > window {
            self.anchors.pop_front();
        }
    }

    pub fn max_proof_bytes(&self) -> usize {
        self.max_proof_bytes
    }

    /// Set by genesis from `max_proof_bytes`, and by `reload_ledger` on every restart. The bound
    /// is the genesis file's to enforce.
    pub fn set_max_proof_bytes(&mut self, bytes: usize) {
        self.max_proof_bytes = bytes;
    }

    /// The largest block, and so the largest transaction, in bytes, as genesis set it (default
    /// [`gas::MAX_BLOCK_BYTES`]).
    pub fn max_block_bytes(&self) -> usize {
        self.max_block_bytes
    }

    /// Set by genesis from `max_block_bytes`, and by `reload_ledger` on every restart.
    pub fn set_max_block_bytes(&mut self, bytes: usize) {
        self.max_block_bytes = bytes;
    }

    /// The largest call input envelope, in bytes, as genesis set it (default
    /// [`crate::types::actions::MAX_CALL_ENVELOPE_BYTES`]).
    pub fn max_call_envelope_bytes(&self) -> usize {
        self.max_call_envelope_bytes
    }

    /// Set by genesis from `max_call_envelope_bytes`, and by `reload_ledger` on every restart.
    pub fn set_max_call_envelope_bytes(&mut self, bytes: usize) {
        self.max_call_envelope_bytes = bytes;
    }

    /// The `Aggregate` action's composite wire cap on this chain: [`gas::MAX_AGGREGATE_BYTES`]
    /// with its proof term at the ledger's `max_proof_bytes` instead of the default, so a proof
    /// the proof cap admits is never refused by the composite cap instead. Today's value on a
    /// chain that does not set `max_proof_bytes`.
    pub fn max_aggregate_bytes(&self) -> usize {
        gas::MAX_AGGREGATE_BYTES - gas::MAX_PROOF_BYTES + self.max_proof_bytes
    }

    /// The largest public input a `Deploy` may fix, in words, as genesis set it (default
    /// [`gas::MAX_PROGRAM_PUBLIC_WORDS`], none).
    pub fn max_program_public_words(&self) -> usize {
        self.max_program_public_words
    }

    /// Set by genesis from `max_program_public_words`, and by `reload_ledger` on every restart.
    pub fn set_max_program_public_words(&mut self, words: usize) {
        self.max_program_public_words = words;
    }

    /// The exact note-envelope size genesis set (`envelope_bytes`, spec 2026-09-26 §2.4), or
    /// `None` on a chain that keeps today's at-most rule.
    pub fn envelope_bytes(&self) -> Option<usize> {
        self.envelope_bytes
    }

    /// Set by genesis from `envelope_bytes`, and by `reload_ledger` on every restart.
    pub fn set_envelope_bytes(&mut self, bytes: Option<usize>) {
        self.envelope_bytes = bytes;
    }

    /// The gas section genesis set (`gas`, design 2026-09-28 §4.2, §4.3, §7.1), or `None` on a
    /// chain whose file does not set one.
    pub fn gas(&self) -> Option<&gas::GasConfig> {
        self.gas.as_ref()
    }

    /// Set by genesis from `gas`, and by `reload_ledger` on every restart (after `load_ledger`
    /// restored the live prices, which this leaves alone — see `gas_prices`). Read by the Phase 2
    /// controller (`close_block`), the state root, the call floor ([`Self::gas_call_floor`]) and
    /// the bundle's pinned gas limit.
    pub fn set_gas(&mut self, g: Option<gas::GasConfig>) {
        self.gas = g;
    }

    /// The live gas prices (spec §7.1): what the controller last moved them to or storage
    /// restored, else the section's own `gas_price`/`byte_price` (the prices a genesis starts
    /// from — the "initialised from the section" case, read lazily so `set_gas`'s place in
    /// `reload_ledger` does not matter), else zero on a chain without a `gas` section.
    pub fn gas_prices(&self) -> gas::GasPrices {
        self.gas_prices.unwrap_or_else(|| {
            self.gas.as_ref().map_or(gas::GasPrices::default(), |g| gas::GasPrices { gas_price: g.gas_price, byte_price: g.byte_price })
        })
    }

    /// Restore the prices a node persisted beside the state (`META_GAS_PRICES`) — `set_supply`'s
    /// twin.
    pub fn set_gas_prices(&mut self, p: gas::GasPrices) {
        self.gas_prices = Some(p);
    }

    /// The gas a verified call adds to its block's `gas_used` (spec §7.1): its declared
    /// `GAS_LIMIT` (`pv::GAS`), the bound it paid for — never the cycle count, which the proof
    /// does not reveal.
    pub fn call_gas_used(outcome: &crate::program::CallOutcome) -> u64 {
        outcome.gas_limit
    }

    /// A call's floor under the `gas` section (spec §4.2, §7.1): `BUNDLE_BASE +
    /// gas_price·gas_limit + byte_price·⌈bytes/1024⌉` at the prices in force at this block's
    /// start ([`Self::gas_prices`]). `None` on a chain without the section, whose tier schedule
    /// ([`gas::call_fee`]) is unchanged. With `gas_limit` 1 it is the pre-verify floor.
    pub fn gas_call_floor(&self, gas_limit: u64, bytes: usize) -> Option<u64> {
        self.gas.as_ref()?;
        let p = self.gas_prices();
        Some(gas::circuit_call_floor(p.gas_price, p.byte_price, gas_limit, bytes))
    }

    /// What a block of `txs` feeds the controller, given the Σ of its calls' gas
    /// (`CallReceiptData::gas_used`): `(bytes_used, gas_used)` = (Σ `encoded_len`, calls' gas +
    /// `bundle_gas_limit` per transaction carrying a bundle proof). One function for the
    /// proposer (`HotStuff::propose`) and the replica (`apply_block_for_sync`), which must agree.
    ///
    /// Audit v6, POOL-2: under `gas.dynamic.byte_load: "paying"` the bytes are only those the
    /// byte price is charged on — each `Call`'s (and RPL-2 `Invoke`'s) proof and input envelope ([`gas::call_bytes`]),
    /// nothing of a transfer, a bond or a burn — so a block of flat-fee transfers moves no byte
    /// price. Absent (chain 18), every transaction's encoded length, as before.
    pub fn block_usage(&self, txs: &[Transaction], call_gas: u64) -> (u64, u64) {
        let bundle_gas = self.gas.as_ref().map_or(0, |g| g.bundle_gas_limit);
        let paying = self.gas.as_ref().and_then(|g| g.dynamic.as_ref()).is_some_and(|d| d.byte_load == Some(gas::ByteLoad::Paying));
        let bytes = txs.iter().fold(0u64, |a, tx| {
            let n = if paying {
                match &tx.action {
                    // An RPL-2 `Invoke` pays the byte price on its call proof as a `Call` does.
                    Action::Call { proof, input_envelope, .. } | Action::Invoke { proof, input_envelope, .. } => {
                        gas::call_bytes(proof, input_envelope.as_ref())
                    }
                    _ => 0,
                }
            } else {
                tx.encoded_len()
            };
            a.saturating_add(n as u64)
        });
        let bundles = txs.iter().filter(|tx| tx.bundle.is_some()).count() as u64;
        (bytes, call_gas.saturating_add(bundles.saturating_mul(bundle_gas)))
    }

    /// The note-envelope rule: exactly `envelope_bytes` when the genesis sets it, else at most
    /// `MAX_ENVELOPE_BYTES` (today's rule, byte for byte).
    fn check_note_envelope(&self, e: &Envelope) -> Result<(), TxError> {
        match self.envelope_bytes {
            Some(want) if e.len() != want => Err(TxError::EnvelopeSize { expected: want, got: e.len() }),
            None if e.len() > MAX_ENVELOPE_BYTES => Err(TxError::EnvelopeTooLarge),
            _ => Ok(()),
        }
    }

    /// The aggregator register (spec §2.1): every row that has ever registered, keyed by
    /// address. Empty on a chain without the section and at chain-9 block 0.
    pub fn aggregators(&self) -> &BTreeMap<Address, aggregation::AggregatorEntry> {
        &self.aggregators
    }

    /// Whether the bridge has already consumed this attestation digest — the `is_spent` of the
    /// bridge's one-shot resource (see [`Transaction::bridge_digests`]). False on a chain
    /// without a bridge, where a `BridgeAttest` is inadmissible for a different reason.
    pub fn is_digest_spent(&self, mu: &Hash) -> bool {
        self.bridge.as_ref().is_some_and(|b| b.spent.contains(mu))
    }

    pub fn tree(&self) -> &CommitmentTree {
        &self.tree
    }

    pub fn root(&self) -> Word8 {
        self.tree.root()
    }

    /// The index the next appended note gets, i.e. the number of notes so far.
    pub fn next_index(&self) -> u64 {
        self.tree.next_index()
    }

    pub fn anchors(&self) -> &VecDeque<(u64, Word8)> {
        &self.anchors
    }

    /// Spec §7 item 4: only a recorded block-end root is an anchor. A root the tree passes
    /// through mid-block is never one, so what a prover may anchor to is exactly what a synced
    /// node can enumerate.
    pub fn is_anchor(&self, root: &Word8) -> bool {
        self.anchors.iter().any(|(_, r)| r == root)
    }

    /// Spec §7 item 5: a `time` is this height at the latest and at most [`TIME_WINDOW`] blocks
    /// behind it — or genesis `proof_window_blocks` (issue #118, [`Ledger::proof_window`]). Three things carry one — a bundle's `time`, which its proof binds the notes it
    /// creates to, a bundle-less `Withdraw`'s (S2) and a `BridgeAttest`'s (S3), each of which the
    /// ledger stamps its derived note with — and all three are a promise about *when* that the
    /// chain has to hold to the same window, or they would drift apart on a chain where only one
    /// of them was checked. Public so the mempool re-checks it with this very function as the
    /// chain scrolls on, rather than re-deriving the rule.
    pub fn time_in_window(&self, time: u32) -> bool {
        let t = time as u64;
        t <= self.height && self.height - t <= self.proof_window()
    }

    fn check_time(&self, time: u32) -> Result<(), TxError> {
        if !self.time_in_window(time) {
            return Err(TxError::TimeOutOfWindow { time, height: self.height, window: self.proof_window() });
        }
        Ok(())
    }

    pub fn nullifiers(&self) -> &SharedSet {
        &self.nullifiers
    }

    pub fn is_spent(&self, nf: &Word8) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Every commitment ever appended, which the frontier tree cannot answer on its own.
    pub fn commitments_set(&self) -> &SharedSet {
        &self.commitments
    }

    pub fn has_commitment(&self, cm: &Word8) -> bool {
        self.commitments.contains(cm)
    }

    pub fn validators(&self) -> &BTreeMap<Address, ValidatorEntry> {
        &self.validators
    }

    pub fn programs(&self) -> &BTreeMap<ProgramId, ProgramRecord> {
        &self.programs
    }

    pub fn program(&self, id: &ProgramId) -> Option<&ProgramRecord> {
        self.programs.get(id)
    }

    /// The public words program `id` was deployed with (issue #55); `None` for a program without
    /// a public input, or one this ledger does not hold.
    pub fn program_public(&self, id: &ProgramId) -> Option<&[u32]> {
        self.program_public.get(id).map(|w| w.as_slice())
    }

    /// Restore the deployed public words (`Storage::load_ledger`, from its `program_public`
    /// column). Each entry must be for a held program and hash to its record's digest, and every
    /// program with a public input must have one — a call under `hardening_v6` is verified over
    /// them, so a node missing them would refuse what its peers accept. Refused whole otherwise,
    /// naming the program.
    pub fn set_program_public(
        &mut self,
        words: BTreeMap<ProgramId, Vec<u32>>,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<(), String> {
        for (id, rec) in &self.programs {
            match (rec.public_digest, words.get(id)) {
                (None, None) => {}
                (Some(d), Some(w)) if w.len() == rec.public_len as usize && executor.public_digest(w) == d => {}
                _ => return Err(format!("program {id}: its stored public words do not match its record")),
            }
        }
        if let Some(id) = words.keys().find(|id| !self.programs.contains_key(*id)) {
            return Err(format!("public words for program {id}, which is not deployed"));
        }
        self.program_public = words;
        Ok(())
    }

    /// The public segment a call against `record` proves over under genesis `hardening_v6`
    /// (INT-4 and its residual, issue #55): the program's deploy-time public words followed by
    /// `binding` (`Transaction::call_binding`) — just the binding for a program without a public
    /// input. The guest reads its public words at the indices it always did.
    pub fn hardened_call_segment(&self, record: &ProgramRecord, binding: &[u32; crate::types::TX_BINDING_WORDS]) -> Vec<u32> {
        crate::program::hardened_call_segment(self.program_public(&record.id).unwrap_or(&[]), binding)
    }

    /// Record the root at the end of block `height`. Idempotent per height: re-recording the
    /// same height replaces that entry rather than filling the window with one block's roots.
    pub fn record_anchor(&mut self, height: u64) {
        let root = self.tree.root();
        if let Some(entry) = self.anchors.iter_mut().find(|(h, _)| *h == height) {
            entry.1 = root;
            return;
        }
        self.anchors.push_back((height, root));
        self.trim_anchors();
    }

    /// Append one note the chain created itself rather than accepted from a bundle: a genesis
    /// alloc note, or the deposit note a `BridgeAttest` mints (spec §10).
    pub fn deposit(&mut self, cm: Word8, executor: &dyn ConfidentialExecutor) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        self.tree.try_append(cm, executor).ok_or(TxError::CommitmentTreeFull)
    }

    /// Write one admitted bundle's notes: its four nullifiers into the spent set, its four
    /// commitments — dummies included — into the set and the tree, in slot order. The write half
    /// of [`Ledger::check_bundle`].
    ///
    /// `check_bundle` established that none of these eight words is already present, and
    /// `validate_inner` that the tree has room (HB-3); the tree-full error is the belt to that.
    fn apply_bundle_notes(&mut self, b: &Bundle, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        for nf in &b.nullifiers {
            if self.nullifiers.insert(*nf) {
                if let Some(m) = &mut self.nullifier_mmr {
                    m.append(nf);
                }
            }
        }
        for cm in &b.commitments {
            self.commitments.insert(*cm);
            self.tree.try_append(*cm, executor).ok_or(TxError::CommitmentTreeFull)?;
        }
        Ok(())
    }

    /// Spec §7 items 4-6 for the bundle: its anchor is live, its `time` is in the window, its
    /// four nullifiers are pairwise distinct and unspent, its four commitments are pairwise
    /// distinct and new. Dummy slots are no exception: a dummy's nullifier is a real nullifier
    /// of a zero-amount note and its commitment a real leaf, so both are held to the same rules.
    ///
    /// What is deliberately *not* here is the burn shape and the fee floor, which depend on the
    /// action (`validate_inner` step 3, and [`tokens::check_asset_burn`] for the two burns).
    fn check_bundle(&self, b: &Bundle) -> Result<(), TxError> {
        if !self.is_anchor(&b.anchor) {
            return Err(TxError::UnknownAnchor { window: self.proof_window() });
        }
        self.check_time(b.time)?;
        if has_duplicate(&b.nullifiers) {
            return Err(TxError::DuplicateNullifierInBundle);
        }
        for nf in &b.nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(TxError::Spent(*nf));
            }
        }
        if has_duplicate(&b.commitments) {
            return Err(TxError::DuplicateCommitmentInBundle);
        }
        for cm in &b.commitments {
            if self.commitments.contains(cm) {
                return Err(TxError::CommitmentExists(*cm));
            }
        }
        Ok(())
    }

    /// The burn shape of the transaction's bundle (the hidden-asset bundle, spec §3.7): which of
    /// `burn_a`, `burn_r` and `burn_asset` this action may set. Pure comparisons.
    ///
    /// - Everywhere first, the canonical RAND burn: `burn_asset == 0 && burn_a > 0` is RAND burned
    ///   through the private-asset slots, which the guest allows (with `A = 0` both of its sums
    ///   are RAND) and the chain refuses ([`TxError::NonCanonicalRandBurn`]). A RAND burn goes
    ///   through `burn_r` only.
    /// - `Bond` and `RegisterAggregator` burn RAND through `burn_r` (exactly the bonded amount /
    ///   the genesis bond) and nothing through `burn_a` or `burn_asset`.
    /// - `TokenBurn` and `BridgeBurn` are checked by [`tokens::check_asset_burn`] in their own
    ///   module, after that module's gate (a chain without `tokens` refuses them `Disabled`
    ///   first): `burn_asset == asset != 0`, `burn_a == amount`, `burn_r == 0`.
    /// - Every other action — a transfer of any asset included — burns nothing: all three zero.
    fn check_burn_shape(&self, action: &Action, b: &Bundle) -> Result<(), TxError> {
        if b.burn_asset == 0 && b.burn_a != 0 {
            return Err(TxError::NonCanonicalRandBurn(b.burn_a));
        }
        // No token burn on an action that burns no token. (`burn_a != 0` with `burn_asset == 0`
        // was refused just above, so the asset is what names the mistake.)
        let no_asset_burn = |b: &Bundle| -> Result<(), TxError> {
            if b.burn_asset != 0 {
                return Err(TxError::UnsupportedAsset(b.burn_asset));
            }
            if b.burn_a != 0 {
                return Err(TxError::UnsupportedBurn(b.burn_a));
            }
            Ok(())
        };
        match action {
            // Phase S2: a `Bond` must burn exactly what it bonds — that is how value leaves the
            // pool and becomes public stake.
            Action::Bond { amount, .. } => {
                no_asset_burn(b)?;
                if b.burn_r != *amount {
                    return Err(StakingError::BurnMismatch { burn: b.burn_r, amount: *amount }.into());
                }
            }
            // Block aggregation: `RegisterAggregator` must burn exactly the genesis bond (spec
            // §2.2) — the `Bond` arm's rule, one register over.
            Action::RegisterAggregator { .. } => {
                no_asset_burn(b)?;
                aggregation::check_burn(self, b.burn_r)?;
            }
            // Their module's rule, after their module's gate (see the doc comment). An RPL-2
            // `Invoke` may set all three: `burn_r` and `burn_a` are what comes into the program's
            // vault (or, for the program's own token, what is destroyed), and
            // `program_state::validate` decides which.
            Action::TokenBurn { .. } | Action::BridgeBurn { .. } | Action::Invoke { .. } => {}
            _ => {
                no_asset_burn(b)?;
                if b.burn_r != 0 {
                    return Err(TxError::UnsupportedBurn(b.burn_r));
                }
            }
        }
        Ok(())
    }

    /// Spec §7 items 8-9 for one bundle: the digest its proof publishes is the digest its
    /// plaintext fields hash to, and the proof verifies against the pinned bundle guest *and*
    /// against `binding`, the [`Transaction::binding`] of the transaction it rides in. This is
    /// the expensive half of admission and runs only after every cheap check of the transaction.
    ///
    /// The binding is what ties a proof to everything its digest does not cover — the action, the
    /// envelopes, the chain id. Without it a copier could keep a transaction's
    /// proofs byte for byte and change the rest (a burn's destination, a bond's validator, an
    /// envelope), and whichever copy committed first would spend the notes.
    ///
    /// `admitted` is the [`VerifiedProofs`] verdict for the transaction the bundle rides in
    /// (audit v3, B5): on a hit the STARK verification is skipped — admission already ran it over
    /// these exact bytes — and the digest compare above still stands, so what is left of this
    /// function is the cheap, deterministic half of it.
    ///
    /// Split authorisation (genesis `hc_auth`, delegated proving Phase 2, spec
    /// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1) adds four checks, each
    /// necessary (`randprotocol-zkvm/tests/hidden_cheating.rs`'s `ledger_rule` shows a cheat that
    /// only it refuses), cheap before expensive: the auth proof is present and the `c` it
    /// publishes (read without verifying) is the bundle's `auth_commit`; the bundle digest
    /// recomputed is the v3 one, over `auth_commit`; then, unless `admitted`, the bundle proof
    /// verifies against the binding and the auth proof verifies against the *same* binding, its
    /// verified `c` again `auth_commit`. On a chain without `hc_auth` both auth fields must be
    /// empty and the digest is the v1 one — today's rule, byte for byte. A pruned bundle keeps its
    /// auth fields (the marker replaces only `proof`), so the sync path runs the same auth checks.
    fn check_bundle_proof(
        &self,
        tx: &Transaction,
        b: &Bundle,
        binding: &[u32; crate::types::TX_BINDING_WORDS],
        executor: &dyn ConfidentialExecutor,
        admitted: bool,
    ) -> Result<(), TxError> {
        self.check_auth_fields(b, executor)?;
        // A pruned bundle (spec §6.2's marker form) carries no proof to check: the covering
        // aggregate — verified when its own block applied — is what this bundle's validity
        // rests on. Two checks stand in for it (spec §7's acceptance, the ledger's half): the
        // proof hash must be one the sync side vouched for, and the bundle's own public fields
        // must hash to the digest the covering aggregate's verified public values commit to —
        // the binding that keeps a peer from substituting the bundle's content.
        //
        // INTERFACE-6: and the record must belong to *this* transaction. There is no proof here,
        // but the record's public values are the covered proof's, verified by the covering
        // aggregate — and their `PUB0..7` is `H_PUB` of the transaction binding that proof was
        // made over. So the binding is checked after all: the record's `PUB` words must be the
        // digest of this transaction's `binding`, and its `tx_hash` this transaction's id. Before,
        // only the certified tx root stood behind the action and envelopes of a pruned transaction
        // (`Transaction::hash` covers both), and a record bound to another transaction's action
        // passed here on a sync peer's word. Two compares and one `H_PUB`, on the sync path only.
        if let Some(proof_hash) = crate::notes::pruned_proof_hash(&b.proof) {
            let Some((record_tx, pv)) = self.pruned_side.get(&proof_hash) else {
                return Err(TxError::InvalidBundleProof(crate::confidential::ConfidentialError::MalformedProof));
            };
            if *record_tx != tx.hash() {
                return Err(TxError::PrunedRecordMismatch("the record names another transaction"));
            }
            let want = self.expected_bundle_digest(b, executor);
            // A short or non-u32 record is a mismatch, never an index past the end: the
            // sync path refuses such a table before it gets here (`MalformedPrunedRecord`),
            // and a store written by an older build gets the same verdict.
            let mut got: Word8 = [0; 8];
            for (k, slot) in got.iter_mut().enumerate() {
                match pv.get(crate::types::pv::OUT0 + k).and_then(|w| u32::try_from(*w).ok()) {
                    Some(w) => *slot = w,
                    None => return Err(TxError::BadDigest),
                }
            }
            if want != got {
                return Err(TxError::BadDigest);
            }
            // After the digest, so a short record is still the `BadDigest` it always was.
            let want_pub = executor.public_digest(binding);
            if (0..8).any(|k| pv.get(crate::types::pv::PUB0 + k).copied() != Some(want_pub[k] as u64)) {
                return Err(TxError::PrunedRecordMismatch("the record's H_PUB is not this transaction's binding"));
            }
            // The auth proof is not covered by the aggregate: verified here, as admission does.
            if !admitted {
                self.verify_auth_proof(b, binding, executor)?;
            }
            return Ok(());
        }
        let published = executor.bundle_proof_digest(&self.hc_bundle, &b.proof).map_err(TxError::InvalidBundleProof)?;
        if published != self.expected_bundle_digest(b, executor) {
            return Err(TxError::BadDigest);
        }
        // Spec §4.3: under the `gas` section every bundle proof declares exactly the genesis
        // `bundle_gas_limit`. A decode, before the verify — a wrong limit must not buy one — and
        // on the verified-set path too, since the value is a statement about these bytes. The
        // verify that follows (or admission's, on a hit) is what makes the decoded value binding.
        if let Some(g) = &self.gas {
            let got = executor.bundle_gas_limit(&b.proof).map_err(TxError::InvalidBundleProof)?;
            if got != Some(g.bundle_gas_limit) {
                return Err(TxError::BundleGasLimit { want: g.bundle_gas_limit, got });
            }
        }
        // B5: the one step a hit on the verified set skips. Everything else about this bundle —
        // the digest just compared, and every structural and stateful check `validate_inner` ran
        // before this function — is checked at apply exactly as at admission. The transaction id
        // binds the auth proof by digest (`rand-txid-3`), so a hit vouches for it too.
        if !admitted {
            executor.verify_bundle(&self.hc_bundle, &b.proof, binding).map_err(TxError::InvalidBundleProof)?;
            self.verify_auth_proof(b, binding, executor)?;
        }
        Ok(())
    }

    /// The digest a bundle's proof must publish: the v3 preimage (`auth_commit` inside) on a
    /// chain whose genesis names `hc_auth`, the v1 one otherwise.
    fn expected_bundle_digest(&self, b: &Bundle, executor: &dyn ConfidentialExecutor) -> Word8 {
        match self.hc_auth {
            Some(_) => executor.bundle_digest_v3(&b.digest_input()),
            None => executor.bundle_digest(&b.digest_input()),
        }
    }

    /// Split authorisation's cheap half: without genesis `hc_auth`, no auth field at all
    /// (`AuthUnexpected`); with it, an auth proof whose published `c` — read, not verified — is
    /// the bundle's `auth_commit` (`AuthMissing`, `InvalidAuthProof`, `AuthMismatch`), and, under
    /// the `gas` section, whose declared `GAS_LIMIT` is exactly the auth guest's ceiling
    /// (`AuthGasLimit`, spec 2026-09-28 §4.3). Every path runs this — admission, apply, a
    /// verified-set hit, a pruned bundle — before either proof's verify, so a wrong limit buys none.
    fn check_auth_fields(&self, b: &Bundle, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        match self.hc_auth {
            None if b.auth_commit != [0; 8] || !b.auth_proof.is_empty() => Err(TxError::AuthUnexpected),
            None => Ok(()),
            Some(_) if b.auth_proof.is_empty() => Err(TxError::AuthMissing),
            Some(_) => {
                let c = executor.auth_proof_digest(&b.auth_proof).map_err(TxError::InvalidAuthProof)?;
                if c != b.auth_commit {
                    return Err(TxError::AuthMismatch);
                }
                if self.gas.is_some() {
                    let want = gas::auth_gas_limit_pin();
                    let got = executor.auth_gas_limit(&b.auth_proof).map_err(TxError::InvalidAuthProof)?;
                    if got != Some(want) {
                        return Err(TxError::AuthGasLimit { want, got });
                    }
                }
                Ok(())
            }
        }
    }

    /// Split authorisation's expensive half: the auth proof verifies against the pinned auth
    /// guest and this transaction's `binding` — the same binding the bundle proof was verified
    /// against — and the `c` it publishes is the bundle's `auth_commit`. Nothing on a chain
    /// without `hc_auth` (`check_auth_fields` has refused any auth field there).
    fn verify_auth_proof(
        &self,
        b: &Bundle,
        binding: &[u32; crate::types::TX_BINDING_WORDS],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<(), TxError> {
        let Some(hc_auth) = self.hc_auth else { return Ok(()) };
        let c = executor.verify_auth(&hc_auth, &b.auth_proof, binding).map_err(TxError::InvalidAuthProof)?;
        if c != b.auth_commit {
            return Err(TxError::AuthMismatch);
        }
        Ok(())
    }

    /// Check a transaction against the current state without applying it. This is admission's
    /// full check — every proof verifies — so it passes [`NoVerified`]: the cache an admission
    /// verification feeds is never what admission itself reads.
    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.validate_inner(tx, executor, &NoVerified).map(|_| ())
    }

    /// Spec §7, in order: cheap before expensive. Returns what it verified so `apply_tx`
    /// verifies each proof and each guardian quorum exactly once.
    ///
    /// `verified_proofs` is the [`VerifiedProofs`] set block application carries (audit v3, B5): a
    /// transaction whose hash it holds skips the STARK verifications — nothing else. `validate`
    /// passes [`NoVerified`]; the apply paths pass what their caller was handed.
    fn validate_inner(
        &self,
        tx: &Transaction,
        executor: &dyn ConfidentialExecutor,
        verified_proofs: &dyn VerifiedProofs,
    ) -> Result<Verified, TxError> {
        // 1. size caps
        //
        // The whole transaction first: a transaction bigger than a block can never be mined, and
        // every per-part cap below can be satisfied by one that is (two proofs at the default
        // 2 MiB cap already exceed the default 4 MiB block). Every cap in this step is the
        // ledger's, as its genesis set it (the call limits, spec §4).
        let encoded_len = tx.encoded_len();
        if encoded_len > self.max_block_bytes {
            return Err(TxError::TransactionTooLarge { size: encoded_len, max: self.max_block_bytes });
        }
        // HB-3: room in the commitment tree for every leaf this transaction may append — a
        // bundle's four, plus the one note the ledger derives for a withdraw, an attestation, a
        // mint, a claim or an aggregate payout ([`MAX_LEAVES_PER_TX`]) — before anything is
        // applied. The tree's `append` `assert!`ed inside block application before this. A
        // comparison; unreachable in practice (four billion leaves).
        if self.tree.remaining() < MAX_LEAVES_PER_TX {
            return Err(TxError::CommitmentTreeFull);
        }
        if let Some(b) = &tx.bundle {
            for e in &b.envelopes {
                self.check_note_envelope(e)?;
            }
            // The split-authorisation auth proof is a proof like any other.
            if b.proof.len() > self.max_proof_bytes || b.auth_proof.len() > self.max_proof_bytes {
                return Err(TxError::ProofTooLarge);
            }
        }
        // The sealed (pruned) marker form is admissible only inside sealed-form sync, where the
        // block's side table vouches for it (`pruned_side`, spec §7). Everywhere else it is
        // refused here, before any proof work, with a verdict that is *not* about the transaction id: the marker form hashes to
        // the raw transaction's id by design (M1), so a cached refusal would censor the honest
        // raw transaction (Task 5b review, fix round 1).
        if let Some(ph) = tx.bundle.as_ref().and_then(|b| crate::notes::pruned_proof_hash(&b.proof)) {
            if !self.pruned_side.contains_key(&ph) {
                return Err(TxError::PrunedFormOutsideSync);
            }
        }
        // Every note envelope an action carries outside the bundle, under the one rule
        // (`check_note_envelope`), ahead of the action's other caps as it always was: each of
        // these arms used to be the first envelope guard its action met. RPL: the envelope
        // sealed against a minted note is a note envelope like any other. The rest of a token
        // action's variable-length fields — name, symbol, salt — are bounded by
        // `check_metadata` at step 7, which costs two length compares.
        match &tx.action {
            Action::Mint { envelope, .. }
            | Action::Withdraw { envelope, .. }
            | Action::WithdrawAggregator { envelope, .. }
            | Action::BridgeAttest { envelope, .. }
            | Action::Aggregate { envelope, .. }
            | Action::TokenMint { envelope, .. }
            // Genesis vesting: a claim's and a revoke's note envelopes, like a withdraw's.
            | Action::ClaimVested { envelope, .. }
            | Action::RevokeVesting { envelope, .. } => self.check_note_envelope(envelope)?,
            Action::RegisterToken { initial: Some(m), .. } => self.check_note_envelope(&m.envelope)?,
            // RPL-2: every note a transition pays out carries a note envelope. The count is
            // capped first, so a transaction cannot buy unbounded envelope checks.
            Action::Invoke { transition, .. } => {
                let payouts = transition.pays.len() + transition.mints.len();
                if payouts > program_state::MAX_PAYOUTS {
                    return Err(program_state::ProgramStateError::TooManyPayouts(payouts).into());
                }
                for p in transition.payouts() {
                    self.check_note_envelope(&p.envelope)?;
                }
            }
            _ => {}
        }
        match &tx.action {
            Action::Deploy { words, .. } if words.len() > self.max_program_words => {
                return Err(TxError::ProgramTooLarge)
            }
            Action::Deploy { public, .. } if public.len() > self.max_program_public_words => {
                return Err(TxError::ProgramPublicTooLarge)
            }
            Action::Call { proof, .. } | Action::Invoke { proof, .. } if proof.len() > self.max_proof_bytes => {
                return Err(TxError::ProofTooLarge)
            }
            Action::BridgeAttest { attestation, .. } if attestation.len() > gas::MAX_ATTESTATION_BYTES => {
                return Err(TxError::AttestationTooLarge)
            }
            // The `Aggregate` action's caps (spec §3.1): the per-field ones every action gets,
            // then the composite wire cap over the transaction's encoding.
            Action::Aggregate { proof, .. } if proof.len() > self.max_proof_bytes => return Err(TxError::ProofTooLarge),
            Action::Aggregate { .. } if encoded_len > self.max_aggregate_bytes() => {
                return Err(TxError::AggregateTooLarge { size: encoded_len, max: self.max_aggregate_bytes() })
            }
            // Audit v6, STAKE-1: two headers with their certificates, and no more (a byte length,
            // before either signature is looked at).
            Action::SlashEquivocation { .. } if encoded_len > staking::MAX_EVIDENCE_BYTES => {
                return Err(StakingError::EvidenceTooLarge { size: encoded_len, max: staking::MAX_EVIDENCE_BYTES }.into())
            }
            _ => {}
        }
        // Every variable-length field that reaches a node before any signature or proof work is
        // capped above, with one exception: a `Call`'s `input_envelope` has its own cap
        // (`max_call_envelope_bytes`, larger than a note envelope's) and is checked in
        // `call_envelope::validate` at step 7. Nothing between here and there reads it.
        // 2. chain id
        if tx.chain_id != self.chain_id {
            return Err(TxError::WrongChain { expected: self.chain_id, actual: tx.chain_id });
        }
        // 3. shape and fee floor
        let bundle: Option<&Bundle> = match (&tx.bundle, tx.action.bundle_less()) {
            (None, Some(_)) => None,
            (None, None) => return Err(TxError::MissingBundle),
            (Some(_), Some(name)) => return Err(TxError::ActionCarriesBundle(name)),
            (Some(b), None) => Some(b),
        };
        if let Some(b) = bundle {
            // The burn shape (the hidden-asset bundle, spec §3.7): which of the three burn fields
            // this action may set. Comparisons only, before anything else about the bundle.
            self.check_burn_shape(&tx.action, b)?;
            // Spec §4.2: under the `gas` section a call's pre-verify floor is the rule at a
            // declared limit of 1 — its bytes are known before any verification, and they are
            // what keeps a verify from being bought for nothing (the byte term replaces
            // `CALL_BASE` in that role). Every other action, and every chain without the
            // section, keeps `fee_floor`.
            let min = match &tx.action {
                Action::Call { proof, input_envelope, .. } | Action::Invoke { proof, input_envelope, .. } => self
                    .gas_call_floor(1, gas::call_bytes(proof, input_envelope.as_ref()))
                    .unwrap_or_else(|| gas::fee_floor(&tx.action)),
                _ => gas::fee_floor(&tx.action),
            }
            // `fees.prove_base` (§6.3) raises every bundle's floor on an aggregating chain; zero
            // on every other chain.
            .saturating_add(self.prove_base());
            if b.fee < min {
                return Err(TxError::FeeTooLow { min, fee: b.fee });
            }
            // 4-6. anchor, time, nullifiers and commitments
            self.check_bundle(b)?;
        }
        // A bundle-less `Withdraw` carries a `time` of its own — the note's, which the sealing
        // node chose — and it is held to the same window by the same rule; a `WithdrawAggregator`'s
        // note time is its twin, one register over. Checked here, at the step a bundle's time is
        // checked, so a stale one is refused before any signature work.
        if let Action::Withdraw { time, .. }
        | Action::WithdrawAggregator { time, .. }
        | Action::Mint { time, .. }
        | Action::ClaimVested { time, .. }
        | Action::RevokeVesting { time, .. } = &tx.action
        {
            self.check_time(*time)?;
        }
        // 7. action-specific cheap checks
        let mut verified = Verified::default();
        let mut call_record = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, pk, time, r, envelope, amount, minter, signature } => {
                if !self.faucet {
                    return Err(TxError::FaucetDisabled);
                }
                if *amount > FAUCET_MAX_UNITS {
                    return Err(TxError::MintTooLarge { amount: *amount, cap: FAUCET_MAX_UNITS });
                }
                // STAKE-2 rule 2: the epoch's budget, after the per-mint cap and before any
                // signature work. The counter is read as of the ledger's own epoch — a counter
                // left from an earlier epoch reads as zero.
                if let Some(s) = &self.staking {
                    let minted = if self.faucet_epoch == self.epoch() { self.faucet_minted_in_epoch } else { 0 };
                    if minted.saturating_add(*amount) > s.faucet_budget_per_epoch {
                        return Err(TxError::FaucetBudgetExhausted { budget: s.faucet_budget_per_epoch, minted });
                    }
                    // The allowlist (chain 15): the published opening's `pk` is the note's owner —
                    // the value rule below ties `cm` to it — so a key off the list gets nothing.
                    if let Some(list) = &s.faucet_recipients {
                        if !list.iter().any(|r| r.0 == *pk) {
                            return Err(TxError::FaucetRecipientNotAllowed);
                        }
                    }
                }
                let addr = minter.address();
                if !self.validators.contains_key(&addr) {
                    return Err(TxError::MinterNotValidator(addr));
                }
                // RESCAN-LEDGER-1, under `staking.faucet_minters` only: a register row is not
                // enough — a permissionless `Bond` writes one, and the key is active two epochs
                // later — so the minter must be on the genesis list. Before the signature, like
                // the row check. Chain 15 has no list and runs on the node's admission policy.
                if let Some(list) = self.staking.as_ref().and_then(|s| s.faucet_minters.as_ref()) {
                    if !list.iter().any(|m| m.0 == addr) {
                        return Err(TxError::MinterNotAllowed(addr));
                    }
                }
                let signing_hash = self.binding_domain.mint_signing_hash(tx.chain_id, cm, pk, *time, r, envelope, *amount);
                if !minter.verify(signing_hash.as_bytes(), signature) {
                    return Err(TxError::BadMintSignature);
                }
                // The value rule (audit v3, POOL-1): the note the tree gains is worth exactly the
                // `amount` the supply counts. A validator's signature is not enough — it signs
                // whatever `cm` it likes — so the ledger derives the commitment itself.
                if mint_commitment(executor, pk, *amount, *time, r) != *cm {
                    return Err(TxError::MintCommitmentMismatch);
                }
                if self.commitments.contains(cm) {
                    return Err(TxError::CommitmentExists(*cm));
                }
            }
            Action::Deploy { base_pc, words, public } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                // CPU-1, under genesis `hardening_v6`: a program no call can hold — past the call
                // tier cap's Poseidon2 budget, less the digests every proof pays first — would be
                // charged `deploy_fee` and never be callable. A comparison against the executor's
                // bound, before it decodes a word. Without the flag this is the node's pool policy
                // only (`admission::deploy_uncallable`), and a block carrying such a deploy
                // applies as before.
                //
                // Under the flag every call carries the call binding (INT-4) after the program's
                // public input (issue #55), `public.len() + TX_BINDING_WORDS` words, so that is the
                // segment the bound is taken against.
                if self.hardening_v6 {
                    let segment = public.len() + crate::types::TX_BINDING_WORDS;
                    if let Some(max_words) = executor.max_callable_program_words(segment) {
                        if words.len() > max_words {
                            return Err(TxError::ProgramUncallable { words: words.len(), public_words: public.len(), max_words });
                        }
                    }
                }
                // ZKV-11, under genesis `hardening_v6`: the padded program table must end at
                // or below the u32 pc wrap, or no honest proof of the program can verify
                // (`program::pc_window_fits`). A comparison, so before the executor decodes a
                // word. Without the flag this is admission policy only (the node's
                // `admission::deploy_outside_pc_window`), and a block carrying such a deploy
                // applies as before.
                if self.hardening_v6 && !crate::program::pc_window_fits(*base_pc, words.len()) {
                    return Err(TxError::BadProgram(crate::program::pc_window_error()));
                }
                executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
            }
            Action::Call { program, input_envelope, .. } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                call_envelope::validate(input_envelope, self.max_call_envelope_bytes)?;
                call_record = Some(self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?);
            }
            // RPL-2. Gated absolutely on the `program_state` genesis section, which
            // `program_state::validate` checks before anything else it does; then the
            // transition's own rules, the vault, the cells read and the payout notes. The cell
            // fee is decided here, before either proof: it is a ledger fact like a registration
            // fee, and a transaction that cannot pay it buys no verification.
            a @ Action::Invoke { program, input_envelope, .. } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
                }
                call_envelope::validate(input_envelope, self.max_call_envelope_bytes)?;
                program_state::validate(self, tx, a, executor)?;
                let min = gas::BUNDLE_BASE.saturating_add(program_state::cell_fee_of(self, a)).saturating_add(self.prove_base());
                if tx.fee() < min {
                    return Err(TxError::FeeTooLow { min, fee: tx.fee() });
                }
                call_record = Some(self.programs.get(program).ok_or(TxError::UnknownProgram(*program))?);
            }
            // `AdmitValidator` (audit v6, STAKE-2) is the register's too: gated on
            // `staking.admission_by_vote`, which `staking::validate` checks before anything else.
            a @ (Action::Bond { .. }
            | Action::Unbond { .. }
            | Action::Withdraw { .. }
            | Action::AdmitValidator { .. }
            | Action::SlashEquivocation { .. }) => {
                staking::validate(self, tx, a, executor)?;
            }
            a @ (Action::ClaimVested { .. }
            | Action::RevokeVesting { .. }
            | Action::BondVested { .. }
            | Action::UnbondVested { .. }) => {
                vesting::validate(self, tx, a, executor)?;
            }
            a @ (Action::BridgeAttest { .. } | Action::BridgeBurn { .. }) => {
                verified.attestation = bridge_notes::validate(self, tx, a, executor)?;
            }
            a @ (Action::RegisterAggregator { .. }
            | Action::UnbondAggregator { .. }
            | Action::WithdrawAggregator { .. }
            | Action::SlashAggregator { .. }) => {
                aggregation::validate(self, tx, a, executor)?;
            }
            // RPL (spec §4). Gated absolutely on the `tokens` genesis section, which
            // `tokens::validate` checks before anything else it does.
            a @ (Action::RegisterToken { .. }
            | Action::TokenMint { .. }
            | Action::SetAuthority { .. }
            | Action::TokenBurn { .. }) => {
                tokens::validate(self, tx, a, executor)?;
            }
            // Bridge hardening B1/B4: the pause and its lifting, and listing after genesis — gated
            // on the `bridge` section. Bridge rules v2: the two rotations, gated on `rules_v2`.
            a @ (Action::PauseMints { .. }
            | Action::UnpauseMints { .. }
            | Action::RegisterBridgedToken { .. }
            | Action::ListBacking { .. }
            | Action::RotatePqGuardians { .. }
            | Action::RotatePauseKey { .. }
            | Action::RotatePqGuardiansV2 { .. }
            | Action::RotatePauseKeyV2 { .. }
            | Action::CancelRotation { .. }) => {
                bridge_gov::validate(self, tx, a)?;
            }
            Action::Aggregate { .. } => {
                // The covered bundles' records live in node storage, which the ledger cannot
                // see: admission and application of an aggregate run through
                // [`Ledger::validate_aggregate`] / [`Ledger::apply_aggregate`], and a proposer's
                // trial apply takes this arm until Task 6 wires the covered pre-pass into
                // `apply_block`.
                return Err(TxError::AggregateNeedsCovered);
            }
        }
        // 7b. under genesis `hardening_v6`, the canonical-proof rules (INT-5, VERIFIER-1/-2): a
        // header or transcript field the honest prover would not write — one the verifier accepts
        // at any value, so a relayer can re-encode the proof into a second transaction id — is
        // refused before either proof is looked at. A decode and a few compares, so it runs on
        // the verified-set path too. Without the flag it is the node's pool policy only
        // (`admission::non_canonical_proofs`) and a block carrying such a proof applies.
        if self.hardening_v6 {
            if let Some(e) = non_canonical_proofs(tx, &|p| executor.non_canonical_proof(p)) {
                return Err(e);
            }
        }
        // 8-9. the bundle's digest, then its proof, against this transaction's binding. Every
        // cheap check (a burn's in step 7's arm for its action) has run by now. B5: one query of
        // the verified set covers both this and the call's proof below, and is skipped entirely
        // on the `NoVerified` paths — an empty set is not worth hashing the transaction for.
        let admitted = !verified_proofs.is_empty() && verified_proofs.contains(&tx.hash());
        if let Some(b) = bundle {
            let binding = tx.binding(&self.binding_domain);
            self.check_bundle_proof(tx, b, &binding, executor, admitted)?;
        }
        // 10. the call's own proof, then its fee: the tier's, and the byte term for proof and
        // envelope bytes past the free allowance (spec §7)
        if let (Some(record), Action::Call { proof, .. } | Action::Invoke { proof, .. }) = (call_record, &tx.action)
        {
            // B5: on a verified-set hit the proof is decoded, not verified — admission's
            // `verify_call` over these same bytes already ran, and the outcome the tier's fee
            // floor and the receipt are read from is the one it computed.
            //
            // INT-4, under genesis `hardening_v6`: the proof must carry this transaction's
            // `call_binding` as its public segment when the program has none of its own, so a copy
            // under another fee bundle is refused (`verify_call_hardened`). Without the flag the
            // old rule, the empty segment, stands.
            //
            // Issue #55 (INT-4's residual): a program deployed with a public input is bound too —
            // its segment is `public ‖ call_binding`, the words this ledger kept at deploy
            // (`hardened_call_segment`). Before, it kept its recorded digest alone and a copy of the
            // proof verified under any fee bundle.
            //
            // RPL-2: an `Invoke`'s segment is `public ‖ call_binding ‖ context` (`invoke_segment`),
            // built from the transaction alone, so the verified set's verdict stands for it as it
            // does for a call: what depends on this ledger's state — the cells read — was compared
            // in step 7 and is never inside the proof's verdict.
            let outcome = match self.invoke_segment(record, tx) {
                Some(segment) if admitted => executor.decode_invoke(record, proof, &segment),
                Some(segment) => executor.verify_invoke(record, proof, &segment),
                None => {
                    let segment =
                        if self.hardening_v6 { self.hardened_call_segment(record, &tx.call_binding(&self.binding_domain)) } else { Vec::new() };
                    match (self.hardening_v6, admitted) {
                        (true, true) => executor.decode_call_hardened(record, proof, &segment),
                        (true, false) => executor.verify_call_hardened(record, proof, &segment),
                        (false, true) => executor.decode_call(record, proof),
                        (false, false) => executor.verify_call(record, proof),
                    }
                }
            }
            .map_err(TxError::InvalidProof)?;
            // The tier-exact floor (`settled_floor`: the gas rule at the declared limit, or the
            // tier schedule, plus an invoke's cell fee) — the one function `fees.burn_floor`
            // burns by, so the burned amount is always a figure the fee was checked against.
            let min = self.settled_floor(tx, Some(&outcome));
            let fee = tx.fee();
            if fee < min {
                return Err(TxError::FeeTooLow { min, fee });
            }
            verified.call = Some(outcome);
        }
        Ok(verified)
    }

    /// Validate and apply one transaction; for calls, return the receipt data. The bundle fee
    /// is credited to `proposer`'s validator entry.
    pub fn apply_tx(
        &mut self,
        tx: &Transaction,
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Option<CallReceiptData>, TxError> {
        self.apply_tx_with(tx, proposer, executor, &NoVerified)
    }

    /// `apply_tx` against a [`VerifiedProofs`] set (audit v3, B5): the proposer's trial apply
    /// and the consensus apply path carry the node's admission cache; everything else takes
    /// `apply_tx` and verifies every proof, exactly as before. The same path as
    /// [`Ledger::apply_tx_checked`], with the refused / half-applied distinction dropped.
    pub fn apply_tx_with(
        &mut self,
        tx: &Transaction,
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
        verified_proofs: &dyn VerifiedProofs,
    ) -> Result<Option<CallReceiptData>, TxError> {
        self.apply_tx_checked(tx, proposer, executor, verified_proofs).map_err(ApplyFailure::into_inner)
    }

    /// The one apply path, telling the proposer how a candidate failed (final review F1).
    /// Everything up to the first write — `validate_inner`, then the proposer lookup and the
    /// fee arithmetic the bundle step computes before it touches the supply — fails as
    /// [`ApplyFailure::Refused`] and leaves the ledger byte-identical; every error after the
    /// first write is [`ApplyFailure::HalfApplied`]. `HotStuff::propose` skips a refusal for
    /// free and rebuilds only after a half-apply (spec 2026-10-05, plan correction 2).
    pub fn apply_tx_checked(
        &mut self,
        tx: &Transaction,
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
        verified_proofs: &dyn VerifiedProofs,
    ) -> Result<Option<CallReceiptData>, ApplyFailure> {
        let verified = self.validate_inner(tx, executor, verified_proofs).map_err(ApplyFailure::Refused)?;
        let split = match &tx.bundle {
            Some(b) => Some(self.bundle_fee_split(tx, b, proposer, verified.call.as_ref()).map_err(ApplyFailure::Refused)?),
            None => None,
        };
        self.apply_validated(tx, proposer, executor, verified, split).map_err(ApplyFailure::HalfApplied)
    }

    /// The bundle step's arithmetic, computed before any write so that its errors are clean
    /// refusals: the burned registration fee (TOK-2), the fee left after it, the burned base or
    /// floor (`fees.burn_base` / `fees.burn_floor`), the part the proposer keeps now, and the
    /// proposer's `rewards` once it is credited. `call` is the decoded call outcome
    /// (`Verified::call`), which `settled_floor` reads.
    fn bundle_fee_split(
        &self,
        tx: &Transaction,
        b: &Bundle,
        proposer: &Address,
        call: Option<&crate::program::CallOutcome>,
    ) -> Result<BundleFeeSplit, TxError> {
        // In practice the proposer is always in the register — `apply_block` rejects a
        // block whose proposer is not, and `HotStuff::propose` runs only when this node
        // is the leader.
        let entry = self.validators.get(proposer).ok_or(TxError::UnknownProposer(*proposer))?;
        // TOK-2 (audit v5): under `tokens.burn_registration_fee` a registration's
        // `registration_fee` is burned rather than paid, so the proposer pays it like anyone
        // else — the fee the split below divides is what is left after it. Zero without the
        // gate (chain 14) and for every action that registers no token. The floor
        // (`tokens::validate`'s `RegistrationFeeTooLow`) already held `fee` to at least
        // `BUNDLE_BASE + registration_fee`, so the subtraction cannot fail after
        // `validate_inner`; refused by name rather than as an overflow if it ever did.
        let registration_burn = self.registration_burn(&tx.action);
        let fee = b.fee.checked_sub(registration_burn).ok_or_else(|| {
            tokens::TokenError::RegistrationFeeTooLow { min: gas::BUNDLE_BASE.saturating_add(registration_burn), fee: b.fee }
        })?;
        // The fee split (block aggregation, spec §5.2): on an aggregating chain the
        // proposer keeps exactly the floor and the excess is bucketed against this
        // transaction's hash — an `Aggregate` may still cover it — where an ungated chain
        // keeps the whole fee to the proposer, byte-for-byte today's accounting. The
        // counter moves with what the proposer actually keeps: the floor now, an expired
        // excess at the sweep (`sweep_expired_excesses`), never the bucketed part.
        //
        // Fee feedback (`fees.burn_base`, `docs/fees.md` §1.3): the base is destroyed instead
        // of kept — `burned` and `base_fees_burned` move by it in `apply_validated` — so the
        // proposer keeps `fee − BUNDLE_BASE`, the tip, on an ungated chain and nothing at
        // inclusion on an aggregating one, whose excess is bucketed exactly as without the flag.
        // Only the base burns, never a Call's priced terms: it is the one part every bundle pays
        // and no proposer can steer. The floor (`validate_inner`) already held `fee` to at least
        // `BUNDLE_BASE`; refused by name rather than wrapped if it ever did not.
        //
        // Under `fees.burn_floor` as well (issue #135, the full EIP-1559 form) the burn is the
        // bundle's whole settled floor, `min(fee, settled_floor)` — a Deploy's per-word term,
        // a Call's tier-exact gas and byte terms (`settled_floor`, the very figure
        // `validate_inner` held the fee to after decoding, read off `verified.call`) — so a
        // proposer gains nothing from a block that lifts a price. The proposer keeps (or the
        // bucket holds) `fee − burn`, the tip, in the same four cells below; the `min` only
        // restates what the check already guarantees. All of it is computed here, before the
        // first write, so a refusal leaves the ledger byte-identical (`ApplyFailure::Refused`).
        if self.fees.burn_base() && fee < gas::BUNDLE_BASE {
            return Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee });
        }
        let fee_burned = self.fee_burn(tx, fee, call);
        let kept_base = match (self.aggregation.is_some(), self.fees.burn_base()) {
            (false, false) => fee,
            (true, false) => gas::BUNDLE_BASE.min(fee),
            (false, true) => fee.saturating_sub(fee_burned),
            (true, true) => 0,
        };
        // The proposer/aggregator split (`fees.proposer_share_bps`, `docs/compute-optimization.md`
        // §6.2), an aggregating chain's rule: of the base the proposer keeps above (`BUNDLE_BASE`,
        // or nothing under `burn_base` — a burned base has no share to split) it keeps
        // `proposer_share_bps / 10 000`, and the remainder is bucketed beside the excess, where a
        // covering aggregate is paid it and the sweep returns it to the proposer. The aggregator's
        // part rounds down, so the proposer's is the remainder-free one: `kept_base −
        // ⌊kept_base · (10 000 − bps) / 10 000⌋`. Genesis bounds `bps` at 10 000; `min` restates it.
        let base_bucketed = match self.proposer_share_bps() {
            Some(bps) => {
                let bps = u128::from(bps.min(10_000));
                u64::try_from(u128::from(kept_base) * (10_000 - bps) / 10_000).expect("at most kept_base")
            }
            None => 0,
        };
        let kept = kept_base - base_bucketed;
        let rewards = entry.rewards.checked_add(kept).ok_or(TxError::Overflow)?;
        Ok(BundleFeeSplit { registration_burn, fee, fee_burned, kept, rewards, base_bucketed })
    }

    /// Everything after the first write: the bundle's supply counters and notes, then the
    /// action step. `split` is [`Ledger::bundle_fee_split`]'s result, present exactly when the
    /// transaction carries a bundle.
    fn apply_validated(
        &mut self,
        tx: &Transaction,
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
        verified: Verified,
        split: Option<BundleFeeSplit>,
    ) -> Result<Option<CallReceiptData>, TxError> {
        if let (Some(b), Some(BundleFeeSplit { registration_burn, fee, fee_burned, kept, rewards, base_bucketed })) = (&tx.bundle, split) {
            // This method is not atomic on its own: the action step below runs after these
            // writes and can still fail (S2's `staking::apply`, S3's `bridge_notes::apply`),
            // which would leave a half-applied bundle behind. What makes a rejected
            // transaction leave the ledger byte-identical is the caller: `apply_transactions`
            // applies every transaction to a scratch clone and only assigns it back once the
            // whole block succeeded. Call `apply_tx` on a ledger you are willing to discard;
            // the proposer, which applies in place, learns which case it hit through
            // `apply_tx_checked`'s [`ApplyFailure`].
            // Both RAND halves of what this bundle takes out of the pool (see [`supply`]): the
            // fee becomes the proposer's `rewards` below, and `burn_r` becomes `stake` in the
            // `Bond` arm (or an aggregator's bond) — which is why they are counted here, where
            // every bundle passes, rather than in the arms that receive them. `burn_a` is never
            // RAND (`check_burn_shape` refuses a RAND `burn_a`): it leaves a token's own
            // `total_supply` in the burn's arm and has no place in the RAND audit. The burned
            // registration fee (TOK-2) and, under `fees.burn_base`, the bundle base are the other
            // RAND exits: destroyed, so they join `burned` beside `burn_r`.
            self.supply.fees_paid = self.supply.fees_paid.checked_add(kept).ok_or(TxError::Overflow)?;
            self.supply.burned = self
                .supply
                .burned
                .checked_add(b.burn_r)
                .and_then(|n| n.checked_add(registration_burn))
                .and_then(|n| n.checked_add(fee_burned))
                .ok_or(TxError::Overflow)?;
            self.registration_fees_burned =
                self.registration_fees_burned.checked_add(registration_burn).ok_or(TxError::Overflow)?;
            self.base_fees_burned = self.base_fees_burned.checked_add(fee_burned).ok_or(TxError::Overflow)?;
            self.apply_bundle_notes(b, executor)?;
            self.validators.get_mut(proposer).expect("looked up in bundle_fee_split").rewards = rewards;
            if self.aggregation.is_some() {
                let until = self.height.checked_add(self.aggregation().expect("just checked").window).ok_or(TxError::Overflow)?;
                // Every bundle is recorded, excess or not: the bucket doubles as the ledger's
                // coverable set (the pre-v0.1 review's H1) — an aggregate may name a cover only
                // while its entry stands, and the entry leaves at the covering aggregate or at
                // the sweep, never to return. The key is the transaction hash an aggregate's
                // covers name; a pruned bundle's marker form hashes to the same value
                // (`Transaction::hash` takes the proof by digest), so the sealed-sync replay
                // keys byte-identically without consulting the side table.
                // The excess is over what is left after the burned registration fee (TOK-2) —
                // `fee − registration_fee − BUNDLE_BASE`, never below zero — and under
                // `fees.burn_floor` over the whole burned floor, `fee − burn` (issue #135), so the
                // aggregator is never paid a priced term the chain just destroyed.
                // `bucket_floor` is the one place that figure is computed.
                // Under `fees.proposer_share_bps` the aggregator's part of the base rides in the same
                // entry (§6.2): one entry per bundle, `excess + base part`, resolved whole by the
                // cover or the sweep. `fees.prove_base` needs nothing here: it is part of `fee`
                // above `bucket_floor` (which never includes it), so it is bucketed whole.
                let excess = fee
                    .saturating_sub(self.bucket_floor(tx, fee, verified.call.as_ref()))
                    .checked_add(base_bucketed)
                    .ok_or(TxError::Overflow)?;
                self.bucket_excess(tx.hash(), excess, *proposer, until);
            }
        }
        let mut receipt = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, amount, .. } => {
                self.supply.faucet_minted =
                    self.supply.faucet_minted.checked_add(*amount).ok_or(TxError::Overflow)?;
                // The epoch counter, only under a `staking` section (STAKE-2 rule 2): reset on
                // the ledger's epoch boundary, then added to. `validate_inner` has already held
                // the sum under the budget, and the budget is a `u64`, so this cannot overflow.
                if self.staking.is_some() {
                    let epoch = self.epoch();
                    if self.faucet_epoch != epoch {
                        self.faucet_epoch = epoch;
                        self.faucet_minted_in_epoch = 0;
                    }
                    self.faucet_minted_in_epoch =
                        self.faucet_minted_in_epoch.checked_add(*amount).ok_or(TxError::Overflow)?;
                }
                self.commitments.insert(*cm);
                self.tree.try_append(*cm, executor).ok_or(TxError::CommitmentTreeFull)?;
            }
            Action::Deploy { base_pc, words, public } => {
                let id = program_id_with_public(*base_pc, words, public);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    // Hashed once, here: a call compares its proof's `H_PUB` with this and never
                    // re-hashes the words (spec §5).
                    let public_digest = (!public.is_empty()).then(|| executor.public_digest(public));
                    if !public.is_empty() {
                        self.program_public.insert(id, public.clone());
                    }
                    self.programs.insert(
                        id,
                        ProgramRecord {
                            id,
                            base_pc: *base_pc,
                            words: words.clone(),
                            code_hash,
                            deployed_at: self.height,
                            public_digest,
                            public_len: public.len() as u32,
                        },
                    );
                }
            }
            Action::Call { program, input_envelope, .. } | Action::Invoke { program, input_envelope, .. } => {
                // RPL-2: the transition first — vault, supplies, cells, payout notes — then the
                // receipt, which is a call's. Every refusal was decided by `validate_inner`.
                if let a @ Action::Invoke { .. } = &tx.action {
                    program_state::apply(self, tx, a, executor)?;
                }
                let o = verified.call.expect("validate_inner returns the outcome for calls");
                receipt = Some(CallReceiptData {
                    program: *program,
                    tier: o.tier,
                    outputs: o.outputs,
                    h_in: o.h_in,
                    // The digest the proof was just checked against (`verify_call`).
                    h_pub: self.programs.get(program).and_then(|r| r.public_digest),
                    input_envelope: input_envelope.clone(),
                    gas_used: Ledger::call_gas_used(&o),
                });
            }
            a @ (Action::Bond { .. }
            | Action::Unbond { .. }
            | Action::Withdraw { .. }
            | Action::AdmitValidator { .. }
            | Action::SlashEquivocation { .. }) => {
                // The proposer is passed in because a `Withdraw` pays it the bundle base out of
                // the amount it withdraws — the one fee that does not come from a bundle.
                staking::apply(self, tx, a, proposer, executor)?;
            }
            a @ (Action::ClaimVested { .. }
            | Action::RevokeVesting { .. }
            | Action::BondVested { .. }
            | Action::UnbondVested { .. }) => {
                // A claim and a revoke pay the proposer the base, as a `Withdraw` does.
                vesting::apply(self, tx, a, proposer, executor)?;
            }
            a @ (Action::BridgeAttest { .. } | Action::BridgeBurn { .. }) => {
                bridge_notes::apply(self, tx, a, executor, verified.attestation)?;
            }
            a @ (Action::RegisterAggregator { .. }
            | Action::UnbondAggregator { .. }
            | Action::WithdrawAggregator { .. }
            | Action::SlashAggregator { .. }) => {
                aggregation::apply(self, tx, a, proposer, executor)?;
            }
            a @ (Action::RegisterToken { .. }
            | Action::TokenMint { .. }
            | Action::SetAuthority { .. }
            | Action::TokenBurn { .. }) => {
                tokens::apply(self, tx, a, executor)?;
            }
            a @ (Action::PauseMints { .. }
            | Action::UnpauseMints { .. }
            | Action::RegisterBridgedToken { .. }
            | Action::ListBacking { .. }
            | Action::RotatePqGuardians { .. }
            | Action::RotatePauseKey { .. }
            | Action::RotatePqGuardiansV2 { .. }
            | Action::RotatePauseKeyV2 { .. }
            | Action::CancelRotation { .. }) => {
                bridge_gov::apply(self, tx, a)?;
            }
            Action::Aggregate { .. } => {
                // Unreachable through `validate_inner` (its action arm refuses first); named
                // the same so a direct caller hears where aggregates go.
                return Err(TxError::AggregateNeedsCovered);
            }
        }
        Ok(receipt)
    }

    /// Apply every tx of a block in order, returning `(index, receipt)` for each call.
    /// On any error the ledger is left unchanged. Does not check the header's state root;
    /// see `apply_block`.
    pub fn apply_transactions(
        &mut self,
        txs: &[Transaction],
        proposer: &Address,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        self.apply_transactions_for_sync(txs, proposer, &BTreeMap::new(), &[], executor, &NoVerified)
    }

    /// `apply_transactions` with the covered-bundle records any `Aggregate` among the
    /// transactions needs (see [`Ledger::apply_block_with_covered`]): an `Aggregate` applies
    /// through [`Ledger::apply_aggregate`] — validation, payment and all — and yields no call
    /// receipt; everything else takes `apply_tx` as today.
    pub fn apply_transactions_with_covered(
        &mut self,
        txs: &[Transaction],
        proposer: &Address,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        self.apply_transactions_for_sync(txs, proposer, covered, &[], executor, &NoVerified)
    }

    /// `apply_transactions_with_covered` with the sealed form's side table (spec §7): the
    /// pruned bundles the block carries in marker form, keyed by proof hash for
    /// `check_bundle_proof`'s membership and binding checks. Empty on every path but
    /// sealed-form sync. `verified_proofs` is the [`VerifiedProofs`] set the apply paths carry
    /// (audit v3, B5) — [`NoVerified`] everywhere but the consensus loop's.
    pub fn apply_transactions_for_sync(
        &mut self,
        txs: &[Transaction],
        proposer: &Address,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        pruned: &[crate::consensus::PrunedBundle],
        executor: &dyn ConfidentialExecutor,
        verified_proofs: &dyn VerifiedProofs,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        let mut scratch = self.clone();
        // The deposits reported after a block are exactly that block's (see `Deposit`).
        scratch.deposits.clear();
        scratch.paid_aggregates.clear();
        // A side table is a peer's wire input: every record must be the `pv::NUM`-word list the
        // covering aggregate's admission and the digest check below index into, checked here
        // once, before any transaction is read.
        for p in pruned {
            if p.public_values_array().is_none() {
                return Err(BlockError::MalformedPrunedRecord {
                    tx: p.tx_hash,
                    words: p.public_values.len(),
                    expected: crate::types::pv::NUM,
                });
            }
            // And every word canonical (ZKQ-4): the rVM absorbs them unreduced, so `x + p` would
            // match the covering aggregate's digest in place of `x`, and this node would store and
            // re-serve a record no honest proof ever carried.
            if let Some(index) = p.public_values.iter().position(|w| *w >= crate::types::pv::GOLDILOCKS_ORDER) {
                return Err(BlockError::NonCanonicalPrunedRecord { tx: p.tx_hash, index });
            }
        }
        // INTERFACE-7: one record per proof hash. Collected into a map, a second record under
        // the same hash replaced the first without a word, and which one this node checked,
        // stored and re-served was the sending peer's ordering.
        let mut side = BTreeMap::new();
        for p in pruned {
            if side.insert(p.proof_hash, (p.tx_hash, p.public_values.clone())).is_some() {
                return Err(BlockError::DuplicatePrunedRecord { proof_hash: p.proof_hash });
            }
        }
        scratch.pruned_side = side;
        let mut receipts = Vec::new();
        let mut aggregate_seen = false;
        for (index, tx) in txs.iter().enumerate() {
            if matches!(tx.action, Action::Aggregate { .. }) {
                // Spec §3.4's "at most one" as a block rule: the second is refused by index,
                // before its records are even looked up.
                if std::mem::replace(&mut aggregate_seen, true) {
                    return Err(BlockError::SecondAggregate { index });
                }
                let c = covered
                    .get(&index)
                    .ok_or(BlockError::InvalidTx { index, error: TxError::AggregateNeedsCovered })?;
                scratch.apply_aggregate(tx, c, executor).map_err(|error| BlockError::InvalidTx { index, error })?;
            } else if let Some(r) =
                scratch.apply_tx_with(tx, proposer, executor, verified_proofs).map_err(|error| BlockError::InvalidTx { index, error })?
            {
                receipts.push((index, r));
            }
        }
        // The side table vouches for this block's marker-form proofs and nothing after it: a
        // ledger left holding it would admit a marker-form copy of a later transaction whose proof
        // hash happened to match.
        scratch.pruned_side.clear();
        *self = scratch;
        Ok(receipts)
    }

    /// Full block application: proposer signature, tx root, every tx, the block-end anchor, and
    /// the resulting state root must match the header. Ledger unchanged on error. Returns the
    /// receipts of the block's calls.
    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError> {
        self.apply_block_for_sync(block, &BTreeMap::new(), &[], executor, &NoVerified)
    }

    /// `apply_block` against a [`VerifiedProofs`] set (audit v3, B5): a transaction whose hash
    /// the set holds has its proofs decoded rather than re-verified — admission already verified
    /// them over these exact bytes — while every other check runs as usual. The consensus
    /// loop's apply path carries the node's admission cache; sync, replay and `verify_chain`
    /// take `apply_block` and verify everything.
    pub fn apply_block_with(
        &mut self,
        block: &Block,
        executor: &dyn ConfidentialExecutor,
        verified: &dyn VerifiedProofs,
    ) -> Result<Vec<CallReceipt>, BlockError> {
        self.apply_block_for_sync(block, &BTreeMap::new(), &[], executor, verified)
    }

    /// `apply_block` with the covered-bundle records any `Aggregate` in the block needs (spec
    /// §4's admission, run at apply exactly as at the pool). The ledger has no transaction
    /// store, so the caller assembles them: the node from its store (spec §3.2's coverability),
    /// `verify_chain` from the store it replays. An `Aggregate` without a record is refused at
    /// its index with the T4 signpost error.
    pub fn apply_block_with_covered(
        &mut self,
        block: &Block,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<CallReceipt>, BlockError> {
        self.apply_block_for_sync(block, covered, &[], executor, &NoVerified)
    }

    /// `apply_block_with_covered` with the sealed form's side table (spec §7): the tx root is
    /// checked over the transactions as served — a marker-form transaction hashes to its raw
    /// hash (`Transaction::hash` takes the proof by digest), so the certified root binds every
    /// byte of it but the proof — the table's attested raw hash must agree with that, and
    /// `check_bundle_proof` runs its membership and digest-binding checks against the table.
    /// `verified_proofs` is the [`VerifiedProofs`] set the consensus loop's apply path carries
    /// (audit v3, B5); sync and replay pass [`NoVerified`].
    pub fn apply_block_for_sync(
        &mut self,
        block: &Block,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        pruned: &[crate::consensus::PrunedBundle],
        executor: &dyn ConfidentialExecutor,
        verified_proofs: &dyn VerifiedProofs,
    ) -> Result<Vec<CallReceipt>, BlockError> {
        // Size limits are a consensus rule, not only proposer policy: without them a Byzantine
        // leader can stuff a block up to the gossip transport cap and force every replica to
        // execute it.
        if block.transactions.len() > gas::MAX_BLOCK_TXS {
            return Err(BlockError::TooManyTransactions);
        }
        let mut bytes = 0usize;
        for tx in &block.transactions {
            bytes += tx.encoded_len();
            if bytes > self.max_block_bytes {
                return Err(BlockError::TooLarge);
            }
        }
        if !block.verify_signature(&self.signing_domain) {
            return Err(BlockError::BadProposerSignature);
        }
        // The tx root, over the transactions as served: the same check for the raw and the
        // sealed form, because a marker-form transaction hashes to its raw hash. Nothing a peer
        // changes outside the proof bytes survives it (the pre-v0.1 review's M1).
        if !block.verify_tx_root() {
            return Err(BlockError::TxRootMismatch);
        }
        // The sealed form's side table (spec §7): every marker-form transaction must have its
        // entry, and the entry's attested raw hash must be the hash the root just certified —
        // the table can vouch for a proof, never rename a transaction.
        for (index, tx) in block.transactions.iter().enumerate() {
            let Some(ph) = tx.bundle.as_ref().and_then(|b| crate::notes::pruned_proof_hash(&b.proof)) else { continue };
            let malformed = || BlockError::InvalidTx {
                index,
                error: TxError::InvalidBundleProof(crate::confidential::ConfidentialError::MalformedProof),
            };
            let entry = pruned.iter().find(|p| p.proof_hash == ph).ok_or_else(malformed)?;
            if entry.tx_hash != tx.hash() {
                return Err(malformed());
            }
        }
        let proposer = block.proposer();
        if !self.validators.contains_key(&proposer) {
            return Err(BlockError::UnknownProposer(proposer));
        }
        // Time bounds validity only where it is consensus input, so a chain without a bridge
        // keeps byte-identical validity rules. With one, block time decides guardian-set expiry
        // (`bridge_notes::validate` → `check_attest(.., self.now_secs())`) and stamps outbound
        // burn messages, so a leader that could rewind it could keep a superseded — possibly
        // compromised — set admissible past its grace window. `HotStuff::propose` already emits
        // `max(now_ms, parent.timestamp_ms)`, so no honest leader builds a block this refuses.
        if self.bridge.is_some() && block.header.timestamp_ms < self.timestamp_ms {
            return Err(BlockError::TimestampRewind { parent: self.timestamp_ms, block: block.header.timestamp_ms });
        }
        // B2, the forward bound: a leader cannot leap the clock either (to expire a rotated
        // guardian set's grace window, or skip a mint-cap day). `HotStuff::propose` clamps to
        // `parent + MAX_TIMESTAMP_STEP_MS`, so no honest leader builds a block this refuses.
        if self.bridge.is_some() && block.header.timestamp_ms > self.timestamp_ms.saturating_add(MAX_TIMESTAMP_STEP_MS) {
            return Err(BlockError::TimestampLeap {
                parent: self.timestamp_ms,
                block: block.header.timestamp_ms,
                max_step: MAX_TIMESTAMP_STEP_MS,
            });
        }
        let mut scratch = self.clone();
        scratch.set_height(block.height());
        scratch.set_timestamp_ms(block.header.timestamp_ms);
        let data = scratch.apply_transactions_for_sync(&block.transactions, &proposer, covered, pruned, executor, verified_proofs)?;
        let call_gas = data.iter().fold(0u64, |a, (_, r)| a.saturating_add(r.gas_used));
        let (bytes_used, gas_used) = scratch.block_usage(&block.transactions, call_gas);
        scratch.close_block(block.height(), &proposer, bytes_used, gas_used);
        let computed = scratch.state_root();
        if computed != block.header.state_root {
            // Components, not just the composite: the divergence names the ledger half it
            // lives in (the capstone's mismatch read as opaque before this).
            tracing::warn!(
                "state root mismatch at block {}: computed {computed}, header {} — computed components: {}",
                block.height(),
                block.header.state_root,
                scratch.debug_state_root_components()
            );
            return Err(BlockError::StateRootMismatch { computed, header: block.header.state_root });
        }
        *self = scratch;
        Ok(data
            .into_iter()
            .map(|(index, r)| CallReceipt {
                tx: block.transactions[index].hash(),
                program: r.program,
                tier: r.tier,
                outputs: r.outputs,
                height: block.height(),
                index: index as u32,
                h_in: r.h_in,
                h_pub: r.h_pub,
                input_envelope: r.input_envelope,
            })
            .collect())
    }

    /// The block-end steps, after the last transaction and before the state root: the
    /// proving-share sweep (spec §5.2 — every bucketed excess whose window passed at this head
    /// is credited to its recorded proposer, and the rewards it credits are in the state root;
    /// a no-op on a chain without the section) and the anchor record. One function for both
    /// paths on purpose: the proposer's header root and the replica's recomputed root must come
    /// from the same steps, or the first expired bucket makes every leader reject its own block
    /// (the pre-v0.1 review's L1).
    ///
    /// Phase 2 (spec §7.1): on a chain with `gas.dynamic`, the controller then moves each live
    /// price by this block's fullness — `gas_price` by `gas_used` against `target_block_gas`,
    /// `byte_price` by `bytes_used` against `target_block_bytes` ([`gas::next_price`]) — before
    /// the root, so the header commits to the prices the next block pays. A no-op without it.
    pub fn close_block(&mut self, height: u64, proposer: &Address, bytes_used: u64, gas_used: u64) {
        self.sweep_expired_excesses(height, proposer);
        if let Some(d) = self.gas.as_ref().and_then(|g| g.dynamic.as_ref()) {
            let p = self.gas_prices();
            // Under a ceiling (audit v6, POOL-2) the step is the same and then clamped; without
            // one `next_price_capped` is `next_price` exactly.
            self.gas_prices = Some(gas::GasPrices {
                gas_price: gas::next_price_capped(p.gas_price, d.min_gas_price, d.max_gas_price(), gas_used, d.target_block_gas, d.adjust_bps),
                byte_price: gas::next_price_capped(p.byte_price, d.min_byte_price, d.max_byte_price(), bytes_used, d.target_block_bytes, d.adjust_bps),
            });
        }
        // The last block of an epoch admits the bond queue's due stake for the next one, before
        // the root: the next epoch's set is derived from exactly this ledger
        // (`HotStuff::shared_set_for_height`, the sync paths), so the admission and the
        // derivation read one state. A no-op without a `staking` section.
        let blocks = self.epoch_blocks.max(1);
        if self.staking.is_some() && height.saturating_add(1).is_multiple_of(blocks) {
            let next_epoch = height.saturating_add(1) / blocks;
            self.admit_queued_stake(next_epoch);
            // Audit v6, STAKE-1: a jail whose epoch has come ends here, in the same state the
            // next set is derived from. Empty without `staking.slashing`.
            self.jailed.retain(|_, until| *until > next_epoch);
        }
        // Audit v6, BRG-14: a pending PQ-set or pause-key rotation whose delay has run out takes
        // effect at this block's end, by this block's own time — the proposer and every replica
        // run this on the same timestamp, so the root both compute already carries the new set,
        // and the next block's attestations verify under it. A no-op without `bridge.rotation`.
        let now = self.now_secs();
        if let Some(bridge) = self.bridge.as_mut() {
            bridge.activate_due_rotations(now);
        }
        self.record_anchor(height);
        // Spec §12's invariant, checked once per block in a debug build: every bridged token's
        // supply is exactly the sum of what its source-chain coins are holding locked. It holds
        // by construction — `lock`/`release` move both sides together and are the only writers of
        // a bridged supply — so this is the assertion that a *new* writer has not appeared, not a
        // consensus rule. Release builds skip it: it is a whole pass over the registry, and a
        // check that can only fire on a code change does not belong in every node's hot path.
        if let Some(tokens) = &self.tokens {
            debug_assert!(
                tokens.backing_invariant_holds(),
                "a bridged token's supply left the sum of its backings at height {height}"
            );
        }
    }

    /// Deterministic state commitment (spec §9):
    /// `blake3("rand-state-2" || tree_root || nullifier_root || validators_root || programs_root)`,
    /// with `|| bridge_root` appended on a chain whose genesis has a `bridge` section (spec §10),
    /// and — on a chain whose genesis has an `aggregation` section — the whole of that under
    /// `rand-state-3` with `|| aggregators_root` appended (block-aggregation spec §2.1).
    /// The nullifier and validator roots are BLAKE3 Merkle roots over the sorted sets; programs
    /// are content addressed, so their ids commit to the code.
    ///
    /// The optional components are appended, never zero-placed, so a chain without a bridge
    /// commits exactly what phase S1 committed and a chain without aggregation exactly what the
    /// bridge commit added — turning either on is a hard fork for the chains that take it and a
    /// no-op for the ones that do not.
    /// The three roots `state_root` binds, in order: nullifiers, validators, programs. Under the
    /// incremental nullifier root the first is the range root, not a sorted merkle root.
    /// Split out so a state-root mismatch can name the component it diverges in.
    fn state_root_leaves(&self) -> (Hash, Hash, Hash) {
        let nf_root = match &self.nullifier_mmr {
            Some(m) => m.root(),
            None => {
                let mut nf_leaves: Vec<Hash> = Vec::with_capacity(self.nullifiers.len());
                self.nullifiers.for_each_sorted(|nf| nf_leaves.push(nullifier_mmr::leaf(nf)));
                merkle_root(&nf_leaves)
            }
        };
        let val_leaves: Vec<Hash> = self
            .validators
            .iter()
            .map(|(addr, v)| {
                let mut buf = Vec::with_capacity(96 + 16 * v.pending.len() + v.payout.kem_ek.len());
                buf.extend_from_slice(addr.as_bytes());
                buf.extend_from_slice(&v.stake.to_be_bytes());
                buf.extend_from_slice(&v.rewards.to_be_bytes());
                buf.extend_from_slice(&v.nonce.to_be_bytes());
                // The queue's length before the queue itself: `pending` is the one
                // variable-length run in the leaf, and without a count a short payout key with
                // one pending entry could serialise to the same bytes as a longer key with
                // none. Every field is fixed-width again from here on.
                buf.extend_from_slice(&(v.pending.len() as u64).to_be_bytes());
                for (release_epoch, amount) in &v.pending {
                    buf.extend_from_slice(&release_epoch.to_be_bytes());
                    buf.extend_from_slice(&amount.to_be_bytes());
                }
                buf.extend_from_slice(&word8_to_bytes(&v.payout.pk));
                buf.extend_from_slice(&v.payout.kem_ek);
                // Under a `staking` section the activation epoch is state the set derivation
                // reads, so the leaf binds it (v4); without one it is 0 everywhere and the v2
                // leaf is committed unchanged (audit v4, STAKE-2).
                if self.staking.is_some() {
                    buf.extend_from_slice(&v.activation_epoch.to_be_bytes());
                    Hash::digest_domain(b"rand-validator-leaf-4", &buf)
                } else {
                    Hash::digest_domain(b"rand-validator-leaf-2", &buf)
                }
            })
            .collect();
        let prog_leaves: Vec<Hash> =
            self.programs.keys().map(|id| Hash::digest_domain(b"rand-program-leaf", id.as_bytes())).collect();
        (nf_root, merkle_root(&val_leaves), merkle_root(&prog_leaves))
    }

    /// The component roots of [`Ledger::state_root`], for logging a mismatch: tree, nullifiers,
    /// validators, programs, tokens, aggregators. A divergence between two ledgers names itself
    /// here.
    pub fn debug_state_root_components(&self) -> String {
        let (nf, val, prog) = self.state_root_leaves();
        let tok = match &self.tokens {
            Some(t) => format!("{:?}", t.root()),
            None => "none".into(),
        };
        let agg = if self.aggregation.is_some() {
            format!("{:?}", aggregation::aggregators_component(&self.aggregators, &self.retired_aggregator_nonces))
        } else {
            "none".into()
        };
        let vest = match &self.vesting {
            Some(v) => format!("{:?}", v.root()),
            None => "none".into(),
        };
        let pstate = match &self.program_state {
            Some(p) => format!("{:?}", p.root()),
            None => "none".into(),
        };
        format!(
            "tree {:?} nullifiers {nf:?} validators {val:?} programs {prog:?} tokens {tok} aggregators {agg} vesting {vest} gas prices {:?} admitted {:?} program state {pstate}",
            self.tree.root(),
            self.gas_prices(),
            self.admitted_root()
        ) + &format!(" jailed {:?}", self.jailed_root())
            + &format!(
                " nullifier range {}",
                match &self.nullifier_mmr {
                    Some(m) => format!("{} leaves", m.count()),
                    None => "off".into(),
                }
            )
    }

    /// `blake3("rand-state-2" || tree || nullifiers || validators || programs)`, with
    /// `|| bridge_root` appended on a bridged chain and, on a chain whose genesis has a `tokens`
    /// section, `|| tokens_root` appended right after the bridge root and the whole thing
    /// re-domained `rand-state-4` — whether or not aggregation is also on, since a tokens-off
    /// chain must still fall through to today's `rand-state-2`/`rand-state-3` paths unchanged.
    /// The aggregators root, when present, is still the last component appended.
    /// The bond queue as one hash: its length, then every row's validator, amount and epoch in
    /// queue order (every field fixed-width, so the count alone makes the encoding unambiguous).
    pub fn bond_queue_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 48 * self.bond_queue.len());
        buf.extend_from_slice(&(self.bond_queue.len() as u64).to_be_bytes());
        for q in &self.bond_queue {
            buf.extend_from_slice(q.validator.as_bytes());
            buf.extend_from_slice(&q.amount.to_be_bytes());
            buf.extend_from_slice(&q.epoch.to_be_bytes());
        }
        Hash::digest_domain(b"rand-bond-queue-1", &buf)
    }

    /// The proving-share bucket as one root: a leaf per entry, in the map's own (transaction-hash)
    /// order, each binding the whole entry.
    ///
    /// Committed because the bucket decides payment and coverability (audit v3, AGG-4). Before
    /// this it was "derived state like supply" and sat outside the root, so two replicas that
    /// disagreed about it — one that lost an entry, one that kept an expired one — computed the
    /// same state root and stayed in consensus while paying different aggregators.
    pub fn unsealed_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .unsealed_fees
            .iter()
            .map(|(tx, (excess, proposer, until))| {
                let mut buf = Vec::with_capacity(32 + 8 + 32 + 8);
                buf.extend_from_slice(tx.as_bytes());
                buf.extend_from_slice(&excess.to_le_bytes());
                buf.extend_from_slice(&proposer.0);
                buf.extend_from_slice(&until.to_le_bytes());
                Hash::digest_domain(b"rand-unsealed-leaf-1", &buf)
            })
            .collect();
        crate::crypto::merkle_root(&leaves)
    }

    ///
    /// On a chain whose genesis has a `staking` section (audit v4, STAKE-2) the faucet's two
    /// epoch counters and the bond queue's root are appended last and the whole thing is re-domained `rand-state-5`,
    /// whatever else is on — the section is gated exactly like the three before it, so a chain
    /// without one falls through to the domains above unchanged.
    ///
    /// Genesis vesting appends the register's root after that (`rand-state-6`), and Phase 2 of
    /// the gas model (spec §7.1), under `gas.dynamic` only, appends the live `gas_price ‖
    /// byte_price` (big-endian u64) after everything, vesting included, re-domained
    /// `rand-state-7`. A fixed-price `gas` section is not in the root: its prices never move.
    ///
    /// Audit v6's staking state is folded in *around* all of that rather than appended inside
    /// it: under `staking.admission_by_vote` the root is `H("rand-state-admitted-1", root ‖
    /// admitted_root)` over the root every paragraph above describes, and under
    /// `staking.slashing` (STAKE-1) `H("rand-state-slashing-1", root ‖ jailed_root)` over that.
    /// A wrapper with its own domain composes with whatever the inner layout grows next, and
    /// without the flags — every chain through 18 — the inner root is returned untouched, byte
    /// for byte.
    ///
    /// Audit v6's TOK-1 (issue #86) is the innermost of them: under `tokens.incremental_root`
    /// the registry's component inside the base is already the incremental
    /// `rand-token-registry-4` root, and the whole is re-domained
    /// `H("rand-state-tokens-1", base)` before the staking wrappers — so a chain on the field
    /// can never collide with one off it whose registry happened to hash alike, and every chain
    /// through 20 (no field) is untouched.
    pub fn state_root(&self) -> Hash {
        let mut root = self.state_root_base();
        if self.tokens.as_ref().is_some_and(|t| t.incremental_root()) {
            root = Hash::digest_domain(b"rand-state-tokens-1", root.as_bytes());
        }
        // The incremental nullifier root (spec 2026-10-05 §4.3): the range root already sits in the
        // nullifier slot of the base; the wrapper keeps a flag-on chain from ever colliding with a
        // flag-off chain whose sorted root happened to equal it. After the tokens wrapper, before the
        // staking wrappers — the order is fixed here.
        if self.nullifier_mmr.is_some() {
            root = Hash::digest_domain(b"rand-state-nf-mmr-1", root.as_bytes());
        }
        if self.staking.as_ref().is_some_and(|s| s.admission_by_vote()) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(root.as_bytes());
            buf.extend_from_slice(self.admitted_root().as_bytes());
            root = Hash::digest_domain(b"rand-state-admitted-1", &buf);
        }
        if self.staking.as_ref().is_some_and(|s| s.slashing.is_some()) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(root.as_bytes());
            buf.extend_from_slice(self.jailed_root().as_bytes());
            root = Hash::digest_domain(b"rand-state-slashing-1", &buf);
        }
        root
    }

    /// [`Ledger::state_root`] before audit v6's wrappers: the `rand-state-2` … `rand-state-7`
    /// layouts, exactly as every chain through 18 commits them, and RPL-2's `rand-state-8` (the
    /// program-state root appended last) under a `program_state` section, which no chain through
    /// 19 carries.
    fn state_root_base(&self) -> Hash {
        let (nf_root, val_root, prog_root) = self.state_root_leaves();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&word8_to_bytes(&self.tree.root()));
        buf.extend_from_slice(nf_root.as_bytes());
        buf.extend_from_slice(val_root.as_bytes());
        buf.extend_from_slice(prog_root.as_bytes());
        if let Some(bridge) = &self.bridge {
            buf.extend_from_slice(bridge.root().as_bytes());
        }
        if let Some(tokens) = &self.tokens {
            buf.extend_from_slice(tokens.root().as_bytes());
        }
        if self.aggregation.is_some() {
            buf.extend_from_slice(
                aggregation::aggregators_component(&self.aggregators, &self.retired_aggregator_nonces).as_bytes(),
            );
            buf.extend_from_slice(self.unsealed_root().as_bytes());
        }
        if self.staking.is_some() {
            buf.extend_from_slice(&self.faucet_epoch.to_be_bytes());
            buf.extend_from_slice(&self.faucet_minted_in_epoch.to_be_bytes());
            // And the bond queue, whole and in order: its order is the admission order.
            buf.extend_from_slice(self.bond_queue_root().as_bytes());
        }
        // Genesis vesting: the register's root last, re-domained `rand-state-6`. Only under
        // the section, so every chain without one keeps its domain and bytes.
        if let Some(v) = &self.vesting {
            buf.extend_from_slice(v.root().as_bytes());
        }
        // Phase 2 (spec §7.1): the live gas prices after everything else, big-endian, re-domained
        // `rand-state-7`. Only under `gas.dynamic`: a fixed-price section (or none) keeps its
        // domain and bytes, since those prices never move.
        let dynamic = self.gas.as_ref().is_some_and(|g| g.dynamic.is_some());
        if dynamic {
            let p = self.gas_prices();
            buf.extend_from_slice(&p.gas_price.to_be_bytes());
            buf.extend_from_slice(&p.byte_price.to_be_bytes());
        }
        // RPL-2: the program-state root after everything else, the live gas prices included,
        // re-domained `rand-state-8`. Only under the `program_state` section, so every chain
        // without one keeps its domain and bytes.
        if let Some(p) = &self.program_state {
            buf.extend_from_slice(p.root().as_bytes());
            return Hash::digest_domain(b"rand-state-8", &buf);
        }
        if dynamic {
            return Hash::digest_domain(b"rand-state-7", &buf);
        }
        if self.vesting.is_some() {
            return Hash::digest_domain(b"rand-state-6", &buf);
        }
        if self.staking.is_some() {
            return Hash::digest_domain(b"rand-state-5", &buf);
        }
        if self.tokens.is_some() {
            return Hash::digest_domain(b"rand-state-4", &buf);
        }
        if self.aggregation.is_some() {
            return Hash::digest_domain(b"rand-state-3", &buf);
        }
        Hash::digest_domain(b"rand-state-2", &buf)
    }
}

/// Default executor for nodes until a real verifier exists.
pub fn default_executor() -> StubExecutor {
    StubExecutor
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::program::program_id;
    use crate::crypto::Keypair;
    use crate::notes::{Envelope, ShieldedAddress};
    use crate::types::{BlockHeader, QuorumCertificate, UNITS_PER_RAND};

    const HC: Word8 = [11; 8];

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }
    }

    fn keys() -> (Keypair, Keypair) {
        (Keypair::from_seed([1; 32]).unwrap(), Keypair::from_seed([2; 32]).unwrap())
    }

    /// A register entry for `k`: the S1 fixture's stake, with the S2 fields at their defaults.
    fn entry(k: &Keypair, stake: u64) -> (Address, ValidatorEntry) {
        (
            k.address(),
            ValidatorEntry {
                public_key: k.public_key().clone(),
                stake,
                pending: Vec::new(),
                rewards: 0,
                payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                nonce: 0,
                activation_epoch: 0,
            },
        )
    }

    /// Spec 2026-10-05 §4.3: without the flag the state root is byte-identical to before (a
    /// chain-20-shaped ledger); with it the nullifier slot holds the range root and the whole is
    /// re-domained `rand-state-nf-mmr-1` once.
    #[test]
    fn the_incremental_nullifier_root_is_gated_and_wrapped_once() {
        let (a, _) = keys();
        let mut off = ledger();
        let mut on = ledger();
        on.set_incremental_nullifier_root(true);
        assert_eq!(off.state_root(), ledger().state_root(), "the flag is off by default");
        let before_on = on.state_root();
        assert_ne!(before_on, off.state_root(), "the wrapper changes an empty ledger's root");
        for l in [&mut off, &mut on] {
            let t = tx(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
            let root = root_after(l, &[tx(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
            l.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        }
        // A bundle inserts all four nullifier slots, the two dummies included.
        assert_eq!(on.nullifier_mmr().unwrap().count(), 4);
        assert_ne!(on.state_root(), off.state_root(), "a flag-on root differs from the flag-off root of the same blocks");
        // The composition, pinned: the range root in the slot, then exactly one wrapper.
        assert_eq!(on.state_root_leaves().0, on.nullifier_mmr().unwrap().root(), "the range root takes the nullifier slot");
        assert_eq!(on.state_root(), Hash::digest_domain(b"rand-state-nf-mmr-1", on.state_root_base().as_bytes()), "exactly one wrapper");
        // The `rand-state-nf-mmr-1` encoding pinned on 2026-10-05; it must never change without a new domain.
        const GOLDEN_ONE_BLOCK_ROOT: &str = "befcd5659aa22337044ed24005d7a62d3e1ed90bead112a223295f58472105b3";
        assert_eq!(on.state_root().to_hex(), GOLDEN_ONE_BLOCK_ROOT);
        assert_eq!(off.state_root(), ledger_after_same_block_flag_off(&a), "the flag-off root is what it was");
        // Determinism: the same blocks on a fresh flag-on ledger give the same root.
        let mut again = ledger();
        again.set_incremental_nullifier_root(true);
        let t = tx(&again, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&again, &[tx(&again, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        again.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        assert_eq!(again.state_root(), on.state_root());
        assert_eq!(again, on, "equality covers the range");
    }

    /// The wrapper order (spec 2026-10-05 §4.3): after `rand-state-tokens-1`, not before it.
    #[test]
    fn the_nullifier_wrapper_follows_the_tokens_wrapper() {
        let mut l = ledger();
        l.set_tokens(Some(tokens::TokenRegistry::new(1_000_000_000).with_incremental_root(true)));
        l.set_incremental_nullifier_root(true);
        let tokens_wrapped = Hash::digest_domain(b"rand-state-tokens-1", l.state_root_base().as_bytes());
        assert_eq!(l.state_root(), Hash::digest_domain(b"rand-state-nf-mmr-1", tokens_wrapped.as_bytes()));
    }

    /// The flag-off root for the same block, computed on a fresh ledger with no reference to the
    /// new code paths: pins "byte-identical to before" without a hard-coded hash.
    fn ledger_after_same_block_flag_off(a: &Keypair) -> Hash {
        let mut l = ledger();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        l.apply_block(&signed_block(vec![t], a, 1, root), &StubExecutor).unwrap();
        l.state_root()
    }

    #[test]
    #[should_panic(expected = "insertion order")]
    fn the_flag_cannot_be_switched_on_over_existing_nullifiers() {
        let (a, _) = keys();
        let mut l = ledger();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let root = root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1);
        l.apply_block(&signed_block(vec![t], &a, 1, root), &StubExecutor).unwrap();
        l.set_incremental_nullifier_root(true);
    }

    fn ledger() -> Ledger {
        let (a, b) = keys();
        let register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
        let mut l = Ledger::new(7, HC, register, &StubExecutor);
        l.set_faucet(true);
        l.set_confidential(true);
        l.set_height(1);
        l
    }

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes. `nfs` and
    /// `cms` are its first two slots; the other two are derived from them (`notes::pad4`), the
    /// dummies an honest bundle carries.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        bundle4(l, crate::notes::pad4(nfs), crate::notes::pad4(cms), fee)
    }

    /// [`bundle`] with all four slots of each set given.
    fn bundle4(l: &Ledger, nfs: [Word8; 4], cms: [Word8; 4], fee: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: l.height as u32,
            envelopes: [env(), env(), env(), env()],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        restub(&mut b);
        b
    }

    /// Re-issue `b`'s stub proof over its current public fields (unbound; `StubExecutor::bind`
    /// binds it once the transaction is assembled).
    fn restub(b: &mut Bundle) {
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
    }

    fn tx(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2]) -> Transaction {
        StubExecutor::bound(Transaction::shielded(7, bundle(l, nfs, cms, gas::BUNDLE_BASE), Action::None))
    }

    /// A block signed by `key`, carrying `state_root` verbatim so a test can commit to a wrong one.
    fn signed_block(txs: Vec<Transaction>, key: &Keypair, height: u64, state_root: Hash) -> Block {
        let header = BlockHeader {
            height,
            view: height,
            parent: Hash::ZERO,
            proposer: key.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(&txs),
            state_root,
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        Block::sign(&crate::types::SigningDomain::v0(Hash::ZERO), header, txs, key)
    }

    /// The state root `txs` leave behind when `proposer` applies them as block `height`.
    fn root_after(l: &Ledger, txs: &[Transaction], proposer: &Address, height: u64) -> Hash {
        let mut scratch = l.clone();
        scratch.set_height(height);
        scratch.apply_transactions(txs, proposer, &StubExecutor).unwrap();
        scratch.record_anchor(height);
        scratch.state_root()
    }

    #[test]
    fn a_valid_bundle_spends_appends_and_pays_the_proposer() {
        let mut l = ledger();
        let (a, _) = keys();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.is_spent(&[1; 8]) && l.is_spent(&[2; 8]));
        assert!(l.has_commitment(&[3; 8]) && l.has_commitment(&[4; 8]));
        // Four slots each, the two dummies included: every nullifier is spent and every
        // commitment is a leaf.
        assert!(t.nullifiers().iter().all(|nf| l.is_spent(nf)));
        assert!(t.commitments().iter().all(|cm| l.has_commitment(cm)));
        assert_eq!(l.next_index(), 4);
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // replay: both nullifiers now spent
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([1; 8])));
    }

    /// Fee feedback, `fees.burn_base` (`docs/fees.md` §1.3): a transfer paying `BUNDLE_BASE + 5`
    /// burns the base — `burned` and `base_fees_burned` up by it — and tips the proposer the 5,
    /// which is all `fees_paid` moves by; the audit holds with the burn on its right. The same
    /// transaction without the flag pays the proposer the whole fee and burns nothing (today's
    /// rule, side by side).
    #[test]
    fn burn_base_destroys_the_base_and_tips_the_proposer() {
        let (a, _) = keys();
        let p = a.address();
        let fee = gas::BUNDLE_BASE + 5;
        let seeded = |burn: bool| {
            let mut l = ledger();
            let staked = register_total(l.validators());
            l.set_genesis_supply(1_000 * fee, staked);
            if burn {
                l.set_fees(fees::FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: None, proposer_share_bps: None, prove_base: None });
            }
            l
        };
        let transfer = |l: &Ledger| {
            StubExecutor::bound(Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee), Action::None))
        };

        let mut plain = seeded(false);
        plain.apply_tx(&transfer(&plain), &p, &StubExecutor).unwrap();
        assert_eq!(plain.validators()[&p].rewards, fee, "without the flag the proposer keeps the whole fee");
        assert_eq!((plain.supply().fees_paid, plain.supply().burned, plain.base_fees_burned()), (fee, 0, 0));
        assert!(plain.audit().invariant_holds(), "{:?}", plain.audit());

        let mut burning = seeded(true);
        burning.apply_tx(&transfer(&burning), &p, &StubExecutor).unwrap();
        assert_eq!(burning.validators()[&p].rewards, 5, "the proposer keeps the tip");
        assert_eq!(burning.supply().fees_paid, 5, "fees_paid moves by what the proposer keeps");
        assert_eq!(burning.supply().burned, gas::BUNDLE_BASE, "the base is destroyed");
        assert_eq!(burning.base_fees_burned(), gas::BUNDLE_BASE);
        assert_eq!(burning.audit().base_fees_burned, gas::BUNDLE_BASE);
        assert!(burning.audit().invariant_holds(), "{:?}", burning.audit());
        assert_ne!(burning, plain, "the proposer's rewards differ, and the register is state");
    }

    // ---- The hidden-asset bundle (spec §3.6–§3.10): four slots, the burn shape ----------------

    /// A plain RAND payment and a token transfer are the same transaction on chain: an
    /// `Action::None` bundle of four nullifiers and four commitments whose three burn fields are
    /// zero — the asset lives only inside the proof. Both validate and apply; every nullifier,
    /// the dummies' included, is spent, every commitment is a leaf, in slot order, and no token
    /// supply moves for the transfer.
    #[test]
    fn a_rand_payment_and_a_token_transfer_are_both_plain_four_slot_bundles() {
        let mut l = ledger();
        let mut registry = tokens::TokenRegistry::new(0);
        let index = registry
            .register(Hash::digest(b"tst"), "Test".into(), "TST".into(), 6, tokens::MintAuthority::None, 0)
            .unwrap();
        l.set_tokens(Some(registry));
        let supply_before = l.tokens().unwrap().get(index).unwrap().total_supply;
        let (a, _) = keys();
        let rand_payment =
            StubExecutor::bound(Transaction::shielded(7, bundle4(&l, [[1; 8], [2; 8], [3; 8], [4; 8]], [[5; 8], [6; 8], [7; 8], [8; 8]], gas::BUNDLE_BASE), Action::None));
        let token_transfer = StubExecutor::bound(Transaction::shielded(
            7,
            bundle4(&l, [[11; 8], [12; 8], [13; 8], [14; 8]], [[15; 8], [16; 8], [17; 8], [18; 8]], gas::BUNDLE_BASE),
            Action::None,
        ));
        for t in [&rand_payment, &token_transfer] {
            assert_eq!(t.nullifiers().len(), 4);
            assert_eq!(t.commitments().len(), 4);
            assert_eq!(l.validate(t, &StubExecutor), Ok(()));
        }
        let before = l.next_index();
        l.apply_tx(&rand_payment, &a.address(), &StubExecutor).unwrap();
        l.apply_tx(&token_transfer, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.next_index(), before + 8, "four leaves per bundle");
        for t in [&rand_payment, &token_transfer] {
            assert!(t.nullifiers().iter().all(|nf| l.is_spent(nf)));
            assert!(t.commitments().iter().all(|cm| l.has_commitment(cm)));
        }
        assert_eq!(l.tokens().unwrap().get(index).unwrap().total_supply, supply_before, "a transfer moves no supply");
        assert_eq!(l.supply().burned, 0);
    }

    /// Every one of the four nullifiers and four commitments — dummy slots included — goes
    /// through the uniqueness rules: any of the six pairs equal, or any slot already on chain,
    /// is refused.
    #[test]
    fn every_slot_is_held_to_the_uniqueness_rules() {
        let mut l = ledger();
        let (a, _) = keys();
        let nfs = [[1; 8], [2; 8], [3; 8], [4; 8]];
        let cms = [[5; 8], [6; 8], [7; 8], [8; 8]];
        for i in 0..4 {
            for j in i + 1..4 {
                let mut n = nfs;
                n[j] = n[i];
                let t = StubExecutor::bound(Transaction::shielded(7, bundle4(&l, n, cms, gas::BUNDLE_BASE), Action::None));
                assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::DuplicateNullifierInBundle), "nullifiers {i},{j}");
                let mut c = cms;
                c[j] = c[i];
                let t = StubExecutor::bound(Transaction::shielded(7, bundle4(&l, nfs, c, gas::BUNDLE_BASE), Action::None));
                assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::DuplicateCommitmentInBundle), "commitments {i},{j}");
            }
        }
        l.apply_tx(&StubExecutor::bound(Transaction::shielded(7, bundle4(&l, nfs, cms, gas::BUNDLE_BASE), Action::None)), &a.address(), &StubExecutor)
            .unwrap();
        l.record_anchor(l.height());
        // A slot-3 (dummy) nullifier or commitment reused by a later bundle.
        let t = StubExecutor::bound(Transaction::shielded(
            7,
            bundle4(&l, [[21; 8], [22; 8], [23; 8], [4; 8]], [[25; 8], [26; 8], [27; 8], [28; 8]], gas::BUNDLE_BASE),
            Action::None,
        ));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([4; 8])));
        let t = StubExecutor::bound(Transaction::shielded(
            7,
            bundle4(&l, [[21; 8], [22; 8], [23; 8], [24; 8]], [[25; 8], [26; 8], [27; 8], [8; 8]], gas::BUNDLE_BASE),
            Action::None,
        ));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists([8; 8])));
    }

    /// The burn shape on an action that burns nothing (spec §3.7): a transfer — of any asset —
    /// must publish `burn_a == burn_r == burn_asset == 0`, and a RAND burn through `burn_a`
    /// (`burn_asset == 0 && burn_a > 0`) is refused everywhere as non-canonical. All of it is
    /// decided before the proof is looked at: the stub proof below is re-issued for the altered
    /// fields, so only the burn rule can refuse it.
    #[test]
    fn a_transfer_burns_nothing_and_a_rand_burn_through_burn_a_is_refused() {
        let l = ledger();
        let with = |f: fn(&mut Bundle)| {
            let mut b = bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE);
            f(&mut b);
            restub(&mut b);
            StubExecutor::bound(Transaction::shielded(7, b, Action::None))
        };
        assert_eq!(l.validate(&with(|_| {}), &StubExecutor), Ok(()));
        assert_eq!(l.validate(&with(|b| b.burn_a = 5), &StubExecutor), Err(TxError::NonCanonicalRandBurn(5)));
        assert_eq!(
            l.validate(&with(|b| { b.burn_a = 5; b.burn_asset = 2 }), &StubExecutor),
            Err(TxError::UnsupportedAsset(2))
        );
        assert_eq!(l.validate(&with(|b| b.burn_asset = 2), &StubExecutor), Err(TxError::UnsupportedAsset(2)));
        assert_eq!(l.validate(&with(|b| b.burn_r = 5), &StubExecutor), Err(TxError::UnsupportedBurn(5)));
        // The canonical rule comes first on every action, a `Bond` included — its RAND goes
        // through `burn_r`, never `burn_a`.
        let v = Address([1; 32]);
        let mut b = bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE);
        b.burn_a = 5;
        restub(&mut b);
        let bond = StubExecutor::bound(Transaction::shielded(7, b, Action::Bond { validator: v, amount: 5, registration: None }));
        assert_eq!(l.validate(&bond, &StubExecutor), Err(TxError::NonCanonicalRandBurn(5)));
    }

    #[test]
    fn admission_checks_run_in_spec_order() {
        let mut l = ledger();
        let (a, _) = keys();
        // wrong chain
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.chain_id = 8;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::WrongChain { expected: 7, actual: 8 }));
        // envelope cap
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().envelopes[0].body = vec![0; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::EnvelopeTooLarge));
        // fee floor
        let t = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE - 1),
            Action::None,
        ));
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 })
        );
        // a burn on a transfer (the burn shape, before the anchor)
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().burn_asset = 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedAsset(1)));
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().burn_r = 5;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
        // unknown anchor
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().anchor = [9; 8];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownAnchor { window: 256 }));
        // time window: future and too old. The height is chosen past the window so both edges
        // exist; the edges themselves are expressed in TIME_WINDOW, never in its current value.
        const H: u64 = TIME_WINDOW + 100;
        let oldest = (H - TIME_WINDOW) as u32;
        l.set_height(H);
        l.record_anchor(H);
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = H as u32 + 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: H as u32 + 1, height: H, window: TIME_WINDOW }));
        t.bundle.as_mut().unwrap().time = oldest - 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: oldest - 1, height: H, window: TIME_WINDOW }));
        t.bundle.as_mut().unwrap().time = oldest; // exactly height - TIME_WINDOW is allowed
        let mut b = t.bundle.clone().unwrap();
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        t.bundle = Some(b);
        StubExecutor::bind(&mut t);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        // duplicate nullifier inside the bundle, duplicate commitment inside the bundle
        assert_eq!(
            l.validate(&tx(&l, [[1; 8], [1; 8]], [[3; 8], [4; 8]]), &StubExecutor),
            Err(TxError::DuplicateNullifierInBundle)
        );
        assert_eq!(
            l.validate(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [3; 8]]), &StubExecutor),
            Err(TxError::DuplicateCommitmentInBundle)
        );
        // existing commitment
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height()); // the block ends; its root becomes the anchor the next tx uses
        assert_eq!(
            l.validate(&tx(&l, [[5; 8], [6; 8]], [[3; 8], [7; 8]]), &StubExecutor),
            Err(TxError::CommitmentExists([3; 8]))
        );
        // digest mismatch: plaintext fee differs from what the proof committed to
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        t.bundle.as_mut().unwrap().fee += 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BadDigest));
        // proof for another guest
        let mut t = tx(&l, [[5; 8], [6; 8]], [[8; 8], [9; 8]]);
        let d = StubExecutor.bundle_digest(&t.bundle.as_ref().unwrap().digest_input());
        t.bundle.as_mut().unwrap().proof = StubExecutor::make_bundle_proof(&[12; 8], &d, &[0; 8]);
        assert!(matches!(l.validate(&t, &StubExecutor), Err(TxError::InvalidBundleProof(_))));
    }

    #[test]
    fn anchors_are_a_sliding_window_of_block_end_roots() {
        let mut l = ledger();
        let (a, _) = keys();
        let genesis_root = l.root();
        for h in 1..=(ANCHOR_WINDOW as u64) {
            l.set_height(h);
            l.apply_tx(
                &tx(
                    &l,
                    [[h as u32; 8], [h as u32 + 1000; 8]],
                    [[h as u32 + 2000; 8], [h as u32 + 3000; 8]],
                ),
                &a.address(),
                &StubExecutor,
            )
            .unwrap();
            l.record_anchor(h);
        }
        assert_eq!(l.anchors().len(), ANCHOR_WINDOW);
        assert!(!l.is_anchor(&genesis_root), "the genesis root scrolled out after ANCHOR_WINDOW blocks");
        assert_eq!(l.anchors().back(), Some(&(ANCHOR_WINDOW as u64, l.root())), "the last block's end root");
        // A root the tree only passes through is not an anchor: apply one more block's worth of
        // notes without closing the block, and a bundle anchored at the live root is rejected.
        // Values above every one the loop generated (it used h, h+1000, h+2000 and h+3000 for
        // h up to ANCHOR_WINDOW), so these notes are fresh whatever the window's size is.
        l.set_height(ANCHOR_WINDOW as u64 + 1);
        l.apply_tx(&tx(&l, [[10_000; 8], [10_001; 8]], [[10_002; 8], [10_003; 8]]), &a.address(), &StubExecutor).unwrap();
        assert!(!l.is_anchor(&l.root()), "a mid-block root is not an anchor");
        assert_eq!(
            l.validate(&tx(&l, [[10_004; 8], [10_005; 8]], [[10_006; 8], [10_007; 8]]), &StubExecutor),
            Err(TxError::UnknownAnchor { window: 256 })
        );
    }

    /// Issue #118: genesis `proof_window_blocks` replaces both windows. Under 1 024 the anchor
    /// deque keeps 1 024 block-end roots and a `time` 1 024 blocks old is still inside; both
    /// refusals name the window in force; without the field (and back at `None`) it is 256/256.
    #[test]
    fn a_genesis_proof_window_widens_both_windows_and_the_errors_name_it() {
        const W: u64 = 1024;
        let mut wide = ledger();
        wide.set_proof_window_blocks(Some(W));
        let mut plain = ledger();
        assert_eq!((plain.proof_window(), plain.proof_window_blocks()), (TIME_WINDOW, None));
        assert_eq!((wide.proof_window(), wide.proof_window_blocks()), (W, Some(W)));
        for h in 1..=(W + 100) {
            for l in [&mut wide, &mut plain] {
                l.set_height(h);
                l.record_anchor(h);
            }
        }
        assert_eq!(plain.anchors().len(), ANCHOR_WINDOW, "no field: today's deque");
        assert_eq!(wide.anchors().len(), W as usize, "the deque keeps the genesis window");
        assert_eq!(wide.anchors().front().map(|(h, _)| *h), Some(100 + 1));
        // The time window, at both edges, under each.
        let h = W + 100;
        assert!(wide.time_in_window((h - W) as u32) && !wide.time_in_window((h - W) as u32 - 1));
        assert!(!plain.time_in_window((h - W) as u32) && plain.time_in_window((h - TIME_WINDOW) as u32));
        // A stale `time` is refused with the window this chain runs, and the text says so.
        let mut t = tx(&wide, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = (h - W) as u32 - 1;
        let err = wide.validate(&t, &StubExecutor).unwrap_err();
        assert_eq!(err, TxError::TimeOutOfWindow { time: (h - W) as u32 - 1, height: h, window: W });
        assert_eq!(err.to_string(), format!("time {} is outside [{}, {h}]", h - W - 1, h - W));
        // An unknown anchor likewise.
        let mut t = tx(&wide, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().anchor = [9; 8];
        let err = wide.validate(&t, &StubExecutor).unwrap_err();
        assert_eq!(err, TxError::UnknownAnchor { window: W });
        assert_eq!(err.to_string(), "anchor is not one of the last 1024 roots");
        // Back to no field: the deque narrows at once to today's window.
        wide.set_proof_window_blocks(None);
        assert_eq!(wide.anchors(), plain.anchors());
    }

    #[test]
    fn apply_block_records_the_block_end_anchor_and_rejects_an_unknown_proposer() {
        let mut l = ledger();
        let (a, _) = keys();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let good = signed_block(vec![t], &a, 1, root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1));
        assert_eq!(l.apply_block(&good, &StubExecutor).unwrap(), Vec::new());
        assert!(l.is_spent(&[1; 8]) && l.has_commitment(&[3; 8]));
        assert_eq!(l.anchors().back(), Some(&(1, l.root())), "the block-end root is recorded");
        // ... and the bundle fee reached the proposer's register entry.
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // A block signed by a key outside the register is rejected before any execution.
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let bad = signed_block(Vec::new(), &stranger, 2, Hash::ZERO);
        assert_eq!(
            l.apply_block(&bad, &StubExecutor),
            Err(BlockError::UnknownProposer(stranger.address()))
        );
        // A header committing to the wrong state leaves the ledger untouched.
        let before = l.clone();
        let wrong = signed_block(Vec::new(), &a, 2, Hash::ZERO);
        assert!(matches!(l.apply_block(&wrong, &StubExecutor), Err(BlockError::StateRootMismatch { .. })));
        assert_eq!(l, before, "unchanged on error");
        // An empty block still closes with its own anchor.
        let empty = signed_block(Vec::new(), &a, 2, root_after(&l, &[], &a.address(), 2));
        l.apply_block(&empty, &StubExecutor).unwrap();
        assert_eq!(l.anchors().back(), Some(&(2, l.root())));
        // The same rule one level down: a fee has nowhere to go if the proposer is not in the
        // register, and the rejected transaction leaves nothing behind.
        let before = l.clone();
        let orphan = tx(&l, [[70; 8], [71; 8]], [[72; 8], [73; 8]]);
        assert_eq!(
            l.apply_tx(&orphan, &stranger.address(), &StubExecutor),
            Err(TxError::UnknownProposer(stranger.address()))
        );
        assert_eq!(l, before, "unchanged on error");
    }

    /// A `StubExecutor` that counts its two expensive calls, so a test can see whether a proof
    /// was verified or only decoded.
    #[derive(Default)]
    struct CountingExecutor {
        bundles: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
        auths: std::sync::atomic::AtomicUsize,
    }

    impl CountingExecutor {
        fn bundles(&self) -> usize {
            self.bundles.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn auths(&self) -> usize {
            self.auths.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl ConfidentialExecutor for CountingExecutor {
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
            StubExecutor.check_program(base_pc, words)
        }
        fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            StubExecutor.verify_call(program, proof)
        }
        // The whole point of the test: the decode path the ledger takes on a verified-set hit
        // is not the verify path. Delegated to the stub's own, uncounted.
        fn decode_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            StubExecutor.decode_call(program, proof)
        }
        fn public_digest(&self, words: &[u32]) -> Word8 {
            StubExecutor.public_digest(words)
        }
        fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
            StubExecutor.node_hash(left, right)
        }
        fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
            StubExecutor.hash_domain(domain, msg)
        }
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            StubExecutor.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest(input)
        }
        fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest_v3(input)
        }
        fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.bundle_proof_digest(hc_bundle, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
            self.auths.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            StubExecutor.verify_auth(hc_auth, proof, binding)
        }
        fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.bundle_gas_limit(proof)
        }
        fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.auth_gas_limit(proof)
        }
        fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), ConfidentialError> {
            self.bundles.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            StubExecutor.verify_bundle(hc_bundle, proof, binding)
        }
        fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            StubExecutor.aggregate_program_digest(shape)
        }
        fn verify_aggregate(
            &self,
            shape: &crate::types::DeclaredShape,
            covered: &[crate::types::CoveredBundle],
            proof: &[u8],
            binding: &[u32; 8],
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            StubExecutor.verify_aggregate(shape, covered, proof, binding)
        }
    }

    /// The set a node hands the ledger at apply, in miniature: the transaction hashes whose
    /// proofs admission verified.
    struct Admitted(std::collections::BTreeSet<Hash>);

    impl Admitted {
        fn of(txs: &[&Transaction]) -> Admitted {
            Admitted(txs.iter().map(|t| t.hash()).collect())
        }
    }

    impl VerifiedProofs for Admitted {
        fn contains(&self, tx: &Hash) -> bool {
            self.0.contains(tx)
        }
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    /// Audit v3, B5: a proof verified at admission is not verified again when the transaction's
    /// block applies. Admission's verdict is keyed on the transaction hash, which binds the
    /// proof; everything stateful — anchors, nullifiers, nonces, digests — is re-checked either
    /// way. A transaction admission never saw is verified at apply as it always was.
    #[test]
    fn apply_skips_the_proof_of_an_admitted_transaction() {
        let mut l = ledger();
        let (a, _) = keys();
        let exec = CountingExecutor::default();
        // Admission verifies the bundle's proof once.
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        l.validate(&t, &exec).unwrap();
        assert_eq!(exec.bundles(), 1, "admission verified the proof");
        let root = root_after(&l, std::slice::from_ref(&t), &a.address(), 1);
        let block = signed_block(vec![t.clone()], &a, 1, root);
        l.apply_block_with(&block, &exec, &Admitted::of(&[&t])).unwrap();
        assert_eq!(exec.bundles(), 1, "an admitted transaction's proof is not verified again at apply");
        // A transaction that was never admitted is still verified at apply.
        let t = tx(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]]);
        let root = root_after(&l, std::slice::from_ref(&t), &a.address(), 2);
        let block = signed_block(vec![t], &a, 2, root);
        l.apply_block_with(&block, &exec, &Admitted::of(&[])).unwrap();
        assert_eq!(exec.bundles(), 2, "a transaction admission never saw is verified at apply");

        // The same for a call's proof: decoded for its outcome at apply, not verified.
        let (mut l, id) = ledger_with_program(|_| {});
        let t = call_tx(&l, 20, id, StubExecutor::make_proof(&id, 12, [9; 8]), fee_for(0));
        l.validate(&t, &exec).unwrap();
        assert_eq!(exec.calls(), 1, "admission verified the call's proof");
        let root = root_after(&l, std::slice::from_ref(&t), &a.address(), 1);
        let block = signed_block(vec![t.clone()], &a, 1, root);
        l.apply_block_with(&block, &exec, &Admitted::of(&[&t])).unwrap();
        assert_eq!(exec.calls(), 1, "an admitted call's proof is decoded, not verified, at apply");
        let t = call_tx(&l, 30, id, StubExecutor::make_proof(&id, 12, [9; 8]), fee_for(0));
        let root = root_after(&l, std::slice::from_ref(&t), &a.address(), 2);
        let block = signed_block(vec![t], &a, 2, root);
        l.apply_block_with(&block, &exec, &Admitted::of(&[])).unwrap();
        assert_eq!(exec.calls(), 2, "a call admission never saw is verified at apply");
    }

    #[test]
    fn mint_needs_the_faucet_a_validator_signature_and_no_bundle() {
        let mut l = ledger();
        let (a, _) = keys();
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let mint = |amount, k: &Keypair| Transaction::mint(7, [5; 8], 0, [6; 8], env(), amount, k, &StubExecutor);
        let t = mint(FAUCET_MAX_UNITS, &a);
        let cm = t.commitments()[0];
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&mint(FAUCET_MAX_UNITS + 1, &a), &StubExecutor),
            Err(TxError::MintTooLarge { amount: FAUCET_MAX_UNITS + 1, cap: FAUCET_MAX_UNITS })
        );
        assert_eq!(l.validate(&mint(1, &stranger), &StubExecutor), Err(TxError::MinterNotValidator(stranger.address())));
        let mut forged = mint(1, &a);
        if let Action::Mint { amount, .. } = &mut forged.action {
            *amount = 2;
        }
        assert_eq!(l.validate(&forged, &StubExecutor), Err(TxError::BadMintSignature));
        let with_bundle =
            Transaction { bundle: Some(bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE)), ..t.clone() };
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle("mint")));
        let no_bundle = Transaction { chain_id: 7, bundle: None, action: Action::None };
        assert_eq!(l.validate(&no_bundle, &StubExecutor), Err(TxError::MissingBundle));
        l.set_faucet(false);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::FaucetDisabled));
        l.set_faucet(true);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.has_commitment(&cm));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists(cm)));
    }

    /// Audit v3, POOL-1: a validator declares one unit, signs, and appends the commitment of a note
    /// worth far more. The signature is honest — the validator signed exactly these bytes — so only
    /// a ledger-derived commitment refuses it. Accepted before the fix (the supply would have
    /// counted one unit for a note worth a million).
    #[test]
    fn a_mint_whose_commitment_opens_to_more_than_its_amount_is_refused() {
        let mut l = ledger();
        let (a, _) = keys();
        let (pk, time, r) = ([5; 8], 0, [6; 8]);
        let big = mint_commitment(&StubExecutor, &pk, 1_000_000, time, &r);
        let signing = Transaction::mint_signing_hash(7, &big, &pk, time, &r, &env(), 1);
        let forged = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Mint {
                cm: big,
                pk,
                time,
                r,
                envelope: env(),
                amount: 1,
                minter: a.public_key().clone(),
                signature: a.sign(signing.as_bytes()),
            },
        };
        assert_eq!(l.validate(&forged, &StubExecutor), Err(TxError::MintCommitmentMismatch));
        let before = l.clone();
        assert_eq!(l.apply_tx(&forged, &a.address(), &StubExecutor), Err(TxError::MintCommitmentMismatch));
        assert_eq!(l, before, "nothing minted");
        // A stale opening time is refused like a withdraw's, before any signature work.
        l.set_height(TIME_WINDOW + 1);
        let stale = Transaction::mint(7, pk, 0, r, env(), 1, &a, &StubExecutor);
        assert_eq!(l.validate(&stale, &StubExecutor), Err(TxError::TimeOutOfWindow { time: 0, height: TIME_WINDOW + 1, window: TIME_WINDOW }));
    }

    #[test]
    fn deploy_and_call_ride_on_bundles_and_pay_their_floors() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let under =
            StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), deploy.clone()));
        assert_eq!(
            l.validate(&under, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: gas::BUNDLE_BASE })
        );
        let ok = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy.clone(),
        ));
        l.apply_tx(&ok, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        assert!(l.program(&id).is_some());
        let proof = StubExecutor::make_proof(&id, 12, [1, 2, 3, 4, 5, 6, 7, 8]);
        let call = Action::Call { program: id, proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], fee), call.clone()));
        let r = l.apply_tx(&t, &a.address(), &StubExecutor).unwrap().unwrap();
        l.record_anchor(l.height());
        assert_eq!(r.outputs, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.tier, 12);
        let cheap = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[9; 8], [10; 8]], [[11; 8], [12; 8]], fee - 1), call.clone()));
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: fee, fee: fee - 1 }));
        l.set_confidential(false);
        // A fresh transaction: `t`'s nullifiers are spent by now, and `Spent` would fire first.
        let disabled = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[13; 8], [14; 8]], [[15; 8], [16; 8]], fee), call));
        assert_eq!(l.validate(&disabled, &StubExecutor), Err(TxError::ConfidentialDisabled));
    }

    /// Step 1 caps every variable-length field the new actions carry, before any signature or
    /// proof work — and before the action step, which is what makes the cap the error a fat
    /// transaction gets. A transaction that clears the cap is still refused further down (an
    /// unregistered validator for S2's staking, `Bridge(Disabled)` for S3's bridge actions on
    /// this bridge-less ledger); what it is never refused for is its size.
    #[test]
    fn the_new_actions_are_size_capped_at_step_one() {
        let l = ledger();
        let v = Address([1; 32]);
        let sig = crate::crypto::Signature::empty();
        let recipient = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        // An envelope of exactly `body` bytes of payload, so the cap edge is exact.
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        let check = |n: u32, action: Action, expect: Result<(), TxError>| {
            // Bundle-less actions are handed over as they ride; everything else gets a bundle
            // that pays its floor, so the only thing under test is the cap.
            let t = match action.bundle_less() {
                Some(_) => Transaction { chain_id: 7, bundle: None, action },
                None => {
                    let b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::fee_floor(&action));
                    StubExecutor::bound(Transaction::shielded(7, b, action))
                }
            };
            let got = l.validate(&t, &StubExecutor);
            match expect {
                Err(e) => assert_eq!(got, Err(e), "n={n}"),
                // "the cap passed": whatever refuses this transaction next, it is not a size
                // error. (A `Withdraw` now reaches the staking rules and is refused there for
                // naming a validator no register holds.)
                Ok(()) => assert!(
                    !matches!(
                        got,
                        Err(TxError::EnvelopeTooLarge | TxError::AttestationTooLarge | TxError::ProofTooLarge)
                    ),
                    "n={n}: {got:?}"
                ),
            }
        };
        let withdraw = |envelope: Envelope| Action::Withdraw {
            validator: v,
            amount: 5,
            nonce: 0,
            time: 0,
            r: [7; 8],
            envelope,
            signature: sig.clone(),
        };
        check(200, withdraw(fat(MAX_ENVELOPE_BYTES)), Ok(()));
        check(204, withdraw(fat(MAX_ENVELOPE_BYTES + 1)), Err(TxError::EnvelopeTooLarge));

        let attest = |attestation: Vec<u8>, envelope: Envelope| Action::BridgeAttest {
            attestation,
            recipient: recipient.clone(),
            r: [7; 8],
            time: l.height() as u32,
            asset: 1,
            envelope,
            pq_signatures: Vec::new(),
        };
        check(208, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES)), Ok(()));
        check(212, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES + 1)), Err(TxError::EnvelopeTooLarge));
        check(216, attest(vec![1; gas::MAX_ATTESTATION_BYTES], env()), Ok(()));
        check(220, attest(vec![1; gas::MAX_ATTESTATION_BYTES + 1], env()), Err(TxError::AttestationTooLarge));

        // Every one of the bundle's four envelopes is capped — the dummy slots' too: exactly at
        // `MAX_ENVELOPE_BYTES` is accepted, one byte over is refused, in each slot.
        let slot_tx = |slot: usize, body: usize| {
            let n = 240 + slot as u32;
            let mut b = bundle(&l, [[n; 8], [n + 10; 8]], [[n + 20; 8], [n + 30; 8]], gas::BUNDLE_BASE);
            b.envelopes[slot] = fat(body);
            StubExecutor::bound(Transaction::shielded(7, b, Action::None))
        };
        for slot in 0..4usize {
            assert_eq!(l.validate(&slot_tx(slot, MAX_ENVELOPE_BYTES), &StubExecutor), Ok(()), "slot {slot} at the cap");
            assert_eq!(
                l.validate(&slot_tx(slot, MAX_ENVELOPE_BYTES + 1), &StubExecutor),
                Err(TxError::EnvelopeTooLarge),
                "slot {slot} one byte over"
            );
        }
    }

    /// Spec 2026-09-26 §2.4: under a genesis `envelope_bytes`, every bundle envelope — each of
    /// the four slots — is exactly that long; one byte either side is refused at step 1.
    #[test]
    fn under_envelope_bytes_a_bundle_envelope_must_be_exactly_that_long() {
        use crate::notes::MEMO_ENVELOPE_BYTES as W;
        let mut l = ledger();
        l.set_envelope_bytes(Some(W));
        assert_eq!(l.envelope_bytes(), Some(W));
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        let slot_tx = |l: &Ledger, n: u32, slot: usize, len: usize| {
            let mut b = bundle(l, [[n; 8], [n + 10; 8]], [[n + 20; 8], [n + 30; 8]], gas::BUNDLE_BASE);
            for e in b.envelopes.iter_mut() {
                *e = fat(W);
            }
            b.envelopes[slot] = fat(len);
            StubExecutor::bound(Transaction::shielded(7, b, Action::None))
        };
        for slot in 0..4usize {
            let n = 300 + slot as u32;
            for (len, ok) in [(W - 1, false), (W, true), (W + 1, false)] {
                let r = l.validate(&slot_tx(&l, n, slot, len), &StubExecutor);
                if ok {
                    assert_eq!(r, Ok(()), "slot {slot} len {len}");
                } else {
                    assert_eq!(r, Err(TxError::EnvelopeSize { expected: W, got: len }), "slot {slot} len {len}");
                }
            }
        }
        // The dummy slots' short envelopes a bundle carried before the memo are refused too.
        let mut b = bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE);
        b.envelopes[0] = fat(W);
        b.envelopes[1] = fat(W);
        b.envelopes[2] = fat(W);
        b.envelopes[3] = fat(1348);
        let t = StubExecutor::bound(Transaction::shielded(7, b, Action::None));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: 1348 }));
    }

    /// The same rule on every action that carries a note envelope outside the bundle: a mint,
    /// a withdraw and a bridge attestation one byte short are refused by size, exactly-long
    /// ones never are.
    #[test]
    fn under_envelope_bytes_every_note_envelope_outside_the_bundle_is_exact_too() {
        use crate::notes::MEMO_ENVELOPE_BYTES as W;
        let mut l = ledger();
        l.set_envelope_bytes(Some(W));
        let (a, _) = keys();
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        let mint = |len: usize| Transaction::mint(7, [5; 8], 0, [6; 8], fat(len), 1, &a, &StubExecutor);
        assert_eq!(l.validate(&mint(W - 1), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W - 1 }));
        assert_eq!(l.validate(&mint(W + 1), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W + 1 }));
        assert!(!matches!(l.validate(&mint(W), &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)));
        let sig = crate::crypto::Signature::empty();
        let withdraw = |len: usize| {
            let action = Action::Withdraw {
                validator: Address([1; 32]),
                amount: 5,
                nonce: 0,
                time: 0,
                r: [7; 8],
                envelope: fat(len),
                signature: sig.clone(),
            };
            let b = bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], gas::fee_floor(&action));
            let mut b = b;
            for e in b.envelopes.iter_mut() {
                *e = fat(W);
            }
            StubExecutor::bound(Transaction::shielded(7, b, action))
        };
        assert_eq!(l.validate(&withdraw(W - 1), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W - 1 }));
        assert!(!matches!(l.validate(&withdraw(W), &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)));
        let attest = |len: usize| Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::BridgeAttest {
                attestation: vec![1; 32],
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [7; 8],
                time: l.height() as u32,
                asset: 1,
                envelope: fat(len),
                pq_signatures: Vec::new(),
            },
        };
        assert_eq!(l.validate(&attest(W - 1), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W - 1 }));
        assert!(!matches!(l.validate(&attest(W), &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)));

        // The RPL actions ride on a fee bundle (itself at the exact size), and their minted
        // note's envelope — `TokenMint`'s, and `RegisterToken`'s initial mint's — is held to
        // the same rule.
        let bundled = |n: u32, action: Action| {
            let mut b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::fee_floor(&action));
            for e in b.envelopes.iter_mut() {
                *e = fat(W);
            }
            StubExecutor::bound(Transaction::shielded(7, b, action))
        };
        let token_mint = |len: usize| Action::TokenMint {
            asset: 1,
            amount: 5,
            recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
            r: [7; 8],
            time: 0,
            envelope: fat(len),
            nonce: 0,
            signature: sig.clone(),
        };
        assert_eq!(l.validate(&bundled(60, token_mint(W - 1)), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W - 1 }));
        assert!(!matches!(
            l.validate(&bundled(70, token_mint(W)), &StubExecutor),
            Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)
        ));
        let register = |len: usize| Action::RegisterToken {
            name: "Test".into(),
            symbol: "TST".into(),
            decimals: 6,
            authority: tokens::MintAuthority::None,
            initial: Some(crate::types::actions::InitialMint {
                amount: 5,
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [7; 8],
                time: 0,
                envelope: fat(len),
            }),
            salt: [9; 32],
            index: 1,
        };
        assert_eq!(l.validate(&bundled(80, register(W + 1)), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W + 1 }));
        assert!(!matches!(
            l.validate(&bundled(90, register(W)), &StubExecutor),
            Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)
        ));
    }

    /// An aggregator's bond withdrawal appends a note (`append_deposit`) like a validator's
    /// `Withdraw`, so its envelope is a note envelope: exact under `envelope_bytes`, at most
    /// `MAX_ENVELOPE_BYTES` without it (fix round 1 — it escaped every size check before).
    #[test]
    fn a_withdraw_aggregator_envelope_is_a_note_envelope() {
        use crate::notes::MEMO_ENVELOPE_BYTES as W;
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        let withdraw = |len: usize| Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::WithdrawAggregator {
                aggregator: Address([1; 32]),
                nonce: 0,
                time: 0,
                r: [7; 8],
                envelope: fat(len),
                signature: crate::crypto::Signature::empty(),
            },
        };
        let mut l = ledger();
        assert_eq!(l.validate(&withdraw(MAX_ENVELOPE_BYTES + 1), &StubExecutor), Err(TxError::EnvelopeTooLarge));
        assert!(!matches!(l.validate(&withdraw(1348), &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)));
        l.set_envelope_bytes(Some(W));
        assert_eq!(l.validate(&withdraw(W - 1), &StubExecutor), Err(TxError::EnvelopeSize { expected: W, got: W - 1 }));
        assert!(!matches!(l.validate(&withdraw(W), &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)));
    }

    /// Chain 14 unchanged: without the genesis field a 1 348-byte (legacy) and a 1 860-byte
    /// (memo) envelope both pass, and the at-most rule is still `MAX_ENVELOPE_BYTES`.
    #[test]
    fn without_envelope_bytes_the_at_most_rule_is_unchanged() {
        let l = ledger();
        assert_eq!(l.envelope_bytes(), None);
        let (a, _) = keys();
        let fat = |body: usize| Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![3; body] };
        for (n, len) in [(400u32, 1348usize), (410, crate::notes::MEMO_ENVELOPE_BYTES), (420, MAX_ENVELOPE_BYTES)] {
            let mut b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::BUNDLE_BASE);
            for e in b.envelopes.iter_mut() {
                *e = fat(len);
            }
            assert_eq!(l.validate(&StubExecutor::bound(Transaction::shielded(7, b, Action::None)), &StubExecutor), Ok(()), "{len}");
            let m = Transaction::mint(7, [5; 8], 0, [6; 8], fat(len), 1, &a, &StubExecutor);
            assert!(!matches!(l.validate(&m, &StubExecutor), Err(TxError::EnvelopeSize { .. } | TxError::EnvelopeTooLarge)), "{len}");
        }
        let mut b = bundle(&l, [[430; 8], [431; 8]], [[432; 8], [433; 8]], gas::BUNDLE_BASE);
        b.envelopes[0] = fat(MAX_ENVELOPE_BYTES + 1);
        assert_eq!(
            l.validate(&StubExecutor::bound(Transaction::shielded(7, b, Action::None)), &StubExecutor),
            Err(TxError::EnvelopeTooLarge)
        );
    }

    /// The one rule of the call-input envelope the chain does enforce, through a real ledger.
    #[test]
    fn a_call_envelope_passes_when_absent_or_small_and_is_capped() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy,
        ));
        l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let envelope = |body: usize| crate::types::CallEnvelope {
            kem_ct: vec![1; 1088],
            to_sender: vec![2; 60],
            to_auditor: vec![3; 60],
            body: vec![4; body],
        };
        let fits = crate::types::MAX_CALL_ENVELOPE_BYTES - (1088 + 60 + 60);
        for (n, input_envelope, expect) in [
            (10u32, None, Ok(())),
            (20, Some(envelope(16)), Ok(())),
            (30, Some(envelope(fits)), Ok(())),
            (40, Some(envelope(fits + 1)), Err(TxError::EnvelopeTooLarge)),
        ] {
            let proof = StubExecutor::make_proof(&id, 12, [0; 8]);
            let action = Action::Call { program: id, proof, input_envelope };
            let b = bundle(&l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee);
            assert_eq!(l.validate(&StubExecutor::bound(Transaction::shielded(7, b, action)), &StubExecutor), expect, "n={n}");
        }
    }

    /// The chain's other half of the call-envelope story (spec §6.1): what it does not check,
    /// it still has to carry. The envelope travels with the call's receipt, which is how an
    /// auditor handed a key months later finds the transcript by transaction hash — and how a
    /// node serves `rand_getCallEnvelope` without re-reading the block.
    #[test]
    fn a_call_receipt_carries_the_envelope_its_call_published() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy,
        ));
        l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let envelope = crate::types::CallEnvelope {
            kem_ct: vec![1; 1088],
            to_sender: vec![2; 60],
            to_auditor: vec![3; 60],
            body: vec![4; 128],
        };
        let sealed = Action::Call {
            program: id,
            proof: StubExecutor::make_proof(&id, 12, [5; 8]),
            input_envelope: Some(envelope.clone()),
        };
        let bare =
            Action::Call { program: id, proof: StubExecutor::make_proof(&id, 12, [6; 8]), input_envelope: None };
        let t1 = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[10; 8], [11; 8]], [[12; 8], [13; 8]], fee), sealed));
        let t2 = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[20; 8], [21; 8]], [[22; 8], [23; 8]], fee), bare));
        let txs = vec![t1.clone(), t2.clone()];
        let block = signed_block(txs.clone(), &a, 2, root_after(&l, &txs, &a.address(), 2));
        let receipts = l.apply_block(&block, &StubExecutor).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].tx, t1.hash());
        assert_eq!(receipts[0].input_envelope, Some(envelope), "the sealed transcript rides with the receipt");
        assert_eq!(receipts[0].outputs, [5; 8]);
        assert_eq!(receipts[1].tx, t2.hash());
        assert_eq!(receipts[1].input_envelope, None, "a call made with --no-envelope stays bare");
        // And it survives the wire: receipts are stored and served as bincode rows.
        let back: CallReceipt = bincode::deserialize(&bincode::serialize(&receipts[0]).unwrap()).unwrap();
        assert_eq!(back, receipts[0]);
    }

    #[test]
    fn deploy_and_call_rejections_and_redeploy_idempotence() {
        let mut l = ledger();
        let (a, _) = keys();
        // An oversized program is refused by the size cap, before any fee or code check.
        let big = Action::Deploy { base_pc: 0, words: vec![0x13; gas::MAX_PROGRAM_WORDS + 1], public: vec![] };
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), big));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::ProgramTooLarge));
        // A call naming a program nobody deployed.
        let ghost = Hash::digest(b"never deployed");
        let unknown = Action::Call { program: ghost, proof: Vec::new(), input_envelope: None };
        let t = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&unknown)),
            unknown,
        ));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownProgram(ghost)));
        // Deploy two programs, then call one with the other's proof.
        let words = vec![0x13u32; 4];
        let other = vec![0x73u32; 4];
        for (n, code) in [(0u32, &words), (1, &other)] {
            let deploy = Action::Deploy { base_pc: 0, words: code.clone(), public: vec![] };
            let d = StubExecutor::bound(Transaction::shielded(
                7,
                bundle(&l, [[10 + n; 8], [20 + n; 8]], [[30 + n; 8], [40 + n; 8]], gas::fee_floor(&deploy)),
                deploy,
            ));
            l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
            l.record_anchor(l.height());
        }
        let (id, other_id) = (program_id(0, &words), program_id(0, &other));
        let wrong_proof = StubExecutor::make_proof(&other_id, 12, [0; 8]);
        let call = Action::Call { program: id, proof: wrong_proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], fee), call));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::InvalidProof(ConfidentialError::WrongProgram)));
        // Redeploying the same code is a no-op: the record keeps its original height.
        assert_eq!(l.program(&id).unwrap().deployed_at, 1);
        l.set_height(9);
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let again = StubExecutor::bound(Transaction::shielded(
            7,
            bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], gas::fee_floor(&deploy)),
            deploy,
        ));
        l.apply_tx(&again, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.programs().len(), 2);
        assert_eq!(l.program(&id).unwrap().deployed_at, 1, "a redeploy does not move deployed_at");
    }

    /// Redeploying a program with the same code *and the same public input* is what a redeploy
    /// has always been (`deploy_and_call_rejections_and_redeploy_idempotence`): it validates and
    /// applies, pays its full floor — code and public words — to the proposer like any deploy,
    /// spends its bundle's nullifiers, and leaves the record exactly as the first deploy wrote it
    /// (same `deployed_at`, digest and `public_len`), with no second record.
    #[test]
    fn a_redeploy_with_the_same_public_input_is_a_no_op_that_pays_its_fee() {
        let mut l = ledger();
        l.set_max_program_public_words(16);
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let public = vec![7u32, 8, 9];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: public.clone() };
        let floor = gas::fee_floor(&deploy);
        assert_eq!(floor, gas::BUNDLE_BASE + gas::deploy_fee(words.len() + public.len()));
        let first = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], floor), deploy.clone()));
        l.apply_tx(&first, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = crate::program::program_id_with_public(0, &words, &public);
        let before = l.program(&id).cloned().expect("deployed");
        assert_eq!(before.deployed_at, 1);

        l.set_height(9);
        // The redeploy is refused below its floor like any deploy: the public words are paid for again.
        let cheap = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], floor - 1), deploy.clone()));
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        let again = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], floor), deploy));
        assert_eq!(l.validate(&again, &StubExecutor), Ok(()));
        let (fees, rewards) = (l.supply().fees_paid, l.validators()[&a.address()].rewards);
        assert_eq!(l.apply_tx(&again, &a.address(), &StubExecutor).unwrap(), None, "a deploy has no receipt");
        assert_eq!(l.supply().fees_paid, fees + floor, "the redeploy's fee is charged");
        assert_eq!(l.validators()[&a.address()].rewards, rewards + floor, "and paid to the proposer");
        assert!(l.is_spent(&[5; 8]) && l.is_spent(&[6; 8]), "its bundle's nullifiers are spent");
        assert_eq!(l.programs().len(), 1, "no second record");
        assert_eq!(l.program(&id), Some(&before), "the record is untouched: deployed_at, digest, public_len");
    }

    /// A public input fixed at deploy (the call limits, spec §5): the program gets the
    /// `rand-program-2` id, pays `DEPLOY_PER_WORD` for its public words as for its code, and its
    /// record carries the executor's digest of them.
    #[test]
    fn a_deploy_with_public_words_gets_the_new_id_pays_for_them_and_stores_the_digest() {
        let mut l = ledger();
        l.set_max_program_public_words(16);
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let public = vec![7u32, 8, 9];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: public.clone() };
        assert_eq!(gas::fee_floor(&deploy), gas::BUNDLE_BASE + gas::deploy_fee(7));
        let code_only = gas::BUNDLE_BASE + gas::deploy_fee(words.len());
        let under = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], code_only), deploy.clone()));
        assert_eq!(
            l.validate(&under, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: code_only }),
            "the public words are paid for"
        );
        let ok =
            StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy));
        l.apply_tx(&ok, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = crate::program::program_id_with_public(0, &words, &public);
        assert_ne!(id, program_id(0, &words));
        let rec = l.program(&id).expect("deployed under the new id");
        assert_eq!(rec.public_digest, Some(StubExecutor.public_digest(&public)));
        assert_eq!(rec.public_len, 3);
        assert_eq!(rec.words, words);
        assert!(l.program(&program_id(0, &words)).is_none(), "the same code without the input is another program");
        // A program deployed without a public input keeps today's id and records no digest.
        let plain = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        assert_eq!(gas::fee_floor(&plain), gas::BUNDLE_BASE + gas::deploy_fee(4));
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], gas::fee_floor(&plain)), plain));
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.program(&program_id(0, &words)).unwrap().public_digest, None);
        assert_eq!(l.program(&program_id(0, &words)).unwrap().public_len, 0);
    }

    /// The public-input cap is the ledger's `max_program_public_words`, checked at step 1 before
    /// any fee or code work; today's default, 0, admits no public input at all.
    #[test]
    fn a_deploy_over_the_public_cap_is_refused() {
        let deploy = |l: &Ledger, n: usize| {
            let action = Action::Deploy { base_pc: 0, words: vec![0x13; 4], public: vec![1; n] };
            StubExecutor::bound(Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action))
        };
        let l = ledger();
        assert_eq!(l.validate(&deploy(&l, 0), &StubExecutor), Ok(()));
        assert_eq!(l.validate(&deploy(&l, 1), &StubExecutor), Err(TxError::ProgramPublicTooLarge));
        let mut raised = ledger();
        raised.set_max_program_public_words(3);
        assert_eq!(raised.validate(&deploy(&raised, 3), &StubExecutor), Ok(()));
        assert_eq!(raised.validate(&deploy(&raised, 4), &StubExecutor), Err(TxError::ProgramPublicTooLarge));
        // Before the fee: an underpaying oversized deploy is refused for its size.
        let action = Action::Deploy { base_pc: 0, words: vec![0x13; 4], public: vec![1; 4] };
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&raised, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), action));
        assert_eq!(raised.validate(&t, &StubExecutor), Err(TxError::ProgramPublicTooLarge));
    }

    /// A call against a program with a public input verifies only with a proof committed to
    /// exactly those words, and its receipt carries the digest it was checked against; a program
    /// without one takes only empty-input proofs and its receipts carry no digest.
    #[test]
    fn a_call_is_checked_against_the_programs_public_digest_and_the_receipt_carries_it() {
        let mut l = ledger();
        l.set_max_program_public_words(16);
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let public = vec![7u32, 8, 9];
        let mut n = 0u32;
        let mut next = || {
            n += 4;
            [[n; 8], [n + 1; 8], [n + 2; 8], [n + 3; 8]]
        };
        for p in [public.clone(), vec![]] {
            let d = Action::Deploy { base_pc: 0, words: words.clone(), public: p };
            let [n0, n1, c0, c1] = next();
            let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [n0, n1], [c0, c1], gas::fee_floor(&d)), d));
            l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
            l.record_anchor(l.height());
        }
        let id = crate::program::program_id_with_public(0, &words, &public);
        let plain = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let mut call = |l: &mut Ledger, program: ProgramId, proof: Vec<u8>, apply: bool| {
            let [n0, n1, c0, c1] = next();
            let t = StubExecutor::bound(Transaction::shielded(
                7,
                bundle(l, [n0, n1], [c0, c1], fee),
                Action::Call { program, proof, input_envelope: None },
            ));
            if apply {
                let r = l.apply_tx(&t, &a.address(), &StubExecutor).map(|r| r.unwrap());
                l.record_anchor(l.height());
                r
            } else {
                l.validate(&t, &StubExecutor).map(|_| unreachable!("refused"))
            }
        };
        let bad = Err(TxError::InvalidProof(ConfidentialError::InvalidProof("PublicValues".into())));
        let right = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &public);
        let r = call(&mut l, id, right, true).unwrap();
        assert_eq!(r.h_pub, Some(StubExecutor.public_digest(&public)));
        assert_eq!(r.outputs, [1; 8]);
        let other = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &[7, 8, 10]);
        assert_eq!(call(&mut l, id, other, false), bad);
        assert_eq!(call(&mut l, id, StubExecutor::make_proof(&id, 12, [1; 8]), false), bad);
        // The plain program: empty-input proofs, as today, and no digest on the receipt.
        let r = call(&mut l, plain, StubExecutor::make_proof(&plain, 12, [2; 8]), true).unwrap();
        assert_eq!(r.h_pub, None);
        let with_input = StubExecutor::make_proof_with_public(&plain, 12, [2; 8], &public);
        assert_eq!(call(&mut l, plain, with_input, false), bad);
    }

    /// ZKV-11: under genesis `hardening_v6` a deploy whose *padded* program table crosses the
    /// u32 pc wrap is refused, at admission and at apply alike. Fib's 15 words at `0xffffffc4` end
    /// exactly at 2^32 (ZH4's bound admits them) but pad to 16 rows, one past it. The window is the
    /// floored table's (PCW-FLOOR): a hardened call declares 128 rows, so `0xffffffc0` — where the
    /// 16 unfloored rows end at 2^32 — is refused too, and `2^32 − 512` is the highest start that
    /// fits. Without the flag — chain 15 — the old rule stands.
    #[test]
    fn under_the_pc_window_flag_a_deploy_whose_padded_table_wraps_is_refused() {
        let (a, _) = keys();
        let deploy = |l: &Ledger, base_pc: u32, n: usize| {
            let action = Action::Deploy { base_pc, words: vec![0x13; n], public: vec![] };
            StubExecutor::bound(Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action))
        };
        let plain = ledger();
        assert!(!plain.hardening_v6(), "absent means the old rule");
        assert_eq!(plain.validate(&deploy(&plain, 0xffff_ffc4, 15), &StubExecutor), Ok(()), "the finding: admitted today");

        let mut gated = ledger();
        gated.set_hardening_v6(true);
        assert_eq!(gated, plain, "the flag is not part of equality");
        assert_eq!(gated.state_root(), plain.state_root(), "nor of the state root");
        let wraps = deploy(&gated, 0xffff_ffc4, 15);
        assert_eq!(gated.validate(&wraps, &StubExecutor), Err(TxError::BadProgram(crate::program::pc_window_error())));
        assert_eq!(gated.clone().apply_tx(&wraps, &a.address(), &StubExecutor), Err(TxError::BadProgram(crate::program::pc_window_error())));
        assert_eq!(
            gated.validate(&deploy(&gated, 0xffff_ffc0, 15), &StubExecutor),
            Err(TxError::BadProgram(crate::program::pc_window_error())),
            "PCW-FLOOR: 16 rows would end at 2^32, the floored 128 do not"
        );
        assert_eq!(gated.validate(&deploy(&gated, 0xffff_fe00, 15), &StubExecutor), Ok(()), "128 rows ending at 2^32 fit");
        // 128 words pad to 256 rows, so the same start that fit 15 words no longer does.
        assert_eq!(gated.validate(&deploy(&gated, 0xffff_fe00, 128), &StubExecutor), Err(TxError::BadProgram(crate::program::pc_window_error())));
        assert_eq!(gated.validate(&deploy(&gated, 0, 4), &StubExecutor), Ok(()), "every live program sits at base_pc 0");
    }

    /// A `StubExecutor` that calls one set of proof bytes non-canonical — the stand-in for a zkVM
    /// proof whose header the honest prover would not write (`non_canonical_proof`), since a stub
    /// proof has no header. Everything else is the stub's.
    struct FlaggingExecutor {
        flagged: Vec<Vec<u8>>,
    }

    impl ConfidentialExecutor for FlaggingExecutor {
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
            StubExecutor.check_program(base_pc, words)
        }
        fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            StubExecutor.verify_call(program, proof)
        }
        fn public_digest(&self, words: &[u32]) -> Word8 {
            StubExecutor.public_digest(words)
        }
        fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
            StubExecutor.node_hash(left, right)
        }
        fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
            StubExecutor.hash_domain(domain, msg)
        }
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            StubExecutor.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest(input)
        }
        fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest_v3(input)
        }
        fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.bundle_proof_digest(hc_bundle, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.verify_auth(hc_auth, proof, binding)
        }
        fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.bundle_gas_limit(proof)
        }
        fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.auth_gas_limit(proof)
        }
        fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), ConfidentialError> {
            StubExecutor.verify_bundle(hc_bundle, proof, binding)
        }
        fn non_canonical_proof(&self, proof: &[u8]) -> Option<String> {
            self.flagged.iter().any(|f| f == proof).then(|| "memory height 17".to_string())
        }
        fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            StubExecutor.aggregate_program_digest(shape)
        }
        fn verify_aggregate(
            &self,
            shape: &crate::types::DeclaredShape,
            covered: &[crate::types::CoveredBundle],
            proof: &[u8],
            binding: &[u32; 8],
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            StubExecutor.verify_aggregate(shape, covered, proof, binding)
        }
    }

    /// The canonical-proof rules (INT-5 first): under genesis `hardening_v6` a transaction whose
    /// bundle proof, or whose call proof, the executor calls non-canonical is refused, at
    /// admission and at apply alike, before any proof is verified; without the flag — chain 15 —
    /// the same bytes are valid (every node's pool refuses them as policy instead).
    #[test]
    fn under_hardening_v6_a_non_canonical_proof_is_refused() {
        let (a, _) = keys();
        let mut plain = ledger();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound(Transaction::shielded(7, bundle(&plain, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy));
        plain.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        plain.record_anchor(plain.height());
        let id = program_id(0, &words);

        let transfer = tx(&plain, [[10; 8], [11; 8]], [[12; 8], [13; 8]]);
        // Bound to its transaction (INT-4), so the only thing wrong with it under the flag is
        // what the flagging executor says.
        let mut call = Transaction::shielded(
            7,
            bundle(&plain, [[20; 8], [21; 8]], [[22; 8], [23; 8]], gas::BUNDLE_BASE + gas::call_fee(12, 0)),
            Action::Call { program: id, proof: vec![], input_envelope: None },
        );
        let call_proof = StubExecutor::make_proof_with_public(&id, 12, [5; 8], &call.call_binding(&crate::types::BindingDomain::ChainId));
        let Action::Call { proof, .. } = &mut call.action else { unreachable!() };
        *proof = call_proof.clone();
        let call = StubExecutor::bound(call);
        let bundle_proof = transfer.bundle.as_ref().unwrap().proof.clone();
        let ex = FlaggingExecutor { flagged: vec![bundle_proof, call_proof] };
        assert_eq!(plain.validate(&transfer, &ex), Ok(()), "the finding: valid today");

        let mut gated = plain.clone();
        gated.set_hardening_v6(true);
        let bundle_refused = Err(TxError::NonCanonicalProof("bundle proof: memory height 17".into()));
        assert_eq!(gated.validate(&transfer, &ex), bundle_refused);
        assert_eq!(gated.clone().apply_tx(&transfer, &a.address(), &ex).map(|_| ()), bundle_refused);
        assert_eq!(gated.validate(&call, &ex), Err(TxError::NonCanonicalProof("call proof: memory height 17".into())));
        assert_eq!(gated.validate(&transfer, &StubExecutor), Ok(()), "a canonical proof is valid under the flag");
        assert_eq!(gated.validate(&call, &StubExecutor), Ok(()));
    }

    /// INT-4: a call proof is not bound to its transaction, so a copy of someone's call proof
    /// attached under another fee bundle yields a second receipt — valid today on every chain.
    /// Under genesis `hardening_v6` a call against a program deployed without a public input must
    /// carry `Transaction::call_binding` as its public segment: the proof made for its own
    /// transaction verifies there, the same proof under another bundle does not, and today's
    /// unbound proof is refused. Without the flag nothing changes — a bound proof is refused there
    /// as a proof over a public segment the program never had. Flag-only by necessity: every
    /// wallet in the field proves the empty segment, so a pool policy would refuse every call.
    #[test]
    fn under_hardening_v6_a_call_proof_is_bound_to_its_transaction() {
        let (a, _) = keys();
        let mut plain = ledger();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound(Transaction::shielded(7, bundle(&plain, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy));
        plain.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        plain.record_anchor(plain.height());
        let id = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        // A wallet's order: the transaction with both proofs empty, the call proved against its
        // call binding, then the bundle bound to the whole.
        let call_tx = |l: &Ledger, nfs: [Word8; 2], proof: Option<Vec<u8>>| {
            let mut t = Transaction::shielded(7, bundle(l, nfs, [[nfs[0][0] + 2; 8], [nfs[0][0] + 3; 8]], fee), Action::Call { program: id, proof: vec![], input_envelope: None });
            let proof = proof.unwrap_or_else(|| StubExecutor::make_proof_with_public(&id, 12, [5; 8], &t.call_binding(&crate::types::BindingDomain::ChainId)));
            let Action::Call { proof: p, .. } = &mut t.action else { unreachable!() };
            *p = proof;
            StubExecutor::bound(t)
        };
        let unbound = StubExecutor::make_proof(&id, 12, [5; 8]);
        let first = call_tx(&plain, [[10; 8], [11; 8]], Some(unbound.clone()));
        let copy = call_tx(&plain, [[20; 8], [21; 8]], Some(unbound.clone()));
        assert_eq!(plain.validate(&first, &StubExecutor), Ok(()));
        assert_eq!(plain.validate(&copy, &StubExecutor), Ok(()), "the finding: the copy under another bundle is valid too");

        let mut gated = plain.clone();
        gated.set_hardening_v6(true);
        let bound = call_tx(&gated, [[30; 8], [31; 8]], None);
        let Action::Call { proof: bound_proof, .. } = &bound.action else { unreachable!() };
        assert_eq!(gated.validate(&bound, &StubExecutor), Ok(()), "the proof made for its own transaction");
        let refused = Err(TxError::InvalidProof(ConfidentialError::InvalidProof("PublicValues".into())));
        let lifted = call_tx(&gated, [[40; 8], [41; 8]], Some(bound_proof.clone()));
        assert_eq!(gated.validate(&lifted, &StubExecutor), refused, "the same proof under another fee bundle");
        assert_eq!(gated.clone().apply_tx(&lifted, &a.address(), &StubExecutor).map(|_| ()), refused);
        assert_eq!(gated.validate(&first, &StubExecutor), refused, "today's unbound proof");
        assert_eq!(plain.validate(&bound, &StubExecutor), refused, "without the flag a bound proof is a stranger");
    }

    /// INT-4's residual (issue #55): under `hardening_v6` a call against a program deployed *with*
    /// a public input kept the record's digest as its whole expectation — the ledger held only the
    /// digest, not the words — so a call proof made for one transaction verified under any other
    /// fee bundle, exactly the copy INT-4 closed for programs without one. The ledger now keeps the
    /// words (`Ledger::program_public`), and under the flag such a call proves over the program's
    /// public input followed by the call binding, `public ‖ call_binding`: the guest reads its
    /// public words at the same indices as before, and the copy fails the digest compare.
    #[test]
    fn under_hardening_v6_a_call_to_a_program_with_a_public_input_is_bound_too() {
        let (a, _) = keys();
        let mut gated = ledger();
        gated.set_hardening_v6(true);
        gated.set_max_program_public_words(64);
        let words = vec![0x13u32; 4];
        let public = vec![7u32, 8, 9];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: public.clone() };
        let d = StubExecutor::bound(Transaction::shielded(7, bundle(&gated, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy));
        gated.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        gated.record_anchor(gated.height());
        let id = crate::program::program_id_with_public(0, &words, &public);
        assert_eq!(gated.program_public(&id), Some(&public[..]), "the ledger keeps the deployed words");
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let segment = |t: &Transaction| [public.as_slice(), t.call_binding(&crate::types::BindingDomain::ChainId).as_slice()].concat();
        let call_tx = |l: &Ledger, nfs: [Word8; 2], proof: Option<Vec<u8>>| {
            let mut t = Transaction::shielded(7, bundle(l, nfs, [[nfs[0][0] + 2; 8], [nfs[0][0] + 3; 8]], fee), Action::Call { program: id, proof: vec![], input_envelope: None });
            let proof = proof.unwrap_or_else(|| StubExecutor::make_proof_with_public(&id, 12, [5; 8], &segment(&t)));
            let Action::Call { proof: p, .. } = &mut t.action else { unreachable!() };
            *p = proof;
            StubExecutor::bound(t)
        };
        let refused = Err(TxError::InvalidProof(ConfidentialError::InvalidProof("PublicValues".into())));
        // Before the fix: a proof over the public input alone, made once and attached anywhere.
        let unbound = StubExecutor::make_proof_with_public(&id, 12, [5; 8], &public);
        let copy = call_tx(&gated, [[20; 8], [21; 8]], Some(unbound));
        assert_eq!(gated.validate(&copy, &StubExecutor), refused, "an unbound proof, under any fee bundle, is refused under the flag");
        let bound = call_tx(&gated, [[30; 8], [31; 8]], None);
        assert_eq!(gated.validate(&bound, &StubExecutor), Ok(()), "the proof over public ‖ its own call binding");
        let Action::Call { proof: bound_proof, .. } = &bound.action else { unreachable!() };
        let lifted = call_tx(&gated, [[40; 8], [41; 8]], Some(bound_proof.clone()));
        assert_eq!(gated.validate(&lifted, &StubExecutor), refused, "the same proof under another fee bundle");
        assert_eq!(gated.clone().apply_tx(&lifted, &a.address(), &StubExecutor).map(|_| ()), refused);
        // Without the flag nothing moves: the record's digest, the words alone.
        let mut plain = gated.clone();
        plain.set_hardening_v6(false);
        let old = call_tx(&plain, [[50; 8], [51; 8]], Some(StubExecutor::make_proof_with_public(&id, 12, [5; 8], &public)));
        assert_eq!(plain.validate(&old, &StubExecutor), Ok(()));
    }

    /// CPU-1: under genesis `hardening_v6` a deploy of more words than any call can hold is
    /// refused, at admission and at apply alike — 8 180 words at tier 14 for a program without a
    /// public input, whose calls carry the eight-word call binding under the flag (8 184 with the
    /// empty segment, the pool's number), fewer beside a public input, which the binding follows
    /// (the stub restates the zkVM's bound). Without the flag
    /// — chain 15, whose genesis admits 65 535-word programs — the old rule stands and such a
    /// deploy is charged for a program no call can prove.
    #[test]
    fn under_hardening_v6_a_deploy_no_call_can_hold_is_refused() {
        let (a, _) = keys();
        let deploy = |l: &Ledger, n: usize, public: usize| {
            let action = Action::Deploy { base_pc: 0, words: vec![0x13; n], public: vec![7; public] };
            StubExecutor::bound(Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action))
        };
        let mut plain = ledger();
        plain.set_max_program_words(65_535);
        plain.set_max_program_public_words(32_768);
        assert_eq!(plain.validate(&deploy(&plain, 8185, 0), &StubExecutor), Ok(()), "the finding: admitted today");

        let mut gated = plain.clone();
        gated.set_hardening_v6(true);
        // Under the flag a call against a program without a public input carries the eight-word
        // call binding (INT-4) as its segment — two digest slots, one more than the empty
        // segment's — so the bound there is 8 180, four words under the pool's 8 184.
        let over = deploy(&gated, 8181, 0);
        let refused = Err(TxError::ProgramUncallable { words: 8181, public_words: 0, max_words: 8180 });
        assert_eq!(gated.validate(&over, &StubExecutor), refused);
        assert_eq!(gated.clone().apply_tx(&over, &a.address(), &StubExecutor).map(|_| ()), refused);
        assert_eq!(gated.validate(&deploy(&gated, 8180, 0), &StubExecutor), Ok(()), "the bound itself fits");
        // A 9-word public input is followed by the binding too under the flag (issue #55): a
        // 17-word segment, five digest slots, four more than the empty segment's one.
        assert_eq!(
            gated.validate(&deploy(&gated, 8169, 9), &StubExecutor),
            Err(TxError::ProgramUncallable { words: 8169, public_words: 9, max_words: 8168 })
        );
        assert_eq!(gated.validate(&deploy(&gated, 8168, 9), &StubExecutor), Ok(()));
        // The EVM interpreter guest, 18 009 words, is what the report found deployable and dead.
        assert!(matches!(gated.validate(&deploy(&gated, 18_009, 0), &StubExecutor), Err(TxError::ProgramUncallable { .. })));
    }

    /// The deploy cap is the ledger's, set from genesis, not the constant: a default ledger keeps
    /// today's 4 096 words exactly, and a ledger built with the zkVM's limit admits what the
    /// `rand-guest` toolchain produces (the EVM interpreter guest is 18 009 words). The cap is a
    /// genesis parameter, so it is outside both the state root and `Ledger`'s equality — a
    /// reloaded ledger, which starts at the default until `reload_ledger` sets it, still compares
    /// equal to the replayed one.
    #[test]
    fn the_deploy_cap_is_the_ledgers_and_defaults_to_4096_words() {
        let (a, _) = keys();
        let deploy = |l: &Ledger, n: usize| {
            let action = Action::Deploy { base_pc: 0, words: vec![0x13; n], public: vec![] };
            StubExecutor::bound(Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action))
        };
        let l = ledger();
        assert_eq!(l.max_program_words(), gas::MAX_PROGRAM_WORDS);
        assert_eq!(l.validate(&deploy(&l, gas::MAX_PROGRAM_WORDS + 1), &StubExecutor), Err(TxError::ProgramTooLarge));
        assert_eq!(l.validate(&deploy(&l, gas::MAX_PROGRAM_WORDS), &StubExecutor), Ok(()));
        assert_eq!(l.validate(&deploy(&l, 5000), &StubExecutor), Err(TxError::ProgramTooLarge));

        let mut raised = ledger();
        raised.set_max_program_words(gas::MAX_PROGRAM_WORDS_LIMIT);
        assert_eq!(raised.max_program_words(), gas::MAX_PROGRAM_WORDS_LIMIT);
        assert_eq!(raised, l, "the cap is not part of equality");
        assert_eq!(raised.state_root(), l.state_root(), "nor of the state root");
        assert_eq!(raised.validate(&deploy(&raised, 5000), &StubExecutor), Ok(()));
        assert_eq!(raised.validate(&deploy(&raised, gas::MAX_PROGRAM_WORDS_LIMIT), &StubExecutor), Ok(()));
        assert_eq!(
            raised.validate(&deploy(&raised, gas::MAX_PROGRAM_WORDS_LIMIT + 1), &StubExecutor),
            Err(TxError::ProgramTooLarge)
        );
        // And applying one stores the whole program.
        let t = deploy(&raised, 5000);
        raised.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        let id = program_id(0, &vec![0x13; 5000]);
        assert_eq!(raised.program(&id).unwrap().words.len(), 5000);
        // A clone — speculative execution, the tip ledger — keeps the cap.
        assert_eq!(raised.clone().max_program_words(), gas::MAX_PROGRAM_WORDS_LIMIT);
    }

    /// The four call-limits parameters (spec §3) live on the ledger the way `max_program_words`
    /// does: today's caps by default, set from genesis, outside the state root and equality, and
    /// kept by a clone. The rules that read them are tested below (`every_proof_cap_is_the_ledgers_max_proof_bytes`
    /// and its neighbours).
    #[test]
    fn the_call_limits_are_ledger_parameters_with_todays_defaults() {
        let l = ledger();
        assert_eq!(l.max_proof_bytes(), gas::MAX_PROOF_BYTES);
        assert_eq!(l.max_block_bytes(), gas::MAX_BLOCK_BYTES);
        assert_eq!(l.max_call_envelope_bytes(), crate::types::actions::MAX_CALL_ENVELOPE_BYTES);
        assert_eq!(l.max_program_public_words(), 0);

        let mut raised = ledger();
        raised.set_max_proof_bytes(8 << 20);
        raised.set_max_block_bytes(20 << 20);
        raised.set_max_call_envelope_bytes(65_536);
        raised.set_max_program_public_words(32_768);
        assert_eq!(raised, l, "the limits are not part of equality");
        assert_eq!(raised.state_root(), l.state_root(), "nor of the state root");
        let c = raised.clone();
        assert_eq!(
            (c.max_proof_bytes(), c.max_block_bytes(), c.max_call_envelope_bytes(), c.max_program_public_words()),
            (8 << 20, 20 << 20, 65_536, 32_768)
        );
    }

    /// `StubExecutor`, except that a call proof may carry padding after the stub's own bytes:
    /// how a test gets a proof the ledger has to *verify* at a size only the call limits admit.
    struct PaddedStub;

    impl PaddedStub {
        /// A stub call proof for `program` at tier 12, zero-padded to exactly `len` bytes.
        fn proof(program: &Hash, len: usize) -> Vec<u8> {
            let mut p = StubExecutor::make_proof(program, 12, [9; 8]);
            assert!(len >= p.len());
            p.resize(len, 0);
            p
        }
    }

    impl ConfidentialExecutor for PaddedStub {
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
            StubExecutor.check_program(base_pc, words)
        }
        fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            let n = StubExecutor::make_proof(&program.id, 0, [0; 8]).len();
            StubExecutor.verify_call(program, &proof[..n.min(proof.len())])
        }
        fn public_digest(&self, words: &[u32]) -> Word8 {
            StubExecutor.public_digest(words)
        }
        fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
            StubExecutor.node_hash(left, right)
        }
        fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
            StubExecutor.hash_domain(domain, msg)
        }
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            StubExecutor.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest(input)
        }
        fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest_v3(input)
        }
        fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.bundle_proof_digest(hc_bundle, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.verify_auth(hc_auth, proof, binding)
        }
        fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.bundle_gas_limit(proof)
        }
        fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            StubExecutor.auth_gas_limit(proof)
        }
        fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), ConfidentialError> {
            StubExecutor.verify_bundle(hc_bundle, proof, binding)
        }
        fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            StubExecutor.aggregate_program_digest(shape)
        }
        fn verify_aggregate(
            &self,
            shape: &crate::types::DeclaredShape,
            covered: &[crate::types::CoveredBundle],
            proof: &[u8],
            binding: &[u32; 8],
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            StubExecutor.verify_aggregate(shape, covered, proof, binding)
        }
    }

    /// A ledger with the four-word test program deployed, and its id.
    fn ledger_with_program(configure: impl FnOnce(&mut Ledger)) -> (Ledger, ProgramId) {
        let mut l = ledger();
        configure(&mut l);
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy));
        l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        (l, program_id(0, &words))
    }

    /// A call to `id` with `proof` and no envelope, paying `fee`, on nullifiers derived from `n`.
    fn call_tx(l: &Ledger, n: u32, id: ProgramId, proof: Vec<u8>, fee: u64) -> Transaction {
        let b = bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee);
        StubExecutor::bound(Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: None }))
    }

    /// What a call carrying `bytes` of proof and envelope pays: the bundle base and `call_fee`.
    fn fee_for(bytes: usize) -> u64 {
        gas::BUNDLE_BASE + gas::call_fee(12, bytes)
    }

    /// Spec §4, step 1: every proof cap — the bundle's and a call's —
    /// is the ledger's `max_proof_bytes`, not the constant. A proof one byte over 2 MiB is
    /// refused by a default ledger and passes the cap on one whose genesis set 8 MiB.
    #[test]
    fn every_proof_cap_is_the_ledgers_max_proof_bytes() {
        let over = gas::MAX_PROOF_BYTES + 1;
        let raise = |l: &mut Ledger| {
            l.set_max_proof_bytes(8 << 20);
            l.set_max_block_bytes(17 << 20);
        };
        let (default, id) = ledger_with_program(|_| {});
        let (raised, _) = ledger_with_program(raise);
        // Either size refusal counts: a proof the proof cap admits must not then trip the
        // whole-transaction cap on the raised ledger either.
        let size_error =
            |r: &Result<(), TxError>| matches!(r, Err(TxError::ProofTooLarge) | Err(TxError::TransactionTooLarge { .. }));

        // The call's own proof: refused by default, and verified and admitted when raised.
        let call = |l: &Ledger| call_tx(l, 20, id, PaddedStub::proof(&id, over), fee_for(over));
        assert_eq!(default.validate(&call(&default), &PaddedStub), Err(TxError::ProofTooLarge));
        assert_eq!(raised.validate(&call(&raised), &PaddedStub), Ok(()));
        let at_cap = call_tx(&raised, 30, id, PaddedStub::proof(&id, 8 << 20), fee_for(8 << 20));
        assert_eq!(raised.validate(&at_cap, &PaddedStub), Ok(()), "exactly at the raised cap");
        let past = call_tx(&raised, 40, id, PaddedStub::proof(&id, (8 << 20) + 1), fee_for((8 << 20) + 1));
        assert_eq!(raised.validate(&past, &PaddedStub), Err(TxError::ProofTooLarge));

        // The fee bundle's proof.
        let fat_bundle = |l: &Ledger| {
            let mut b = bundle(l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], gas::BUNDLE_BASE);
            b.proof = vec![0; over];
            StubExecutor::bound(Transaction::shielded(7, b, Action::None))
        };
        assert_eq!(default.validate(&fat_bundle(&default), &StubExecutor), Err(TxError::ProofTooLarge));
        let got = raised.validate(&fat_bundle(&raised), &StubExecutor);
        assert!(!size_error(&got), "the raised cap admits the bundle's size: {got:?}");

        // There is no second bundle any more (the hidden-asset bundle, spec §3.7): a burn's
        // one bundle is the one capped above.
    }

    /// Spec §4, step 1: the whole-transaction cap is the ledger's `max_block_bytes`. Two proofs
    /// at the default proof cap are over a default 4 MiB block, and fit a raised one.
    #[test]
    fn the_whole_transaction_cap_is_the_ledgers_max_block_bytes() {
        let (default, id) = ledger_with_program(|_| {});
        let (raised, _) = ledger_with_program(|l| l.set_max_block_bytes(5 << 20));
        let fat = |l: &Ledger| {
            let mut t = call_tx(l, 20, id, PaddedStub::proof(&id, gas::MAX_PROOF_BYTES), fee_for(gas::MAX_PROOF_BYTES));
            t.bundle.as_mut().unwrap().proof = vec![0; gas::MAX_PROOF_BYTES];
            t
        };
        let t = fat(&default);
        let size = t.encoded_len();
        assert!(size > gas::MAX_BLOCK_BYTES && size <= 5 << 20, "{size}");
        assert_eq!(
            default.validate(&t, &PaddedStub),
            Err(TxError::TransactionTooLarge { size, max: gas::MAX_BLOCK_BYTES })
        );
        let got = raised.validate(&fat(&raised), &PaddedStub);
        assert!(!matches!(got, Err(TxError::TransactionTooLarge { .. })), "{got:?}");
        // And a lowered cap bites a transaction the default admits: the rule reads the field.
        let (mut small, _) = ledger_with_program(|_| {});
        let ok = call_tx(&small, 70, id, StubExecutor::make_proof(&id, 12, [0; 8]), fee_for(0));
        assert_eq!(small.validate(&ok, &StubExecutor), Ok(()));
        small.set_max_block_bytes(ok.encoded_len() - 1);
        assert_eq!(
            small.validate(&ok, &StubExecutor),
            Err(TxError::TransactionTooLarge { size: ok.encoded_len(), max: ok.encoded_len() - 1 })
        );
        // Exactly at the cap is admitted: the rule is `size > max`, not `>=`.
        small.set_max_block_bytes(ok.encoded_len());
        assert_eq!(small.validate(&ok, &StubExecutor), Ok(()), "a transaction exactly at the cap");
        // And the 4 MiB transaction on a ledger whose cap is exactly its size passes the size
        // check (its zero-filled bundle proof is then refused by the stub, a later step).
        let (exact, _) = ledger_with_program(|_| {});
        let t = fat(&exact);
        let (mut exact, _) = ledger_with_program(|l| l.set_max_block_bytes(t.encoded_len()));
        let got = exact.validate(&t, &PaddedStub);
        assert!(!matches!(got, Err(TxError::TransactionTooLarge { .. })), "{} B at a {} B cap: {got:?}", t.encoded_len(), exact.max_block_bytes());
        exact.set_max_block_bytes(t.encoded_len() - 1);
        assert_eq!(
            exact.validate(&t, &PaddedStub),
            Err(TxError::TransactionTooLarge { size: t.encoded_len(), max: t.encoded_len() - 1 })
        );
    }

    /// Spec §4, step 7: the call envelope's cap is the ledger's `max_call_envelope_bytes`.
    #[test]
    fn the_call_envelope_cap_is_the_ledgers() {
        let (default, id) = ledger_with_program(|_| {});
        let (raised, _) = ledger_with_program(|l| l.set_max_call_envelope_bytes(65_536));
        let envelope = |total: usize| crate::types::CallEnvelope {
            kem_ct: vec![1; 1088],
            to_sender: vec![2; 60],
            to_auditor: vec![3; 60],
            body: vec![4; total - (1088 + 60 + 60)],
        };
        let call = |l: &Ledger, n: u32, total: usize| {
            let proof = StubExecutor::make_proof(&id, 12, [0; 8]);
            let bytes = proof.len() + total;
            let b = bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee_for(bytes));
            StubExecutor::bound(Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: Some(envelope(total)) }))
        };
        let today = crate::types::MAX_CALL_ENVELOPE_BYTES;
        assert_eq!(default.validate(&call(&default, 10, today), &StubExecutor), Ok(()));
        assert_eq!(default.validate(&call(&default, 20, today + 1), &StubExecutor), Err(TxError::EnvelopeTooLarge));
        assert_eq!(raised.validate(&call(&raised, 20, today + 1), &StubExecutor), Ok(()));
        assert_eq!(raised.validate(&call(&raised, 30, 65_536), &StubExecutor), Ok(()));
        assert_eq!(raised.validate(&call(&raised, 40, 65_537), &StubExecutor), Err(TxError::EnvelopeTooLarge));
    }

    /// The state root `txs` leave behind, like `root_after`, under `executor`.
    fn root_after_with(
        l: &Ledger,
        txs: &[Transaction],
        proposer: &Address,
        height: u64,
        executor: &dyn ConfidentialExecutor,
    ) -> Hash {
        let mut scratch = l.clone();
        scratch.set_height(height);
        scratch.apply_transactions(txs, proposer, executor).unwrap();
        scratch.record_anchor(height);
        scratch.state_root()
    }

    /// Spec §4: `apply_block_for_sync`'s byte cap is the ledger's `max_block_bytes`. A block
    /// carrying one 5 MiB call is refused as too large by a default ledger, and applied — the
    /// call verified, its receipt produced — by one whose genesis raised both caps.
    #[test]
    fn apply_block_for_sync_uses_the_ledgers_block_cap() {
        let (a, _) = keys();
        let limits = |l: &mut Ledger| {
            l.set_max_proof_bytes(8 << 20);
            l.set_max_block_bytes(17 << 20);
        };
        let (mut raised, id) = ledger_with_program(limits);
        let big = 5 << 20;
        let t = call_tx(&raised, 20, id, PaddedStub::proof(&id, big), fee_for(big));
        let txs = vec![t.clone()];
        let block = signed_block(txs.clone(), &a, 2, root_after_with(&raised, &txs, &a.address(), 2, &PaddedStub));

        let (mut default, _) = ledger_with_program(|_| {});
        assert_eq!(
            default.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub, &NoVerified),
            Err(BlockError::TooLarge)
        );
        let receipts = raised.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub, &NoVerified).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tx, t.hash());
        assert_eq!(receipts[0].outputs, [9; 8]);

        // One byte under the block's size, the raised ledger refuses the same block.
        let (mut tight, _) = ledger_with_program(|l| {
            limits(l);
            l.set_max_block_bytes(t.encoded_len() - 1);
        });
        assert_eq!(tight.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub, &NoVerified), Err(BlockError::TooLarge));
        // Exactly at the block's size, it is applied: the block cap is `bytes > max`, not `>=`.
        let (mut exact, _) = ledger_with_program(|l| {
            limits(l);
            l.set_max_block_bytes(t.encoded_len());
        });
        let receipts = exact.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub, &NoVerified).unwrap();
        assert_eq!(receipts.len(), 1, "a block exactly at the cap");
    }

    /// Spec §7: step 10 charges the byte term. A call that pays today's fee with a proof past the
    /// free allowance is refused for its fee, naming the fee it owes, and admitted paying it.
    #[test]
    fn a_call_paying_todays_fee_with_an_oversized_proof_is_refused_for_its_fee() {
        let (l, id) = ledger_with_program(|l| l.set_max_proof_bytes(8 << 20));
        let today = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let bytes = gas::CALL_FREE_BYTES + 1;
        let under = call_tx(&l, 20, id, PaddedStub::proof(&id, bytes), today);
        assert_eq!(
            l.validate(&under, &PaddedStub),
            Err(TxError::FeeTooLow { min: today + gas::CALL_PER_KIB, fee: today })
        );
        let paid = call_tx(&l, 20, id, PaddedStub::proof(&id, bytes), today + gas::CALL_PER_KIB);
        assert_eq!(l.validate(&paid, &PaddedStub), Ok(()));
        // At the allowance exactly, today's fee is still enough.
        let free = call_tx(&l, 30, id, PaddedStub::proof(&id, gas::CALL_FREE_BYTES), today);
        assert_eq!(l.validate(&free, &PaddedStub), Ok(()));
        // The envelope counts too: a proof at the allowance plus any envelope owes the byte term.
        let (le, _) = ledger_with_program(|l| l.set_max_proof_bytes(8 << 20));
        let proof = PaddedStub::proof(&id, gas::CALL_FREE_BYTES);
        let envelope = crate::types::CallEnvelope { kem_ct: vec![], to_sender: vec![2; 60], to_auditor: vec![], body: vec![] };
        let b = bundle(&le, [[40; 8], [41; 8]], [[42; 8], [43; 8]], today);
        let t = StubExecutor::bound(Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: Some(envelope) }));
        assert_eq!(le.validate(&t, &PaddedStub), Err(TxError::FeeTooLow { min: today + gas::CALL_PER_KIB, fee: today }));
    }

    /// Spec 2026-10-05 §5.3: a clone taken before a commit keeps answering, and the committed
    /// ledger's delta is empty after the commit step. A bundle writes all four nullifier slots,
    /// the two dummies included.
    #[test]
    fn shared_sets_commit_and_a_pre_commit_clone_still_answers() {
        let (a, _) = keys();
        let mut l = ledger();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let good = signed_block(vec![t1], &a, 1, root_after(&l, &[tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]])], &a.address(), 1));
        let snapshot = l.clone();
        l.apply_block(&good, &StubExecutor).unwrap();
        assert_eq!(l.nullifiers().added_len(), 4);
        l.commit_shared_sets();
        assert_eq!((l.nullifiers().added_len(), l.nullifiers().len()), (0, 4));
        assert!(l.is_spent(&[1; 8]));
        // The snapshot shares the base and now sees the committed spends — by design, since every
        // live clone descends from the committed head; its len() is exact.
        assert!(snapshot.is_spent(&[1; 8]));
        assert_eq!(snapshot.nullifiers().len(), 4);
    }

    #[test]
    fn state_root_covers_tree_nullifiers_validators_and_programs() {
        let mut l = ledger();
        let (a, _) = keys();
        let r0 = l.state_root();
        l.apply_tx(&tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        let r1 = l.state_root();
        assert_ne!(r0, r1);
        let mut l2 = ledger();
        l2.apply_tx(&tx(&l2, [[1; 8], [2; 8]], [[3; 8], [4; 8]]), &a.address(), &StubExecutor).unwrap();
        assert_eq!(l2.state_root(), r1, "deterministic");
        let rebuilt = Ledger::from_parts(
            7,
            HC,
            l.tree().clone(),
            l.commitments_set().snapshot(),
            l.nullifiers().snapshot(),
            l.anchors().iter().copied().collect(),
            l.validators().clone(),
            l.programs().clone(),
        );
        assert_eq!(rebuilt.state_root(), r1);
        assert_eq!(rebuilt, l);
    }

    /// The register is state: every field of the v2 validator leaf — including the two S2
    /// additions, `pending` and `payout` — moves the state root, so two chains that disagree
    /// about a validator's unbonding queue or where its rewards go cannot both be valid.
    #[test]
    fn validator_leaf_v2_changes_the_root_when_pending_or_payout_change() {
        let k = Keypair::from_seed([1; 32]).unwrap();
        let base = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 1_000,
            pending: Vec::new(),
            rewards: 0,
            payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        let root_of = |e: &ValidatorEntry| {
            let register: BTreeMap<Address, ValidatorEntry> = [(k.address(), e.clone())].into_iter().collect();
            Ledger::new(7, HC, register, &StubExecutor).state_root()
        };
        let r0 = root_of(&base);
        assert_eq!(r0, root_of(&base.clone()), "deterministic");
        let mut roots = vec![r0];
        for changed in [
            ValidatorEntry { stake: 1_001, ..base.clone() },
            ValidatorEntry { rewards: 1, ..base.clone() },
            ValidatorEntry { nonce: 1, ..base.clone() },
            ValidatorEntry { pending: vec![(3, 10)], ..base.clone() },
            ValidatorEntry { pending: vec![(4, 10)], ..base.clone() },
            ValidatorEntry { pending: vec![(3, 11)], ..base.clone() },
            ValidatorEntry { pending: vec![(3, 10), (4, 10)], ..base.clone() },
            ValidatorEntry {
                payout: crate::notes::ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] },
                ..base.clone()
            },
            ValidatorEntry {
                payout: crate::notes::ShieldedAddress { pk: [4; 8], kem_ek: vec![7; 32] },
                ..base.clone()
            },
        ] {
            let r = root_of(&changed);
            assert!(!roots.contains(&r), "a v2 leaf field does not reach the state root: {changed:?}");
            roots.push(r);
        }
    }

    /// Spec §10: the bridge root is the *fifth* component, appended only on a bridged chain.
    /// A chain without a `bridge` section hashes the same four roots phase S1 hashed, so
    /// turning the bridge on is a hard fork for the chains that take it and nothing at all for
    /// the ones that do not.
    #[test]
    fn the_bridge_root_is_appended_only_on_a_bridged_chain() {
        use crate::bridge::{BridgeConfig, BridgeState};

        let plain = ledger();
        let unbridged = plain.state_root();

        let config =
            BridgeConfig {
                emitter: [1; 32],
                guardians: vec![[2; 20]],
                emitters: BTreeMap::from([(2u16, [9u8; 32])]),
                pq_guardians: vec![],
                pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
                rules_v2: None,
                guardian_set_index: None,
                burn_sequence: None,
                min_inbound_sequence: None,
                rotation: None,
                fees: None,
            };
        let mut bridged = plain.clone();
        bridged.set_bridge(Some(BridgeState::from_config(&config)));
        assert_ne!(bridged.state_root(), unbridged, "the bridge root joins the commitment");
        // Clearing the bridge again returns exactly the four-component root, which is what makes
        // this fork opt-in: the fifth component is appended, never a zero placeholder.
        let mut cleared = bridged.clone();
        cleared.set_bridge(None);
        assert_eq!(cleared.state_root(), unbridged);

        // Bridge state is consensus state: a different guardian set is a different root.
        let mut other = plain.clone();
        let mut cfg2 = config.clone();
        cfg2.guardians = vec![[3; 20]];
        other.set_bridge(Some(BridgeState::from_config(&cfg2)));
        assert_ne!(other.state_root(), bridged.state_root());
        // And two ledgers whose only difference is the bridge are not the same ledger.
        assert_ne!(other, bridged);
    }

    /// On a bridged chain the block timestamp is consensus input: guardian-set expiry is
    /// evaluated against it (`bridge_notes::validate` calls `check_attest(.., ledger.now_secs())`)
    /// and outbound burn messages are stamped with it. So a Byzantine leader must not be able to
    /// rewind time and keep a superseded — possibly compromised — guardian set inside its grace
    /// window. Equal timestamps pass (the rule is `<`, not `<=`), and a chain with no bridge keeps
    /// byte-identical validity rules, because nothing on it reads a clock at all.
    #[test]
    fn a_bridged_chain_refuses_a_block_whose_timestamp_rewinds_its_parents() {
        use crate::bridge::{BridgeConfig, BridgeState};

        let (a, _) = keys();
        let empty = |l: &Ledger, height: u64, timestamp_ms: u64| {
            let header = BlockHeader {
                height,
                view: height,
                parent: Hash::ZERO,
                proposer: a.public_key().clone(),
                timestamp_ms,
                tx_root: Block::tx_root(&[]),
                state_root: root_after(l, &[], &a.address(), height),
                justify: QuorumCertificate::genesis(Hash::ZERO),
            };
            Block::sign(&crate::types::SigningDomain::v0(Hash::ZERO), header, Vec::new(), &a)
        };

        let config =
            BridgeConfig {
                emitter: [1; 32],
                guardians: vec![[2; 20]],
                emitters: BTreeMap::from([(2u16, [9u8; 32])]),
                pq_guardians: vec![],
                pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
                rules_v2: None,
                guardian_set_index: None,
                burn_sequence: None,
                min_inbound_sequence: None,
                rotation: None,
                fees: None,
            };
        let mut l = ledger();
        l.set_bridge(Some(BridgeState::from_config(&config)));
        l.set_timestamp_ms(1_000_000);

        assert_eq!(
            l.apply_block(&empty(&l, 2, 999_999), &StubExecutor),
            Err(BlockError::TimestampRewind { parent: 1_000_000, block: 999_999 })
        );
        // Equal is allowed, and so is moving forward — which is all the proposer ever emits
        // (`HotStuff::propose` builds `max(now_ms, parent.timestamp_ms)`).
        l.apply_block(&empty(&l, 2, 1_000_000), &StubExecutor).unwrap();
        l.apply_block(&empty(&l, 3, 1_000_001), &StubExecutor).unwrap();
        assert_eq!(
            l.apply_block(&empty(&l, 4, 1_000_000), &StubExecutor),
            Err(BlockError::TimestampRewind { parent: 1_000_001, block: 1_000_000 })
        );
        assert_eq!(l.timestamp_ms(), 1_000_001, "a refused block leaves the ledger where it was");

        // The very same rewind on a chain with no bridge, which is accepted: block time
        // constrains validity only where it is consensus input.
        let mut plain = ledger();
        plain.set_timestamp_ms(1_000_000);
        plain.apply_block(&empty(&plain, 2, 999_999), &StubExecutor).unwrap();
        assert_eq!(plain.timestamp_ms(), 999_999);
    }

    /// B2 (bridge hardening spec §3): on a bridged chain a block may run at most
    /// `MAX_TIMESTAMP_STEP_MS` past its parent — a validity rule, so it binds replay of committed
    /// history too (`apply_block` is the replay path). Exactly +60 000 is accepted, +60 001 is
    /// refused and leaves the ledger where it was; a chain without a bridge is unchanged.
    #[test]
    fn a_bridged_chain_refuses_a_block_whose_timestamp_leaps_past_the_step() {
        use crate::bridge::{BridgeConfig, BridgeState};

        let (a, _) = keys();
        let empty = |l: &Ledger, height: u64, timestamp_ms: u64| {
            let header = BlockHeader {
                height,
                view: height,
                parent: Hash::ZERO,
                proposer: a.public_key().clone(),
                timestamp_ms,
                tx_root: Block::tx_root(&[]),
                state_root: root_after(l, &[], &a.address(), height),
                justify: QuorumCertificate::genesis(Hash::ZERO),
            };
            Block::sign(&crate::types::SigningDomain::v0(Hash::ZERO), header, Vec::new(), &a)
        };
        assert_eq!(MAX_TIMESTAMP_STEP_MS, 60_000);

        let config =
            BridgeConfig {
                emitter: [1; 32],
                guardians: vec![[2; 20]],
                emitters: BTreeMap::from([(2u16, [9u8; 32])]),
                pq_guardians: vec![],
                pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
                rules_v2: None,
                guardian_set_index: None,
                burn_sequence: None,
                min_inbound_sequence: None,
                rotation: None,
                fees: None,
            };
        let mut l = ledger();
        l.set_bridge(Some(BridgeState::from_config(&config)));
        l.set_timestamp_ms(1_000_000);

        assert_eq!(
            l.apply_block(&empty(&l, 2, 1_060_001), &StubExecutor),
            Err(BlockError::TimestampLeap { parent: 1_000_000, block: 1_060_001, max_step: 60_000 })
        );
        assert_eq!(l.timestamp_ms(), 1_000_000, "a refused block leaves the ledger where it was");
        l.apply_block(&empty(&l, 2, 1_060_000), &StubExecutor).unwrap();
        assert_eq!(l.timestamp_ms(), 1_060_000);

        // The same leap on a chain with no bridge is accepted, as it always was.
        let mut plain = ledger();
        plain.set_timestamp_ms(1_000_000);
        plain.apply_block(&empty(&plain, 2, 1_000_000 + 10_000_000), &StubExecutor).unwrap();
    }

    #[test]
    fn a_block_with_two_bundles_sharing_a_nullifier_is_invalid() {
        let l = ledger();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let t2 = tx(&l, [[2; 8], [5; 8]], [[6; 8], [7; 8]]);
        let (a, _) = keys();
        let mut scratch = l.clone();
        let err = scratch.apply_transactions(&[t1, t2], &a.address(), &StubExecutor).unwrap_err();
        assert_eq!(err, BlockError::InvalidTx { index: 1, error: TxError::Spent([2; 8]) });
        assert_eq!(scratch, l, "unchanged on error");
    }

    /// The positive counterpart: two bundles that share nothing both land in one block, even
    /// though both are anchored at the root as it stood when the block started — the first
    /// bundle's two new leaves move the tree, but an anchor is checked against the recorded
    /// block-end roots, not against the mid-block root, so the second bundle is still valid.
    #[test]
    fn two_independent_bundles_anchored_at_the_block_start_root_both_apply() {
        let l = ledger();
        let (a, _) = keys();
        let start_root = l.root();
        let t1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let t2 = tx(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]]);
        assert_eq!(t1.bundle.as_ref().unwrap().anchor, start_root);
        assert_eq!(t2.bundle.as_ref().unwrap().anchor, start_root);

        let mut scratch = l.clone();
        let receipts = scratch.apply_transactions(&[t1, t2], &a.address(), &StubExecutor).unwrap();
        assert!(receipts.is_empty(), "neither bundle carries a call");
        for nf in [[1; 8], [2; 8], [5; 8], [6; 8]] {
            assert!(scratch.is_spent(&nf), "nullifier {nf:?} not spent");
        }
        for cm in [[3; 8], [4; 8], [7; 8], [8; 8]] {
            assert!(scratch.has_commitment(&cm), "commitment {cm:?} not appended");
        }
        assert_eq!(scratch.next_index(), 8, "four new leaves per bundle, in tree order");
        assert_eq!(scratch.validators()[&a.address()].rewards, 2 * gas::BUNDLE_BASE);
    }

    /// Task 5b: a plain transfer's envelopes are what its recipients open their notes with, and
    /// the proof never saw them — so before the binding a copier could replace one with garbage
    /// and, by committing first, strand the payment forever. Refused now; so is the same
    /// transaction under another chain id. The original still validates.
    #[test]
    fn a_transfers_proof_cannot_ride_a_changed_envelope_or_chain() {
        let l = ledger();
        let original = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let accepted: Vec<String> = (0..4)
            .map(|slot| {
                let mut copy = original.clone();
                copy.bundle.as_mut().unwrap().envelopes[slot].body = vec![0xee; 8];
                (slot, l.validate(&copy, &StubExecutor))
            })
            .filter(|(_, got)| !matches!(got, Err(TxError::InvalidBundleProof(_))))
            .map(|(slot, got)| format!("envelope {slot} replaced: {got:?}"))
            .collect();
        assert!(accepted.is_empty(), "{accepted:#?}");
        let mut other_chain = original.clone();
        other_chain.chain_id = 8;
        assert!(l.validate(&other_chain, &StubExecutor).is_err());
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// Fix round 1: a `Call`'s proof is inside the transaction binding. A program is public and
    /// stateless, so anyone can prove their own run of it and swap that proof in under someone
    /// else's fee bundle — the victim pays, the receipt's outputs and `H_IN` become the
    /// attacker's, and the victim's input envelope (sealed to its own `H_IN`) no longer opens.
    /// The swapped copy is refused at the fee bundle's proof; the original validates.
    #[test]
    fn a_calls_fee_bundle_cannot_ride_a_swapped_call_proof() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let fee = gas::fee_floor(&deploy);
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee), deploy));
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        let call = Action::Call { program: id, proof: StubExecutor::make_proof(&id, 12, [1; 8]), input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let original = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], fee), call));
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
        let mut swapped = original.clone();
        let Action::Call { proof, .. } = &mut swapped.action else { panic!("a call") };
        *proof = StubExecutor::make_proof(&id, 12, [9; 8]);
        assert!(
            matches!(l.validate(&swapped, &StubExecutor), Err(TxError::InvalidBundleProof(_))),
            "a swapped call proof: {:?}",
            l.validate(&swapped, &StubExecutor)
        );
        assert_eq!(l.validate(&original, &StubExecutor), Ok(()));
    }

    /// Deep scan 2026-09-24 (consensus reviewer, critical): a sync peer serves the sealed form's
    /// side table, and its `public_values` is a wire `Vec` — `check_bundle_proof` indexed it and
    /// `apply_synced` `expect`ed 34 words, so a peer could crash any node that synced from it
    /// with a record of the wrong length. A malformed record is refused when the block is applied,
    /// before any transaction is read, and the digest check never indexes past what it holds.
    #[test]
    fn a_pruned_record_of_the_wrong_length_is_refused_not_a_panic() {
        let mut l = ledger();
        let proposer = l.validators.keys().next().copied().unwrap();
        let bad = crate::consensus::PrunedBundle {
            tx_hash: Hash([1; 32]),
            proof_hash: Hash([2; 32]),
            public_values: vec![7; 33],
            shape: crate::types::DeclaredShape { profile: crate::types::FriProfile::Test, tier: 14, program_log_height: 12, input_log_height: 10, keccak_log_height: 0, sha256_log_height: 0, public_log_height: 2, mem_log_height: 16 },
        };
        let err = l
            .apply_transactions_for_sync(&[], &proposer, &BTreeMap::new(), &[bad], &StubExecutor, &NoVerified)
            .expect_err("a 33-word side table is refused");
        assert!(matches!(err, BlockError::MalformedPrunedRecord { words: 33, .. }), "{err:?}");
        // The digest check itself, fed a short record (a store written by a build that let one in):
        // a refusal, never an index past the end.
        let raw = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let mut marker = raw.clone();
        let b = marker.bundle.as_mut().unwrap();
        let ph = Hash::digest(&b.proof);
        let mut m = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        m.extend_from_slice(ph.as_bytes());
        b.proof = m;
        l.pruned_side.insert(ph, (raw.hash(), Vec::new()));
        let binding = [0u32; crate::types::TX_BINDING_WORDS];
        assert_eq!(
            l.check_bundle_proof(&marker, marker.bundle.as_ref().unwrap(), &binding, &StubExecutor, false),
            Err(TxError::BadDigest)
        );
    }

    /// INTERFACE-6 (recursion-VM review, dormant): the pruned path checked the record's `OUT`
    /// digest against the bundle's public fields and nothing tying the record to the rest of the
    /// transaction. The record's `PUB0..7` is `H_PUB` of the binding the covered proof was made
    /// over (the covering aggregate verified it), and its `tx_hash` names the raw transaction; a
    /// marker-form transaction whose action or envelopes differ from what the proof was bound to
    /// was accepted on a sync peer's word. Both are now checked: the record's `tx_hash` must be
    /// this transaction's id and its `PUB` words the digest of this transaction's binding.
    #[test]
    fn a_pruned_record_must_carry_this_transactions_binding() {
        let mut l = ledger();
        let raw = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let mut marker = raw.clone();
        let b = marker.bundle.as_mut().unwrap();
        let ph = Hash::digest(&b.proof);
        let mut m = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        m.extend_from_slice(ph.as_bytes());
        b.proof = m;
        let b = marker.bundle.as_ref().unwrap();
        let binding = marker.binding(&crate::types::BindingDomain::ChainId);
        let record = |hpub: Word8| {
            let mut pv = vec![0u64; crate::types::pv::NUM];
            let digest = StubExecutor.bundle_digest(&b.digest_input());
            for k in 0..8 {
                pv[crate::types::pv::OUT0 + k] = digest[k] as u64;
                pv[crate::types::pv::PUB0 + k] = hpub[k] as u64;
            }
            pv
        };
        let honest = record(StubExecutor.public_digest(&binding));
        l.pruned_side.insert(ph, (raw.hash(), honest.clone()));
        assert_eq!(l.check_bundle_proof(&marker, b, &binding, &StubExecutor, false), Ok(()), "the record of this transaction");
        // The same bundle, the same OUT digest — but the covered proof was bound to another
        // transaction (another action, another envelope): refused.
        l.pruned_side.insert(ph, (raw.hash(), record(StubExecutor.public_digest(&[9; 8]))));
        assert_eq!(
            l.check_bundle_proof(&marker, b, &binding, &StubExecutor, false),
            Err(TxError::PrunedRecordMismatch("the record's H_PUB is not this transaction's binding"))
        );
        // And a record naming another transaction id.
        l.pruned_side.insert(ph, (Hash([5; 32]), honest));
        assert_eq!(
            l.check_bundle_proof(&marker, b, &binding, &StubExecutor, false),
            Err(TxError::PrunedRecordMismatch("the record names another transaction"))
        );
    }

    /// INTERFACE-7 (recursion-VM review, dormant): a side table carrying two records under one
    /// proof hash was collected into a map, the later silently replacing the earlier — so which
    /// record a node checked, stored and served was the peer's ordering. Refused before any
    /// transaction is read; one record per proof hash applies as before.
    #[test]
    fn a_side_table_with_a_duplicate_proof_hash_is_refused() {
        let mut l = ledger();
        let proposer = l.validators.keys().next().copied().unwrap();
        let record = |tx: u8| crate::consensus::PrunedBundle {
            tx_hash: Hash([tx; 32]),
            proof_hash: Hash([2; 32]),
            public_values: vec![7; crate::types::pv::NUM],
            shape: crate::types::DeclaredShape { profile: crate::types::FriProfile::Test, tier: 14, program_log_height: 12, input_log_height: 10, keccak_log_height: 0, sha256_log_height: 0, public_log_height: 2, mem_log_height: 16 },
        };
        let err = l
            .apply_transactions_for_sync(&[], &proposer, &BTreeMap::new(), &[record(1), record(3)], &StubExecutor, &NoVerified)
            .expect_err("two records under one proof hash");
        assert_eq!(err, BlockError::DuplicatePrunedRecord { proof_hash: Hash([2; 32]) });
        assert!(l.apply_transactions_for_sync(&[], &proposer, &BTreeMap::new(), &[record(1)], &StubExecutor, &NoVerified).is_ok());
    }

    /// HB-3 (zkVM/ISA review, info): the commitment tree's 2^32-leaf capacity was enforced by an
    /// `assert!` inside `CommitmentTree::append`, reached from block application — a transaction
    /// admitted into the last few leaves panicked the applying node. Now a transaction that could
    /// overflow the tree is refused at validation (`CommitmentTreeFull`), and the apply path
    /// returns the same error rather than panicking.
    #[test]
    fn a_transaction_that_would_overflow_the_commitment_tree_is_refused_not_a_panic() {
        let (a, _) = keys();
        let mut l = ledger();
        let t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        l.tree = crate::notes::CommitmentTree::nearly_full_for_tests(2, &StubExecutor);
        let root = l.tree.root();
        l.anchors.push_back((l.height, root));
        let t = {
            let mut t = t;
            t.bundle.as_mut().unwrap().anchor = root;
            restub(t.bundle.as_mut().unwrap());
            StubExecutor::bound(t)
        };
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentTreeFull), "four leaves into a tree with room for two");
        let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| l.clone().apply_tx(&t, &a.address(), &StubExecutor).map(|_| ())));
        assert_eq!(applied.expect("no panic in block application"), Err(TxError::CommitmentTreeFull));
        l.tree = crate::notes::CommitmentTree::nearly_full_for_tests(8, &StubExecutor);
        assert_ne!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentTreeFull), "room enough");
    }

    /// The rescan's ZKQ-4: the rVM absorbs a covered bundle's public values with
    /// `F::from_u64`, which does not reduce — so a sync peer could serve a pruned record with
    /// `x + p` in place of `x` in any of the 18 words neither the `HC` pin nor the `OUT` digest
    /// check reads, the covering aggregate's interface digest still matched, and the node stored
    /// and re-served a non-canonical record. Every word of a side-table record must be a
    /// canonical Goldilocks element, refused with the length check before any transaction.
    #[test]
    fn a_pruned_record_with_a_non_canonical_word_is_refused() {
        let mut l = ledger();
        let proposer = l.validators.keys().next().copied().unwrap();
        let mut public_values = vec![7u64; crate::types::pv::NUM];
        // `pv::PC_ENTRY` is read by nothing the ledger checks: a word a peer could lift by p.
        public_values[0] = 7 + crate::types::pv::GOLDILOCKS_ORDER;
        let bad = crate::consensus::PrunedBundle {
            tx_hash: Hash([1; 32]),
            proof_hash: Hash([2; 32]),
            public_values,
            shape: crate::types::DeclaredShape { profile: crate::types::FriProfile::Test, tier: 14, program_log_height: 12, input_log_height: 10, keccak_log_height: 0, sha256_log_height: 0, public_log_height: 4, mem_log_height: 16 },
        };
        let err = l
            .apply_transactions_for_sync(&[], &proposer, &BTreeMap::new(), &[bad], &StubExecutor, &NoVerified)
            .expect_err("a record with a word at or past p is refused");
        assert!(matches!(err, BlockError::NonCanonicalPrunedRecord { index: 0, .. }), "{err:?}");
    }

    /// Fix round 1, item 2: a marker-form copy of a raw transaction — `bundle.proof` replaced by
    /// `PRUNED_PROOF_MARKER ‖ digest(proof)` — hashes to the raw transaction's id by design (M1).
    /// Outside sealed-form sync it must be refused with an error that is *not* a statement about
    /// the id (a node caches permanent refusals by `tx.hash()`), and before any proof work; the
    /// honest transaction still validates afterwards. The asset bundle of a two-bundle action
    /// gets the same rule.
    #[test]
    fn a_marker_form_copy_is_refused_as_not_admissible_and_the_raw_one_still_validates() {
        let l = ledger();
        let raw = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let mut marker = raw.clone();
        let b = marker.bundle.as_mut().unwrap();
        let mut m = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        m.extend_from_slice(Hash::digest(&b.proof).as_bytes());
        b.proof = m;
        assert_eq!(marker.hash(), raw.hash(), "the marker form is the raw id by design");
        assert_eq!(l.validate(&marker, &StubExecutor), Err(TxError::PrunedFormOutsideSync));
        assert_eq!(l.validate(&raw, &StubExecutor), Ok(()));
    }

    /// Audit v4, STAKE-2: the staking section is gated exactly like the bridge, tokens and
    /// aggregation sections. Without it a ledger commits today's domain over today's leaves —
    /// the faucet counters and the activation epoch reach nothing — so chain 14's state roots
    /// do not move by a byte. The pin is this fixture's root as computed before the section
    /// existed.
    #[test]
    fn without_the_section_the_state_root_domain_and_counters_are_untouched() {
        let l = ledger();
        assert!(l.staking().is_none());
        assert_eq!(l.faucet_epoch_counters(), (0, 0));
        assert_eq!(
            l.state_root().to_hex(),
            "8442e5f9a8b33426212ff172c8e11c87b047a3da726238411056885357d731d7",
            "the chain-14 shape's root, as computed before the staking section existed"
        );
        // And a mint on such a chain moves the supply counter, never the epoch counters.
        let mut l = l;
        let (a, _) = keys();
        let t = Transaction::mint(7, [5; 8], 1, [6; 8], env(), FAUCET_MAX_UNITS, &a, &StubExecutor);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.faucet_epoch_counters(), (0, 0), "no section, no counter");
        assert_eq!(l.supply().faucet_minted, FAUCET_MAX_UNITS);
    }

    /// Audit v4, STAKE-2 rule 2: the faucet budget is per epoch, and the epoch is the ledger's
    /// own (`height / epoch_blocks`), never wall time. A mint that would push the epoch's total
    /// over the budget is refused; the first block of the next epoch starts from zero. The
    /// refusal is state, not bytes: the same transaction is admitted again an epoch later.
    #[test]
    fn the_faucet_budget_is_per_epoch_and_resets_on_the_ledgers_epoch_boundary() {
        let budget = 100 * UNITS_PER_RAND;
        let mut l = ledger();
        l.set_epoch_blocks(10);
        l.set_staking(Some(StakingConfig { faucet_budget_per_epoch: budget, bond_activation_epochs: 0, ..Default::default() }));
        let (a, _) = keys();
        let mint = |l: &Ledger, seed: u32, amount: u64| {
            Transaction::mint(7, [seed; 8], l.height() as u32, [seed + 1; 8], env(), amount, &a, &StubExecutor)
        };
        let t = mint(&l, 10, 60 * UNITS_PER_RAND);
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.faucet_epoch_counters(), (0, 60 * UNITS_PER_RAND));
        let over = mint(&l, 20, 50 * UNITS_PER_RAND);
        let e = l.validate(&over, &StubExecutor).unwrap_err();
        assert!(matches!(e, TxError::FaucetBudgetExhausted { budget: b, minted } if b == budget && minted == 60 * UNITS_PER_RAND), "{e:?}");
        let before = l.clone();
        assert_eq!(l.apply_tx(&over, &a.address(), &StubExecutor), Err(e));
        assert_eq!(l, before, "a refused mint leaves the ledger untouched");
        // Exactly the budget is admitted (the bound is `>`), one unit more is not — still epoch 0
        // in its last block.
        l.set_height(9);
        let exact = mint(&l, 30, 40 * UNITS_PER_RAND);
        l.apply_tx(&exact, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.faucet_epoch_counters(), (0, budget));
        let one = mint(&l, 40, 1);
        assert!(matches!(l.validate(&one, &StubExecutor), Err(TxError::FaucetBudgetExhausted { minted, .. }) if minted == budget));
        // Height 10 is epoch 1: the counter resets on the ledger's boundary and the refused
        // transaction is admitted again.
        l.set_height(10);
        assert_eq!(l.epoch(), 1);
        assert_eq!(l.validate(&over, &StubExecutor), Ok(()), "the same bytes, admitted an epoch later");
        l.apply_tx(&over, &a.address(), &StubExecutor).unwrap();
        assert_eq!(l.faucet_epoch_counters(), (1, 50 * UNITS_PER_RAND));
        assert_eq!(l.supply().faucet_minted, 150 * UNITS_PER_RAND, "the supply counter is the running total");
    }

    /// Chain 15's faucet allowlist: under `staking.faucet_recipients` a `Mint` pays only a listed
    /// spend key — the `pk` its published opening names, which the value rule ties to `cm` — at
    /// admission and at apply alike, and the epoch budget still applies on top. Refused before
    /// any signature work, and a refused mint leaves the ledger untouched.
    #[test]
    fn the_faucet_allowlist_refuses_a_mint_to_an_unlisted_key() {
        let budget = 100 * UNITS_PER_RAND;
        let mut l = ledger();
        l.set_staking(Some(StakingConfig {
            faucet_budget_per_epoch: budget,
            bond_activation_epochs: 0,
            faucet_recipients: Some(vec![FaucetRecipient([5; 8]), FaucetRecipient([6; 8])]),
            ..Default::default()
        }));
        let (a, _) = keys();
        let mint = |l: &Ledger, pk: u32, r: u32, amount: u64| {
            Transaction::mint(7, [pk; 8], l.height() as u32, [r; 8], env(), amount, &a, &StubExecutor)
        };
        let stranger = mint(&l, 9, 10, UNITS_PER_RAND);
        assert_eq!(l.validate(&stranger, &StubExecutor), Err(TxError::FaucetRecipientNotAllowed));
        let before = l.clone();
        assert_eq!(l.apply_tx(&stranger, &a.address(), &StubExecutor), Err(TxError::FaucetRecipientNotAllowed));
        assert_eq!(l, before, "a refused mint leaves the ledger untouched");
        // Both listed keys are paid.
        for (pk, r) in [(5, 11), (6, 12)] {
            let t = mint(&l, pk, r, 40 * UNITS_PER_RAND);
            l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        }
        assert_eq!(l.faucet_epoch_counters(), (0, 80 * UNITS_PER_RAND));
        // And the budget binds a listed key too.
        let over = mint(&l, 5, 13, 21 * UNITS_PER_RAND);
        assert!(matches!(l.validate(&over, &StubExecutor), Err(TxError::FaucetBudgetExhausted { .. })));
        // Without the list the same stranger's mint is only budget-bound.
        l.set_staking(Some(StakingConfig { faucet_budget_per_epoch: budget, bond_activation_epochs: 0, ..Default::default() }));
        assert_eq!(l.validate(&stranger, &StubExecutor), Ok(()));
    }

    /// The two epoch counters and the validator's activation epoch are consensus state on a
    /// chain with the section — folded into the state root under `rand-state-5` and the
    /// `rand-validator-leaf-4` leaf — and reach nothing without it.
    #[test]
    fn the_counters_and_the_activation_epoch_reach_the_root_only_under_the_staking_section() {
        let cfg = StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() };
        // The counters.
        let plain = ledger();
        let mut counted = plain.clone();
        counted.set_faucet_epoch_counters(3, 7);
        assert_eq!(counted.state_root(), plain.state_root(), "without the section the counters are outside the root");
        assert_ne!(counted, plain, "but they are still compared: a reloaded node must restore them");
        let mut gated = plain.clone();
        gated.set_staking(Some(cfg.clone()));
        assert_ne!(gated.state_root(), plain.state_root(), "the section re-domains the root");
        let mut gated_counted = gated.clone();
        gated_counted.set_faucet_epoch_counters(3, 7);
        assert_ne!(gated_counted.state_root(), gated.state_root(), "under it the counters are in the root");
        let mut other_epoch = gated.clone();
        other_epoch.set_faucet_epoch_counters(4, 7);
        assert_ne!(other_epoch.state_root(), gated_counted.state_root());
        // The activation epoch.
        let (a, b) = keys();
        let root_of = |activation: u64, staking: Option<StakingConfig>| {
            let mut register: BTreeMap<Address, ValidatorEntry> = [entry(&a, 10), entry(&b, 10)].into_iter().collect();
            register.get_mut(&a.address()).unwrap().activation_epoch = activation;
            let mut l = Ledger::new(7, HC, register, &StubExecutor);
            l.set_staking(staking);
            l.state_root()
        };
        assert_eq!(root_of(0, None), root_of(5, None), "without the section the activation epoch is outside the leaf");
        assert_ne!(root_of(0, Some(cfg.clone())), root_of(5, Some(cfg.clone())), "under it the leaf binds it");
        assert_ne!(root_of(0, Some(cfg.clone())), root_of(0, None));
        // The bond queue (the v4 re-review's admission and delay rules): in the root under the
        // section, row by row and in order, and outside it without one.
        let row = |v: &Keypair, amount: u64| staking::QueuedStake { validator: v.address(), amount, epoch: 3 };
        let with_queue = |q: Vec<staking::QueuedStake>, staking: Option<StakingConfig>| {
            let mut l = ledger();
            l.set_staking(staking);
            l.set_bond_queue(q);
            l.state_root()
        };
        let s = Some(cfg);
        assert_eq!(with_queue(vec![row(&a, 5)], None), with_queue(vec![], None));
        assert_ne!(with_queue(vec![row(&a, 5)], s.clone()), with_queue(vec![], s.clone()));
        assert_ne!(with_queue(vec![row(&a, 5)], s.clone()), with_queue(vec![row(&a, 6)], s.clone()));
        assert_ne!(
            with_queue(vec![row(&a, 5), row(&b, 5)], s.clone()),
            with_queue(vec![row(&b, 5), row(&a, 5)], s),
            "the order is the admission order, so the root binds it"
        );
    }

    // ---- Split authorisation (delegated proving Phase 2, spec 2026-09-28 §4.1) --------------

    /// The auth guest a v3 test chain pins (genesis `hc_auth`).
    const HCA: Word8 = [21; 8];
    /// The auth commitment `c` an honest wallet's auth proof and bundle both carry.
    const C: Word8 = [0xc0; 8];

    /// [`ledger`] with split authorisation on.
    fn v3_ledger() -> Ledger {
        let mut l = ledger();
        l.set_hc_auth(Some(HCA));
        l
    }

    /// A v3 transaction as an honest wallet makes it: the bundle carries `auth_commit` `c`, its
    /// stub proof publishes the v3 digest over it, and the auth proof (made by `hc_auth`)
    /// publishes `proof_c` — `c` itself when honest. Both proofs are bound to the transaction.
    fn v3_tx_with(l: &Ledger, c: Word8, proof_c: Word8, hc_auth: Word8) -> Transaction {
        let mut b = bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE);
        b.auth_commit = c;
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest_v3(&b.digest_input()), &[0; 8]);
        b.auth_proof = StubExecutor::make_auth_proof(&hc_auth, &proof_c, &[0; 8]);
        StubExecutor::bound(Transaction::shielded(7, b, Action::None))
    }

    fn v3_tx(l: &Ledger) -> Transaction {
        v3_tx_with(l, C, C, HCA)
    }

    #[test]
    fn a_v3_bundle_with_a_valid_auth_proof_is_accepted() {
        let mut l = v3_ledger();
        let (a, _) = keys();
        let t = v3_tx(&l);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
        assert!(l.nullifiers.contains(&[1; 8]), "the bundle spent");
    }

    #[test]
    fn a_v3_chain_refuses_a_bundle_without_an_auth_proof() {
        let l = v3_ledger();
        let mut t = v3_tx(&l);
        t.bundle.as_mut().unwrap().auth_proof = Vec::new();
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::AuthMissing));
        // Nor does a v1 bundle — zero `auth_commit`, no auth proof, the v1 digest — pass there.
        let v1 = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        assert_eq!(l.validate(&v1, &StubExecutor), Err(TxError::AuthMissing));
    }

    /// A v3 chain recomputes the v3 digest — `auth_commit` inside — and nothing else: a bundle
    /// proof publishing the v1 digest over the same fields is refused, and so is a bundle whose
    /// `auth_commit` field is changed after its proof was made (the auth proof following it).
    #[test]
    fn a_v3_chain_recomputes_the_v3_digest() {
        let l = v3_ledger();
        let mut t = v3_tx(&l);
        let b = t.bundle.as_mut().unwrap();
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()), &[0; 8]);
        StubExecutor::bind(&mut t);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BadDigest));
        let mut t = v3_tx(&l);
        let b = t.bundle.as_mut().unwrap();
        b.auth_commit = [0xc1; 8];
        b.auth_proof = StubExecutor::make_auth_proof(&HCA, &[0xc1; 8], &[0; 8]);
        StubExecutor::bind(&mut t);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BadDigest));
    }

    /// The auth proof's `c` must be the bundle's `auth_commit`: a prover holding `nk` makes a
    /// bundle over its own `c` (salt), and an auth proof the key holder made publishes another.
    /// Refused on the cheap read (before any verify), and also when only the verify reads it.
    #[test]
    fn an_auth_commit_that_differs_from_the_proofs_c_is_refused() {
        let l = v3_ledger();
        let t = v3_tx_with(&l, C, [0xc1; 8], HCA);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::AuthMismatch));
        let b = t.bundle.as_ref().unwrap();
        assert_eq!(l.check_bundle_proof(&t, b, &t.binding(&crate::types::BindingDomain::ChainId), &StubExecutor, true), Err(TxError::AuthMismatch), "the cheap half runs on a verified-set hit too");

        /// An executor whose cheap read reports the bundle's own `c` while the verified proof
        /// publishes another — the verify's answer is compared as well.
        struct LyingDigest;
        impl ConfidentialExecutor for LyingDigest {
            fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
                StubExecutor.check_program(base_pc, words)
            }
            fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
                StubExecutor.verify_call(program, proof)
            }
            fn public_digest(&self, words: &[u32]) -> Word8 {
                StubExecutor.public_digest(words)
            }
            fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
                StubExecutor.node_hash(left, right)
            }
            fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
                StubExecutor.hash_domain(domain, msg)
            }
            fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
                StubExecutor.note_commitment(pk, from, amount, asset, time, r)
            }
            fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
                StubExecutor.bundle_digest(input)
            }
            fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
                StubExecutor.bundle_digest_v3(input)
            }
            fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
                StubExecutor.bundle_proof_digest(hc_bundle, proof)
            }
            fn auth_proof_digest(&self, _proof: &[u8]) -> Result<Word8, ConfidentialError> {
                Ok(C)
            }
            fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
                StubExecutor.verify_auth(hc_auth, proof, binding)
            }
            fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), ConfidentialError> {
                StubExecutor.verify_bundle(hc_bundle, proof, binding)
            }
            fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
                StubExecutor.aggregate_program_digest(shape)
            }
            fn verify_aggregate(
                &self,
                shape: &crate::types::DeclaredShape,
                covered: &[crate::types::CoveredBundle],
                proof: &[u8],
                binding: &[u32; 8],
            ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
                StubExecutor.verify_aggregate(shape, covered, proof, binding)
            }
        }
        assert_eq!(l.validate(&t, &LyingDigest), Err(TxError::AuthMismatch));
    }

    /// An auth proof is bound to one transaction: one made for another binding (a replay onto a
    /// transaction the key holder never saw) is refused, and so is one by another guest.
    #[test]
    fn an_auth_proof_for_another_binding_is_refused() {
        let l = v3_ledger();
        let mut t = v3_tx(&l);
        let b = t.bundle.as_mut().unwrap();
        b.auth_proof = StubExecutor::make_auth_proof(&HCA, &C, &[9; 8]);
        let b = t.bundle.as_ref().unwrap();
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::InvalidAuthProof(ConfidentialError::InvalidProof("PublicValues".into())))
        );
        // B5: admission verified it, so a verified-set hit skips the verify, as for the bundle.
        assert_eq!(l.check_bundle_proof(&t, b, &t.binding(&crate::types::BindingDomain::ChainId), &StubExecutor, true), Ok(()));
        let other_guest = v3_tx_with(&l, C, C, [22; 8]);
        assert_eq!(l.validate(&other_guest, &StubExecutor), Err(TxError::InvalidAuthProof(ConfidentialError::WrongProgram)));
        let mut junk = v3_tx(&l);
        junk.bundle.as_mut().unwrap().auth_proof = b"junk".to_vec();
        assert_eq!(l.validate(&junk, &StubExecutor), Err(TxError::InvalidAuthProof(ConfidentialError::MalformedProof)));
    }

    /// A chain whose genesis names no `hc_auth` keeps today's rules byte for byte: a bundle
    /// carrying either auth field is refused, before any proof is looked at.
    #[test]
    fn a_pre_v3_chain_refuses_a_bundle_carrying_auth_fields() {
        let l = ledger();
        assert_eq!(l.hc_auth(), None);
        let honest = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        assert_eq!(l.validate(&honest, &StubExecutor), Ok(()));
        let mut t = honest.clone();
        t.bundle.as_mut().unwrap().auth_commit = C;
        StubExecutor::bind(&mut t);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::AuthUnexpected));
        let mut t = honest.clone();
        t.bundle.as_mut().unwrap().auth_proof = StubExecutor::make_auth_proof(&HCA, &[0; 8], &[0; 8]);
        StubExecutor::bind(&mut t);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::AuthUnexpected));
        // A whole v3 transaction, likewise.
        assert_eq!(l.validate(&v3_tx(&v3_ledger()), &StubExecutor), Err(TxError::AuthUnexpected));
    }

    /// An auth proof is a proof: held to the chain's proof size cap like the bundle's.
    #[test]
    fn an_oversized_auth_proof_is_refused() {
        let l = v3_ledger();
        let mut t = v3_tx(&l);
        t.bundle.as_mut().unwrap().auth_proof = vec![0; l.max_proof_bytes() + 1];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::ProofTooLarge));
    }

    /// A pruned v3 bundle keeps its `auth_commit` and `auth_proof` (the marker replaces only
    /// `proof`): the record's `OUT` digest is the v3 one, and the auth proof is verified on the
    /// sync path as at admission.
    #[test]
    fn a_pruned_v3_bundle_checks_the_v3_digest_and_its_auth_proof() {
        let mut l = v3_ledger();
        let raw = v3_tx(&l);
        let mut marker = raw.clone();
        let b = marker.bundle.as_mut().unwrap();
        let ph = Hash::digest(&b.proof);
        let mut m = crate::notes::PRUNED_PROOF_MARKER.to_vec();
        m.extend_from_slice(ph.as_bytes());
        b.proof = m;
        assert_eq!(marker.hash(), raw.hash(), "the marker form keeps the raw id");
        let binding = marker.binding(&crate::types::BindingDomain::ChainId);
        let record = |digest: Word8| {
            let mut pv = vec![0u64; crate::types::pv::NUM];
            let hpub = StubExecutor.public_digest(&binding);
            for k in 0..8 {
                pv[crate::types::pv::OUT0 + k] = digest[k] as u64;
                pv[crate::types::pv::PUB0 + k] = hpub[k] as u64;
            }
            pv
        };
        let b = marker.bundle.clone().unwrap();
        l.pruned_side.insert(ph, (raw.hash(), record(StubExecutor.bundle_digest_v3(&b.digest_input()))));
        assert_eq!(l.check_bundle_proof(&marker, &b, &binding, &StubExecutor, false), Ok(()));
        let mut replayed = b.clone();
        replayed.auth_proof = StubExecutor::make_auth_proof(&HCA, &C, &[9; 8]);
        assert_eq!(
            l.check_bundle_proof(&marker, &replayed, &binding, &StubExecutor, false),
            Err(TxError::InvalidAuthProof(ConfidentialError::InvalidProof("PublicValues".into())))
        );
        let mut missing = b.clone();
        missing.auth_proof = Vec::new();
        assert_eq!(l.check_bundle_proof(&marker, &missing, &binding, &StubExecutor, false), Err(TxError::AuthMissing));
        l.pruned_side.insert(ph, (raw.hash(), record(StubExecutor.bundle_digest(&b.digest_input()))));
        assert_eq!(l.check_bundle_proof(&marker, &b, &binding, &StubExecutor, false), Err(TxError::BadDigest), "a v1 record");
    }

    /// Phase 2's controller parameters for the tests below: prices 100 / 800 at their floors.
    fn dynamic_gas() -> gas::GasConfig {
        gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: gas::gas_max(14, 0, 0),
            metering: gas::GasMetering::Circuit,
            dynamic: Some(gas::DynamicGas {
                target_block_bytes: 4096,
                target_block_gas: 20_000,
                adjust_bps: 1250,
                min_gas_price: 100,
                min_byte_price: 800,
                max_gas_price: None,
                max_byte_price: None,
                byte_load: None,
            }),
        }
    }

    /// RPL-2 beside audit v6's POOL-2: an `Invoke` pays the byte price on its call proof as a
    /// `Call` does (the ledger's floor for it is the call floor plus the cell fee), so under
    /// `byte_load: "paying"` its proof and input envelope are what it feeds the byte meter.
    #[test]
    fn an_invokes_call_proof_counts_under_the_paying_byte_load() {
        let mut cfg = dynamic_gas();
        cfg.dynamic.as_mut().unwrap().byte_load = Some(gas::ByteLoad::Paying);
        let mut l = ledger();
        l.set_gas(Some(cfg));
        let proof = vec![5u8; 70_000];
        let transition = program_state::Transition { reads: vec![], writes: vec![], inflow: program_state::Inflow::None, pays: vec![], mints: vec![] };
        let b = bundle(&l, [[200; 8], [201; 8]], [[202; 8], [203; 8]], gas::BUNDLE_BASE);
        let invoke = Transaction::shielded(7, b, Action::Invoke { program: Hash([7; 32]), proof: proof.clone(), input_envelope: None, transition });
        assert_eq!(l.block_usage(&[invoke], 0).0 as usize, gas::call_bytes(&proof, None));
    }

    /// Audit v6, POOL-2: under `byte_load: "paying"` a block of transfers moves no byte price,
    /// since a transfer pays none — and under chain 18's rule (no `byte_load`) the same block
    /// still does, pinned. Seven full transfers, each padded to a chain-18 transfer's ~2.85 MB
    /// against a 10 MiB target: ~1.9× the target, `+adjust_bps` a block.
    #[test]
    fn a_block_of_transfers_moves_the_byte_price_only_under_the_all_bytes_load() {
        let (a0, _) = keys();
        let proposer = a0.address();
        let mut cfg = dynamic_gas();
        cfg.dynamic.as_mut().unwrap().target_block_bytes = 10_485_760;
        let transfers: Vec<Transaction> = (0..7u32)
            .map(|i| {
                let n = 100 + 4 * i;
                let mut b = bundle(&ledger(), [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], gas::BUNDLE_BASE);
                b.proof = vec![i as u8; 2_850_000];
                Transaction::shielded(7, b, Action::None)
            })
            .collect();
        let total: usize = transfers.iter().map(Transaction::encoded_len).sum();
        assert!(total > 19 << 20, "seven of them are a chain-18 block: {total}");
        // Chain 18's rule: every byte counts, and the block is past twice the target.
        let mut all = ledger();
        all.set_gas(Some(cfg.clone()));
        let (bytes, _) = all.block_usage(&transfers, 0);
        assert_eq!(bytes as usize, total);
        all.close_block(1, &proposer, bytes, 0);
        assert_eq!(all.gas_prices().byte_price, gas::next_price(800, 800, bytes, 10_485_760, 1250));
        assert_eq!(all.gas_prices().byte_price, 890, "chain 18: 1.9× the target, +11.25 % on a block of transfers");
        // `paying`: the same block is zero bytes to the controller, and the price falls instead.
        cfg.dynamic.as_mut().unwrap().byte_load = Some(gas::ByteLoad::Paying);
        let mut paying = ledger();
        paying.set_gas(Some(cfg.clone()));
        paying.set_gas_prices(gas::GasPrices { gas_price: 100, byte_price: 1_000 });
        let (bytes, gas_used) = paying.block_usage(&transfers, 0);
        assert_eq!((bytes, gas_used), (0, 7 * gas::gas_max(14, 0, 0)), "no call bytes; the bundles' flat gas as before");
        paying.close_block(1, &proposer, bytes, gas_used);
        assert_eq!(paying.gas_prices().byte_price, 875, "an empty block to the byte meter: −12.5 %");
        // A call's proof and envelope are what count: exactly `call_bytes`, whatever rides beside it.
        let (mut with_call, id) = ledger_with_program(|l| l.set_gas(Some(cfg.clone())));
        let proof = vec![5u8; 6 << 20];
        let call = call_tx(&with_call, 20, id, proof.clone(), fee_for(proof.len()));
        let mut block = transfers.clone();
        block.push(call.clone());
        let (bytes, _) = with_call.block_usage(&block, 0);
        assert_eq!(bytes as usize, gas::call_bytes(&proof, None));
        assert!(bytes < call.encoded_len() as u64, "the call's own fee bundle is not charged either");
        with_call.set_gas_prices(gas::GasPrices { gas_price: 100, byte_price: 1_000 });
        with_call.close_block(1, &proposer, bytes, 0);
        let expected = gas::next_price(1_000, 800, bytes, 10_485_760, 1250);
        assert!(expected < 1_000, "6 MiB of call bytes is under the 10 MiB target");
        assert_eq!(with_call.gas_prices().byte_price, expected);
    }

    /// Audit v6, POOL-2: the proposer and the replica compute one figure for a block of mixed
    /// traffic (`block_usage` is the one function both call), under either byte load, and a
    /// ceiling holds through full blocks on both sides.
    #[test]
    fn proposer_and_replica_agree_on_the_capped_price_after_a_block_of_mixed_traffic() {
        let (a0, _) = keys();
        let proposer = a0.address();
        for byte_load in [None, Some(gas::ByteLoad::Paying)] {
            let mut cfg = dynamic_gas();
            let d = cfg.dynamic.as_mut().unwrap();
            d.byte_load = byte_load;
            d.max_byte_price = Some(1_000);
            d.max_gas_price = Some(150);
            // A stub call proof is ~110 B: a target both loads' blocks pass twice over.
            d.target_block_bytes = 32;
            let (l, id) = ledger_with_program(|l| l.set_gas(Some(cfg.clone())));
            let proof = StubExecutor::make_proof(&id, 12, [7; 8]);
            let call = call_tx(&l, 20, id, proof.clone(), fee_for(proof.len()) + 1_000_000);
            let mut transfer = bundle(&l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], gas::BUNDLE_BASE);
            for e in &mut transfer.envelopes {
                e.body = vec![9u8; 2048];
            }
            let transfer = Transaction::shielded(7, transfer, Action::None);
            let block = vec![transfer, call];
            let (mut a, mut b) = (l.clone(), l.clone());
            // Twelve full blocks: the price climbs to its ceiling and no further, on both sides.
            for h in 1..=12 {
                let (bytes, gas_used) = a.block_usage(&block, 40_000);
                assert_eq!((bytes, gas_used), b.block_usage(&block, 40_000), "{byte_load:?}");
                a.close_block(h, &proposer, bytes, gas_used);
                b.close_block(h, &proposer, bytes, gas_used);
                assert_eq!(a.gas_prices(), b.gas_prices(), "{byte_load:?} block {h}");
                assert_eq!(a.state_root(), b.state_root(), "{byte_load:?} block {h}");
            }
            assert_eq!(a.gas_prices(), gas::GasPrices { gas_price: 150, byte_price: 1_000 }, "{byte_load:?}: at both ceilings");
            // And falls from the ceiling on an empty block.
            a.close_block(13, &proposer, 0, 0);
            assert_eq!(a.gas_prices(), gas::GasPrices { gas_price: 131, byte_price: 875 }, "{byte_load:?}: −12.5 %, floor division");
        }
    }

    /// Review focus 5: the same block from the same parent gives the same prices and root; an
    /// empty block walks each price back to its floor and never below; a chain without `dynamic`
    /// never moves and keeps its pre-gas root.
    #[test]
    fn the_controller_is_deterministic_and_floored() {
        let (a0, _) = keys();
        let proposer = a0.address();
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(dynamic_gas())));
        assert_eq!(l.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 }, "starts at the section's prices");
        let r0 = l.state_root();
        let (mut a, mut b) = (l.clone(), l.clone());
        let proof = StubExecutor::make_proof(&id, 12, [7; 8]);
        let fee = fee_for(proof.len());
        let tx = call_tx(&l, 20, id, proof, fee);
        for l in [&mut a, &mut b] {
            l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
            // B1/B3 have not landed: the call's own gas is driven directly here.
            l.close_block(1, &proposer, tx.encoded_len() as u64, 40_000 + gas::gas_max(14, 0, 0));
        }
        assert_eq!(a.gas_prices(), b.gas_prices());
        assert_eq!(a.state_root(), b.state_root());
        assert_ne!(a.state_root(), r0, "the prices are in the root");
        assert!(a.gas_prices().gas_price > 100, "gas above target raised the gas price");
        // An empty block lowers each price toward its floor and never below.
        for h in 2..40 {
            a.close_block(h, &proposer, 0, 0);
        }
        assert_eq!(a.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 });
        // A chain without `dynamic` never moves and keeps rand-state-6's root shape.
        let (fixed, _) = ledger_with_program(|l| l.set_gas(Some(gas::GasConfig { dynamic: None, ..dynamic_gas() })));
        let r = fixed.state_root();
        let mut f = fixed.clone();
        f.close_block(1, &proposer, 1 << 30, 1 << 30);
        assert_eq!(f.gas_prices(), gas::GasPrices { gas_price: 100, byte_price: 800 });
        assert_eq!(f.state_root(), r, "without `dynamic` the prices are not in the root and never move");
    }

    /// The root folds the prices only under `dynamic`: a fixed-price section leaves every byte of
    /// the root as it was without a section, and a dynamic one changes it only once the prices
    /// move.
    #[test]
    fn the_prices_are_in_the_root_only_under_dynamic() {
        let (a0, _) = keys();
        let proposer = a0.address();
        let bare = ledger();
        let mut fixed = ledger();
        fixed.set_gas(Some(gas::GasConfig { dynamic: None, ..dynamic_gas() }));
        assert_eq!(fixed.state_root(), bare.state_root(), "a fixed-price section is not in the root");
        let mut dynamic = ledger();
        dynamic.set_gas(Some(dynamic_gas()));
        assert_ne!(dynamic.state_root(), bare.state_root(), "under `dynamic` the root is re-domained");
        // At the target on both meters: the prices hold, and so does the root (the anchor aside).
        let mut held = dynamic.clone();
        let mut moved = dynamic.clone();
        held.close_block(1, &proposer, 4096, 20_000);
        moved.close_block(1, &proposer, 4096, 40_000);
        assert_eq!(held.gas_prices(), dynamic.gas_prices());
        assert_ne!(moved.gas_prices(), dynamic.gas_prices());
        assert_ne!(moved.state_root(), held.state_root(), "moved prices move the root");
        // With the prices set back by hand, the two roots agree again: the prices are the only
        // difference.
        moved.set_gas_prices(held.gas_prices());
        assert_eq!(moved.state_root(), held.state_root());
    }

    /// The `rand-state-7` byte layout, pinned: the pre-gas buffer (here the four base leaves,
    /// then the vesting root when a register is present), then `be(gas_price) ‖ be(byte_price)`.
    #[test]
    fn the_rand_state_7_layout_is_pinned() {
        for vesting in [false, true] {
            let mut l = ledger();
            if vesting {
                l.set_vesting(Some(vesting::VestingRegister::default()));
            }
            l.set_gas(Some(dynamic_gas()));
            l.set_gas_prices(gas::GasPrices { gas_price: 0x0102_0304_0506_0708, byte_price: 0x1112_1314_1516_1718 });
            let (nf, val, prog) = l.state_root_leaves();
            let mut buf = Vec::new();
            buf.extend_from_slice(&word8_to_bytes(&l.tree.root()));
            buf.extend_from_slice(nf.as_bytes());
            buf.extend_from_slice(val.as_bytes());
            buf.extend_from_slice(prog.as_bytes());
            if let Some(v) = l.vesting() {
                buf.extend_from_slice(v.root().as_bytes());
            }
            buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            buf.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
            assert_eq!(l.state_root(), Hash::digest_domain(b"rand-state-7", &buf), "vesting {vesting}");
        }
    }

    /// Audit v6 (TOK-1, issue #86): under `tokens.incremental_root` the state root is
    /// `H("rand-state-tokens-1", base)` over the base whose tokens component is the registry's
    /// `rand-token-registry-4` root; without the field the base is returned untouched — chain
    /// 18's `rand-state-4` layout, byte for byte — and the flag re-applied off again gives the
    /// same ledger and root back.
    #[test]
    fn the_incremental_token_root_wraps_the_state_root_only_under_the_field() {
        let mut off = ledger();
        off.set_tokens(Some(tokens::TokenRegistry::new(1_000_000_000)));
        let (nf, val, prog) = off.state_root_leaves();
        let mut buf = Vec::new();
        buf.extend_from_slice(&word8_to_bytes(&off.tree.root()));
        buf.extend_from_slice(nf.as_bytes());
        buf.extend_from_slice(val.as_bytes());
        buf.extend_from_slice(prog.as_bytes());
        let head = buf.clone();
        buf.extend_from_slice(off.tokens().unwrap().root().as_bytes());
        assert_eq!(off.state_root(), Hash::digest_domain(b"rand-state-4", &buf), "no field: chain 18's layout");

        let mut on = off.clone();
        on.set_tokens_incremental_root(true);
        assert!(on.tokens().unwrap().incremental_root());
        let mut inner = head;
        inner.extend_from_slice(on.tokens().unwrap().root().as_bytes());
        let base = Hash::digest_domain(b"rand-state-4", &inner);
        assert_eq!(on.state_root(), Hash::digest_domain(b"rand-state-tokens-1", base.as_bytes()), "the field: re-domained over the incremental registry root");
        assert_ne!(on.state_root(), off.state_root());
        assert_ne!(on, off, "the flag is inside the ledger's equality");
        on.set_tokens_incremental_root(false);
        assert_eq!(on.state_root(), off.state_root(), "the flag off again is the old root");
        assert_eq!(on, off);
    }

    /// A chain with `vesting` and a FIXED gas section keeps exactly the `rand-state-6` root it
    /// had without the gas section.
    #[test]
    fn a_fixed_gas_section_keeps_the_vesting_root() {
        let mut bare = ledger();
        bare.set_vesting(Some(vesting::VestingRegister::default()));
        let mut fixed = bare.clone();
        fixed.set_gas(Some(gas::GasConfig { dynamic: None, ..dynamic_gas() }));
        assert_eq!(fixed.state_root(), bare.state_root());
        let (nf, val, prog) = bare.state_root_leaves();
        let mut buf = Vec::new();
        buf.extend_from_slice(&word8_to_bytes(&bare.tree.root()));
        buf.extend_from_slice(nf.as_bytes());
        buf.extend_from_slice(val.as_bytes());
        buf.extend_from_slice(prog.as_bytes());
        buf.extend_from_slice(bare.vesting().unwrap().root().as_bytes());
        assert_eq!(fixed.state_root(), Hash::digest_domain(b"rand-state-6", &buf));
    }

    /// Spec §7.1: a call adds its declared `GAS_LIMIT` (`pv::GAS`, `CallOutcome::gas_limit`) to
    /// its block's `gas_used` — the bound it paid for, not a count it revealed.
    #[test]
    fn a_calls_gas_used_is_its_declared_limit() {
        let o = crate::program::CallOutcome {
            tier: 20,
            outputs: [0; 8],
            h_in: [0; 8],
            keccak_log_height: 12,
            sha256_log_height: 13,
            gas_limit: crate::gas::gas_max(20, 12, 13),
        };
        assert_eq!(Ledger::call_gas_used(&o), crate::gas::gas_max(20, 12, 13));
        assert_eq!(Ledger::call_gas_used(&crate::program::CallOutcome { gas_limit: 40_000, ..o }), 40_000);
    }

    /// `apply_block` charges the controller Σ `encoded_len` in bytes and, in gas, each call's
    /// declared limit plus `bundle_gas_limit` per bundle proof: the replica's prices after a one-call block are exactly what a
    /// direct `close_block` with those two sums gives.
    #[test]
    fn apply_block_feeds_the_controller_the_blocks_bytes_and_gas() {
        let (a0, _) = keys();
        // Above both floors, so a block under target moves both prices.
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(gas::GasConfig { gas_price: 200, byte_price: 1_600, ..dynamic_gas() })));
        let proof = StubExecutor::make_proof(&id, 12, [7; 8]);
        let fee = fee_for(proof.len());
        let tx = call_tx(&l, 20, id, proof, fee);
        let mut expect = l.clone();
        expect.set_height(2);
        expect.apply_tx(&tx, &a0.address(), &StubExecutor).unwrap();
        // The call's declared limit (a stub tier-12 proof declares `gas_max(12, 0, 0)`) plus the
        // one bundle's `bundle_gas_limit`.
        expect.close_block(2, &a0.address(), tx.encoded_len() as u64, gas::gas_max(12, 0, 0) + gas::gas_max(14, 0, 0));
        let block = signed_block(vec![tx], &a0, 2, expect.state_root());
        let mut replica = l.clone();
        replica.apply_block(&block, &StubExecutor).unwrap();
        assert_eq!(replica.gas_prices(), expect.gas_prices());
        assert_ne!(replica.gas_prices(), l.gas_prices(), "the block moved the prices");
    }

    /// A ledger with the test program deployed and a fixed-price `gas` section (100 / 800,
    /// bundle limit `gas_max(14, 0, 0)` = 20 479).
    fn gas_ledger() -> (Ledger, ProgramId) {
        ledger_with_program(|l| {
            l.set_gas(Some(gas::GasConfig {
                gas_price: 100,
                byte_price: 800,
                bundle_gas_limit: gas::gas_max(14, 0, 0),
                metering: gas::GasMetering::Circuit,
                dynamic: None,
            }))
        })
    }

    /// Spec §4.2: under the section a call pays gas_price·GAS_LIMIT + byte_price·KiB over the
    /// base — the declared limit, not the tier — and the old tier floor no longer applies. The
    /// pre-verify floor is the same rule at a limit of 1, so a verify is still never bought for
    /// less than the bytes.
    #[test]
    fn under_the_gas_section_a_call_pays_its_declared_limit() {
        let (l, id) = gas_ledger();
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 3_000);
        let kib = proof.len().div_ceil(1024) as u64;
        assert_eq!(kib, 1, "a stub proof is under one KiB");
        let floor = gas::BUNDLE_BASE + 100 * 3_000 + 800 * kib;
        assert!(floor < gas::BUNDLE_BASE + gas::call_fee(12, proof.len()), "cheaper than the tier floor for a small declared limit");
        let short = call_tx(&l, 20, id, proof.clone(), floor - 1);
        assert_eq!(l.validate(&short, &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        let paid = call_tx(&l, 30, id, proof.clone(), floor);
        assert!(l.validate(&paid, &StubExecutor).is_ok());
        // A limit of gas_max(20, 0, 0) with the same bytes costs 0.1 RAND more.
        let big = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], 1_048_575);
        let kib = big.len().div_ceil(1024) as u64;
        let floor = gas::BUNDLE_BASE + 100 * 1_048_575 + 800 * kib;
        assert_eq!(l.validate(&call_tx(&l, 40, id, big.clone(), floor - 1), &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        assert!(l.validate(&call_tx(&l, 50, id, big, floor), &StubExecutor).is_ok());
        // The pre-verify floor: under `BUNDLE_BASE + gas_price·1 + byte_price·KiB` the call is
        // refused at step 3, before its proof is decoded or verified.
        let pre = gas::BUNDLE_BASE + 100 + 800;
        let exec = CountingExecutor::default();
        assert_eq!(l.validate(&call_tx(&l, 60, id, proof.clone(), pre - 1), &exec), Err(TxError::FeeTooLow { min: pre, fee: pre - 1 }));
        assert_eq!((exec.calls(), exec.bundles()), (0, 0), "no verify is bought under the byte floor");
        // Without the section the tier schedule stands, byte for byte.
        let (plain, id) = ledger_with_program(|_| {});
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 3_000);
        let cheap = gas::BUNDLE_BASE + 100 * 3_000 + 800;
        assert_eq!(
            plain.validate(&call_tx(&plain, 20, id, proof.clone(), cheap), &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE + gas::CALL_BASE, fee: cheap })
        );
        let old = gas::BUNDLE_BASE + gas::call_fee(12, proof.len());
        assert!(plain.validate(&call_tx(&plain, 30, id, proof.clone(), old), &StubExecutor).is_ok());
        assert_eq!(
            plain.validate(&call_tx(&plain, 40, id, proof.clone(), old - 1), &StubExecutor),
            Err(TxError::FeeTooLow { min: old, fee: old - 1 })
        );
    }

    /// Phase 2 prices a call at the prices in force (`gas_prices`), not the section's: once the
    /// controller has moved the gas price, the floor moves with it.
    #[test]
    fn a_calls_floor_is_at_the_current_prices() {
        let (mut l, id) = ledger_with_program(|l| l.set_gas(Some(dynamic_gas())));
        l.set_gas_prices(gas::GasPrices { gas_price: 300, byte_price: 900 });
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 3_000);
        let floor = gas::BUNDLE_BASE + 300 * 3_000 + 900;
        assert_eq!(l.validate(&call_tx(&l, 20, id, proof.clone(), floor - 1), &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        assert!(l.validate(&call_tx(&l, 30, id, proof, floor), &StubExecutor).is_ok());
    }

    /// Review focus 4 (spec §4.3): every bundle proof declares exactly `bundle_gas_limit`, checked
    /// before the STARK verify and on the verified-set (B5) path too.
    #[test]
    fn a_bundle_declaring_any_other_gas_limit_is_refused() {
        let (a, _) = keys();
        let (l, _) = gas_ledger();
        let ok = tx(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]]);
        assert!(l.validate(&ok, &StubExecutor).is_ok());
        for other in [20_478u64, 20_480, 16_383, 1] {
            let mut t = ok.clone();
            StubExecutor::with_bundle_gas(&mut t.bundle.as_mut().unwrap().proof, other);
            let t = StubExecutor::bound(t);
            assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::BundleGasLimit { want: 20_479, got: Some(other) }), "{other}");
            // A wrong limit buys no verify.
            let exec = CountingExecutor::default();
            assert_eq!(l.validate(&t, &exec), Err(TxError::BundleGasLimit { want: 20_479, got: Some(other) }));
            assert_eq!(exec.bundles(), 0, "refused before the verify");
            // And the verified-set hit, which skips the verify, still checks the limit.
            let mut applied = l.clone();
            assert_eq!(
                applied.apply_tx_with(&t, &a.address(), &StubExecutor, &Admitted::of(&[&t])),
                Err(TxError::BundleGasLimit { want: 20_479, got: Some(other) })
            );
        }
        // An executor whose proofs carry no limit declares none, and is refused under the section.
        struct NoGas;
        impl ConfidentialExecutor for NoGas {
            fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
                StubExecutor.check_program(base_pc, words)
            }
            fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
                StubExecutor.verify_call(program, proof)
            }
            fn public_digest(&self, words: &[u32]) -> Word8 {
                StubExecutor.public_digest(words)
            }
            fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
                StubExecutor.node_hash(left, right)
            }
            fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
                StubExecutor.hash_domain(domain, msg)
            }
            fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
                StubExecutor.note_commitment(pk, from, amount, asset, time, r)
            }
            fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
                StubExecutor.bundle_digest(input)
            }
            fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
                StubExecutor.bundle_digest_v3(input)
            }
            fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
                StubExecutor.bundle_proof_digest(hc_bundle, proof)
            }
            fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
                StubExecutor.auth_proof_digest(proof)
            }
            fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
                StubExecutor.verify_auth(hc_auth, proof, binding)
            }
            fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), ConfidentialError> {
                StubExecutor.verify_bundle(hc_bundle, proof, binding)
            }
            fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
                StubExecutor.aggregate_program_digest(shape)
            }
            fn verify_aggregate(
                &self,
                shape: &crate::types::DeclaredShape,
                covered: &[crate::types::CoveredBundle],
                proof: &[u8],
                binding: &[u32; 8],
            ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
                StubExecutor.verify_aggregate(shape, covered, proof, binding)
            }
        }
        assert_eq!(l.validate(&ok, &NoGas), Err(TxError::BundleGasLimit { want: 20_479, got: None }));
        // Without the section any limit is accepted (chains 16/17).
        let (plain, _) = ledger_with_program(|_| {});
        let mut t = tx(&plain, [[60; 8], [61; 8]], [[62; 8], [63; 8]]);
        StubExecutor::with_bundle_gas(&mut t.bundle.as_mut().unwrap().proof, 1);
        assert!(plain.validate(&StubExecutor::bound(t), &StubExecutor).is_ok());
        assert!(plain.validate(&tx(&plain, [[70; 8], [71; 8]], [[72; 8], [73; 8]]), &NoGas).is_ok());
    }

    /// Spec §4.3 for the second proof a v3 (split-authorisation) transaction carries: under the gas
    /// section the auth proof declares exactly the auth guest's tier-10, hash-free ceiling
    /// (`gas::auth_gas_limit_pin`, 1 279) — checked before either proof's verify, and on the
    /// verified-set (B5) path too, exactly like the bundle proof's `bundle_gas_limit`. A chain with
    /// `hc_auth` but no gas section (chain 17) reads no limit at all.
    #[test]
    fn an_auth_proof_declaring_any_other_gas_limit_is_refused() {
        let (a, _) = keys();
        let mut l = v3_ledger();
        l.set_gas(Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: gas::bundle_gas_limit_pin(),
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        }));
        assert_eq!(gas::auth_gas_limit_pin(), 1_279, "(2^10 − 1) + 2^8: tier 10, no hash table");
        assert_eq!(gas::auth_gas_limit_pin(), crate::confidential::STUB_AUTH_GAS_LIMIT);
        let ok = v3_tx(&l);
        assert_eq!(l.validate(&ok, &StubExecutor), Ok(()), "the ceiling passes");
        for other in [1_278u64, 1_280, 20_479, 1] {
            let mut t = ok.clone();
            StubExecutor::with_auth_gas(&mut t.bundle.as_mut().unwrap().auth_proof, other);
            let t = StubExecutor::bound(t);
            let want = Err(TxError::AuthGasLimit { want: 1_279, got: Some(other) });
            assert_eq!(l.validate(&t, &StubExecutor), want, "{other}");
            // A wrong limit buys no verify, of either proof.
            let exec = CountingExecutor::default();
            assert_eq!(l.validate(&t, &exec), want);
            assert_eq!((exec.bundles(), exec.auths()), (0, 0), "refused before either verify");
            // And the verified-set hit, which skips both verifies, still checks the limit.
            let mut applied = l.clone();
            assert_eq!(applied.apply_tx_with(&t, &a.address(), &StubExecutor, &Admitted::of(&[&t])).map(|_| ()), want);
        }
        // Without the gas section (chain 17's rules) the auth proof's limit is not read.
        let plain = v3_ledger();
        let mut t = v3_tx(&plain);
        StubExecutor::with_auth_gas(&mut t.bundle.as_mut().unwrap().auth_proof, 1);
        assert_eq!(plain.validate(&StubExecutor::bound(t), &StubExecutor), Ok(()));
    }

    /// Spec §7.1: a block's `gas_used` is Σ its calls' declared limits plus `bundle_gas_limit` per
    /// bundle proof. One call at limit 40 000 riding its bundle is 40 000 + 20 479 — over the
    /// 20 000 target, so the gas price rises.
    #[test]
    fn a_blocks_gas_used_is_its_calls_limits_and_its_bundles() {
        let (a0, _) = keys();
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(dynamic_gas())));
        let proof = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 40_000);
        let fee = gas::circuit_call_floor(100, 800, 40_000, proof.len());
        let tx = call_tx(&l, 20, id, proof, fee);
        let mut expect = l.clone();
        expect.set_height(2);
        expect.apply_tx(&tx, &a0.address(), &StubExecutor).unwrap();
        expect.close_block(2, &a0.address(), tx.encoded_len() as u64, 40_000 + gas::gas_max(14, 0, 0));
        let block = signed_block(vec![tx], &a0, 2, expect.state_root());
        let mut replica = l.clone();
        replica.apply_block(&block, &StubExecutor).unwrap();
        assert_eq!(replica.gas_prices(), expect.gas_prices());
        assert!(replica.gas_prices().gas_price > 100, "60 479 gas against a 20 000 target raised the price");
    }

    // ---- Issue #135: `fees.burn_floor`, the whole floor burned under `burn_base` --------------

    /// Chain 18's fixed prices as a `gas` section without the controller: 100 per gas, 800 per
    /// KiB, the tier-14 bundle pin. The burn-floor tests price their calls at these.
    fn fixed_gas() -> gas::GasConfig {
        gas::GasConfig { dynamic: None, ..dynamic_gas() }
    }

    /// The three `fees` sections the burn-floor tests compare: the base alone, the base with the
    /// floor, and the floor spelt out `false` (which must be the base alone, byte for byte).
    fn burn_rules(floor: Option<bool>) -> fees::FeesConfig {
        fees::FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: floor, proposer_share_bps: None, prove_base: None }
    }

    /// `l` with `rules` installed and a genesis supply its audit can check against: a large
    /// deposit (the fees below are paid out of it) and the register's stakes, read before any
    /// reward so a fixture that already applied a transaction still balances.
    fn with_rules(mut l: Ledger, rules: fees::FeesConfig) -> Ledger {
        l.set_fees(rules);
        let staked = l.validators().values().map(|e| e.stake).sum();
        l.set_genesis_supply(1_000 * UNITS_PER_RAND, staked);
        l
    }

    /// What one bundle moved, read off the ledger before and after: (burned, kept by the
    /// proposer, `base_fees_burned`, `fees_paid`).
    fn split_of(before: &Ledger, after: &Ledger, p: &Address) -> (u64, u64, u64, u64) {
        (
            after.supply().burned - before.supply().burned,
            after.validators()[p].rewards - before.validators()[p].rewards,
            after.base_fees_burned() - before.base_fees_burned(),
            after.supply().fees_paid - before.supply().fees_paid,
        )
    }

    /// Issue #135, a transfer: its floor is `BUNDLE_BASE`, so under `burn_floor` it burns exactly
    /// what `burn_base` alone burns — the base — and tips the proposer the rest.
    #[test]
    fn burn_floor_burns_a_transfers_base_and_tips_the_rest() {
        let (a, _) = keys();
        let p = a.address();
        let fee = gas::BUNDLE_BASE + 5;
        let l = with_rules(ledger(), burn_rules(Some(true)));
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee), Action::None));
        assert_eq!(l.settled_floor(&t, None), gas::BUNDLE_BASE, "a transfer's floor is the base");
        let mut after = l.clone();
        after.apply_tx(&t, &p, &StubExecutor).unwrap();
        assert_eq!(split_of(&l, &after, &p), (gas::BUNDLE_BASE, 5, gas::BUNDLE_BASE, 5));
        assert!(after.audit().invariant_holds(), "{:?}", after.audit());
    }

    /// Issue #135, a Deploy: its floor is `BUNDLE_BASE + deploy_fee(words)` (`gas::fee_floor`),
    /// all of which burns under `burn_floor`; `burn_base` alone burns the base and pays the
    /// per-word term to the proposer. `base_fees_burned` counts the whole burn under either flag.
    #[test]
    fn burn_floor_burns_a_deploys_whole_floor() {
        let (a, _) = keys();
        let p = a.address();
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 7], public: vec![] };
        let floor = gas::fee_floor(&deploy);
        assert_eq!(floor, gas::BUNDLE_BASE + gas::deploy_fee(7));
        let fee = floor + 7;
        let apply = |rules| {
            let l = with_rules(ledger(), rules);
            let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee), deploy.clone()));
            assert_eq!(l.settled_floor(&t, None), floor);
            let mut after = l.clone();
            after.apply_tx(&t, &p, &StubExecutor).unwrap();
            assert!(after.audit().invariant_holds(), "{:?}", after.audit());
            split_of(&l, &after, &p)
        };
        assert_eq!(apply(burn_rules(Some(true))), (floor, 7, floor, 7), "the whole floor burns, the 7 is the tip");
        let base_only = fee - gas::BUNDLE_BASE;
        assert_eq!(apply(burn_rules(None)), (gas::BUNDLE_BASE, base_only, gas::BUNDLE_BASE, base_only), "burn_base alone");
    }

    /// Issue #135, a Call under a `gas` section: the burned amount is the tier-exact floor
    /// `validate_inner` held the fee to after decoding — `circuit_call_floor` at the proof's
    /// declared `GAS_LIMIT` — never the pre-verify floor at a limit of 1. Without a `gas` section
    /// it is the tier schedule's `BUNDLE_BASE + call_fee(tier, bytes)`. One function,
    /// `settled_floor`, is both the check and the burn: a fee one under it is refused naming it.
    #[test]
    fn burn_floor_burns_a_calls_tier_exact_floor() {
        let (a, _) = keys();
        let p = a.address();
        // Under the gas section, a tier-14 call declaring the tier's ceiling.
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(fixed_gas())));
        let l = with_rules(l, burn_rules(Some(true)));
        let limit = gas::gas_max(14, 0, 0);
        let proof = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], limit);
        let floor = gas::circuit_call_floor(100, 800, limit, proof.len());
        assert_eq!(floor, gas::BUNDLE_BASE + 100 * 20_479 + 800, "a stub proof is under a KiB");
        assert!(floor > l.gas_call_floor(1, proof.len()).unwrap(), "the tier-exact floor, not the pre-verify one");
        let short = call_tx(&l, 20, id, proof.clone(), floor - 1);
        assert_eq!(l.validate(&short, &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        let t = call_tx(&l, 20, id, proof, floor + 11);
        let outcome = StubExecutor.verify_call(l.programs.get(&id).unwrap(), match &t.action {
            Action::Call { proof, .. } => proof,
            _ => unreachable!(),
        });
        assert_eq!(l.settled_floor(&t, outcome.as_ref().ok()), floor);
        let mut after = l.clone();
        after.apply_tx(&t, &p, &StubExecutor).unwrap();
        assert_eq!(split_of(&l, &after, &p), (floor, 11, floor, 11));
        assert!(after.audit().invariant_holds(), "{:?}", after.audit());

        // Without the section: the tier schedule, tier 12.
        let (l, id) = ledger_with_program(|_| {});
        let l = with_rules(l, burn_rules(Some(true)));
        let proof = StubExecutor::make_proof(&id, 12, [7; 8]);
        let floor = gas::BUNDLE_BASE + gas::call_fee(12, proof.len());
        assert!(floor > gas::fee_floor(&Action::Call { program: id, proof: proof.clone(), input_envelope: None }), "tier 12 is over the pre-verify CALL_BASE");
        let t = call_tx(&l, 20, id, proof, floor + 3);
        let mut after = l.clone();
        after.apply_tx(&t, &p, &StubExecutor).unwrap();
        assert_eq!(split_of(&l, &after, &p), (floor, 3, floor, 3));
        assert!(after.audit().invariant_holds(), "{:?}", after.audit());
    }

    /// Issue #135: `burn_floor` absent or `false` is `burn_base` alone, byte for byte — the same
    /// block leaves the same state root — and `true` is a different chain (the proposer's
    /// rewards are in the register). A `burn_floor` without `burn_base` burns nothing: the ledger
    /// reads it only beside the base (genesis refuses it alone).
    #[test]
    fn burn_floor_off_or_false_is_byte_identical_to_burn_base_alone() {
        let (a, _) = keys();
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 9], public: vec![] };
        let root = |rules: fees::FeesConfig| {
            let l = with_rules(ledger(), rules);
            let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy) + 9), deploy.clone()));
            root_after(&l, &[t], &a.address(), 1)
        };
        let base = root(burn_rules(None));
        assert_eq!(root(burn_rules(Some(false))), base, "false is the flag's absence");
        assert_ne!(root(burn_rules(Some(true))), base, "true moves the split, and so the root");
        let alone = fees::FeesConfig { burn_base: None, subsidy_net_of_fees: None, burn_floor: Some(true), proposer_share_bps: None, prove_base: None };
        assert_eq!(root(alone), root(fees::FeesConfig::default()), "burn_floor alone is no rule at all");
    }

    /// Issue #135 under moving prices (`gas.dynamic`): the proposer builds each block its own way
    /// — `apply_tx` per transaction, then `close_block` with `block_usage`'s figures — and a
    /// replica runs `apply_block` on the signed result. Block 2's call (40 000 gas against a
    /// 20 000 target) raises the gas price; block 3 carries a transfer, a Deploy and a tier-14
    /// Call priced at the block-2 prices, and the call burns `circuit_call_floor` at *those*
    /// prices, not the genesis ones. Both sides reach the same root, counters and prices.
    #[test]
    fn a_replica_replays_burn_floor_blocks_at_the_prices_in_force() {
        let (a, _) = keys();
        let p = a.address();
        let (l, id) = ledger_with_program(|l| l.set_gas(Some(dynamic_gas())));
        let l = with_rules(l, burn_rules(Some(true)));
        let genesis_prices = l.gas_prices();
        // The proposer's path: each transaction applied on its own, the controller fed the
        // block's usage, the root read off the result and signed into the block.
        let propose = |parent: &Ledger, txs: Vec<Transaction>, h: u64| -> (Ledger, Block) {
            let mut next = parent.clone();
            next.set_height(h);
            let mut call_gas = 0u64;
            for tx in &txs {
                if let Some(r) = next.apply_tx(tx, &p, &StubExecutor).unwrap() {
                    call_gas += r.gas_used;
                }
            }
            let (bytes, gas_used) = next.block_usage(&txs, call_gas);
            next.close_block(h, &p, bytes, gas_used);
            let block = signed_block(txs, &a, h, next.state_root());
            (next, block)
        };

        // Block 2: one call declaring 40 000 gas, paid at the genesis prices.
        let raise = StubExecutor::make_proof_with_gas(&id, 12, [7; 8], 40_000);
        let raise_fee = gas::circuit_call_floor(genesis_prices.gas_price, genesis_prices.byte_price, 40_000, raise.len());
        let (p2_ledger, b2) = propose(&l, vec![call_tx(&l, 20, id, raise, raise_fee)], 2);
        let p2 = p2_ledger.gas_prices();
        assert!(p2.gas_price > genesis_prices.gas_price, "block 2 raised the gas price: {p2:?}");

        // Block 3: a transfer, a Deploy and a tier-14 call, each paying its floor plus a tip.
        let limit = gas::gas_max(14, 0, 0);
        let proof = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], limit);
        let floor = gas::circuit_call_floor(p2.gas_price, p2.byte_price, limit, proof.len());
        assert_ne!(floor, gas::circuit_call_floor(genesis_prices.gas_price, genesis_prices.byte_price, limit, proof.len()));
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x17; 5], public: vec![] };
        let deploy_floor = gas::fee_floor(&deploy);
        let txs = vec![
            StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[40; 8], [41; 8]], [[42; 8], [43; 8]], gas::BUNDLE_BASE + 5), Action::None)),
            StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], deploy_floor + 7), deploy)),
            call_tx(&l, 30, id, proof, floor + 11),
        ];
        let (proposer, b3) = propose(&p2_ledger, txs, 3);
        assert_eq!(proposer.base_fees_burned() - p2_ledger.base_fees_burned(), gas::BUNDLE_BASE + deploy_floor + floor);
        assert_eq!(proposer.validators()[&p].rewards - p2_ledger.validators()[&p].rewards, 5 + 7 + 11);
        assert!(proposer.audit().invariant_holds(), "{:?}", proposer.audit());

        let mut replica = l.clone();
        replica.apply_block(&b2, &StubExecutor).unwrap();
        replica.apply_block(&b3, &StubExecutor).unwrap();
        assert_eq!(replica.state_root(), proposer.state_root());
        assert_eq!(replica.gas_prices(), proposer.gas_prices());
        assert_eq!(replica.base_fees_burned(), proposer.base_fees_burned());
        assert_eq!(replica.supply(), proposer.supply());
        assert_eq!(replica.validators()[&p].rewards, proposer.validators()[&p].rewards);
        assert_eq!(replica.audit(), proposer.audit());
    }

    // ---- The fee split across every flag (test/fees-core) ---------------------------------

    /// An aggregation section for the split tests: the proving-share bucket on, a `window`-block
    /// coverable window, no admitted shapes (no aggregate is applied here).
    pub(crate) fn split_aggregation(window: u64) -> aggregation::AggregationConfig {
        aggregation::AggregationConfig {
            bond: 100 * UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * UNITS_PER_RAND,
            halving_blocks: 210_000,
            window,
            admitted_shapes: vec![],
        }
    }

    /// The split invariant, exhaustively (`docs/fees.md` §1.3, issue #135): for every `fees`
    /// section the ledger can run — none, `burn_base`, `burn_base + burn_floor` — on a chain with
    /// and without aggregation, for a transfer, a Deploy and a tier-14 Call under a `gas` section,
    /// at tips 0, 1, 999 and 1 000 000 over the action's floor, one block's bundle divides its fee
    /// exactly: `kept + fee_burned + bucketed == fee`, with `kept` the proposer's `rewards` delta,
    /// `fee_burned` the `base_fees_burned` delta, `bucketed` the bundle's bucket entry. `fees_paid`
    /// moves by `kept` and `burned` by `fee_burned`, each cell gets the figure its rule says, the
    /// audit holds, and a replica applying the signed block reaches the proposer's root. Pins the
    /// four-cell `kept` match and `bucket_floor` against each other, so no rule can leak or mint
    /// a unit of a fee in any corner.
    #[test]
    fn the_fee_split_divides_every_fee_exactly_under_every_rule() {
        let (a, _) = keys();
        let p = a.address();
        let rules = [
            ("no fees section", fees::FeesConfig::default()),
            ("burn_base", burn_rules(None)),
            ("burn_base+burn_floor", burn_rules(Some(true))),
        ];
        let limit = gas::gas_max(14, 0, 0);
        let mut cells = 0;
        for (rule_name, rule) in &rules {
            for aggregating in [false, true] {
                // The program is deployed at height 1 under the `gas` section; the bundle under
                // test is block 2.
                let (base, id) = ledger_with_program(|l| l.set_gas(Some(fixed_gas())));
                let mut l = with_rules(base, rule.clone());
                if aggregating {
                    l.set_aggregation(Some(split_aggregation(256)));
                }
                let chain = if aggregating { "aggregating" } else { "non-aggregating" };
                let call_proof = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], limit);
                let deploy = Action::Deploy { base_pc: 0, words: vec![0x17; 5], public: vec![] };
                let actions: [(&str, u64); 3] = [
                    ("transfer", gas::BUNDLE_BASE),
                    ("Deploy of 5 words", gas::fee_floor(&deploy)),
                    ("tier-14 Call", gas::circuit_call_floor(fixed_gas().gas_price, fixed_gas().byte_price, limit, call_proof.len())),
                ];
                for (action_name, floor) in actions {
                    for tip in [0u64, 1, 999, 1_000_000] {
                        let what = format!("{rule_name}, {chain} chain, {action_name}, tip {tip}");
                        let fee = floor + tip;
                        let t = match action_name {
                            "transfer" => StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], fee), Action::None)),
                            "tier-14 Call" => call_tx(&l, 70, id, call_proof.clone(), fee),
                            _ => StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], fee), deploy.clone())),
                        };
                        // The proposer's path, exactly as `a_replica_replays_burn_floor_blocks_…`.
                        let mut after = l.clone();
                        after.set_height(2);
                        let mut call_gas = 0u64;
                        if let Some(r) = after.apply_tx(&t, &p, &StubExecutor).unwrap_or_else(|e| panic!("{what}: {e:?}")) {
                            call_gas += r.gas_used;
                        }
                        let (bytes, gas_used) = after.block_usage(std::slice::from_ref(&t), call_gas);
                        after.close_block(2, &p, bytes, gas_used);

                        let kept = after.validators()[&p].rewards - l.validators()[&p].rewards;
                        let fee_burned = after.base_fees_burned() - l.base_fees_burned();
                        let bucketed = after.unsealed_fees().get(&t.hash()).map_or(0, |e| e.0);
                        assert_eq!(kept + fee_burned + bucketed, fee, "{what}: kept {kept} + burned {fee_burned} + bucketed {bucketed} ≠ fee {fee}");
                        assert_eq!(after.supply().fees_paid - l.supply().fees_paid, kept, "{what}: fees_paid moves by what the proposer keeps");
                        assert_eq!(after.supply().burned - l.supply().burned, fee_burned, "{what}: burned moves by the fee burn alone");
                        // Each cell's own figure (the four-cell `kept` match and `fee_burn`).
                        let want_burn = match *rule_name {
                            "no fees section" => 0,
                            "burn_base" => gas::BUNDLE_BASE,
                            _ => floor,
                        };
                        let want_kept = match (aggregating, want_burn > 0) {
                            (false, false) => fee,
                            (true, false) => gas::BUNDLE_BASE,
                            (false, true) => fee - want_burn,
                            (true, true) => 0,
                        };
                        assert_eq!((kept, fee_burned), (want_kept, want_burn), "{what}: (kept, burned)");
                        assert_eq!(after.unsealed_fees().contains_key(&t.hash()), aggregating, "{what}: a bucket entry exactly on an aggregating chain");
                        assert!(after.audit().invariant_holds(), "{what}: {:?}", after.audit());

                        // Determinism: a replica applying the signed block reaches the same root,
                        // twice over.
                        let block = signed_block(vec![t.clone()], &a, 2, after.state_root());
                        for replica_run in 0..2 {
                            let mut replica = l.clone();
                            replica.apply_block(&block, &StubExecutor).unwrap_or_else(|e| panic!("{what}, replica {replica_run}: {e:?}"));
                            assert_eq!(replica.state_root(), after.state_root(), "{what}: replica {replica_run}'s root");
                            assert_eq!(replica.base_fees_burned(), after.base_fees_burned(), "{what}: replica {replica_run}'s burn");
                        }
                        cells += 1;
                    }
                }
            }
        }
        assert_eq!(cells, 3 * 2 * 3 * 4, "every combination ran");
    }

    /// The sweep under `burn_floor` when the recording proposer is gone (`sweep_expired_excesses`,
    /// spec §5.2): on an aggregating chain under `burn_base + burn_floor` a tier-14 Call's
    /// excess `fee − floor` is bucketed against the proposer that included it; that entry then
    /// leaves the register; when the window expires the *committing* proposer takes exactly
    /// `fee − floor` — never the burned floor — and `fees_paid` moves by it. The ledger has no
    /// action that deletes a register entry today (a full `Withdraw` leaves an empty entry), so
    /// the test removes the emptied entry directly to reach the sweep's fallback arm.
    #[test]
    fn the_sweep_pays_the_committing_proposer_fee_less_the_floor_when_the_recorder_is_gone() {
        let (a, _) = keys();
        let committing = a.address();
        let (base, id) = ledger_with_program(|l| l.set_gas(Some(fixed_gas())));
        let mut l = base;
        l.set_aggregation(Some(split_aggregation(2)));
        // The recorder: a register entry with nothing in it, so removing it moves no value.
        let recorder_key = Keypair::from_seed([3; 32]).unwrap();
        let (recorder, recorder_entry) = entry(&recorder_key, 0);
        l.validators.insert(recorder, recorder_entry);
        let mut l = with_rules(l, burn_rules(Some(true)));
        l.set_height(2);

        let limit = gas::gas_max(14, 0, 0);
        let proof = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], limit);
        let floor = gas::circuit_call_floor(100, 800, limit, proof.len());
        let tip = 4_321;
        let t = call_tx(&l, 20, id, proof, floor + tip);
        l.apply_tx(&t, &recorder, &StubExecutor).unwrap();
        l.close_block(2, &recorder, 0, 0);
        assert_eq!(l.unsealed_fees().get(&t.hash()), Some(&(tip, recorder, 4)), "fee − floor bucketed to the recorder, until 2 + 2");
        assert_eq!(l.validators()[&recorder].rewards, 0, "the recorder kept nothing at inclusion");
        assert_eq!(l.base_fees_burned(), floor, "the whole floor burned");

        // The recorder leaves the register (empty, so the register total does not move).
        assert_eq!(l.validators.remove(&recorder).map(|e| (e.stake, e.rewards, e.pending.len())), Some((0, 0, 0)));
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());

        let before = l.clone();
        for h in [3u64, 4] {
            let mut next = l.clone();
            next.set_height(h);
            next.close_block(h, &committing, 0, 0);
            let block = signed_block(vec![], &a, h, next.state_root());
            l.apply_block(&block, &StubExecutor).unwrap();
            if h == 3 {
                assert!(l.unsealed_fees().contains_key(&t.hash()), "still coverable at 3");
            }
        }
        assert!(l.unsealed_fees().is_empty(), "the window passed at 4");
        assert_eq!(
            l.validators()[&committing].rewards - before.validators()[&committing].rewards,
            tip,
            "the committing proposer takes exactly fee − floor"
        );
        assert_eq!(l.supply().fees_paid - before.supply().fees_paid, tip, "fees_paid moves by the swept excess");
        assert_eq!(l.base_fees_burned(), before.base_fees_burned(), "the sweep burns nothing more");
        assert!(l.audit().invariant_holds(), "{:?}", l.audit());
    }

    // ---- The proposer/aggregator split and `prove_base` (docs/compute-optimization.md §6.2–§6.3) --

    /// The proposal's `prove_base`, 0.0006 RAND.
    const PROVE_BASE: u64 = 600_000;

    /// A `fees` section carrying the split's two fields beside the older flags.
    fn split_rules(burn_base: bool, burn_floor: bool, bps: Option<u32>, prove_base: Option<u64>) -> fees::FeesConfig {
        fees::FeesConfig {
            burn_base: burn_base.then_some(true),
            subsidy_net_of_fees: None,
            burn_floor: burn_floor.then_some(true),
            proposer_share_bps: bps,
            prove_base,
        }
    }

    /// The fee split's two fields, exhaustively, on an aggregating chain: for `proposer_share_bps`
    /// at 0, 4 000 and 10 000, with and without `prove_base`, alone and under `burn_base` and
    /// `burn_base + burn_floor`, for a transfer, a Deploy and a tier-14 Call at tips 0, 1, 999 and
    /// 1 000 000 over the floor: the floor (pre-verify and post-decode alike) is the old floor
    /// plus `prove_base` — one unit under it is `FeeTooLow` naming it, `settled_floor` reports
    /// it — and the bundle divides its fee exactly, `kept + burned + bucketed == fee`, with
    /// `kept` the proposer's part of the base it keeps today (`BUNDLE_BASE`, or nothing under
    /// `burn_base`), `burned` the floor *without* `prove_base` under `burn_floor`, and the bucket
    /// the rest (the tip, `prove_base` whole, and the aggregator's part of the base). `fees_paid`
    /// moves by `kept`, the audit holds, and a replica applying the signed block reaches the
    /// proposer's root.
    #[test]
    fn the_proposer_share_and_prove_base_divide_every_fee_exactly() {
        let (a, _) = keys();
        let p = a.address();
        let limit = gas::gas_max(14, 0, 0);
        let mut cells = 0;
        for (burn_base, burn_floor) in [(false, false), (true, false), (true, true)] {
            // Odd shares (1, 9 999) exercise the rounding rule, though while `BUNDLE_BASE` is a
            // multiple of 10 000 (1 000 000 = 100 · 10 000) `kept_base · (10 000 − bps)` always
            // divides exactly and the floor never rounds — the rule only bites if the base moves.
            for bps in [Some(0u32), Some(1), Some(4000), Some(9_999), Some(10_000), None] {
                for prove_base in [None, Some(PROVE_BASE)] {
                    if bps.is_none() && prove_base.is_none() {
                        continue; // the older rules alone: `the_fee_split_divides_every_fee_exactly_under_every_rule`
                    }
                    let rule = split_rules(burn_base, burn_floor, bps, prove_base);
                    let (base, id) = ledger_with_program(|l| l.set_gas(Some(fixed_gas())));
                    let mut l = with_rules(base, rule.clone());
                    l.set_aggregation(Some(split_aggregation(256)));
                    let pb = prove_base.unwrap_or(0);
                    let call_proof = StubExecutor::make_proof_with_gas(&id, 14, [7; 8], limit);
                    let deploy = Action::Deploy { base_pc: 0, words: vec![0x17; 5], public: vec![] };
                    let actions: [(&str, u64); 3] = [
                        ("transfer", gas::BUNDLE_BASE),
                        ("Deploy of 5 words", gas::fee_floor(&deploy)),
                        ("tier-14 Call", gas::circuit_call_floor(fixed_gas().gas_price, fixed_gas().byte_price, limit, call_proof.len())),
                    ];
                    for (action_name, old_floor) in actions {
                        let floor = old_floor + pb;
                        let make = |l: &Ledger, fee: u64| match action_name {
                            "transfer" => StubExecutor::bound(Transaction::shielded(7, bundle(l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], fee), Action::None)),
                            "tier-14 Call" => call_tx(l, 70, id, call_proof.clone(), fee),
                            _ => StubExecutor::bound(Transaction::shielded(7, bundle(l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], fee), deploy.clone())),
                        };
                        let what = format!("{rule:?}, {action_name}");
                        // The floor: one unit under it is refused by name, at the new minimum.
                        assert_eq!(
                            l.validate(&make(&l, floor - 1), &StubExecutor),
                            Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }),
                            "{what}: the floor includes prove_base"
                        );
                        if action_name != "tier-14 Call" {
                            assert_eq!(l.settled_floor(&make(&l, floor), None), floor, "{what}: settled_floor adds prove_base");
                        }
                        for tip in [0u64, 1, 999, 1_000_000] {
                            let what = format!("{what}, tip {tip}");
                            let fee = floor + tip;
                            let t = make(&l, fee);
                            let mut after = l.clone();
                            after.set_height(2);
                            let mut call_gas = 0u64;
                            if let Some(r) = after.apply_tx(&t, &p, &StubExecutor).unwrap_or_else(|e| panic!("{what}: {e:?}")) {
                                call_gas += r.gas_used;
                            }
                            let (bytes, gas_used) = after.block_usage(std::slice::from_ref(&t), call_gas);
                            after.close_block(2, &p, bytes, gas_used);

                            let kept = after.validators()[&p].rewards - l.validators()[&p].rewards;
                            let burned = after.base_fees_burned() - l.base_fees_burned();
                            let bucketed = after.unsealed_fees().get(&t.hash()).map_or(0, |e| e.0);
                            let want_burn = match (burn_base, burn_floor) {
                                (false, _) => 0,
                                (true, false) => gas::BUNDLE_BASE,
                                (true, true) => old_floor,
                            };
                            let kept_base = if burn_base { 0 } else { gas::BUNDLE_BASE };
                            let aggregator_part = bps.map_or(0, |b| kept_base * (10_000 - b as u64) / 10_000);
                            let want_kept = kept_base - aggregator_part;
                            assert_eq!((kept, burned), (want_kept, want_burn), "{what}: (kept, burned)");
                            assert_eq!(bucketed, fee - want_burn - want_kept, "{what}: the bucket holds the rest");
                            assert!(bucketed >= tip + pb + aggregator_part, "{what}: prove_base and the base part are bucketed whole");
                            assert_eq!(kept + burned + bucketed, fee, "{what}: exact");
                            assert_eq!(after.supply().fees_paid - l.supply().fees_paid, kept, "{what}: fees_paid moves by the proposer part");
                            assert_eq!(after.supply().burned - l.supply().burned, burned, "{what}: burned moves by the fee burn alone");
                            assert!(after.audit().invariant_holds(), "{what}: {:?}", after.audit());

                            let block = signed_block(vec![t.clone()], &a, 2, after.state_root());
                            let mut replica = l.clone();
                            replica.apply_block(&block, &StubExecutor).unwrap_or_else(|e| panic!("{what}, replica: {e:?}"));
                            assert_eq!(replica.state_root(), after.state_root(), "{what}: the replica's root");
                            assert_eq!(replica.unsealed_fees(), after.unsealed_fees(), "{what}: the replica's bucket");
                            assert_eq!(replica.supply(), after.supply(), "{what}: the replica's counters");
                            cells += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(gas::BUNDLE_BASE % 10_000, 0, "the premise of the rounding comment above");
        assert_eq!(cells, 3 * 11 * 3 * 4, "every combination ran");
    }

    /// The proposal's worked arithmetic (`docs/fees.md` §1.3): a 0.0012 RAND transfer under
    /// 4 000 bps pays 0.0004 to the proposer at inclusion and buckets 0.0008 (0.0006 of base and
    /// the 0.0002 tip); with `prove_base` 0.0006 the floor is 0.0016, so the same tip is a 0.0018
    /// RAND fee and the bucket 0.0014. A bundle paying the old 0.001 floor is `FeeTooLow` at the
    /// new one.
    #[test]
    fn the_worked_split_arithmetic_holds() {
        let (a, _) = keys();
        let p = a.address();
        for (prove_base, fee, kept, bucket) in [(None, 1_200_000, 400_000, 800_000), (Some(PROVE_BASE), 1_800_000, 400_000, 1_400_000)] {
            let mut l = with_rules(ledger(), split_rules(false, false, Some(4000), prove_base));
            l.set_aggregation(Some(split_aggregation(256)));
            let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], fee), Action::None));
            if prove_base.is_some() {
                let old = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), Action::None));
                assert_eq!(l.validate(&old, &StubExecutor), Err(TxError::FeeTooLow { min: 1_600_000, fee: gas::BUNDLE_BASE }));
                assert_eq!(l.prove_base(), PROVE_BASE);
            }
            let mut after = l.clone();
            after.apply_tx(&t, &p, &StubExecutor).unwrap();
            let (_, k, _, paid) = split_of(&l, &after, &p);
            assert_eq!((k, paid), (kept, kept), "{prove_base:?}: the proposer's 40 % of the base");
            assert_eq!(after.unsealed_fees()[&t.hash()].0, bucket, "{prove_base:?}: the bucket");
            assert!(after.audit().invariant_holds(), "{:?}", after.audit());
        }
    }

    /// Both split fields are an aggregating chain's rules: genesis refuses them anywhere else,
    /// and a ledger handed them without an `aggregation` section (only a test can) runs neither —
    /// the floor, the split and the root are the plain chain's, byte for byte.
    #[test]
    fn without_aggregation_the_split_fields_change_nothing() {
        let (a, _) = keys();
        let p = a.address();
        let run = |rules: fees::FeesConfig| {
            let mut l = with_rules(ledger(), rules);
            let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE + 5), Action::None));
            assert_eq!(l.settled_floor(&t, None), gas::BUNDLE_BASE);
            assert_eq!(l.prove_base(), 0);
            l.apply_tx(&t, &p, &StubExecutor).unwrap();
            (l.validators()[&p].rewards, l.supply(), l.state_root())
        };
        assert_eq!(run(split_rules(false, false, Some(4000), Some(PROVE_BASE))), run(fees::FeesConfig::default()));
    }

    /// A `StubExecutor` whose `check_program` accepts a seven-word program on every even-numbered
    /// ask and refuses it on every odd one. A `Deploy` asks twice, once in `validate_inner` and once
    /// in the action step after `apply_bundle_notes` has written the bundle, so every such deploy
    /// passes validation and then fails mid-application: the half-applied case
    /// ([`ApplyFailure::HalfApplied`]) that `apply_tx_with`'s comment names, which the double spend
    /// (refused before any write, [`ApplyFailure::Refused`]) is not. Shared with the consensus
    /// tests, whose proposer replays exactly on this case.
    pub(crate) struct FlakyDeploy {
        pub(crate) asked: std::sync::atomic::AtomicUsize,
    }

    impl ConfidentialExecutor for FlakyDeploy {
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, crate::confidential::ConfidentialError> {
            if words.len() == 7 && self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 2 == 1 {
                return Err(crate::confidential::ConfidentialError::Disabled);
            }
            StubExecutor.check_program(base_pc, words)
        }
        fn verify_call(&self, program: &crate::program::ProgramRecord, proof: &[u8]) -> Result<crate::program::CallOutcome, crate::confidential::ConfidentialError> {
            StubExecutor.verify_call(program, proof)
        }
        fn public_digest(&self, words: &[u32]) -> crate::notes::Word8 {
            StubExecutor.public_digest(words)
        }
        fn hash_domain(&self, domain: u32, msg: &[u32]) -> crate::notes::Word8 {
            StubExecutor.hash_domain(domain, msg)
        }
        fn node_hash(&self, left: &crate::notes::Word8, right: &crate::notes::Word8) -> crate::notes::Word8 {
            StubExecutor.node_hash(left, right)
        }
        fn note_commitment(&self, pk: &crate::notes::Word8, from: &crate::notes::Word8, amount: u64, asset: u32, time: u32, r: &crate::notes::Word8) -> crate::notes::Word8 {
            StubExecutor.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> crate::notes::Word8 {
            StubExecutor.bundle_digest(input)
        }
        fn bundle_digest_v3(&self, input: &crate::notes::BundleDigestInput) -> crate::notes::Word8 {
            StubExecutor.bundle_digest_v3(input)
        }
        fn bundle_proof_digest(&self, hc_bundle: &crate::notes::Word8, proof: &[u8]) -> Result<crate::notes::Word8, crate::confidential::ConfidentialError> {
            StubExecutor.bundle_proof_digest(hc_bundle, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<crate::notes::Word8, crate::confidential::ConfidentialError> {
            StubExecutor.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc_auth: &crate::notes::Word8, proof: &[u8], binding: &[u32; 8]) -> Result<crate::notes::Word8, crate::confidential::ConfidentialError> {
            StubExecutor.verify_auth(hc_auth, proof, binding)
        }
        fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, crate::confidential::ConfidentialError> {
            StubExecutor.bundle_gas_limit(proof)
        }
        fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, crate::confidential::ConfidentialError> {
            StubExecutor.auth_gas_limit(proof)
        }
        fn verify_bundle(&self, hc_bundle: &crate::notes::Word8, proof: &[u8], binding: &[u32; 8]) -> Result<(), crate::confidential::ConfidentialError> {
            StubExecutor.verify_bundle(hc_bundle, proof, binding)
        }
        fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], crate::confidential::ConfidentialError> {
            StubExecutor.aggregate_program_digest(shape)
        }
        fn verify_aggregate(
            &self,
            shape: &crate::types::DeclaredShape,
            covered: &[crate::types::CoveredBundle],
            proof: &[u8],
            binding: &[u32; 8],
        ) -> Result<Vec<[u32; 8]>, crate::confidential::ConfidentialError> {
            StubExecutor.verify_aggregate(shape, covered, proof, binding)
        }
    }

    /// The proposer's split (final review F1): a candidate refused by validation leaves the
    /// ledger byte-identical, so `HotStuff::propose` skips it without a replay; one that passed
    /// validation and failed in the action step has written its bundle, so the proposer must
    /// rebuild. `apply_tx_checked` names which, and `apply_tx_with` is the same path with the
    /// distinction dropped.
    #[test]
    fn apply_tx_checked_names_a_refusal_apart_from_a_half_apply() {
        let (a, _) = keys();
        let mut l = ledger();
        // Built against the same anchor as the first, which the apply below does not record.
        let first = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        let dup = tx(&l, [[1; 8], [9; 8]], [[5; 8], [6; 8]]);
        let deploy = Action::Deploy { base_pc: 0, words: vec![0x13; 7], public: vec![] };
        let t = StubExecutor::bound(Transaction::shielded(7, bundle(&l, [[20; 8], [21; 8]], [[22; 8], [23; 8]], gas::fee_floor(&deploy)), deploy));
        l.apply_tx(&first, &a.address(), &StubExecutor).unwrap();
        let before = l.clone();
        // The double spend: refused before any write.
        let err = l.apply_tx_checked(&dup, &a.address(), &StubExecutor, &NoVerified).unwrap_err();
        assert_eq!(err, ApplyFailure::Refused(TxError::Spent([1; 8])));
        assert!(l == before, "a refusal leaves the ledger equal to its pre-call clone");
        assert_eq!(l.apply_tx_with(&dup, &a.address(), &StubExecutor, &NoVerified), Err(TxError::Spent([1; 8])), "the same error through apply_tx_with");
        // The half-apply: validation passes, the action step refuses after the bundle was written.
        let flaky = FlakyDeploy { asked: Default::default() };
        let err = l.apply_tx_checked(&t, &a.address(), &flaky, &NoVerified).unwrap_err();
        assert!(matches!(err, ApplyFailure::HalfApplied(TxError::BadProgram(_))), "{err:?}");
        assert!(l.is_spent(&[20; 8]) && l.is_spent(&[21; 8]), "the bundle's nullifiers were written before the refusal");
        assert!(l != before, "a half-apply leaves the ledger dirty");
    }
}
