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
pub mod bridge_notes;
pub mod call_envelope;
pub mod staking;
pub mod supply;

use crate::bridge::{BridgeError, BridgeState, CheckedAttestation};
use crate::confidential::{ConfidentialError, ConfidentialExecutor, StubExecutor};
use crate::crypto::{merkle_root, Address, Hash};
use crate::gas;
use crate::notes::{word8_to_bytes, Bundle, CommitmentTree, Envelope, Word8, MAX_ENVELOPE_BYTES};
use crate::program::{program_id_with_public, CallOutcome, CallReceipt, ProgramId, ProgramRecord};
use crate::types::{Action, Block, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// How many block-end roots a bundle may anchor to (spec §7 item 4).
///
/// The spec proposed 64, sized for "about a minute at 1 s blocks". A tier-14 bundle proof measures
/// ~100 s on a laptop and the fleet makes a block every ~2 s, so 64 blocks expired an anchor
/// roughly halfway through proving one honest transfer. 256 blocks is ~8.5 minutes at the fleet's
/// pace and ~2 minutes even at 500 ms blocks — comfortably longer than the proof it has to outlive.
pub const ANCHOR_WINDOW: usize = 256;
/// How far behind the current height a bundle's `time` may be (spec §7 item 5). Kept equal to
/// [`ANCHOR_WINDOW`]: the two windows exist for the same reason (a prover needs the chain to still
/// accept what it started proving), and a shorter `time` window would reject bundles whose anchor
/// is still live.
pub const TIME_WINDOW: u64 = 256;

pub use staking::{StakingError, ValidatorEntry};
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
    #[error("asset {0} is not supported in this release")]
    UnsupportedAsset(u32),
    #[error("burn of {0} is not supported in this release")]
    UnsupportedBurn(u64),
    #[error("fee {fee} below minimum {min}")]
    FeeTooLow { min: u64, fee: u64 },
    #[error("anchor is not one of the last {ANCHOR_WINDOW} roots")]
    UnknownAnchor,
    /// A bundle's `time`, or a bundle-less `Withdraw`'s, outside the window (spec §7 item 5).
    #[error("time {time} is outside [{}, {height}]", height.saturating_sub(TIME_WINDOW))]
    TimeOutOfWindow { time: u32, height: u64 },
    /// One bundle spends a nullifier twice, or — in a `BridgeBurn` — the fee bundle and the
    /// asset bundle spend the same one. Both are the same double spend within one transaction.
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
    #[error("minter {0} is not a validator")]
    MinterNotValidator(Address),
    #[error("bad mint signature")]
    BadMintSignature,
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
    #[error("invalid bundle proof: {0}")]
    InvalidBundleProof(ConfidentialError),
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
    /// Only a first sighting can reach it in practice: the index a registered asset deposits
    /// under never changes, while a new token's is the registry's `next_index` at apply time, and
    /// a competing first sighting moves it. Refusing costs the submitter a fee bundle and a
    /// re-proof; accepting would append a note whose `asset` word is not the one the recipient's
    /// envelope was sealed against, which no key of theirs opens.
    #[error("the attestation deposits under asset {expected}, and the transaction names {actual}")]
    AttestAssetMismatch { expected: u32, actual: u32 },
    /// A `BridgeBurn`'s asset bundle is in the wrong asset, pays a fee, or burns the wrong
    /// amount. All three are the same mistake — the asset bundle does not match the burn the
    /// action declares — and all three are caught before either bundle's proof is verified.
    #[error("the burn's asset bundle is in asset {actual}, not the declared {expected}")]
    BurnAssetMismatch { expected: u32, actual: u32 },
    #[error("the burn's asset bundle pays a fee of {0}; the fee is paid by the RAND bundle")]
    BurnAssetBundleFee(u64),
    #[error("the burn's asset bundle burns {actual}, not the {expected} the action sends")]
    BurnAmountMismatch { expected: u64, actual: u64 },
    #[error("proposer {0} is not in the validator register")]
    UnknownProposer(Address),
    /// Phase S2: a `Bond`, `Unbond` or `Withdraw` the register refused (see [`StakingError`]).
    #[error("staking: {0}")]
    Staking(#[from] StakingError),
    /// Block aggregation: a register action or aggregate the aggregation module refused (see
    /// [`aggregation::AggregationError`]).
    #[error("aggregation: {0}")]
    Aggregation(#[from] aggregation::AggregationError),
    #[error("arithmetic overflow")]
    Overflow,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("tx {index} invalid: {error}")]
    InvalidTx { index: usize, error: TxError },
    #[error("tx root mismatch")]
    TxRootMismatch,
    #[error("state root mismatch: computed {computed}, header {header}")]
    StateRootMismatch { computed: Hash, header: Hash },
    #[error("bad proposer signature")]
    BadProposerSignature,
    #[error("proposer {0} is not a validator")]
    UnknownProposer(Address),
    #[error("too many transactions in block")]
    TooManyTransactions,
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
}

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
}

/// What `validate_inner` verified that `apply_tx` would otherwise verify again: a call's
/// outcome (a STARK verification) and a `BridgeAttest`'s checked attestation (a guardian
/// quorum's worth of signature recoveries). `Ledger::validate` drops it; `apply_tx` spends it.
#[derive(Clone, Debug, Default)]
struct Verified {
    call: Option<CallOutcome>,
    attestation: Option<CheckedAttestation>,
}

/// In-memory chain state: the note commitment tree, the nullifier set, the validator register
/// and the deployed programs. Cheap to clone (used for speculative execution).
#[derive(Clone, Debug)]
pub struct Ledger {
    chain_id: u64,
    /// The pinned commitment of the `bundle` guest every bundle proof must be for.
    hc_bundle: Word8,
    faucet: bool,
    confidential: bool,
    tree: CommitmentTree,
    /// Every leaf ever appended — spec §7 item 6 needs membership the frontier cannot answer.
    commitments: BTreeSet<Word8>,
    nullifiers: BTreeSet<Word8>,
    /// Block-end roots, oldest first, at most ANCHOR_WINDOW.
    anchors: VecDeque<(u64, Word8)>,
    validators: BTreeMap<Address, ValidatorEntry>,
    programs: BTreeMap<ProgramId, ProgramRecord>,
    /// Blocks per epoch (spec §8), from genesis. Not state: like `faucet` and `confidential`,
    /// a reloading node sets it from its genesis file.
    epoch_blocks: u64,
    /// The public half of the bridge, present exactly when genesis has a `bridge` section
    /// (spec §10). `None` makes the two bridge actions inadmissible and leaves the state root
    /// with the four components a bridge-less chain has always had.
    bridge: Option<BridgeState>,
    /// The aggregation section of genesis (spec §2), set from the genesis file exactly like
    /// `epoch_blocks` — a genesis parameter, not consensus state. `None` makes the five
    /// aggregation actions inadmissible and keeps the state root byte-for-byte today's.
    aggregation: Option<aggregation::AggregationConfig>,
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
    /// The aggregator register, hashed into the state root (spec §2.1) when `aggregation` is
    /// set; empty otherwise and at chain-9 block 0.
    aggregators: BTreeMap<Address, aggregation::AggregatorEntry>,
    /// Height of the block being applied (the `time` window and `ProgramRecord::deployed_at`).
    height: u64,
    /// Timestamp of the block being applied, in unix milliseconds.
    timestamp_ms: u64,
    /// Deposit notes this block's transactions made the ledger create (see [`Deposit`]).
    deposits: Vec<Deposit>,
    /// The sealed form's side table for the block being applied (spec §7), keyed by proof
    /// hash: the raw transaction hash and the 34 public values per pruned bundle. Scratch,
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
            && self.anchors == o.anchors
            && self.validators == o.validators
            && self.programs == o.programs
            && self.bridge == o.bridge
            && self.aggregators == o.aggregators
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
            commitments: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            anchors,
            validators,
            programs: BTreeMap::new(),
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            bridge: None,
            aggregation: None,
            max_program_words: gas::MAX_PROGRAM_WORDS,
            max_proof_bytes: gas::MAX_PROOF_BYTES,
            max_block_bytes: gas::MAX_BLOCK_BYTES,
            max_call_envelope_bytes: crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
            max_program_public_words: gas::MAX_PROGRAM_PUBLIC_WORDS,
            aggregators: BTreeMap::new(),
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            pruned_side: BTreeMap::new(),
            supply: Supply::default(),
            unsealed_fees: BTreeMap::new(),
        }
    }

    /// Rebuild a ledger from stored state. The faucet and confidential switches come from
    /// genesis, not from storage, so the caller sets them afterwards — and so does the bridge,
    /// via [`Ledger::set_bridge`].
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
            commitments,
            nullifiers,
            anchors: anchors.into_iter().collect(),
            validators,
            programs,
            epoch_blocks: staking::EPOCH_BLOCKS_DEFAULT,
            bridge: None,
            aggregation: None,
            max_program_words: gas::MAX_PROGRAM_WORDS,
            max_proof_bytes: gas::MAX_PROOF_BYTES,
            max_block_bytes: gas::MAX_BLOCK_BYTES,
            max_call_envelope_bytes: crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
            max_program_public_words: gas::MAX_PROGRAM_PUBLIC_WORDS,
            aggregators: BTreeMap::new(),
            height: 0,
            timestamp_ms: 0,
            deposits: Vec::new(),
            pruned_side: BTreeMap::new(),
            supply: Supply::default(),
            unsealed_fees: BTreeMap::new(),
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

    /// The validator set the next epoch would use if this ledger were the last block of one
    /// (spec §8). The rule itself lives in [`staking::derive_set`].
    pub fn derive_next_set(&self) -> ValidatorSet {
        staking::derive_set(&self.validators)
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

    /// What genesis itself created, set once by [`crate::genesis::Genesis::build`]: the deposit
    /// notes in the pool and the stakes in the register. Neither was minted by a transaction,
    /// and together they are the whole of a chain's supply before its first block.
    pub fn set_genesis_supply(&mut self, deposited: u64, staked: u64) {
        self.supply.genesis_deposited = deposited;
        self.supply.genesis_staked = staked;
    }

    /// The supply audit against this ledger's own register.
    pub fn audit(&self) -> Audit {
        Audit::new(
            self.supply,
            register_total(&self.validators).saturating_add(supply::aggregators_total(&self.aggregators)),
        )
    }

    /// Deposit notes this ledger created while applying the current block (see [`Deposit`]).
    pub fn deposits(&self) -> &[Deposit] {
        &self.deposits
    }

    /// Take the deposits, leaving the list empty.
    pub fn take_deposits(&mut self) -> Vec<Deposit> {
        std::mem::take(&mut self.deposits)
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
        let index = self.tree.append(cm, executor);
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

    /// The largest proof a transaction may carry, in bytes, as genesis set it (default
    /// [`gas::MAX_PROOF_BYTES`]).
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
    /// behind it. Three things carry one — a bundle's `time`, which its proof binds the notes it
    /// creates to, a bundle-less `Withdraw`'s (S2) and a `BridgeAttest`'s (S3), each of which the
    /// ledger stamps its derived note with — and all three are a promise about *when* that the
    /// chain has to hold to the same window, or they would drift apart on a chain where only one
    /// of them was checked. Public so the mempool re-checks it with this very function as the
    /// chain scrolls on, rather than re-deriving the rule.
    pub fn time_in_window(&self, time: u32) -> bool {
        let t = time as u64;
        t <= self.height && self.height - t <= TIME_WINDOW
    }

    fn check_time(&self, time: u32) -> Result<(), TxError> {
        if !self.time_in_window(time) {
            return Err(TxError::TimeOutOfWindow { time, height: self.height });
        }
        Ok(())
    }

    pub fn nullifiers(&self) -> &BTreeSet<Word8> {
        &self.nullifiers
    }

    pub fn is_spent(&self, nf: &Word8) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Every commitment ever appended, which the frontier tree cannot answer on its own.
    pub fn commitments_set(&self) -> &BTreeSet<Word8> {
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

    /// Record the root at the end of block `height`. Idempotent per height: re-recording the
    /// same height replaces that entry rather than filling the window with one block's roots.
    pub fn record_anchor(&mut self, height: u64) {
        let root = self.tree.root();
        if let Some(entry) = self.anchors.iter_mut().find(|(h, _)| *h == height) {
            entry.1 = root;
            return;
        }
        self.anchors.push_back((height, root));
        while self.anchors.len() > ANCHOR_WINDOW {
            self.anchors.pop_front();
        }
    }

    /// Append one note the chain created itself rather than accepted from a bundle: a genesis
    /// alloc note, or the deposit note a `BridgeAttest` mints (spec §10).
    pub fn deposit(&mut self, cm: Word8, executor: &dyn ConfidentialExecutor) -> Result<u64, TxError> {
        if !self.commitments.insert(cm) {
            return Err(TxError::CommitmentExists(cm));
        }
        Ok(self.tree.append(cm, executor))
    }

    /// Write one admitted bundle's notes: nullifiers into the spent set, commitments into the
    /// set and the tree. The write half of [`Ledger::check_bundle`], and like it, shared by the
    /// transaction's fee bundle and a `BridgeBurn`'s asset bundle so the two cannot drift.
    ///
    /// Infallible by the time it runs: `check_bundle` established that none of these four
    /// words is already present.
    fn apply_bundle_notes(&mut self, b: &Bundle, executor: &dyn ConfidentialExecutor) {
        for nf in &b.nullifiers {
            self.nullifiers.insert(*nf);
        }
        for cm in &b.commitments {
            self.commitments.insert(*cm);
            self.tree.append(*cm, executor);
        }
    }

    /// Spec §7 items 4-6 for one bundle: its anchor is live, its `time` is in the window, its
    /// two nullifiers differ and are unspent, its two commitments differ and are new.
    ///
    /// Every bundle on the chain passes through here — the transaction's fee bundle above and a
    /// `BridgeBurn`'s asset bundle in [`bridge_notes`] — so the two cannot drift apart. What is
    /// deliberately *not* here is the shape (asset, burn, fee floor): a fee bundle and an asset
    /// bundle differ in exactly those three fields, and each caller reports its own mismatch.
    fn check_bundle(&self, b: &Bundle) -> Result<(), TxError> {
        if !self.is_anchor(&b.anchor) {
            return Err(TxError::UnknownAnchor);
        }
        self.check_time(b.time)?;
        if b.nullifiers[0] == b.nullifiers[1] {
            return Err(TxError::DuplicateNullifierInBundle);
        }
        for nf in &b.nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(TxError::Spent(*nf));
            }
        }
        if b.commitments[0] == b.commitments[1] {
            return Err(TxError::DuplicateCommitmentInBundle);
        }
        for cm in &b.commitments {
            if self.commitments.contains(cm) {
                return Err(TxError::CommitmentExists(*cm));
            }
        }
        Ok(())
    }

    /// Spec §7 items 8-9 for one bundle: the digest its proof publishes is the digest its
    /// plaintext fields hash to, and the proof verifies against the pinned bundle guest. This
    /// is the expensive half of admission and runs only after every cheap check of *every*
    /// bundle in the transaction.
    fn check_bundle_proof(&self, b: &Bundle, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        // A pruned bundle (spec §6.2's marker form) carries no proof to check: the covering
        // aggregate — verified when its own block applied — is what this bundle's validity
        // rests on. Two checks stand in for it (spec §7's acceptance, the ledger's half): the
        // proof hash must be one the sync side vouched for, and the bundle's own public fields
        // must hash to the digest the covering aggregate's verified public values commit to —
        // the binding that keeps a peer from substituting the bundle's content.
        if let Some(proof_hash) = crate::notes::pruned_proof_hash(&b.proof) {
            let Some((_, pv)) = self.pruned_side.get(&proof_hash) else {
                return Err(TxError::InvalidBundleProof(crate::confidential::ConfidentialError::MalformedProof));
            };
            let want = executor.bundle_digest(&b.digest_input());
            let got: Word8 = std::array::from_fn(|k| {
                u32::try_from(pv[crate::types::pv::OUT0 + k]).expect("a pruned record's OUT words are u32-range")
            });
            return if want == got { Ok(()) } else { Err(TxError::BadDigest) };
        }
        let published = executor.bundle_proof_digest(&b.proof).map_err(TxError::InvalidBundleProof)?;
        if published != executor.bundle_digest(&b.digest_input()) {
            return Err(TxError::BadDigest);
        }
        executor.verify_bundle(&self.hc_bundle, &b.proof).map_err(TxError::InvalidBundleProof)
    }

    /// Check a transaction against the current state without applying it.
    pub fn validate(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<(), TxError> {
        self.validate_inner(tx, executor).map(|_| ())
    }

    /// Spec §7, in order: cheap before expensive. Returns what it verified so `apply_tx`
    /// verifies each proof and each guardian quorum exactly once.
    fn validate_inner(&self, tx: &Transaction, executor: &dyn ConfidentialExecutor) -> Result<Verified, TxError> {
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
        if let Some(b) = &tx.bundle {
            if b.envelopes.iter().any(|e| e.len() > MAX_ENVELOPE_BYTES) {
                return Err(TxError::EnvelopeTooLarge);
            }
            if b.proof.len() > self.max_proof_bytes {
                return Err(TxError::ProofTooLarge);
            }
        }
        match &tx.action {
            Action::Mint { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::Deploy { words, .. } if words.len() > self.max_program_words => {
                return Err(TxError::ProgramTooLarge)
            }
            Action::Deploy { public, .. } if public.len() > self.max_program_public_words => {
                return Err(TxError::ProgramPublicTooLarge)
            }
            Action::Call { proof, .. } if proof.len() > self.max_proof_bytes => return Err(TxError::ProofTooLarge),
            Action::Withdraw { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeAttest { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeAttest { attestation, .. } if attestation.len() > gas::MAX_ATTESTATION_BYTES => {
                return Err(TxError::AttestationTooLarge)
            }
            // The `Aggregate` action's caps (spec §3.1): the per-field ones every action gets,
            // then the composite wire cap over the transaction's encoding.
            Action::Aggregate { envelope, .. } if envelope.len() > MAX_ENVELOPE_BYTES => {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::Aggregate { proof, .. } if proof.len() > self.max_proof_bytes => return Err(TxError::ProofTooLarge),
            Action::Aggregate { .. } if encoded_len > self.max_aggregate_bytes() => {
                return Err(TxError::AggregateTooLarge { size: encoded_len, max: self.max_aggregate_bytes() })
            }
            // A burn's second bundle is a bundle: the caps above it are the caps every bundle
            // gets, applied here because `tx.bundle` is only the fee bundle.
            Action::BridgeBurn { asset_bundle, .. }
                if asset_bundle.envelopes.iter().any(|e| e.len() > MAX_ENVELOPE_BYTES) =>
            {
                return Err(TxError::EnvelopeTooLarge)
            }
            Action::BridgeBurn { asset_bundle, .. } if asset_bundle.proof.len() > self.max_proof_bytes => {
                return Err(TxError::ProofTooLarge)
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
            // The transaction's own bundle is always the RAND fee bundle and never burns:
            // value leaves the pool through a `BridgeBurn`'s *asset* bundle, which carries the
            // asset and the burn and is admitted by [`bridge_notes`] through the same two
            // helpers below.
            if b.asset != 0 {
                return Err(TxError::UnsupportedAsset(b.asset));
            }
            // Phase S2: `Bond` is the one action whose bundle may burn, and it must burn exactly
            // what it bonds — that is how value leaves the pool and becomes public stake.
            match &tx.action {
                Action::Bond { amount, .. } if b.burn != *amount => {
                    return Err(StakingError::BurnMismatch { burn: b.burn, amount: *amount }.into())
                }
                Action::Bond { .. } => {}
                // Block aggregation: `RegisterAggregator` is the one aggregation action whose
                // bundle burns, and it must burn exactly the genesis bond (spec §2.2) — the
                // `Bond` arm's rule, one register over.
                Action::RegisterAggregator { .. } => {
                    aggregation::check_burn(self, b.burn)?;
                }
                _ if b.burn != 0 => return Err(TxError::UnsupportedBurn(b.burn)),
                _ => {}
            }
            let min = gas::fee_floor(&tx.action);
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
        if let Action::Withdraw { time, .. } | Action::WithdrawAggregator { time, .. } = &tx.action {
            self.check_time(*time)?;
        }
        // 7. action-specific cheap checks
        let mut verified = Verified::default();
        let mut call_record = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, envelope, amount, minter, signature } => {
                if !self.faucet {
                    return Err(TxError::FaucetDisabled);
                }
                if *amount > FAUCET_MAX_UNITS {
                    return Err(TxError::MintTooLarge { amount: *amount, cap: FAUCET_MAX_UNITS });
                }
                let addr = minter.address();
                if !self.validators.contains_key(&addr) {
                    return Err(TxError::MinterNotValidator(addr));
                }
                let signing_hash = Transaction::mint_signing_hash(tx.chain_id, cm, envelope, *amount);
                if !minter.verify(signing_hash.as_bytes(), signature) {
                    return Err(TxError::BadMintSignature);
                }
                if self.commitments.contains(cm) {
                    return Err(TxError::CommitmentExists(*cm));
                }
            }
            Action::Deploy { base_pc, words, .. } => {
                if !self.confidential {
                    return Err(TxError::ConfidentialDisabled);
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
            a @ (Action::Bond { .. } | Action::Unbond { .. } | Action::Withdraw { .. }) => {
                staking::validate(self, tx, a, executor)?;
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
            Action::Aggregate { .. } => {
                // The covered bundles' records live in node storage, which the ledger cannot
                // see: admission and application of an aggregate run through
                // [`Ledger::validate_aggregate`] / [`Ledger::apply_aggregate`], and a proposer's
                // trial apply takes this arm until Task 6 wires the covered pre-pass into
                // `apply_block`.
                return Err(TxError::AggregateNeedsCovered);
            }
        }
        // 8-9. the bundle's digest, then its proof
        if let Some(b) = bundle {
            self.check_bundle_proof(b, executor)?;
        }
        // 10. the call's own proof, then its fee: the tier's, and the byte term for proof and
        // envelope bytes past the free allowance (spec §7)
        if let (Some(record), Action::Call { proof, input_envelope, .. }) = (call_record, &tx.action) {
            let outcome = executor.verify_call(record, proof).map_err(TxError::InvalidProof)?;
            let bytes = gas::call_bytes(proof, input_envelope.as_ref());
            let min = gas::BUNDLE_BASE + gas::call_fee(outcome.tier, bytes);
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
        let verified = self.validate_inner(tx, executor)?;
        if let Some(b) = &tx.bundle {
            // This method is not atomic on its own: the action step below runs after these
            // writes and can still fail (S2's `staking::apply`, S3's `bridge_notes::apply`),
            // which would leave a half-applied bundle behind. What makes a rejected
            // transaction leave the ledger byte-identical is the caller: `apply_transactions`
            // applies every transaction to a scratch clone and only assigns it back once the
            // whole block succeeded. Call `apply_tx` on a ledger you are willing to discard.
            // In practice the proposer is always in the register — `apply_block` rejects a
            // block whose proposer is not, and `HotStuff::propose` runs only when this node
            // is the leader.
            let entry = self.validators.get(proposer).ok_or(TxError::UnknownProposer(*proposer))?;
            // The fee split (block aggregation, spec §5.2): on an aggregating chain the
            // proposer keeps exactly the floor and the excess is bucketed against this
            // transaction's hash — an `Aggregate` may still cover it — where an ungated chain
            // keeps the whole fee to the proposer, byte-for-byte today's accounting. The
            // counter moves with what the proposer actually keeps: the floor now, an expired
            // excess at the sweep (`sweep_expired_excesses`), never the bucketed part.
            let kept = if self.aggregation.is_some() { gas::BUNDLE_BASE.min(b.fee) } else { b.fee };
            let rewards = entry.rewards.checked_add(kept).ok_or(TxError::Overflow)?;
            // Both halves of what this bundle takes out of the pool (see [`supply`]): the fee
            // becomes the proposer's `rewards` below, and the burn becomes `stake` in the
            // `Bond` arm — which is why they are counted here, where every bundle passes,
            // rather than in the arms that receive them.
            self.supply.fees_paid = self.supply.fees_paid.checked_add(kept).ok_or(TxError::Overflow)?;
            self.supply.burned = self.supply.burned.checked_add(b.burn).ok_or(TxError::Overflow)?;
            // S3 factored the note writes out so a `BridgeBurn`'s asset bundle can reuse them;
            // the counters stay here, on the *fee* bundle's path only, because a bridged asset's
            // burn is not RAND and has no place in the RAND audit.
            self.apply_bundle_notes(b, executor);
            self.validators.get_mut(proposer).expect("looked up above").rewards = rewards;
            if self.aggregation.is_some() {
                let until = self.height.checked_add(self.aggregation().expect("just checked").window).ok_or(TxError::Overflow)?;
                // Every bundle is recorded, excess or not: the bucket doubles as the ledger's
                // coverable set (the pre-v0.1 review's H1) — an aggregate may name a cover only
                // while its entry stands, and the entry leaves at the covering aggregate or at
                // the sweep, never to return. The key is the transaction hash an aggregate's
                // covers name; a pruned bundle's marker form hashes to the same value
                // (`Transaction::hash` takes the proof by digest), so the sealed-sync replay
                // keys byte-identically without consulting the side table.
                self.bucket_excess(tx.hash(), b.fee - gas::BUNDLE_BASE, *proposer, until);
            }
        }
        let mut receipt = None;
        match &tx.action {
            Action::None => {}
            Action::Mint { cm, amount, .. } => {
                self.supply.faucet_minted =
                    self.supply.faucet_minted.checked_add(*amount).ok_or(TxError::Overflow)?;
                self.commitments.insert(*cm);
                self.tree.append(*cm, executor);
            }
            Action::Deploy { base_pc, words, public } => {
                let id = program_id_with_public(*base_pc, words, public);
                if !self.programs.contains_key(&id) {
                    let code_hash = executor.check_program(*base_pc, words).map_err(TxError::BadProgram)?;
                    // Hashed once, here: a call compares its proof's `H_PUB` with this and never
                    // re-hashes the words (spec §5).
                    let public_digest = (!public.is_empty()).then(|| executor.public_digest(public));
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
            Action::Call { program, input_envelope, .. } => {
                let o = verified.call.expect("validate_inner returns the outcome for calls");
                receipt = Some(CallReceiptData {
                    program: *program,
                    tier: o.tier,
                    outputs: o.outputs,
                    h_in: o.h_in,
                    // The digest the proof was just checked against (`verify_call`).
                    h_pub: self.programs.get(program).and_then(|r| r.public_digest),
                    input_envelope: input_envelope.clone(),
                });
            }
            a @ (Action::Bond { .. } | Action::Unbond { .. } | Action::Withdraw { .. }) => {
                // The proposer is passed in because a `Withdraw` pays it the bundle base out of
                // the amount it withdraws — the one fee that does not come from a bundle.
                staking::apply(self, tx, a, proposer, executor)?;
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
        self.apply_transactions_with_covered(txs, proposer, &BTreeMap::new(), executor)
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
        self.apply_transactions_for_sync(txs, proposer, covered, &[], executor)
    }

    /// `apply_transactions_with_covered` with the sealed form's side table (spec §7): the
    /// pruned bundles the block carries in marker form, keyed by proof hash for
    /// `check_bundle_proof`'s membership and binding checks. Empty on every path but
    /// sealed-form sync.
    pub fn apply_transactions_for_sync(
        &mut self,
        txs: &[Transaction],
        proposer: &Address,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        pruned: &[crate::consensus::PrunedBundle],
        executor: &dyn ConfidentialExecutor,
    ) -> Result<Vec<(usize, CallReceiptData)>, BlockError> {
        let mut scratch = self.clone();
        // The deposits reported after a block are exactly that block's (see `Deposit`).
        scratch.deposits.clear();
        scratch.pruned_side =
            pruned.iter().map(|p| (p.proof_hash, (p.tx_hash, p.public_values.clone()))).collect();
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
                scratch.apply_tx(tx, proposer, executor).map_err(|error| BlockError::InvalidTx { index, error })?
            {
                receipts.push((index, r));
            }
        }
        *self = scratch;
        Ok(receipts)
    }

    /// Full block application: proposer signature, tx root, every tx, the block-end anchor, and
    /// the resulting state root must match the header. Ledger unchanged on error. Returns the
    /// receipts of the block's calls.
    pub fn apply_block(&mut self, block: &Block, executor: &dyn ConfidentialExecutor) -> Result<Vec<CallReceipt>, BlockError> {
        self.apply_block_with_covered(block, &BTreeMap::new(), executor)
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
        self.apply_block_for_sync(block, covered, &[], executor)
    }

    /// `apply_block_with_covered` with the sealed form's side table (spec §7): the tx root is
    /// checked over the transactions as served — a marker-form transaction hashes to its raw
    /// hash (`Transaction::hash` takes the proof by digest), so the certified root binds every
    /// byte of it but the proof — the table's attested raw hash must agree with that, and
    /// `check_bundle_proof` runs its membership and digest-binding checks against the table.
    pub fn apply_block_for_sync(
        &mut self,
        block: &Block,
        covered: &BTreeMap<usize, Vec<crate::types::CoveredBundle>>,
        pruned: &[crate::consensus::PrunedBundle],
        executor: &dyn ConfidentialExecutor,
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
        if !block.verify_signature() {
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
        let mut scratch = self.clone();
        scratch.set_height(block.height());
        scratch.set_timestamp_ms(block.header.timestamp_ms);
        let data = scratch.apply_transactions_for_sync(&block.transactions, &proposer, covered, pruned, executor)?;
        scratch.close_block(block.height(), &proposer);
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
    pub fn close_block(&mut self, height: u64, proposer: &Address) {
        self.sweep_expired_excesses(height, proposer);
        self.record_anchor(height);
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
    /// The three merkle roots `state_root` binds, in order: nullifiers, validators, programs.
    /// Split out so a state-root mismatch can name the component it diverges in.
    fn state_root_leaves(&self) -> (Hash, Hash, Hash) {
        let nf_leaves: Vec<Hash> = self
            .nullifiers
            .iter()
            .map(|nf| Hash::digest_domain(b"rand-nullifier-leaf", &word8_to_bytes(nf)))
            .collect();
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
                Hash::digest_domain(b"rand-validator-leaf-2", &buf)
            })
            .collect();
        let prog_leaves: Vec<Hash> =
            self.programs.keys().map(|id| Hash::digest_domain(b"rand-program-leaf", id.as_bytes())).collect();
        (merkle_root(&nf_leaves), merkle_root(&val_leaves), merkle_root(&prog_leaves))
    }

    /// The component roots of [`Ledger::state_root`], for logging a mismatch: tree, nullifiers,
    /// validators, programs, aggregators. A divergence between two ledgers names itself here.
    pub fn debug_state_root_components(&self) -> String {
        let (nf, val, prog) = self.state_root_leaves();
        let agg = if self.aggregation.is_some() {
            format!("{:?}", aggregation::aggregators_root(&self.aggregators))
        } else {
            "none".into()
        };
        format!("tree {:?} nullifiers {nf:?} validators {val:?} programs {prog:?} aggregators {agg}", self.tree.root())
    }

    pub fn state_root(&self) -> Hash {
        let (nf_root, val_root, prog_root) = self.state_root_leaves();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&word8_to_bytes(&self.tree.root()));
        buf.extend_from_slice(nf_root.as_bytes());
        buf.extend_from_slice(val_root.as_bytes());
        buf.extend_from_slice(prog_root.as_bytes());
        if let Some(bridge) = &self.bridge {
            buf.extend_from_slice(bridge.root().as_bytes());
        }
        if self.aggregation.is_some() {
            buf.extend_from_slice(aggregation::aggregators_root(&self.aggregators).as_bytes());
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
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::program::program_id;
    use crate::crypto::Keypair;
    use crate::notes::{Envelope, ShieldedAddress};
    use crate::types::{BlockHeader, QuorumCertificate};

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
            },
        )
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

    /// A bundle whose stub proof publishes exactly the digest the ledger recomputes.
    fn bundle(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2], fee: u64) -> Bundle {
        let mut b = Bundle {
            anchor: l.root(),
            nullifiers: nfs,
            commitments: cms,
            fee,
            burn: 0,
            asset: 0,
            time: l.height as u32,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d);
        b
    }

    fn tx(l: &Ledger, nfs: [Word8; 2], cms: [Word8; 2]) -> Transaction {
        Transaction::shielded(7, bundle(l, nfs, cms, gas::BUNDLE_BASE), Action::None)
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
        Block::sign(header, txs, key)
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
        assert_eq!(l.next_index(), 2);
        assert_eq!(l.validators()[&a.address()].rewards, gas::BUNDLE_BASE);
        // replay: both nullifiers now spent
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::Spent([1; 8])));
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
        let t = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE - 1),
            Action::None,
        );
        assert_eq!(
            l.validate(&t, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 })
        );
        // asset / burn unsupported in S1
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().asset = 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedAsset(1)));
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().burn = 5;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnsupportedBurn(5)));
        // unknown anchor
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().anchor = [9; 8];
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownAnchor));
        // time window: future and too old. The height is chosen past the window so both edges
        // exist; the edges themselves are expressed in TIME_WINDOW, never in its current value.
        const H: u64 = TIME_WINDOW + 100;
        let oldest = (H - TIME_WINDOW) as u32;
        l.set_height(H);
        l.record_anchor(H);
        let mut t = tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]]);
        t.bundle.as_mut().unwrap().time = H as u32 + 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: H as u32 + 1, height: H }));
        t.bundle.as_mut().unwrap().time = oldest - 1;
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::TimeOutOfWindow { time: oldest - 1, height: H }));
        t.bundle.as_mut().unwrap().time = oldest; // exactly height - TIME_WINDOW is allowed
        let mut b = t.bundle.clone().unwrap();
        b.proof = StubExecutor::make_bundle_proof(&HC, &StubExecutor.bundle_digest(&b.digest_input()));
        t.bundle = Some(b);
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
        t.bundle.as_mut().unwrap().proof = StubExecutor::make_bundle_proof(&[12; 8], &d);
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
            Err(TxError::UnknownAnchor)
        );
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

    #[test]
    fn mint_needs_the_faucet_a_validator_signature_and_no_bundle() {
        let mut l = ledger();
        let (a, _) = keys();
        let stranger = Keypair::from_seed([9; 32]).unwrap();
        let t = Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS, &a);
        assert_eq!(l.validate(&t, &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&Transaction::mint(7, [5; 8], env(), FAUCET_MAX_UNITS + 1, &a), &StubExecutor),
            Err(TxError::MintTooLarge { amount: FAUCET_MAX_UNITS + 1, cap: FAUCET_MAX_UNITS })
        );
        assert_eq!(
            l.validate(&Transaction::mint(7, [5; 8], env(), 1, &stranger), &StubExecutor),
            Err(TxError::MinterNotValidator(stranger.address()))
        );
        let mut forged = Transaction::mint(7, [5; 8], env(), 1, &a);
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
        assert!(l.has_commitment(&[5; 8]));
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::CommitmentExists([5; 8])));
    }

    #[test]
    fn deploy_and_call_ride_on_bundles_and_pay_their_floors() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let under =
            Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), deploy.clone());
        assert_eq!(
            l.validate(&under, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: gas::BUNDLE_BASE })
        );
        let ok = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy.clone(),
        );
        l.apply_tx(&ok, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = program_id(0, &words);
        assert!(l.program(&id).is_some());
        let proof = StubExecutor::make_proof(&id, 12, [1, 2, 3, 4, 5, 6, 7, 8]);
        let call = Action::Call { program: id, proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let t = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], fee), call.clone());
        let r = l.apply_tx(&t, &a.address(), &StubExecutor).unwrap().unwrap();
        l.record_anchor(l.height());
        assert_eq!(r.outputs, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.tier, 12);
        let cheap = Transaction::shielded(7, bundle(&l, [[9; 8], [10; 8]], [[11; 8], [12; 8]], fee - 1), call.clone());
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: fee, fee: fee - 1 }));
        l.set_confidential(false);
        // A fresh transaction: `t`'s nullifiers are spent by now, and `Spent` would fire first.
        let disabled = Transaction::shielded(7, bundle(&l, [[13; 8], [14; 8]], [[15; 8], [16; 8]], fee), call);
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
                    Transaction::shielded(7, b, action)
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
        };
        check(208, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES)), Ok(()));
        check(212, attest(vec![1; 32], fat(MAX_ENVELOPE_BYTES + 1)), Err(TxError::EnvelopeTooLarge));
        check(216, attest(vec![1; gas::MAX_ATTESTATION_BYTES], env()), Ok(()));
        check(220, attest(vec![1; gas::MAX_ATTESTATION_BYTES + 1], env()), Err(TxError::AttestationTooLarge));

        // A burn's asset bundle gets the caps every bundle gets: `tx.bundle` is only the fee one.
        let burn = |envelopes: [Envelope; 2], proof: Vec<u8>| {
            let mut asset_bundle = bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], 0);
            asset_bundle.envelopes = envelopes;
            asset_bundle.proof = proof;
            Action::BridgeBurn { asset_bundle, asset: 1, amount: 400, relayer_fee: 100, to_chain: 2, to: [9; 32] }
        };
        check(224, burn([fat(MAX_ENVELOPE_BYTES), env()], vec![]), Ok(()));
        check(228, burn([env(), fat(MAX_ENVELOPE_BYTES + 1)], vec![]), Err(TxError::EnvelopeTooLarge));
        check(232, burn([env(), env()], vec![0; gas::MAX_PROOF_BYTES]), Ok(()));
        check(236, burn([env(), env()], vec![0; gas::MAX_PROOF_BYTES + 1]), Err(TxError::ProofTooLarge));
    }

    /// The one rule of the call-input envelope the chain does enforce, through a real ledger.
    #[test]
    fn a_call_envelope_passes_when_absent_or_small_and_is_capped() {
        let mut l = ledger();
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy,
        );
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
            assert_eq!(l.validate(&Transaction::shielded(7, b, action), &StubExecutor), expect, "n={n}");
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
        let d = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)),
            deploy,
        );
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
        let t1 = Transaction::shielded(7, bundle(&l, [[10; 8], [11; 8]], [[12; 8], [13; 8]], fee), sealed);
        let t2 = Transaction::shielded(7, bundle(&l, [[20; 8], [21; 8]], [[22; 8], [23; 8]], fee), bare);
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
        let t = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), big);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::ProgramTooLarge));
        // A call naming a program nobody deployed.
        let ghost = Hash::digest(b"never deployed");
        let unknown = Action::Call { program: ghost, proof: Vec::new(), input_envelope: None };
        let t = Transaction::shielded(
            7,
            bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&unknown)),
            unknown,
        );
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::UnknownProgram(ghost)));
        // Deploy two programs, then call one with the other's proof.
        let words = vec![0x13u32; 4];
        let other = vec![0x73u32; 4];
        for (n, code) in [(0u32, &words), (1, &other)] {
            let deploy = Action::Deploy { base_pc: 0, words: code.clone(), public: vec![] };
            let d = Transaction::shielded(
                7,
                bundle(&l, [[10 + n; 8], [20 + n; 8]], [[30 + n; 8], [40 + n; 8]], gas::fee_floor(&deploy)),
                deploy,
            );
            l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
            l.record_anchor(l.height());
        }
        let (id, other_id) = (program_id(0, &words), program_id(0, &other));
        let wrong_proof = StubExecutor::make_proof(&other_id, 12, [0; 8]);
        let call = Action::Call { program: id, proof: wrong_proof, input_envelope: None };
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let t = Transaction::shielded(7, bundle(&l, [[50; 8], [51; 8]], [[52; 8], [53; 8]], fee), call);
        assert_eq!(l.validate(&t, &StubExecutor), Err(TxError::InvalidProof(ConfidentialError::WrongProgram)));
        // Redeploying the same code is a no-op: the record keeps its original height.
        assert_eq!(l.program(&id).unwrap().deployed_at, 1);
        l.set_height(9);
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let again = Transaction::shielded(
            7,
            bundle(&l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], gas::fee_floor(&deploy)),
            deploy,
        );
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
        let first = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], floor), deploy.clone());
        l.apply_tx(&first, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        let id = crate::program::program_id_with_public(0, &words, &public);
        let before = l.program(&id).cloned().expect("deployed");
        assert_eq!(before.deployed_at, 1);

        l.set_height(9);
        // The redeploy is refused below its floor like any deploy: the public words are paid for again.
        let cheap = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], floor - 1), deploy.clone());
        assert_eq!(l.validate(&cheap, &StubExecutor), Err(TxError::FeeTooLow { min: floor, fee: floor - 1 }));
        let again = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], floor), deploy);
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
        let under = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], code_only), deploy.clone());
        assert_eq!(
            l.validate(&under, &StubExecutor),
            Err(TxError::FeeTooLow { min: gas::fee_floor(&deploy), fee: code_only }),
            "the public words are paid for"
        );
        let ok =
            Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy);
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
        let t = Transaction::shielded(7, bundle(&l, [[5; 8], [6; 8]], [[7; 8], [8; 8]], gas::fee_floor(&plain)), plain);
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
            Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action)
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
        let t = Transaction::shielded(7, bundle(&raised, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::BUNDLE_BASE), action);
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
            let t = Transaction::shielded(7, bundle(&l, [n0, n1], [c0, c1], gas::fee_floor(&d)), d);
            l.apply_tx(&t, &a.address(), &StubExecutor).unwrap();
            l.record_anchor(l.height());
        }
        let id = crate::program::program_id_with_public(0, &words, &public);
        let plain = program_id(0, &words);
        let fee = gas::BUNDLE_BASE + gas::call_fee(12, 0);
        let mut call = |l: &mut Ledger, program: ProgramId, proof: Vec<u8>, apply: bool| {
            let [n0, n1, c0, c1] = next();
            let t = Transaction::shielded(
                7,
                bundle(l, [n0, n1], [c0, c1], fee),
                Action::Call { program, proof, input_envelope: None },
            );
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
            Transaction::shielded(7, bundle(l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&action)), action)
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
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            StubExecutor.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &crate::notes::BundleDigestInput) -> Word8 {
            StubExecutor.bundle_digest(input)
        }
        fn bundle_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            StubExecutor.bundle_proof_digest(proof)
        }
        fn verify_bundle(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<(), ConfidentialError> {
            StubExecutor.verify_bundle(hc_bundle, proof)
        }
        fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            StubExecutor.aggregate_program_digest(shape)
        }
        fn verify_aggregate(
            &self,
            shape: &crate::types::DeclaredShape,
            covered: &[crate::types::CoveredBundle],
            proof: &[u8],
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            StubExecutor.verify_aggregate(shape, covered, proof)
        }
    }

    /// A ledger with the four-word test program deployed, and its id.
    fn ledger_with_program(configure: impl FnOnce(&mut Ledger)) -> (Ledger, ProgramId) {
        let mut l = ledger();
        configure(&mut l);
        let (a, _) = keys();
        let words = vec![0x13u32; 4];
        let deploy = Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] };
        let d = Transaction::shielded(7, bundle(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], gas::fee_floor(&deploy)), deploy);
        l.apply_tx(&d, &a.address(), &StubExecutor).unwrap();
        l.record_anchor(l.height());
        (l, program_id(0, &words))
    }

    /// A call to `id` with `proof` and no envelope, paying `fee`, on nullifiers derived from `n`.
    fn call_tx(l: &Ledger, n: u32, id: ProgramId, proof: Vec<u8>, fee: u64) -> Transaction {
        let b = bundle(l, [[n; 8], [n + 1; 8]], [[n + 2; 8], [n + 3; 8]], fee);
        Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: None })
    }

    /// What a call carrying `bytes` of proof and envelope pays: the bundle base and `call_fee`.
    fn fee_for(bytes: usize) -> u64 {
        gas::BUNDLE_BASE + gas::call_fee(12, bytes)
    }

    /// Spec §4, step 1: every proof cap — the fee bundle's, a call's, a burn's asset bundle's —
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
        let size_error = |r: &Result<(), TxError>| matches!(r, Err(TxError::ProofTooLarge));

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
            Transaction::shielded(7, b, Action::None)
        };
        assert_eq!(default.validate(&fat_bundle(&default), &StubExecutor), Err(TxError::ProofTooLarge));
        let got = raised.validate(&fat_bundle(&raised), &StubExecutor);
        assert!(!size_error(&got), "the raised cap admits the bundle's size: {got:?}");

        // A burn's asset bundle.
        let burn = |l: &Ledger| {
            let mut asset_bundle = bundle(l, [[60; 8], [61; 8]], [[62; 8], [63; 8]], 0);
            asset_bundle.proof = vec![0; over];
            let action =
                Action::BridgeBurn { asset_bundle, asset: 1, amount: 400, relayer_fee: 100, to_chain: 2, to: [9; 32] };
            let b = bundle(l, [[64; 8], [65; 8]], [[66; 8], [67; 8]], gas::fee_floor(&action));
            Transaction::shielded(7, b, action)
        };
        assert_eq!(default.validate(&burn(&default), &StubExecutor), Err(TxError::ProofTooLarge));
        let got = raised.validate(&burn(&raised), &StubExecutor);
        assert!(!size_error(&got), "the raised cap admits the asset bundle's size: {got:?}");
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
            Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: Some(envelope(total)) })
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
            default.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub),
            Err(BlockError::TooLarge)
        );
        let receipts = raised.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tx, t.hash());
        assert_eq!(receipts[0].outputs, [9; 8]);

        // One byte under the block's size, the raised ledger refuses the same block.
        let (mut tight, _) = ledger_with_program(|l| {
            limits(l);
            l.set_max_block_bytes(t.encoded_len() - 1);
        });
        assert_eq!(tight.apply_block_for_sync(&block, &BTreeMap::new(), &[], &PaddedStub), Err(BlockError::TooLarge));
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
        let t = Transaction::shielded(7, b, Action::Call { program: id, proof, input_envelope: Some(envelope) });
        assert_eq!(le.validate(&t, &PaddedStub), Err(TxError::FeeTooLow { min: today + gas::CALL_PER_KIB, fee: today }));
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
            l.commitments_set().clone(),
            l.nullifiers().clone(),
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
            BridgeConfig { emitter: [1; 32], guardians: vec![[2; 20]], emitters: BTreeMap::from([(2u16, [9u8; 32])]) };
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
            Block::sign(header, Vec::new(), &a)
        };

        let config =
            BridgeConfig { emitter: [1; 32], guardians: vec![[2; 20]], emitters: BTreeMap::from([(2u16, [9u8; 32])]) };
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
        assert_eq!(scratch.next_index(), 4, "four new leaves in tree order");
        assert_eq!(scratch.validators()[&a.address()].rewards, 2 * gas::BUNDLE_BASE);
    }
}
