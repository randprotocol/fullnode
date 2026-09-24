//! Genesis configuration and derivation of the genesis block + ledger.

use crate::bridge::state::hex_bytes32;
use crate::bridge::{BridgeCommit, BridgeConfig, BridgeState, GuardianKey, CHAIN_RAND, GOVERNANCE_EMITTER};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, Hash, PublicKey, Signature};
use crate::gas;
use crate::ledger::staking::MIN_STAKE;
use crate::ledger::tokens::{
    check_metadata, Backing, MintAuthority, TokenRegistry, BRIDGE_DECIMALS, MAX_BACKINGS, MAX_BACKING_DECIMALS,
};
use crate::ledger::{Ledger, ValidatorEntry};
use crate::notes::{word8_from_hex, word8_to_bytes, Envelope, ShieldedAddress, Word8};
use crate::types::{Block, BlockHeader, QuorumCertificate, ValidatorSet, SigningDomain};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded Dilithium2 public key.
    pub public_key: PublicKey,
    /// The register narrows this to a `u64` (spec §8), so a stake above `u64::MAX` is refused
    /// rather than silently truncated. The field itself stays `u128` to match `ValidatorSet`.
    pub stake: u128,
    /// Phase S2: the shielded address (`rand1…`) this validator's rewards and unbonded stake
    /// are paid to. Required, and part of the genesis binding: it is register state, so two
    /// nodes that disagree about it compute different state roots from the first block on.
    pub payout: String,
}

/// The four envelope parts as hex text, so a genesis file stays readable JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHex {
    pub kem_ct: String,
    pub to_receiver: String,
    pub to_sender: String,
    pub body: String,
}

impl EnvelopeHex {
    pub fn from_envelope(e: &Envelope) -> EnvelopeHex {
        EnvelopeHex {
            kem_ct: hex::encode(&e.kem_ct),
            to_receiver: hex::encode(&e.to_receiver),
            to_sender: hex::encode(&e.to_sender),
            body: hex::encode(&e.body),
        }
    }

    pub fn to_envelope(&self) -> Result<Envelope, GenesisError> {
        let part = |s: &String| hex::decode(s).map_err(|_| GenesisError::BadNote(s.clone()));
        Ok(Envelope {
            kem_ct: part(&self.kem_ct)?,
            to_receiver: part(&self.to_receiver)?,
            to_sender: part(&self.to_sender)?,
            body: part(&self.body)?,
        })
    }
}

/// What an alloc note's commitment opens to, beside the `amount` the note already declares: the
/// owner's `pk`, the note's `time` word and its blinding `r` (64 hex characters each for the two
/// `Word8`s). `from` is the zero word and `asset` is 0, exactly as every other note the *chain*
/// computes — the faucet mint (`ledger::mint_commitment`), a withdraw, an aggregate payout — so
/// neither is written down here: a genesis note is a RAND note or it is not a genesis note.
///
/// Core I-2. Without it a `cm` is opaque: nothing ties it to `(asset = 0, amount)`, so a genesis
/// author could put a note committing to `(amount, asset = 1)` in `alloc` and hand itself
/// spendable zUSD that no backing ever locked — fungible with the real thing, `BridgeBurn`-able
/// against any backing up to its real `locked`, and invisible to the supply audit, which counts
/// `amount` as RAND. This is POOL-1's rule ("a validator's signature is not enough — the ledger
/// derives the commitment itself") applied to the one note-creating path that had no derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisOpening {
    /// The owner's `pk`, 64 hex characters.
    pub pk: String,
    /// The note's `time` word. Genesis notes are stamped 0 by `rand-node genesis`; any value
    /// hashes fine, so this records what the file actually used.
    pub time: u32,
    /// The commitment randomness, 64 hex characters.
    pub r: String,
}

/// A deposit note the chain starts with (spec §8): its commitment, the envelope that opens it,
/// and the amount it carries. The amount is not chain state — the note's value lives inside the
/// commitment — but it is part of the genesis binding so every node agrees on the initial supply.
///
/// `opening` is **required on any chain with a `tokens` section** (core I-2, see
/// [`GenesisOpening`]) and optional otherwise, so every genesis file cut before it — chains ≤ 13
/// and their pinned hashes — parses and builds byte-for-byte as before. It is deliberately *not*
/// in the genesis commitment: the commitment already covers `cm` and `amount`, and an opening
/// that does not reproduce `cm` never builds a chain at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisNote {
    /// 64 hex characters.
    pub cm: String,
    pub envelope: EnvelopeHex,
    pub amount: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opening: Option<GenesisOpening>,
}

/// One source-chain coin behind a listed token: the chain id, the token address there (64 hex
/// characters in the genesis file), and that source token's own decimal count (bridge-06/audit
/// O-5) — never [`BRIDGE_DECIMALS`], which is what the *bridged token* is normalized to on this
/// chain: USDT is 6 decimals on Ethereum and 18 on BSC, both backing the same eight-decimal zUSD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisBacking {
    pub chain: u16,
    #[serde(with = "hex_bytes32")]
    pub token: [u8; 32],
    pub decimals: u8,
}

/// One token a `tokens` section lists at genesis: always a `Bridge`-authority token (a native
/// token at genesis has no note to mint into, so a creator registers one after launch — a later
/// task's `Action::RegisterToken`). The *token's* decimals are always [`BRIDGE_DECIMALS`]; that is
/// not [`crate::ledger::tokens::TokenRegistry::register`]'s rule to enforce (it does not tie a
/// `Bridge` authority to eight decimals), so this listing code passes the constant itself. Each
/// backing's own decimals — the source token's — are [`GenesisBacking::decimals`].
///
/// One token, many coins (spec §12): chain 14 lists a single zUSD backed by USDT and USDC on
/// four source chains at once, so a listing carries a *list* of `(chain, token)` pairs — one to
/// [`crate::ledger::tokens::MAX_BACKINGS`], each pair listed at most once across the whole
/// section, and each on a chain the `bridge` section registers an emitter for.
///
/// `salt` is what makes the registered [`crate::bridge::AssetId`] unique: a bridged token's id is
/// over its registration fields (`tokens::bridged_asset_id` — name, symbol, the eight decimals,
/// this salt) and no longer over a `(chain, token)` pair, because there is no single pair to hash
/// any more and the backings grow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisToken {
    pub name: String,
    pub symbol: String,
    /// 64 hex characters.
    #[serde(with = "hex_bytes32")]
    pub salt: [u8; 32],
    pub backings: Vec<GenesisBacking>,
}

/// The `tokens` genesis section (spec's RPL token standard): the registration fee every later
/// `Action::RegisterToken` must pay at least, and the tokens genesis itself lists — bridged
/// tokens only, registered before any transaction runs.
///
/// `mint_cap_per_day` (bridge hardening B1) is the most one backing of any bridged token may mint
/// in one UTC day of the block timestamp, in the token's own eight-decimal units — chain 14's is
/// `100_000 × 10^8`. It applies to the tokens listed here and to every bridged token registered
/// later (`Action::RegisterBridgedToken`). A bridged chain must set it above zero; a chain without
/// a bridge has no bridged token for it to bound.
///
/// `deny_unknown_fields` like its children (core M-4 / node M5): both of the fields below are
/// `#[serde(default)]`, so a misspelt `tokens` key used to cut a chain with an empty token list
/// and a misspelt `mint_cap_per_day` a chain with a zero cap — the second is caught on a bridged
/// chain (`validate` refuses a zero cap there), the first is not caught anywhere. It is **not**
/// on [`Genesis`]: older genesis files must keep parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokensConfig {
    pub registration_fee: u64,
    #[serde(default)]
    pub mint_cap_per_day: u64,
    #[serde(default)]
    pub tokens: Vec<GenesisToken>,
}

/// The plain-bytes twin of [`TokensConfig`], used for the genesis commitment — exactly what
/// [`BridgeCommit`] is to [`BridgeConfig`], and for the same reason.
///
/// [`GenesisBacking::token`] and [`GenesisToken::salt`] serialize as 64 hex characters so the
/// genesis file is editable, and `bincode` of that commits to the hex *string*: two files whose
/// token bytes differ only in the case of their hex would commit differently, and — worse — the
/// bytes the commitment covers would not be the bytes the chain runs on. The genesis hash
/// commits to this struct instead, whose salt and token addresses are the 32 bytes themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensCommit {
    pub registration_fee: u64,
    /// B1's per-backing daily mint cap, committed like the fee: two files that differ only in it
    /// must build different chains.
    pub mint_cap_per_day: u64,
    /// `(name, symbol, salt, backings)` per listed token, in file order — which is registration
    /// order, which is index order — each backing as its `(chain, token, decimals)` triple, in
    /// file order too, since the order a token's coins are listed in is the order its `backings`
    /// vector holds them in and so is part of the state the leaf hashes. `decimals` rides beside
    /// the pair so a backing's declared source precision is committed exactly like its chain and
    /// address are — a genesis file that changed only a backing's decimals must build a different
    /// chain.
    pub tokens: Vec<(String, String, [u8; 32], Vec<(u16, [u8; 32], u8)>)>,
}

impl From<&TokensConfig> for TokensCommit {
    /// Destructured on purpose, like [`BridgeCommit::from`]: a new [`TokensConfig`],
    /// [`GenesisToken`] or [`GenesisBacking`] field must not silently fall out of the genesis
    /// commitment — it has to break this conversion.
    fn from(cfg: &TokensConfig) -> TokensCommit {
        let TokensConfig { registration_fee, mint_cap_per_day, tokens } = cfg;
        TokensCommit {
            registration_fee: *registration_fee,
            mint_cap_per_day: *mint_cap_per_day,
            tokens: tokens
                .iter()
                .map(|t| {
                    let GenesisToken { name, symbol, salt, backings } = t;
                    let backings = backings
                        .iter()
                        .map(|b| {
                            let GenesisBacking { chain, token, decimals } = b;
                            (*chain, *token, *decimals)
                        })
                        .collect();
                    (name.clone(), symbol.clone(), *salt, backings)
                })
                .collect(),
        }
    }
}

/// The `staking` genesis section (audit v4, STAKE-2), defined beside the rules it switches on.
pub use crate::ledger::staking::StakingConfig;
/// Shortest `bridge.rules_v2.cap_window_secs` (one hour) and longest (seven days) a genesis may set.
pub const MIN_CAP_WINDOW_SECS: u32 = 3_600;
pub const MAX_CAP_WINDOW_SECS: u32 = 7 * 86_400;

/// Smallest `registration_fee` a `tokens` section may set, in RAND's base unit.
pub const MIN_REGISTRATION_FEE: u64 = 1_000_000_000;
/// Largest `registration_fee` a `tokens` section may set.
pub const MAX_REGISTRATION_FEE: u64 = 10_000_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: u64,
    pub timestamp_ms: u64,
    pub validators: Vec<GenesisValidator>,
    /// The deposit notes the chain starts with.
    #[serde(default)]
    pub alloc: Vec<GenesisNote>,
    /// Testnet only: allow `Mint` transactions (up to 100 RAND each). Part of the genesis hash.
    #[serde(default)]
    pub faucet: bool,
    /// Allow Deploy/Call transactions (zkVM verification). Part of the genesis hash.
    #[serde(default = "default_true")]
    pub confidential: bool,
    /// zkVM FRI profile every node must use: "production" or "test" (tests only). Part of the genesis hash.
    #[serde(default = "default_profile")]
    pub fri_profile: String,
    /// The `bundle` guest's program commitment, 64 hex characters: the only proof-system
    /// parameter a bundle proof is checked against. Part of the genesis hash.
    pub hc_bundle: String,
    /// Cross-chain bridge (spec §10): the outbound emitter, the initial guardian set and the
    /// source-chain emitters. Part of the genesis hash and of the state root when present;
    /// omitted entirely when absent, so a bridge-less chain's genesis file, hash and state root
    /// are byte-for-byte what phase S1 produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<BridgeConfig>,
    /// RPL tokens (spec's RPL token standard): the registration fee and any bridged tokens
    /// listed at genesis. Part of the genesis hash and of the state root when present, right
    /// after the bridge root; omitted entirely when absent, so a chain without one hashes and
    /// commits byte-for-byte what it always did. A `bridge` section without this is
    /// [`GenesisError::BridgeNeedsTokens`]; a listed token without a `bridge` section is
    /// [`GenesisError::BadTokens`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokensConfig>,
    /// Block aggregation (spec §2): the aggregator bond, cover cap, subsidy schedule, sealing
    /// window and admitted inner shapes. Part of the genesis hash and of the state root when
    /// present; omitted entirely when absent, so an aggregation-less chain's genesis file, hash
    /// and state root are byte-for-byte today's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<crate::ledger::aggregation::AggregationConfig>,
    /// Audit v4: the consensus signing domain (`SigningDomain`). Absent — chain 14 — or `0`:
    /// votes, new-views and proposals sign exactly what they always signed. `1`: every one
    /// carries the genesis hash under a fresh tag, so a signature for this chain verifies under
    /// no other. Part of the genesis hash only when present; omitted entirely when absent, so
    /// a file without it hashes byte-for-byte as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_domain: Option<u32>,
    /// Audit v4, STAKE-2: the faucet's per-epoch budget and the bond activation delay, and the
    /// rule that a faucet and a bridge exclude each other. Part of the genesis hash (by name)
    /// and of the state root when present; omitted entirely when absent, so a chain without
    /// one — chain 14 — keeps its genesis file, hash and state roots byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staking: Option<StakingConfig>,
    /// Phase S2: blocks per epoch — the validator set for epoch `e` is derived from the
    /// register as of the last block of epoch `e - 1`. Configurable so a cluster test does not
    /// have to run 1000 blocks to cross a boundary. Part of the genesis hash: two chains that
    /// disagree about it derive different sets from the same register.
    #[serde(default = "default_epoch_blocks")]
    pub epoch_blocks: u64,
    /// v0.4: the largest program a `Deploy` may carry, in words, `1..=`
    /// [`gas::MAX_PROGRAM_WORDS_LIMIT`] (the zkVM's own 16-bit limit). Absent means
    /// [`gas::MAX_PROGRAM_WORDS`], today's 4 096. Part of the genesis hash when present; omitted
    /// entirely when absent, so a chain cut without it (chain 12 included) keeps its genesis
    /// file and hash byte-for-byte. Never part of the state root: like `epoch_blocks` it is a
    /// parameter the ledger runs with, and a reloading node sets it from this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_program_words: Option<u32>,
    /// Call limits (spec §3): the largest proof a transaction may carry, in bytes,
    /// `gas::MAX_PROOF_BYTES_MIN..=gas::MAX_PROOF_BYTES_LIMIT` (1 MiB ..= 32 MiB). Absent means
    /// [`gas::MAX_PROOF_BYTES`]. Like `max_program_words`: omitted when absent, bound into the
    /// genesis hash by name when present, never part of the state root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_proof_bytes: Option<u32>,
    /// Call limits: the largest block, and so the largest transaction, in bytes,
    /// `gas::MAX_BLOCK_BYTES_MIN..=gas::MAX_BLOCK_BYTES_LIMIT` (4 MiB ..= 64 MiB) and at least
    /// `2 · max_proof_bytes + 1 MiB` (the effective proof cap: the default when that field is
    /// absent). Absent means [`gas::MAX_BLOCK_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_block_bytes: Option<u32>,
    /// Call limits: the largest call input envelope, in bytes, 18 432 ..=
    /// `gas::MAX_CALL_ENVELOPE_BYTES_LIMIT` (1 MiB). Absent means
    /// [`crate::types::actions::MAX_CALL_ENVELOPE_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_call_envelope_bytes: Option<u32>,
    /// Call limits: the largest public input a `Deploy` may fix, in words, 0 ..=
    /// `gas::MAX_PROGRAM_PUBLIC_WORDS_LIMIT` (the zkVM's 16-bit bound). Absent means
    /// [`gas::MAX_PROGRAM_PUBLIC_WORDS`], no public input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_program_public_words: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// Spec §8: blocks per epoch unless the genesis file says otherwise. Defined by the staking
/// rules and re-exported here, where genesis files reach it.
pub use crate::ledger::staking::EPOCH_BLOCKS_DEFAULT;

fn default_epoch_blocks() -> u64 {
    EPOCH_BLOCKS_DEFAULT
}

/// Largest `epoch_blocks` a genesis file may ask for. `epoch(h) = h / epoch_blocks`, so zero is
/// a division by zero and anything past a chain's reachable height is an epoch that never ends —
/// one set, forever, which is not what a genesis author means by a large number. `1 << 32` blocks
/// is ~136 years at 1 s blocks: far beyond any real chain and still far from `u64::MAX`.
pub const MAX_EPOCH_BLOCKS: u64 = 1 << 32;

fn default_profile() -> String {
    "production".into()
}

pub const FRI_PROFILES: [&str; 2] = ["production", "test"];

#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("no validators")]
    NoValidators,
    #[error("validator {0} has zero stake")]
    ZeroStake(Address),
    #[error("validator {addr} stake {stake} is below the minimum {min}")]
    BelowMinStake { addr: Address, stake: u128, min: u64 },
    #[error("validator {0} stake does not fit in the register's u64")]
    StakeTooLarge(Address),
    #[error("bad payout address {0}")]
    BadPayout(String),
    #[error("duplicate validator {0}")]
    DuplicateValidator(Address),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown fri_profile {0} (production|test)")]
    BadFriProfile(String),
    #[error("bad bridge config: {0}")]
    BadBridgeConfig(String),
    #[error("bad aggregation config: {0}")]
    BadAggregationConfig(String),
    #[error("a bridge section needs a tokens section (RPL tokens key on the same gate)")]
    BridgeNeedsTokens,
    #[error("bad tokens config: {0}")]
    BadTokens(String),
    #[error("unknown consensus_domain {0} (0 or 1)")]
    BadConsensusDomain(u32),
    /// Audit v4, STAKE-2 rule 1: under a `staking` section a chain that holds bridged custody
    /// cannot also hand out free RAND.
    #[error("a staking section refuses a faucet on a bridged chain (faucet: true with a bridge section)")]
    FaucetWithBridge,
    #[error("bad hc_bundle {0} (64 hex characters)")]
    BadHcBundle(String),
    #[error("bad alloc note {0}")]
    BadNote(String),
    #[error("duplicate alloc note {0}")]
    DuplicateNote(String),
    /// Core I-2: a chain that can hold bridged value must be able to show that every note it
    /// starts with is a RAND note of the amount it declares.
    #[error("alloc note {0} has no opening, which a chain with a tokens section requires")]
    MissingNoteOpening(String),
    #[error("alloc note {0}'s opening does not produce its commitment")]
    NoteCommitmentMismatch(String),
    #[error("bad epoch_blocks {0} (1..={MAX_EPOCH_BLOCKS})")]
    BadEpochBlocks(u64),
    #[error("bad max_program_words {0} (1..={limit})", limit = gas::MAX_PROGRAM_WORDS_LIMIT)]
    BadMaxProgramWords(u32),
    #[error("bad max_proof_bytes {0} ({min}..={limit})", min = gas::MAX_PROOF_BYTES_MIN, limit = gas::MAX_PROOF_BYTES_LIMIT)]
    BadMaxProofBytes(u32),
    #[error(
        "bad max_block_bytes {0} ({min}..={limit}, and at least 2 * max_proof_bytes + {headroom})",
        min = gas::MAX_BLOCK_BYTES_MIN,
        limit = gas::MAX_BLOCK_BYTES_LIMIT,
        headroom = gas::BLOCK_PROOF_HEADROOM
    )]
    BadMaxBlockBytes(u32),
    #[error(
        "bad max_call_envelope_bytes {0} ({min}..={limit})",
        min = crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
        limit = gas::MAX_CALL_ENVELOPE_BYTES_LIMIT
    )]
    BadMaxCallEnvelopeBytes(u32),
    #[error("bad max_program_public_words {0} (0..={limit})", limit = gas::MAX_PROGRAM_PUBLIC_WORDS_LIMIT)]
    BadMaxProgramPublicWords(u32),
    #[error("the genesis supply (alloc notes plus validator stakes) sums past u64::MAX")]
    SupplyOverflow,
}

/// Everything a node derives from the genesis file.
#[derive(Clone, Debug)]
pub struct GenesisState {
    pub chain_id: u64,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    pub hc_bundle: Word8,
    pub validators: ValidatorSet,
    /// Phase S2: blocks per epoch, as the genesis file set it.
    pub epoch_blocks: u64,
    /// The consensus signing domain's version (audit v4): 0 when the file has none.
    pub consensus_domain: u32,
    /// Audit v4, STAKE-2: the `staking` section, as the genesis file set it (also on the
    /// ledger, `Ledger::staking`, which is what a reloading node restores from).
    pub staking: Option<StakingConfig>,
    pub ledger: Ledger,
    pub block: Block,
    /// The alloc notes in file order: commitment, envelope, amount.
    pub notes: Vec<(Word8, Envelope, u64)>,
}

impl GenesisState {
    pub fn hash(&self) -> Hash {
        self.block.hash()
    }

    /// What every consensus signature on this chain is under: the file's version over this
    /// genesis hash.
    pub fn signing_domain(&self) -> SigningDomain {
        SigningDomain { version: self.consensus_domain, genesis: self.hash() }
    }
}

impl Genesis {
    pub fn from_json(s: &str) -> Result<Genesis, GenesisError> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("genesis serializes")
    }

    /// Structural checks that need no [`ConfidentialExecutor`]: no validators, an unknown FRI
    /// profile, an unrunnable `bridge`/`aggregation` section, an unusable `epoch_blocks`, the
    /// program-words and call-limits caps out of bounds, and the RPL `tokens` gate (a `bridge`
    /// section needs one; a listed token needs a `bridge` section, no duplicate `(chain, token)`
    /// listing, and metadata that passes [`crate::ledger::tokens::check_metadata`]). [`Self::build`]
    /// calls this first; a caller that only wants to know whether a genesis file is well-formed,
    /// without paying for a ledger, can call it directly.
    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.validators.is_empty() {
            return Err(GenesisError::NoValidators);
        }
        if !FRI_PROFILES.contains(&self.fri_profile.as_str()) {
            return Err(GenesisError::BadFriProfile(self.fri_profile.clone()));
        }
        if let Some(bridge) = &self.bridge {
            check_bridge(bridge)?;
        }
        if let Some(aggregation) = &self.aggregation {
            check_aggregation(aggregation, &self.fri_profile)?;
        }
        // S2 divides by `epoch_blocks` to get the epoch of a height; a genesis file that says
        // zero would panic every node on the first block rather than at the one place that
        // reads the file. The upper bound costs nothing and rejects an epoch that never ends.
        if self.epoch_blocks == 0 || self.epoch_blocks > MAX_EPOCH_BLOCKS {
            return Err(GenesisError::BadEpochBlocks(self.epoch_blocks));
        }
        // A zero cap refuses every program; one past the zkVM's 16-bit word count admits
        // programs no call could ever prove, so a deployer would pay for dead code.
        if let Some(n) = self.max_program_words {
            if n == 0 || n as usize > gas::MAX_PROGRAM_WORDS_LIMIT {
                return Err(GenesisError::BadMaxProgramWords(n));
            }
        }
        // The call limits (spec §3). Each bound keeps a chain runnable: a proof cap under 1 MiB
        // refuses every production proof, and one past 32 MiB, or a block past 64 MiB, is more
        // than any validator is asked to carry.
        if let Some(n) = self.max_proof_bytes {
            if !(gas::MAX_PROOF_BYTES_MIN..=gas::MAX_PROOF_BYTES_LIMIT).contains(&(n as usize)) {
                return Err(GenesisError::BadMaxProofBytes(n));
            }
        }
        // A block must carry a transaction with two worst-case proofs — the fee bundle's and the
        // call's — plus 1 MiB for the rest, or the proof cap admits proofs no block can hold. The
        // rule reads the effective proof cap, the default when the file leaves it out. A file
        // with neither field is today's chain, whose 4 MiB block predates the rule, and is not
        // judged by it.
        if self.max_proof_bytes.is_some() || self.max_block_bytes.is_some() {
            let proof = self.max_proof_bytes.map_or(gas::MAX_PROOF_BYTES, |n| n as usize);
            let block = self.max_block_bytes.map_or(gas::MAX_BLOCK_BYTES, |n| n as usize);
            if !(gas::MAX_BLOCK_BYTES_MIN..=gas::MAX_BLOCK_BYTES_LIMIT).contains(&block)
                || block < 2 * proof + gas::BLOCK_PROOF_HEADROOM
            {
                return Err(GenesisError::BadMaxBlockBytes(block as u32));
            }
        }
        if let Some(n) = self.max_call_envelope_bytes {
            if !(crate::types::actions::MAX_CALL_ENVELOPE_BYTES..=gas::MAX_CALL_ENVELOPE_BYTES_LIMIT).contains(&(n as usize)) {
                return Err(GenesisError::BadMaxCallEnvelopeBytes(n));
            }
        }
        if let Some(n) = self.max_program_public_words {
            if n as usize > gas::MAX_PROGRAM_PUBLIC_WORDS_LIMIT {
                return Err(GenesisError::BadMaxProgramPublicWords(n));
            }
        }
        // RPL tokens: the gate. A bridge without tokens cannot register a bridged token; tokens
        // listed without a bridge have no chain to attest them.
        if self.bridge.is_some() && self.tokens.is_none() {
            return Err(GenesisError::BridgeNeedsTokens);
        }
        if let Some(tokens) = &self.tokens {
            check_tokens(tokens, self.bridge.as_ref())?;
        }
        // The consensus domain (audit v4): a version this build cannot sign is refused here,
        // not at the first vote.
        if let Some(v) = self.consensus_domain {
            if v > SigningDomain::MAX_VERSION {
                return Err(GenesisError::BadConsensusDomain(v));
            }
        }
        // Audit v4, STAKE-2 rule 1, only under the section: a faucet and a bridge exclude each
        // other. Chain 14's genesis has both and no section, so it still loads.
        if self.staking.is_some() && self.faucet && self.bridge.is_some() {
            return Err(GenesisError::FaucetWithBridge);
        }
        Ok(())
    }

    pub fn build(&self, executor: &dyn ConfidentialExecutor) -> Result<GenesisState, GenesisError> {
        self.validate()?;
        // The register (spec §8) is what genesis actually seeds; the validator set for epoch 0
        // is derived from it at the `ValidatorSet` boundary, where the stake widens again.
        let mut register: BTreeMap<Address, ValidatorEntry> = BTreeMap::new();
        for v in &self.validators {
            let addr = v.public_key.address();
            if v.stake == 0 {
                return Err(GenesisError::ZeroStake(addr));
            }
            let stake = u64::try_from(v.stake).map_err(|_| GenesisError::StakeTooLarge(addr))?;
            // A genesis validator below the minimum is in the register but in no epoch's set
            // (`staking::derive_set` filters it out), so a chain seeded entirely from such
            // entries would derive an empty set at its first epoch boundary and have nobody to
            // pick a leader from. Refused at the file rather than discovered at block 1000.
            if stake < MIN_STAKE {
                return Err(GenesisError::BelowMinStake { addr, stake: v.stake, min: MIN_STAKE });
            }
            let payout =
                ShieldedAddress::parse(&v.payout).map_err(|_| GenesisError::BadPayout(v.payout.clone()))?;
            // ValidatorSet::new would silently collapse duplicates (and the genesis hash would
            // commit to the collapsed set): reject instead.
            if register.contains_key(&addr) {
                return Err(GenesisError::DuplicateValidator(addr));
            }
            register.insert(
                addr,
                ValidatorEntry {
                    public_key: v.public_key.clone(),
                    stake,
                    pending: Vec::new(),
                    rewards: 0,
                    payout,
                    nonce: 0,
                    // Genesis validators activate at epoch 0, section or no section.
                    activation_epoch: 0,
                },
            );
        }
        let validators = ValidatorSet::from_entries(register.values().map(|e| (&e.public_key, e.stake)));

        let hc_bundle = word8_from_hex(&self.hc_bundle).ok_or_else(|| GenesisError::BadHcBundle(self.hc_bundle.clone()))?;
        let mut ledger = Ledger::new(self.chain_id, hc_bundle, register.clone(), executor);
        ledger.set_epoch_blocks(self.epoch_blocks);
        ledger.set_faucet(self.faucet);
        ledger.set_confidential(self.confidential);
        ledger.set_bridge(self.bridge.as_ref().map(BridgeState::from_config));
        // RPL tokens: `Bridge`-authority tokens only at genesis (a native token has no note to
        // mint into yet — a creator registers one after launch, a later task's action). Listed
        // in file order, so dense indices from `FIRST_TOKEN_INDEX` land exactly where the file
        // lists them (checked by `check_tokens`, called from `validate`, above).
        if let Some(tconf) = &self.tokens {
            let mut registry = TokenRegistry::new(tconf.registration_fee).with_mint_cap(tconf.mint_cap_per_day);
            for t in &tconf.tokens {
                // The id is over the registration fields, never over a backing: one token has
                // many coins and they grow (`add_backing`), so an identity built from a
                // `(chain, token)` pair could name only one of them and would move when a coin
                // was added.
                let id = crate::ledger::tokens::bridged_asset_id(&t.name, &t.symbol, &t.salt);
                registry
                    .register(
                        id,
                        t.name.clone(),
                        t.symbol.clone(),
                        BRIDGE_DECIMALS,
                        MintAuthority::Bridge {
                            backings: t
                                .backings
                                .iter()
                                .map(|b| Backing::new(b.chain, b.token, b.decimals))
                                .collect(),
                        },
                        0,
                    )
                    .map_err(|e| GenesisError::BadTokens(e.to_string()))?;
            }
            // Bridge rules v2: the registry keeps the rolling windows the bridge section asks
            // for (`check_bridge` bounded the parameters).
            if let Some(rules) = self.bridge.as_ref().and_then(|b| b.rules_v2.as_ref()) {
                registry = registry.with_rules_v2(rules.cap_window_secs, rules.global_mint_cap_per_window);
            }
            ledger.set_tokens(Some(registry));
        }
        ledger.set_aggregation(self.aggregation.clone());
        ledger.set_staking(self.staking.clone());
        ledger.set_max_program_words(self.max_program_words.map_or(gas::MAX_PROGRAM_WORDS, |n| n as usize));
        ledger.set_max_proof_bytes(self.max_proof_bytes.map_or(gas::MAX_PROOF_BYTES, |n| n as usize));
        ledger.set_max_block_bytes(self.max_block_bytes.map_or(gas::MAX_BLOCK_BYTES, |n| n as usize));
        ledger.set_max_call_envelope_bytes(
            self.max_call_envelope_bytes.map_or(crate::types::actions::MAX_CALL_ENVELOPE_BYTES, |n| n as usize),
        );
        ledger.set_max_program_public_words(self.max_program_public_words.map_or(gas::MAX_PROGRAM_PUBLIC_WORDS, |n| n as usize));
        // The genesis ledger is positioned at the genesis block, so it carries that block's
        // time structurally rather than relying on every caller to patch it in. The timestamp
        // is transient state, not part of the state root or the genesis hash.
        ledger.set_timestamp_ms(self.timestamp_ms);
        let mut notes = Vec::new();
        // Everything this chain starts with, for the supply audit (`ledger::supply`). Genesis
        // notes are the only value on the chain that no transaction ever minted, so this is the
        // one place the counter is set rather than accumulated.
        let mut deposited: u64 = 0;
        // Core I-2: on a chain that can hold bridged value, an alloc `cm` is no longer taken on
        // trust. Every note must carry the opening it commits to, and the ledger recomputes the
        // commitment as a RAND note — asset 0, `from` the zero word — exactly as it recomputes a
        // faucet mint's (`ledger::mint_commitment`, POOL-1). A note that opens to some other
        // asset, or to another amount than the supply counter is told, never builds a chain.
        // Gated on the `tokens` section so every genesis file cut before this parses and hashes
        // as before.
        let openings_required = self.tokens.is_some();
        for n in &self.alloc {
            let cm = word8_from_hex(&n.cm).ok_or_else(|| GenesisError::BadNote(n.cm.clone()))?;
            let envelope = n.envelope.to_envelope()?;
            match &n.opening {
                Some(o) => {
                    let pk = word8_from_hex(&o.pk).ok_or_else(|| GenesisError::BadNote(o.pk.clone()))?;
                    let r = word8_from_hex(&o.r).ok_or_else(|| GenesisError::BadNote(o.r.clone()))?;
                    if crate::ledger::mint_commitment(executor, &pk, n.amount, o.time, &r) != cm {
                        return Err(GenesisError::NoteCommitmentMismatch(n.cm.clone()));
                    }
                }
                // An opening is checked whenever it is there — a chain ≤ 13 that carries one
                // gets the same guarantee — and required only where it is load-bearing.
                None if openings_required => return Err(GenesisError::MissingNoteOpening(n.cm.clone())),
                None => {}
            }
            ledger.deposit(cm, executor).map_err(|_| GenesisError::DuplicateNote(n.cm.clone()))?;
            deposited = deposited.checked_add(n.amount).ok_or(GenesisError::SupplyOverflow)?;
            notes.push((cm, envelope, n.amount));
        }
        // The register's stakes are supply too (see `ledger::supply`): genesis is the one place
        // stake appears without a bond having burned notes for it.
        let mut staked: u64 = 0;
        for e in register.values() {
            staked = staked.checked_add(e.stake).ok_or(GenesisError::SupplyOverflow)?;
        }
        ledger.set_genesis_supply(deposited, staked);
        // Replaces the empty-tree root `Ledger::new` recorded, so the only anchor a chain
        // starts with is the root the deposit notes leave behind.
        ledger.record_anchor(0);

        // The genesis block is unsigned and has a self-referential placeholder justify; its hash
        // commits to chain id, validators, the chain switches, the bundle guest and every note.
        let proposer = validators.iter().next().expect("non-empty").public_key.clone();
        let mut commit = Vec::new();
        commit.extend_from_slice(&self.chain_id.to_be_bytes());
        commit.extend_from_slice(&bincode::serialize(&validators).expect("serializes"));
        commit.push(self.faucet as u8);
        commit.push(self.confidential as u8);
        commit.extend_from_slice(self.fri_profile.as_bytes());
        commit.extend_from_slice(&word8_to_bytes(&hc_bundle));
        for (cm, _, amount) in &notes {
            commit.extend_from_slice(&word8_to_bytes(cm));
            commit.extend_from_slice(&amount.to_be_bytes());
        }
        // Phase S2, after the notes: the epoch length, then every validator's payout address in
        // address order (the order the register itself is in, not the file's, so two files that
        // list the same validators in a different order still build the same chain).
        commit.extend_from_slice(&self.epoch_blocks.to_be_bytes());
        for e in register.values() {
            commit.extend_from_slice(&word8_to_bytes(&e.payout.pk));
            commit.extend_from_slice(&e.payout.kem_ek);
        }
        // S3, last: appended only when a bridge is configured, so a bridge-less chain's genesis
        // hash is unchanged by this phase. `BridgeCommit` is the plain-bytes twin of
        // `BridgeConfig`, whose own serde is hex text — bincode of that would commit to hex
        // *strings*.
        if let Some(bridge) = &self.bridge {
            commit.extend_from_slice(&bincode::serialize(&BridgeCommit::from(bridge)).expect("serializes"));
        }
        // Bridge rules v2 (audit v4), right after the bridge bytes and tagged like the call
        // limits: appended only when the group is present, so chain 14's file hashes
        // byte-for-byte as before. Not inside `BridgeCommit`, whose bincode would put an
        // `Option` byte into every bridged chain's commitment.
        if let Some(rules) = self.bridge.as_ref().and_then(|b| b.rules_v2.as_ref()) {
            commit.extend_from_slice(b"bridge_rules_v2");
            commit.extend_from_slice(&rules.global_mint_cap_per_window.to_be_bytes());
            commit.extend_from_slice(&rules.cap_window_secs.to_be_bytes());
        }
        // RPL tokens, after the bridge bytes: appended only when the section is configured, so a
        // chain without one hashes byte-for-byte as before. `TokensCommit` is the plain-bytes
        // twin of `TokensConfig`, whose own serde renders a token address as hex text — bincode
        // of that would commit to hex *strings* rather than to the bytes the chain runs on,
        // exactly as `BridgeCommit` exists for `BridgeConfig`.
        if let Some(tokens) = &self.tokens {
            commit.extend_from_slice(&bincode::serialize(&TokensCommit::from(tokens)).expect("serializes"));
        }
        // Block aggregation, likewise: appended only when the section is configured, so an
        // aggregation-less chain's genesis hash is byte-for-byte today's.
        if let Some(aggregation) = &self.aggregation {
            commit.extend_from_slice(&bincode::serialize(aggregation).expect("serializes"));
        }
        // v0.4's program cap, likewise: appended only when the file sets it, so a genesis
        // without one — chain 12's — hashes byte-for-byte as before. Tagged, unlike the two
        // sections above: it is a bare four bytes appended after optional variable-length ones,
        // so the tag names them rather than leaving a cap to read as the tail of a section.
        if let Some(n) = self.max_program_words {
            commit.extend_from_slice(b"max_program_words");
            commit.extend_from_slice(&n.to_be_bytes());
        }
        // The call limits, the same way and in this fixed order after `max_program_words`: each
        // appended with its name only when the file sets it.
        for (tag, value) in [
            (&b"max_proof_bytes"[..], self.max_proof_bytes),
            (&b"max_block_bytes"[..], self.max_block_bytes),
            (&b"max_call_envelope_bytes"[..], self.max_call_envelope_bytes),
            (&b"max_program_public_words"[..], self.max_program_public_words),
        ] {
            if let Some(n) = value {
                commit.extend_from_slice(tag);
                commit.extend_from_slice(&n.to_be_bytes());
            }
        }
        // The consensus domain (audit v4), tagged the same way and only when the file sets it:
        // two chains that disagree about what a vote signs are two chains.
        if let Some(v) = self.consensus_domain {
            commit.extend_from_slice(b"consensus_domain");
            commit.extend_from_slice(&v.to_be_bytes());
        }
        // The staking section (audit v4, STAKE-2), tagged like the caps and appended only when
        // the file sets it, so chain 14's genesis hashes byte-for-byte as before. Its two fields
        // are fixed-width, so they follow the tag directly.
        if let Some(s) = &self.staking {
            commit.extend_from_slice(b"staking");
            commit.extend_from_slice(&s.faucet_budget_per_epoch.to_be_bytes());
            commit.extend_from_slice(&s.bond_activation_epochs.to_be_bytes());
        }
        let genesis_binding = Hash::digest_domain(b"rand-genesis-2", &commit);
        let header = BlockHeader {
            height: 0,
            view: 0,
            parent: genesis_binding,
            proposer,
            timestamp_ms: self.timestamp_ms,
            tx_root: Hash::ZERO,
            state_root: ledger.state_root(),
            justify: QuorumCertificate { view: 0, block_hash: Hash::ZERO, votes: Vec::new() },
        };
        let block = Block { header, transactions: Vec::new(), signature: Signature::empty() };
        // The signing domain carries the genesis hash, so it can only be set once the block
        // exists; it is not state, so the root above is unaffected.
        let consensus_domain = self.consensus_domain.unwrap_or(0);
        ledger.set_signing_domain(SigningDomain { version: consensus_domain, genesis: block.hash() });
        Ok(GenesisState {
            chain_id: self.chain_id,
            faucet: self.faucet,
            confidential: self.confidential,
            fri_profile: self.fri_profile.clone(),
            hc_bundle,
            validators,
            epoch_blocks: self.epoch_blocks,
            consensus_domain,
            staking: self.staking.clone(),
            ledger,
            block,
            notes,
        })
    }
}

/// Rejects a `bridge` section a chain could not run: an empty, duplicated or zero guardian set,
/// Rand itself registered as a source emitter, or a source emitter that collides with the
/// governance emitter (which would let a source chain forge guardian-set upgrades).
fn check_bridge(cfg: &BridgeConfig) -> Result<(), GenesisError> {
    let bad = |m: String| Err(GenesisError::BadBridgeConfig(m));
    if cfg.guardians.is_empty() {
        return bad("no guardians".into());
    }
    // A set whose own quorum attestation cannot fit the wire cap is a chain that could not
    // run: a transfer attestation is 6 envelope bytes + 66 per signature + a 51-byte body
    // header + a 133-byte payload, and it must fit `MAX_ATTESTATION_BYTES`. Governance keeps
    // sets far smaller (a Solana release transaction fits about seven signatures), but that is
    // cross-chain policy; this bound is the one above which no attestation can ever verify.
    let quorum = crate::bridge::quorum(cfg.guardians.len());
    let attestation_len = 6 + 66 * quorum + 51 + crate::bridge::TRANSFER_PAYLOAD_LEN;
    if attestation_len > crate::gas::MAX_ATTESTATION_BYTES {
        return bad(format!(
            "guardian set of {} is too large: quorum {} makes a {}-byte attestation, above MAX_ATTESTATION_BYTES ({})",
            cfg.guardians.len(),
            quorum,
            attestation_len,
            crate::gas::MAX_ATTESTATION_BYTES
        ));
    }
    if cfg.guardians.iter().collect::<std::collections::BTreeSet<&GuardianKey>>().len() != cfg.guardians.len() {
        return bad("duplicate guardian key".into());
    }
    if cfg.guardians.contains(&[0u8; 20]) {
        return bad("zero guardian key".into());
    }
    // B3: the Dilithium2 co-signers, index-aligned with `guardians` — one PQ key per operator,
    // each exactly a Dilithium2 public key, none repeated (a repeated key would let one operator
    // count twice toward the PQ quorum).
    if cfg.pq_guardians.len() != cfg.guardians.len() {
        return bad(format!(
            "pq_guardians has {} keys, guardians has {}: the two lists are index-aligned",
            cfg.pq_guardians.len(),
            cfg.guardians.len()
        ));
    }
    if let Some((i, k)) =
        cfg.pq_guardians.iter().enumerate().find(|(_, k)| k.as_bytes().len() != crate::bridge::PQ_PUBLIC_KEY_LEN)
    {
        return bad(format!(
            "pq_guardians[{i}] is {} bytes, not a Dilithium2 public key's {}",
            k.as_bytes().len(),
            crate::bridge::PQ_PUBLIC_KEY_LEN
        ));
    }
    if cfg.pq_guardians.iter().map(|k| k.as_bytes()).collect::<std::collections::BTreeSet<&[u8]>>().len()
        != cfg.pq_guardians.len()
    {
        return bad("duplicate pq_guardians key".into());
    }
    // B1: the one key that may pause minting — required on every bridged chain, exactly a
    // Dilithium2 key, and none of the PQ guardians' (the spec wants it held away from the machine
    // that holds the guardian keys; a key shared with a guardian is at least provably not).
    let Some(pause_key) = &cfg.pause_key else {
        return bad("no pause_key: a bridged chain needs the key that can pause minting".into());
    };
    if pause_key.as_bytes().len() != crate::bridge::PQ_PUBLIC_KEY_LEN {
        return bad(format!(
            "pause_key is {} bytes, not a Dilithium2 public key's {}",
            pause_key.as_bytes().len(),
            crate::bridge::PQ_PUBLIC_KEY_LEN
        ));
    }
    if cfg.pq_guardians.contains(pause_key) {
        return bad("pause_key is one of the pq_guardians: it must be held apart from the guardian keys".into());
    }
    // Bridge rules v2 (audit v4): a window shorter than an hour is finer than the slot the
    // accounting keeps, one past a week is more custody exposure than a cap is for; a zero
    // global cap could never mint a thing.
    if let Some(rules) = &cfg.rules_v2 {
        if !(MIN_CAP_WINDOW_SECS..=MAX_CAP_WINDOW_SECS).contains(&rules.cap_window_secs) {
            return bad(format!(
                "rules_v2.cap_window_secs {} is out of bounds ({MIN_CAP_WINDOW_SECS}..={MAX_CAP_WINDOW_SECS})",
                rules.cap_window_secs
            ));
        }
        if rules.global_mint_cap_per_window == 0 {
            return bad("rules_v2.global_mint_cap_per_window is zero: the bridge could never mint".into());
        }
    }
    if cfg.emitter == [0u8; 32] {
        return bad("zero emitter address".into());
    }
    if cfg.emitter == GOVERNANCE_EMITTER {
        return bad("emitter is the governance emitter".into());
    }
    if cfg.emitters.contains_key(&CHAIN_RAND) {
        return bad(format!("chain {CHAIN_RAND} is Rand itself and cannot be a source emitter"));
    }
    if let Some((chain, _)) = cfg.emitters.iter().find(|(_, addr)| **addr == GOVERNANCE_EMITTER) {
        return bad(format!("emitter for chain {chain} is the governance emitter"));
    }
    // A zero source emitter is never a real contract, and registering one would mean any
    // attestation naming that chain with an all-zero `emitter_address` passes the emitter
    // binding of spec 3.8.
    if let Some((chain, _)) = cfg.emitters.iter().find(|(_, addr)| **addr == [0u8; 32]) {
        return bad(format!("zero emitter address for chain {chain}"));
    }
    Ok(())
}

/// Rejects an `aggregation` section a chain could not run (spec §2.3): a zero bond, cover cap,
/// halving interval or window (each would make a rule the section exists to create
/// meaningless), or an admitted shape whose aggregate-program digest is all zero — the
/// activation placeholder, which must never reach a fleet (spec §10's `FILL-AT-ACTIVATION`).
fn check_aggregation(
    cfg: &crate::ledger::aggregation::AggregationConfig,
    fri_profile: &str,
) -> Result<(), GenesisError> {
    let bad = |m: String| Err(GenesisError::BadAggregationConfig(m));
    if cfg.bond == 0 {
        return bad("zero bond".into());
    }
    if cfg.max_covers == 0 {
        return bad("zero max_covers".into());
    }
    if cfg.halving_blocks == 0 {
        return bad("zero halving_blocks".into());
    }
    if cfg.window == 0 {
        return bad("zero window".into());
    }
    if cfg.admitted_shapes.iter().any(|s| s.aggregate_program_digest == [0; 4]) {
        return bad("an admitted shape has no aggregate-program digest (the activation placeholder)".into());
    }
    // An admitted shape declares a FRI profile of its own, and it has to be the chain's (audit v3,
    // CHAIN9-1). A mismatch is not unsafe — every aggregate would be refused as an unregistered
    // shape — but it leaves aggregation dead on a chain that believes it has it, and the first
    // aggregator to bond is what discovers that. Cheap to catch here, expensive to find later.
    let want = match fri_profile {
        "test" => crate::types::FriProfile::Test,
        _ => crate::types::FriProfile::Production,
    };
    if let Some(s) = cfg.admitted_shapes.iter().find(|s| s.shape.profile != want) {
        return bad(format!(
            "an admitted shape declares the {:?} profile on a {fri_profile} chain",
            s.shape.profile
        ));
    }
    Ok(())
}

/// Rejects a `tokens` section a chain could not run: a `registration_fee` out of bounds, a
/// listed token when there is no `bridge` section to attest it, a listing with no backings or
/// more than [`MAX_BACKINGS`], a backing whose declared source decimals is over
/// [`MAX_BACKING_DECIMALS`] ([`TokenError::BadBackingDecimals`]'s genesis-time twin), a
/// `(chain, token)` pair listed twice anywhere in the section, a backing on a chain the `bridge`
/// section registers no emitter for, or metadata [`check_metadata`] itself would refuse (a
/// genesis token is always `BRIDGE_DECIMALS`, spec's RPL token standard).
///
/// The emitter rule is the one this amendment adds (spec §12): a coin on a chain with no
/// registered emitter can never be attested, so a backing naming one is a listing the chain
/// could not use — caught in the file rather than discovered as an `UnlistedToken` that no
/// correction can fix without a new genesis.
///
/// [`TokenError::BadBackingDecimals`]: crate::ledger::tokens::TokenError::BadBackingDecimals
fn check_tokens(cfg: &TokensConfig, bridge: Option<&BridgeConfig>) -> Result<(), GenesisError> {
    let bad = |m: String| Err(GenesisError::BadTokens(m));
    if !(MIN_REGISTRATION_FEE..=MAX_REGISTRATION_FEE).contains(&cfg.registration_fee) {
        return bad(format!(
            "registration_fee {} is out of bounds ({MIN_REGISTRATION_FEE}..={MAX_REGISTRATION_FEE})",
            cfg.registration_fee
        ));
    }
    // B1: a bridged chain with a zero cap could never mint a thing — every deposit would be
    // `MintCapExceeded` for ever — so the file is refused rather than the chain.
    if bridge.is_some() && cfg.mint_cap_per_day == 0 {
        return bad("mint_cap_per_day is zero: a bridged chain could never mint".into());
    }
    let Some(bridge) = bridge else {
        return if cfg.tokens.is_empty() {
            Ok(())
        } else {
            bad("listed tokens need a bridge section to attest them".into())
        };
    };
    let mut seen: BTreeSet<(u16, [u8; 32])> = BTreeSet::new();
    for t in &cfg.tokens {
        check_metadata(&t.name, &t.symbol, BRIDGE_DECIMALS).map_err(|e| GenesisError::BadTokens(e.to_string()))?;
        if t.backings.is_empty() {
            return bad(format!("token {} has no backings", t.symbol));
        }
        if t.backings.len() > MAX_BACKINGS {
            return bad(format!("token {} has {} backings, more than {MAX_BACKINGS}", t.symbol, t.backings.len()));
        }
        for b in &t.backings {
            if b.decimals > MAX_BACKING_DECIMALS {
                return bad(format!(
                    "backing for chain {} token {} declares {} decimals, over the maximum {MAX_BACKING_DECIMALS}",
                    b.chain,
                    hex::encode(b.token),
                    b.decimals
                ));
            }
            if !seen.insert((b.chain, b.token)) {
                return bad(format!("duplicate backing for chain {} token {}", b.chain, hex::encode(b.token)));
            }
            if !bridge.emitters.contains_key(&b.chain) {
                return bad(format!(
                    "backing on chain {}, which the bridge section registers no emitter for",
                    b.chain
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;
    use crate::crypto::Keypair;
    use crate::notes::word8_to_hex;
    use crate::types::UNITS_PER_RAND;
    use std::collections::BTreeMap;

    fn note(seed: u32, amount: u64) -> GenesisNote {
        GenesisNote {
            cm: word8_to_hex(&[seed; 8]),
            envelope: EnvelopeHex::from_envelope(&Envelope {
                kem_ct: vec![1; 8],
                to_receiver: vec![],
                to_sender: vec![],
                body: vec![2; 8],
            }),
            amount,
            opening: None,
        }
    }

    /// An alloc note whose commitment the ledger can recompute: a RAND note (asset 0, `from` the
    /// zero word) owned by `[seed; 8]`, blinded with `[seed + 1; 8]`, stamped 0 — what
    /// `rand-node genesis` writes since core I-2.
    fn opened_note(seed: u32, amount: u64) -> GenesisNote {
        let (pk, r) = ([seed; 8], [seed + 1; 8]);
        let mut n = note(seed, amount);
        n.cm = word8_to_hex(&crate::ledger::mint_commitment(&StubExecutor, &pk, amount, 0, &r));
        n.opening = Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r) });
        n
    }

    /// The alloc every chain *with* a `tokens` section needs since core I-2: the same two notes
    /// [`genesis`] uses, each carrying the opening its commitment is derived from.
    fn opened_alloc() -> Vec<GenesisNote> {
        vec![opened_note(7, 1_000_000), opened_note(8, 2_000_000)]
    }

    /// A valid `rand1…` payout address, distinct per `i`.
    fn payout(i: u8) -> String {
        ShieldedAddress { pk: [i as u32; 8], kem_ek: vec![i; crate::notes::KEM_EK_BYTES] }.to_string()
    }

    fn genesis(n: u8) -> Genesis {
        let keys: Vec<Keypair> = (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        Genesis {
            chain_id: 42,
            timestamp_ms: 1_700_000_000_000,
            validators: keys
                .iter()
                .enumerate()
                .map(|(i, k)| GenesisValidator {
                    public_key: k.public_key().clone(),
                    // A genesis validator has to be in the first epoch's set, so it has to meet
                    // the staking minimum.
                    stake: MIN_STAKE as u128,
                    payout: payout(i as u8 + 1),
                })
                .collect(),
            alloc: vec![note(7, 1_000_000), note(8, 2_000_000)],
            faucet: false,
            confidential: true,
            fri_profile: "production".into(),
            hc_bundle: word8_to_hex(&[3; 8]),
            bridge: None,
            tokens: None,
            aggregation: None,
            consensus_domain: None,
            staking: None,
            epoch_blocks: EPOCH_BLOCKS_DEFAULT,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
        }
    }

    /// The name the RPL tokens tests use for [`genesis(1)`] — the same one-validator plain
    /// chain [`a_bridge_section_is_accepted_and_only_a_bridged_chain_changes`] builds from.
    fn base_genesis() -> Genesis {
        genesis(1)
    }

    fn build(g: &Genesis) -> GenesisState {
        g.build(&StubExecutor).unwrap()
    }

    /// Consensus domain v1 (audit v4) is genesis-gated: the field is committed only when present,
    /// so chain 14's file — which has none — builds to the same hash; validation refuses a
    /// version this build does not sign.
    #[test]
    fn a_genesis_with_consensus_domain_1_commits_it_and_one_without_is_unchanged() {
        let base = genesis(1);
        assert_eq!(base.consensus_domain, None, "chain 14's shape has no field");
        let plain = build(&base);
        let mut g = base.clone();
        g.consensus_domain = Some(1);
        let v1 = build(&g);
        assert_ne!(v1.hash(), plain.hash(), "the version is part of the genesis binding");
        assert_eq!((plain.consensus_domain, v1.consensus_domain), (0, 1));
        assert_eq!(plain.signing_domain(), SigningDomain::v0(plain.hash()));
        assert_eq!(v1.signing_domain(), SigningDomain::v1(v1.hash()));
        assert_eq!(v1.ledger.signing_domain(), &v1.signing_domain(), "the ledger's replay check reads the same domain");
        let mut bad = base.clone();
        bad.consensus_domain = Some(2);
        assert!(matches!(bad.validate(), Err(GenesisError::BadConsensusDomain(2))));
        // The field round-trips through the file, and an absent one stays absent.
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap().consensus_domain, Some(1));
        assert!(!base.to_json().contains("consensus_domain"));
        assert_eq!(build(&Genesis::from_json(&base.to_json()).unwrap()).hash(), plain.hash());
    }

    /// Audit v3, CHAIN9-1: the admitted shapes are declared with a FRI profile of their own, and
    /// nothing checked it against the chain's. A production chain admitting a Test-profile shape
    /// is not unsafe — every aggregate is refused as an unregistered shape — but aggregation is
    /// then dead on a chain that believes it has it, discovered only when the first aggregator
    /// bonds. The genesis is where that is cheap to catch.
    #[test]
    fn an_admitted_shape_must_carry_the_chains_own_fri_profile() {
        use crate::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use crate::types::{DeclaredShape, FriProfile};
        let with = |profile: FriProfile, chain: &str| {
            let mut g = base_genesis();
            g.fri_profile = chain.into();
            let shape = DeclaredShape {
                profile,
                tier: 21,
                program_log_height: 12,
                input_log_height: 10,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: 2,
                mem_log_height: 16,
            };
            g.aggregation = Some(AggregationConfig {
                bond: 1_000,
                max_covers: 3,
                subsidy_base: 100,
                halving_blocks: 210_000,
                window: 256,
                admitted_shapes: vec![AdmittedShape {
                    shape,
                    hc: Hash::digest(b"the bundle guest"),
                    aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
                }],
            });
            g.validate()
        };
        assert!(with(FriProfile::Production, "production").is_ok(), "the chain's own profile is fine");
        assert!(with(FriProfile::Test, "test").is_ok());
        let e = with(FriProfile::Test, "production").unwrap_err();
        assert!(
            matches!(&e, GenesisError::BadAggregationConfig(m) if m.contains("profile")),
            "a Test shape on a production chain was accepted: {e}"
        );
        let e = with(FriProfile::Production, "test").unwrap_err();
        assert!(matches!(&e, GenesisError::BadAggregationConfig(m) if m.contains("profile")), "{e}");
    }

    /// Core I-2. On a chain with a `tokens` section an alloc commitment is no longer opaque:
    /// every note carries the opening it commits to, and `build` recomputes the commitment as a
    /// RAND note — asset 0, `from` the zero word — exactly as `ledger::mint_commitment` does for
    /// a faucet mint (POOL-1). Without it a genesis author could put a note committing to
    /// `(amount, asset = 1)` in `alloc` and hand itself spendable zUSD that no backing ever
    /// locked, fungible with the real thing and invisible to both the RAND audit and
    /// `custody >= supply`.
    #[test]
    fn a_tokens_chains_alloc_notes_must_open_to_rand_notes_of_their_declared_amount() {
        // The chain shape: a bridge, its tokens section, and alloc notes beside them.
        let bridged = |alloc: Vec<GenesisNote>| {
            let mut g = base_genesis();
            g.alloc = alloc;
            g.bridge = Some(bridge_cfg());
            g.tokens = Some(TokensConfig {
                registration_fee: MIN_REGISTRATION_FEE,
                tokens: vec![GenesisToken {
                    name: "Tether USD".into(),
                    symbol: "zUSDT".into(),
                    salt: [1; 32],
                    backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: BRIDGE_DECIMALS }],
                }],
                mint_cap_per_day: 100_000 * 100_000_000,
            });
            g
        };

        // The honest case: two openable notes, in the tree, counted as RAND.
        let honest = bridged(vec![opened_note(7, 1_000_000), opened_note(8, 2_000_000)]);
        let s = honest.build(&StubExecutor).expect("openings that reproduce their commitments");
        assert_eq!(s.ledger.next_index(), 2);
        assert_eq!(s.notes.iter().map(|(_, _, a)| *a).collect::<Vec<_>>(), vec![1_000_000, 2_000_000]);

        // No opening at all — the shape every chain ≤ 13 was cut with.
        let bare = bridged(vec![note(7, 1_000_000)]);
        assert!(
            matches!(bare.build(&StubExecutor), Err(GenesisError::MissingNoteOpening(cm)) if cm == word8_to_hex(&[7; 8]))
        );

        // An opening that does not reproduce the commitment: the amount is the field the supply
        // counter reads, so a note worth more than it declares is the audit hole.
        let mut lying = bridged(vec![opened_note(7, 1_000_000)]);
        lying.alloc[0].amount = 1;
        assert!(matches!(lying.build(&StubExecutor), Err(GenesisError::NoteCommitmentMismatch(_))));

        // The attack itself: a commitment over `(pk, from = 0, amount, asset = 1, time, r)` —
        // spendable zUSD at the chain-14 launch index — declared as `amount` RAND. It has no
        // opening that this rule accepts, because the rule fixes `asset = 0`.
        let (pk, r) = ([7u32; 8], [8u32; 8]);
        let mut asset_one = bridged(vec![opened_note(7, 1_000_000)]);
        asset_one.alloc[0].cm = word8_to_hex(&StubExecutor.note_commitment(&pk, &[0; 8], 1_000_000, 1, 0, &r));
        asset_one.alloc[0].opening =
            Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r) });
        assert!(
            matches!(asset_one.build(&StubExecutor), Err(GenesisError::NoteCommitmentMismatch(_))),
            "an asset-1 commitment cannot be opened as a genesis note"
        );

        // And a token-less chain is untouched: the same opening-less notes still build, and the
        // genesis hash is the one the section-less test pins.
        let plain = base_genesis();
        assert!(plain.alloc.iter().all(|n| n.opening.is_none()));
        assert_eq!(
            build(&plain).hash().to_hex(),
            "c3f27a29bfdf8abcfd4aaa24fadb127e34c4098cdacc09941a7e7ad3fa6b0b2c",
            "adding the field changes no existing chain's hash"
        );
        // An opening is verified wherever it appears, section or no section — it is only
        // *required* where it is load-bearing.
        let mut plain_wrong = base_genesis();
        plain_wrong.alloc[0].opening = Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r) });
        assert!(matches!(plain_wrong.build(&StubExecutor), Err(GenesisError::NoteCommitmentMismatch(_))));
    }

    /// The field is `#[serde(default)]`, so a genesis file written before core I-2 parses
    /// unchanged — and one written since round-trips its opening.
    #[test]
    fn an_alloc_note_without_an_opening_still_parses() {
        let old = r#"{"cm":"0707070707070707070707070707070707070707070707070707070707070707",
            "envelope":{"kem_ct":"01","to_receiver":"","to_sender":"","body":"02"},"amount":5}"#;
        let n: GenesisNote = serde_json::from_str(old).expect("a pre-I-2 alloc note parses");
        assert_eq!((n.amount, n.opening.as_ref()), (5, None));
        // And is written back without the key, so re-serializing an old file does not grow it.
        assert!(!serde_json::to_string(&n).unwrap().contains("opening"));
        let with = opened_note(7, 5);
        let back: GenesisNote = serde_json::from_str(&serde_json::to_string(&with).unwrap()).unwrap();
        assert_eq!(back, with);
    }

    #[test]
    fn alloc_notes_are_in_the_tree_and_the_binding() {
        let g = genesis(1);
        let s = build(&g);
        assert_eq!(s.ledger.next_index(), 2);
        assert!(s.ledger.has_commitment(&[7; 8]) && s.ledger.has_commitment(&[8; 8]));
        assert_eq!(s.notes.iter().map(|(cm, _, a)| (*cm, *a)).collect::<Vec<_>>(), vec![([7; 8], 1_000_000), ([8; 8], 2_000_000)]);
        assert_eq!(s.notes[0].1.body, vec![2; 8]);
        // The genesis ledger starts with exactly one anchor: the root the notes leave behind.
        assert_eq!(s.ledger.anchors().len(), 1);
        assert_eq!(s.ledger.anchors()[0], (0, s.ledger.root()));
        // An amount is part of the binding even though it is not chain state.
        let mut other = g.clone();
        other.alloc[1].amount += 1;
        assert_ne!(build(&other).hash(), s.hash());
        assert_eq!(build(&other).ledger.state_root(), s.ledger.state_root());
        // ... and so is the commitment, which is.
        let mut moved = g.clone();
        moved.alloc[1] = note(9, 2_000_000);
        assert_ne!(build(&moved).hash(), s.hash());
        assert_ne!(build(&moved).ledger.state_root(), s.ledger.state_root());
        // The same note twice is rejected rather than silently collapsed.
        let mut dup = g.clone();
        dup.alloc.push(note(7, 5));
        assert!(matches!(dup.build(&StubExecutor), Err(GenesisError::DuplicateNote(_))));
        let mut bad = g.clone();
        bad.alloc[0].cm = "zz".into();
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadNote(_))));
        let mut bad_env = g.clone();
        bad_env.alloc[0].envelope.body = "nothex".into();
        assert!(matches!(bad_env.build(&StubExecutor), Err(GenesisError::BadNote(_))));
    }

    #[test]
    fn hc_bundle_is_required_and_bound() {
        let g = genesis(1);
        let mut without = serde_json::to_value(&g).unwrap();
        without.as_object_mut().unwrap().remove("hc_bundle");
        assert!(Genesis::from_json(&without.to_string()).is_err(), "hc_bundle has no default");
        let s = build(&g);
        assert_eq!(s.hc_bundle, [3; 8]);
        assert_eq!(s.ledger.hc_bundle(), [3; 8]);
        let mut other = g.clone();
        other.hc_bundle = word8_to_hex(&[4; 8]);
        assert_ne!(build(&other).hash(), s.hash());
        let mut bad = g.clone();
        bad.hc_bundle = "not hex".into();
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadHcBundle(_))));
    }

    #[test]
    fn faucet_and_confidential_flags_change_the_hash_not_the_state_root() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.faucet = true;
        let mut c = genesis(1);
        c.confidential = false;
        let mut d = genesis(1);
        d.fri_profile = "test".into();
        let (sa, sb, sc, sd) = (build(&a), build(&b), build(&c), build(&d));
        assert_ne!(sa.hash(), sb.hash());
        assert_ne!(sa.hash(), sc.hash());
        assert_ne!(sa.hash(), sd.hash());
        assert!(!sa.ledger.faucet_enabled() && sb.ledger.faucet_enabled());
        assert!(sa.ledger.confidential_enabled() && !sc.ledger.confidential_enabled());
        for s in [&sb, &sc, &sd] {
            assert_eq!(s.ledger.state_root(), sa.ledger.state_root(), "chain switches are not state");
        }
        // The genesis ledger is positioned at the genesis block's time.
        assert_eq!(sa.ledger.timestamp_ms(), sa.block.header.timestamp_ms);
        let mut bogus = genesis(1);
        bogus.fri_profile = "bogus".into();
        assert!(matches!(bogus.build(&StubExecutor), Err(GenesisError::BadFriProfile(_))));
        assert!(a.to_json().contains("\"confidential\": true"));
    }

    /// A real Dilithium2 public key, from seed `[0x70 + i; 32]`.
    fn pq_key(i: u8) -> crate::crypto::PublicKey {
        crate::crypto::Keypair::from_seed([0x70 + i; 32]).unwrap().public_key().clone()
    }

    /// A distinct key of the right length that no seed derives — genesis checks a PQ key's
    /// length and uniqueness, and hundreds of real key generations would only slow a test down.
    fn synthetic_pq_key(i: usize) -> crate::crypto::PublicKey {
        let mut b = vec![0x5a; crate::crypto::PUBLIC_KEY_LEN];
        b[..8].copy_from_slice(&(i as u64).to_le_bytes());
        crate::crypto::PublicKey::from_bytes(&b).unwrap()
    }

    fn bridge_cfg() -> BridgeConfig {
        BridgeConfig {
            emitter: [1; 32],
            guardians: vec![[2; 20]],
            emitters: BTreeMap::from([(2u16, [9u8; 32])]),
            pq_guardians: vec![pq_key(0)],
            pause_key: Some(crate::crypto::Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
        }
    }

    /// The hard fork phase S3 ships is opt-in per chain: a genesis without a `bridge` section
    /// builds a chain whose state root has the four components it always had, and one with a
    /// section gets a fifth and a different genesis hash.
    ///
    /// The pinned root below is *not* phase S1's any more — phase S2 widened the validator leaf to
    /// v2 (`pending`, `payout`, `nonce`), which is a state-root fork of its own, and chain 6 takes
    /// both phases at once. What the pin still guards is the thing this test is about: the bridge
    /// root must not appear when the bridge is merely *available*, only when a chain turns it on.
    /// (`rand-node`'s `the_genesis_hash_is_pinned` guards the whole genesis binding the same
    /// way.)
    #[test]
    fn a_bridge_section_is_accepted_and_only_a_bridged_chain_changes() {
        let plain = genesis(1);
        let s = build(&plain);
        assert!(s.ledger.bridge().is_none());
        assert_eq!(
            s.ledger.state_root().to_hex(),
            "e845c110b5e366acf87806cb7f09cc212ad47008cac7cafbd141c30da4c738d4",
            "a chain without a bridge commits the four components, over S2's v2 register leaf"
        );
        assert!(!plain.to_json().contains("bridge"), "and its genesis file does not mention one");

        let mut bridged = plain.clone();
        bridged.bridge = Some(bridge_cfg());
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        // A chain with a `tokens` section needs openable alloc notes (core I-2); `plain` keeps
        // the opening-less ones the pins above are computed from.
        bridged.alloc = opened_alloc();
        let sb = build(&bridged);
        assert!(sb.ledger.bridge().is_some());
        assert_ne!(sb.ledger.state_root(), s.ledger.state_root(), "the bridge root is the fifth component");
        assert_ne!(sb.hash(), s.hash(), "and the section is part of the genesis binding");
        assert!(bridged.to_json().contains("bridge"));
        // The initial guardian set is set 0 and is the one the file named.
        let bridge = sb.ledger.bridge().unwrap();
        assert_eq!(bridge.current_set, 0);
        assert_eq!(bridge.guardian_sets[&0].keys, vec![[2u8; 20]]);
        assert_eq!(bridge.emitters, BTreeMap::from([(2u16, [9u8; 32])]));
        // Two chains that differ only in their guardians are different chains.
        let mut other_guardians = bridged.clone();
        other_guardians.bridge.as_mut().unwrap().guardians = vec![[3; 20]];
        assert_ne!(build(&other_guardians).hash(), sb.hash());
    }

    /// Audit v4 (bridge rules v2): a `rules_v2` group inside the bridge section is committed to
    /// the genesis hash under its own tag only when present — a chain-14-shaped file (no group)
    /// hashes and roots exactly as before — reaches the bridge state and the registry's windows,
    /// and is held to its bounds: the window in `3600..=7*86400`, the global cap above zero.
    #[test]
    fn bridge_rules_v2_are_committed_only_when_present_and_bounded() {
        let mut bridged = genesis(1);
        bridged.bridge = Some(bridge_cfg());
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        bridged.alloc = opened_alloc();
        let base = build(&bridged);
        assert_eq!(base.ledger.bridge().unwrap().rules_v2, None);
        assert_eq!(base.ledger.tokens().unwrap().windows(), None);
        assert!(!bridged.to_json().contains("rules_v2"), "absent from the file when absent");

        let mut v2 = bridged.clone();
        let rules = crate::bridge::BridgeRulesV2 { global_mint_cap_per_window: 500_000 * 100_000_000, cap_window_secs: 86_400 };
        v2.bridge.as_mut().unwrap().rules_v2 = Some(rules.clone());
        let sv2 = build(&v2);
        assert_ne!(sv2.hash(), base.hash(), "the group is in the genesis binding");
        assert_ne!(sv2.ledger.state_root(), base.ledger.state_root(), "and in the bridge and token roots");
        assert_eq!(sv2.ledger.bridge().unwrap().rules_v2, Some(rules.clone()));
        let w = sv2.ledger.tokens().unwrap().windows().unwrap();
        assert_eq!((w.window_secs, w.global_cap), (rules.cap_window_secs, rules.global_mint_cap_per_window));
        // Round trip through the file: what is written is what is read.
        let back: Genesis = serde_json::from_str(&v2.to_json()).unwrap();
        assert_eq!(back, v2);
        assert!(v2.to_json().contains("\"rules_v2\""));
        // Two files that differ only in a cap parameter build different chains.
        let mut other = v2.clone();
        other.bridge.as_mut().unwrap().rules_v2.as_mut().unwrap().cap_window_secs = 7_200;
        assert_ne!(build(&other).hash(), sv2.hash());

        let bad = |f: fn(&mut crate::bridge::BridgeRulesV2)| {
            let mut g = v2.clone();
            f(g.bridge.as_mut().unwrap().rules_v2.as_mut().unwrap());
            match g.validate() {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert!(bad(|r| r.cap_window_secs = 3_599).contains("cap_window_secs"));
        assert!(bad(|r| r.cap_window_secs = 7 * 86_400 + 1).contains("cap_window_secs"));
        assert!(bad(|r| r.global_mint_cap_per_window = 0).contains("global_mint_cap_per_window"));
        let mut edge = v2.clone();
        edge.bridge.as_mut().unwrap().rules_v2 = Some(crate::bridge::BridgeRulesV2 { global_mint_cap_per_window: 1, cap_window_secs: 7 * 86_400 });
        assert!(edge.validate().is_ok());
    }

    /// A `bridge` section a chain could not safely run is refused at build time rather than at
    /// the first attestation.
    #[test]
    fn an_unrunnable_bridge_section_is_refused() {
        let bad = |f: fn(&mut BridgeConfig)| {
            let mut g = genesis(1);
            let mut cfg = bridge_cfg();
            f(&mut cfg);
            g.bridge = Some(cfg);
            g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
            match g.build(&StubExecutor) {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert_eq!(bad(|c| c.guardians.clear()), "no guardians");
        // B3: the PQ guardians — index-aligned with `guardians`, each a Dilithium2 key's exact
        // length, none repeated.
        assert_eq!(bad(|c| c.pq_guardians.clear()), "pq_guardians has 0 keys, guardians has 1: the two lists are index-aligned");
        assert_eq!(
            bad(|c| c.pq_guardians.push(pq_key(1))),
            "pq_guardians has 2 keys, guardians has 1: the two lists are index-aligned"
        );
        assert_eq!(
            bad(|c| {
                let mut b = c.pq_guardians[0].as_bytes().to_vec();
                b.pop();
                c.pq_guardians[0] = serde_json::from_value(serde_json::json!(hex::encode(b))).unwrap();
            }),
            "pq_guardians[0] is 1311 bytes, not a Dilithium2 public key's 1312"
        );
        assert_eq!(
            bad(|c| {
                c.guardians.push([3; 20]);
                c.pq_guardians.push(c.pq_guardians[0].clone());
            }),
            "duplicate pq_guardians key"
        );
        // B1: the pause key — required, a Dilithium2 key's exact length, and no PQ guardian's.
        assert_eq!(bad(|c| c.pause_key = None), "no pause_key: a bridged chain needs the key that can pause minting");
        assert_eq!(
            bad(|c| {
                let mut b = c.pause_key.as_ref().unwrap().as_bytes().to_vec();
                b.push(0);
                c.pause_key = Some(serde_json::from_value(serde_json::json!(hex::encode(b))).unwrap());
            }),
            "pause_key is 1313 bytes, not a Dilithium2 public key's 1312"
        );
        assert_eq!(
            bad(|c| c.pause_key = Some(c.pq_guardians[0].clone())),
            "pause_key is one of the pq_guardians: it must be held apart from the guardian keys"
        );
        assert_eq!(bad(|c| c.guardians = vec![[2; 20], [2; 20]]), "duplicate guardian key");
        assert_eq!(bad(|c| c.guardians = vec![[0; 20]]), "zero guardian key");
        assert_eq!(bad(|c| c.emitter = [0; 32]), "zero emitter address");
        assert_eq!(bad(|c| c.emitter = GOVERNANCE_EMITTER), "emitter is the governance emitter");
        // Rand cannot be its own source chain: that is how governance payloads are told apart.
        assert!(bad(|c| {
            c.emitters.insert(CHAIN_RAND, [9; 32]);
        })
        .contains("is Rand itself"));
        assert!(bad(|c| {
            c.emitters.insert(2, GOVERNANCE_EMITTER);
        })
        .contains("is the governance emitter"));
        assert!(bad(|c| {
            c.emitters.insert(2, [0; 32]);
        })
        .contains("zero emitter address for chain 2"));
    }

    /// A guardian set too large for its own quorum's attestation to fit
    /// `MAX_ATTESTATION_BYTES` is a chain that could not run: refused at
    /// build time, with the boundary itself pinned (quorum 245 fits a
    /// 16,360-byte attestation, quorum 246 needs 16,426).
    #[test]
    fn an_oversized_guardian_set_is_refused() {
        let key = |i: usize| {
            let mut k = [0u8; 20];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            k[19] = 1; // never the zero key
            k
        };
        let mut g = genesis(1);
        let mut cfg = bridge_cfg();
        cfg.guardians = (0..368).map(key).collect();
        g.bridge = Some(cfg);
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        match g.build(&StubExecutor) {
            Err(GenesisError::BadBridgeConfig(m)) => {
                assert!(m.contains("too large"), "{m}");
                assert!(m.contains("368"), "{m}");
            }
            other => panic!("expected BadBridgeConfig, got {other:?}"),
        }
        // The largest set whose quorum attestation still fits is accepted:
        // quorum(367) = 245, so the attestation is 6 + 66*245 + 51 + 133 = 16,360 bytes.
        let mut g = genesis(1);
        let mut cfg = bridge_cfg();
        cfg.guardians = (0..367).map(key).collect();
        cfg.pq_guardians = (0..367).map(synthetic_pq_key).collect();
        g.bridge = Some(cfg);
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        assert!(g.build(&StubExecutor).is_ok(), "367 guardians is the largest runnable set");
    }

    /// The RPL gate is opt-in per chain, like `bridge` and `aggregation`: a genesis without a
    /// `tokens` section builds a chain whose registry is `None` and whose file never mentions
    /// one; one with a section — even an empty one — is a different chain, with a different
    /// state root.
    #[test]
    fn a_tokens_section_is_the_only_thing_that_changes_a_chain() {
        let plain = base_genesis();
        let s = build(&plain);
        assert!(s.ledger.tokens().is_none());
        assert!(!plain.to_json().contains("tokens"));
        let mut tok = plain.clone();
        tok.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        tok.alloc = opened_alloc();
        let st = build(&tok);
        assert_ne!(st.ledger.state_root(), s.ledger.state_root());
        assert_ne!(st.hash(), s.hash(), "and so is the genesis hash");
    }

    /// The genesis hash commits to a listed token's 32 *bytes*, not to the hex string its serde
    /// renders: `TokensCommit` is the plain-bytes twin `BridgeCommit` is for the bridge section.
    /// Without it a one-byte change to a token address that happens to keep the same hex length
    /// would still move the hash — bincode of a `String` does commit to its contents — but the
    /// bytes covered would be the file's text rather than the chain's state, and a file written
    /// with upper-case hex would hash as a different chain while building the identical one.
    #[test]
    fn the_genesis_hash_commits_to_a_listed_tokens_bytes_not_its_hex() {
        let listing = |token: [u8; 32]| TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![GenesisToken {
                name: "Tether USD".into(),
                symbol: "zUSDT".into(),
                salt: [0x55; 32],
                backings: vec![GenesisBacking { chain: 2, token, decimals: BRIDGE_DECIMALS }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000,
        };
        let mut g = base_genesis();
        g.alloc = opened_alloc();
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(listing([0x11; 32]));
        let base = build(&g).hash();

        // One byte of a backing's token address, and the genesis is a different chain.
        let mut other_token = g.clone();
        other_token.tokens = Some(listing({
            let mut t = [0x11; 32];
            t[31] = 0x12;
            t
        }));
        assert_ne!(build(&other_token).hash(), base, "a backing's token byte is committed");
        // So are the rest of a listing's fields and the fee. (Chain 3 needs an emitter to be a
        // usable backing at all, so this variant registers one.)
        let mut other_chain = g.clone();
        other_chain.bridge.as_mut().unwrap().emitters.insert(3, [3; 32]);
        other_chain.tokens.as_mut().unwrap().tokens[0].backings[0].chain = 3;
        assert_ne!(build(&other_chain).hash(), base);
        let mut other_symbol = g.clone();
        other_symbol.tokens.as_mut().unwrap().tokens[0].symbol = "zUSDC".into();
        assert_ne!(build(&other_symbol).hash(), base);
        let mut other_name = g.clone();
        other_name.tokens.as_mut().unwrap().tokens[0].name = "Tether".into();
        assert_ne!(build(&other_name).hash(), base);
        let mut other_salt = g.clone();
        other_salt.tokens.as_mut().unwrap().tokens[0].salt = [0x56; 32];
        assert_ne!(build(&other_salt).hash(), base, "the salt, which is what the asset id is over");
        let mut other_fee = g.clone();
        other_fee.tokens.as_mut().unwrap().registration_fee = MIN_REGISTRATION_FEE + 1;
        assert_ne!(build(&other_fee).hash(), base);
        // B1: the daily mint cap is committed, and it is the registry's cap from block 0.
        let mut other_cap = g.clone();
        other_cap.tokens.as_mut().unwrap().mint_cap_per_day += 1;
        assert_ne!(build(&other_cap).hash(), base, "the mint cap is committed");
        assert_eq!(build(&g).ledger.tokens().unwrap().mint_cap_per_day(), 100_000 * 100_000_000);
        assert_ne!(build(&other_cap).ledger.state_root(), build(&g).ledger.state_root(), "and in the state root");
        // …and the pause key (B1) is committed like every other bridge field.
        let mut other_pause = g.clone();
        other_pause.bridge.as_mut().unwrap().pause_key = Some(pq_key(9));
        assert_ne!(build(&other_pause).hash(), base, "the pause key is committed");
        // A bridged chain with a zero cap could never mint: refused at the file.
        let mut zero = g.clone();
        zero.tokens.as_mut().unwrap().mint_cap_per_day = 0;
        assert!(matches!(zero.validate(), Err(GenesisError::BadTokens(m)) if m.contains("mint_cap_per_day is zero")));
        // A second backing on the same token is a different chain too — the whole list is bound.
        let mut two = g.clone();
        two.bridge.as_mut().unwrap().emitters.insert(3, [3; 32]);
        two.tokens.as_mut().unwrap().tokens[0].backings.push(GenesisBacking { chain: 3, token: [0x33; 32], decimals: BRIDGE_DECIMALS });
        assert_ne!(build(&two).hash(), base, "a token's backing set is committed whole");

        // The twin is the bytes, not the text: the hex spelling is not what is hashed.
        let commit = TokensCommit::from(g.tokens.as_ref().unwrap());
        assert_eq!(commit.tokens[0].3, vec![(2u16, [0x11u8; 32], BRIDGE_DECIMALS)]);
        let bytes = bincode::serialize(&commit).unwrap();
        assert!(
            bytes.windows(32).any(|w| w == [0x11u8; 32]),
            "the 32 bytes themselves are in the commitment"
        );
        assert!(
            !bytes.windows(4).any(|w| w == b"1111"),
            "and their hex spelling is not"
        );

        // And a chain with no `tokens` section hashes exactly what it hashed before this section
        // existed: nothing is appended for it at all. The pin is the real guard — chain 13's own
        // genesis file, checked against its live hash by `rand-node`'s
        // `chain_13s_genesis_file_still_builds_chain_13`, which this cannot restate because this
        // fixture's `base_genesis` is not that file.
        let plain = base_genesis();
        assert!(!plain.to_json().contains("tokens"));
        assert_eq!(
            build(&plain).hash().to_hex(),
            "c3f27a29bfdf8abcfd4aaa24fadb127e34c4098cdacc09941a7e7ad3fa6b0b2c",
            "an unbridged, token-less chain's genesis hash is untouched by the RPL sections"
        );
    }

    /// A `bridge` section needs a `tokens` section (the RPL gate rides the same fork); and a
    /// listed token is registered `Bridge`-authority, at `BRIDGE_DECIMALS`, in file order.
    #[test]
    fn a_bridge_needs_tokens_and_listed_tokens_need_a_bridge_entry() {
        let mut g = base_genesis();
        g.alloc = opened_alloc();
        g.bridge = Some(bridge_cfg());
        assert!(matches!(g.validate(), Err(GenesisError::BridgeNeedsTokens)));
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![
                GenesisToken {
                    name: "Tether USD".into(),
                    symbol: "zUSDT".into(),
                    salt: [1; 32],
                    backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: BRIDGE_DECIMALS }],
                },
                GenesisToken {
                    name: "USD Coin".into(),
                    symbol: "zUSDC".into(),
                    salt: [2; 32],
                    backings: vec![GenesisBacking { chain: 2, token: [0x22; 32], decimals: BRIDGE_DECIMALS }],
                },
            ],
            mint_cap_per_day: 100_000 * 100_000_000,
        });
        assert!(g.validate().is_ok());
        let s = build(&g);
        let t = s.ledger.tokens().unwrap();
        assert_eq!((t.get(1).unwrap().symbol.as_str(), t.get(2).unwrap().symbol.as_str()), ("zUSDT", "zUSDC"));
        assert_eq!(t.get(1).unwrap().decimals, 8);
        assert_eq!(
            t.get(1).unwrap().authority,
            MintAuthority::Bridge { backings: vec![Backing { chain: 2, token: [0x11; 32], decimals: BRIDGE_DECIMALS, locked: 0, minted_today: 0, mint_day: 0 }] }
        );
        assert_eq!(t.get(1).unwrap().id, crate::ledger::tokens::bridged_asset_id("Tether USD", "zUSDT", &[1; 32]));
        assert_eq!(t.bridged(2, &[0x22; 32]).unwrap().index, 2, "each coin resolves to its own token");
        assert!(t.backing_invariant_holds(), "and nothing is locked yet");

        // A listed token with no `bridge` section has no chain to attest it.
        let mut no_bridge = base_genesis();
        no_bridge.tokens = g.tokens.clone();
        assert!(matches!(no_bridge.validate(), Err(GenesisError::BadTokens(_))));
    }

    /// A 32-byte hex string, as the real backings table (`chain14-zusd-backings.md`) and the
    /// genesis file itself spell a token address.
    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Chain 14's own listing (spec §12, bridge-06 2026-09-19's `chain14-zusd-backings.md`): one
    /// zUSD backed by USDT and USDC on Ethereum (2), BSC (3) and Solana (5), plus USDT on Tron
    /// (4) — Tron USDC is discontinued. Seven coins, one index, eight decimals for the *token*,
    /// and each backing's own **source** decimals — 6 on Ethereum, Tron and Solana, 18 on BSC,
    /// which is what makes this the release-unit rule's real fixture rather than a synthetic one.
    #[test]
    fn one_zusd_with_seven_backings_builds() {
        // The exact addresses and source decimals bridge-06 will whitelist, verbatim from
        // `chain14-zusd-backings.md`.
        let backings = vec![
            GenesisBacking { chain: 2, token: hex32("000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7"), decimals: 6 },
            GenesisBacking { chain: 2, token: hex32("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), decimals: 6 },
            GenesisBacking { chain: 3, token: hex32("00000000000000000000000055d398326f99059ff775485246999027b3197955"), decimals: 18 },
            GenesisBacking { chain: 3, token: hex32("0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d"), decimals: 18 },
            GenesisBacking { chain: 4, token: hex32("000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c"), decimals: 6 },
            GenesisBacking { chain: 5, token: hex32("ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264"), decimals: 6 },
            GenesisBacking { chain: 5, token: hex32("c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61"), decimals: 6 },
        ];
        let mut g = base_genesis();
        g.alloc = opened_alloc();
        let mut bridge = bridge_cfg();
        bridge.emitters = (2u16..=5).map(|c| (c, [c as u8; 32])).collect();
        g.bridge = Some(bridge);
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![GenesisToken {
                name: "Rand USD".into(),
                symbol: "zUSD".into(),
                salt: [0x5a; 32],
                backings: backings.clone(),
            }],
            mint_cap_per_day: 100_000 * 100_000_000,
        });
        assert!(g.validate().is_ok());
        let s = build(&g);
        let t = s.ledger.tokens().unwrap();
        assert_eq!(t.len(), 1, "one token, not seven");
        assert_eq!(t.get(1).unwrap().symbol, "zUSD");
        assert_eq!(t.get(1).unwrap().decimals, 8, "the token itself is always eight decimals");
        for b in &backings {
            assert_eq!(t.bridged(b.chain, &b.token).unwrap().index, 1, "chain {}", b.chain);
            let live = t.backing(1, b.chain, &b.token).unwrap();
            assert_eq!(live.locked, 0);
            assert_eq!(live.decimals, b.decimals, "the backing's own source decimals, chain {}", b.chain);
        }
        assert!(t.backing_invariant_holds());
        // Tron is the one chain with a single coin — Tron USDC is discontinued and is not listed,
        // so chain 4 has exactly one backing. Asked with Ethereum's *USDC* address, which is a
        // listed coin on chain 2 and nothing at all on chain 4, since a backing is the pair and
        // never the address alone.
        assert_eq!(backings.iter().filter(|b| b.chain == 4).count(), 1, "USDT only on Tron");
        assert!(t.bridged(4, &backings[1].token).is_none(), "Ethereum's USDC does not back anything on Tron");

        // A backing on a chain with no registered emitter could never be attested.
        let mut orphan = g.clone();
        orphan.tokens.as_mut().unwrap().tokens[0].backings.push(GenesisBacking { chain: 9, token: backings[0].token, decimals: 6 });
        match orphan.validate() {
            Err(GenesisError::BadTokens(m)) => assert!(m.contains("chain 9"), "{m}"),
            other => panic!("expected BadTokens, got {other:?}"),
        }
        // And the same coin cannot back two listed tokens, nor be listed twice on one.
        let mut twice = g.clone();
        twice.tokens.as_mut().unwrap().tokens.push(GenesisToken {
            name: "Copy USD".into(),
            symbol: "cUSD".into(),
            salt: [0x5b; 32],
            backings: vec![GenesisBacking { chain: 2, token: backings[0].token, decimals: 6 }],
        });
        match twice.validate() {
            Err(GenesisError::BadTokens(m)) => assert!(m.contains("duplicate backing"), "{m}"),
            other => panic!("expected BadTokens, got {other:?}"),
        }
        // Zero backings, and more than the cap.
        let mut none = g.clone();
        none.tokens.as_mut().unwrap().tokens[0].backings.clear();
        assert!(matches!(none.validate(), Err(GenesisError::BadTokens(m)) if m.contains("no backings")));
        let mut too_many = g.clone();
        let mut bridge = bridge_cfg();
        // Chains 2..=34: chain 0 is unassigned and chain 1 is Rand itself, neither of which may
        // be a source emitter.
        bridge.emitters = (2u16..=64).map(|c| (c, [c as u8; 32])).collect();
        too_many.bridge = Some(bridge);
        too_many.tokens.as_mut().unwrap().tokens[0].backings =
            (2..MAX_BACKINGS as u16 + 3).map(|i| GenesisBacking { chain: i, token: [i as u8; 32], decimals: BRIDGE_DECIMALS }).collect();
        match too_many.validate() {
            Err(GenesisError::BadTokens(m)) => assert!(m.contains("more than 32"), "{m}"),
            other => panic!("expected BadTokens, got {other:?}"),
        }
        // A backing whose declared decimals is over the maximum is refused at genesis, the
        // twin of `TokenRegistry::add_backing`'s own `BadBackingDecimals`.
        let mut bad_decimals = g.clone();
        bad_decimals.tokens.as_mut().unwrap().tokens[0].backings[0].decimals = MAX_BACKING_DECIMALS + 1;
        match bad_decimals.validate() {
            Err(GenesisError::BadTokens(m)) => assert!(m.contains("decimals"), "{m}"),
            other => panic!("expected BadTokens, got {other:?}"),
        }

        // A backing's decimals is state — the token leaf commits it, and `TokensCommit` carries it
        // beside the pair — so a file that changed only Ethereum USDT's 6 to 18 builds a
        // different chain, which is what stops a mis-declared coin being "corrected" in place
        // under a genesis hash operators have already pinned.
        let mut restated = g.clone();
        restated.tokens.as_mut().unwrap().tokens[0].backings[0].decimals = 18;
        let base = build(&g);
        let moved = build(&restated);
        assert_ne!(moved.hash(), base.hash(), "decimals is part of the genesis binding");
        assert_ne!(moved.ledger.state_root(), base.ledger.state_root(), "and of the token leaf");
    }

    /// `GenesisToken` denies unknown fields, like its child `GenesisBacking` always has: a stray
    /// or legacy key — such as a single-backing `chain` left over from before a token could have
    /// many — is refused rather than silently ignored, which is what would otherwise let a typo'd
    /// or half-migrated genesis file build a chain nobody meant to build.
    #[test]
    fn a_genesis_token_with_a_stray_field_is_refused() {
        let mut g = base_genesis();
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![GenesisToken {
                name: "Tether USD".into(),
                symbol: "zUSDT".into(),
                salt: [1; 32],
                backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: 6 }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000,
        });
        assert!(g.validate().is_ok(), "the well-formed file parses and validates");
        let mut v = serde_json::to_value(&g).unwrap();
        v["tokens"]["tokens"][0].as_object_mut().unwrap().insert("chain".into(), serde_json::json!(2));
        assert!(
            Genesis::from_json(&v.to_string()).is_err(),
            "a stray `chain` key beside `backings` is refused, not silently dropped"
        );
    }

    /// `registration_fee` has to be a fee a chain can actually run at, and the same `(chain,
    /// token)` pair cannot be listed twice — it is one `AssetId` either way
    /// (`crate::bridge::asset_id`), so a second listing can only ever collide.
    #[test]
    fn registration_fee_bounds_and_duplicate_listings_are_refused() {
        let mut g = base_genesis();
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE - 1, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
        g.tokens = Some(TokensConfig { registration_fee: MAX_REGISTRATION_FEE + 1, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        assert!(g.validate().is_ok());

        let dup = GenesisToken {
            name: "A".into(),
            symbol: "A".into(),
            salt: [3; 32],
            backings: vec![GenesisBacking { chain: 2, token: [1; 32], decimals: BRIDGE_DECIMALS }],
        };
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![dup.clone(), dup], mint_cap_per_day: 100_000 * 100_000_000 });
        assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
    }

    /// Phase S2: genesis seeds the register with each validator's payout address and fixes the
    /// epoch length. Both are part of the genesis binding; the payout is also part of the state,
    /// because it sits in the validator leaf the state root covers.
    #[test]
    fn genesis_seeds_payout_and_epoch_blocks() {
        let g = genesis(1);
        let s = build(&g);
        assert_eq!(s.epoch_blocks, EPOCH_BLOCKS_DEFAULT);
        assert_eq!(s.ledger.epoch_blocks(), EPOCH_BLOCKS_DEFAULT, "the ledger derives epochs with it");

        // The register starts as one entry per genesis validator, with the file's payout.
        let addr = g.validators[0].public_key.address();
        let e = &s.ledger.validators()[&addr];
        assert_eq!(e.stake, MIN_STAKE, "the genesis stake, narrowed to the register's u64");
        assert_eq!((e.rewards, e.nonce, e.pending.len()), (0, 0, 0));
        assert_eq!(e.payout, ShieldedAddress::parse(&g.validators[0].payout).unwrap());

        let mut faster = g.clone();
        faster.epoch_blocks = 4;
        let sf = build(&faster);
        assert_eq!(sf.epoch_blocks, 4);
        assert_eq!(sf.ledger.epoch_blocks(), 4);
        assert_ne!(sf.hash(), s.hash(), "epoch_blocks is part of the genesis binding");
        assert_eq!(sf.ledger.state_root(), s.ledger.state_root(), "and is not state");

        let mut paid = g.clone();
        paid.validators[0].payout = payout(9);
        let sp = build(&paid);
        assert_ne!(sp.hash(), s.hash(), "the payout address is bound");
        assert_ne!(sp.ledger.state_root(), s.ledger.state_root(), "and it is state, in the validator leaf");

        // The payout is required and must be a shielded address.
        let mut without = serde_json::to_value(&g).unwrap();
        without["validators"][0].as_object_mut().unwrap().remove("payout");
        assert!(Genesis::from_json(&without.to_string()).is_err(), "payout has no default");
        let mut bad = g.clone();
        bad.validators[0].payout = "rand1nonsense".into();
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadPayout(_))));

        assert!(g.to_json().contains("\"payout\""));
        assert!(g.to_json().contains("\"epoch_blocks\""));
        let mut old = serde_json::to_value(&g).unwrap();
        old.as_object_mut().unwrap().remove("epoch_blocks");
        assert_eq!(Genesis::from_json(&old.to_string()).unwrap().epoch_blocks, EPOCH_BLOCKS_DEFAULT);
    }

    /// `epoch(h) = h / epoch_blocks`, so a genesis file has to name a divisor the chain can
    /// actually use. Rejected at the one place that reads the file, not at the first division.
    #[test]
    fn epoch_blocks_must_be_a_usable_divisor() {
        let g = genesis(1);
        for bad in [0, MAX_EPOCH_BLOCKS + 1, u64::MAX] {
            let mut broken = g.clone();
            broken.epoch_blocks = bad;
            match broken.build(&StubExecutor) {
                Err(GenesisError::BadEpochBlocks(n)) => assert_eq!(n, bad),
                other => panic!("expected BadEpochBlocks for {bad}, got {other:?}"),
            }
        }
        // The edges that are fine: one block per epoch, and the cap itself.
        for ok in [1, EPOCH_BLOCKS_DEFAULT, MAX_EPOCH_BLOCKS] {
            let mut fine = g.clone();
            fine.epoch_blocks = ok;
            let s = build(&fine);
            assert_eq!(s.epoch_blocks, ok);
            assert_eq!(s.ledger.epoch_blocks(), ok);
        }
    }

    /// v0.4's program cap is opt-in per chain, like the bridge and aggregation sections: a file
    /// without `max_program_words` is today's file, builds today's hash and runs today's 4 096-word
    /// cap; a file with it is a different chain (the binding is the field's *presence*, so even
    /// spelling out the default moves the hash) whose ledger runs the cap it names. It is a
    /// genesis parameter, not state, so the state root never sees it.
    #[test]
    fn max_program_words_is_optional_and_bound_into_the_hash_only_when_present() {
        let plain = genesis(2);
        assert_eq!(plain.max_program_words, None);
        assert!(!plain.to_json().contains("max_program_words"), "an absent cap is absent from the file");
        let s = build(&plain);
        assert_eq!(s.ledger.max_program_words(), crate::gas::MAX_PROGRAM_WORDS, "absent means the old cap");
        // A file written before the field existed parses to `None` and builds the same chain.
        let old = Genesis::from_json(&plain.to_json()).unwrap();
        assert_eq!(old.max_program_words, None);
        assert_eq!(build(&old).hash(), s.hash());

        let mut raised = plain.clone();
        raised.max_program_words = Some(65_535);
        let r = build(&raised);
        assert_eq!(r.ledger.max_program_words(), 65_535, "the ledger runs the cap genesis names");
        assert_ne!(r.hash(), s.hash(), "a raised cap is a different chain");
        assert_eq!(r.ledger.state_root(), s.ledger.state_root(), "the cap is a parameter, not state");
        assert!(raised.to_json().contains("\"max_program_words\": 65535"));
        assert_eq!(Genesis::from_json(&raised.to_json()).unwrap(), raised, "and it round-trips");

        let mut explicit = plain.clone();
        explicit.max_program_words = Some(crate::gas::MAX_PROGRAM_WORDS as u32);
        let e = build(&explicit);
        assert_eq!(e.ledger.max_program_words(), crate::gas::MAX_PROGRAM_WORDS);
        assert_ne!(e.hash(), s.hash(), "the binding is presence: spelling out the default is a new chain");
        assert_ne!(e.hash(), r.hash(), "and two caps are two chains");
    }

    /// The cap must be a program length the zkVM can prove: at least one word, and no more than
    /// the 16-bit word count the CPU AIR range-checks.
    #[test]
    fn max_program_words_must_be_a_provable_length() {
        let g = genesis(1);
        for bad in [0u32, crate::gas::MAX_PROGRAM_WORDS_LIMIT as u32 + 1, u32::MAX] {
            let mut broken = g.clone();
            broken.max_program_words = Some(bad);
            match broken.build(&StubExecutor) {
                Err(GenesisError::BadMaxProgramWords(n)) => assert_eq!(n, bad),
                other => panic!("expected BadMaxProgramWords for {bad}, got {other:?}"),
            }
        }
        for ok in [1u32, 4096, 18_009, crate::gas::MAX_PROGRAM_WORDS_LIMIT as u32] {
            let mut fine = g.clone();
            fine.max_program_words = Some(ok);
            assert_eq!(build(&fine).ledger.max_program_words(), ok as usize);
        }
    }

    /// `g` with one of the four call-limits parameters (spec §3) set, by name.
    fn with_limit(g: &Genesis, field: &str, v: u32) -> Genesis {
        let mut g = g.clone();
        match field {
            "max_proof_bytes" => g.max_proof_bytes = Some(v),
            "max_block_bytes" => g.max_block_bytes = Some(v),
            "max_call_envelope_bytes" => g.max_call_envelope_bytes = Some(v),
            "max_program_public_words" => g.max_program_public_words = Some(v),
            _ => unreachable!(),
        }
        g
    }

    /// The four call-limits parameters are opt-in per chain, like `max_program_words`: absent,
    /// the file and the hash are today's and the ledger runs today's caps; present, each is
    /// bound into the hash by name (so even the default spelled out is a new chain), the ledger
    /// runs it, and the state root never sees it.
    #[test]
    fn the_call_limits_are_optional_and_bound_into_the_hash_only_when_present() {
        let plain = genesis(2);
        let s = build(&plain);
        let json = plain.to_json();
        for name in ["max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"] {
            assert!(!json.contains(name), "an absent {name} is absent from the file");
        }
        assert_eq!(s.ledger.max_proof_bytes(), crate::gas::MAX_PROOF_BYTES);
        assert_eq!(s.ledger.max_block_bytes(), crate::gas::MAX_BLOCK_BYTES);
        assert_eq!(s.ledger.max_call_envelope_bytes(), crate::types::actions::MAX_CALL_ENVELOPE_BYTES);
        assert_eq!(s.ledger.max_program_public_words(), crate::gas::MAX_PROGRAM_PUBLIC_WORDS);
        assert_eq!(crate::gas::MAX_PROGRAM_PUBLIC_WORDS, 0, "no public input is today's behaviour");
        let old = Genesis::from_json(&json).unwrap();
        assert_eq!(build(&old).hash(), s.hash(), "a file without the fields builds the same chain");

        // Chain 13's values (spec §3), all four at once.
        let mut c13 = plain.clone();
        c13.max_program_words = Some(65_535);
        c13.max_proof_bytes = Some(8 << 20);
        c13.max_block_bytes = Some(20 << 20);
        c13.max_call_envelope_bytes = Some(65_536);
        c13.max_program_public_words = Some(32_768);
        let c = build(&c13);
        assert_eq!(c.ledger.max_proof_bytes(), 8 << 20);
        assert_eq!(c.ledger.max_block_bytes(), 20 << 20);
        assert_eq!(c.ledger.max_call_envelope_bytes(), 65_536);
        assert_eq!(c.ledger.max_program_public_words(), 32_768);
        assert_eq!(c.ledger.state_root(), s.ledger.state_root(), "the limits are parameters, not state");
        assert_eq!(Genesis::from_json(&c13.to_json()).unwrap(), c13, "and they round-trip");
        assert!(c13.to_json().contains("\"max_proof_bytes\": 8388608"));
        // A reloaded clone keeps them.
        assert_eq!(c.ledger.clone().max_block_bytes(), 20 << 20);

        // Each field alone, at its default and at another value: every one is a different chain,
        // from the plain one and from each other.
        let cases: [(&str, u32, u32); 4] = [
            ("max_proof_bytes", 1 << 20, 3 << 19),
            // 5 MiB is the smallest block the default 2 MiB proof cap allows (2 · 2 + 1).
            ("max_block_bytes", 5 << 20, 8 << 20),
            ("max_call_envelope_bytes", 18_432, 65_536),
            ("max_program_public_words", 0, 32_768),
        ];
        let mut hashes = vec![s.hash(), c.hash()];
        for (name, a, b) in cases {
            for v in [a, b] {
                let built = build(&with_limit(&plain, name, v));
                let h = built.hash();
                assert!(!hashes.contains(&h), "{name} = {v} must be its own chain");
                hashes.push(h);
                assert_eq!(built.ledger.state_root(), s.ledger.state_root());
            }
        }
        assert_eq!(build(&with_limit(&plain, "max_proof_bytes", 1 << 20)).ledger.max_proof_bytes(), 1 << 20);
        assert_eq!(build(&with_limit(&plain, "max_block_bytes", 8 << 20)).ledger.max_block_bytes(), 8 << 20);
        assert_eq!(build(&with_limit(&plain, "max_call_envelope_bytes", 65_536)).ledger.max_call_envelope_bytes(), 65_536);
        assert_eq!(build(&with_limit(&plain, "max_program_public_words", 7)).ledger.max_program_public_words(), 7);
    }

    /// Each limit's bounds (spec §3), and the block rule: a block must hold two worst-case
    /// proofs — the fee bundle's and the call's — plus 1 MiB for everything else, judged on the
    /// effective proof cap (the default when the file leaves it out).
    #[test]
    fn the_call_limits_are_refused_out_of_bounds() {
        let g = genesis(1);
        let refused = |g: &Genesis| g.build(&StubExecutor).err();

        for bad in [0u32, (1 << 20) - 1, (32 << 20) + 1, u32::MAX] {
            let mut b = with_limit(&g, "max_proof_bytes", bad);
            b.max_block_bytes = Some(64 << 20);
            assert!(matches!(refused(&b), Some(GenesisError::BadMaxProofBytes(n)) if n == bad), "proof {bad}");
        }
        // 32 MiB is inside the proof bound itself; the block rule, not this one, is what refuses
        // it with a 64 MiB block (below). Checked here against the bound alone.
        for ok in [1u32 << 20, 3 << 20, 63 << 19] {
            let mut o = with_limit(&g, "max_proof_bytes", ok);
            o.max_block_bytes = Some(64 << 20);
            assert_eq!(build(&o).ledger.max_proof_bytes(), ok as usize);
        }
        let mut top = with_limit(&g, "max_proof_bytes", 32 << 20);
        top.max_block_bytes = Some(64 << 20);
        assert!(matches!(refused(&top), Some(GenesisError::BadMaxBlockBytes(_))), "32 MiB passes the proof bound");

        for bad in [0u32, (4 << 20) - 1, (64 << 20) + 1, u32::MAX] {
            let mut b = with_limit(&g, "max_block_bytes", bad);
            b.max_proof_bytes = Some(1 << 20);
            assert!(matches!(refused(&b), Some(GenesisError::BadMaxBlockBytes(n)) if n == bad), "block {bad}");
        }
        for ok in [4u32 << 20, 20 << 20, 64 << 20] {
            let mut o = with_limit(&g, "max_block_bytes", ok);
            o.max_proof_bytes = Some(1 << 20);
            assert_eq!(build(&o).ledger.max_block_bytes(), ok as usize);
        }

        // The block rule: block >= 2 * proof + 1 MiB.
        let pair = |proof: Option<u32>, block: Option<u32>| {
            let mut p = g.clone();
            p.max_proof_bytes = proof;
            p.max_block_bytes = block;
            p
        };
        // Chain 13: 8 MiB proofs need 17 MiB of block; 20 MiB passes, 17 MiB exactly passes,
        // one byte under refuses.
        assert!(pair(Some(8 << 20), Some(20 << 20)).build(&StubExecutor).is_ok());
        assert!(pair(Some(8 << 20), Some(17 << 20)).build(&StubExecutor).is_ok());
        assert!(matches!(
            refused(&pair(Some(8 << 20), Some((17 << 20) - 1))),
            Some(GenesisError::BadMaxBlockBytes(n)) if n == (17 << 20) - 1
        ));
        // A raised proof cap with the block cap left at its 4 MiB default is refused.
        assert!(matches!(refused(&pair(Some(8 << 20), None)), Some(GenesisError::BadMaxBlockBytes(n)) if n == 4 << 20));
        // A block cap given alone is judged against the default 2 MiB proof cap: 5 MiB is the floor.
        assert!(matches!(refused(&pair(None, Some(4 << 20))), Some(GenesisError::BadMaxBlockBytes(n)) if n == 4 << 20));
        assert!(pair(None, Some(5 << 20)).build(&StubExecutor).is_ok());
        // 32 MiB proofs need 65 MiB of block, past the 64 MiB ceiling: the largest proof cap a
        // chain can actually run is 31.5 MiB.
        assert!(matches!(refused(&pair(Some(32 << 20), Some(64 << 20))), Some(GenesisError::BadMaxBlockBytes(_))));
        assert!(pair(Some(63 << 19), Some(64 << 20)).build(&StubExecutor).is_ok());
        // Both absent: today's chain, where the 4 MiB block predates the rule, is untouched.
        assert!(pair(None, None).build(&StubExecutor).is_ok());

        for bad in [0u32, 18_431, (1 << 20) + 1, u32::MAX] {
            assert!(
                matches!(refused(&with_limit(&g, "max_call_envelope_bytes", bad)), Some(GenesisError::BadMaxCallEnvelopeBytes(n)) if n == bad),
                "envelope {bad}"
            );
        }
        for ok in [18_432u32, 65_536, 1 << 20] {
            assert_eq!(build(&with_limit(&g, "max_call_envelope_bytes", ok)).ledger.max_call_envelope_bytes(), ok as usize);
        }

        for bad in [65_536u32, u32::MAX] {
            assert!(
                matches!(refused(&with_limit(&g, "max_program_public_words", bad)), Some(GenesisError::BadMaxProgramPublicWords(n)) if n == bad),
                "public {bad}"
            );
        }
        for ok in [0u32, 1, 27_151, 65_535] {
            assert_eq!(build(&with_limit(&g, "max_program_public_words", ok)).ledger.max_program_public_words(), ok as usize);
        }
    }

    #[test]
    fn json_roundtrip_and_deterministic_hash() {
        let g = genesis(2);
        let js = g.to_json();
        let g2 = Genesis::from_json(&js).unwrap();
        assert_eq!(g, g2);
        let s1 = build(&g);
        let s2 = build(&g2);
        assert_eq!(s1.hash(), s2.hash());
        assert_eq!(s1.validators.len(), 2);
        assert_eq!(s1.ledger.validators().len(), 2);
        assert_eq!(s1.block.header.state_root, s1.ledger.state_root());
    }

    #[test]
    fn different_chain_id_changes_genesis_hash() {
        let a = genesis(1);
        let mut b = genesis(1);
        b.chain_id = 43;
        assert_ne!(build(&a).hash(), build(&b).hash());
    }

    #[test]
    fn rejects_bad_validators() {
        let mut g = genesis(1);
        g.validators.clear();
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::NoValidators)));
        let mut g = genesis(1);
        g.validators[0].stake = 0;
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::ZeroStake(_))));
        // A validator the staking rules would leave out of every epoch's set: in the register,
        // in no validator set, and — if every validator were like it — no set at all.
        let mut g = genesis(1);
        g.validators[0].stake = MIN_STAKE as u128 - 1;
        match g.build(&StubExecutor) {
            Err(GenesisError::BelowMinStake { stake, min, .. }) => {
                assert_eq!((stake, min), (MIN_STAKE as u128 - 1, MIN_STAKE))
            }
            other => panic!("expected BelowMinStake, got {other:?}"),
        }
        let mut g = genesis(1);
        g.validators[0].stake = MIN_STAKE as u128;
        assert!(g.build(&StubExecutor).is_ok(), "the minimum itself is enough");
        let mut g = genesis(2);
        g.validators.push(g.validators[0].clone());
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::DuplicateValidator(_))));
        // The register holds a u64 (spec §8), so a genesis stake that cannot be one is refused
        // here rather than silently narrowed into a different chain. (It also replaces S1's
        // total-stake overflow check: a set of u64 stakes cannot overflow the u128 total.)
        let mut g = genesis(2);
        g.validators[0].stake = u128::MAX;
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::StakeTooLarge(_))));
        let mut g = genesis(1);
        g.validators[0].stake = u64::MAX as u128 + 1;
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::StakeTooLarge(_))));
    }

    /// Audit v4, STAKE-2 rule 1: with the `staking` section on, a faucet and a bridge exclude
    /// each other — a free mint against a chain holding bridged custody is what the finding is
    /// about. Chain 14's genesis has both and no section, so it still loads, hashes and builds
    /// exactly as before; the section itself is bound into the genesis hash by name.
    #[test]
    fn a_genesis_with_faucet_and_bridge_is_refused_once_staking_rules_are_on() {
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        g.faucet = true;
        assert!(g.validate().is_ok(), "chain 14's shape still loads");
        let unsectioned = build(&g);
        assert!(unsectioned.ledger.staking().is_none());
        assert!(!g.to_json().contains("staking"), "and its file never mentions the section");
        let cfg = StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2 };
        g.staking = Some(cfg.clone());
        assert!(matches!(g.validate(), Err(GenesisError::FaucetWithBridge)), "{:?}", g.validate());
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::FaucetWithBridge)));
        // Either half alone is fine under the section.
        let mut faucet_only = genesis(1);
        faucet_only.faucet = true;
        faucet_only.staking = Some(cfg.clone());
        let s = build(&faucet_only);
        assert_eq!(s.ledger.staking(), Some(&cfg), "the ledger runs with the section");
        assert_eq!(s.staking, Some(cfg.clone()));
        g.faucet = false;
        assert!(g.validate().is_ok(), "a bridged chain without a faucet");
        assert!(build(&g).ledger.staking().is_some());
        // The section is part of the genesis binding, by name, and the file round-trips it
        // with the budget as a decimal string (every amount in a genesis file is).
        let plain = genesis(1);
        let mut sectioned = plain.clone();
        sectioned.staking = Some(cfg.clone());
        assert_ne!(build(&sectioned).hash(), build(&plain).hash());
        let mut other_budget = sectioned.clone();
        other_budget.staking.as_mut().unwrap().faucet_budget_per_epoch += 1;
        assert_ne!(build(&other_budget).hash(), build(&sectioned).hash());
        let mut other_delay = sectioned.clone();
        other_delay.staking.as_mut().unwrap().bond_activation_epochs += 1;
        assert_ne!(build(&other_delay).hash(), build(&sectioned).hash());
        let json = sectioned.to_json();
        assert!(json.contains("\"faucet_budget_per_epoch\": \"100000000000\""), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), sectioned);
        // And the state root domain moved with the section (`rand-state-5`), not without it.
        assert_ne!(build(&sectioned).ledger.state_root(), build(&plain).ledger.state_root());
        assert_eq!(
            build(&plain).ledger.state_root().to_hex(),
            "e845c110b5e366acf87806cb7f09cc212ad47008cac7cafbd141c30da4c738d4",
            "the pin `a_bridge_section_is_accepted_and_only_a_bridged_chain_changes` guards, unchanged"
        );
    }
}
