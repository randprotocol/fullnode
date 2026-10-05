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
/// `Word8`s), and its `asset` word. `from` is the zero word, exactly as every other note the
/// *chain* computes — the faucet mint (`ledger::mint_commitment`), a bridge deposit
/// (`bridge_notes::deposit_commitment`), a withdraw, an aggregate payout — so it is not written
/// down here.
///
/// `asset` is 0 — RAND — unless the file says otherwise, and is then left out of the file, so
/// every opening written before it existed means what it always meant. A non-zero `asset` is the
/// registry index of a bridged token **this genesis lists** (the first listed token is index 1):
/// the note is genesis supply of that token, and `Genesis::validate` holds each listed token's
/// genesis notes to exactly the `locked` its backings start with, so custody and supply agree
/// from block 0. Such a note is a deposit in all but the attestation — its commitment is the
/// deposit commitment at that index — and it never counts toward the RAND supply.
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
    /// The note's `asset` word: 0 (RAND, and absent from the file) or the index of a token the
    /// `tokens` section lists.
    #[serde(default, skip_serializing_if = "is_rand_asset")]
    pub asset: u32,
}

fn is_rand_asset(asset: &u32) -> bool {
    *asset == 0
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
    /// What this backing starts the chain holding locked, in the *token's* eight-decimal units
    /// (like `mint_cap_per_day`) — the custody a source contract already holds when a chain is
    /// cut from another one's state (chain 15 from chain 14). Applied by `Genesis::build` through
    /// [`TokenRegistry::lock`] itself, so the token's `total_supply` moves with it and
    /// `total_supply == Σ locked` holds by the same code path a deposit takes; the token's genesis
    /// notes (a [`GenesisOpening::asset`] naming it) must sum to exactly its backings' `locked`.
    /// Absent — every chain before 15 — is zero and changes nothing. It is bound to the genesis
    /// hash through the state root (a backing's `locked` is in its token's leaf, and the genesis
    /// header commits the root), so two files that differ only in it build different chains;
    /// `TokensCommit` leaves it out so chain 14's commitment keeps its bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked: Option<u64>,
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
    /// Audit v4 (TOK-1): the most tokens the registry may ever hold — `RegisterToken` and
    /// `RegisterBridgedToken` are refused `RegistryFull` at it. Absent (chain 14) is today's
    /// `u32::MAX`; when present it is committed under its own tag (`b"max_tokens"` ‖ value, only
    /// then) and folded into the token root, and must be at least one and at least the number of
    /// tokens this section lists. The registry root stays O(tokens); the cap is what bounds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Audit v5 (TOK-2): whether a `RegisterToken`'s or `RegisterBridgedToken`'s
    /// `registration_fee` is burned instead of paid to the block's proposer — so a proposer
    /// registering its own token pays the fee like anyone else. Absent (chain 14) or `false` is
    /// today's rule, the whole fee to the proposer; `true` is committed under its own tag
    /// (`b"burn_registration_fee"` ‖ `1`, only then), carried on the registry's extension (and
    /// so in the token root), and makes the ledger keep `fee − registration_fee` for the
    /// proposer and add `registration_fee` to `supply.burned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_registration_fee: Option<bool>,
    /// Deep scan 2026-09-24 (ledger arithmetic): whether the ledger refuses to create a note
    /// worth `MAX_NOTE_VALUE` (2^63) or more — the hidden-asset guest range-checks every value
    /// to u63, so such a note can never be spent — and holds every token's `total_supply` below
    /// it. Absent (chain 14) or `false` is today's rule: any `u64` mints or deposits; `true` is
    /// committed under its own tag (`b"bound_note_value"` ‖ `1`, only then), carried on the
    /// registry's extension (and so in the token root), and refuses such a `TokenMint`, initial
    /// mint or bridge deposit at validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_note_value: Option<bool>,
    /// Audit v6 (TOK-1, issue #86): whether the registry's root is an incremental merkle
    /// commitment over `rand-token-leaf-2` leaves (`rand-token-registry-4`, the state root
    /// re-domained `rand-state-tokens-1`) kept up to date leaf by leaf, with the node storing
    /// one row per token and rewriting only the rows a block changed — instead of re-hashing
    /// every token at every state root and rewriting the whole registry blob at every commit.
    /// Absent (every chain through 20) or `false` is today's root and store, byte for byte;
    /// `true` is committed under its own tag (`b"tokens_incremental_root"` ‖ `1`, after every
    /// tag that existed before it, only then), and switches the registry at `build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental_root: Option<bool>,
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
    pub tokens: Vec<TokenCommitRow>,
}

/// One token as the genesis hash commits to it: name, symbol, asset id and its backings, each
/// `(source chain, source token address, source decimals)`.
pub type TokenCommitRow = (String, String, [u8; 32], Vec<(u16, [u8; 32], u8)>);

impl From<&TokensConfig> for TokensCommit {
    /// Destructured on purpose, like [`BridgeCommit::from`]: a new [`TokensConfig`],
    /// [`GenesisToken`] or [`GenesisBacking`] field must not silently fall out of the genesis
    /// commitment — it has to break this conversion.
    ///
    /// `max_tokens`, `burn_registration_fee`, `bound_note_value` and `incremental_root` are
    /// destructured and deliberately *not* here, for `BridgeCommit`'s reason: an `Option` field
    /// in bincode would put a byte into chain 14's commitment. `Genesis::build` commits each
    /// under its own tag, only when present (the three flags only when `true`).
    fn from(cfg: &TokensConfig) -> TokensCommit {
        let TokensConfig {
            registration_fee,
            mint_cap_per_day,
            tokens,
            max_tokens: _,
            burn_registration_fee: _,
            bound_note_value: _,
            incremental_root: _,
        } = cfg;
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
                            // `locked` is bound through the state root instead (a backing's
                            // locked is in its token's leaf), so chain 14's bytes stay put.
                            let GenesisBacking { chain, token, decimals, locked: _ } = b;
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
pub use crate::ledger::staking::{FaucetMinter, FaucetRecipient, SlashingConfig, StakingConfig};
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
    /// absent), `3 · max_proof_bytes + 1 MiB` when `hc_auth` is set ([`gas::min_block_bytes`]).
    /// Absent means [`gas::MAX_BLOCK_BYTES`].
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
    /// Spec 2026-09-26 §2.4: every note envelope is exactly this many bytes (only `1860`, the
    /// memo layout, is accepted). Absent means today's rule — at most `MAX_ENVELOPE_BYTES` — and
    /// a genesis hash unchanged byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_bytes: Option<u32>,
    /// Genesis vesting (`docs/superpowers/specs/2026-09-28-genesis-vesting-design.md`): the
    /// timelocked allocations — team, investors, founding partners — the vesting register
    /// starts with. Part of the genesis hash and of the state root (`rand-state-6`) when
    /// present; omitted entirely when absent, so every chain without one hashes and commits
    /// byte-for-byte as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vesting: Option<crate::ledger::vesting::VestingConfig>,
    /// The v0.6 hardening switch (the 2026-09-27 zkVM/ISA review's R4: *one* activation for every
    /// stricter validity rule on a live path — its class H). `true` turns each of them from the
    /// node's pool policy into a validity rule, at admission and at apply alike; `Ledger::
    /// hardening_v6`'s doc comment lists them, and `docs/deploy.md` ("The next cut: hardening_v6")
    /// is the operator's list. The first was ZKV-11's pc window, which shipped on `feat/v0.6` as
    /// its own `program_pc_window` flag and was folded in here before any genesis carried it.
    /// Absent or `false` is the old rules, byte for byte (every node still refuses the same
    /// transactions at its pool, as policy, where old wallets allow). Part of the genesis hash,
    /// tagged, only when `true`, so chain 15's file hashes byte-for-byte as before; never part of
    /// the state root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardening_v6: Option<bool>,
    /// Split authorisation (delegated proving Phase 2, spec
    /// `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): the auth guest's
    /// program commitment, 64 hex characters. Present, every bundle must carry an auth proof of
    /// this guest publishing its `auth_commit`, and the bundle digest is the v3 one; `hc_bundle`
    /// must then be bundle guest v3, which the node checks at startup (core cannot name guests).
    /// Absent is today's rules, byte for byte. Part of the genesis hash, tagged and appended
    /// after `hardening_v6`, only when present — so chains 14, 15 and 16 hash as before; never
    /// part of the state root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hc_auth: Option<String>,
    /// The gas section (design 2026-09-28 §4.2, §4.3, §7.1): the chain's declared prices, the
    /// bundle guest's flat gas limit, the metering scheme, and (Phase 2) the dynamic price
    /// controller's parameters. A genesis parameter like `max_program_words`: outside the state
    /// root and `Ledger`'s equality, restored by `reload_ledger` on every restart. Absent from a
    /// chain cut before it — chain 15's file included — hashes byte-for-byte as before; present,
    /// it is bound into the genesis hash after `hardening_v6`. Read by the call floor (a validity
    /// rule: `Ledger::gas_call_floor`), the bundle's pinned `bundle_gas_limit`
    /// (`TxError::BundleGasLimit`) and, under `dynamic`, the per-block price controller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<gas::GasConfig>,
    /// Audit v6, STAKE-2 (§8.5 option 2): the explicit testnet marker. A genesis with `faucet:
    /// true` and a `bridge` section — free RAND beside real custody — is refused
    /// ([`GenesisError::FaucetWithBridgeNeedsTestnet`]) unless it says `"testnet": true` here;
    /// "mainnet never carries a faucet" was a sentence in `docs/deploy.md`, and this is the check.
    /// The chains cut before the marker existed and carry both (14–19,
    /// [`FAUCET_BESIDE_BRIDGE_CHAIN_IDS`]) are grandfathered by chain id, so their committed files
    /// still build. Committed to the genesis hash under its own tag, after every earlier one, only
    /// when `true` (`false` commits nothing, like `hardening_v6`); on the ledger as a parameter
    /// (`Ledger::testnet`, restored by `reload_ledger`), never state; served as `testnet` by
    /// `rand_status` and `rand_getLimits` so a wallet and an explorer can show it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub testnet: Option<bool>,
    /// BIND-1 (audit v6, issue #79): what every transaction binding and every signed action
    /// message on this chain is over ([`crate::types::BindingDomain`]). Absent — chains 14 to 19 —
    /// or `0`: the chain id alone, exactly the messages those chains' wallets prove and sign. `1`:
    /// the genesis hash enters every one under a fresh tag (`rand-tx-bind-2`, `rand-call-bind-2`,
    /// the faucet mint's, `Unbond`'s, `Withdraw`'s, the RPL token messages', the aggregator
    /// actions' and the bridge governance messages' `-N+1` tags), so a proof or a signature made
    /// for this chain verifies on no other chain, whatever its chain id. Part of the genesis hash,
    /// tagged and appended after `gas`, only when present — a file without it hashes byte-for-byte
    /// as before; never part of the state root (a genesis parameter `reload_ledger` restores).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_domain: Option<u32>,
    /// Issue #118: one window, in blocks, for both of a bundle's freshness rules — how far
    /// behind the height its `time` may be and how many block-end roots it may anchor to
    /// (`ledger::TIME_WINDOW` and `ledger::ANCHOR_WINDOW`, both 256, which exist for the same
    /// reason: a prover needs the chain to still accept what it started proving). 256 blocks is
    /// ~300 s at chain 18's 1.17 s blocks, and a delegated proof on a slow prover was refused at
    /// 294 s. Absent — chains 14 to 19 — is 256/256 byte for byte; present, it must lie in
    /// `[MIN_PROOF_WINDOW_BLOCKS, MAX_PROOF_WINDOW_BLOCKS]` = `[256, 4096]`. Part of the genesis
    /// hash, tagged and appended after `bridge_rotation`, only when present; never part of the
    /// state root (a genesis parameter `reload_ledger` restores).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_window_blocks: Option<u64>,
    /// RPL-2 (design 2026-09-30): program state, program vaults and the `Invoke` action. Present,
    /// it switches on the `program_state` ledger module with an empty state, lets a token name a
    /// program as its mint authority, appends the program-state root to the state root
    /// (`rand-state-8`) and is bound into the genesis hash last, after `proof_window_blocks`. It requires
    /// `tokens`, `gas`, `hardening_v6` and `hc_auth`. Absent — every chain cut before it — the
    /// genesis hashes byte-for-byte as before and every `Invoke` is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_state: Option<crate::ledger::program_state::ProgramStateConfig>,
    /// The fee-feedback rules (`ledger::fees`, `docs/fees.md` §1.3): `burn_base` destroys every
    /// bundle's `BUNDLE_BASE` instead of paying it, `subsidy_net_of_fees` pays an aggregate's
    /// subsidy from its proving shares first (it needs `aggregation`,
    /// [`GenesisError::SubsidyNetOfFeesWithoutAggregation`]), and `burn_floor` widens the burned
    /// base to the bundle's whole settled floor (issue #135; it needs `burn_base`,
    /// [`GenesisError::BurnFloorWithoutBurnBase`]). Absent — every chain cut before it —
    /// or present with no `true` flag, the genesis hashes and the chain runs byte for byte as
    /// before; a `true` flag is bound into the genesis hash right after the `tokens` section
    /// ([`fees_commit`]). Never part of the state root (a genesis parameter `reload_ledger`
    /// restores).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fees: Option<crate::ledger::fees::FeesConfig>,
}

/// The chains whose committed genesis file (`deploy/genesis-chain<N>.json`) carries both
/// `faucet: true` and a `bridge` section and predates the `testnet` marker (audit v6, STAKE-2):
/// chain 14 (no `staking` section at all) and chains 15–19 (a section with a faucet allowlist;
/// chain 19 was cut on v0.6.7, 2026-10-01, after this list was written).
/// `Genesis::validate` exempts exactly these chain ids from
/// [`GenesisError::FaucetWithBridgeNeedsTestnet`], so every one of those files still validates
/// and builds its pinned hash — `every_committed_genesis_file_still_validates` walks them — and
/// every later chain id must carry the marker. The pattern of
/// `randprotocol_client::LEGACY_ENVELOPE_CHAIN_IDS` and `node::CHAINS_THIS_BUILD_CANNOT_RUN`: a
/// named list, never a rule that reads the file's own shape, so a new chain cannot slip in by
/// looking like an old one. Add nothing here: a chain cut on a build that has the marker says `testnet: true`.
pub const FAUCET_BESIDE_BRIDGE_CHAIN_IDS: &[u64] = &[14, 15, 16, 17, 18, 19];

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
    #[error("unknown binding_domain {0} (0 or 1)")]
    BadBindingDomain(u32),
    /// Issue #118: a `proof_window_blocks` outside `[MIN_PROOF_WINDOW_BLOCKS,
    /// MAX_PROOF_WINDOW_BLOCKS]`.
    #[error(
        "bad proof_window_blocks {0} ({min}..={max})",
        min = crate::ledger::MIN_PROOF_WINDOW_BLOCKS,
        max = crate::ledger::MAX_PROOF_WINDOW_BLOCKS
    )]
    BadProofWindowBlocks(u64),
    /// Audit v4, STAKE-2 rule 1: under a `staking` section a chain that holds bridged custody
    /// cannot also hand out free RAND — unless `staking.faucet_recipients` limits the faucet to
    /// named spend keys.
    #[error("a staking section refuses a faucet on a bridged chain (faucet: true with a bridge section) unless staking.faucet_recipients limits it")]
    FaucetWithBridge,
    /// Audit v6, STAKE-2 (option 2): a faucet beside a bridge, on a chain id not in
    /// [`FAUCET_BESIDE_BRIDGE_CHAIN_IDS`], without the explicit `testnet: true` marker. A mainnet
    /// genesis cannot carry a faucet, and a testnet that needs both has to say so.
    #[error("chain {chain_id} has faucet: true beside a bridge section and no \"testnet\": true marker: a chain holding custody hands out no free RAND unless its genesis says it is a testnet")]
    FaucetWithBridgeNeedsTestnet { chain_id: u64 },
    /// A `staking` section field no chain could run: a weight cap outside `1..=10000` basis
    /// points, a zero entry budget (nothing would ever become weight), or an empty or duplicated
    /// faucet allowlist.
    #[error("bad staking config: {0}")]
    BadStaking(String),
    /// The `vesting` section breaks one of `VestingConfig::check`'s rules.
    #[error("bad vesting config: {0}")]
    BadVesting(String),
    /// The `gas` section breaks one of `GasConfig::check`'s rules.
    #[error("bad gas config: {0}")]
    Gas(String),
    /// The `program_state` section is out of bounds, or a section it depends on is missing.
    #[error("bad program_state config: {0}")]
    BadProgramState(String),
    /// Controller ruling (task B6): the byte price is driven by Σ `encoded_len` over a block as
    /// served, and a pruned bundle's marker form encodes shorter than its raw form, so a sealed-form
    /// sync would compute another price and fail the state root.
    #[error("gas.dynamic cannot be combined with aggregation: a pruned bundle's encoded size differs from its raw size, so sealed-form sync would diverge on the byte price")]
    DynamicGasWithAggregation,
    /// `fees.subsidy_net_of_fees: true` nets the aggregation subsidy against proving shares, and
    /// a chain without an `aggregation` section has neither.
    #[error("fees.subsidy_net_of_fees needs an aggregation section: without one there is no subsidy to net")]
    SubsidyNetOfFeesWithoutAggregation,
    /// `fees.burn_floor: true` widens `burn_base`'s burned base to the bundle's whole floor
    /// (issue #135); without `burn_base: true` there is no burned base to widen, and a flag that
    /// silently did nothing would read as a rule the chain does not run.
    #[error("fees.burn_floor needs fees.burn_base: true — it widens the burned base to the whole floor")]
    BurnFloorWithoutBurnBase,
    #[error("bad hc_bundle {0} (64 hex characters)")]
    BadHcBundle(String),
    #[error("bad hc_auth {0} (64 hex characters)")]
    BadHcAuth(String),
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
    /// A genesis note of a token must name one this genesis lists: there is no other registry
    /// index at block 0.
    #[error("alloc note {cm} names asset {asset}, which is not a token this genesis lists")]
    BadNoteAsset { cm: String, asset: u32 },
    /// A listed token's genesis notes and its backings' genesis `locked` must be the same
    /// amount — `total_supply == Σ locked` from block 0, and every unit of it held by a note.
    #[error("token {symbol} starts with {notes} in genesis notes but {locked} locked in its backings")]
    TokenSupplyMismatch { symbol: String, notes: u128, locked: u128 },
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
    /// Split authorisation (`hc_auth` set): a transaction carries up to three proofs, so the block
    /// cap must hold three at the proof cap plus the headroom ([`gas::min_block_bytes`]).
    #[error(
        "max_block_bytes {block} is too small for split authorisation: a transaction carries three proofs \
         (bundle, auth, call), so with max_proof_bytes {proof} a block needs at least \
         3 * {proof} + {headroom} = {need} bytes (set max_block_bytes, or a smaller max_proof_bytes)",
        headroom = gas::BLOCK_PROOF_HEADROOM
    )]
    BlockTooSmallForSplitAuth { block: usize, proof: usize, need: usize },
    #[error(
        "bad max_call_envelope_bytes {0} ({min}..={limit})",
        min = crate::types::actions::MAX_CALL_ENVELOPE_BYTES,
        limit = gas::MAX_CALL_ENVELOPE_BYTES_LIMIT
    )]
    BadMaxCallEnvelopeBytes(u32),
    #[error("bad max_program_public_words {0} (0..={limit})", limit = gas::MAX_PROGRAM_PUBLIC_WORDS_LIMIT)]
    BadMaxProgramPublicWords(u32),
    #[error("bad envelope_bytes {0} (only {only} is supported)", only = crate::notes::MEMO_ENVELOPE_BYTES)]
    BadEnvelopeBytes(u32),
    #[error("alloc note {cm}'s envelope is {got} bytes, the genesis requires exactly {want} (envelope_bytes)")]
    AllocEnvelopeSize { cm: String, got: usize, want: usize },
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
    /// Audit v6, STAKE-2: whether the file says `testnet: true` (also `Ledger::testnet`).
    pub testnet: bool,
    pub ledger: Ledger,
    pub block: Block,
    /// The alloc notes in file order: commitment, envelope, amount.
    pub notes: Vec<(Word8, Envelope, u64)>,
}

/// The bytes a `gas` section appends to the genesis commitment, last (design 2026-09-28 §4.2,
/// §4.3, §7.1): `"gas" ‖ be64(gas_price) ‖ be64(byte_price) ‖ be64(bundle_gas_limit) ‖
/// "circuit"`, then, under `dynamic`, `"gas_dynamic" ‖ be64(target_block_bytes) ‖
/// be64(target_block_gas) ‖ be64(adjust_bps) ‖ be64(min_gas_price) ‖ be64(min_byte_price)`,
/// then (audit v6, POOL-2) each of `"max_gas_price" ‖ be64`, `"max_byte_price" ‖ be64` and
/// `"byte_load" ‖ "paying"` only when the file sets it, in that order — so chain 18's section,
/// which sets none, commits byte for byte as before. Pinned byte for byte by
/// `the_gas_sections_hash_contribution_is_pinned`.
fn gas_commit(g: &gas::GasConfig) -> Vec<u8> {
    let mut commit = Vec::new();
    commit.extend_from_slice(b"gas");
    commit.extend_from_slice(&g.gas_price.to_be_bytes());
    commit.extend_from_slice(&g.byte_price.to_be_bytes());
    commit.extend_from_slice(&g.bundle_gas_limit.to_be_bytes());
    commit.extend_from_slice(b"circuit");
    if let Some(d) = &g.dynamic {
        commit.extend_from_slice(b"gas_dynamic");
        for x in [d.target_block_bytes, d.target_block_gas, d.adjust_bps as u64, d.min_gas_price, d.min_byte_price] {
            commit.extend_from_slice(&x.to_be_bytes());
        }
        if let Some(m) = d.max_gas_price {
            commit.extend_from_slice(b"max_gas_price");
            commit.extend_from_slice(&m.to_be_bytes());
        }
        if let Some(m) = d.max_byte_price {
            commit.extend_from_slice(b"max_byte_price");
            commit.extend_from_slice(&m.to_be_bytes());
        }
        if d.byte_load == Some(gas::ByteLoad::Paying) {
            commit.extend_from_slice(b"byte_load");
            commit.extend_from_slice(b"paying");
        }
    }
    commit
}

/// The bytes a `fees` section appends to the genesis commitment, right after the `tokens`
/// contribution: `"fees"`, then `"burn_base" ‖ 1` if `burn_base` is `true`, then
/// `"subsidy_net_of_fees" ‖ 1` if `subsidy_net_of_fees` is `true`, then `"burn_floor" ‖ 1` if
/// `burn_floor` is `true` (issue #135; appended last so the two older flags' bytes, and every hash
/// pinned over them, stay put), in that order — and nothing at all when no flag is `true`, so a
/// file that spells the defaults out hashes as one without the section (TOK-2's rule for
/// `burn_registration_fee`). Pinned byte for byte by
/// `the_fees_sections_hash_contribution_is_pinned`.
fn fees_commit(f: &crate::ledger::fees::FeesConfig) -> Vec<u8> {
    let mut commit = Vec::new();
    if !f.any() {
        return commit;
    }
    commit.extend_from_slice(b"fees");
    if f.burn_base() {
        commit.extend_from_slice(b"burn_base");
        commit.push(1);
    }
    if f.subsidy_net_of_fees() {
        commit.extend_from_slice(b"subsidy_net_of_fees");
        commit.push(1);
    }
    if f.burn_floor() {
        commit.extend_from_slice(b"burn_floor");
        commit.push(1);
    }
    commit
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
        // A block must carry a transaction with every worst-case proof it can hold — the fee
        // bundle's and the call's, plus the auth proof under split authorisation — plus 1 MiB
        // for the rest, or the proof cap admits proofs no block can hold (`gas::min_block_bytes`).
        // The rule reads the effective caps, the defaults when the file leaves them out. A file
        // with neither field and no `hc_auth` is a pre-rule chain, whose 4 MiB block predates the
        // rule, and is not judged by it; an `hc_auth` chain always is — at the defaults (2 MiB
        // proofs, 4 MiB blocks) it is refused, since at production FRI it would admit no `Call`.
        let split_auth = self.hc_auth.is_some();
        if split_auth || self.max_proof_bytes.is_some() || self.max_block_bytes.is_some() {
            let proof = self.max_proof_bytes.map_or(gas::MAX_PROOF_BYTES, |n| n as usize);
            let block = self.max_block_bytes.map_or(gas::MAX_BLOCK_BYTES, |n| n as usize);
            let need = gas::min_block_bytes(proof, split_auth);
            if !(gas::MAX_BLOCK_BYTES_MIN..=gas::MAX_BLOCK_BYTES_LIMIT).contains(&block)
                || (!split_auth && block < need)
            {
                return Err(GenesisError::BadMaxBlockBytes(block as u32));
            }
            if block < need {
                return Err(GenesisError::BlockTooSmallForSplitAuth { block, proof, need });
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
        if let Some(n) = self.envelope_bytes {
            if n as usize != crate::notes::MEMO_ENVELOPE_BYTES {
                return Err(GenesisError::BadEnvelopeBytes(n));
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
        check_genesis_token_supply(&self.alloc, self.tokens.as_ref())?;
        // The consensus domain (audit v4): a version this build cannot sign is refused here,
        // not at the first vote.
        if let Some(v) = self.consensus_domain {
            if v > SigningDomain::MAX_VERSION {
                return Err(GenesisError::BadConsensusDomain(v));
            }
        }
        // Audit v6, STAKE-2 (option 2): a faucet and a bridge exclude each other on every chain
        // — section or no section, allowlist or none — unless the genesis says `testnet: true`.
        // The chains cut before the marker (14–19) carry both and are named, by id, so their
        // committed files still build; the section rule below stands on top of this one, so a
        // sectioned testnet still needs its allowlist as well.
        if self.faucet && self.bridge.is_some() && self.testnet != Some(true) && !FAUCET_BESIDE_BRIDGE_CHAIN_IDS.contains(&self.chain_id) {
            return Err(GenesisError::FaucetWithBridgeNeedsTestnet { chain_id: self.chain_id });
        }
        // The binding domain (audit v6, BIND-1), likewise: a version this build cannot compute
        // would leave every wallet and the ledger hashing different words.
        if let Some(v) = self.binding_domain {
            if v > crate::types::BindingDomain::MAX_VERSION {
                return Err(GenesisError::BadBindingDomain(v));
            }
        }
        // Issue #118: the proof window, inside its bounds — never below today's 256, never past
        // the ceiling that keeps the anchor deque and a live anchor's age bounded.
        if let Some(w) = self.proof_window_blocks {
            if !(crate::ledger::MIN_PROOF_WINDOW_BLOCKS..=crate::ledger::MAX_PROOF_WINDOW_BLOCKS).contains(&w) {
                return Err(GenesisError::BadProofWindowBlocks(w));
            }
        }
        // Audit v4, STAKE-2 rule 1, only under the section: a faucet and a bridge exclude each
        // other. Chain 14's genesis has both and no section, so it still loads.
        // A faucet limited to named spend keys (`faucet_recipients`, chain 15) cannot buy the
        // register for anyone else, so it may sit beside a bridge.
        let allowlisted = self.staking.as_ref().is_some_and(|s| s.faucet_recipients.is_some());
        if self.staking.is_some() && self.faucet && self.bridge.is_some() && !allowlisted {
            return Err(GenesisError::FaucetWithBridge);
        }
        if let Some(s) = &self.staking {
            if let Some(list) = &s.faucet_recipients {
                if list.is_empty() {
                    return Err(GenesisError::BadStaking("faucet_recipients is empty: the faucet could pay no one".into()));
                }
                let distinct: std::collections::BTreeSet<_> = list.iter().map(|r| r.0).collect();
                if distinct.len() != list.len() {
                    return Err(GenesisError::BadStaking("faucet_recipients names a key twice".into()));
                }
            }
            // The minter list, the same two rules: empty mints for no one, a key twice is a typo.
            if let Some(list) = &s.faucet_minters {
                if list.is_empty() {
                    return Err(GenesisError::BadStaking("faucet_minters is empty: no key could mint".into()));
                }
                let distinct: std::collections::BTreeSet<_> = list.iter().collect();
                if distinct.len() != list.len() {
                    return Err(GenesisError::BadStaking("faucet_minters names a key twice".into()));
                }
            }
            if let Some(bps) = s.max_weight_bps {
                if bps == 0 || bps > crate::ledger::staking::MAX_WEIGHT_BPS {
                    return Err(GenesisError::BadStaking(format!("max_weight_bps {bps} is outside 1..=10000")));
                }
            }
            if s.max_stake_entry_per_epoch == Some(0) {
                return Err(GenesisError::BadStaking("max_stake_entry_per_epoch 0 would admit no stake ever".into()));
            }
            // Audit v6, STAKE-1: the slash fraction bounded like the cap; the evidence is two
            // signatures under the chain's own domain, so v1 it must be; and no `vesting`
            // section beside it (`SlashingConfig`'s doc comment says why).
            if let Some(sl) = s.slashing {
                if sl.equivocation_bps == 0 || sl.equivocation_bps > crate::ledger::staking::MAX_WEIGHT_BPS {
                    return Err(GenesisError::BadStaking(format!("slashing.equivocation_bps {} is outside 1..=10000", sl.equivocation_bps)));
                }
                if (1..=crate::ledger::staking::EVIDENCE_EPOCHS).contains(&sl.jail_epochs) {
                    return Err(GenesisError::BadStaking(format!(
                        "slashing.jail_epochs {} must be 0 (for good) or more than the {}-epoch evidence window, or one offence could be slashed twice",
                        sl.jail_epochs,
                        crate::ledger::staking::EVIDENCE_EPOCHS
                    )));
                }
                if self.consensus_domain != Some(1) {
                    return Err(GenesisError::BadStaking(
                        "slashing needs consensus_domain 1: the evidence is two block signatures under this chain's own domain".into(),
                    ));
                }
                if self.vesting.is_some() {
                    return Err(GenesisError::BadStaking(
                        "slashing beside a vesting section is not supported: stake bonded from a lock returns to the lock's unbonding rows, which name no validator, and would escape a slash".into(),
                    ));
                }
            }
            // Audit v6, STAKE-2: the fraction, bounded like the weight cap, and one budget only.
            if let Some(bps) = s.max_stake_entry_bps_per_epoch {
                if bps == 0 || bps > crate::ledger::staking::MAX_WEIGHT_BPS {
                    return Err(GenesisError::BadStaking(format!("max_stake_entry_bps_per_epoch {bps} is outside 1..=10000")));
                }
                if s.max_stake_entry_per_epoch.is_some() {
                    return Err(GenesisError::BadStaking(
                        "max_stake_entry_bps_per_epoch and max_stake_entry_per_epoch are two entry budgets; set one".into(),
                    ));
                }
            }
        }
        if let Some(v) = &self.vesting {
            v.check().map_err(GenesisError::BadVesting)?;
        }
        // RPL-2: the section's own bound, then what it stands on. An invoke pays into a vault
        // through the token-aware bundle and mints registry tokens (`tokens`); its proof is a
        // call proof priced by gas (`gas`) and always bound to its transaction, under the
        // hardened call rules (`hardening_v6`); and every chain that has those runs the v3
        // bundle guest with split authorisation (`hc_auth`).
        if let Some(p) = &self.program_state {
            p.check().map_err(GenesisError::BadProgramState)?;
            for (on, name) in [
                (self.tokens.is_some(), "tokens"),
                (self.gas.is_some(), "gas"),
                (self.hardening_v6 == Some(true), "hardening_v6"),
                (self.hc_auth.is_some(), "hc_auth"),
                (self.confidential, "confidential"),
            ] {
                if !on {
                    return Err(GenesisError::BadProgramState(format!("program_state needs `{name}`")));
                }
            }
        }
        if let Some(g) = &self.gas {
            let max_block_bytes = self.max_block_bytes.map_or(gas::MAX_BLOCK_BYTES, |n| n as usize);
            g.check(max_block_bytes).map_err(GenesisError::Gas)?;
            if g.dynamic.is_some() && self.aggregation.is_some() {
                return Err(GenesisError::DynamicGasWithAggregation);
            }
        }
        // Fee feedback: the fee-first subsidy nets the aggregation subsidy against proving
        // shares, and a chain without `aggregation` has neither to net.
        if self.fees.as_ref().is_some_and(|f| f.subsidy_net_of_fees()) && self.aggregation.is_none() {
            return Err(GenesisError::SubsidyNetOfFeesWithoutAggregation);
        }
        // Issue #135: the full-floor burn widens the burned base, so it needs one to widen. A
        // `burn_floor` alone would hash into the genesis and change nothing the ledger does —
        // a rule in the binding the chain does not run.
        if self.fees.as_ref().is_some_and(|f| f.burn_floor() && !f.burn_base()) {
            return Err(GenesisError::BurnFloorWithoutBurnBase);
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
        // The weight cap (`staking.max_weight_bps`) holds from epoch 0: the genesis set is the
        // one set not derived by `derive_set_with`, so it is capped here by the same function.
        let validators = match self.staking.as_ref().and_then(|s| s.max_weight_bps) {
            Some(bps) => crate::ledger::staking::cap_weights(validators, bps),
            None => validators,
        };

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
            // TOK-1: the cap, after the listing (`check_tokens` held it to the listing's size).
            if let Some(n) = tconf.max_tokens {
                registry = registry.with_max_tokens(n);
            }
            // TOK-2 (audit v5): the burned registration fee, only when the file says `true`.
            if tconf.burn_registration_fee == Some(true) {
                registry = registry.with_burn_registration_fee(true);
            }
            // The note-value bound (deep scan 2026-09-24), only when the file says `true`.
            if tconf.bound_note_value == Some(true) {
                registry = registry.with_bound_note_value(true);
            }
            // The incremental commitment (audit v6 TOK-1, issue #86), only when the file says
            // `true`: the tree is built over the listed tokens here and every genesis lock below
            // moves it leaf by leaf, as every block will.
            if tconf.incremental_root == Some(true) {
                registry = registry.with_incremental_root(true);
            }
            // Genesis custody (chain 15): each backing's starting `locked`, through `lock` itself
            // — the one writer that moves `locked` and `total_supply` together — at the genesis
            // block's time, after every rule above is in place, so a genesis lock is judged and
            // counted exactly like a deposit in the chain's first second (the note bound, the
            // per-backing daily cap and, under rules v2, the rolling windows). The matching notes
            // are held to the same sum by `check_genesis_token_supply` in `validate`.
            let first = crate::ledger::tokens::FIRST_TOKEN_INDEX;
            for (i, t) in tconf.tokens.iter().enumerate() {
                for b in t.backings.iter().filter(|b| b.locked.is_some_and(|l| l > 0)) {
                    registry
                        .lock(first + i as u32, b.chain, &b.token, b.locked.unwrap_or(0), self.timestamp_ms / 1000)
                        .map_err(|e| GenesisError::BadTokens(format!("genesis locked on chain {}: {e}", b.chain)))?;
                }
            }
            ledger.set_tokens(Some(registry));
        }
        ledger.set_aggregation(self.aggregation.clone());
        ledger.set_fees(self.fees.clone().unwrap_or_default());
        ledger.set_staking(self.staking.clone());
        ledger.set_max_program_words(self.max_program_words.map_or(gas::MAX_PROGRAM_WORDS, |n| n as usize));
        ledger.set_max_proof_bytes(self.max_proof_bytes.map_or(gas::MAX_PROOF_BYTES, |n| n as usize));
        ledger.set_max_block_bytes(self.max_block_bytes.map_or(gas::MAX_BLOCK_BYTES, |n| n as usize));
        ledger.set_max_call_envelope_bytes(
            self.max_call_envelope_bytes.map_or(crate::types::actions::MAX_CALL_ENVELOPE_BYTES, |n| n as usize),
        );
        ledger.set_max_program_public_words(self.max_program_public_words.map_or(gas::MAX_PROGRAM_PUBLIC_WORDS, |n| n as usize));
        ledger.set_envelope_bytes(self.envelope_bytes.map(|n| n as usize));
        ledger.set_hardening_v6(self.hardening_v6 == Some(true));
        let hc_auth = match &self.hc_auth {
            Some(h) => Some(word8_from_hex(h).ok_or_else(|| GenesisError::BadHcAuth(h.clone()))?),
            None => None,
        };
        ledger.set_hc_auth(hc_auth);
        ledger.set_gas(self.gas.clone());
        ledger.set_testnet(self.testnet == Some(true));
        ledger.set_proof_window_blocks(self.proof_window_blocks);
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
            // Spec 2026-09-26 §2.4: under `envelope_bytes` an alloc note's envelope is held to the
            // same exact length as every envelope a transaction carries.
            if let Some(want) = self.envelope_bytes {
                if envelope.len() != want as usize {
                    return Err(GenesisError::AllocEnvelopeSize {
                        cm: n.cm.clone(),
                        got: envelope.len(),
                        want: want as usize,
                    });
                }
            }
            match &n.opening {
                Some(o) => {
                    let pk = word8_from_hex(&o.pk).ok_or_else(|| GenesisError::BadNote(o.pk.clone()))?;
                    let r = word8_from_hex(&o.r).ok_or_else(|| GenesisError::BadNote(o.r.clone()))?;
                    // At the note's own asset: 0 is `mint_commitment`'s RAND note, a listed
                    // token's index is the deposit commitment a `BridgeAttest` would append for
                    // it (`from` the zero word either way) — `validate` has already refused an
                    // index no listed token holds.
                    if executor.note_commitment(&pk, &[0; 8], n.amount, o.asset, o.time, &r) != cm {
                        return Err(GenesisError::NoteCommitmentMismatch(n.cm.clone()));
                    }
                }
                // An opening is checked whenever it is there — a chain ≤ 13 that carries one
                // gets the same guarantee — and required only where it is load-bearing.
                None if openings_required => return Err(GenesisError::MissingNoteOpening(n.cm.clone())),
                None => {}
            }
            ledger.deposit(cm, executor).map_err(|_| GenesisError::DuplicateNote(n.cm.clone()))?;
            // A token's genesis note is that token's supply (the registry's `total_supply`, set
            // by the genesis `lock` above), never RAND's.
            if n.opening.as_ref().is_none_or(|o| o.asset == 0) {
                deposited = deposited.checked_add(n.amount).ok_or(GenesisError::SupplyOverflow)?;
            }
            notes.push((cm, envelope, n.amount));
        }
        // The register's stakes are supply too (see `ledger::supply`): genesis is the one place
        // stake appears without a bond having burned notes for it.
        let mut staked: u64 = 0;
        for e in register.values() {
            staked = staked.checked_add(e.stake).ok_or(GenesisError::SupplyOverflow)?;
        }
        ledger.set_genesis_supply(deposited, staked);
        // The vesting register is issuance too, beside the notes and the stakes: all three
        // together must fit a u64, or the supply audit could not state the total.
        if let Some(v) = &self.vesting {
            let vested = v.check().map_err(GenesisError::BadVesting)?;
            deposited.checked_add(staked).and_then(|t| t.checked_add(vested)).ok_or(GenesisError::SupplyOverflow)?;
            ledger.set_vesting(Some(crate::ledger::vesting::VestingRegister::from_config(v)));
        }
        // RPL-2: an empty program state under the section. No value is seeded — a vault fills
        // only through an `Invoke`'s bundle — so the supply check above is unaffected.
        if let Some(p) = &self.program_state {
            ledger.set_program_state(Some(crate::ledger::program_state::ProgramState::from_config(p)));
        }
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
        // A bridge carried over from another chain (chain 15): the guardian set it starts at and
        // the sequence its first burn carries, each tagged and appended only when present, in
        // this fixed order after the rules — so chain 14's file hashes byte-for-byte as before.
        if let Some(index) = self.bridge.as_ref().and_then(|b| b.guardian_set_index) {
            commit.extend_from_slice(b"bridge_guardian_set_index");
            commit.extend_from_slice(&index.to_be_bytes());
        }
        if let Some(sequence) = self.bridge.as_ref().and_then(|b| b.burn_sequence) {
            commit.extend_from_slice(b"bridge_burn_sequence");
            commit.extend_from_slice(&sequence.to_be_bytes());
        }
        // The inbound replay floor (C15-1), tagged and appended only when present, after the
        // burn sequence: the entry count, then each (chain, floor) in ascending chain order — so
        // chain 15's file, which has none, hashes byte-for-byte as before.
        if let Some(floor) = self.bridge.as_ref().and_then(|b| b.min_inbound_sequence.as_ref()) {
            commit.extend_from_slice(b"bridge_min_inbound_sequence");
            commit.extend_from_slice(&(floor.len() as u32).to_be_bytes());
            for (chain, sequence) in floor {
                commit.extend_from_slice(&chain.to_be_bytes());
                commit.extend_from_slice(&sequence.to_be_bytes());
            }
        }
        // RPL tokens, after the bridge bytes: appended only when the section is configured, so a
        // chain without one hashes byte-for-byte as before. `TokensCommit` is the plain-bytes
        // twin of `TokensConfig`, whose own serde renders a token address as hex text — bincode
        // of that would commit to hex *strings* rather than to the bytes the chain runs on,
        // exactly as `BridgeCommit` exists for `BridgeConfig`.
        if let Some(tokens) = &self.tokens {
            commit.extend_from_slice(&bincode::serialize(&TokensCommit::from(tokens)).expect("serializes"));
            // TOK-1 (audit v4): the registry cap, tagged and appended only when the file sets it,
            // right after the section it belongs to — not inside `TokensCommit`, for
            // `BridgeCommit`'s reason.
            if let Some(n) = tokens.max_tokens {
                commit.extend_from_slice(b"max_tokens");
                commit.extend_from_slice(&n.to_be_bytes());
            }
            // TOK-2 (audit v5): the burned registration fee, tagged and appended only when the
            // file says `true` — `false` is today's rule and commits nothing, so a file that
            // spells the default out hashes as one that leaves it out.
            if tokens.burn_registration_fee == Some(true) {
                commit.extend_from_slice(b"burn_registration_fee");
                commit.push(1);
            }
            // The note-value bound (deep scan 2026-09-24), tagged and appended only when the
            // file says `true`, for the same reason and in this fixed order after the burn flag.
            if tokens.bound_note_value == Some(true) {
                commit.extend_from_slice(b"bound_note_value");
                commit.push(1);
            }
        }
        // Fee feedback (`docs/fees.md` §1.3), right after the tokens bytes: the `fees` section's
        // `true` flags, tagged — nothing at all for an absent section or one with no `true` flag,
        // so every file cut before it hashes byte for byte as before.
        if let Some(fees) = &self.fees {
            commit.extend_from_slice(&fees_commit(fees));
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
            // The v4 re-review's three fields, each tagged and appended only when set, in this
            // fixed order, so a section without them hashes exactly as v0.5.4's did.
            if let Some(bps) = s.max_weight_bps {
                commit.extend_from_slice(b"max_weight_bps");
                commit.extend_from_slice(&bps.to_be_bytes());
            }
            if let Some(n) = s.max_stake_entry_per_epoch {
                commit.extend_from_slice(b"max_stake_entry_per_epoch");
                commit.extend_from_slice(&n.to_be_bytes());
            }
            // Like `bound_note_value`: `false` is today's rule and commits nothing.
            if s.registration_v2 == Some(true) {
                commit.extend_from_slice(b"registration_v2");
                commit.push(1);
            }
            // The faucet allowlist: its length, then each key's 32 bytes in file order.
            if let Some(list) = &s.faucet_recipients {
                commit.extend_from_slice(b"faucet_recipients");
                commit.extend_from_slice(&(list.len() as u32).to_be_bytes());
                for r in list {
                    commit.extend_from_slice(&crate::notes::word8_to_bytes(&r.0));
                }
            }
            // The minter list (RESCAN-LEDGER-1), the same way and after it: its length, then each
            // address's 32 bytes in file order. Absent, nothing — chain 15 (`cc30e085…`) hashes
            // byte-for-byte as before.
            if let Some(list) = &s.faucet_minters {
                commit.extend_from_slice(b"faucet_minters");
                commit.extend_from_slice(&(list.len() as u32).to_be_bytes());
                for m in list {
                    commit.extend_from_slice(&m.0 .0);
                }
            }
        }
        // The exact envelope size (spec 2026-09-26 §2.4), last and only when the file sets it,
        // so every genesis cut before it — chain 14's included — hashes byte-for-byte as before.
        if let Some(n) = self.envelope_bytes {
            commit.extend_from_slice(b"envelope_bytes");
            commit.extend_from_slice(&n.to_be_bytes());
        }
        // Genesis vesting, after the envelope size — last: its count, then every entry in id
        // order (the register's order, so two files listing the same entries differently are one
        // chain), every field
        // fixed-width — the keys are held to their length by `validate` — with a presence byte
        // before each optional one. Absent, nothing.
        if let Some(v) = &self.vesting {
            let mut entries: Vec<_> = v.entries.iter().collect();
            entries.sort_by_key(|a| a.id);
            commit.extend_from_slice(b"vesting");
            commit.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for e in entries {
                commit.extend_from_slice(&e.id);
                commit.extend_from_slice(e.class.as_str().as_bytes());
                commit.push(0);
                commit.extend_from_slice(e.beneficiary.as_bytes());
                // Audit v6, STAKE-3: the revokers' count (0 = irrevocable, and then nothing
                // more), the threshold, each key in file order — a revoke names its signers by
                // position, so the order is a term — and the treasury's two fields. `validate`
                // has held the keys and the address to their lengths and made the threshold and
                // the treasury present, so every field is fixed-width.
                commit.push(e.revokers.len() as u8);
                if !e.revokers.is_empty() {
                    commit.push(e.threshold.unwrap_or(0));
                    for r in &e.revokers {
                        commit.extend_from_slice(r.as_bytes());
                    }
                    if let Some(t) = e.treasury_address() {
                        commit.extend_from_slice(&word8_to_bytes(&t.pk));
                        commit.extend_from_slice(&t.kem_ek);
                    }
                }
                for w in [e.amount, e.start_ms, e.cliff_ms, e.linear_ms] {
                    commit.extend_from_slice(&w.to_be_bytes());
                }
                match e.step_ms {
                    Some(step) => {
                        commit.push(1);
                        commit.extend_from_slice(&step.to_be_bytes());
                    }
                    None => commit.push(0),
                }
            }
        }
        // The v0.6 hardening switch, last: tagged and appended only when the file says `true`,
        // like `bound_note_value` — `false` is the old rules and commits nothing, so chain 15
        // (`cc30e085…`) hashes byte-for-byte as before.
        if self.hardening_v6 == Some(true) {
            commit.extend_from_slice(b"hardening_v6");
            commit.push(1);
        }
        // Split authorisation's auth guest, after the v0.6 switch: tagged and appended only when
        // the file names one, so chains 14, 15 (`cc30e085…`) and 16 (`20925ae6…`) hash as before.
        if let Some(hc_auth) = ledger.hc_auth() {
            commit.extend_from_slice(b"hc_auth");
            commit.extend_from_slice(&word8_to_bytes(&hc_auth));
        }
        // Gas (design 2026-09-28 §4.2, §4.3, §7.1), last: only when the file sets it, so every
        // genesis cut before it hashes byte-for-byte as before.
        if let Some(g) = &self.gas {
            commit.extend_from_slice(&gas_commit(g));
        }
        // Audit v6, STAKE-2: the staking section's later fields, each under its own tag after
        // every tag that existed before it and only when set — inside the `staking` block above
        // they would sit between tags chain 18's hash already commits. `false` is today's rule
        // and commits nothing, like `registration_v2`.
        if self.staking.as_ref().is_some_and(|s| s.admission_by_vote()) {
            commit.extend_from_slice(b"staking_admission_by_vote");
            commit.push(1);
        }
        // The testnet marker (audit v6, STAKE-2), after it: only when `true` — `false` and
        // absent are both "not a testnet" and commit nothing, so chains 14–19 hash as before.
        if self.testnet == Some(true) {
            commit.extend_from_slice(b"testnet");
            commit.push(1);
        }
        // The entry budget as a fraction (audit v6, STAKE-2), after it, only when set.
        if let Some(bps) = self.staking.as_ref().and_then(|s| s.max_stake_entry_bps_per_epoch) {
            commit.extend_from_slice(b"staking_max_stake_entry_bps_per_epoch");
            commit.extend_from_slice(&bps.to_be_bytes());
        }
        // Slashing (audit v6, STAKE-1), after it, only when set: the fraction and the jail.
        if let Some(sl) = self.staking.as_ref().and_then(|s| s.slashing) {
            commit.extend_from_slice(b"staking_slashing");
            commit.extend_from_slice(&sl.equivocation_bps.to_be_bytes());
            commit.extend_from_slice(&sl.jail_epochs.to_be_bytes());
        }
        // The binding domain (audit v6, BIND-1), after `gas` — last — tagged like the consensus
        // domain and only when the file sets it, so chain 18 (`a7cb020c…`) and every genesis cut
        // before it hashes byte-for-byte as before.
        if let Some(v) = self.binding_domain {
            commit.extend_from_slice(b"binding_domain");
            commit.extend_from_slice(&v.to_be_bytes());
        }
        // The bridge rotation rules (audit v6, BRG-14), after `binding_domain` — last — tagged
        // and only when the bridge section carries the group: each field behind a presence byte,
        // fixed width. Chain 18's file has none and hashes byte-for-byte as before.
        if let Some(r) = self.bridge.as_ref().and_then(|b| b.rotation.as_ref()) {
            commit.extend_from_slice(b"bridge_rotation");
            match r.delay_secs {
                Some(d) => {
                    commit.push(1);
                    commit.extend_from_slice(&d.to_be_bytes());
                }
                None => commit.push(0),
            }
            match r.needs_possession {
                Some(p) => {
                    commit.push(1);
                    commit.push(p as u8);
                }
                None => commit.push(0),
            }
        }
        // The proof window (issue #118), after `bridge_rotation` — last — tagged and only when the
        // file sets it, so chain 18 (`a7cb020c…`) and every genesis cut before it hash as before.
        if let Some(w) = self.proof_window_blocks {
            commit.extend_from_slice(b"proof_window_blocks");
            commit.extend_from_slice(&w.to_be_bytes());
        }
        // RPL-2, after `proof_window_blocks` — last — tagged, and only when the file has the section,
        // so chain 18 (`a7cb020c…`) and every genesis cut before it hashes byte-for-byte as before.
        // One fixed-width field.
        if let Some(p) = &self.program_state {
            commit.extend_from_slice(b"program_state");
            commit.extend_from_slice(&p.cell_fee.to_be_bytes());
        }
        // The bridge fees (v0.6.8), after `program_state` — last — tagged, and only when the
        // bridge section carries the group, so chain 18 (`a7cb020c…`), chain 19 and every genesis
        // cut before them hash byte-for-byte as before. Fixed width (`BridgeFees::commit_bytes`).
        if let Some(f) = self.bridge.as_ref().and_then(|b| b.fees.as_ref()) {
            commit.extend_from_slice(b"bridge_fees");
            commit.extend_from_slice(&f.commit_bytes());
        }
        // The incremental token root (audit v6 TOK-1, issue #86), after `bridge_fees` — last —
        // tagged, and only when the tokens section says `true` (`false` is today's rule and
        // commits nothing), so chains 18, 19 and 20 and every genesis cut before them hash
        // byte-for-byte as before. Not beside the section's other tags: those were last when
        // they were added, and a tag inserted before `aggregation`'s bytes would move chain
        // 20's hash.
        if self.tokens.as_ref().is_some_and(|t| t.incremental_root == Some(true)) {
            commit.extend_from_slice(b"tokens_incremental_root");
            commit.push(1);
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
        // BIND-1: the binding domain carries the same hash, for the same reason set here; like the
        // signing domain it is not state.
        ledger.set_binding_domain(crate::types::BindingDomain::for_version(self.binding_domain.unwrap_or(0), block.hash()));
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
            testnet: self.testnet == Some(true),
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
    // A set at the last index could never be rotated away from: the next rotation must carry
    // `index + 1`, which does not exist.
    if cfg.guardian_set_index == Some(u32::MAX) {
        return bad("guardian_set_index u32::MAX leaves no index to rotate to".into());
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
    // Audit v6, BRG-14: the rotation rules sit beside `rules_v2` (the rotations they govern are
    // v2 actions), a delay is between a second and thirty days, and an empty group is refused
    // rather than committed for nothing.
    if let Some(r) = &cfg.rotation {
        if cfg.rules_v2.is_none() {
            return bad("rotation rules need rules_v2: the rotations they govern are bridge rules v2 actions".into());
        }
        if r.delay_secs.is_none() && r.needs_possession.is_none() {
            return bad("rotation is an empty group: set delay_secs and/or needs_possession, or leave it out".into());
        }
        if let Some(d) = r.delay_secs {
            if d == 0 || d > crate::bridge::MAX_ROTATION_DELAY_SECS {
                return bad(format!("rotation.delay_secs {d} is out of bounds (1..={})", crate::bridge::MAX_ROTATION_DELAY_SECS));
            }
        }
    }
    // v0.6.8: the bridge fees. At most 1 % each way, and a recipient whose ML-KEM key is one —
    // the fee notes are sealed to nobody, but a treasury address whose key no wallet could hold
    // is a typo, and every fee would go to a key nobody can derive a viewing key for. The pk is
    // any 32 bytes, as every shielded address's is.
    if let Some(f) = &cfg.fees {
        for (name, bps) in [("mint_bps", f.mint_bps), ("burn_bps", f.burn_bps)] {
            if bps > crate::bridge::MAX_BRIDGE_FEE_BPS {
                return bad(format!("fees.{name} {bps} is out of bounds (0..={}, 1 %)", crate::bridge::MAX_BRIDGE_FEE_BPS));
            }
        }
        if !crate::notes::kem_ek_is_valid(&f.recipient.kem_ek) {
            return bad("fees.recipient's kem_ek is not a valid ML-KEM-768 encapsulation key".into());
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
    // C15-1: the replay floor. Present means it says something: an empty map would move the
    // genesis hash and refuse nothing. A chain the emitter table does not register can never
    // be attested (`WrongEmitter` comes first), so a floor on it is dead — almost certainly a
    // mistyped chain id, which would leave the chain meant unguarded. A floor of 0 refuses
    // nothing either, and is the value an unset cut variable would write.
    if let Some(floor) = &cfg.min_inbound_sequence {
        if floor.is_empty() {
            return bad("min_inbound_sequence is empty: omit it, or name each source chain's floor".into());
        }
        if let Some(chain) = floor.keys().find(|c| !cfg.emitters.contains_key(c)) {
            return bad(format!("min_inbound_sequence names chain {chain}, which has no registered emitter"));
        }
        if let Some((chain, _)) = floor.iter().find(|(_, s)| **s == 0) {
            return bad(format!("min_inbound_sequence for chain {chain} is 0, which refuses nothing"));
        }
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
    // And every admitted shape must be the bundle header a chain actually accepts (the interface
    // review's IFACE-9): the one bundle tier, no keccak or sha256 table, and the transaction
    // binding's public height — the header `decode_and_check` pins on every bundle proof. Any
    // other shape registers one no committed bundle can ever match, so aggregation would be dead
    // on a chain that believes it has it (chain 9's `public 2` was that, after the binding fork).
    // Whether the rVM can build an inner verifier key for the shape (`InnerShape::try_of`) is the
    // node's to check — core cannot name the rVM — and `rand-node genesis` does, at the cut.
    for s in &cfg.admitted_shapes {
        let d = &s.shape;
        let pinned: [(&str, u8, u8); 4] = [
            ("tier", d.tier, crate::types::BUNDLE_PROOF_TIER),
            ("keccak_log_height", d.keccak_log_height, 0),
            ("sha256_log_height", d.sha256_log_height, 0),
            ("public_log_height", d.public_log_height, crate::types::BUNDLE_PUBLIC_LOG_HEIGHT),
        ];
        if let Some((field, got, want)) = pinned.into_iter().find(|(_, got, want)| got != want) {
            return bad(format!(
                "an admitted shape declares {field} {got}; every bundle proof declares {want}, so no bundle could match it"
            ));
        }
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
    // TOK-1: a cap of zero refuses every registration for ever, and one below the file's own
    // listing would build a registry that is already over it.
    if let Some(n) = cfg.max_tokens {
        if n == 0 || (n as usize) < cfg.tokens.len() {
            return bad(format!("max_tokens {n} is below the {} tokens the section lists (and must be at least 1)", cfg.tokens.len()));
        }
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

/// Genesis supply of a bridged token (chain 15): every alloc note whose opening names a non-zero
/// `asset` must name a token the `tokens` section lists — index `FIRST_TOKEN_INDEX + position` —
/// and, per listed token, its notes must sum to exactly its backings' genesis `locked`. Both
/// sides are summed in `u128`, so neither can wrap into agreement; whether the sum fits the
/// token's `u64` supply is `TokenRegistry::lock`'s own refusal, in `Genesis::build`.
///
/// Structural only: that a note's opening reproduces its commitment at that asset needs the
/// executor and is checked by `build`.
fn check_genesis_token_supply(alloc: &[GenesisNote], tokens: Option<&TokensConfig>) -> Result<(), GenesisError> {
    let listed = tokens.map_or(&[][..], |t| &t.tokens[..]);
    let first = crate::ledger::tokens::FIRST_TOKEN_INDEX;
    let mut notes = vec![0u128; listed.len()];
    for n in alloc {
        let asset = n.opening.as_ref().map_or(0, |o| o.asset);
        if asset == 0 {
            continue;
        }
        let slot = asset
            .checked_sub(first)
            .map(|i| i as usize)
            .filter(|&i| i < listed.len())
            .ok_or_else(|| GenesisError::BadNoteAsset { cm: n.cm.clone(), asset })?;
        notes[slot] += n.amount as u128;
    }
    for (t, notes) in listed.iter().zip(notes) {
        let locked: u128 = t.backings.iter().map(|b| b.locked.unwrap_or(0) as u128).sum();
        if notes != locked {
            return Err(GenesisError::TokenSupplyMismatch { symbol: t.symbol.clone(), notes, locked });
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
        n.opening = Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r), asset: 0 });
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
            envelope_bytes: None,
            vesting: None,
            hardening_v6: None,
            hc_auth: None,
            gas: None,
            testnet: None,
            binding_domain: None,
            proof_window_blocks: None,
            program_state: None,
            fees: None,
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

    /// Issue #118: `proof_window_blocks` is genesis-gated — committed, tagged and last, only when
    /// present, so a file without it builds the same hash and a 256/256 ledger; with it the ledger
    /// runs the window; validation holds it to [256, 4096]; never state.
    #[test]
    fn a_genesis_proof_window_is_committed_only_when_present_and_bounded() {
        use crate::ledger::{MAX_PROOF_WINDOW_BLOCKS, MIN_PROOF_WINDOW_BLOCKS, TIME_WINDOW};
        let base = genesis(1);
        assert_eq!(base.proof_window_blocks, None, "chain 18's shape has no field");
        let plain = build(&base);
        assert_eq!((plain.ledger.proof_window(), plain.ledger.proof_window_blocks()), (TIME_WINDOW, None));
        let mut g = base.clone();
        g.proof_window_blocks = Some(1024);
        let wide = build(&g);
        assert_ne!(wide.hash(), plain.hash(), "the window is part of the genesis binding");
        assert_eq!((wide.ledger.proof_window(), wide.ledger.proof_window_blocks()), (1024, Some(1024)));
        assert_eq!(wide.ledger.state_root(), plain.ledger.state_root(), "a genesis parameter, never state");
        // `256` is today's window, but it is a field in the file, so it is in the hash.
        let mut floor = base.clone();
        floor.proof_window_blocks = Some(MIN_PROOF_WINDOW_BLOCKS);
        assert_ne!(build(&floor).hash(), plain.hash());
        assert_ne!(build(&floor).hash(), wide.hash());
        let mut ceiling = base.clone();
        ceiling.proof_window_blocks = Some(MAX_PROOF_WINDOW_BLOCKS);
        assert!(ceiling.validate().is_ok());
        for bad in [0, MIN_PROOF_WINDOW_BLOCKS - 1, MAX_PROOF_WINDOW_BLOCKS + 1, u64::MAX] {
            let mut b = base.clone();
            b.proof_window_blocks = Some(bad);
            assert!(matches!(b.validate(), Err(GenesisError::BadProofWindowBlocks(v)) if v == bad), "{bad}");
        }
        // The field round-trips through the file, and an absent one stays absent.
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap().proof_window_blocks, Some(1024));
        assert!(!base.to_json().contains("proof_window_blocks"));
        assert_eq!(build(&Genesis::from_json(&base.to_json()).unwrap()).hash(), plain.hash());
    }

    /// BIND-1 (audit v6): the binding domain is genesis-gated exactly as the consensus domain is.
    /// The field is committed — tagged, last — only when present, so a file without it builds to
    /// the same hash and a `ChainId` ledger; with `1` the ledger's domain carries the genesis hash
    /// the file itself builds to; validation refuses a version this build does not compute.
    #[test]
    fn a_genesis_with_binding_domain_1_commits_it_and_one_without_is_unchanged() {
        use crate::types::BindingDomain;
        let base = genesis(1);
        assert_eq!(base.binding_domain, None, "chain 18's shape has no field");
        let plain = build(&base);
        assert_eq!(plain.ledger.binding_domain(), &BindingDomain::ChainId);
        let mut g = base.clone();
        g.binding_domain = Some(1);
        let v1 = build(&g);
        assert_ne!(v1.hash(), plain.hash(), "the version is part of the genesis binding");
        assert_eq!(v1.ledger.binding_domain(), &BindingDomain::Genesis(v1.hash()), "the ledger binds this genesis' own hash");
        assert_eq!(v1.ledger.state_root(), plain.ledger.state_root(), "a genesis parameter, never state");
        assert_eq!(v1.ledger, plain.ledger, "and outside the ledger's equality");
        // `0` is today's messages, but it is a field in the file, so it is in the hash.
        let mut zero = base.clone();
        zero.binding_domain = Some(0);
        let v0 = build(&zero);
        assert_eq!(v0.ledger.binding_domain(), &BindingDomain::ChainId);
        assert_ne!(v0.hash(), plain.hash());
        assert_ne!(v0.hash(), v1.hash());
        let mut bad = base.clone();
        bad.binding_domain = Some(2);
        assert!(matches!(bad.validate(), Err(GenesisError::BadBindingDomain(2))));
        // The field round-trips through the file, and an absent one stays absent.
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap().binding_domain, Some(1));
        assert!(!base.to_json().contains("binding_domain"));
        assert_eq!(build(&Genesis::from_json(&base.to_json()).unwrap()).hash(), plain.hash());
        // Beside the consensus domain the two tags are independent: each moves the hash alone.
        let mut both = g.clone();
        both.consensus_domain = Some(1);
        assert_ne!(build(&both).hash(), v1.hash());
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
            // The pinned bundle header (IFACE-9), so only the profile differs.
            let shape = DeclaredShape {
                profile,
                tier: crate::types::BUNDLE_PROOF_TIER,
                program_log_height: 12,
                input_log_height: 10,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: crate::types::BUNDLE_PUBLIC_LOG_HEIGHT,
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

    /// The interface review's IFACE-9 (VERIFIER-2, node side): an admitted shape was checked for
    /// its digest and its profile, never against the bundle header every coverable bundle
    /// carries — tier [`BUNDLE_PROOF_TIER`], no keccak or sha256 table, the transaction binding's
    /// public height ([`crate::types::BUNDLE_PUBLIC_LOG_HEIGHT`]). A genesis admitting any other
    /// shape registers one no bundle can match: aggregation dead on a chain that believes it
    /// has it (chain 9's `public 2` was exactly that after the binding fork). Refused here, by
    /// name.
    ///
    /// [`BUNDLE_PROOF_TIER`]: crate::types::BUNDLE_PROOF_TIER
    #[test]
    fn an_admitted_shape_must_be_the_pinned_bundle_header() {
        use crate::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use crate::types::{DeclaredShape, FriProfile};
        let honest = DeclaredShape {
            profile: FriProfile::Production,
            tier: crate::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: crate::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        let with = |shape: DeclaredShape| {
            let mut g = base_genesis();
            g.fri_profile = "production".into();
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
        assert!(with(honest).is_ok(), "the pinned header is admissible");
        for (field, bad) in [
            ("keccak", DeclaredShape { keccak_log_height: 12, ..honest }),
            ("sha256", DeclaredShape { sha256_log_height: 12, ..honest }),
            ("tier", DeclaredShape { tier: 21, ..honest }),
            ("public", DeclaredShape { public_log_height: 2, ..honest }),
        ] {
            let e = with(bad).unwrap_err();
            assert!(
                matches!(&e, GenesisError::BadAggregationConfig(m) if m.contains(field)),
                "a shape with a non-bundle {field} was accepted: {e}"
            );
        }
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
                    backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: BRIDGE_DECIMALS, locked: None }],
                }],
                mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
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
            Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r), asset: 0 });
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
        plain_wrong.alloc[0].opening = Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r), asset: 0 });
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
            guardian_set_index: None,
            burn_sequence: None,
            min_inbound_sequence: None,
            rotation: None,
            fees: None,
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
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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

    /// Audit v4 (TOK-1): `tokens.max_tokens` caps how many tokens the registry may hold. Committed
    /// to the genesis hash as `b"max_tokens"` ‖ value only when present — a chain-14-shaped file
    /// (no field) hashes and roots exactly as before — held to at least one and at least the number
    /// of tokens the file lists, and reaches the registry, whose root moves with it.
    #[test]
    fn max_tokens_is_committed_only_when_present_and_caps_the_registry() {
        let token = |salt: u8, coin: u8| GenesisToken {
            name: "Shielded USD".into(),
            symbol: "zUSD".into(),
            salt: [salt; 32],
            backings: vec![GenesisBacking { chain: 2, token: [coin; 32], decimals: 6, locked: None }],
        };
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![token(1, 0x11), token(2, 0x22)],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
        });
        g.alloc = opened_alloc();
        let base = build(&g);
        assert_eq!(base.ledger.tokens().unwrap().max_tokens(), u32::MAX);
        assert!(!g.to_json().contains("max_tokens"), "absent from the file when absent");

        let mut capped = g.clone();
        capped.tokens.as_mut().unwrap().max_tokens = Some(2);
        let sc = build(&capped);
        assert_ne!(sc.hash(), base.hash(), "the cap is in the genesis binding");
        assert_ne!(sc.ledger.state_root(), base.ledger.state_root(), "and in the token root");
        assert_eq!(sc.ledger.tokens().unwrap().max_tokens(), 2);
        assert!(sc.ledger.tokens().unwrap().is_full(), "two listed under a cap of two");
        let back: Genesis = serde_json::from_str(&capped.to_json()).unwrap();
        assert_eq!(back, capped);
        let mut three = capped.clone();
        three.tokens.as_mut().unwrap().max_tokens = Some(3);
        assert_ne!(build(&three).hash(), sc.hash(), "two files that differ only in the cap build different chains");
        assert!(!build(&three).ledger.tokens().unwrap().is_full());

        let bad = |n: u32| {
            let mut g = capped.clone();
            g.tokens.as_mut().unwrap().max_tokens = Some(n);
            match g.validate() {
                Err(GenesisError::BadTokens(m)) => m,
                other => panic!("expected BadTokens, got {other:?}"),
            }
        };
        assert!(bad(0).contains("max_tokens"));
        assert!(bad(1).contains("max_tokens"), "below the number of tokens the file lists");
    }

    /// Audit v5 (TOK-2): `tokens.burn_registration_fee` burns a registration's fee instead of
    /// paying it to the proposer. Committed to the genesis hash as `b"burn_registration_fee"` ‖ 1
    /// only when `true` — a chain-14-shaped file (no field) and a file saying `false` hash and
    /// root exactly as before — and reaches the registry, whose root moves with it.
    #[test]
    fn the_registration_fee_burn_is_committed_only_when_true() {
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
        });
        g.alloc = opened_alloc();
        let base = build(&g);
        assert!(!base.ledger.tokens().unwrap().burns_registration_fee());
        assert!(!g.to_json().contains("burn_registration_fee"), "absent from the file when absent");

        let mut off = g.clone();
        off.tokens.as_mut().unwrap().burn_registration_fee = Some(false);
        let off_state = build(&off);
        assert_eq!(off_state.hash(), base.hash(), "`false` is today's rule and commits nothing");
        assert_eq!(off_state.ledger.state_root(), base.ledger.state_root());
        assert!(!off_state.ledger.tokens().unwrap().burns_registration_fee());

        let mut on = g.clone();
        on.tokens.as_mut().unwrap().burn_registration_fee = Some(true);
        let on_state = build(&on);
        assert_ne!(on_state.hash(), base.hash(), "the flag is in the genesis binding");
        assert_ne!(on_state.ledger.state_root(), base.ledger.state_root(), "and in the token root");
        assert!(on_state.ledger.tokens().unwrap().burns_registration_fee(), "and reaches the registry");
        assert!(on.to_json().contains("burn_registration_fee"));
        let back: Genesis = serde_json::from_str(&on.to_json()).unwrap();
        assert_eq!(back, on);
    }

    /// A genesis whose `aggregation` section validates: the production shape and profile the
    /// `dynamic_gas_is_refused_beside_aggregation` fixture uses.
    fn aggregating_genesis() -> Genesis {
        use crate::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use crate::types::{DeclaredShape, FriProfile};
        let shape = DeclaredShape {
            profile: FriProfile::Production,
            tier: crate::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: crate::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        let mut g = base_genesis();
        g.fri_profile = "production".into();
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
        g
    }

    /// Fee feedback (`docs/fees.md` §1.3): a `fees` section with no `true` flag is the section's
    /// absence — the same genesis hash, the same state root, the rules off on the ledger — exactly
    /// as TOK-2's `burn_registration_fee: false` is.
    #[test]
    fn a_fees_section_with_no_true_flag_hashes_as_absent() {
        use crate::ledger::fees::FeesConfig;
        let g = genesis(1);
        let base = build(&g);
        assert_eq!(base.ledger.fees(), &FeesConfig::default());
        for off in [
            FeesConfig::default(),
            FeesConfig { burn_base: Some(false), subsidy_net_of_fees: None, burn_floor: None },
            FeesConfig { burn_base: Some(false), subsidy_net_of_fees: Some(false), burn_floor: None },
        ] {
            let mut with = g.clone();
            with.fees = Some(off.clone());
            let state = build(&with);
            assert_eq!(state.hash(), base.hash(), "{off:?} commits nothing");
            assert_eq!(state.ledger.state_root(), base.ledger.state_root());
            assert!(!state.ledger.fees().burn_base() && !state.ledger.fees().subsidy_net_of_fees());
        }
        // A `true` flag moves the hash, never the state root (a genesis parameter, not state),
        // and reaches the ledger.
        let mut on = g.clone();
        on.fees = Some(FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: None });
        let on_state = build(&on);
        assert_ne!(on_state.hash(), base.hash(), "the flag is in the genesis binding");
        assert_eq!(on_state.ledger.state_root(), base.ledger.state_root(), "and not in the state root");
        assert!(on_state.ledger.fees().burn_base());
    }

    /// Fee feedback: the `fees` section's contribution to the genesis hash, byte for byte —
    /// `"fees"`, then each `true` flag's tag and a `1`, `burn_base` before `subsidy_net_of_fees` —
    /// and nothing for a section without a `true` flag. A re-tagged or reordered flag is a new
    /// chain, so it must fail here first.
    #[test]
    fn the_fees_sections_hash_contribution_is_pinned() {
        use crate::ledger::fees::FeesConfig;
        let burn = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: None };
        let mut want = b"fees".to_vec();
        want.extend_from_slice(b"burn_base");
        want.push(1);
        assert_eq!(fees_commit(&burn), want);

        let both = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: Some(true), burn_floor: None };
        want.extend_from_slice(b"subsidy_net_of_fees");
        want.push(1);
        assert_eq!(fees_commit(&both), want);

        let net = FeesConfig { burn_base: Some(false), subsidy_net_of_fees: Some(true), burn_floor: None };
        let mut want = b"fees".to_vec();
        want.extend_from_slice(b"subsidy_net_of_fees");
        want.push(1);
        assert_eq!(fees_commit(&net), want);

        // Issue #135: `burn_floor` appends its tag and a `1` after everything above, and only
        // when `true` — the base with the floor, then all three flags.
        let floor = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: Some(true) };
        let mut want = b"fees".to_vec();
        want.extend_from_slice(b"burn_base");
        want.push(1);
        want.extend_from_slice(b"burn_floor");
        want.push(1);
        assert_eq!(fees_commit(&floor), want);
        let all = FeesConfig { burn_base: Some(true), subsidy_net_of_fees: Some(true), burn_floor: Some(true) };
        let mut want = b"fees".to_vec();
        want.extend_from_slice(b"burn_base");
        want.push(1);
        want.extend_from_slice(b"subsidy_net_of_fees");
        want.push(1);
        want.extend_from_slice(b"burn_floor");
        want.push(1);
        assert_eq!(fees_commit(&all), want);
        // `false` spelt out commits nothing, so the two older sections keep their bytes.
        assert_eq!(fees_commit(&FeesConfig { burn_floor: Some(false), ..burn.clone() }), fees_commit(&burn));
        assert_eq!(fees_commit(&FeesConfig { burn_floor: Some(false), ..both.clone() }), fees_commit(&both));

        assert!(fees_commit(&FeesConfig::default()).is_empty());
        assert!(fees_commit(&FeesConfig { burn_base: Some(false), subsidy_net_of_fees: Some(false), burn_floor: None }).is_empty());

        // Each flag reaches the hash `build` computes, and the three are three chains.
        let hash_of = |f: Option<FeesConfig>| {
            let mut g = aggregating_genesis();
            g.fees = f;
            build(&g).hash()
        };
        let hashes = [hash_of(None), hash_of(Some(burn)), hash_of(Some(both)), hash_of(Some(net)), hash_of(Some(floor)), hash_of(Some(all))];
        for i in 0..hashes.len() {
            for j in i + 1..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "{i} vs {j}");
            }
        }
    }

    /// And its *position*: `fees_commit`'s bytes sit after the `tokens` bytes and before the
    /// `aggregation` bytes in the genesis commitment. The byte pin above cannot see a reorder —
    /// moving the `fees` block anywhere else in `build` keeps its bytes and makes a new chain —
    /// so this pins the hash of a genesis carrying all three sections (and the `bridge` the
    /// `tokens` section needs). A move of this hex is consensus-breaking: regenerate it only
    /// together with a deliberate change of the commitment's layout.
    #[test]
    fn the_fees_section_sits_between_tokens_and_aggregation_in_the_genesis_hash() {
        use crate::ledger::fees::FeesConfig;
        let mut g = aggregating_genesis();
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        g.alloc = opened_alloc();
        g.fees = Some(FeesConfig { burn_base: Some(true), subsidy_net_of_fees: Some(true), burn_floor: None });
        assert_eq!(build(&g).hash().to_hex(), "de93090f45fefa36f131e934849bf188aea7782ed47c07e77f653d32354ebc06");
    }

    /// Fee feedback: the fee-first subsidy nets the aggregation subsidy, so a chain without an
    /// `aggregation` section cannot ask for it; `burn_base` needs nothing.
    #[test]
    fn subsidy_net_of_fees_requires_an_aggregation_section() {
        use crate::ledger::fees::FeesConfig;
        let net = FeesConfig { burn_base: None, subsidy_net_of_fees: Some(true), burn_floor: None };
        let mut plain = base_genesis();
        plain.fees = Some(net.clone());
        let e = plain.validate().unwrap_err();
        assert!(matches!(e, GenesisError::SubsidyNetOfFeesWithoutAggregation), "{e}");
        assert!(e.to_string().contains("aggregation"), "{e}");

        let mut agg = aggregating_genesis();
        agg.fees = Some(net);
        assert!(agg.validate().is_ok());
        assert!(build(&agg).ledger.fees().subsidy_net_of_fees());

        let mut burn_only = base_genesis();
        burn_only.fees = Some(FeesConfig { burn_base: Some(true), subsidy_net_of_fees: Some(false), burn_floor: None });
        assert!(burn_only.validate().is_ok(), "burn_base needs no aggregation, and a false flag asks for nothing");
    }

    /// Issue #135: `burn_floor` widens the burned base to the whole floor, so without `burn_base`
    /// there is nothing to widen — refused by name rather than read as off. With it, on any
    /// chain, it validates; spelt `false` it asks for nothing.
    #[test]
    fn burn_floor_requires_burn_base() {
        use crate::ledger::fees::FeesConfig;
        for base in [None, Some(false)] {
            let mut g = base_genesis();
            g.fees = Some(FeesConfig { burn_base: base, subsidy_net_of_fees: None, burn_floor: Some(true) });
            let e = g.validate().unwrap_err();
            assert!(matches!(e, GenesisError::BurnFloorWithoutBurnBase), "{e}");
            assert!(e.to_string().contains("burn_base"), "{e}");
        }
        let mut g = base_genesis();
        g.fees = Some(FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: Some(true) });
        assert!(g.validate().is_ok());
        assert!(build(&g).ledger.fees().burn_floor());
        g.fees = Some(FeesConfig { burn_base: None, subsidy_net_of_fees: None, burn_floor: Some(false) });
        assert!(g.validate().is_ok(), "a false flag asks for nothing");
    }

    /// Fee feedback: the section round-trips through the file — kept as written when present,
    /// omitted entirely when absent, so every existing file serialises byte for byte as before.
    #[test]
    fn the_fees_section_round_trips_and_is_omitted_when_absent() {
        use crate::ledger::fees::FeesConfig;
        let g = genesis(1);
        assert!(!g.to_json().contains("\"fees\""), "absent from the file when absent");
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), g);

        let mut on = g.clone();
        on.fees = Some(FeesConfig { burn_base: Some(true), subsidy_net_of_fees: None, burn_floor: None });
        let json = on.to_json();
        assert!(json.contains("\"fees\"") && json.contains("\"burn_base\": true"), "{json}");
        assert!(!json.contains("subsidy_net_of_fees"), "an absent flag stays absent: {json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), on);
    }

    /// Audit v6 (TOK-1, issue #86): `tokens.incremental_root` is committed to the genesis hash
    /// under its own tag only when `true` — a chain-20-shaped file (no field) and a file saying
    /// `false` hash and root exactly as before — and reaches the registry, whose root (and the
    /// state root's domain) moves with it. The tag is last: it lands after `bridge_fees`, the
    /// newest tag before it, so a file carrying both commits both, in that order.
    #[test]
    fn the_incremental_token_root_is_committed_only_when_true_and_last() {
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
        });
        g.alloc = opened_alloc();
        let base = build(&g);
        assert!(!base.ledger.tokens().unwrap().incremental_root());
        assert!(!g.to_json().contains("incremental_root"), "absent from the file when absent");

        // The genesis binding itself (the genesis block's `parent`), not the block hash: the
        // state root moves with the flag too, so the block hash would move without the tag.
        let binding = |state: &GenesisState| state.block.header.parent;

        let mut off = g.clone();
        off.tokens.as_mut().unwrap().incremental_root = Some(false);
        let off_state = build(&off);
        assert_eq!(off_state.hash(), base.hash(), "`false` is today's rule and commits nothing");
        assert_eq!(binding(&off_state), binding(&base));
        assert_eq!(off_state.ledger.state_root(), base.ledger.state_root());
        assert!(!off_state.ledger.tokens().unwrap().incremental_root());

        let mut on = g.clone();
        on.tokens.as_mut().unwrap().incremental_root = Some(true);
        let on_state = build(&on);
        assert_ne!(binding(&on_state), binding(&base), "the flag is in the genesis binding");
        assert_ne!(on_state.hash(), base.hash());
        assert_ne!(on_state.ledger.state_root(), base.ledger.state_root(), "and in the state root");
        assert!(on_state.ledger.tokens().unwrap().incremental_root(), "and reaches the registry");
        assert!(on.to_json().contains("\"incremental_root\": true"));
        let back: Genesis = serde_json::from_str(&on.to_json()).unwrap();
        assert_eq!(back, on);

        // Last: with `bridge_fees` (the tag before it) the two commit in that order — the hash
        // with both is neither hash alone, and the bytes are `bridge_fees ‖ … ‖
        // tokens_incremental_root ‖ 1`, which `commit_bytes` below reproduces.
        let treasury = ShieldedAddress { pk: [3; 8], kem_ek: vec![0x11; crate::notes::KEM_EK_BYTES] };
        let fees = crate::bridge::BridgeFees { mint_bps: 10, burn_bps: 10, recipient: treasury };
        let mut both = on.clone();
        both.bridge.as_mut().unwrap().fees = Some(fees.clone());
        let mut fees_only = g.clone();
        fees_only.bridge.as_mut().unwrap().fees = Some(fees);
        let (both_state, fees_state) = (build(&both), build(&fees_only));
        assert_ne!(binding(&both_state), binding(&on_state));
        assert_ne!(binding(&both_state), binding(&fees_state), "the flag's tag follows the fees' in the binding");
    }

    /// Deep scan 2026-09-24 (ledger arithmetic): `tokens.bound_note_value` refuses a mint or
    /// deposit of a note the guest could never spend (2^63 and above). Committed to the genesis
    /// hash as `b"bound_note_value"` ‖ 1 only when `true` — a chain-14-shaped file (no field) and
    /// a file saying `false` hash and root exactly as before — and reaches the registry, whose
    /// root moves with it.
    #[test]
    fn the_note_value_bound_is_committed_only_when_true() {
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            tokens: vec![],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
        });
        g.alloc = opened_alloc();
        let base = build(&g);
        assert!(!base.ledger.tokens().unwrap().bounds_note_value());
        assert!(!g.to_json().contains("bound_note_value"), "absent from the file when absent");

        let mut off = g.clone();
        off.tokens.as_mut().unwrap().bound_note_value = Some(false);
        let off_state = build(&off);
        assert_eq!(off_state.hash(), base.hash(), "`false` is today's rule and commits nothing");
        assert_eq!(off_state.ledger.state_root(), base.ledger.state_root());
        assert!(!off_state.ledger.tokens().unwrap().bounds_note_value());

        let mut on = g.clone();
        on.tokens.as_mut().unwrap().bound_note_value = Some(true);
        let on_state = build(&on);
        assert_ne!(on_state.hash(), base.hash(), "the flag is in the genesis binding");
        assert_ne!(on_state.ledger.state_root(), base.ledger.state_root(), "and in the token root");
        assert!(on_state.ledger.tokens().unwrap().bounds_note_value(), "and reaches the registry");
        assert!(on.to_json().contains("bound_note_value"));
        let back: Genesis = serde_json::from_str(&on.to_json()).unwrap();
        assert_eq!(back, on);
    }

    /// Audit v4 (bridge rules v2): a `rules_v2` group inside the bridge section is committed to
    /// the genesis hash under its own tag only when present — a chain-14-shaped file (no group)
    /// hashes and roots exactly as before — reaches the bridge state and the registry's windows,
    /// and is held to its bounds: the window in `3600..=7*86400`, the global cap above zero.
    #[test]
    fn bridge_rules_v2_are_committed_only_when_present_and_bounded() {
        let mut bridged = genesis(1);
        bridged.bridge = Some(bridge_cfg());
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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

    /// Audit v6, BRG-14: the `bridge.rotation` group is committed under its own tag only when
    /// present (a chain-18-shaped file hashes, roots and stores as before), reaches the bridge
    /// state, needs `rules_v2` beside it, refuses an empty group and a delay of zero or over
    /// thirty days, and each of its two fields moves the hash alone.
    #[test]
    fn bridge_rotation_rules_are_committed_only_when_present_and_bounded() {
        use crate::bridge::{RotationRules, MAX_ROTATION_DELAY_SECS};
        let mut bridged = genesis(1);
        bridged.bridge = Some(bridge_cfg());
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        bridged.alloc = opened_alloc();
        bridged.bridge.as_mut().unwrap().rules_v2 = Some(crate::bridge::BridgeRulesV2 { global_mint_cap_per_window: 500_000 * 100_000_000, cap_window_secs: 86_400 });
        let base = build(&bridged);
        assert_eq!(base.ledger.bridge().unwrap().rotation_rules, None);
        assert_eq!(base.ledger.bridge().unwrap().rotation_meta(), None, "nothing to store without the group");
        assert!(!bridged.to_json().contains("rotation"), "absent from the file when absent");

        let rules = RotationRules { delay_secs: Some(86_400), needs_possession: Some(true) };
        let mut with = bridged.clone();
        with.bridge.as_mut().unwrap().rotation = Some(rules.clone());
        let built = build(&with);
        assert_ne!(built.hash(), base.hash(), "the group is in the genesis hash");
        // In the genesis commitment itself — the header's `parent` is its digest alone — and not
        // only through the state root the header also carries.
        assert_ne!(built.block.header.parent, base.block.header.parent, "the group is in the genesis commitment");
        assert_ne!(built.ledger.state_root(), base.ledger.state_root(), "and in the bridge root");
        assert_eq!(built.ledger.bridge().unwrap().rotation_rules, Some(rules.clone()));
        assert_eq!((built.ledger.bridge().unwrap().pending_pq.clone(), built.ledger.bridge().unwrap().pending_pause.clone()), (None, None));
        let back: Genesis = serde_json::from_str(&with.to_json()).unwrap();
        assert_eq!(back, with);
        assert!(with.to_json().contains("\"rotation\""));
        // Each field alone moves the hash, and the two together differ from either.
        let only = |r: RotationRules| {
            let mut g = bridged.clone();
            g.bridge.as_mut().unwrap().rotation = Some(r);
            build(&g).hash()
        };
        let delay_only = only(RotationRules { delay_secs: Some(86_400), needs_possession: None });
        let possession_only = only(RotationRules { delay_secs: None, needs_possession: Some(true) });
        assert!(delay_only != possession_only && delay_only != built.hash() && possession_only != built.hash());
        assert_ne!(only(RotationRules { delay_secs: Some(3_600), needs_possession: None }), delay_only);
        assert_ne!(only(RotationRules { delay_secs: None, needs_possession: Some(false) }), possession_only);

        let bad = |f: fn(&mut BridgeConfig)| {
            let mut g = with.clone();
            f(g.bridge.as_mut().unwrap());
            match g.validate() {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert!(bad(|b| b.rules_v2 = None).contains("rules_v2"));
        assert!(bad(|b| b.rotation = Some(RotationRules { delay_secs: None, needs_possession: None })).contains("empty"));
        assert!(bad(|b| b.rotation.as_mut().unwrap().delay_secs = Some(0)).contains("delay_secs"));
        assert!(bad(|b| b.rotation.as_mut().unwrap().delay_secs = Some(MAX_ROTATION_DELAY_SECS + 1)).contains("delay_secs"));
        let mut edge = with.clone();
        edge.bridge.as_mut().unwrap().rotation = Some(RotationRules { delay_secs: Some(MAX_ROTATION_DELAY_SECS), needs_possession: Some(false) });
        assert!(edge.validate().is_ok());
        // An unknown key inside the group is refused, as everywhere in the bridge section.
        let json = with.to_json().replace("\"needs_possession\"", "\"needs_possesion\"");
        assert!(Genesis::from_json(&json).is_err());
    }

    /// v0.6.8: the `bridge.fees` group is committed under its own tag only when present (a
    /// chain-18/19-shaped file hashes and roots as before), reaches the bridge state, round-trips
    /// through the file with the recipient as `rand1…` text, and refuses a share over 1 % and a
    /// recipient whose ML-KEM key is not one — or whose text is not an address at all.
    #[test]
    fn bridge_fees_are_committed_only_when_present_and_bounded() {
        use crate::bridge::{BridgeFees, MAX_BRIDGE_FEE_BPS};
        let mut bridged = genesis(1);
        bridged.bridge = Some(bridge_cfg());
        bridged.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        bridged.alloc = opened_alloc();
        let base = build(&bridged);
        assert_eq!(base.ledger.bridge().unwrap().fees, None);
        assert!(!bridged.to_json().contains("\"fees\""), "absent from the file when absent");

        let treasury = ShieldedAddress { pk: [3; 8], kem_ek: vec![0x11; crate::notes::KEM_EK_BYTES] };
        let fees = BridgeFees { mint_bps: 10, burn_bps: 10, recipient: treasury.clone() };
        let mut with = bridged.clone();
        with.bridge.as_mut().unwrap().fees = Some(fees.clone());
        with.validate().expect("a valid group");
        let built = build(&with);
        assert_ne!(built.block.header.parent, base.block.header.parent, "the group is in the genesis commitment");
        assert_ne!(built.ledger.state_root(), base.ledger.state_root(), "and in the bridge root");
        assert_eq!(built.ledger.bridge().unwrap().fees, Some(fees.clone()));
        let json = with.to_json();
        assert!(json.contains(&format!("\"recipient\": \"{}\"", treasury)), "the recipient is its rand1… text");
        let back: Genesis = serde_json::from_str(&json).unwrap();
        assert_eq!(back, with);
        // Each field moves the hash.
        let hash_of = |f: BridgeFees| {
            let mut g = bridged.clone();
            g.bridge.as_mut().unwrap().fees = Some(f);
            build(&g).hash()
        };
        assert_ne!(hash_of(BridgeFees { mint_bps: 11, ..fees.clone() }), built.hash());
        assert_ne!(hash_of(BridgeFees { burn_bps: 11, ..fees.clone() }), built.hash());
        assert_ne!(hash_of(BridgeFees { recipient: ShieldedAddress { pk: [4; 8], ..treasury.clone() }, ..fees.clone() }), built.hash());

        let bad = |f: &dyn Fn(&mut BridgeFees)| {
            let mut g = with.clone();
            f(g.bridge.as_mut().unwrap().fees.as_mut().unwrap());
            match g.validate() {
                Err(GenesisError::BadBridgeConfig(m)) => m,
                other => panic!("expected BadBridgeConfig, got {other:?}"),
            }
        };
        assert!(bad(&|f| f.mint_bps = MAX_BRIDGE_FEE_BPS + 1).contains("mint_bps"));
        assert!(bad(&|f| f.burn_bps = MAX_BRIDGE_FEE_BPS + 1).contains("burn_bps"));
        // A coefficient of 0xfff ≥ q: not an ML-KEM-768 key, whatever its length.
        assert!(bad(&|f| f.recipient.kem_ek = vec![0xff; crate::notes::KEM_EK_BYTES]).contains("kem_ek"));
        let mut edge = with.clone();
        edge.bridge.as_mut().unwrap().fees = Some(BridgeFees { mint_bps: MAX_BRIDGE_FEE_BPS, burn_bps: 0, recipient: treasury });
        assert!(edge.validate().is_ok());
        // Text that is not an address, and an unknown key in the group, are refused at parse.
        assert!(Genesis::from_json(&json.replace(&with.bridge.as_ref().unwrap().fees.as_ref().unwrap().recipient.to_string(), "rand1nonsense")).is_err());
        assert!(Genesis::from_json(&json.replace("\"burn_bps\"", "\"burn_bp\"")).is_err());
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
            g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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
        tok.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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
                backings: vec![GenesisBacking { chain: 2, token, decimals: BRIDGE_DECIMALS, locked: None }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
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
        two.tokens.as_mut().unwrap().tokens[0].backings.push(GenesisBacking { chain: 3, token: [0x33; 32], decimals: BRIDGE_DECIMALS, locked: None });
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
                    backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: BRIDGE_DECIMALS, locked: None }],
                },
                GenesisToken {
                    name: "USD Coin".into(),
                    symbol: "zUSDC".into(),
                    salt: [2; 32],
                    backings: vec![GenesisBacking { chain: 2, token: [0x22; 32], decimals: BRIDGE_DECIMALS, locked: None }],
                },
            ],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
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

    /// Chain 14's live zUSD registration, as `rand_getTokens` and its `RegisterBridgedToken`
    /// (transaction `7fa28fe6…`, block 256) show it: the name, symbol and salt that id it, and
    /// its seven backings in the registry's order — Ethereum USDT (the registration's own), then
    /// the six `ListBacking`s. Chain 15 lists exactly this at genesis.
    fn live_zusd(locked: [Option<u64>; 7]) -> GenesisToken {
        let coins: [(u16, &str, u8); 7] = [
            (2, "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", 6),
            (2, "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
            (3, "00000000000000000000000055d398326f99059ff775485246999027b3197955", 18),
            (3, "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
            (4, "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6),
            (5, "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", 6),
            (5, "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", 6),
        ];
        GenesisToken {
            name: "Shielded USD".into(),
            symbol: "zUSD".into(),
            salt: hex32("27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60"),
            backings: coins
                .iter()
                .zip(locked)
                .map(|(&(chain, token, decimals), locked)| GenesisBacking { chain, token: hex32(token), decimals, locked })
                .collect(),
        }
    }

    /// A genesis note of token `asset`, opened: the deposit commitment at that index.
    fn token_note(seed: u32, amount: u64, asset: u32) -> GenesisNote {
        let (pk, r) = ([seed; 8], [seed + 1; 8]);
        let mut n = note(seed, amount);
        n.cm = word8_to_hex(&StubExecutor.note_commitment(&pk, &[0; 8], amount, asset, 0, &r));
        n.opening = Some(GenesisOpening { pk: word8_to_hex(&pk), time: 0, r: word8_to_hex(&r), asset });
        n
    }

    /// Chain 15's shape: chain 14's zUSD listed at genesis with the residue custody chain 14 left
    /// behind — 9 USDT on Tron and 1 USDT on Solana, the ten zUSD a third party still holds —
    /// and one ten-zUSD note for that holder.
    fn chain15_shape() -> Genesis {
        let mut g = base_genesis();
        let mut bridge = bridge_cfg();
        bridge.emitters = (2u16..=5).map(|c| (c, [c as u8; 32])).collect();
        g.bridge = Some(bridge);
        g.tokens = Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            mint_cap_per_day: 100_000 * 100_000_000,
            tokens: vec![live_zusd([None, None, None, None, Some(900_000_000), Some(100_000_000), None])],
            max_tokens: None,
            burn_registration_fee: None,
            bound_note_value: None, incremental_root: None,
        });
        g.alloc = opened_alloc();
        g.alloc.push(token_note(21, 1_000_000_000, 1));
        g
    }

    /// The two carried-over bridge fields reach the genesis ledger's bridge and are committed
    /// only when present: chain 14's shape (neither field) is untouched, each one moves the hash,
    /// neither appears in a file that does not set it, and the last index is refused.
    #[test]
    fn a_bridge_can_start_at_a_guardian_set_and_burn_sequence_and_both_are_committed() {
        let g = chain15_shape();
        let plain = build(&g);
        let mut carried = g.clone();
        let b = carried.bridge.as_mut().unwrap();
        (b.guardian_set_index, b.burn_sequence) = (Some(1), Some(7));
        let s = build(&carried);
        let bridge = s.ledger.bridge().unwrap();
        assert_eq!((bridge.current_set, bridge.burn_sequence), (1, 7));
        assert_eq!(bridge.guardian_sets.keys().copied().collect::<Vec<_>>(), vec![1]);
        assert_ne!(s.hash(), plain.hash());
        let json = carried.to_json();
        assert!(json.contains("\"guardian_set_index\": 1") && json.contains("\"burn_sequence\": 7"), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), carried);
        assert!(!g.to_json().contains("guardian_set_index") && !g.to_json().contains("burn_sequence"));
        // Each one alone is its own chain.
        let mut index_only = g.clone();
        index_only.bridge.as_mut().unwrap().guardian_set_index = Some(1);
        let mut sequence_only = g.clone();
        sequence_only.bridge.as_mut().unwrap().burn_sequence = Some(7);
        let hashes = [plain.hash(), build(&index_only).hash(), build(&sequence_only).hash(), s.hash()];
        assert_eq!(hashes.iter().collect::<BTreeSet<_>>().len(), 4, "{hashes:?}");
        let mut last = g.clone();
        last.bridge.as_mut().unwrap().guardian_set_index = Some(u32::MAX);
        assert!(matches!(last.validate(), Err(GenesisError::BadBridgeConfig(m)) if m.contains("guardian_set_index")));
    }

    /// C15-1: the replay floor reaches the genesis ledger's bridge, is committed only when
    /// present (chain 15's shape, without it, keeps its hash; each floor is its own chain), is
    /// absent from a file that does not set it, and is refused empty, on an unregistered chain or
    /// at zero.
    #[test]
    fn a_bridge_replay_floor_is_committed_only_when_present_and_validated() {
        let mut g = chain15_shape();
        let b = g.bridge.as_mut().unwrap();
        (b.guardian_set_index, b.burn_sequence) = (Some(1), Some(7));
        let plain = build(&g);
        assert!(plain.ledger.bridge().unwrap().min_inbound_sequence.is_empty());
        let with = |floor: &[(u16, u64)]| {
            let mut f = g.clone();
            f.bridge.as_mut().unwrap().min_inbound_sequence = Some(floor.iter().copied().collect());
            f
        };
        let floored = with(&[(2, 3), (4, 2)]);
        let s = build(&floored);
        assert_eq!(
            s.ledger.bridge().unwrap().min_inbound_sequence,
            [(2u16, 3u64), (4, 2)].into_iter().collect::<BTreeMap<_, _>>()
        );
        let hashes = [plain.hash(), s.hash(), build(&with(&[(2, 4), (4, 2)])).hash(), build(&with(&[(2, 3)])).hash()];
        assert_eq!(hashes.iter().collect::<BTreeSet<_>>().len(), 4, "{hashes:?}");
        let json = floored.to_json();
        assert!(json.contains("\"min_inbound_sequence\": {"), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), floored);
        assert!(!g.to_json().contains("min_inbound_sequence"));
        for (floor, why) in [(&[][..], "empty"), (&[(6, 1)][..], "chain 6"), (&[(2, 0)][..], "is 0")] {
            match with(floor).validate() {
                Err(GenesisError::BadBridgeConfig(m)) => assert!(m.contains(why), "{m}"),
                other => panic!("{floor:?}: expected BadBridgeConfig, got {other:?}"),
            }
        }
    }

    /// Listed at genesis with chain 14's registration fields, zUSD keeps chain 14's asset id —
    /// what a wallet, the explorer and the bridge's own tables know it by.
    #[test]
    fn zusd_listed_at_genesis_keeps_chain_14s_asset_id() {
        let s = build(&chain15_shape());
        let z = s.ledger.tokens().unwrap().get(1).unwrap();
        assert_eq!(z.id.to_hex(), "32e5ab28c782c663e14da2650a3feb12f16a12db85599f4f62dc169d26f37b1f");
        assert_eq!((z.symbol.as_str(), z.decimals), ("zUSD", 8));
    }

    /// Chain 15: a bridged token can start the chain holding supply. Each backing's genesis
    /// `locked` goes through `lock`, so `total_supply == Σ locked` holds at block 0 and equals the
    /// token's genesis notes; the notes' commitments are recomputed at the token's index; and none
    /// of it is RAND supply.
    #[test]
    fn a_genesis_can_start_a_bridged_token_with_locked_custody_and_its_notes() {
        let g = chain15_shape();
        let s = build(&g);
        let t = s.ledger.tokens().unwrap();
        let z = t.get(1).unwrap();
        assert_eq!(z.total_supply, 1_000_000_000, "ten zUSD from block 0");
        let tron = &g.tokens.as_ref().unwrap().tokens[0].backings[4];
        let sol_usdt = &g.tokens.as_ref().unwrap().tokens[0].backings[5];
        assert_eq!(t.backing(1, 4, &tron.token).unwrap().locked, 900_000_000, "9 USDT on Tron");
        assert_eq!(t.backing(1, 5, &sol_usdt.token).unwrap().locked, 100_000_000, "1 USDT on Solana");
        assert!(t.backing_invariant_holds());
        // The token note is a leaf like any other, and RAND's genesis supply is the RAND notes
        // (and stakes) alone.
        assert_eq!(s.notes.len(), 3);
        assert_eq!(s.ledger.supply().genesis_deposited, 3_000_000);

        // The commitment is recomputed at the asset the opening names: a RAND note's commitment
        // declared as a zUSD note (or the reverse) never builds, so a file cannot pass a leaf of
        // one asset off as supply of another.
        let mut rand_as_zusd = g.clone();
        let (pk, r) = ([21; 8], [22; 8]);
        rand_as_zusd.alloc[2].cm = word8_to_hex(&crate::ledger::mint_commitment(&StubExecutor, &pk, 1_000_000_000, 0, &r));
        assert!(matches!(rand_as_zusd.build(&StubExecutor), Err(GenesisError::NoteCommitmentMismatch(_))));

        // A chain without any of it — chain 14's shape — is unchanged: no field in the file.
        let json = g.to_json();
        assert!(json.contains("\"locked\": 900000000") && json.contains("\"asset\": 1"), "{json}");
        let back = Genesis::from_json(&json).unwrap();
        assert_eq!(back, g);
        let plain = serde_json::to_string(&GenesisBacking { chain: 2, token: [1; 32], decimals: 6, locked: None }).unwrap();
        assert!(!plain.contains("locked"), "{plain}");
        assert!(!serde_json::to_string(&opened_note(1, 1)).unwrap().contains("asset"));
    }

    /// Custody and notes must agree per token, and a note must be of a listed token.
    #[test]
    fn genesis_token_notes_must_match_their_backings_locked_exactly() {
        // More notes than locked.
        let mut over = chain15_shape();
        over.alloc.push(token_note(22, 1, 1));
        assert!(matches!(
            over.validate(),
            Err(GenesisError::TokenSupplyMismatch { notes: 1_000_000_001, locked: 1_000_000_000, .. })
        ));
        // Locked with no note at all.
        let mut bare = chain15_shape();
        bare.alloc.pop();
        assert!(matches!(bare.validate(), Err(GenesisError::TokenSupplyMismatch { notes: 0, locked: 1_000_000_000, .. })));
        // A note with no locked behind it.
        let mut unbacked = chain15_shape();
        for b in &mut unbacked.tokens.as_mut().unwrap().tokens[0].backings {
            b.locked = None;
        }
        assert!(matches!(unbacked.validate(), Err(GenesisError::TokenSupplyMismatch { notes: 1_000_000_000, locked: 0, .. })));
        // An asset no listed token holds, and a token note on a chain that lists none.
        let mut unlisted = chain15_shape();
        unlisted.alloc[2] = token_note(21, 1_000_000_000, 2);
        assert!(matches!(unlisted.validate(), Err(GenesisError::BadNoteAsset { asset: 2, .. })));
        let mut tokenless = base_genesis();
        tokenless.alloc.push(token_note(21, 5, 1));
        assert!(matches!(tokenless.validate(), Err(GenesisError::BadNoteAsset { asset: 1, .. })));
        // A genesis lock is a lock: over the per-backing daily cap is refused, not written.
        let mut capped = chain15_shape();
        capped.tokens.as_mut().unwrap().mint_cap_per_day = 500_000_000;
        assert!(matches!(capped.build(&StubExecutor), Err(GenesisError::BadTokens(m)) if m.contains("chain 4")));
    }

    /// The custody split is part of the genesis binding: the same notes over a different split
    /// of `locked` across the backings are a different chain — through the state root, which
    /// holds every backing's `locked` and which the genesis header commits.
    #[test]
    fn the_genesis_locked_split_is_committed() {
        let g = chain15_shape();
        let mut other = g.clone();
        let b = &mut other.tokens.as_mut().unwrap().tokens[0].backings;
        b[4].locked = Some(800_000_000);
        b[5].locked = Some(200_000_000);
        assert_ne!(build(&other).hash(), build(&g).hash());
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
            GenesisBacking { chain: 2, token: hex32("000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7"), decimals: 6, locked: None },
            GenesisBacking { chain: 2, token: hex32("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), decimals: 6, locked: None },
            GenesisBacking { chain: 3, token: hex32("00000000000000000000000055d398326f99059ff775485246999027b3197955"), decimals: 18, locked: None },
            GenesisBacking { chain: 3, token: hex32("0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d"), decimals: 18, locked: None },
            GenesisBacking { chain: 4, token: hex32("000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c"), decimals: 6, locked: None },
            GenesisBacking { chain: 5, token: hex32("ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264"), decimals: 6, locked: None },
            GenesisBacking { chain: 5, token: hex32("c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61"), decimals: 6, locked: None },
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
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
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
        orphan.tokens.as_mut().unwrap().tokens[0].backings.push(GenesisBacking { chain: 9, token: backings[0].token, decimals: 6, locked: None });
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
            backings: vec![GenesisBacking { chain: 2, token: backings[0].token, decimals: 6, locked: None }],
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
            (2..MAX_BACKINGS as u16 + 3).map(|i| GenesisBacking { chain: i, token: [i as u8; 32], decimals: BRIDGE_DECIMALS, locked: None }).collect();
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
                backings: vec![GenesisBacking { chain: 2, token: [0x11; 32], decimals: 6, locked: None }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None,
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
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE - 1, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
        g.tokens = Some(TokensConfig { registration_fee: MAX_REGISTRATION_FEE + 1, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        assert!(matches!(g.validate(), Err(GenesisError::BadTokens(_))));
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        assert!(g.validate().is_ok());

        let dup = GenesisToken {
            name: "A".into(),
            symbol: "A".into(),
            salt: [3; 32],
            backings: vec![GenesisBacking { chain: 2, token: [1; 32], decimals: BRIDGE_DECIMALS, locked: None }],
        };
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![dup.clone(), dup], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
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

    /// `hardening_v6` is opt-in per chain and bound into the hash only when `true`, like
    /// `tokens.bound_note_value`: absent or `false` is the old rules and the same chain, `true` is a
    /// new chain whose ledger runs the v0.6 rules (the pc window first). Never state.
    #[test]
    fn hardening_v6_is_bound_into_the_hash_only_when_true() {
        let plain = genesis(2);
        assert_eq!(plain.hardening_v6, None);
        assert!(!plain.to_json().contains("hardening_v6"), "an absent flag is absent from the file");
        let s = build(&plain);
        assert!(!s.ledger.hardening_v6(), "absent means the old rule");

        let mut off = plain.clone();
        off.hardening_v6 = Some(false);
        let o = build(&off);
        assert_eq!(o.hash(), s.hash(), "`false` commits nothing");
        assert!(!o.ledger.hardening_v6());

        let mut on = plain.clone();
        on.hardening_v6 = Some(true);
        let g = build(&on);
        assert!(g.ledger.hardening_v6(), "the ledger runs the rule genesis names");
        assert_ne!(g.hash(), s.hash(), "the rule is a different chain");
        assert_eq!(g.ledger.state_root(), s.ledger.state_root(), "a parameter, not state");
        assert!(on.to_json().contains("\"hardening_v6\": true"));
        assert_eq!(Genesis::from_json(&on.to_json()).unwrap(), on, "and it round-trips");
    }

    /// Split authorisation's `hc_auth` is opt-in per chain: absent, the file, the hash and the
    /// ledger are as before (chains 14–16 hash unchanged — the node pins their files); present, it
    /// is bound into the hash (after `hardening_v6`), set on the ledger, never state, and a
    /// malformed one is refused.
    #[test]
    fn hc_auth_is_bound_into_the_hash_only_when_present() {
        // Block room for three proofs (`gas::min_block_bytes`): the chain-17 caps, on both sides
        // so the pin is the only difference.
        let mut plain = genesis(2);
        plain.max_proof_bytes = Some(4 << 20);
        plain.max_block_bytes = Some(20 << 20);
        assert_eq!(plain.hc_auth, None);
        assert!(!plain.to_json().contains("hc_auth"), "an absent pin is absent from the file");
        let s = build(&plain);
        assert_eq!(s.ledger.hc_auth(), None);

        let mut on = plain.clone();
        on.hc_auth = Some(word8_to_hex(&[21; 8]));
        let g = build(&on);
        assert_eq!(g.ledger.hc_auth(), Some([21; 8]), "the ledger runs the guest genesis names");
        assert_ne!(g.hash(), s.hash(), "the rule is a different chain");
        assert_eq!(g.ledger.state_root(), s.ledger.state_root(), "a parameter, not state");
        let mut other = plain.clone();
        other.hc_auth = Some(word8_to_hex(&[22; 8]));
        assert_ne!(build(&other).hash(), g.hash(), "and the pin itself is bound");
        assert!(on.to_json().contains("\"hc_auth\""));
        assert_eq!(Genesis::from_json(&on.to_json()).unwrap(), on, "and it round-trips");
        // After `hardening_v6`, and independent of it.
        let mut both = on.clone();
        both.hardening_v6 = Some(true);
        let mut v6 = plain.clone();
        v6.hardening_v6 = Some(true);
        assert!([s.hash(), g.hash(), build(&v6).hash()].iter().all(|h| *h != build(&both).hash()));

        let mut bad = plain.clone();
        bad.hc_auth = Some("not hex".into());
        assert!(matches!(bad.build(&StubExecutor), Err(GenesisError::BadHcAuth(_))));
    }

    /// A genesis every section `program_state` stands on is switched on in: `tokens`, a fixed
    /// `gas` section, `hardening_v6` and `hc_auth`, with a block big enough for three proofs.
    fn rpl2_ready() -> Genesis {
        let mut g = genesis(1);
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None });
        g.max_block_bytes = Some(20 << 20);
        g.gas = Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: gas::bundle_gas_limit_pin(),
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        });
        g.hardening_v6 = Some(true);
        g.hc_auth = Some(word8_to_hex(&[21; 8]));
        // A chain with a `tokens` section opens every genesis note; these tests need none.
        g.alloc.clear();
        g
    }

    /// RPL-2: the `program_state` section switches the ledger's program state on, empty, and is
    /// bound into the hash and the state root only when present. It needs the four sections it
    /// stands on, and its one parameter is bounded.
    #[test]
    fn a_program_state_section_is_committed_only_when_present_and_needs_what_it_stands_on() {
        use crate::ledger::program_state::{ProgramStateConfig, MAX_CELL_FEE};
        let plain = rpl2_ready();
        assert!(!plain.to_json().contains("program_state"), "an absent section is absent from the file");
        let bare = build(&plain);
        assert!(bare.ledger.program_state().is_none());

        let mut on = plain.clone();
        on.program_state = Some(ProgramStateConfig { cell_fee: 10_000_000 });
        let g = build(&on);
        let state = g.ledger.program_state().expect("the section seeds an empty program state");
        assert_eq!((state.cell_fee, state.cell_count(), state.rand_held()), (10_000_000, 0, 0));
        assert_ne!(g.hash(), bare.hash(), "the section is a different chain");
        assert_ne!(g.ledger.state_root(), bare.ledger.state_root(), "and its root is in the state root");
        assert!(g.ledger.audit().invariant_holds() == bare.ledger.audit().invariant_holds(), "no value is seeded");
        let mut dearer = on.clone();
        dearer.program_state = Some(ProgramStateConfig { cell_fee: 10_000_001 });
        assert_ne!(build(&dearer).hash(), g.hash(), "the cell fee is bound");
        assert_eq!(build(&dearer).ledger.state_root(), g.ledger.state_root(), "a parameter, not state");
        assert_eq!(Genesis::from_json(&on.to_json()).unwrap(), on, "it round-trips");
        assert!(Genesis::from_json(&on.to_json().replace("\"cell_fee\"", "\"cell_fees\"")).is_err(), "a stray key is refused");

        // What it stands on, one missing at a time.
        type Drop = fn(&mut Genesis);
        let drops: [(&str, Drop); 4] = [
            ("tokens", |g| g.tokens = None),
            ("gas", |g| g.gas = None),
            ("hardening_v6", |g| g.hardening_v6 = None),
            ("hc_auth", |g| g.hc_auth = None),
        ];
        for (name, drop) in drops {
            let mut g = on.clone();
            drop(&mut g);
            match g.build(&StubExecutor) {
                Err(GenesisError::BadProgramState(why)) => assert!(why.contains(name), "{name}: {why}"),
                other => panic!("{name}: {:?}", other.map(|s| s.hash())),
            }
        }
        let mut off = on.clone();
        off.confidential = false;
        assert!(matches!(off.build(&StubExecutor), Err(GenesisError::BadProgramState(_))));
        let mut over = on.clone();
        over.program_state = Some(ProgramStateConfig { cell_fee: MAX_CELL_FEE + 1 });
        assert!(matches!(over.build(&StubExecutor), Err(GenesisError::BadProgramState(_))));
        let mut edge = on;
        edge.program_state = Some(ProgramStateConfig { cell_fee: MAX_CELL_FEE });
        edge.build(&StubExecutor).unwrap();
    }

    /// Split authorisation (review I-1): a v3 `Call` carries three proofs — bundle, auth, call —
    /// so with `hc_auth` set the block cap must hold `3 · max_proof_bytes + 1 MiB`, judged even
    /// when the file sets neither cap (the 4 MiB default would admit no `Call` at production FRI).
    /// A chain without `hc_auth` keeps the two-proof rule, both edges.
    #[test]
    fn a_split_auth_genesis_needs_block_room_for_three_proofs() {
        let headroom = crate::gas::BLOCK_PROOF_HEADROOM as u32;
        let caps = |auth: bool, proof: Option<u32>, block: Option<u32>| {
            let mut g = genesis(2);
            g.hc_auth = auth.then(|| word8_to_hex(&[21; 8]));
            g.max_proof_bytes = proof;
            g.max_block_bytes = block;
            g
        };
        let p = 4u32 << 20;
        // v3: one byte under 3p + 1 MiB is refused, naming the three proofs and both numbers.
        let under = caps(true, Some(p), Some(3 * p + headroom - 1));
        match under.build(&StubExecutor) {
            Err(e @ GenesisError::BlockTooSmallForSplitAuth { block, proof, need }) => {
                assert_eq!((block, proof, need), ((3 * p + headroom - 1) as usize, p as usize, (3 * p + headroom) as usize));
                let msg = e.to_string();
                assert!(msg.contains("bundle, auth, call") && msg.contains(&p.to_string()) && msg.contains(&(3 * p + headroom - 1).to_string()), "{msg}");
            }
            other => panic!("expected BlockTooSmallForSplitAuth, got {:?}", other.map(|s| s.hash())),
        }
        // Exactly 3p + 1 MiB passes; so do chain 17's 4 MiB proofs in 20 MiB blocks.
        assert!(caps(true, Some(p), Some(3 * p + headroom)).build(&StubExecutor).is_ok());
        assert!(caps(true, Some(p), Some(20 << 20)).build(&StubExecutor).is_ok());
        // Neither cap set: the defaults (2 MiB proofs, 4 MiB blocks) are refused under hc_auth…
        assert!(matches!(
            caps(true, None, None).build(&StubExecutor),
            Err(GenesisError::BlockTooSmallForSplitAuth { block, proof, need })
                if block == crate::gas::MAX_BLOCK_BYTES && proof == crate::gas::MAX_PROOF_BYTES && need == 7 << 20
        ));
        // …and chain 16's 8 MiB proofs in 20 MiB blocks would be too.
        assert!(caps(true, Some(8 << 20), Some(20 << 20)).build(&StubExecutor).is_err());
        // Pre-v3: the two-proof threshold, both edges, and the rule-free defaults.
        assert!(matches!(
            caps(false, Some(p), Some(2 * p + headroom - 1)).build(&StubExecutor),
            Err(GenesisError::BadMaxBlockBytes(n)) if n == 2 * p + headroom - 1
        ));
        assert!(caps(false, Some(p), Some(2 * p + headroom)).build(&StubExecutor).is_ok());
        assert!(caps(false, None, None).build(&StubExecutor).is_ok());
    }

    /// The `gas` section (design 2026-09-28 §4.2, §4.3, §7.1) is bound into the genesis hash
    /// only when present, prices are decimal strings, and `dynamic` is bound under its own tag.
    #[test]
    fn the_gas_section_is_bound_into_the_hash_only_when_present() {
        let plain = genesis(1);
        assert!(plain.gas.is_none() && !plain.to_json().contains("\"gas\""));
        let h0 = build(&plain).hash();

        let mut g = plain.clone();
        g.gas = Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        });
        let s = build(&g);
        assert_ne!(s.hash(), h0);
        assert_eq!(s.ledger.gas().unwrap().gas_price, 100);
        assert!(g.to_json().contains("\"gas_price\": \"100\""), "amounts are decimal strings");
        assert_eq!(s.ledger.state_root(), build(&plain).ledger.state_root(), "a parameter, not state");

        let mut d = g.clone();
        d.gas.as_mut().unwrap().dynamic = Some(gas::DynamicGas {
            target_block_bytes: 2 << 20,
            target_block_gas: 1 << 18,
            adjust_bps: 1250,
            min_gas_price: 100,
            min_byte_price: 800,
            max_gas_price: None,
            max_byte_price: None,
            byte_load: None,
        });
        assert_ne!(build(&d).hash(), build(&g).hash(), "dynamic is bound under its own tag");
        assert_eq!(Genesis::from_json(&d.to_json()).unwrap(), d, "round-trips");
    }

    /// `GasConfig::check`'s rules, reached through `Genesis::validate`.
    #[test]
    fn the_gas_section_is_validated() {
        let base = genesis(1);
        let ok = gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        };
        let mut g = base.clone();
        g.gas = Some(gas::GasConfig { gas_price: 0, ..ok.clone() });
        assert!(g.validate().unwrap_err().to_string().contains("gas_price"));

        let mut g = base.clone();
        g.gas = Some(gas::GasConfig { bundle_gas_limit: 0, ..ok.clone() });
        assert!(g.validate().unwrap_err().to_string().contains("bundle_gas_limit"));

        let bad_dyn = |d: gas::DynamicGas| -> String {
            let mut g = base.clone();
            g.gas = Some(gas::GasConfig { dynamic: Some(d), ..ok.clone() });
            g.validate().unwrap_err().to_string()
        };
        let d = gas::DynamicGas {
            target_block_bytes: 2 << 20,
            target_block_gas: 1 << 18,
            adjust_bps: 1250,
            min_gas_price: 100,
            min_byte_price: 800,
            max_gas_price: None,
            max_byte_price: None,
            byte_load: None,
        };
        assert!(bad_dyn(gas::DynamicGas { adjust_bps: 0, ..d.clone() }).contains("adjust_bps"));
        assert!(bad_dyn(gas::DynamicGas { adjust_bps: 5001, ..d.clone() }).contains("adjust_bps"));
        assert!(bad_dyn(gas::DynamicGas { target_block_bytes: (64 << 20) + 1, ..d.clone() }).contains("target_block_bytes"));
        assert!(bad_dyn(gas::DynamicGas { target_block_gas: 0, ..d.clone() }).contains("target_block_gas"));
        assert!(
            bad_dyn(gas::DynamicGas { min_gas_price: 101, ..d.clone() }).contains("min_gas_price"),
            "the floor cannot exceed the starting price"
        );
    }

    /// Final-review minor 6: the gas section's contribution to the genesis hash, byte for byte,
    /// written out by hand — a reordered, re-endianed or re-tagged field is a new chain, so it
    /// must fail here first. And it is what `build` appends: each field moves the hash.
    #[test]
    fn the_gas_sections_hash_contribution_is_pinned() {
        let fixed = gas::GasConfig {
            gas_price: 0x0102,
            byte_price: 0x0304,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        };
        let mut want = b"gas".to_vec();
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x02]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x03, 0x04]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x4f, 0xff]); // 20 479
        want.extend_from_slice(b"circuit");
        assert_eq!(gas_commit(&fixed), want);

        let dynamic = gas::GasConfig {
            dynamic: Some(gas::DynamicGas {
                target_block_bytes: 10_485_760,
                target_block_gas: 262_144,
                adjust_bps: 1250,
                min_gas_price: 0x0102,
                min_byte_price: 0x0304,
                max_gas_price: None,
                max_byte_price: None,
                byte_load: None,
            }),
            ..fixed.clone()
        };
        want.extend_from_slice(b"gas_dynamic");
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0xa0, 0, 0]); // 10 485 760
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0x04, 0, 0]); // 262 144
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x04, 0xe2]); // 1 250
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x02]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x03, 0x04]);
        assert_eq!(gas_commit(&dynamic), want);

        // Every field reaches the hash `build` computes.
        let hash_of = |cfg: gas::GasConfig| {
            let mut g = genesis(1);
            g.max_block_bytes = Some(20 << 20);
            g.gas = Some(cfg);
            build(&g).hash()
        };
        let base = hash_of(dynamic.clone());
        let d = dynamic.dynamic.clone().unwrap();
        for moved in [
            gas::GasConfig { gas_price: 0x0103, dynamic: Some(gas::DynamicGas { min_gas_price: 0x0103, ..d.clone() }), ..dynamic.clone() },
            gas::GasConfig { byte_price: 0x0305, ..dynamic.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { target_block_bytes: 10_485_761, ..d.clone() }), ..dynamic.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { target_block_gas: 262_145, ..d.clone() }), ..dynamic.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { adjust_bps: 1251, ..d.clone() }), ..dynamic.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { min_byte_price: 0x0303, ..d.clone() }), ..dynamic.clone() },
            fixed.clone(),
        ] {
            assert_ne!(hash_of(moved.clone()), base, "{moved:?}");
        }
        // Audit v6, POOL-2: the two ceilings and the byte load, each tagged and appended only
        // when set, in this order after the floors — chain 18's section commits as above.
        let capped = gas::GasConfig {
            dynamic: Some(gas::DynamicGas {
                max_gas_price: Some(0x0105),
                max_byte_price: Some(0x0306),
                byte_load: Some(gas::ByteLoad::Paying),
                ..d.clone()
            }),
            ..dynamic.clone()
        };
        want.extend_from_slice(b"max_gas_price");
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x05]);
        want.extend_from_slice(b"max_byte_price");
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x03, 0x06]);
        want.extend_from_slice(b"byte_load");
        want.extend_from_slice(b"paying");
        assert_eq!(gas_commit(&capped), want);
        let cd = capped.dynamic.clone().unwrap();
        for moved in [
            gas::GasConfig { dynamic: Some(gas::DynamicGas { max_gas_price: Some(0x0106), ..cd.clone() }), ..capped.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { max_byte_price: Some(0x0307), ..cd.clone() }), ..capped.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { byte_load: None, ..cd.clone() }), ..capped.clone() },
            gas::GasConfig { dynamic: Some(gas::DynamicGas { max_gas_price: None, ..cd.clone() }), ..capped.clone() },
            dynamic.clone(),
        ] {
            assert_ne!(hash_of(moved.clone()), hash_of(capped.clone()), "{moved:?}");
        }
        // A ceiling under the starting price is refused at the file.
        let mut g = genesis(1);
        g.max_block_bytes = Some(20 << 20);
        g.gas = Some(gas::GasConfig { dynamic: Some(gas::DynamicGas { max_gas_price: Some(0x0101), ..cd.clone() }), ..capped.clone() });
        assert!(matches!(g.validate(), Err(GenesisError::Gas(ref why)) if why.contains("max_gas_price 257 is under the starting gas_price 258")), "{:?}", g.validate());
    }

    /// Final-review minor 5: a misspelled key inside `gas` (or `gas.dynamic`) is refused at
    /// parse — a `"dynamik"` must not quietly mean fixed prices, nor a `"min_gas_prise"` a floor
    /// of the default.
    #[test]
    fn a_misspelled_gas_key_is_refused() {
        let mut g = genesis(1);
        g.gas = Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: Some(gas::DynamicGas {
                target_block_bytes: 2 << 20,
                target_block_gas: 1 << 18,
                adjust_bps: 1250,
                min_gas_price: 100,
                min_byte_price: 800,
                max_gas_price: None,
                max_byte_price: None,
                byte_load: None,
            }),
        });
        let json = g.to_json();
        assert!(Genesis::from_json(&json).is_ok());
        let dynamik = json.replacen("\"dynamic\"", "\"dynamik\"", 1);
        assert_ne!(dynamik, json);
        assert!(Genesis::from_json(&dynamik).is_err(), "a misspelled `dynamic` must not parse as fixed prices");
        let inner = json.replacen("\"adjust_bps\"", "\"adjust_bps\": 1250, \"adjust_bsp\"", 1);
        assert_ne!(inner, json);
        assert!(Genesis::from_json(&inner).is_err(), "an unknown key inside `dynamic` is refused too");
    }

    /// Final-review I3: `bundle_gas_limit` must be the bundle guest's own ceiling,
    /// `gas_max(BUNDLE_PROOF_TIER, 0, 0)` = 20 479 — every bundle proof declares exactly that, so
    /// any other value is a chain on which no bundle can ever be admitted.
    #[test]
    fn the_bundle_gas_limit_must_be_the_bundle_guests_ceiling() {
        let pin = gas::gas_max(crate::types::BUNDLE_PROOF_TIER, 0, 0);
        assert_eq!(pin, 20_479);
        let with = |limit: u64| {
            let mut g = genesis(1);
            g.gas = Some(gas::GasConfig {
                gas_price: 100,
                byte_price: 800,
                bundle_gas_limit: limit,
                metering: gas::GasMetering::Circuit,
                dynamic: None,
            });
            g.validate()
        };
        for bad in [7, pin - 1, pin + 1, gas::gas_max(12, 0, 0)] {
            let e = with(bad).expect_err(&format!("bundle_gas_limit {bad} must be refused")).to_string();
            assert!(e.contains("bundle_gas_limit") && e.contains("20479"), "{e}");
        }
        assert!(with(pin).is_ok());
    }

    /// Controller ruling (task B6): `gas.dynamic` prices bytes by Σ `encoded_len` over the block
    /// as served, and a pruned (marker-form) bundle encodes shorter than its raw form, so a node
    /// syncing sealed history would compute another byte price and fail the root. Refused by name
    /// until the side table carries raw lengths; a fixed-price section beside aggregation is fine.
    #[test]
    fn dynamic_gas_is_refused_beside_aggregation() {
        use crate::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use crate::types::{DeclaredShape, FriProfile};
        let shape = DeclaredShape {
            profile: FriProfile::Production,
            tier: crate::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: crate::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        let fixed = gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        };
        let dynamic = gas::GasConfig {
            dynamic: Some(gas::DynamicGas {
                target_block_bytes: 2 << 20,
                target_block_gas: 1 << 18,
                adjust_bps: 1250,
                min_gas_price: 100,
                min_byte_price: 800,
                max_gas_price: None,
                max_byte_price: None,
                byte_load: None,
            }),
            ..fixed.clone()
        };
        let with = |g_cfg: gas::GasConfig| {
            let mut g = base_genesis();
            g.fri_profile = "production".into();
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
            g.gas = Some(g_cfg);
            g.validate()
        };
        assert!(with(fixed).is_ok(), "fixed prices never move, so sealed sync cannot diverge on them");
        let e = with(dynamic.clone()).unwrap_err();
        assert!(matches!(e, GenesisError::DynamicGasWithAggregation), "{e}");
        assert!(e.to_string().contains("gas.dynamic cannot be combined with aggregation"), "{e}");
        let mut alone = base_genesis();
        alone.gas = Some(dynamic);
        assert!(alone.validate().is_ok(), "dynamic without aggregation is fine");
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

    /// Spec 2026-09-26 §2.4: `envelope_bytes` is opt-in like the call limits — absent, the file
    /// and the hash are today's and the ledger keeps today's at-most rule; present, only
    /// `MEMO_ENVELOPE_BYTES` is accepted, it is bound into the hash, and the state root never
    /// sees it.
    #[test]
    fn envelope_bytes_is_optional_bound_into_the_hash_and_only_1860() {
        let plain = genesis(2);
        let json = plain.to_json();
        assert!(!json.contains("envelope_bytes"));
        assert_eq!(build(&plain).ledger.envelope_bytes(), None);
        let mut g = plain.clone();
        g.alloc = memo_alloc();
        let unset = build(&g);
        g.envelope_bytes = Some(crate::notes::MEMO_ENVELOPE_BYTES as u32);
        let s = build(&g);
        assert_eq!(s.ledger.envelope_bytes(), Some(crate::notes::MEMO_ENVELOPE_BYTES));
        assert_ne!(s.hash(), unset.hash(), "a new chain");
        assert_eq!(s.ledger.state_root(), unset.ledger.state_root(), "not state");
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), g, "and it round-trips");
        assert!(g.to_json().contains("\"envelope_bytes\": 1860"));
        for bad in [0u32, 1348, 1859, 1861, 2048] {
            let mut g = plain.clone();
            g.envelope_bytes = Some(bad);
            assert!(
                matches!(g.build(&StubExecutor).err(), Some(GenesisError::BadEnvelopeBytes(n)) if n == bad),
                "{bad}"
            );
        }
    }

    /// Two alloc notes like [`genesis`]'s, their envelopes exactly `MEMO_ENVELOPE_BYTES` long.
    fn memo_alloc() -> Vec<GenesisNote> {
        let mut alloc = vec![note(7, 1_000_000), note(8, 2_000_000)];
        for n in &mut alloc {
            let mut e = n.envelope.to_envelope().unwrap();
            e.body = vec![2; crate::notes::MEMO_ENVELOPE_BYTES - e.kem_ct.len()];
            n.envelope = EnvelopeHex::from_envelope(&e);
        }
        alloc
    }

    #[test]
    fn under_envelope_bytes_every_alloc_envelope_is_exactly_that_long() {
        let mut g = genesis(2);
        g.envelope_bytes = Some(crate::notes::MEMO_ENVELOPE_BYTES as u32);
        // `genesis(2)`'s alloc envelopes are the fixture's 16-byte ones.
        assert!(
            matches!(
                g.build(&StubExecutor).err(),
                Some(GenesisError::AllocEnvelopeSize { ref cm, got: 16, want: crate::notes::MEMO_ENVELOPE_BYTES }) if *cm == g.alloc[0].cm
            ),
            "{:?}",
            g.build(&StubExecutor).err()
        );
        // An opened alloc note one byte short is refused by name too.
        let mut opened = opened_alloc();
        let mut e = opened[1].envelope.to_envelope().unwrap();
        e.body = vec![0; crate::notes::MEMO_ENVELOPE_BYTES - 1 - e.kem_ct.len()];
        opened[1].envelope = EnvelopeHex::from_envelope(&e);
        let mut first = opened[0].envelope.to_envelope().unwrap();
        first.body = vec![0; crate::notes::MEMO_ENVELOPE_BYTES - first.kem_ct.len()];
        opened[0].envelope = EnvelopeHex::from_envelope(&first);
        g.alloc = opened.clone();
        assert!(
            matches!(
                g.build(&StubExecutor).err(),
                Some(GenesisError::AllocEnvelopeSize { ref cm, got, want: crate::notes::MEMO_ENVELOPE_BYTES }) if *cm == opened[1].cm && got == crate::notes::MEMO_ENVELOPE_BYTES - 1
            ),
            "{:?}",
            g.build(&StubExecutor).err()
        );
        // Exactly the length builds.
        g.alloc = memo_alloc();
        assert!(g.build(&StubExecutor).is_ok());
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
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None, mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        g.faucet = true;
        // Audit v6, STAKE-2: chain 14's shape — a faucet beside a bridge, no section — loads
        // on chain 14's own id and, on any other, only with the explicit `testnet` marker
        // (`a_faucet_beside_a_bridge_needs_the_testnet_marker_on_a_new_chain`).
        g.testnet = Some(true);
        assert!(g.validate().is_ok(), "chain 14's shape still loads, marked");
        let unsectioned = build(&g);
        assert!(unsectioned.ledger.staking().is_none());
        assert!(!g.to_json().contains("staking"), "and its file never mentions the section");
        let cfg = StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() };
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

    /// Audit v6, STAKE-2 (option 2): "mainnet never carries a faucet" was a sentence in
    /// `docs/deploy.md`. Now a genesis with `faucet: true` and a `bridge` section is refused on
    /// any chain id not in [`FAUCET_BESIDE_BRIDGE_CHAIN_IDS`] unless it says `testnet: true` —
    /// whether or not it has a `staking` section or an allowlist. The marker is committed to the
    /// hash only when `true`, rides on the ledger for the node to serve, and chains 14–19 (the
    /// committed files with both and no marker) still validate by id alone.
    #[test]
    fn a_faucet_beside_a_bridge_needs_the_testnet_marker_on_a_new_chain() {
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None, mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        g.faucet = true;
        assert_eq!(g.testnet, None, "the shape every chain through 18 was cut with");
        let id = g.chain_id;
        assert!(!FAUCET_BESIDE_BRIDGE_CHAIN_IDS.contains(&id), "a new chain id");
        assert!(matches!(g.validate(), Err(GenesisError::FaucetWithBridgeNeedsTestnet { chain_id }) if chain_id == id), "{:?}", g.validate());
        assert!(matches!(g.build(&StubExecutor), Err(GenesisError::FaucetWithBridgeNeedsTestnet { chain_id }) if chain_id == id));
        g.testnet = Some(false);
        assert!(matches!(g.validate(), Err(GenesisError::FaucetWithBridgeNeedsTestnet { .. })), "`false` is not a marker");
        // A staking section with an allowlist does not stand in for it: the two rules stack.
        let mut listed = g.clone();
        listed.staking = Some(StakingConfig {
            faucet_budget_per_epoch: 100 * UNITS_PER_RAND,
            bond_activation_epochs: 2,
            faucet_recipients: Some(vec![FaucetRecipient([1; 8])]),
            ..Default::default()
        });
        assert!(matches!(listed.validate(), Err(GenesisError::FaucetWithBridgeNeedsTestnet { .. })));
        // Marked, it builds; the marker is on the ledger, in the file and in the hash.
        g.testnet = Some(true);
        let s = build(&g);
        assert!(s.ledger.testnet() && s.testnet);
        assert!(g.to_json().contains("\"testnet\": true"));
        assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), g);
        listed.testnet = Some(true);
        assert!(listed.validate().is_ok(), "marked and allowlisted: chain 15's shape on a new id");
        // Without a bridge the marker is optional, and only `true` moves the hash.
        let plain = genesis(1);
        let mut marked = plain.clone();
        marked.testnet = Some(true);
        let mut unmarked = plain.clone();
        unmarked.testnet = Some(false);
        assert_ne!(build(&marked).hash(), build(&plain).hash(), "the marker is part of the genesis hash");
        assert_eq!(build(&unmarked).hash(), build(&plain).hash(), "`false` commits nothing");
        assert!(!plain.to_json().contains("testnet"), "absent from a file that does not set it");
        assert!(!build(&plain).ledger.testnet());
        assert_eq!(build(&marked).ledger.state_root(), build(&plain).ledger.state_root(), "never state");
        // The chains cut before the marker are grandfathered by id, and nothing else is.
        let mut old = g.clone();
        old.testnet = None;
        for id in FAUCET_BESIDE_BRIDGE_CHAIN_IDS {
            old.chain_id = *id;
            assert!(old.validate().is_ok(), "chain {id} predates the marker");
        }
        assert_eq!(FAUCET_BESIDE_BRIDGE_CHAIN_IDS, &[14, 15, 16, 17, 18, 19]);
        old.chain_id = 20;
        assert!(matches!(old.validate(), Err(GenesisError::FaucetWithBridgeNeedsTestnet { chain_id: 20 })));
    }

    /// Every committed genesis file still validates under the rule above: the ones with a faucet
    /// beside a bridge are exactly the grandfathered ids, and every other file is untouched by it.
    /// A file this build's `Genesis` no longer parses (a chain cut before a required field
    /// existed) is skipped, named — the rule cannot be what refuses it.
    #[test]
    fn every_committed_genesis_file_still_validates() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy");
        let mut seen = 0;
        let mut both = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !(name.starts_with("genesis-chain") && name.ends_with(".json")) {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let Ok(g) = Genesis::from_json(&text) else {
                eprintln!("{name}: predates a required field; skipped");
                continue;
            };
            seen += 1;
            assert!(g.validate().is_ok(), "{name}: {:?}", g.validate().err());
            // A chain cut on a build with the marker (chain 20 on) says it; every grandfathered
            // chain was cut before it existed and does not.
            if g.testnet == Some(true) {
                assert!(!FAUCET_BESIDE_BRIDGE_CHAIN_IDS.contains(&g.chain_id), "{name}: a grandfathered id needs no marker");
                continue;
            }
            assert_eq!(g.testnet, None, "{name}: cut before the marker existed");
            if g.faucet && g.bridge.is_some() {
                both.push(g.chain_id);
            }
        }
        assert!(seen >= 6, "the chain 14–19 files at least");
        both.sort();
        assert_eq!(both, FAUCET_BESIDE_BRIDGE_CHAIN_IDS, "the grandfathered ids are exactly the committed files with both");
    }

    /// Chain 15: `staking.faucet_recipients` limits the faucet to named spend keys, and that is
    /// what lets `faucet: true` sit beside a `bridge` section. An empty or duplicated list is
    /// refused; the list is committed to the genesis hash only when present, key by key, and a
    /// `rand1…` address and the hex of its `pk` name the same key — the same chain.
    #[test]
    fn a_faucet_allowlist_lets_a_bridged_chain_keep_its_faucet() {
        use crate::notes::{ShieldedAddress, KEM_EK_BYTES};
        let mut g = genesis(1);
        g.bridge = Some(bridge_cfg());
        g.tokens = Some(TokensConfig { registration_fee: MIN_REGISTRATION_FEE, tokens: vec![], max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None, mint_cap_per_day: 100_000 * 100_000_000 });
        g.alloc = opened_alloc();
        g.faucet = true;
        g.testnet = Some(true);
        g.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let plain = g.clone();
        assert!(matches!(plain.validate(), Err(GenesisError::FaucetWithBridge)), "no list, no faucet beside a bridge");
        let with = |list: Vec<FaucetRecipient>| {
            let mut g = plain.clone();
            g.staking.as_mut().unwrap().faucet_recipients = Some(list);
            g
        };
        let (me, anish) = (FaucetRecipient([5; 8]), FaucetRecipient([6; 8]));
        let listed = with(vec![me, anish]);
        let s = build(&listed);
        assert_eq!(s.ledger.staking().unwrap().faucet_recipients, Some(vec![me, anish]), "the ledger runs with the list");
        assert!(matches!(with(vec![]).validate(), Err(GenesisError::BadStaking(_))), "an empty list pays no one");
        assert!(matches!(with(vec![me, me]).validate(), Err(GenesisError::BadStaking(_))));
        // Committed, key by key; absent from the file and the hash when unset.
        let unlisted = { let mut u = plain.clone(); u.bridge = None; u };
        assert!(!unlisted.to_json().contains("faucet_recipients"));
        let unlisted_hash = build(&unlisted).hash();
        let mut listed_unbridged = unlisted.clone();
        listed_unbridged.staking.as_mut().unwrap().faucet_recipients = Some(vec![me]);
        assert_ne!(build(&listed_unbridged).hash(), unlisted_hash);
        assert_ne!(build(&with(vec![me])).hash(), build(&with(vec![anish])).hash());
        assert_ne!(s.hash(), build(&with(vec![me])).hash());
        // The file writes hex and reads either spelling back to the same chain.
        let json = listed.to_json();
        let me_hex = crate::notes::word8_to_hex(&me.0);
        assert!(json.contains(&me_hex), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), listed);
        let address = ShieldedAddress { pk: me.0, kem_ek: vec![7; KEM_EK_BYTES] }.to_string();
        let by_address = Genesis::from_json(&json.replace(&me_hex, &address)).unwrap();
        assert_eq!(by_address, listed);
        assert_eq!(build(&by_address).hash(), s.hash());
        assert!(Genesis::from_json(&json.replace(&me_hex, "rand1notanaddress")).is_err());
        assert!(Genesis::from_json(&json.replace(&me_hex, "abcd")).is_err());
    }

    /// RESCAN-LEDGER-1's `staking.faucet_minters`, parsed, validated and committed exactly like
    /// `faucet_recipients`: absent from the file and the hash unless set, an empty or duplicated
    /// list refused, committed address by address, and the three spellings of a key — base58
    /// address, its 64 hex characters, the validator's public key in hex — one chain. The ledger
    /// runs with the list.
    #[test]
    fn a_faucet_minter_list_is_committed_only_when_present_and_refused_empty_or_duplicated() {
        let mut base = genesis(2);
        base.faucet = true;
        base.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let plain = build(&base);
        assert!(!base.to_json().contains("faucet_minters"), "absent from a file that does not set it");
        let (a, b) = (base.validators[0].public_key.clone(), base.validators[1].public_key.clone());
        let with = |list: Vec<FaucetMinter>| {
            let mut g = base.clone();
            g.staking.as_mut().unwrap().faucet_minters = Some(list);
            g
        };
        let (ma, mb) = (FaucetMinter(a.address()), FaucetMinter(b.address()));
        let listed = with(vec![ma]);
        let s = build(&listed);
        assert_eq!(s.ledger.staking().unwrap().faucet_minters, Some(vec![ma]), "the ledger runs with the list");
        assert_ne!(s.hash(), plain.hash());
        assert_ne!(build(&with(vec![mb])).hash(), s.hash());
        assert_ne!(build(&with(vec![ma, mb])).hash(), s.hash());
        assert!(matches!(with(vec![]).validate(), Err(GenesisError::BadStaking(_))), "an empty list mints for no one");
        assert!(matches!(with(vec![ma, ma]).validate(), Err(GenesisError::BadStaking(_))));
        // The file writes the base58 address and reads every spelling back to the same chain.
        let json = listed.to_json();
        let text = a.address().to_string();
        assert!(json.contains(&format!("\"faucet_minters\": [\n      \"{text}\"")), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), listed);
        for spelling in [hex::encode(a.address().0), a.to_hex()] {
            let other = Genesis::from_json(&json.replace(&text, &spelling)).unwrap();
            assert_eq!(other, listed, "{spelling}");
            assert_eq!(build(&other).hash(), s.hash());
        }
        assert!(Genesis::from_json(&json.replace(&text, "abcd")).is_err());
        assert!(Genesis::from_json(&json.replace(&text, "0OIl")).is_err(), "not base58");
    }

    /// The v4 re-review's three `staking` fields ride the section's own gate one level down:
    /// each is omitted from the file and from the genesis binding when absent — a v0.5.4-shaped
    /// section hashes exactly as it did — committed by name when present, bounded at
    /// `validate`, and the weight cap holds from the genesis set itself.
    #[test]
    fn the_later_staking_fields_are_committed_only_when_present_and_bounded() {
        // Four equal stakes: a 3333-bps cap does not bind on them, so only the field's own
        // commitment can move the hash.
        let mut base = genesis(4);
        base.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let plain = build(&base);
        let json = base.to_json();
        for name in ["max_weight_bps", "max_stake_entry_per_epoch", "registration_v2"] {
            assert!(!json.contains(name), "{name} is absent from a file that does not set it");
        }
        // Each field moves the hash, and a `false` flag commits exactly what an absent one does.
        let with = |f: fn(&mut StakingConfig)| {
            let mut g = base.clone();
            f(g.staking.as_mut().unwrap());
            g
        };
        let capped = with(|s| s.max_weight_bps = Some(3333));
        let budgeted = with(|s| s.max_stake_entry_per_epoch = Some(5 * MIN_STAKE));
        let bound = with(|s| s.registration_v2 = Some(true));
        let unbound = with(|s| s.registration_v2 = Some(false));
        for g in [&capped, &budgeted, &bound] {
            assert_ne!(build(g).hash(), plain.hash(), "{:?}", g.staking);
            assert_eq!(Genesis::from_json(&g.to_json()).unwrap(), *g, "the file round-trips it");
        }
        assert_eq!(build(&unbound).hash(), plain.hash(), "`false` is today's rule");
        assert_ne!(build(&with(|s| s.max_weight_bps = Some(3334))).hash(), build(&capped).hash());
        assert_ne!(build(&with(|s| s.max_stake_entry_per_epoch = Some(6 * MIN_STAKE))).hash(), build(&budgeted).hash());
        assert!(budgeted.to_json().contains("\"max_stake_entry_per_epoch\": \"5000000000000\""), "an amount is a decimal string");
        assert_eq!(build(&capped).validators, plain.validators, "a cap that does not bind changes no weight");
        // The genesis set is capped from epoch 0: the whale holds 100 of 103 MIN_STAKE unclamped.
        let mut whaled = base.clone();
        whaled.validators[0].stake = 100 * MIN_STAKE as u128;
        let whale = whaled.validators[0].public_key.address();
        assert_eq!(build(&whaled).validators.get(&whale).unwrap().stake, 100 * MIN_STAKE as u128);
        whaled.staking.as_mut().unwrap().max_weight_bps = Some(3333);
        let set = build(&whaled).validators;
        let w = set.get(&whale).unwrap().stake;
        assert!(w * 10_000 <= 3333 * set.total_stake() && !set.has_third(w), "{w} of {}", set.total_stake());
        // Bounds.
        for g in [with(|s| s.max_weight_bps = Some(0)), with(|s| s.max_weight_bps = Some(10_001))] {
            assert!(matches!(g.validate(), Err(GenesisError::BadStaking(_))), "{:?}", g.staking);
        }
        assert!(with(|s| s.max_weight_bps = Some(10_000)).validate().is_ok());
        assert!(matches!(with(|s| s.max_stake_entry_per_epoch = Some(0)).validate(), Err(GenesisError::BadStaking(_))));
    }

    /// Audit v6, STAKE-2: `staking.max_stake_entry_bps_per_epoch` — committed only when present,
    /// bounded `1..=10000`, and never beside the fixed `max_stake_entry_per_epoch` (one budget).
    #[test]
    fn the_fractional_entry_budget_is_committed_only_when_present_bounded_and_exclusive() {
        let mut base = genesis(4);
        base.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let plain = build(&base);
        assert!(!base.to_json().contains("max_stake_entry_bps_per_epoch"));
        let with = |bps: Option<u32>, fixed: Option<u64>| {
            let mut g = base.clone();
            let s = g.staking.as_mut().unwrap();
            s.max_stake_entry_bps_per_epoch = bps;
            s.max_stake_entry_per_epoch = fixed;
            g
        };
        let quarter = with(Some(2_500), None);
        assert_ne!(build(&quarter).hash(), plain.hash(), "part of the genesis hash");
        assert_ne!(build(&with(Some(2_501), None)).hash(), build(&quarter).hash());
        assert_eq!(Genesis::from_json(&quarter.to_json()).unwrap(), quarter);
        assert_eq!(build(&quarter).ledger.staking().unwrap().max_stake_entry_bps_per_epoch, Some(2_500));
        for g in [with(Some(0), None), with(Some(10_001), None), with(Some(2_500), Some(5 * MIN_STAKE))] {
            assert!(matches!(g.validate(), Err(GenesisError::BadStaking(_))), "{:?}", g.staking);
        }
        assert!(with(Some(10_000), None).validate().is_ok());
    }

    /// Audit v6, STAKE-1: `staking.slashing` — committed only when present, the fraction bounded,
    /// the jail 0 or longer than the evidence window, consensus domain 1 required, and refused
    /// beside a `vesting` section (locked stake would escape a slash).
    #[test]
    fn the_slashing_section_is_committed_only_when_present_and_validated() {
        let mut base = genesis(4);
        base.consensus_domain = Some(1);
        base.staking = Some(StakingConfig { faucet_budget_per_epoch: 0, bond_activation_epochs: 2, ..Default::default() });
        let plain = build(&base);
        assert!(!base.to_json().contains("slashing"));
        let with = |bps: u32, jail: u64| {
            let mut g = base.clone();
            g.staking.as_mut().unwrap().slashing = Some(SlashingConfig { equivocation_bps: bps, jail_epochs: jail });
            g
        };
        let on = with(1_000, 4);
        let built = build(&on);
        assert_ne!(built.hash(), plain.hash(), "part of the genesis hash");
        assert_ne!(build(&with(1_000, 5)).hash(), built.hash());
        assert_ne!(build(&with(1_001, 4)).hash(), built.hash());
        assert_ne!(built.ledger.state_root(), plain.ledger.state_root(), "the jail is in the root");
        assert_eq!(Genesis::from_json(&on.to_json()).unwrap(), on);
        assert!(with(10_000, 0).validate().is_ok() && with(1, 2).validate().is_ok());
        for g in [with(0, 4), with(10_001, 4), with(1_000, 1)] {
            assert!(matches!(g.validate(), Err(GenesisError::BadStaking(_))), "{:?}", g.staking);
        }
        let mut v0 = on.clone();
        v0.consensus_domain = None;
        assert!(matches!(v0.validate(), Err(GenesisError::BadStaking(_))), "domain 0 signs no genesis");
        let mut vested = on.clone();
        vested.vesting = Some(crate::ledger::vesting::VestingConfig { entries: vec![vesting_entry(1, 10 * MIN_STAKE)] });
        assert!(matches!(vested.validate(), Err(GenesisError::BadStaking(_))));
        let misspelled = on.to_json().replace("jail_epochs", "jail_epoch");
        assert!(Genesis::from_json(&misspelled).is_err(), "deny_unknown_fields");
    }

    /// Audit v6, STAKE-2: `staking.admission_by_vote` rides the section's gate like the fields
    /// before it — absent from a file that does not set it, committed to the genesis hash (after
    /// every earlier tag) only when `true`, on the ledger the chain runs with, and in the state
    /// root only then. A section without it builds exactly the chain it built before.
    #[test]
    fn admission_by_vote_is_committed_only_when_true() {
        let mut base = genesis(4);
        base.staking = Some(StakingConfig { faucet_budget_per_epoch: 100 * UNITS_PER_RAND, bond_activation_epochs: 2, ..Default::default() });
        let plain = build(&base);
        assert!(!base.to_json().contains("admission_by_vote"), "absent from a file that does not set it");
        assert!(!plain.ledger.staking().unwrap().admission_by_vote());
        let with = |v: Option<bool>| {
            let mut g = base.clone();
            g.staking.as_mut().unwrap().admission_by_vote = v;
            g
        };
        let on = with(Some(true));
        let built = build(&on);
        assert_ne!(built.hash(), plain.hash(), "the flag is part of the genesis hash");
        assert!(built.ledger.staking().unwrap().admission_by_vote(), "the ledger runs the rule genesis names");
        assert!(built.ledger.admitted().is_empty(), "nobody is admitted at genesis: the genesis validators are the register");
        assert_ne!(built.ledger.state_root(), plain.ledger.state_root(), "and the admitted set is in the root");
        assert!(on.to_json().contains("\"admission_by_vote\": true"));
        assert_eq!(Genesis::from_json(&on.to_json()).unwrap(), on, "the file round-trips it");
        // `false` is today's rule: the same hash and the same root as a file without the field.
        let off = build(&with(Some(false)));
        assert_eq!(off.hash(), plain.hash());
        assert_eq!(off.ledger.state_root(), plain.ledger.state_root());
        // The section still refuses a key it does not know.
        let misspelled = on.to_json().replace("admission_by_vote", "admission_by_votes");
        assert!(Genesis::from_json(&misspelled).is_err(), "deny_unknown_fields still holds");
    }

    // ------------------------------------------------------------------ genesis vesting

    fn vesting_entry(id: u8, amount: u64) -> crate::ledger::vesting::VestingEntryConfig {
        crate::ledger::vesting::VestingEntryConfig {
            id: [id; 32],
            class: crate::ledger::vesting::Class::Investor,
            beneficiary: Keypair::from_seed([50 + id; 32]).unwrap().public_key().clone(),
            revokers: Vec::new(),
            threshold: None,
            treasury: None,
            amount,
            start_ms: 1_700_000_000_000,
            cliff_ms: 1_000,
            linear_ms: 2_000,
            step_ms: None,
        }
    }

    fn vested_genesis(entries: Vec<crate::ledger::vesting::VestingEntryConfig>) -> Genesis {
        let mut g = genesis(1);
        g.vesting = Some(crate::ledger::vesting::VestingConfig { entries });
        g
    }

    /// Genesis vesting (spec §3, §5, §7): the section seeds the register, is committed to the
    /// genesis hash and to the state root under `rand-state-6`, and the supply identity holds
    /// at block 0 with the register as issuance; a genesis without it is unchanged.
    #[test]
    fn a_vesting_section_seeds_the_register_and_is_committed_only_when_present() {
        let plain = build(&genesis(1));
        assert!(plain.ledger.vesting().is_none());
        assert!(!genesis(1).to_json().contains("vesting"), "absent from a file that does not set it");
        let g = vested_genesis(vec![vesting_entry(2, 700 * UNITS_PER_RAND), vesting_entry(1, 300 * UNITS_PER_RAND)]);
        let gs = build(&g);
        let v = gs.ledger.vesting().expect("the register is seeded");
        assert_eq!(v.entries.len(), 2);
        assert_eq!(v.entries[0].id, [1; 32], "in id order");
        assert_eq!(v.issued(), 1_000 * UNITS_PER_RAND);
        let audit = gs.ledger.audit();
        assert!(audit.invariant_holds(), "{audit:?}");
        assert_eq!(audit.vesting_in_register, 1_000 * UNITS_PER_RAND);
        assert_ne!(gs.hash(), plain.hash());
        assert_ne!(gs.ledger.state_root(), plain.ledger.state_root());
        assert!(!gs.ledger.debug_state_root_components().contains("vesting none"));
        assert!(plain.ledger.debug_state_root_components().contains("vesting none"));
        // The file round-trips, amounts as decimal strings.
        let json = g.to_json();
        assert!(json.contains("\"amount\": \"300000000000\""), "{json}");
        assert_eq!(Genesis::from_json(&json).unwrap(), g);
        // The same entries listed in another order are the same chain.
        let reordered = vested_genesis(vec![vesting_entry(1, 300 * UNITS_PER_RAND), vesting_entry(2, 700 * UNITS_PER_RAND)]);
        assert_eq!(build(&reordered).hash(), gs.hash());
        // Every committed field moves the hash.
        let with = |f: fn(&mut crate::ledger::vesting::VestingEntryConfig)| {
            let mut x = g.clone();
            f(&mut x.vesting.as_mut().unwrap().entries[0]);
            build(&x).hash()
        };
        let moved = [
            with(|e| e.id = [9; 32]),
            with(|e| e.class = crate::ledger::vesting::Class::Team),
            with(|e| e.beneficiary = Keypair::from_seed([99; 32]).unwrap().public_key().clone()),
            with(|e| revocable(e, &[98], 1, 3)),
            with(|e| e.amount += 1),
            with(|e| e.start_ms += 1),
            with(|e| e.cliff_ms += 1),
            with(|e| e.linear_ms += 1000),
            with(|e| e.step_ms = Some(1000)),
        ];
        for (i, h) in moved.iter().enumerate() {
            assert_ne!(*h, gs.hash(), "field {i} must be in the genesis binding");
        }
        // Audit v6, STAKE-3: who may revoke, how many of them it takes and where a revoke pays
        // are each in the binding — and so is the revokers' order, which a revoke's signer
        // indices read.
        let base = with(|e| revocable(e, &[97, 98, 99], 2, 3));
        let moved = [
            with(|e| revocable(e, &[97, 98, 96], 2, 3)),
            with(|e| revocable(e, &[98, 97, 99], 2, 3)),
            with(|e| revocable(e, &[97, 98], 2, 3)),
            with(|e| revocable(e, &[97, 98, 99], 3, 3)),
            with(|e| revocable(e, &[97, 98, 99], 2, 4)),
        ];
        for (i, h) in moved.iter().enumerate() {
            assert_ne!(*h, base, "revocation term {i} must be in the genesis binding");
        }
        // …and in the register's root: the treasury is part of the entry.
        let root = |f: fn(&mut crate::ledger::vesting::VestingEntryConfig)| {
            let mut x = g.clone();
            f(&mut x.vesting.as_mut().unwrap().entries[0]);
            build(&x).ledger.vesting().unwrap().root()
        };
        assert_ne!(root(|e| revocable(e, &[97, 98, 99], 2, 3)), root(|e| revocable(e, &[97, 98, 99], 2, 4)));
    }

    /// Make `e` revocable by `threshold` of the keys seeded by `seeds`, paying the treasury
    /// `payout(treasury)`.
    fn revocable(e: &mut crate::ledger::vesting::VestingEntryConfig, seeds: &[u8], threshold: u8, treasury: u8) {
        e.class = crate::ledger::vesting::Class::Team;
        e.revokers = seeds.iter().map(|s| Keypair::from_seed([*s; 32]).unwrap().public_key().clone()).collect();
        e.threshold = Some(threshold);
        e.treasury = Some(payout(treasury));
    }

    /// Audit v6, STAKE-3: a revocable entry without a treasury — the address a revoke pays — is
    /// refused at the file, and so is every other malformed revoker set. Before, an entry named
    /// one key and no destination, and that key's holder chose where the unvested part went.
    #[test]
    fn a_revocable_vesting_entry_without_a_treasury_is_refused() {
        let with = |f: fn(&mut crate::ledger::vesting::VestingEntryConfig)| {
            let mut e = vesting_entry(1, 5);
            revocable(&mut e, &[97, 98, 99], 2, 3);
            f(&mut e);
            vested_genesis(vec![e]).validate()
        };
        assert!(with(|_| ()).is_ok(), "{:?}", with(|_| ()));
        let refused = |r: Result<(), GenesisError>, what: &str| match r {
            Err(GenesisError::BadVesting(why)) => assert!(why.contains(what), "{why:?} should mention {what:?}"),
            other => panic!("expected a vesting refusal mentioning {what:?}, got {other:?}"),
        };
        refused(with(|e| e.treasury = None), "needs a treasury");
        refused(with(|e| e.treasury = Some("rand1nonsense".into())), "not a shielded address");
        refused(with(|e| e.threshold = None), "needs a threshold");
        refused(with(|e| e.threshold = Some(0)), "outside 1..=3");
        refused(with(|e| e.threshold = Some(4)), "outside 1..=3");
        refused(with(|e| e.revokers[2] = e.revokers[0].clone()), "listed twice");
        refused(with(|e| e.revokers[1] = e.beneficiary.clone()), "its own revoker");
        refused(with(|e| revocable(e, &[91, 92, 93, 94, 95, 96], 2, 3)), "at most 5");
        // An irrevocable entry names neither: a treasury or a threshold with no revoker is a
        // file that means something other than it says.
        refused(with(|e| e.revokers.clear()), "without revokers");
        // One key with threshold 1 is still expressible (and five keys are the most).
        assert!(with(|e| revocable(e, &[97], 1, 3)).is_ok());
        assert!(with(|e| revocable(e, &[91, 92, 93, 94, 95], 5, 3)).is_ok());
    }

    #[test]
    fn a_bad_vesting_section_is_refused_at_the_file() {
        let bad = |g: Genesis| assert!(matches!(g.validate(), Err(GenesisError::BadVesting(_))), "{:?}", g.validate());
        bad(vested_genesis(vec![]));
        bad(vested_genesis(vec![vesting_entry(1, 5), vesting_entry(1, 6)]));
        bad(vested_genesis(vec![vesting_entry(1, 0)]));
        // The register, the notes and the stakes together must fit a u64.
        let huge = vested_genesis(vec![vesting_entry(1, u64::MAX - 1)]);
        assert!(matches!(huge.build(&StubExecutor), Err(GenesisError::SupplyOverflow)));
    }

}
