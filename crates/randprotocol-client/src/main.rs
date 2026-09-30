//! `rand`: the shielded command-line wallet, talking to a RAND full node over JSON-RPC.
//!
//! Phase S1 redacted the chain: there are no accounts and no balances to ask a node about, so
//! every command that used to be a question for the node ("what is this address worth?") is now
//! a question for this machine. The wallet keeps a spend key (`--key`) and a note store next to
//! it (`<key>.notes.json`), scans the commitment tree for notes only that key can open, and
//! spends them by proving a four-slot hidden-asset bundle locally (any asset in slots 0–1, the
//! RAND fee in slots 2–3). The node is asked for chain state —
//! leaves, nullifiers, anchors, witnesses — and handed a finished bundle; it is never told who
//! anyone is.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use randprotocol_client::governance;
use randprotocol_client::memo_display;
use randprotocol_client::wallet::{self, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_client::wallet::{Burn, Proving, Submission};
use randprotocol_client::prover::{self, PairedProver, RemoteProver};
use randprotocol_prover::pairing::PairingLink;
#[cfg(test)]
use randprotocol_client::contacts;
use randprotocol_client::contacts::Contacts;
use randprotocol_core::ledger::staking::MIN_STAKE;
use randprotocol_core::notes::{word8_to_hex, ShieldedAddress, Word8};
use randprotocol_core::payment_uri::PaymentUri;
use randprotocol_core::types::actions::Registration;
use randprotocol_core::{format_amount, gas, parse_amount, Action, Address, Hash, Keypair};
use randprotocol_zkvm::machine::{Backend, FriProfile, Tier, TIERS};
use randprotocol_zkvm::{call_envelope, codec, emulator, executor, guests, hash, isa::Program};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "rand", version, about = "RAND shielded wallet: scan, send and prove through a full node's RPC")]
struct Cli {
    /// Full node JSON-RPC endpoint.
    #[arg(long, global = true, env = "RAND_RPC", default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Spend-key file. The note store lives next to it, at `<key>.notes.json`.
    #[arg(long, global = true, env = "RAND_KEY", default_value = "wallet.key.json")]
    key: PathBuf,
    /// Prove bundles on the prover paired with this wallet (`rand prover pair`) instead of on
    /// this machine. The proof is checked here — its digest, its size and a local verify —
    /// before it goes into a transaction.
    #[arg(long, global = true)]
    prover: bool,
    /// The most a paired prover may charge per bundle, in RAND (display units, up to 9 decimals).
    /// A quote above it is refused before any bundle is built, on every command; `0` refuses any
    /// fee.
    #[arg(long, global = true, value_name = "RAND", default_value = "1")]
    max_prover_fee: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new spend-key file (refuses to overwrite).
    Keygen,
    /// Show this wallet's shielded address, and optionally a `randpay:` link or QR of it.
    Address {
        /// Print the address as a `randpay:` link (spec §2.2).
        #[arg(long)]
        uri: bool,
        /// Include an amount in the link (display units: RAND for asset 0).
        #[arg(long)]
        amount: Option<String>,
        /// Include an asset in the link: a registry index, or a token id (`rpl1…` or 64 hex).
        #[arg(long)]
        asset: Option<String>,
        /// Include a memo in the link.
        #[arg(long)]
        memo: Option<String>,
        /// Print the link as a QR code, in the terminal.
        #[arg(long)]
        qr: bool,
        /// Write the link as a QR code PNG to this path.
        #[arg(long = "qr-png")]
        qr_png: Option<PathBuf>,
    },
    /// Delegated proving: pair this wallet with a prover (a `randprover:` link from
    /// `rand-prover pair`), show the pairing, or forget it. `--prover` then proves there.
    Prover {
        #[command(subcommand)]
        op: ProverOp,
    },
    /// Named addresses this wallet can send to by name instead of a `rand1…` address.
    Contacts {
        #[command(subcommand)]
        op: ContactsOp,
    },
    /// Print this wallet's viewing key: 64 hex, the form `rand_importViewingKey` takes.
    ///
    /// It reads every note this wallet has sent or received and can spend none of them. Anyone
    /// holding it sees this wallet's whole history, so hand it only to whoever should.
    ViewingKey,
    /// Print the per-transaction key of each output of a transaction this wallet sent or received.
    ///
    /// Each key discloses exactly one output: hand the `sent` row's key to a payee or an auditor
    /// and `rand_checkTransaction <hash> <key>` shows them that payment and nothing else. The keys
    /// are recovered from the chain, so this works for any transaction, however old.
    TxKey {
        /// The transaction hash.
        hash: String,
    },
    /// Scan, then show what this wallet can spend.
    Balance,
    /// Scan, then show what this wallet holds in a bridged asset (or in every asset).
    ///
    /// Amounts are in the asset's own smallest unit: only RAND (index 0) has this chain's nine
    /// decimals, and what a bridged token's unit means is the source chain's business.
    AssetBalance {
        /// The registry index a note's `asset` word carries; omit for every asset held.
        index: Option<u32>,
    },
    /// Scan the chain for notes and spends without printing a balance.
    Sync {
        /// Start the note store over first — every note, spent mark, pending hold and cursor
        /// forgotten, the chain binding kept — and rescan from leaf 0. The way back when a node
        /// reported this wallet's notes as spent wrongly (a scan never un-spends a note);
        /// best run against a node you trust.
        #[arg(long)]
        rescan: bool,
    },
    /// List every note this wallet has ever been able to open.
    Notes {
        /// Print each note's whole memo instead of the first 24 characters.
        #[arg(long)]
        memo: bool,
    },
    /// List every note this wallet created for someone else.
    History {
        /// Print each note's whole memo instead of the first 24 characters.
        #[arg(long)]
        memo: bool,
    },
    /// Send RAND or a token to a shielded address, a `randpay:` link or a saved contact name:
    /// scan, select, prove and submit.
    ///
    /// Either way the transaction is a plain four-slot bundle that does not say which asset moved,
    /// and the fee is RAND — a token transfer needs RAND in the wallet for it. Amounts (here and
    /// in a link) are always the asset's own display units: RAND at nine decimals, a token at its
    /// registry row's own `decimals`.
    Send {
        /// A `rand1…` shielded address, a `randpay:` link, or a saved contact's name.
        to: String,
        /// Amount, in the asset's display units; omit it when TO is a link that carries one.
        amount: Option<String>,
        /// The asset to send: a registry index (0, the default, is RAND), or a token id — `rpl1…`
        /// or 64 hex — found in the node's whole token listing (never a lookup of that one token,
        /// which would tell the node what is about to move). A link's own `asset` is used when
        /// this is not given; the two must agree if both are.
        #[arg(long)]
        asset: Option<String>,
        /// A memo to seal with the payment. A link's own `memo` is used when this is not given;
        /// the two must agree if both are.
        #[arg(long)]
        memo: Option<String>,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Send without asking for confirmation first.
        #[arg(long)]
        yes: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Stake RAND onto a validator: the bundle burns the stake out of this wallet's notes.
    ///
    /// A validator the register does not know yet needs `--registration`, the hex blob its
    /// operator gets from `rand-node register --payout <rand1…>`; one it already knows must
    /// not carry one. Bonded weight counts from the next epoch, and unbonding it is the
    /// validator's own command (`rand-node unbond`), not this wallet's.
    Bond {
        /// The validator's address (base58), as `rand validators` lists it.
        validator: String,
        /// Amount in RAND. Registering a new validator needs at least the staking minimum.
        amount: String,
        /// The hex `Registration` from `rand-node register`, for a validator not yet in the
        /// register.
        #[arg(long)]
        registration: Option<String>,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Testnet faucet: ask a validator to mint RAND into a note (default: this wallet).
    Faucet {
        /// A `rand1…` shielded address; defaults to this wallet's.
        address: Option<String>,
        /// Amount in RAND (max 100).
        #[arg(long, default_value = "100")]
        amount: String,
    },
    /// Confidential programs: build, deploy, show.
    #[command(subcommand)]
    Program(ProgramCmd),
    /// Run a confidential call: prove locally, pay from a bundle, wait for the receipt.
    ///
    /// By default the call also publishes a sealed transcript of its private inputs (spec §6.1),
    /// which nobody but this wallet — and an auditor it names — can open. `--no-envelope` keeps
    /// even that from the chain, at the price of a call whose inputs nobody can ever recover.
    Call {
        /// Program id (hex).
        program: String,
        /// Private inputs (u32), in order; never leave this machine.
        #[arg(long = "input")]
        inputs: Vec<u32>,
        /// Refuse, before proving, unless the program's deploy-time public input is exactly this
        /// file's words (same forms as `program deploy --public`). A call carries no public words
        /// of its own: it always proves over the program's.
        #[arg(long)]
        expect_public: Option<PathBuf>,
        /// Force a gas tier (10, 12, ..., 20); default: smallest that fits.
        #[arg(long)]
        tier: Option<u8>,
        /// The gas limit the proof declares, `N` or `max` (spec 2026-09-28 §5): what a chain with
        /// a gas section charges, and an upper bound on the run anyone can read. Default there:
        /// the exact gas rounded up to a quarter of the tier; `max` declares the header's ceiling
        /// and leaks nothing the tier does not. Elsewhere the default is `max` (it buys nothing),
        /// and on `--cuda`, which can declare nothing else.
        #[arg(long)]
        gas_limit: Option<String>,
        /// Fee in RAND; default: the floor for the declared gas (or, without a gas section, the
        /// tier), plus two price steps of headroom where prices move.
        #[arg(long)]
        fee: Option<String>,
        /// Also seal the transcript to this `rand1…` address, which can then open this one call.
        #[arg(long)]
        auditor: Option<String>,
        /// Publish no input transcript at all.
        #[arg(long)]
        no_envelope: bool,
        /// Print this call's per-call disclosure key: whoever holds it can open this call's inputs.
        #[arg(long)]
        print_call_key: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Open a call's input transcript and check it against the receipt (spec §6.1).
    ///
    /// With no flag it opens as the caller, through this wallet's outgoing viewing key — the key
    /// that opens every call this wallet made. Then it re-runs the program on the inputs it
    /// recovered, so the receipt's outputs can be read next to the ones those inputs produce.
    OpenCall {
        /// The call's transaction hash.
        txhash: String,
        /// Open with one call's disclosure key (64 hex characters) instead.
        #[arg(long)]
        call_key: Option<String>,
        /// Open as the auditor the caller named, through this wallet's viewing key.
        #[arg(long)]
        as_auditor: bool,
    },
    /// Show the receipt of a confidential call.
    Receipt { tx: String },
    /// Mint a bridge deposit: submit a guardian-signed attestation as a note for its recipient.
    BridgeMint {
        /// The attestation as hex, or `@path` to read the hex from a file.
        attestation: String,
        /// The guardians' Dilithium2 co-signatures, required on every mint: a JSON array
        /// `[{"index":0,"signature":"<4840 hex>"},…]`, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// The shielded address the depositor named; defaults to this wallet's.
        #[arg(long)]
        to: Option<String>,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Submit a guardian-set rotation (payload 2) with its Dilithium2 co-signature quorum: a
    /// `BridgeAttest` whose fee bundle pays for it and which deposits nothing. Prints the
    /// guardian-set index Rand is on afterwards.
    BridgeRotate {
        /// The rotation attestation as hex, or `@path` to read the hex from a file.
        rotation: String,
        /// The current PQ guardian set's co-signatures: a JSON array
        /// `[{"index":0,"signature":"<4840 hex>"},…]`, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Pause bridge minting with the pause key's signature (bridge hardening B1): a bundle-less,
    /// fee-less `PauseMints` — no spend key and no RAND needed. The file is what
    /// `rand-bridge-gov pause` writes, a 2 420-byte signature as hex, made for the bridge's current
    /// `pause_nonce`; one made for another nonce is refused here, naming it. Burns and rotations
    /// stay open while paused; only a PQ guardian quorum can unpause.
    BridgePause {
        /// The signature as hex, or `@path` to read it from a file.
        #[arg(long)]
        sig: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
    /// Lift a mint pause with a PQ guardian quorum (bridge hardening B1): a bundle-less, fee-less
    /// `UnpauseMints`. The file is what `rand-bridge-gov pq-unpause` writes,
    /// `[{"index":0,"signature":"<4840 hex>"},…]`, made for the bridge's current `pause_nonce`.
    BridgeUnpause {
        /// The quorum as JSON, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
    /// Burn a bridged asset to another chain: one bundle burns the asset and pays the RAND fee.
    BridgeBurn {
        /// The asset's registry index (`rand asset-balance`).
        asset: u32,
        /// Amount in the asset's own smallest unit.
        amount: u64,
        /// Destination chain id.
        to_chain: u16,
        /// The source-chain token address to release, 32 bytes of hex: which of the asset's
        /// backings this burn redeems (`rand bridge` lists them, one row per coin with its
        /// locked amount). One bridged token is backed by several coins on several chains.
        token: String,
        /// 32-byte destination address, hex.
        to: String,
        /// A portion of AMOUNT paid to the relayer on the destination chain, in the same asset.
        #[arg(long, default_value_t = 0)]
        relayer_fee: u64,
        /// Fee in RAND; the floor is 0.01 — the bridge fee, which covers the bundle's base.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// RPL tokens: burn one this wallet holds; register a bridged token and list its backings
    /// after genesis (bridge hardening B4).
    #[command(subcommand)]
    Token(TokenCmd),
    /// The bridge's public state: guardians, emitters, the asset registry, the burn sequence.
    Bridge,
    /// The outbound burn message with this sequence, for a guardian to sign.
    BridgeMessage { sequence: u64 },
    /// Minimum fee: `fee bundle`, `fee deploy <words> [--public-words M]` or
    /// `fee call <tier> [--bytes B] [--keccak-log-height K] [--sha256-log-height S]`.
    Fee {
        /// bundle | deploy | call
        kind: String,
        /// Program words for `deploy`, the tier for `call`.
        n: Option<u64>,
        /// `deploy`: public-input words, priced like code words.
        #[arg(long)]
        public_words: Option<u64>,
        /// `call`: the call's proof plus input-envelope bytes. Under a node's gas policy every
        /// byte prices in; without one, only bytes past the free allowance (2 MiB + 18 432) add
        /// to the fee.
        #[arg(long)]
        bytes: Option<u64>,
        /// `call`: the proof's declared hash-table heights, 0 = none.
        #[arg(long)]
        keccak_log_height: Option<u8>,
        /// `call`: the proof's declared hash-table heights, 0 = none.
        #[arg(long)]
        sha256_log_height: Option<u8>,
        /// `call`: the gas limit the proof declares, which a chain with a gas section prices
        /// (`rand call` prints it before proving); absent there, the header's ceiling
        /// `gas_max(tier, K, S)` is priced.
        #[arg(long)]
        gas: Option<u64>,
    },
    /// Look up a transaction by hash.
    Tx { hash: String },
    /// Show a block by height or hash.
    Block { id: String },
    /// Current head of the chain.
    Head,
    /// Node status.
    Status,
    /// Connected peers.
    Peers,
    /// Validator set.
    Validators,
}

#[derive(Subcommand)]
enum ProverOp {
    /// Pair with the prover a `randprover:` link names. Shows what that prover will receive (this
    /// wallet's viewing key: it can read the whole history, it cannot spend) and asks first; then
    /// its key's fingerprint is checked against what the prover itself answers before anything
    /// is saved (`<key>.prover.json`, mode 0600).
    Pair {
        /// The `randprover:` link `rand-prover pair` printed. Omit it with `--trusted`.
        #[arg(required_unless_present = "trusted")]
        link: Option<String>,
        /// Pair with the validators' prover pool, `https://prover.randprotocol.org`, whose link
        /// this build carries. It is not your own prover: it proves from a viewing-key witness,
        /// so its operators can read this wallet's whole history; they cannot spend.
        #[arg(long, conflicts_with = "link")]
        trusted: bool,
        /// A name to print for this prover instead of its URL.
        #[arg(long)]
        name: Option<String>,
        /// Pair without asking for confirmation first.
        #[arg(long)]
        yes: bool,
    },
    /// Print the pairing (never its token).
    Show,
    /// Delete the pairing.
    Forget,
}

#[derive(Subcommand)]
enum ContactsOp {
    /// Save a shielded address (or a `randpay:` link's address) under a name.
    Add {
        /// The contact's name: 1-64 characters, never starting with `rand1` or `randpay:`.
        name: String,
        /// A `rand1…` shielded address, or a `randpay:` link.
        to: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// List every saved contact.
    List,
    /// Show one contact's address and fingerprint.
    Show {
        name: String,
        /// Print the address as a QR code, in the terminal.
        #[arg(long)]
        qr: bool,
    },
    /// Remove a saved contact.
    Remove { name: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Destroy some of a token this wallet holds: its public supply drops by exactly AMOUNT.
    ///
    /// One bundle burns the token and pays the RAND fee. A bridged token is burned with
    /// `rand bridge-burn` instead, which names the coin released on the other chain.
    Burn {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        asset: String,
        /// Amount in the token's display units, at its registry row's own `decimals` (as
        /// `send --asset` reads it).
        amount: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Register a bridged token with its first backing, authorised by a PQ guardian quorum
    /// (`rand-bridge-gov pq-register`'s file) and paid by this wallet's fee bundle: the bundle base
    /// plus the registry's registration fee. The token is eight decimals on Rand, at the next
    /// index. List on Rand FIRST, `setToken` on the endpoint SECOND.
    RegisterBridged {
        /// Display name, 1 to 32 bytes.
        #[arg(long)]
        name: String,
        /// Ticker, 1 to 12 ASCII graphic characters.
        #[arg(long)]
        symbol: String,
        /// The 32-byte salt the asset id is over, hex.
        #[arg(long)]
        salt: String,
        /// The first backing's bridge chain id (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
        #[arg(long)]
        chain: u16,
        /// The first backing's 32-byte wire token address, hex.
        #[arg(long)]
        token: String,
        /// The first backing's decimals on its own chain (the source coin's, not the eight on Rand).
        #[arg(long)]
        decimals: u8,
        /// The PQ guardian quorum over the registration, as JSON or `@path`.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; default the bundle base plus the registration fee.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Add a backing to a bridged token, authorised by a PQ guardian quorum
    /// (`rand-bridge-gov pq-list`'s file) and paid by this wallet's fee bundle.
    ListBacking {
        /// The bridged token's registry index.
        #[arg(long)]
        asset: u32,
        /// The backing's bridge chain id (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
        #[arg(long)]
        chain: u16,
        /// The backing's 32-byte wire token address, hex.
        #[arg(long)]
        token: String,
        /// The backing's decimals on its own chain.
        #[arg(long)]
        decimals: u8,
        /// The PQ guardian quorum over the listing, as JSON or `@path`.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Create an RPL token at the registry's next index: fixed supply (`--fixed-supply`, minted
    /// once, at registration) or `Key`-authorised (`--authority-key-out`, mintable again with
    /// `rand token mint`), with or without an initial mint.
    Create {
        /// Display name, 1 to 32 bytes.
        #[arg(long)]
        name: String,
        /// Ticker, 1 to 12 ASCII graphic characters.
        #[arg(long)]
        symbol: String,
        /// Smallest-unit decimals, 0 to 9.
        #[arg(long)]
        decimals: u8,
        /// The 32-byte salt the asset id is over, hex. Random if not given.
        #[arg(long)]
        salt: Option<String>,
        /// Fixed supply: mint exactly this many units at registration, forever — `authority` is
        /// `none`. Needs `--to`; mutually exclusive with `--authority-key-out`.
        #[arg(long)]
        fixed_supply: Option<u64>,
        /// A fresh Dilithium2 key file is written here (0600, refusing to overwrite) and becomes
        /// the token's mint authority. Mutually exclusive with `--fixed-supply`.
        #[arg(long)]
        authority_key_out: Option<PathBuf>,
        /// With `--authority-key-out`: mint this many units at registration too. Needs `--to`.
        #[arg(long)]
        initial: Option<u64>,
        /// The initial mint's recipient. Required with `--fixed-supply` or `--initial`.
        #[arg(long)]
        to: Option<String>,
        /// RPL-2: a program token — its mint authority is this program (hex id), and only that
        /// program's invokes mint or burn it. Starts at zero supply (no `--initial`), needs the
        /// chain's `program_state` section. Mutually exclusive with the other two authorities.
        #[arg(long)]
        program: Option<String>,
        /// Fee in RAND; default the bundle base plus the registry's registration fee.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Mint more of a `Key`-authorised token, signed by its authority key.
    Mint {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        #[arg(long)]
        asset: String,
        /// The recipient's shielded address.
        #[arg(long)]
        to: String,
        /// Amount in the token's display units, at its registry row's own `decimals` (as
        /// `send --asset` reads it).
        #[arg(long)]
        amount: String,
        /// The token's mint authority: a Dilithium2 key file (`rand-node keygen`'s shape, or
        /// `rand token create --authority-key-out`'s).
        #[arg(long)]
        authority_key: PathBuf,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Hand a `Key`-authorised token to another key, or renounce minting for good.
    SetAuthority {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        #[arg(long)]
        asset: String,
        /// The token's current mint authority: a Dilithium2 key file.
        #[arg(long)]
        authority_key: PathBuf,
        /// Hand the token to this key file's public key. Mutually exclusive with `--renounce`.
        #[arg(long)]
        new_key: Option<PathBuf>,
        /// Retire minting for good: no key can ever mint this token again. Mutually exclusive
        /// with `--new-key`.
        #[arg(long)]
        renounce: bool,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// One token's public row: name, symbol, decimals, authority, supply, registration height,
    /// id (hex and `rpl1…`) and, if bridged, each backing (chain, token, decimals, locked,
    /// minted_today).
    Info {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        token: String,
    },
    /// Every registered token, paged.
    List {
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 1000)]
        limit: u64,
    },
}

#[derive(Subcommand)]
enum ProgramCmd {
    /// Assemble a built-in guest program to a JSON file.
    Build {
        /// fib | memcpy | bubble_sort | balance_check | private_payment | public_echo | rpl2_counter
        #[arg(long)]
        guest: String,
        /// Guest argument(s): fib n, memcpy n, bubble_sort v..., balance_check threshold, private_payment threshold
        #[arg(long = "arg")]
        args: Vec<u32>,
        #[arg(long, default_value = "program.json")]
        out: PathBuf,
    },
    /// Deploy a program from a .json ({base_pc, words}) or .bin (raw LE words) file.
    Deploy {
        file: PathBuf,
        /// Deploy-time public input: a file of whitespace-separated u32 words (decimal or 0x hex),
        /// or an ELF `.so`, word-encoded as the sBPF guest reads it. The chain stores it with the
        /// program, and every call proves over it.
        #[arg(long)]
        public: Option<PathBuf>,
        /// Before paying for the deploy, run a call over these private inputs (u32, in order)
        /// through the emulator and refuse unless it fits the call tier cap. The deploy bound is
        /// the prover's limit for a call with no inputs, so a program inside it can still be
        /// uncallable once a call's inputs are digested too (issue #57). Nothing is proved.
        #[arg(long = "input")]
        inputs: Vec<u32>,
        /// Run that check with no private inputs (implied by `--input`).
        #[arg(long)]
        check_call: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Show a deployed program.
    Show { id: String },
    /// RPL-2: invoke a program — declare a state transition (`--transition FILE.json`), prove the
    /// call over it, pay from one bundle (the fee, plus what the transition deposits), wait for
    /// the receipt. Exit 3 when the chain refuses it as a stale read (a cell moved since the
    /// transition was quoted: re-read it and retry).
    Invoke {
        /// Program id (hex).
        program: String,
        /// The transition, as JSON: `{"reads": [{"key", "value"}], "writes": [...], "deposit":
        /// {"rand": "<units>", "asset": n, "amount": "<units>", "kind": "none"|"deposit"|"burn"},
        /// "pays": [{"asset", "amount", "to"?}], "mints": [...]}`; every field optional, keys and
        /// values 64 hex, amounts decimal strings in units, `to` a rand1… address (default: this
        /// wallet's own).
        #[arg(long)]
        transition: PathBuf,
        /// Private inputs (u32), in order; never leave this machine.
        #[arg(long = "input")]
        inputs: Vec<u32>,
        /// Private inputs as a JSON array of u32, appended after `--input`s.
        #[arg(long)]
        inputs_file: Option<PathBuf>,
        /// Fee in RAND; default: the call's floor for the declared gas plus the cell fee for
        /// each cell the transition creates (plus price headroom where prices move).
        #[arg(long)]
        fee: Option<String>,
        /// The gas limit the proof declares, `N` or `max` (as `rand call --gas-limit`).
        #[arg(long)]
        gas_limit: Option<String>,
        /// Force a gas tier (10, 12, ..., 20); default: smallest that fits.
        #[arg(long)]
        tier: Option<u8>,
        /// Return once the node accepts the transaction instead of waiting for the receipt.
        #[arg(long)]
        no_wait: bool,
    },
    /// RPL-2: a program's cells (`rand_getProgramCells`), or one cell with `--cell`.
    State {
        /// Program id (hex).
        id: String,
        /// One cell's key, 64 hex; without it, every cell in key order. (`--key` is the wallet
        /// key file, as everywhere in `rand`.)
        #[arg(long)]
        cell: Option<String>,
    },
    /// RPL-2: a program's vault (`rand_getProgramVault`): what it holds, per asset.
    Vault {
        /// Program id (hex).
        id: String,
    },
}

/// `rand program invoke --transition FILE.json`, as another tool emits it (RPL-2). Every field
/// is optional: absent is empty, zero or `none`.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionFile {
    #[serde(default)]
    reads: Vec<CellFile>,
    #[serde(default)]
    writes: Vec<CellFile>,
    #[serde(default)]
    deposit: DepositFile,
    #[serde(default)]
    pays: Vec<PayoutFile>,
    #[serde(default)]
    mints: Vec<PayoutFile>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CellFile {
    key: String,
    value: String,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositFile {
    /// RAND units into the vault (`burn_r`), a decimal string.
    #[serde(default)]
    rand: Option<String>,
    /// The token (registry index) and units (`burn_asset`, `burn_a`) the bundle burns.
    #[serde(default)]
    asset: u32,
    #[serde(default)]
    amount: Option<String>,
    /// `none` | `deposit` | `burn`: what `amount` of `asset` is to the program.
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutFile {
    #[serde(default)]
    asset: u32,
    amount: String,
    /// A `rand1…` address; this wallet's own when absent.
    #[serde(default)]
    to: Option<String>,
}

/// The exit code `rand program invoke` leaves on a stale read — distinct, so a calling tool can
/// re-quote the cells and retry rather than treat it as a hard refusal.
const STALE_READ_EXIT: i32 = 3;

/// A decimal amount in units (never RAND's decimals: a payout may be a token's).
fn parse_units(s: &str, what: &str) -> Result<u64> {
    s.trim().parse::<u64>().with_context(|| format!("{what}: {s:?} is not a decimal amount in units"))
}

/// A 64-hex `Word8` (with or without `0x`), as a cell key or value.
fn parse_word8(s: &str, what: &str) -> Result<randprotocol_core::Word8> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    randprotocol_core::notes::word8_from_hex(h).with_context(|| format!("{what}: {s:?} is not 64 hex characters"))
}

/// The plan a transition file asks for: parsed, amounts and words decoded, recipients resolved
/// (this wallet's address when a payout names none). Nothing is read from the chain here.
fn read_transition_file(
    path: &Path,
    program: randprotocol_core::program::ProgramId,
    me: &randprotocol_core::notes::ShieldedAddress,
) -> Result<wallet::InvokePlan> {
    use randprotocol_core::ledger::program_state::{Cell, Inflow};
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file: TransitionFile = serde_json::from_str(&text).with_context(|| format!("{} is not a transition file", path.display()))?;
    let cells = |list: &[CellFile], what: &str| -> Result<Vec<Cell>> {
        list.iter()
            .map(|c| Ok(Cell { key: parse_word8(&c.key, &format!("{what} key"))?, value: parse_word8(&c.value, &format!("{what} value"))? }))
            .collect()
    };
    let payouts = |list: &[PayoutFile], what: &str| -> Result<Vec<wallet::PayoutRequest>> {
        list.iter()
            .map(|p| {
                let to = match &p.to {
                    Some(a) => parse_address(a).with_context(|| format!("{what}: `to`"))?,
                    None => me.clone(),
                };
                Ok(wallet::PayoutRequest { asset: p.asset, amount: parse_units(&p.amount, &format!("{what} amount"))?, to })
            })
            .collect()
    };
    let burn_r = file.deposit.rand.as_deref().map(|s| parse_units(s, "deposit.rand")).transpose()?.unwrap_or(0);
    let burn_a = file.deposit.amount.as_deref().map(|s| parse_units(s, "deposit.amount")).transpose()?.unwrap_or(0);
    let inflow = match file.deposit.kind.as_deref().unwrap_or("none") {
        "none" => Inflow::None,
        "deposit" => Inflow::Deposit,
        "burn" => Inflow::Burn,
        other => anyhow::bail!("deposit.kind must be none, deposit or burn, not {other:?}"),
    };
    if (burn_a == 0) != matches!(inflow, Inflow::None) {
        anyhow::bail!("deposit.kind is `none` exactly when deposit.amount is zero or absent");
    }
    if burn_a != 0 && file.deposit.asset == 0 {
        anyhow::bail!("deposit.asset 0 is RAND, which goes in through deposit.rand");
    }
    Ok(wallet::InvokePlan {
        program,
        reads: cells(&file.reads, "reads")?,
        writes: cells(&file.writes, "writes")?,
        inflow,
        pays: payouts(&file.pays, "pays")?,
        mints: payouts(&file.mints, "mints")?,
        burn_r,
        burn_asset: if burn_a != 0 { file.deposit.asset } else { 0 },
        burn_a,
        input_envelope: None,
        created_cells: 0,
    })
}

fn build_guest(name: &str, args: &[u32]) -> Result<Program> {
    let need = |n: usize| -> Result<()> { if args.len() < n { anyhow::bail!("{name} needs {n} --arg value(s)") } else { Ok(()) } };
    Ok(match name {
        "fib" => { need(1)?; guests::fib(args[0]) }
        "memcpy" => { need(1)?; guests::memcpy(args[0]) }
        "bubble_sort" => { need(1)?; guests::bubble_sort(args) }
        "balance_check" => { need(1)?; guests::balance_check(args[0]) }
        "private_payment" => { need(1)?; guests::private_payment(args[0]) }
        // Reads four public words (deploy it with `--public`): out0 = their sum + public[1].
        "public_echo" => guests::public_echo(),
        // RPL-2's counter: accepts exactly the transitions that read one cell and write it to its
        // first word plus one, `out0` the new count (`rand program invoke`).
        "rpl2_counter" => guests::rpl2_counter(),
        other => anyhow::bail!("unknown guest {other}"),
    })
}

fn load_program(file: &Path) -> Result<Program> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    if file.extension().and_then(|e| e.to_str()) == Some("json") {
        codec::program_from_json(std::str::from_utf8(&bytes)?).map_err(|e| anyhow::anyhow!(e))
    } else {
        codec::program_from_bytes(&bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// `hc` in the one form the chain ever shows it in: `rand_getProgram` / `rand program show` hex
/// `ProgramRecord.code_hash`, which `check_program` (`executor.rs`) fills as `Program::digest`'s
/// eight `u32` words, each in *little-endian* byte order, concatenated. `Program::code_hash()`
/// hex-encodes the same words big-endian instead (`{w:08x}` per word) — a different string for
/// the same digest — so the wallet must not call it here; this function is the RPC's spelling,
/// computed locally before any proof or submission exists to ask the RPC for it.
fn rpc_hc_hex(p: &Program) -> String {
    let mut bytes = Vec::with_capacity(32);
    for w in p.digest() {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    hex::encode(bytes)
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

fn parse_address(s: &str) -> Result<ShieldedAddress> {
    ShieldedAddress::parse(s).map_err(|e| anyhow::anyhow!("{e}")).context("invalid shielded address")
}

/// `rand send`'s TO argument, and `rand contacts add`'s TO: a `rand1…` address first, then a
/// `randpay:` link, then a saved contact's name — in that order, so a name that happens to
/// collide with neither shape is still refused with one clear error rather than three swallowed
/// ones. Returns the address, the link if TO was one (so its `amount`/`asset`/`memo` can be
/// merged with any flags), and the name the address is saved under, if it is — whether TO was
/// that name, the bare address or a link to it (so the confirmation can show it).
fn resolve_recipient(to: &str, contacts: &Contacts) -> Result<(ShieldedAddress, Option<PaymentUri>, Option<String>)> {
    // A pasted address or link names its saved contact too (final review B2): the confirmation
    // then says who it is, and a stranger's address shows no name at all.
    if let Ok(a) = ShieldedAddress::parse(to) {
        let name = contacts.name_of(&a).map(str::to_string);
        return Ok((a, None, name));
    }
    if let Ok(u) = PaymentUri::parse(to) {
        let a = u.address.clone();
        let name = contacts.name_of(&a).map(str::to_string);
        return Ok((a, Some(u), name));
    }
    if let Some(a) = contacts.get(to) {
        return Ok((a, None, Some(to.to_string())));
    }
    Err(anyhow!("{to} is not a shielded address, a randpay: link, or a saved contact"))
}

/// A value that can come from a `--flag` or from a `randpay:` link's own field: agree if both are
/// given, either alone if only one is, `None` if neither. A silent flag/link disagreement would
/// mean the amount or asset a person confirmed on screen is not the one that gets sealed —
/// refused instead. `what` is `"memo"` for a link's memo field too, which is hostile text like any
/// other memo, so both sides of the mismatch go through [`memo_display::truncate`] before they
/// reach this error message — never the raw value (final review A, C2).
fn merge_uri(flag: Option<String>, uri: Option<String>, what: &str) -> Result<Option<String>> {
    match (flag, uri) {
        (Some(f), Some(u)) if f != u => Err(anyhow!(
            "--{what} {} does not match the link's {what} {}",
            memo_display::truncate(&f, 60),
            memo_display::truncate(&u, 60)
        )),
        (Some(f), _) => Ok(Some(f)),
        (None, u) => Ok(u),
    }
}

/// A memo as `rand notes`, `rand history` and `rand tx-key` show it: [`memo_display::sanitize`]d
/// first (a memo is anyone's text — final review A), then cut to 24 **display columns**, `…`
/// included, for a column that must not blow up a terminal's width; `--memo` on `rand notes`/
/// `rand history` asks for the whole sanitised text instead. Sanitising first means padding
/// collapses before the cut and a cut never splits an escape. Columns, not characters
/// ([`memo_display::truncate_cols`], not `truncate`) — a CJK character or an emoji is one `char`
/// but renders as two columns, so a character-counting cut can leave this column far wider than
/// 24 (re-review fix round 2, finding 1); measured by the same upper bound as the confirmation
/// line, 2 columns per non-ASCII code point (fix round 4). `None` (no memo, or a note from before the memo existed)
/// prints as `-`.
fn memo_column(memo: &Option<String>, whole: bool) -> String {
    match memo {
        None => "-".to_string(),
        Some(m) if whole => memo_display::sanitize(m),
        Some(m) => memo_display::truncate_cols(m, 24),
    }
}

/// `rand history`'s header, `to` before `memo` (reviewer's report: the memo — anyone's hostile
/// text — was printed ahead of the recipient column, where it could read as if it were the
/// recipient). Shared with [`history_row`] and this module's own test, so the column order in
/// the header and in every row can never drift apart.
fn history_header() -> String {
    format!("{:>8}  {:>18}  {:>8}  {:<24}  {}", "index", "amount", "height", "to", "memo")
}

/// One `rand history` row, in the same column order as [`history_header`].
fn history_row(index: u64, amount: &str, height: u64, to: &str, memo: &str) -> String {
    format!("{:>8}  {:>18}  {:>8}  {:<24}  {}", index, amount, height, to, memo)
}

/// The confirmation memo line's cut point, in **display columns** — not characters: a CJK
/// character or an emoji is one `char` but renders as two terminal columns, so a character count
/// can pass a memo through whole (57 characters, comfortably under a 60-character budget) while
/// its actual display width forges a second line well past it (re-review fix round 2, finding 1:
/// `"x" + 36×"中" + "to alice · 1000 RAND"`, 57 characters, was let through uncut and drew exactly
/// that forged line in an 80-column terminal). Long enough to show a real memo whole almost
/// always, short enough that, together with the fixed `memo: "…"` wrapping and a byte-count
/// suffix of up to [`randprotocol_core::notes::MEMO_TEXT_MAX_BYTES`]'s three digits, the whole
/// line never passes 80 columns (7 + 60 + 1 + 12 = 80 exactly, at the longest memo the chain
/// accepts, measured throughout by [`memo_display::display_width`] — a table-independent upper
/// bound, 1 column per ASCII character and 2 per any other code point, since no terminal draws
/// one code point wider than 2 (fix round 4: a width table under-charged the invisible U+3164
/// HANGUL FILLER, and a memo of them wrapped into a forged row)).
const MEMO_CONFIRM_COLS: usize = 60;

/// `rand send`'s confirmation, before anything proves: `to <name?> · fingerprint … · <amount>
/// <asset>`, then — only when there is one — the memo on its own `memo: "…"` line, itself cut to
/// [`MEMO_CONFIRM_COLS`] **display columns** with [`memo_display::truncate_cols`] so a memo of
/// any length, or any mix of narrow and wide characters, can never wrap the terminal, and — only
/// when it was in fact cut, by width — a `(N bytes)` suffix naming the raw memo's full length,
/// since a cut memo can otherwise look complete. The memo is hostile text (anyone can send one,
/// and a link carries any), so it never shares the recipient line, and it and the contact name
/// (user-entered, and a link can suggest one) are shown through [`memo_display::sanitize`]: a
/// memo padded with spaces or carrying a line break, a terminal escape or a bidi override cannot
/// draw a second recipient line, and one long enough to wrap — or built of ordinary visible
/// filler, like ASCII dashes, the invisible-looking Braille blank U+2800, or a run of CJK
/// characters or emoji, none of which sanitizing touches — cannot draw a forged one past the cut
/// either (final review A, C1; re-review fix round 2, finding 1).
fn confirmation(name: Option<&str>, fingerprint: &str, amount: &str, memo: &str) -> String {
    // The separator goes through the rule with the name, so a name ending in a space (names are
    // never trimmed) cannot leave a run of two.
    let name_part = name.map(|n| memo_display::sanitize(&format!("{n} · "))).unwrap_or_default();
    let mut shown = format!("to {name_part}fingerprint {fingerprint} · {}", memo_display::sanitize(amount));
    if !memo.is_empty() {
        let full_cols = memo_display::display_width(&memo_display::sanitize(memo));
        let cut = memo_display::truncate_cols(memo, MEMO_CONFIRM_COLS);
        if full_cols > MEMO_CONFIRM_COLS {
            shown.push_str(&format!("\nmemo: \"{cut}\" ({} bytes)", memo.len()));
        } else {
            shown.push_str(&format!("\nmemo: \"{cut}\""));
        }
    }
    shown
}

/// The bare `randpay:` link naming just an address — no amount, asset or memo. Every QR this
/// wallet renders is a `randpay:` link, level M, never a bare address (`rand address --qr`'s own
/// link, built with whatever `--amount`/`--asset`/`--memo` were given, is the other case of the
/// same rule); this is the shared bare form so `rand contacts show --qr` cannot drift back to
/// encoding the address text directly.
fn pay_link(a: &ShieldedAddress) -> String {
    PaymentUri { address: a.clone(), amount: None, asset: None, memo: None }.format()
}

/// The saved contact whose address's `pk` matches `pk`, if any — what `rand history`'s `to`
/// column shows instead of a bare hex `pk` when this wallet has a name for the recipient.
fn contact_name_for(contacts: &Contacts, pk: &Word8) -> Option<String> {
    contacts.entries.iter().find_map(|(name, addr)| {
        let a = ShieldedAddress::parse(addr).ok()?;
        (&a.pk == pk).then(|| name.clone())
    })
}

/// Ask `question [y/N]` and go on only on `y`. A stdin that is not a terminal (a script, a pipe,
/// `</dev/null`) can answer nothing, so it is refused up front with the flag that skips the
/// question — never read as a silent "no" (final review B1).
fn confirm(question: &str, verb: &str, declined: &str) -> Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("stdin is not a terminal: pass --yes to {verb} without confirmation");
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if !line.trim().eq_ignore_ascii_case("y") {
        anyhow::bail!("{declined}");
    }
    Ok(())
}

/// The wallet, where its note store lives, and the store itself.
fn open_wallet(key: &Path) -> Result<(Wallet, PathBuf, NoteStore)> {
    let w = Wallet::load(key)?;
    let path = wallet::store_path(key);
    let store = NoteStore::load(&path);
    Ok((w, path, store))
}

/// The FRI profile the chain runs; a test-profile chain is announced, because a proof under it
/// is not a security claim.
async fn profile_of(rpc: &RpcClient) -> Result<FriProfile> {
    let status = rpc.status().await?;
    let name = status["fri_profile"].as_str().unwrap_or("production");
    let profile = executor::ZkExecutor::profile_from_str(name).context("node reports an unknown fri profile")?;
    if profile == FriProfile::Test {
        eprintln!("warning: chain uses the insecure test FRI profile");
    }
    Ok(profile)
}

/// No fallback: `--cuda` on a build or a machine that cannot run it is an error, so a proof is
/// never quietly produced somewhere other than where it was asked for.
fn backend_for(cuda: bool) -> Result<Backend> {
    if !cuda {
        return Ok(Backend::Cpu);
    }
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    {
        Ok(Backend::Cuda)
    }
    #[cfg(not(any(feature = "cuda", feature = "mock-cuda")))]
    {
        anyhow::bail!("built without CUDA support; rebuild rand with --features cuda")
    }
}

/// How this invocation proves its bundle: on the paired prover under `--prover`, else here on
/// `--cuda`'s backend. Both at once is refused — a proof is made in one place, the one asked for.
fn proving_for(prover: bool, cuda: bool, key: &Path, max_prover_fee: &str) -> Result<Proving> {
    let cap = parse_amount(max_prover_fee).map_err(|e| anyhow!("--max-prover-fee {max_prover_fee}: {e}"))?;
    if !prover {
        return Ok(Proving::local(backend_for(cuda)?));
    }
    if cuda {
        anyhow::bail!("--prover and --cuda: the bundle is proved on the paired prover or on this machine's GPU, not both");
    }
    let paired = PairedProver::load(key)?.ok_or_else(|| anyhow!("no prover paired for this wallet: rand prover pair <link>, or `rand prover pair --trusted` for prover.randprotocol.org"))?;
    prover::check_prover_url(&paired.url)?;
    Ok(Proving::Remote(std::sync::Arc::new(RemoteProver::new(paired).with_max_fee(cap))))
}

/// `rand call --gas-limit`, parsed: absent, `max`, or a number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GasArg {
    Default,
    Max,
    Exactly(u64),
}

fn parse_gas_limit(arg: Option<&str>) -> Result<GasArg> {
    match arg {
        None => Ok(GasArg::Default),
        Some("max") => Ok(GasArg::Max),
        Some(n) => n.parse().map(GasArg::Exactly).map_err(|_| anyhow!("--gas-limit takes a whole number of gas or `max`, not {n:?}")),
    }
}

/// What a call declares, from its dry run (spec 2026-09-28 §5, §9): `(the prover's gas_limit,
/// the gas the fee is priced at before proving)`. `None` proves under the header's own ceiling
/// (`max`, and the default on a chain without a gas section, where the limit buys nothing and
/// would only leak, or on a non-CPU backend, which cannot declare anything else); the default
/// under a section on the CPU backend is the quarter-tier bucket over the exact gas.
/// Prints `gas: <exact> (declaring <limit>, tier <t>)` before any proving, and refuses a limit
/// under the exact gas or over the ceiling, naming the bound.
fn resolve_gas_limit(
    arg: GasArg,
    run: &executor::CallDryRun,
    tier: u8,
    limits: Option<&randprotocol_client::ChainLimits>,
    cpu: bool,
) -> Result<(Option<u64>, u64)> {
    let ceiling = gas::gas_max(tier, run.keccak_log_height, run.sha256_log_height);
    if run.gas > ceiling {
        anyhow::bail!("this call spends {} gas, over tier {tier}'s ceiling {ceiling}; drop --tier or raise it", run.gas);
    }
    let section = limits.is_some_and(|l| l.gas_circuit);
    let declare = match arg {
        GasArg::Max => None,
        // A non-CPU backend (`--cuda`) proves under the header's ceiling only (its prover takes no
        // options), so the default there is the ceiling, not the bucket.
        GasArg::Default if !section || !cpu => None,
        GasArg::Default => Some(wallet::gas_bucket(run.gas, tier, ceiling)),
        GasArg::Exactly(n) if !cpu => {
            anyhow::bail!("--gas-limit {n}: this backend proves under the header's gas ceiling only; pass --gas-limit max, or prove on the CPU backend")
        }
        GasArg::Exactly(n) => {
            wallet::check_gas_limit(n, run.gas, ceiling)?;
            Some(n)
        }
    };
    let priced = declare.unwrap_or(ceiling);
    eprintln!("gas: {} (declaring {priced}, tier {tier})", run.gas);
    Ok((declare, priced))
}

/// `rand fee call <tier>` without `--gas` (spec §9): on a chain with a gas section, the ceiling of
/// the header the flags describe — `gas_max(tier, 0, 0)` for a hash-free call, what
/// `rand call --gas-limit max` declares — so the answer is the most such a call can cost; `None`
/// (no `gas` sent) on a chain without one, which prices the header instead.
fn fee_call_default_gas(section: bool, tier: u64, keccak_log_height: Option<u8>, sha256_log_height: Option<u8>) -> Option<u64> {
    section.then(|| {
        let tier = u8::try_from(tier).unwrap_or(u8::MAX);
        gas::gas_max(tier, keccak_log_height.unwrap_or(0), sha256_log_height.unwrap_or(0))
    })
}

/// The fee line's suffix under the dynamic controller: the default pays two price steps over the
/// tip's floor (spec §7.1).
fn headroom_note(limits: Option<&randprotocol_client::ChainLimits>) -> &'static str {
    if limits.and_then(|l| l.adjust_bps).is_some() {
        " (incl. two price steps of headroom)"
    } else {
        ""
    }
}

/// The summary line, printed. The wording lives in [`Submission::summary`], where a test can read
/// it back.
fn report(s: &Submission, what: &str) {
    println!("{}", s.summary(what));
}

/// Decode a `Registration` as `rand-node register` prints it: its bincode form as hex.
fn parse_registration(text: &str) -> Result<Registration> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text)).context("--registration must be hex")?;
    Registration::decode(&bytes).context("--registration is not a registration from `rand-node register`")
}

/// 32 fresh random bytes, for `rand token create --salt` when none is given. Reuses
/// `randprotocol_zkvm`'s own random source (`TxKey::random`, already a dependency here for
/// sealing envelopes) rather than adding a direct `rand` crate dependency to this binary.
fn random_salt() -> [u8; 32] {
    randprotocol_zkvm::viewing::TxKey::random().0
}

/// `TokenError::IndexMismatch`'s wire text (`"token: wrong token index: expected {expected}, got
/// {got}"`, `ledger::tokens::TokenError`'s `Display`, wrapped once by `TxError::Token`) —
/// `rand token create`'s only refusal that a fresh chain read cannot prevent, because it is a
/// race: another registration can commit between this wallet's read of `next_index` and its own
/// submission. `None` for any other message, which is reported as it always is.
fn parse_index_mismatch(message: &str) -> Option<(u32, u32)> {
    let rest = message.strip_prefix("token: wrong token index: expected ")?;
    let (expected, rest) = rest.split_once(", got ")?;
    Some((expected.parse().ok()?, rest.trim().parse().ok()?))
}

/// A validator's bonded stake as the register reports it, or `None` when it holds no entry for
/// that address. Amounts come out as decimal strings: a stake in units outgrows a JSON number.
async fn register_stake(rpc: &RpcClient, address: &str) -> Result<Option<u64>> {
    let rows = rpc.validators().await?;
    let Some(row) = rows.as_array().and_then(|rows| rows.iter().find(|r| r["address"].as_str() == Some(address))) else {
        return Ok(None);
    };
    let stake = row["stake"].as_str().context("getValidators reply has no stake")?;
    Ok(Some(stake.parse().context("the register's stake is not a number")?))
}

/// The verdict `rand open-call` returns to its caller: `Ok` only when the opened transcript is
/// both faithful and consistent with the receipt it came with.
///
/// Two independent checks, and the chain makes neither. `faithful` is that the transcript hashes to
/// the `H_IN` the proof published, which commits in-circuit to every word the guest read — so an
/// unfaithful transcript is a lie its holder can show to anyone (spec §6.1). The second is that
/// re-running the program on those words reproduces the outputs the receipt reports; the emulator is
/// the reference semantics for the same program, so a difference means these inputs are not what
/// produced that receipt even if they hash correctly.
///
/// An `Err` is the point: this is what makes the command exit non-zero, so a script that opens a
/// transcript to check a claim gets an answer it cannot mistake for a yes.
fn transcript_verdict(faithful: bool, emulated: &[u32], receipt_outputs: &serde_json::Value) -> Result<()> {
    if !faithful {
        anyhow::bail!(
            "NOT FAITHFUL: this transcript is not the preimage of the receipt's H_IN — \
             whoever published it did not run the program on these words"
        );
    }
    // The receipt's outputs are JSON numbers; anything else means this is not a call receipt at all,
    // which is worth failing on rather than comparing against nothing.
    let from_receipt: Option<Vec<u32>> = receipt_outputs
        .as_array()
        .map(|a| a.iter().map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok())).collect::<Option<Vec<u32>>>())
        .unwrap_or(None);
    let Some(from_receipt) = from_receipt else {
        anyhow::bail!("the receipt's outputs are not eight numbers ({receipt_outputs}) — nothing to compare against");
    };
    if from_receipt != emulated {
        anyhow::bail!(
            "OUTPUT MISMATCH: re-running the program on this transcript gives {emulated:?}, \
             and the receipt reports {from_receipt:?} — these inputs are not what produced that receipt"
        );
    }
    Ok(())
}

/// A command-line argument that is either text outright or `@path` to read it from a file.
fn read_text_arg(arg: &str) -> Result<String> {
    match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}")),
        None => Ok(arg.to_string()),
    }
}

/// A command-line argument that is either hex outright or `@path` to read the hex from a file.
/// Whitespace is ignored, so a file written by `xxd` or an editor works as it is.
fn read_hex_arg(arg: &str) -> Result<Vec<u8>> {
    let text = match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
        None => arg.to_string(),
    };
    let compact: String = text.split_whitespace().collect();
    let compact = compact.strip_prefix("0x").unwrap_or(&compact);
    hex::decode(compact).context("expected hex, or @path to a file of hex")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new(cli.rpc.clone());
    match cli.cmd {
        Cmd::Keygen => {
            let w = Wallet::generate();
            w.save_new(&cli.key)?;
            println!("wrote {}\naddress: {}", cli.key.display(), w.address);
        }
        Cmd::Address { uri, amount, asset, memo, qr, qr_png } => {
            let a = Wallet::load(&cli.key)?.address;
            // stdout is exactly the address (and the link/QR asked for), so `$(rand address)`
            // works in a script; the fingerprint is for the person reading, on stderr.
            println!("{a}");
            eprintln!("fingerprint {}", a.fingerprint());
            let u = PaymentUri { address: a, amount, asset, memo };
            let text = u.format();
            // Round-trips through the same parser a payee's wallet uses, so a bad `--amount` or
            // `--asset` is refused here rather than printed as a link nobody can pay.
            PaymentUri::parse(&text).map_err(|e| anyhow!("{e}"))?;
            if uri {
                println!("{text}");
            }
            if qr {
                println!("{}", randprotocol_client::qr::terminal(&text)?);
            }
            if let Some(path) = qr_png {
                randprotocol_client::qr::png(&text, &path)?;
                eprintln!("wrote {}", path.display());
            }
        }
        Cmd::Prover { op } => match op {
            ProverOp::Pair { link, trusted, name, yes } => {
                let (link, name) = match link {
                    Some(text) => (PairingLink::parse(text.trim()).map_err(|e| anyhow!("{e}"))?, name),
                    None => {
                        debug_assert!(trusted, "clap requires a link unless --trusted");
                        (prover::trusted_prover_link()?, name.or_else(|| Some("prover.randprotocol.org".into())))
                    }
                };
                prover::check_prover_url(&link.url)?;
                let paired = PairedProver::from_link(&link, name);
                // VK-4: who is being paired and what it will receive, then the question — before
                // the prover is contacted and before anything is saved. The same for every link:
                // its `own=1` is a label, never what decides which key a prover is sent.
                for line in paired.pairing_confirmation() {
                    println!("{line}");
                }
                if !yes {
                    confirm("pair?", "pair", "not paired")?;
                }
                // `info` refuses a prover whose key is not the one the link names.
                RemoteProver::new(paired.clone()).info().await?;
                paired.save(&cli.key)?;
                // The URL goes through `shown()` like every other prover-supplied string (VK-5).
                println!("{}", paired.paired_line());
            }
            ProverOp::Show => match PairedProver::load(&cli.key)? {
                Some(p) => println!("{}", p.show()),
                None => println!("no prover paired for this wallet"),
            },
            ProverOp::Forget => {
                if PairedProver::forget(&cli.key)? {
                    println!("forgot the pairing ({})", PairedProver::path_for(&cli.key).display());
                } else {
                    println!("no prover was paired for this wallet");
                }
            }
        },
        Cmd::Contacts { op } => {
            let mut c = Contacts::load(&cli.key)?;
            match op {
                ContactsOp::Add { name, to, yes } => {
                    let addr = match ShieldedAddress::parse(&to) {
                        Ok(a) => a,
                        Err(_) => PaymentUri::parse(&to)
                            .map(|u| u.address)
                            .map_err(|_| anyhow!("{to} is neither a shielded address nor a randpay: link"))?,
                    };
                    println!("fingerprint {}", addr.fingerprint());
                    if !yes {
                        confirm(&format!("add {}?", memo_display::sanitize(&name)), "add", "not added")?;
                    }
                    c.add(&name, &addr)?;
                    c.save(&cli.key)?;
                    println!("saved {}", memo_display::sanitize(&name));
                }
                ContactsOp::List => {
                    if c.entries.is_empty() {
                        println!("no contacts");
                    } else {
                        for (name, addr) in &c.entries {
                            println!("{}  {addr}", memo_display::sanitize(name));
                        }
                    }
                }
                ContactsOp::Show { name, qr } => {
                    let addr = c.get(&name).ok_or_else(|| anyhow!("no contact named {name}"))?;
                    println!("{addr}");
                    println!("fingerprint {}", addr.fingerprint());
                    if qr {
                        println!("{}", randprotocol_client::qr::terminal(&pay_link(&addr))?);
                    }
                }
                ContactsOp::Remove { name } => {
                    c.remove(&name)?;
                    c.save(&cli.key)?;
                    println!("removed {}", memo_display::sanitize(&name));
                }
            }
        }
        Cmd::ViewingKey => {
            println!("{}", Wallet::load(&cli.key)?.viewing_key_hex());
            eprintln!("reads every note this wallet sent or received; spends nothing. A node imports it with rand_importViewingKey.");
        }
        Cmd::TxKey { hash } => {
            let w = Wallet::load(&cli.key)?;
            let h = Hash::from_hex(&hash).context("invalid hash")?;
            let tx = rpc
                .raw_transaction(&h)
                .await?
                .ok_or_else(|| anyhow::anyhow!("{} is not a committed transaction on this node", h.to_hex()))?;
            let rows = wallet::output_keys(&w, &tx);
            if rows.is_empty() {
                anyhow::bail!("this wallet neither sent nor received an output of {}", h.to_hex());
            }
            println!("{:<15} {:<9} {:>22}  {:<24}  tx key", "output", "role", "amount", "memo");
            for r in &rows {
                let amount = if r.note.asset == 0 {
                    format!("{} RAND", format_amount(r.note.amount))
                } else {
                    format!("{} (asset {})", r.note.amount, r.note.asset)
                };
                let memo = memo_column(&r.memo, false);
                println!(
                    "{:<15} {:<9} {:>22}  {:<24}  {}",
                    format!("{}:{}", r.output, r.slot), r.role.as_str(), amount, memo, hex::encode(r.key.0)
                );
            }
            eprintln!("each key discloses exactly its own output: rand_checkTransaction <hash> <key> shows it to anyone holding it.");
        }
        Cmd::Balance => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            // Saved whether or not the scan finished (issue #117): every cursor and the walk's
            // pending notes are consistent at each point the scan can fail, so a first sync cut
            // short by a rate limit or a dropped connection resumes instead of starting over.
            let scanned = wallet::scan(&rpc, &w, &mut store).await;
            store.save(&path)?;
            scanned?;
            println!("balance: {} RAND\nnotes: {} unspent", format_amount(store.balance()), store.spendable().len());
        }
        Cmd::AssetBalance { index } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            // Saved whether or not the scan finished (issue #117): every cursor and the walk's
            // pending notes are consistent at each point the scan can fail, so a first sync cut
            // short by a rate limit or a dropped connection resumes instead of starting over.
            let scanned = wallet::scan(&rpc, &w, &mut store).await;
            store.save(&path)?;
            scanned?;
            // The registry names the token behind an index; a note whose asset it does not name is
            // still reported, under its own index, because the note is real either way. Same for a
            // chain with no bridge at all, which answers with an empty registry — or a node too old
            // to answer: the balance is this wallet's own, and the registry only adds a name to it.
            let assets = rpc.assets().await.unwrap_or_default();
            // One bridged token can be backed by several coins (spec §12), and the registry
            // serves one row per coin under the one index — so every coin behind an index is
            // named, not just whichever happens to be listed first.
            let token_of = |index: u32| {
                let coins: Vec<String> = assets
                    .iter()
                    .filter(|a| a.index == index)
                    .map(|a| format!("chain {} token {}", a.chain, hex::encode(&a.token)))
                    .collect();
                match (coins.is_empty(), index) {
                    (false, _) => coins.join(", "),
                    (true, 0) => "RAND".to_string(),
                    (true, _) => "not in this chain's registry".to_string(),
                }
            };
            match index {
                Some(index) => {
                    println!(
                        "asset {index}: {} units ({}), {} notes unspent",
                        store.balance_of(index),
                        token_of(index),
                        store.spendable_of(index).len()
                    );
                }
                None => {
                    let rows = store.asset_balances();
                    if rows.is_empty() {
                        println!("no notes (run `rand sync`)");
                    } else {
                        println!("{:>8}  {:>22}  token", "asset", "units");
                        for (index, units) in rows {
                            println!("{index:>8}  {units:>22}  {}", token_of(index));
                        }
                    }
                }
            }
        }
        Cmd::Sync { rescan } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            if rescan {
                store.reset();
                eprintln!("rescanning from leaf 0: every note and spent mark is rebuilt from the chain");
            }
            // Saved whether or not the scan finished (issue #117): every cursor and the walk's
            // pending notes are consistent at each point the scan can fail, so a first sync cut
            // short by a rate limit or a dropped connection resumes instead of starting over.
            let scanned = wallet::scan(&rpc, &w, &mut store).await;
            store.save(&path)?;
            scanned?;
            println!("scanned {} leaves and {} blocks; {} notes, {} unspent", store.scanned_index, store.scanned_height, store.notes.len(), store.spendable().len());
        }
        Cmd::Notes { memo } => {
            let (_, _, store) = open_wallet(&cli.key)?;
            if store.notes.is_empty() {
                println!("no notes (run `rand sync`)");
            } else {
                // `pending` is a note this wallet has submitted a spend for without waiting for
                // the commit: not spent, not spendable, and the next `sync` decides which.
                // `amount` is in the asset's own smallest unit, so only asset 0 is a RAND figure;
                // a bridged asset's decimals belong to its source chain, not to this one.
                println!("{:>8}  {:>5}  {:>22}  {:>8}  {:>7}  {:<9}  memo", "index", "asset", "amount", "height", "spent", "pending");
                for n in &store.notes {
                    let pending = match n.pending {
                        Some(time) => format!("since {time}"),
                        None => "-".into(),
                    };
                    let amount = if n.note.asset == 0 {
                        format_amount(n.note.amount)
                    } else {
                        n.note.amount.to_string()
                    };
                    println!(
                        "{:>8}  {:>5}  {:>22}  {:>8}  {:>7}  {:<9}  {}",
                        n.index, n.note.asset, amount, n.height, n.spent, pending, memo_column(&n.memo, memo)
                    );
                }
            }
        }
        Cmd::History { memo } => {
            let (_, _, store) = open_wallet(&cli.key)?;
            let contacts = Contacts::load(&cli.key)?;
            if store.sent.is_empty() {
                println!("no notes sent from this wallet");
            } else {
                println!("{}", history_header());
                for s in &store.sent {
                    let to = contact_name_for(&contacts, &s.to_pk)
                        .map(|n| memo_display::sanitize(&n))
                        .unwrap_or_else(|| randprotocol_core::notes::word8_to_hex(&s.to_pk));
                    println!("{}", history_row(s.index, &format_amount(s.amount), s.height, &to, &memo_column(&s.memo, memo)));
                }
            }
        }
        Cmd::Send { to, amount, asset, memo, fee, no_wait, yes, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let contacts = Contacts::load(&cli.key)?;
            let (to, link, name) = resolve_recipient(&to, &contacts)?;
            let amount_text = merge_uri(amount, link.as_ref().and_then(|u| u.amount.clone()), "amount")?
                .ok_or_else(|| anyhow!("no amount: give one or use a link that carries it"))?;
            let asset_text = merge_uri(asset, link.as_ref().and_then(|u| u.asset.clone()), "asset")?
                .unwrap_or_else(|| "0".to_string());
            let memo_text = merge_uri(memo, link.as_ref().and_then(|u| u.memo.clone()), "memo")?.unwrap_or_default();
            // The unit is decided by what was typed, never by the index the node's listing
            // answered (WAL-1): `0`/`rand` is RAND; anything else names a token, and a token id
            // the listing answers with RAND's index 0 is refused rather than read as RAND.
            let is_rand = wallet::names_rand(&asset_text);
            let asset = wallet::resolve_asset(&rpc, &asset_text).await?;
            anyhow::ensure!(
                is_rand == (asset == 0),
                "--asset {asset_text} resolved to index {asset}: only 0 or rand names RAND, and a token never sits at index 0"
            );
            // Display units, whichever asset moves: RAND's nine decimals, or the token registry's
            // own `decimals` for its own — the same units a `randpay:` link's `amount` carries.
            // The confirmation shows the display figure *and* the base units the proof will carry
            // (final review B3), so a node that lies about a token's decimals is visible here.
            let (decimals, symbol) = wallet::asset_units(&rpc, asset).await?;
            let amount = wallet::parse_decimal(&amount_text, decimals)?;
            let shown = wallet::display_amount(amount, decimals, &symbol);
            println!("{}", confirmation(name.as_deref(), &to.fingerprint().to_string(), &shown, &memo_text));
            // A paired prover's fee and, for one not the owner's own, what it can read: shown
            // before the y/N, so both can be declined (spec §5).
            let proving = proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?;
            for line in wallet::prover_confirmation(&rpc, &proving).await? {
                println!("{line}");
            }
            if !yes {
                confirm("send?", "send", "not sent")?;
            }
            let fee = match fee { Some(f) => parse_amount(&f)?, None => gas::BUNDLE_BASE };
            if is_rand {
                eprintln!("sending {} RAND (asset 0), fee {} RAND", format_amount(amount), format_amount(fee));
            } else {
                eprintln!("sending {amount} units of asset {asset} ({asset_text}), fee {} RAND", format_amount(fee));
            }
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::send_asset(&rpc, &w, &mut store, &to, asset, amount, &memo_text, fee, profile, &proving, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            report(&s?, "transfer");
            if !no_wait {
                if asset != 0 {
                    println!("asset {asset} balance: {} units", store.balance_of(asset));
                }
                println!("balance: {} RAND", format_amount(store.balance()));
            }
        }
        Cmd::Bond { validator, amount, registration, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let validator = Address::from_base58(&validator)
                .with_context(|| format!("{validator} is not a validator address"))?;
            let address = validator.to_base58();
            let amount = parse_amount(&amount)?;
            anyhow::ensure!(amount > 0, "a bond of 0 RAND moves no stake and still pays a fee and a proof");
            let registration = registration.as_deref().map(parse_registration).transpose()?;
            // The register decides which of the two shapes a bond has (`staking::check_bond`), so
            // asking it first turns a rejected transaction into an answer before anything is
            // proved — a minute of proving, on a stake this wallet would not get back.
            let staked = register_stake(&rpc, &address).await?;
            match (staked, &registration) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("{address} is already in the register; drop --registration")
                }
                (None, None) => anyhow::bail!(
                    "{address} is not in the register; its operator must send you the registration from `rand-node register --payout <rand1…>` and it goes here as --registration <hex>"
                ),
                (None, Some(r)) => {
                    anyhow::ensure!(
                        r.public_key.address() == validator,
                        "that registration is for validator {}, not {address}",
                        r.public_key.address()
                    );
                    anyhow::ensure!(
                        amount >= MIN_STAKE,
                        "registering a validator bonds at least {} RAND, not {}",
                        format_amount(MIN_STAKE),
                        format_amount(amount)
                    );
                }
                (Some(_), None) => {}
            }
            let action = Action::Bond { validator, amount, registration };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            // `Burn::rand(amount)`: the stake leaves the shielded pool instead of becoming a
            // note, and the ledger admits a bond only when the bundle burns exactly what is
            // bonded. The unit is RAND, which is now in the type rather than in this comment.
            let s =
                wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::rand(amount), profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                    .await;
            store.save(&path)?;
            report(&s?, "bond");
            if !no_wait {
                // The set for the next epoch is derived from the register as it stands at this
                // epoch's last block (spec §8), so a bond that has just committed is weight from
                // the next epoch on — not in the one it landed in.
                let epoch = rpc.epoch().await?["epoch"].as_u64().context("getEpoch reply has no epoch")?;
                if let Some(stake) = register_stake(&rpc, &address).await? {
                    println!(
                        "{address}: stake {} RAND, counting as consensus weight from epoch {}",
                        format_amount(stake),
                        epoch + 1
                    );
                }
                println!("balance: {} RAND", format_amount(store.balance()));
            }
        }
        Cmd::Faucet { address, amount } => {
            let to = match address {
                Some(a) => parse_address(&a)?,
                None => Wallet::load(&cli.key)?.address,
            };
            let units = parse_amount(&amount)?;
            // An observer node answers "only a validator can mint"; that is the node's own
            // wording and is shown as it came, since it says exactly what to do next.
            let hash = rpc.mint_shielded(&to.to_string(), Some(units)).await?;
            println!("submitted mint {hash} ({} RAND to {to})", format_amount(units));
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            println!("committed in block {} (index {})", r.height, r.index);
        }
        Cmd::Program(ProgramCmd::Build { guest, args, out }) => {
            let p = build_guest(&guest, &args)?;
            std::fs::write(&out, codec::program_to_json(&p))?;
            // No public input at build time; `program deploy --public` gives the id one changes it to.
            println!(
                "wrote {} ({} words, program id {})",
                out.display(),
                p.words.len(),
                randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &[])
            );
        }
        Cmd::Program(ProgramCmd::Deploy { file, public, inputs, check_call, cuda }) => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let p = load_program(&file)?;
            let public = public.as_deref().map(wallet::public_file_words).transpose()?.unwrap_or_default();
            // The id binds the public input too (`program_id_with_public`); without one it is the
            // plain `program_id`, unchanged.
            let id = randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &public);
            // Printed before anything is proved: the program id and `hc` are what `rand program
            // show`/`rand_getProgram` will report back for this same program once it lands, so
            // this is the wallet's confirmation that the file it loaded is the one that will show
            // up on chain — in the same spelling, not `Program::code_hash()`'s byte-swapped one
            // (see `rpc_hc_hex`).
            if public.is_empty() {
                println!("program id: {id} ({} words, hc {})", p.words.len(), rpc_hc_hex(&p));
            } else {
                println!(
                    "program id: {id} ({} words, hc {}, public input {} words, digest {})",
                    p.words.len(),
                    rpc_hc_hex(&p),
                    public.len(),
                    randprotocol_core::notes::word8_to_hex(&hash::public_digest(&public))
                );
            }
            // Before any proof: `rand_getLimits` and `rand_estimateFee` apply this chain's own
            // `max_program_words` and `max_program_public_words` admission, so a program over
            // either cap is refused here rather than after a proof the ledger would throw away.
            wallet::deploy_precheck(&rpc, p.words.len(), public.len()).await?;
            // Issue #57: the callable-size bound above holds only for an input-free call; a call
            // over the deployer's own inputs is dry-run against the tier cap before any fee moves.
            if check_call || !inputs.is_empty() {
                let hardened = rpc.limits().await?.is_some_and(|l| l.hardening_v6);
                let tier = wallet::deploy_dry_run(&p, &public, &inputs, hardened)?;
                eprintln!("a call over {} input words proves at tier {tier}", inputs.len());
            }
            let action = Action::Deploy { base_pc: p.base_pc, words: p.words.clone(), public };
            let fee = wallet::deploy_fee_default(&action);
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::None, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, true).await;
            store.save(&path)?;
            // No repeat of the program id/hc line after submission: both are pure functions of
            // the file the wallet loaded (checked above, before the proof), never of the chain's
            // response, so printing them again here would only be a duplicate of the pre-proof
            // line — `report` below is what actually changed.
            report(&s?, "deploy");
        }
        Cmd::Program(ProgramCmd::Show { id }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            match rpc.program(&id).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("unknown program"),
            }
        }
        Cmd::Program(ProgramCmd::State { id, cell }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            match cell {
                Some(k) => {
                    let key = parse_word8(&k, "--cell")?;
                    let value = rpc.program_cell(&id, &key).await?.context("this chain has no program_state section")?;
                    println!("{}", pretty(&serde_json::json!({ "key": word8_to_hex(&key), "value": word8_to_hex(&value) })));
                }
                None => {
                    let mut after = None;
                    let mut cells = Vec::new();
                    loop {
                        let (page, next) =
                            rpc.program_cells(&id, after.as_ref(), 1000).await?.context("this chain has no program_state section")?;
                        cells.extend(page.iter().map(|c| serde_json::json!({ "key": word8_to_hex(&c.key), "value": word8_to_hex(&c.value) })));
                        match next {
                            Some(n) => after = Some(n),
                            None => break,
                        }
                    }
                    println!("{}", pretty(&serde_json::json!({ "program": id.to_hex(), "cells": cells })));
                }
            }
        }
        Cmd::Program(ProgramCmd::Vault { id }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            let vault = rpc.program_vault(&id).await?.context("this chain has no program_state section")?;
            let rows: Vec<_> = vault.iter().map(|(asset, amount)| serde_json::json!({ "asset": asset, "amount": amount.to_string() })).collect();
            println!("{}", pretty(&serde_json::json!({ "program": id.to_hex(), "vault": rows })));
        }
        Cmd::Program(ProgramCmd::Invoke { program, transition, inputs, inputs_file, fee, gas_limit, tier, no_wait }) => {
            use randprotocol_core::ledger::program_state::{segment_fits, CONTEXT_HEADER_WORDS};
            let gas_arg = parse_gas_limit(gas_limit.as_deref())?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            let mut plan = read_transition_file(&transition, pid, &w.address)?;
            let mut inputs = inputs;
            if let Some(f) = &inputs_file {
                let more: Vec<u32> = serde_json::from_str(&std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?)
                    .with_context(|| format!("{} is not a JSON array of u32", f.display()))?;
                inputs.extend(more);
            }
            // Everything cheap before a proof is paid for, in the ledger's own order: the gate,
            // the program, the segment rule, the cells read, the vault, and what this wallet
            // holds — so nothing below spends a minute of proving on a transaction the chain
            // would refuse in a microsecond.
            let limits = rpc.limits().await?;
            let Some(ps) = limits.and_then(|l| l.program_state) else {
                anyhow::bail!("this chain has no program_state section: no invoke is admitted");
            };
            let (prog, public) = wallet::load_call_program(&rpc, &pid).await?;
            let context_words = CONTEXT_HEADER_WORDS + 16 * (plan.reads.len() + plan.writes.len()) + 3 * (plan.pays.len() + plan.mints.len());
            if !segment_fits(public.len(), context_words) {
                anyhow::bail!(
                    "the transition's context is {context_words} words, which does not fit beside this program's {}-word public input                      and the 8 binding words in one public table (the segment rule): fewer cells or payouts",
                    public.len()
                );
            }
            let zero = [0u32; 8];
            for c in &plan.reads {
                let live = rpc.program_cell(&pid, &c.key).await?.context("this chain has no program_state section")?;
                if live != c.value {
                    eprintln!(
                        "cell {} is stale: the transition read {} and the chain holds {}; re-read the program's state and retry",
                        word8_to_hex(&c.key),
                        word8_to_hex(&c.value),
                        word8_to_hex(&live)
                    );
                    std::process::exit(STALE_READ_EXIT);
                }
            }
            // The cells the writes create, for the fee: a non-zero value where the chain holds
            // zeros (a read of the same key already told us; the rest are asked).
            let mut created = 0u64;
            for c in plan.writes.iter().filter(|c| c.value != zero) {
                let live = match plan.reads.iter().find(|r| r.key == c.key) {
                    Some(r) => r.value,
                    None => rpc.program_cell(&pid, &c.key).await?.context("this chain has no program_state section")?,
                };
                if live == zero {
                    created += 1;
                }
            }
            plan.created_cells = created;
            let vault = rpc.program_vault(&pid).await?.context("this chain has no program_state section")?;
            let mut assets: Vec<u32> = plan.pays.iter().map(|p| p.asset).collect();
            assets.sort_unstable();
            assets.dedup();
            for asset in assets {
                let held = vault.iter().find(|(a, _)| *a == asset).map_or(0, |(_, v)| *v);
                let deposited = if asset == 0 {
                    plan.burn_r
                } else if plan.burn_asset == asset && matches!(plan.inflow, randprotocol_core::ledger::program_state::Inflow::Deposit) {
                    plan.burn_a
                } else {
                    0
                };
                let want: u64 = plan.pays.iter().filter(|p| p.asset == asset).map(|p| p.amount).sum();
                if held.saturating_add(deposited) < want {
                    anyhow::bail!("the vault holds {held} of asset {asset} (plus {deposited} this transition deposits) and the transition pays {want}");
                }
            }
            if plan.burn_a != 0 && store.balance_of(plan.burn_asset) < plan.burn_a {
                anyhow::bail!("this wallet holds {} of asset {} and the transition deposits {}", store.balance_of(plan.burn_asset), plan.burn_asset, plan.burn_a);
            }
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let proving = if cli.prover { proving_for(true, false, &cli.key, &cli.max_prover_fee)? } else { Proving::local(Backend::Cpu) };
            // The dry run over the REAL context words — the guest branches on them — with eight
            // zero words standing in for the binding, which the guest never reads.
            let context = {
                use randprotocol_core::ledger::program_state::{Payout, Transition};
                let dummy = |p: &wallet::PayoutRequest| Payout {
                    asset: p.asset,
                    amount: p.amount,
                    recipient: w.address.clone(),
                    r: [0; 8],
                    envelope: randprotocol_core::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] },
                };
                let probe = Transition {
                    reads: plan.reads.clone(),
                    writes: plan.writes.clone(),
                    inflow: plan.inflow,
                    pays: plan.pays.iter().map(dummy).collect(),
                    mints: plan.mints.iter().map(dummy).collect(),
                };
                probe.context(plan.burn_r, plan.burn_asset, plan.burn_a)
            };
            let segment = [public.as_slice(), &zero, context.as_slice()].concat();
            let run = executor::dry_run_call(&prog, &inputs, &segment)
                .map_err(|e| anyhow::anyhow!("the program does not accept this transition: {e}"))?;
            let tier = tier.unwrap_or(run.tier);
            let (declare, priced_gas) = resolve_gas_limit(gas_arg, &run, tier, limits.as_ref(), true)?;
            let salt = executor::fresh_call_salt();
            let cap = wallet::proof_cap(limits.as_ref());
            let cell_term = ps.cell_fee.saturating_mul(created);
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::call_fee_default(limits.as_ref(), tier, 0, 0, priced_gas, wallet::hardened_call_quote_bytes(limits.as_ref(), 0))?
                    .checked_add(cell_term)
                    .context("fee overflow")?,
            };
            eprintln!(
                "fee {} RAND ({created} cell{} created at {} RAND each){}",
                format_amount(fee),
                if created == 1 { "" } else { "s" },
                format_amount(ps.cell_fee),
                headroom_note(limits.as_ref())
            );
            let need_rand = fee.checked_add(plan.burn_r).context("fee + deposit overflows")?;
            if store.balance_of(0) < need_rand {
                anyhow::bail!(
                    "this wallet holds {} RAND and the invoke needs {} (fee {} + {} deposited)",
                    format_amount(store.balance_of(0)),
                    format_amount(need_rand),
                    format_amount(fee),
                    format_amount(plan.burn_r)
                );
            }
            eprintln!("proving the invoke locally ({} inputs stay private, over {context_words} context words)…", inputs.len());
            let prove = |binding: &[u32; randprotocol_core::types::TX_BINDING_WORDS], context: &[u32]| -> Result<Vec<u8>> {
                let t = std::time::Instant::now();
                let (proof, outputs, tier) =
                    executor::prove_invoke(profile, &prog, &inputs, &public, binding, context, salt, Some(tier), declare)
                        .map_err(|e| anyhow::anyhow!(e))?;
                eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
                wallet::check_proof_size(proof.len(), cap)?;
                Ok(proof)
            };
            let s = wallet::submit_bound_invoke(&rpc, &w, &mut store, &plan, fee, &prove, limits.as_ref(), profile, &proving, chain_id, !no_wait).await;
            store.save(&path)?;
            let (s, sent) = match s {
                Ok(v) => v,
                Err(e) => {
                    // The chain's stale-read verdict is not a refusal of the bytes: a cell moved
                    // between the quote and the block. Distinct, so a calling tool re-quotes.
                    if format!("{e:#}").contains("is no longer what this transition read") {
                        eprintln!("{e:#}");
                        std::process::exit(STALE_READ_EXIT);
                    }
                    return Err(e);
                }
            };
            report(&s, "invoke");
            for (what, list) in [("paid", &sent.pays), ("minted", &sent.mints)] {
                for p in list {
                    println!("  {what} {} of asset {} to {}", p.amount, p.asset, p.recipient.fingerprint());
                }
            }
            if !no_wait {
                let receipt = rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await?;
                let outputs: Vec<u64> = receipt["outputs"].as_array().map(|o| o.iter().filter_map(|v| v.as_u64()).collect()).unwrap_or_default();
                println!("outputs {outputs:?}");
                println!("{}", pretty(&receipt));
            }
        }
        Cmd::Call { program, inputs, expect_public, tier, gas_limit, fee, auditor, no_envelope, print_call_key, cuda } => {
            let gas_arg = parse_gas_limit(gas_limit.as_deref())?;
            if no_envelope && (auditor.is_some() || print_call_key) {
                anyhow::bail!("--no-envelope publishes no transcript, so there is no auditor and no call key");
            }
            let auditor = auditor.as_deref().map(parse_address).transpose()?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            // The code and the deploy-time public input, checked against the id before proving.
            let (prog, public) = wallet::load_call_program(&rpc, &pid).await?;
            if let Some(file) = &expect_public {
                wallet::check_expected_public(&public, &wallet::public_file_words(file)?)?;
            }
            // The caps come from the chain (`rand_getLimits`); an older node gets the old ones.
            let limits = rpc.limits().await?;
            let caps = wallet::call_caps(limits.as_ref());
            if !no_envelope && inputs.len() > caps.max_input_words {
                anyhow::bail!(
                    "{} input words is over this chain's call-input cap of {} (from max_call_envelope_bytes {})",
                    inputs.len(),
                    caps.max_input_words,
                    caps.max_envelope_bytes
                );
            }
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let backend = backend_for(cuda)?;
            // The call proof is always made here, on `--cuda`'s backend; `--prover` moves only the
            // paying bundle.
            let proving = if cli.prover { proving_for(true, false, &cli.key, &cli.max_prover_fee)? } else { Proving::local(backend) };
            if public.is_empty() {
                eprintln!("proving the call locally ({} inputs stay private)…", inputs.len());
            } else {
                eprintln!(
                    "proving the call locally ({} inputs stay private, over the program's {}-word public input)…",
                    inputs.len(),
                    public.len()
                );
            }
            // INT-4: on a chain whose genesis sets `hardening_v6` a call proof is bound to its own
            // transaction — its public segment is `Transaction::call_binding`, which covers the fee
            // bundle — so it is proved *inside* the submission, after the bundle's notes are chosen
            // and before the bundle is proved. Everything the binding covers is fixed first: the
            // `H_IN` salt and the sealed input envelope, and the fee, from the tier the call lands
            // on (`executor::call_tier`, no proving). On any other chain the old order stands.
            let hardened = limits.as_ref().is_some_and(|l| l.hardening_v6);
            let (s, call_key) = if hardened {
                if !matches!(backend, Backend::Cpu) {
                    anyhow::bail!("this chain binds each call proof to its transaction (hardening_v6); prove it on the CPU backend");
                }
                // The program's public input, then the binding (issue #55: a program with one is
                // bound too).
                let segment_words = public.len() + randprotocol_core::types::TX_BINDING_WORDS;
                let mut segment = public.clone();
                segment.resize(segment_words, 0);
                let run = executor::dry_run_call(&prog, &inputs, &segment).map_err(|e| anyhow::anyhow!("the call does not run: {e}"))?;
                let tier = tier.unwrap_or(run.tier);
                // The limit is fixed here, before proving, because the fee is (the binding covers
                // the fee bundle). `max` proves with `None` — the real header's ceiling — and is
                // priced at the dry run's; the guard after proving re-prices the real one.
                let (declare, priced_gas) = resolve_gas_limit(gas_arg, &run, tier, limits.as_ref(), true)?;
                let salt = executor::fresh_call_salt();
                let (envelope, call_key) = if no_envelope {
                    (None, None)
                } else {
                    let h_in = hash::input_digest(salt, &inputs);
                    let (e, key) = call_envelope::seal_call_envelope(&w.vk, auditor.as_ref(), &h_in, salt, &inputs, caps)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    (Some(e), Some(key))
                };
                // The proof's own bytes cannot be known before it exists — the hardened path fixes
                // the fee before proving (the binding covers the fee bundle, so the bundle is built
                // first). Under the node's gas policy every byte prices in, so the proof's bytes
                // cannot be left out of the quote: `hardened_call_quote_bytes` prices the chain's
                // proof cap in the proof's own place (and heights 0, 0 — the real header is just as
                // unknown), which can only overpay, by at most `(cap − actual) · byte_price`
                // (≈ 0.0007 RAND at the 2 MiB cap); `--fee` pays exact. Without a policy the
                // ledger's byte term charges only past the free allowance, so the quote is the
                // envelope alone, as before — the cap would over-charge a raised-cap chain.
                // `submit_bound_call` re-prices the real proof's header once it exists and refuses
                // to submit under its floor, naming the fee to retry with.
                let cap = wallet::proof_cap(limits.as_ref());
                let bytes = wallet::hardened_call_quote_bytes(limits.as_ref(), envelope.as_ref().map_or(0, |e| e.len()));
                let fee = match fee {
                    Some(f) => parse_amount(&f)?,
                    None => wallet::call_fee_default(limits.as_ref(), tier, 0, 0, priced_gas, bytes)?,
                };
                if limits.as_ref().is_some_and(|l| l.gas_circuit) {
                    eprintln!("fee {} RAND{}", format_amount(fee), headroom_note(limits.as_ref()));
                }
                let prove = |binding: &[u32; randprotocol_core::types::TX_BINDING_WORDS]| -> Result<Vec<u8>> {
                    let t = std::time::Instant::now();
                    let (proof, outputs, tier) =
                        executor::prove_call_hardened(profile, &prog, &inputs, &public, binding, salt, Some(tier), declare)
                            .map_err(|e| anyhow::anyhow!(e))?;
                    eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
                    wallet::check_proof_size(proof.len(), cap)?;
                    Ok(proof)
                };
                let action = Action::Call { program: pid, proof: Vec::new(), input_envelope: envelope };
                let s =
                    wallet::submit_bound_call(&rpc, &w, &mut store, action, fee, &prove, limits.as_ref(), profile, &proving, chain_id, true).await;
                (s, call_key)
            } else {
                let run = executor::dry_run_call(&prog, &inputs, &public).map_err(|e| anyhow::anyhow!("the call does not run: {e}"))?;
                let (declare, _) = resolve_gas_limit(gas_arg, &run, tier.unwrap_or(run.tier), limits.as_ref(), matches!(backend, Backend::Cpu))?;
                let t = std::time::Instant::now();
                // Two provers, one difference: `prove_call` returns the `H_IN` salt as well, which is
                // what the transcript is sealed with. It is CPU-only — every other backend draws that
                // salt inside the prover and drops it — so a GPU proof has to go without an envelope,
                // and says so in its own words rather than being quietly downgraded here.
                let (proof, outputs, tier, envelope, call_key) = if no_envelope {
                    let (proof, outputs, tier) =
                        executor::prove(profile, &prog, &inputs, &public, tier, backend, declare).map_err(|e| anyhow::anyhow!(e))?;
                    (proof, outputs, tier, None, None)
                } else {
                    let (proof, outputs, tier, salt) =
                        executor::prove_call(profile, &prog, &inputs, &public, tier, backend, caps.max_input_words, declare)
                            .map_err(|e| anyhow::anyhow!(e))?;
                    let h_in = hash::input_digest(salt, &inputs);
                    let (e, key) = call_envelope::seal_call_envelope(&w.vk, auditor.as_ref(), &h_in, salt, &inputs, caps)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    (proof, outputs, tier, Some(e), Some(key))
                };
                eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
                // Before the paying bundle is proved: a proof over the chain's cap would be refused.
                wallet::check_proof_size(proof.len(), wallet::proof_cap(limits.as_ref()))?;
                // The fee's byte term counts the proof and the envelope (spec §7); under a node's
                // gas policy every byte prices in, and without one only what is past the free
                // allowance does.
                let bytes = gas::call_bytes(&proof, envelope.as_ref());
                // The header the fee is priced on (spec 2026-09-28 §4.1): the proof just made.
                let header = randprotocol_zkvm::executor::decode_canonical(&proof).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                let (klh, slh) = (header.keccak_log_height, header.sha256_log_height);
                let gas_bound = gas::gas_max(tier, klh, slh);
                // Constraint set 8: the limit the proof declares (`pv::GAS`), what a gas section
                // charges — read off the proof itself, so `max` prices the real header's ceiling.
                // Fail-closed (`wallet::declared_gas`): a proof whose public values stop short of
                // GAS is an error here, never silently priced at the header's ceiling.
                let declared = wallet::declared_gas(&header.public_values)?;
                let floor = wallet::call_fee_default(limits.as_ref(), tier, klh, slh, declared, bytes)?;
                let fee = match fee {
                    Some(f) => parse_amount(&f)?,
                    None => floor,
                };
                eprintln!(
                    "gas bound {gas_bound} (tier {tier}{}{}), declared {declared}, {bytes} bytes, fee {} RAND{}",
                    if klh > 0 { format!(", keccak 2^{klh}") } else { String::new() },
                    if slh > 0 { format!(", sha256 2^{slh}") } else { String::new() },
                    format_amount(fee),
                    headroom_note(limits.as_ref())
                );
                let action = Action::Call { program: pid, proof, input_envelope: envelope };
                let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::None, profile, &proving, chain_id, true).await;
                (s, call_key)
            };
            store.save(&path)?;
            let s = s?;
            report(&s, "call");
            let receipt = rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await?;
            println!("{}", pretty(&receipt));
            if let Some(key) = call_key {
                println!(
                    "input transcript published{}; open it with `rand open-call {}`",
                    match &auditor {
                        Some(a) => format!(" (also readable by the auditor {a})"),
                        None => String::new(),
                    },
                    s.hash
                );
                if print_call_key {
                    // A per-call key is exactly as secret as the inputs it opens, and this is the
                    // only moment it exists outside the envelope: it is not derived from any other
                    // key, so it cannot be recovered later.
                    println!("call key: {} — whoever holds this can read this call's inputs", hex::encode(key.0));
                }
            }
        }
        Cmd::OpenCall { txhash, call_key, as_auditor } => {
            let h = Hash::from_hex(&txhash).context("invalid hash")?;
            let receipt = rpc.receipt(&h).await?.context("no receipt for this hash (not a call, or not yet committed)")?;
            let (h_in, envelope) =
                rpc.call_envelope(&h).await?.context("this call published no input transcript")?;
            let receipt_h_in = randprotocol_core::notes::word8_from_hex(receipt["h_in"].as_str().unwrap_or_default())
                .context("the receipt's h_in is not 64 hex characters")?;
            if receipt_h_in != h_in {
                anyhow::bail!("the node's receipt and envelope disagree about this call's H_IN");
            }
            let (how, salt, inputs) = match (&call_key, as_auditor) {
                (Some(_), true) => anyhow::bail!("--call-key and --as-auditor are two different keys; pass one"),
                (Some(hex), false) => {
                    let key = call_envelope::CallKey(randprotocol_client::hex32(hex).context("--call-key must be 32 bytes of hex")?);
                    let (salt, inputs) =
                        call_envelope::open_call_with_key(&envelope, &h_in, &key).context("this call key does not open it")?;
                    ("the per-call key", salt, inputs)
                }
                (None, auditor) => {
                    let w = Wallet::load(&cli.key)?;
                    let opened = if auditor {
                        call_envelope::open_call_as_auditor(&envelope, &h_in, &w.vk)
                            .context("this wallet is not the auditor of this call")?
                    } else {
                        call_envelope::open_call_as_sender(&envelope, &h_in, &w.vk)
                            .context("this wallet did not make this call (try --as-auditor, or --call-key)")?
                    };
                    let (_, salt, inputs) = opened;
                    (if auditor { "the auditor's viewing key" } else { "the caller's viewing key" }, salt, inputs)
                }
            };
            println!("opened with {how}: {} input word(s)\ninputs: {inputs:?}", inputs.len());
            // The chain checks nothing about a transcript's *contents*: what makes one faithful is
            // that it hashes to the `H_IN` the proof published, which commits in-circuit to every
            // word the guest read. A transcript that fails this is a lie the holder can show to
            // anyone (spec §6.1).
            let faithful = call_envelope::call_envelope_is_faithful(&h_in, salt, &inputs);
            // Re-run the program on the transcript. The receipt's outputs came out of a proof; these
            // come out of the emulator, which is the reference semantics for the same program, so a
            // difference means the transcript is not what produced that receipt.
            let pid = Hash::from_hex(receipt["program"].as_str().unwrap_or_default()).context("receipt program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("the program is no longer on chain")?;
            // The public segment the proof was made over (issue #116): the program's deploy-time
            // public words and, under genesis `hardening_v6`, the eight-word call binding after
            // them — what the ledger verified the call against. The re-run used to pass an empty
            // segment, so every program deployed with `--public` trapped at its first
            // `READ_PUBLIC` and the faithfulness check never ran.
            let public = rpc.program_public(&pid).await?.context("the program is no longer on chain")?;
            let hardened = rpc.limits().await?.is_some_and(|l| l.hardening_v6);
            let tx = rpc.raw_transaction(&h).await?.context("the node no longer holds this transaction")?;
            // BIND-1: the call binding in the chain's domain — asked only when it is read at all.
            let domain = match hardened {
                true => rpc.binding_domain(tx.chain_id).await?,
                false => randprotocol_core::BindingDomain::ChainId,
            };
            let segment = wallet::open_call_public_segment(&public, hardened, &tx, &domain);
            let exec = emulator::execute(&Program { base_pc, words }, &inputs, &segment, Tier(*TIERS.last().expect("a tier")).max_cycles())
                .map_err(|e| anyhow::anyhow!("re-running the program on these inputs failed: {e:?}"))?;
            println!("emulator outputs: {:?}\nreceipt outputs:  {}", exec.outputs, receipt["outputs"]);
            // The verdict is the exit status, not a line of output: whoever runs this in a script is
            // asking "is this transcript the one that produced that receipt", and a printed
            // NOT FAITHFUL beside a zero exit reads as a yes.
            transcript_verdict(faithful, &exec.outputs, &receipt["outputs"])?;
            println!("verdict: faithful — these are the words the proof was made over, and they reproduce its outputs");
        }
        Cmd::BridgeMint { attestation, pq, to, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let bytes = read_hex_arg(&attestation)?;
            let d = wallet::attested_deposit(&bytes)?;
            // The Dilithium2 co-signatures (B3), checked here under the chain's own rules against
            // the node's PQ set and chain id — before anything is proved.
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            wallet::check_pq_cosignatures(&rpc.bridge_state().await?, rpc.chain_id().await?, &bytes, &pq_signatures)?;
            let recipient = match &to {
                Some(a) => parse_address(a)?,
                None => w.address.clone(),
            };
            // The guardians signed a 32-byte hash of the recipient's address, and the ledger
            // refuses a transaction whose address does not hash to it — so this wallet checks
            // before paying for a proof it could not get admitted.
            if recipient.recipient_hash() != d.to_hash {
                anyhow::bail!(
                    "this attestation deposits to the address hashing to {}, and {} does not; \
                     pass --to with the address the depositor named",
                    hex::encode(d.to_hash),
                    if to.is_some() { "the address given" } else { "this wallet's address" }
                );
            }
            // The asset id comes from the node, over the two wire fields the guardians signed — a
            // disagreement with the one this wallet computed would mean the two are not speaking
            // about the same chain.
            let asset_id = rpc.bridge_asset_id(d.token_chain, &d.token).await?;
            if asset_id != d.asset.to_hex() {
                anyhow::bail!("the node computes a different asset id ({asset_id}) than this wallet ({})", d.asset.to_hex());
            }
            // The index a note carries is state, so it is asked of the node too — and it is a
            // fact, not a guess: a bridged token is listed before any attestation of it is
            // admissible, and a listing's index never moves. A token this chain has not listed is
            // an error here rather than a refused transaction an hour later (`wallet::deposit_index`).
            let bridge = rpc.bridge_state().await?;
            let index = wallet::deposit_index(&bridge, &rpc.assets().await?, &asset_id)?;
            // The two ledger rules that can refuse a perfect attestation (node M4): the B1 pause,
            // and this coin's remaining share of the daily mint cap. Both are on the reply just
            // read, and hearing either of them after ~100 s of proving is the wrong order.
            wallet::mint_is_possible(&bridge, d.token_chain, &d.token, d.amount)?;
            // The note is stamped with a `time` this wallet chooses, inside the window admission
            // allows, which is what makes its commitment predictable enough to seal an envelope
            // against (`Action::BridgeAttest`). The head is the freshest such time.
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            // The blinding is the attestation digest's, not this wallet's (F1): the same note
            // whoever submits this attestation at this `time`, which is what makes a copier's
            // submission a conflict rather than a second, different note.
            // The chain id this transaction is built for, read once: it also decides the envelope
            // format, so a node's memo claim on a pre-`envelope_bytes` chain is not believed (#64).
            let chain_id = rpc.chain_id().await?;
            let (note, envelope) =
                wallet::deposit_note_for(&w, &recipient, &bytes, d.amount, index, time, rpc.envelope_format(chain_id).await?)?;
            let owner = recipient.to_string();
            // The action names the index this envelope was sealed for, and admission refuses a
            // mismatch (`Action::BridgeAttest`) — which nothing on a listed token can now cause,
            // since no transaction hands an index out and a listing's index never moves.
            let action = Action::BridgeAttest {
                attestation: bytes,
                recipient,
                r: note.r,
                time,
                asset: index,
                envelope,
                pq_signatures,
            };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridge attestation");
            // Everything the deposit note is made of, every time. `r` and `time` are already public
            // in this transaction, so printing them discloses nothing — and they are the only way to
            // rebuild the note by hand if the node's registry turns out to disagree, below.
            println!(
                "deposit: {} units of asset {index}\n  note {}\n  owner {owner}, from 0, time {time}, r {}",
                d.amount,
                randprotocol_core::notes::word8_to_hex(&note.commitment()),
                randprotocol_core::notes::word8_to_hex(&note.r),
            );
            if !no_wait {
                // Belt and braces. The action names its index and admission refuses a transaction
                // that disagrees with the registry, so a *committed* attest cannot have landed
                // under another index. What is left for this to catch is a node whose registry
                // disagrees with the one the index was read from, which is worth a line rather
                // than a silence.
                let committed = rpc.call("rand_getTransaction", serde_json::json!([s.hash.to_hex()])).await?;
                let landed = match wallet::deposit_index_check(index, &committed) {
                    wallet::DepositIndexCheck::Agrees => index,
                    wallet::DepositIndexCheck::Mismatch { predicted, committed } => {
                        println!(
                            "warning: this node says the deposit landed under asset {committed}, not the {predicted} \
                             the envelope was sealed for — which admission should have refused, so treat this node's \
                             registry as suspect.\n  \
                             If it is right, the envelope opens nothing: rebuild the note as (owner {owner}, from 0, \
                             amount {}, asset {committed}, time {time}, r {}) and import it by hand.",
                            d.amount,
                            randprotocol_core::notes::word8_to_hex(&note.r),
                        );
                        committed
                    }
                    // Only reachable if this node cannot render the action it just committed.
                    wallet::DepositIndexCheck::Unknown => {
                        println!("warning: the node cannot say which asset this deposit landed under; check `rand tx {}`", s.hash);
                        index
                    }
                };
                println!("asset {landed} balance: {} units", store.balance_of(landed));
            }
        }
        Cmd::BridgeRotate { rotation, pq, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let bytes = read_hex_arg(&rotation)?;
            let new_index = wallet::attested_rotation(&bytes)?;
            let state = rpc.bridge_state().await?;
            let chain_id = rpc.chain_id().await?;
            // A rotation must step the current set by one (the ledger's `BadUpgradeIndex`); said
            // here, before a proof, rather than after one.
            let current = state["guardian_set_index"].as_u64().context("the node serves no guardian_set_index")?;
            if u64::from(new_index) != current + 1 {
                anyhow::bail!("this rotation is to guardian set {new_index}, but Rand is on set {current}: it must be {}", current + 1);
            }
            // Every attest carries the PQ quorum, a rotation's included — by the *current* PQ set,
            // which a payload-2 rotation does not change.
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            wallet::check_pq_cosignatures(&state, chain_id, &bytes, &pq_signatures)?;
            // A rotation deposits nothing: the deposit fields are placeholders the ledger reads for
            // a transfer only — this wallet's address, asset 0 and an empty envelope. `time` still
            // gets the admission window every attest's does, and `r` is still the one the
            // attestation's digest derives (F1): the rule is every attest's, so no attest
            // transaction carries a field a copier could vary.
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            let empty = randprotocol_core::notes::Envelope {
                kem_ct: Vec::new(),
                to_receiver: Vec::new(),
                to_sender: Vec::new(),
                body: Vec::new(),
            };
            let r = randprotocol_core::ledger::bridge_notes::deposit_r(&bytes)
                .context("the attestation has no body to derive the deposit blinding from")?;
            let action = Action::BridgeAttest {
                attestation: bytes,
                recipient: w.address.clone(),
                r,
                time,
                asset: 0,
                envelope: empty,
                pq_signatures,
            };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "guardian-set rotation");
            if no_wait {
                println!("submitted the rotation to guardian set {new_index}; `rand` did not wait for it to commit");
            } else {
                let after = rpc.bridge_state().await?;
                println!("guardian_set_index: {}", after["guardian_set_index"]);
            }
        }
        Cmd::BridgeBurn { asset, amount, to_chain, token, to, relayer_fee, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let to = randprotocol_client::hex32(&to).context("the destination address must be 32 bytes of hex")?;
            let token = randprotocol_client::hex32(&token)
                .context("the source-chain token address must be 32 bytes of hex")?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::burn_fee_default(),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_burn(
                &rpc,
                &w,
                &mut store,
                asset,
                amount,
                relayer_fee,
                to_chain,
                token,
                to,
                fee,
                profile,
                &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?,
                chain_id,
                !no_wait,
            )
            .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridge burn");
            println!(
                "burned {amount} units of asset {asset} to chain {to_chain} ({}), of which {relayer_fee} pays the relayer there, change {}",
                hex::encode(to),
                s.change
            );
            if !no_wait {
                println!("asset {asset} balance: {} units", store.balance_of(asset));
            }
        }
        Cmd::Token(TokenCmd::Burn { asset, amount, fee, no_wait, cuda }) => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let asset = wallet::resolve_asset(&rpc, &asset).await?;
            let (decimals, symbol) = wallet::asset_units(&rpc, asset).await?;
            let amount = wallet::parse_decimal(&amount, decimals)?;
            eprintln!("burning {}", memo_display::sanitize(&wallet::display_amount(amount, decimals, &symbol)));
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&Action::TokenBurn { asset, amount }),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_token_burn(&rpc, &w, &mut store, asset, amount, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            report(&s?, "token burn");
            if !no_wait {
                println!("asset {asset} balance: {} units", store.balance_of(asset));
            }
        }
        Cmd::Token(TokenCmd::RegisterBridged { name, symbol, salt, chain, token, decimals, pq, fee, no_wait, cuda }) => {
            let salt = randprotocol_client::hex32(&salt).context("--salt must be 32 bytes of hex")?;
            let token = randprotocol_client::hex32(&token).context("--token must be 32 bytes of hex")?;
            let chain_id = rpc.chain_id().await?;
            // BIND-1: the message the file is checked against is this chain's — genesis-bound off
            // the chains cut before `binding_domain`, by chain id, never by the node's claim.
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?.bound_to(rpc.binding_domain(chain_id).await?);
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            // Everything refusable is refused here, before a key file is opened or a bundle
            // proved: the name rules, the backing, and the quorum at the bridge's list_nonce.
            let action = governance::register_bridged_action(&state, chain_id, &name, &symbol, salt, chain, token, decimals, pq_signatures)?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::default_registration_fee(
                    gas::fee_floor(&action),
                    state.registration_fee.context("the node serves no registration_fee: pass --fee")?,
                )?,
            };
            eprintln!("registering {symbol} ({name}): fee {} RAND", format_amount(fee));
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridged-token registration");
            let id = randprotocol_core::ledger::tokens::bridged_asset_id(&name, &symbol, &salt);
            println!("registered {symbol} ({name}), asset id {id}, at list_nonce {}", state.list_nonce);
        }
        Cmd::Token(TokenCmd::ListBacking { asset, chain, token, decimals, pq, fee, no_wait, cuda }) => {
            let token = randprotocol_client::hex32(&token).context("--token must be 32 bytes of hex")?;
            let chain_id = rpc.chain_id().await?;
            // BIND-1: the message the file is checked against is this chain's — genesis-bound off
            // the chains cut before `binding_domain`, by chain id, never by the node's claim.
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?.bound_to(rpc.binding_domain(chain_id).await?);
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            let action = governance::list_backing_action(&state, chain_id, asset, chain, token, decimals, pq_signatures)?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "backing listing");
            println!("listed chain {chain} token {} under asset {asset}, at list_nonce {}", hex::encode(token), state.list_nonce);
        }
        Cmd::Token(TokenCmd::Create { name, symbol, decimals, salt, fixed_supply, authority_key_out, initial, to, program, fee, no_wait, cuda }) => {
            // Every cheap refusal — the flag combination — before any key file, network read or
            // proof.
            let program = program.as_deref().map(|p| Hash::from_hex(p).context("--program: invalid program id")).transpose()?;
            if program.is_some() {
                if fixed_supply.is_some() || authority_key_out.is_some() || initial.is_some() || to.is_some() {
                    anyhow::bail!("--program is the token's whole authority: no --fixed-supply, --authority-key-out, --initial or --to beside it");
                }
            } else if fixed_supply.is_some() == authority_key_out.is_some() {
                anyhow::bail!("pass exactly one of --fixed-supply, --authority-key-out or --program");
            }
            let (authority_keypair, initial_amount) = if program.is_some() {
                (None, None)
            } else if let Some(supply) = fixed_supply {
                if initial.is_some() {
                    anyhow::bail!("--fixed-supply is the whole initial supply; do not also pass --initial");
                }
                if supply == 0 {
                    anyhow::bail!("a fixed supply of zero mints nothing");
                }
                if to.is_none() {
                    anyhow::bail!("--fixed-supply needs --to (the initial mint's recipient)");
                }
                (None, Some(supply))
            } else {
                if initial.is_some() != to.is_some() {
                    anyhow::bail!("--initial and --to must be given together");
                }
                if initial == Some(0) {
                    anyhow::bail!("an initial mint of zero mints nothing");
                }
                (Some(Keypair::generate()), initial)
            };
            // `wallet::create_token` writes this branch's fresh key to `<out>.pending` only after
            // `build_register_token`'s own checks pass, right before the one call that can refuse
            // the registration — so a stale `.pending` from an earlier crashed run, or an
            // already-taken target, is worth refusing here, before any network read or proof,
            // rather than inside that write (review round 1).
            if let Some(out) = &authority_key_out {
                if out.exists() {
                    anyhow::bail!("{} already exists; refusing to overwrite", out.display());
                }
                let pending = wallet::pending_authority_key_path(out);
                if pending.exists() {
                    anyhow::bail!(
                        "{} already exists (an earlier `token create` may have crashed right after writing it); \
                         move or remove it before retrying",
                        pending.display()
                    );
                }
            }
            let recipient = to.as_deref().map(parse_address).transpose()?;
            let salt = match salt {
                Some(s) => randprotocol_client::hex32(&s).context("--salt must be 32 bytes of hex")?,
                None => random_salt(),
            };
            let fee = fee.map(|f| parse_amount(&f)).transpose()?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let authority = authority_keypair.as_ref().map(|kp| (kp, authority_key_out.as_deref().expect("checked above")));
            let result = wallet::create_token(
                &rpc,
                &w,
                &mut store,
                &name,
                &symbol,
                decimals,
                authority,
                program,
                initial_amount.map(|amount| (amount, recipient.clone().expect("checked above"))),
                salt,
                fee,
                profile,
                &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?,
                chain_id,
                !no_wait,
            )
            .await;
            store.save(&path)?;
            let result = match result {
                Ok(r) => r,
                Err(e) => {
                    // A refused send now carries its reply inside `SubmitRefused` (node I1), so
                    // the lost-race hint reads either label — and a *later* call's `RpcError`
                    // can never be an `IndexMismatch` anyway.
                    let reply = e
                        .downcast_ref::<randprotocol_client::SubmitRefused>()
                        .map(|s| &s.0)
                        .or_else(|| e.downcast_ref::<randprotocol_client::RpcError>());
                    if let Some(rpc_err) = reply {
                        if let Some((expected, got)) = parse_index_mismatch(&rpc_err.message) {
                            eprintln!("another token took index {got} first — re-run to register at {expected}");
                        }
                    }
                    return Err(e);
                }
            };
            report(&result.submission, "token registration");
            println!("index {}, id {} ({})", result.index, result.id.to_hex(), randprotocol_core::token_id::encode(&result.id));
            if !no_wait {
                let committed = rpc.call("rand_getTransaction", serde_json::json!([result.submission.hash.to_hex()])).await?;
                println!("committed at height {}", committed["height"]);
            }
        }
        Cmd::Token(TokenCmd::Mint { asset, to, amount, authority_key, fee, no_wait, cuda }) => {
            // One whole-listing read serves both the index and the row `build_token_mint` needs
            // (`mint_nonce`, id, authority) — never a second one (review round 1).
            let row = wallet::find_token_row(&rpc, &asset).await?;
            let asset = u32::try_from(row["index"].as_u64().context("a token row without its index")?)
                .context("a token row whose index is not a u32")?;
            let recipient = parse_address(&to)?;
            let amount_text = amount;
            let amount = wallet::parse_row_amount(&row, asset, &amount_text)?;
            let authority = wallet::load_authority_key(&authority_key)?;
            let chain_id = rpc.chain_id().await?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            // Refused up front (not the token's authority, or not Key-authorised at all) inside
            // `build_token_mint`, before any RAND is touched.
            // BIND-1: the authority signs this chain's message — the store is scanned first, so
            // the genesis hash in it is the one the fee bundle's binding will carry.
            let domain = wallet::binding_domain(&rpc, &w, &mut store, chain_id).await?;
            let action = wallet::build_token_mint(&rpc, &w, &domain, chain_id, asset, &row, &recipient, amount, &authority).await?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_token_mint(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait).await;
            store.save(&path)?;
            report(&s?, "token mint");
            println!("minted {amount_text} ({amount} units) of asset {asset} to {to}");
        }
        Cmd::Token(TokenCmd::SetAuthority { asset, authority_key, new_key, renounce, fee, no_wait, cuda }) => {
            if renounce == new_key.is_some() {
                anyhow::bail!("pass exactly one of --new-key or --renounce");
            }
            // One whole-listing read, reused for the index and the row (review round 1).
            let row = wallet::find_token_row(&rpc, &asset).await?;
            let asset = u32::try_from(row["index"].as_u64().context("a token row without its index")?)
                .context("a token row whose index is not a u32")?;
            let authority = wallet::load_authority_key(&authority_key)?;
            // Only the successor's public key is ever read — never its seed, which this command
            // has no reason to hold (review round 1).
            let new = match &new_key {
                Some(path) => Some(wallet::load_authority_public_key(path)?),
                None => None,
            };
            let chain_id = rpc.chain_id().await?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            // BIND-1, as for a mint: scan, then sign this chain's message.
            let domain = wallet::binding_domain(&rpc, &w, &mut store, chain_id).await?;
            let action = wallet::build_token_set_authority(&domain, chain_id, asset, &row, &authority, new.clone())?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s =
                wallet::submit_token_set_authority(&rpc, &w, &mut store, action, fee, profile, &proving_for(cli.prover, cuda, &cli.key, &cli.max_prover_fee)?, chain_id, !no_wait)
                    .await;
            store.save(&path)?;
            report(&s?, "set token authority");
            match new {
                Some(pk) => println!("asset {asset}'s mint authority is now {}", pk.to_hex()),
                None => println!("asset {asset}'s mint authority is renounced for good"),
            }
        }
        Cmd::Token(TokenCmd::Info { token }) => {
            let row = wallet::find_token_row(&rpc, &token).await?;
            println!("{}", pretty(&row));
        }
        Cmd::Token(TokenCmd::List { from, limit }) => {
            let reply = rpc.call("rand_getTokens", serde_json::json!([from, limit])).await?;
            println!("{}", pretty(&reply));
        }
        Cmd::BridgePause { sig, no_wait } => {
            // No key file: a pause must work from a machine holding no spend key and no RAND.
            let chain_id = rpc.chain_id().await?;
            // BIND-1: the message the file is checked against is this chain's — genesis-bound off
            // the chains cut before `binding_domain`, by chain id, never by the node's claim.
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?.bound_to(rpc.binding_domain(chain_id).await?);
            let signature = governance::parse_pause_signature(&read_text_arg(&sig)?)?;
            let action = governance::pause_action(&state, chain_id, signature)?;
            let hash = governance::submit_bundle_less(&rpc, chain_id, action, !no_wait).await?;
            if no_wait {
                println!("submitted the pause at pause_nonce {} as {hash}", state.pause_nonce);
            } else {
                let after = rpc.bridge_state().await?;
                println!("paused: bridge minting is off (tx {hash}); mint_paused {}, pause_nonce {}", after["mint_paused"], after["pause_nonce"]);
            }
        }
        Cmd::BridgeUnpause { pq, no_wait } => {
            let chain_id = rpc.chain_id().await?;
            // BIND-1: the message the file is checked against is this chain's — genesis-bound off
            // the chains cut before `binding_domain`, by chain id, never by the node's claim.
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?.bound_to(rpc.binding_domain(chain_id).await?);
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            let action = governance::unpause_action(&state, chain_id, pq_signatures)?;
            let hash = governance::submit_bundle_less(&rpc, chain_id, action, !no_wait).await?;
            if no_wait {
                println!("submitted the unpause at pause_nonce {} as {hash}", state.pause_nonce);
            } else {
                let after = rpc.bridge_state().await?;
                println!("unpaused: bridge minting is on (tx {hash}); mint_paused {}, pause_nonce {}", after["mint_paused"], after["pause_nonce"]);
            }
        }
        Cmd::Bridge => println!("{}", pretty(&rpc.bridge_state().await?)),
        Cmd::BridgeMessage { sequence } => match rpc.bridge_burn(sequence).await? {
            Some(v) => println!("{}", pretty(&v)),
            None => println!("no burn with sequence {sequence}"),
        },
        Cmd::Receipt { tx } => {
            let h = Hash::from_hex(&tx).context("invalid hash")?;
            match rpc.receipt(&h).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("no receipt (not a call, or not yet committed)"),
            }
        }
        Cmd::Fee { kind, n, public_words, bytes, keccak_log_height, sha256_log_height, gas } => {
            if gas.is_some() && kind != "call" {
                anyhow::bail!("--gas is for `fee call`");
            }
            if public_words.is_some() && kind != "deploy" {
                anyhow::bail!("--public-words is for `fee deploy`");
            }
            if bytes.is_some() && kind != "call" {
                anyhow::bail!("--bytes is for `fee call`");
            }
            if keccak_log_height.is_some() && kind != "call" {
                anyhow::bail!("--keccak-log-height is for `fee call`");
            }
            if sha256_log_height.is_some() && kind != "call" {
                anyhow::bail!("--sha256-log-height is for `fee call`");
            }
            // The optional fields are sent only when given, so an older node is asked exactly
            // what it always was.
            let spec = match (kind.as_str(), n) {
                ("bundle", _) => serde_json::json!({ "kind": "bundle" }),
                ("deploy", Some(words)) => match public_words {
                    Some(m) => serde_json::json!({ "kind": "deploy", "words": words, "public_words": m }),
                    None => serde_json::json!({ "kind": "deploy", "words": words }),
                },
                ("call", Some(tier)) => {
                    let mut spec = serde_json::json!({ "kind": "call", "tier": tier });
                    let obj = spec.as_object_mut().expect("just built as an object");
                    if let Some(b) = bytes {
                        obj.insert("bytes".to_string(), serde_json::json!(b));
                    }
                    if let Some(k) = keccak_log_height {
                        obj.insert("keccak_log_height".to_string(), serde_json::json!(k));
                    }
                    if let Some(s) = sha256_log_height {
                        obj.insert("sha256_log_height".to_string(), serde_json::json!(s));
                    }
                    // Spec §3.3, §9: a chain with a gas section prices the declared limit and its
                    // node refuses an estimate without one (-32602); without `--gas` the wallet
                    // sends the header's ceiling — what `rand call --gas-limit max` declares.
                    let gas = match gas {
                        Some(g) => Some(g),
                        None => fee_call_default_gas(
                            rpc.limits().await?.is_some_and(|l| l.gas_circuit),
                            tier,
                            keccak_log_height,
                            sha256_log_height,
                        ),
                    };
                    if let Some(g) = gas {
                        obj.insert("gas".to_string(), serde_json::json!(g));
                    }
                    spec
                }
                ("deploy", None) => anyhow::bail!("`fee deploy` needs a word count"),
                ("call", None) => anyhow::bail!("`fee call` needs a tier"),
                (other, _) => anyhow::bail!("unknown fee kind {other}; expected bundle, deploy or call"),
            };
            println!("{} RAND", format_amount(rpc.estimate_fee(spec).await?));
        }
        Cmd::Tx { hash } => {
            let h = Hash::from_hex(&hash).context("invalid hash")?;
            let v = rpc.call("rand_getTransaction", serde_json::json!([h.to_hex()])).await?;
            if v.is_null() {
                println!("not found (not yet committed, or unknown)");
            } else {
                println!("{}", pretty(&v));
            }
        }
        Cmd::Block { id } => {
            let v = match id.parse::<u64>() {
                Ok(h) => rpc.block_by_height(h).await?,
                Err(_) => rpc.block_by_hash(&Hash::from_hex(&id).context("block id must be a height or a hash")?).await?,
            };
            println!("{}", pretty(&v));
        }
        Cmd::Head => println!("{}", pretty(&rpc.head().await?)),
        Cmd::Status => println!("{}", pretty(&rpc.status().await?)),
        Cmd::Peers => println!("{}", pretty(&rpc.peers().await?)),
        Cmd::Validators => println!("{}", pretty(&rpc.validators().await?)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section_limits() -> randprotocol_client::ChainLimits {
        randprotocol_client::ChainLimits {
            max_program_words: 4096,
            max_proof_bytes: 2 << 20,
            max_block_bytes: 4 << 20,
            max_call_envelope_bytes: 18_432,
            max_program_public_words: 64,
            envelope_bytes: None,
            hardening_v6: false,
            gas_price: Some(100),
            byte_price: Some(800),
            gas_circuit: true,
            bundle_gas_limit: Some(gas::gas_max(14, 0, 0)),
            adjust_bps: None,
            proof_window_blocks: None,
            program_state: None,
        }
    }

    /// B5 review ruling (spec §9): `rand fee call <tier>` on a section chain without `--gas`
    /// prices the header's ceiling instead of refusing; off a section nothing is sent.
    #[test]
    fn fee_call_without_gas_defaults_to_the_headers_ceiling_under_a_section() {
        assert_eq!(fee_call_default_gas(true, 12, None, None), Some(gas::gas_max(12, 0, 0)));
        assert_eq!(fee_call_default_gas(true, 14, None, None), Some(20_479));
        // Heights given describe a hashing header: its ceiling, not the hash-free one.
        assert_eq!(fee_call_default_gas(true, 14, Some(12), Some(13)), Some(gas::gas_max(14, 12, 13)));
        // A tier past u8 clamps like the header rule does (gas_max clamps to 20).
        assert_eq!(fee_call_default_gas(true, 1_000, None, None), Some(gas::gas_max(20, 0, 0)));
        assert_eq!(fee_call_default_gas(false, 12, None, None), None, "no section: the node prices the header");
    }

    /// B5 review ruling: on a non-CPU backend (`--cuda`) the prover declares only the header's
    /// ceiling, so the default under a section is `None` (the ceiling), not the bucket, and an
    /// explicit limit is refused naming `--gas-limit max`.
    #[test]
    fn a_non_cpu_backend_declares_the_ceiling_and_refuses_an_explicit_limit() {
        let run = executor::CallDryRun { gas: 700, tier: 10, keccak_log_height: 0, sha256_log_height: 0 };
        let l = section_limits();
        let ceiling = gas::gas_max(10, 0, 0);
        assert_eq!(resolve_gas_limit(GasArg::Default, &run, 10, Some(&l), true).unwrap(), (Some(768), 768), "CPU: the bucket");
        assert_eq!(resolve_gas_limit(GasArg::Default, &run, 10, Some(&l), false).unwrap(), (None, ceiling), "GPU: the ceiling");
        assert_eq!(resolve_gas_limit(GasArg::Max, &run, 10, Some(&l), false).unwrap(), (None, ceiling));
        let e = resolve_gas_limit(GasArg::Exactly(800), &run, 10, Some(&l), false).unwrap_err().to_string();
        assert!(e.contains("--gas-limit max"), "{e}");
        assert_eq!(resolve_gas_limit(GasArg::Exactly(800), &run, 10, Some(&l), true).unwrap(), (Some(800), 800));
    }

    /// The four bridge-governance command lines parse under the names agreed with the bridge
    /// session (`docs/mainnet-launch.md` §5 in the bridge repo).
    #[test]
    fn the_bridge_governance_commands_parse_as_the_launch_doc_writes_them() {
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        let salt = "27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60";
        let usdt = "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7";
        let Ok(Cmd::Token(TokenCmd::RegisterBridged { name, symbol, chain, decimals, pq, .. })) = parse(&[
            "token", "register-bridged", "--name", "Shielded USD", "--symbol", "zUSD", "--salt", salt, "--chain", "2", "--token", usdt,
            "--decimals", "6", "--pq", "@zusd-0-register.json",
        ]) else {
            panic!("register-bridged parses")
        };
        assert_eq!((name.as_str(), symbol.as_str(), chain, decimals, pq.as_str()), ("Shielded USD", "zUSD", 2, 6, "@zusd-0-register.json"));
        let Ok(Cmd::Token(TokenCmd::ListBacking { asset, chain, decimals, .. })) = parse(&[
            "token", "list-backing", "--asset", "1", "--chain", "3", "--token", usdt, "--decimals", "18", "--pq", "@zusd-2.json",
        ]) else {
            panic!("list-backing parses")
        };
        assert_eq!((asset, chain, decimals), (1, 3, 18));
        assert!(matches!(parse(&["bridge-pause", "--sig", "@pause.sig"]), Ok(Cmd::BridgePause { .. })));
        assert!(matches!(parse(&["bridge-unpause", "--pq", "@unpause.json", "--no-wait"]), Ok(Cmd::BridgeUnpause { no_wait: true, .. })));
    }

    /// RPL-2's three `rand program` commands and `rand token create --program` parse with their
    /// documented flags, and a transition file — the interface another tool emits — is read
    /// field for field: every field optional, amounts in units, `to` defaulting to this wallet.
    #[test]
    fn the_program_state_commands_parse_and_the_transition_file_is_read_as_documented() {
        use randprotocol_core::ledger::program_state::Inflow;
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        let id = "ab".repeat(32);
        let Ok(Cmd::Program(ProgramCmd::Invoke { program, transition, inputs, inputs_file, fee, no_wait, .. })) = parse(&[
            "program", "invoke", &id, "--transition", "t.json", "--input", "3", "--input", "4", "--inputs-file", "in.json", "--fee", "0.5", "--no-wait",
        ]) else {
            panic!("invoke parses")
        };
        assert_eq!((program.as_str(), transition.to_str(), inputs, inputs_file.as_deref().and_then(|p| p.to_str()), fee.as_deref(), no_wait), (id.as_str(), Some("t.json"), vec![3, 4], Some("in.json"), Some("0.5"), true));
        assert!(matches!(parse(&["program", "state", &id]), Ok(Cmd::Program(ProgramCmd::State { cell: None, .. }))));
        assert!(matches!(parse(&["program", "state", &id, "--cell", "00"]), Ok(Cmd::Program(ProgramCmd::State { cell: Some(_), .. }))));
        assert!(matches!(parse(&["program", "vault", &id]), Ok(Cmd::Program(ProgramCmd::Vault { .. }))));
        assert!(matches!(parse(&["program", "build", "--guest", "rpl2_counter"]), Ok(Cmd::Program(ProgramCmd::Build { .. }))));
        assert_eq!(build_guest("rpl2_counter", &[]).unwrap().words, guests::rpl2_counter().words);
        let Ok(Cmd::Token(TokenCmd::Create { program, fixed_supply, authority_key_out, .. })) =
            parse(&["token", "create", "--name", "Pool Share", "--symbol", "LP", "--decimals", "6", "--program", &id])
        else {
            panic!("token create --program parses")
        };
        assert_eq!((program.as_deref(), fixed_supply, authority_key_out), (Some(id.as_str()), None, None));

        let me = Wallet::generate();
        let you = Wallet::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.json");
        let key = format!("01{}", "00".repeat(31));
        let file = serde_json::json!({
            "reads": [{ "key": key, "value": "00".repeat(32) }],
            "writes": [{ "key": key, "value": format!("0x2a{}", "00".repeat(31)) }],
            "deposit": { "rand": "1000", "asset": 2, "amount": "300", "kind": "deposit" },
            "pays": [{ "asset": 0, "amount": "600", "to": you.address.to_string() }],
            "mints": [{ "asset": 3, "amount": "40" }],
        });
        std::fs::write(&path, file.to_string()).unwrap();
        let pid = Hash([0xab; 32]);
        let plan = read_transition_file(&path, pid, &me.address).unwrap();
        assert_eq!((plan.program, plan.reads[0].key, plan.reads[0].value, plan.writes[0].value[0]), (pid, [1, 0, 0, 0, 0, 0, 0, 0], [0; 8], 42));
        assert_eq!((plan.burn_r, plan.burn_asset, plan.burn_a, plan.inflow), (1000, 2, 300, Inflow::Deposit));
        assert_eq!((plan.pays[0].asset, plan.pays[0].amount, &plan.pays[0].to), (0, 600, &you.address));
        assert_eq!((plan.mints[0].asset, plan.mints[0].amount, &plan.mints[0].to), (3, 40, &me.address), "`to` defaults to this wallet");
        assert_eq!(plan.created_cells, 0, "counted against the chain later");
        // Every field optional.
        std::fs::write(&path, "{}").unwrap();
        let empty = read_transition_file(&path, pid, &me.address).unwrap();
        assert!(empty.reads.is_empty() && empty.writes.is_empty() && empty.pays.is_empty() && empty.mints.is_empty());
        assert_eq!((empty.burn_r, empty.burn_asset, empty.burn_a, empty.inflow), (0, 0, 0, Inflow::None));
        // The cheap refusals: an inflow word without a burn, a burn without one, RAND as a token,
        // a stray key, a malformed word.
        for (bad, why) in [
            (r#"{"deposit": {"kind": "burn"}}"#, "kind is `none` exactly when"),
            (r#"{"deposit": {"asset": 2, "amount": "5"}}"#, "kind is `none` exactly when"),
            (r#"{"deposit": {"asset": 0, "amount": "5", "kind": "deposit"}}"#, "deposit.asset 0 is RAND"),
            (r#"{"deposit": {"kind": "melt"}}"#, "must be none, deposit or burn"),
            (r#"{"read": []}"#, "not a transition file"),
            (r#"{"writes": [{"key": "01", "value": "02"}]}"#, "not 64 hex"),
            (r#"{"pays": [{"amount": "1.5"}]}"#, "decimal amount in units"),
        ] {
            std::fs::write(&path, bad).unwrap();
            let e = format!("{:#}", read_transition_file(&path, pid, &me.address).unwrap_err());
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    /// `rand sync` scans from where the store left off; `--rescan` starts the store over first
    /// (WAL-3).
    #[test]
    fn sync_takes_rescan() {
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        assert!(matches!(parse(&["sync"]), Ok(Cmd::Sync { rescan: false })));
        assert!(matches!(parse(&["sync", "--rescan"]), Ok(Cmd::Sync { rescan: true })));
    }

    /// The five `rand token` commands (T8b): `create` (both authority branches), `mint`,
    /// `set-authority` (both of `--new-key`/`--renounce`), `info` and `list`.
    #[test]
    fn the_token_standard_commands_parse_with_their_documented_flags() {
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        let to = "rand1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

        let Ok(Cmd::Token(TokenCmd::Create { name, symbol, decimals, fixed_supply, to: to_arg, .. })) =
            parse(&["token", "create", "--name", "Fixed Coin", "--symbol", "FIX", "--decimals", "6", "--fixed-supply", "1000000", "--to", to])
        else {
            panic!("create --fixed-supply parses")
        };
        assert_eq!((name.as_str(), symbol.as_str(), decimals, fixed_supply, to_arg.as_deref()), ("Fixed Coin", "FIX", 6, Some(1_000_000), Some(to)));

        let Ok(Cmd::Token(TokenCmd::Create { authority_key_out, initial, .. })) = parse(&[
            "token", "create", "--name", "Keyed Coin", "--symbol", "KEY", "--decimals", "8",
            "--authority-key-out", "authority.key.json", "--initial", "500", "--to", to,
        ]) else {
            panic!("create --authority-key-out parses")
        };
        assert_eq!((authority_key_out.as_deref(), initial), (Some(Path::new("authority.key.json")), Some(500)));

        // Final review B3: `token mint` and `token burn` read AMOUNT in the token's display
        // units, like `send --asset` — one convention across the CLI.
        let Ok(Cmd::Token(TokenCmd::Mint { asset, to: to_arg, amount, authority_key, .. })) =
            parse(&["token", "mint", "--asset", "rpl1keyed", "--to", to, "--amount", "1.5", "--authority-key", "authority.key.json"])
        else {
            panic!("mint parses")
        };
        assert_eq!((asset.as_str(), to_arg.as_str(), amount.as_str(), authority_key.as_path()), ("rpl1keyed", to, "1.5", Path::new("authority.key.json")));
        let Ok(Cmd::Token(TokenCmd::Burn { asset, amount, .. })) = parse(&["token", "burn", "2", "0.25"]) else {
            panic!("burn parses a display-unit amount")
        };
        assert_eq!((asset.as_str(), amount.as_str()), ("2", "0.25"));

        let Ok(Cmd::Token(TokenCmd::SetAuthority { asset, new_key, renounce, .. })) =
            parse(&["token", "set-authority", "--asset", "2", "--authority-key", "authority.key.json", "--new-key", "successor.key.json"])
        else {
            panic!("set-authority --new-key parses")
        };
        assert_eq!((asset.as_str(), new_key.as_deref(), renounce), ("2", Some(Path::new("successor.key.json")), false));
        assert!(matches!(
            parse(&["token", "set-authority", "--asset", "2", "--authority-key", "authority.key.json", "--renounce"]),
            Ok(Cmd::Token(TokenCmd::SetAuthority { renounce: true, new_key: None, .. }))
        ));

        assert!(matches!(parse(&["token", "info", "2"]), Ok(Cmd::Token(TokenCmd::Info { token })) if token == "2"));
        assert!(matches!(parse(&["token", "list"]), Ok(Cmd::Token(TokenCmd::List { from: 0, limit: 1000 }))));
        assert!(matches!(
            parse(&["token", "list", "--from", "5", "--limit", "10"]),
            Ok(Cmd::Token(TokenCmd::List { from: 5, limit: 10 }))
        ));
    }

    /// `parse_index_mismatch` reads `TokenError::IndexMismatch`'s exact wire text
    /// (`TxError::Token`'s `"token: {0}"` wrapping the ledger's own `Display`) and nothing else,
    /// so `rand token create`'s lost-race hint fires only on that one refusal.
    #[test]
    fn parse_index_mismatch_reads_the_ledgers_own_error_text_and_nothing_else() {
        assert_eq!(parse_index_mismatch("token: wrong token index: expected 3, got 2"), Some((3, 2)));
        assert_eq!(parse_index_mismatch("token: wrong token index: expected 10, got 9"), Some((10, 9)));
        assert_eq!(parse_index_mismatch("token: registration fee 100 is below the minimum 1000000"), None);
        assert_eq!(parse_index_mismatch("wrong mint nonce: expected 1, got 0"), None);
        assert_eq!(parse_index_mismatch(""), None);
    }

    /// `open-call`'s verdict is its exit status. A transcript that is not the preimage of the
    /// receipt's `H_IN` is a lie its holder can show to anyone, and one whose words do not
    /// reproduce the receipt's outputs is not what produced that receipt — either way the command
    /// has to fail, or a script checking a disclosure reads a printed warning beside a zero exit as
    /// a yes.
    #[test]
    fn a_transcript_that_is_not_the_one_behind_the_receipt_fails() {
        let outputs = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let receipt = json!(outputs);

        // Faithful and reproducing: the only case that passes.
        transcript_verdict(true, &outputs, &receipt).expect("a faithful, consistent transcript opens");

        // Unfaithful, even with matching outputs — H_IN is the commitment, and it is checked first.
        let e = transcript_verdict(false, &outputs, &receipt).unwrap_err().to_string();
        assert!(e.contains("NOT FAITHFUL"), "{e}");

        // Faithful, but the program run on these words produces something else.
        let mut other = outputs;
        other[7] = 9;
        let e = transcript_verdict(true, &other, &receipt).unwrap_err().to_string();
        assert!(e.contains("OUTPUT MISMATCH") && e.contains("[1, 2, 3, 4, 5, 6, 7, 9]"), "{e}");
        // And a length disagreement is a mismatch too, not a silent prefix compare.
        assert!(transcript_verdict(true, &outputs[..7], &receipt).is_err());

        // A receipt that is not shaped like outputs at all fails rather than comparing to nothing.
        for bad in [json!(null), json!("nope"), json!([1, "two"]), json!([1, -2]), json!([1, 4294967296u64])] {
            let e = transcript_verdict(true, &outputs, &bad).unwrap_err().to_string();
            assert!(e.contains("not eight numbers"), "{bad}: {e}");
        }
    }

    /// The two-spellings-of-`hc` bug (final review, item 1): `rpc_hc_hex` is what `rand program
    /// deploy` now prints before proving, and it must equal what a node's `check_program` — the
    /// function `rand_getProgram`'s `code_hash` field is built from — computes for the very same
    /// program. Exercised against the vendored `evm.bin`, the one image `rand program deploy`
    /// actually ships in this repo, so this is not just `rpc_hc_hex` checked against its own
    /// formula: `check_program` is the real admission path (`ConfidentialExecutor`), run here the
    /// same way a node would run it at deploy time.
    #[test]
    fn the_wallets_hc_string_matches_what_the_rpc_would_return_for_the_same_program() {
        use randprotocol_core::confidential::ConfidentialExecutor;

        let p = guests::compiled::evm();
        let node_code_hash = executor::ZkExecutor::new(FriProfile::Test)
            .check_program(p.base_pc, &p.words)
            .expect("evm.bin is a committed, known-good build");

        assert_eq!(rpc_hc_hex(&p), hex::encode(&node_code_hash));
        // And it must differ from `Program::code_hash()`'s big-endian spelling of the same eight
        // words — that mismatch is exactly the bug this fixes.
        assert_ne!(rpc_hc_hex(&p), p.code_hash());
    }

    /// The hostile memos (and contact names) every display surface is tested with (final
    /// review A): padding to push a fake line into view, terminal escapes, line breaks, bidi and
    /// zero-width characters.
    fn hostile() -> Vec<String> {
        let tail = "to alice · fingerprint AAAA-AAAA-AAAA-AAAA · 1 RAND";
        vec![
            format!("x{}{tail}", "\u{3000}".repeat(120)),
            format!("x{}{tail}", " ".repeat(400)),
            format!("\r\x1b[2K{tail}"),
            format!("\n\nto alice\u{2028}{tail}\u{2029}"),
            format!("\u{202E}DNAR 1\u{202C} \u{2066}{tail}\u{2069}\u{200E}\u{200F}\u{061C}"),
            "a\u{200B}\u{200C}\u{200D}b\u{2060}\u{2064}c\u{FEFF}d\u{00AD}e".to_string(),
        ]
    }

    /// `rand send`'s confirmation: the recipient line carries no memo text at all — the memo is
    /// its own `memo: "…"` line after it, itself cut to [`MEMO_CONFIRM_COLS`] display columns —
    /// and a hostile memo or contact name shows with no line break, no control or format
    /// character and no run of spaces.
    #[test]
    fn the_confirmation_puts_a_sanitised_memo_on_its_own_line() {
        let fp = "AAAA-BBBB-CCCC-DDDD";
        assert_eq!(confirmation(Some("alice"), fp, "1.5 RAND", ""), "to alice · fingerprint AAAA-BBBB-CCCC-DDDD · 1.5 RAND");
        assert_eq!(confirmation(None, fp, "1.5 RAND", "hi"), "to fingerprint AAAA-BBBB-CCCC-DDDD · 1.5 RAND\nmemo: \"hi\"");
        // A saved name may end in a space (names are never trimmed): it and the separator collapse.
        assert_eq!(confirmation(Some("alice "), fp, "1.5 RAND", ""), "to alice · fingerprint AAAA-BBBB-CCCC-DDDD · 1.5 RAND");
        for m in hostile() {
            let shown = confirmation(Some("alice"), fp, "1.5 RAND", &m);
            let lines: Vec<&str> = shown.split('\n').collect();
            assert_eq!(lines.len(), 2, "{shown:?}");
            assert_eq!(lines[0], "to alice · fingerprint AAAA-BBBB-CCCC-DDDD · 1.5 RAND");
            assert!(lines[1].starts_with("memo: \""), "{shown:?}");
            // A cut memo's line ends in the closing quote alone; a memo long enough to be cut
            // (some of the hostile cases are, once their format characters are counted) ends in
            // the `(N bytes)` suffix instead.
            assert!(lines[1].ends_with('"') || lines[1].ends_with(" bytes)"), "{shown:?}");
            assert!(memo_display::is_displayable(lines[1]), "{shown:?}");
            // A contact name is user-entered too, and reaches the same line.
            let shown = confirmation(Some(&m), fp, "1.5 RAND", "");
            assert!(!shown.contains('\n') && memo_display::is_displayable(&shown), "{shown:?}");
        }
    }

    /// The reproduction from the reviewer's report: a memo built to draw a forged `to alice ·
    /// fingerprint …` line on its own row — one padded with the invisible-looking Braille blank
    /// U+2800 (not a space separator, so [`memo_display::sanitize`] does not touch it), one
    /// padded with plain visible ASCII dashes, both `sanitize` cannot shorten, and (re-review fix
    /// round 2, finding 1) memos padded with wide characters — CJK ideographs and an emoji, each
    /// one `char` but two display columns, so a *character*-counting cut lets far more of the
    /// padding through than a column budget allows — is cut by the confirmation line's
    /// [`MEMO_CONFIRM_COLS`] **display-column** limit before the forged text is ever reached. A
    /// memo at the chain's own maximum, [`randprotocol_core::notes::MEMO_TEXT_MAX_BYTES`] (510)
    /// bytes, is the longest byte-count suffix this ever prints (three digits): the memo line
    /// still never passes 80 display columns, measured by [`memo_display::display_width`] (not
    /// `chars().count()`, which the wide-character cases would pass wrongly).
    #[test]
    fn a_memo_line_never_forges_a_recipient_line_and_never_passes_eighty_columns() {
        let fp = "AAAA-BBBB-CCCC-DDDD";
        let tail = "to alice · fingerprint AAAA-AAAA-AAAA-AAAA · 1 RAND";
        let short_tail = "to alice · 1000 RAND";
        let u2800_padded = format!("x{}{tail}", "\u{2800}".repeat(72));
        let dash_padded = format!("x{}{tail}", "-".repeat(72));
        let at_the_chains_own_max = "y".repeat(randprotocol_core::notes::MEMO_TEXT_MAX_BYTES);
        assert!(at_the_chains_own_max.len() == randprotocol_core::notes::MEMO_TEXT_MAX_BYTES);
        // The re-review's exact reproduction: 57 characters — comfortably under the old
        // character-counting budget of 60 — but far wider than 60 display columns, since each of
        // the 36 CJK characters is two columns.
        let cjk_short = format!("x{}{short_tail}", "中".repeat(36));
        assert_eq!(cjk_short.chars().count(), 57, "the character-counting bug's premise");
        let cjk_full = format!("x{}{tail}", "中".repeat(36));
        let cjk_all = format!("{}{tail}", "中".repeat(60));
        let emoji_padded = format!("x{}{tail}", "🍜".repeat(36));
        // Re-review fix round 3, finding 1: an emoji modifier sequence (a base emoji plus a
        // Fitzpatrick skin-tone modifier, two code points) priced by unicode_width's string-level
        // `width_cjk` as one glyph, 2 columns — but a per-code-point terminal (xterm, the Linux
        // console, conhost) draws both code points, 4 columns; `display_width` must measure and
        // the cut must act on the per-code-point total (94), not the string-level one (58).
        let thumbs_up_skin_tone = format!("x{}{short_tail}", "\u{1F44D}\u{1F3FB}".repeat(18));
        // Fix round 4: U+3164 HANGUL FILLER is invisible (Lo) and unicode-width prices it 0, so
        // the old per-code-point measure charged it 1 column — but terminals draw it 2 wide. 36 of
        // them measured 58 under the old rule (uncut) and wrapped at column 80 into a forged
        // `to alice · 1000 RAND"` row. Every non-ASCII code point is now charged the upper bound, 2.
        let hangul_filler = format!("x{}{short_tail}", "\u{3164}".repeat(36));
        for m in [u2800_padded, dash_padded, at_the_chains_own_max, cjk_short, cjk_full, cjk_all, emoji_padded, thumbs_up_skin_tone, hangul_filler] {
            let shown = confirmation(Some("alice"), fp, "1.5 RAND", &m);
            let lines: Vec<&str> = shown.split('\n').collect();
            assert_eq!(lines.len(), 2, "{shown:?}");
            let cols = memo_display::display_width(lines[1]);
            assert!(cols <= 80, "{} is {} columns: {shown:?}", lines[1], cols);
            assert!(!lines[1].contains("to alice"), "{shown:?}");
            assert!(!lines[1].contains("fingerprint AAAA-AAAA-AAAA-AAAA"), "{shown:?}");
            assert!(lines[1].ends_with(" bytes)"), "expected a byte-count suffix (this case must be cut): {shown:?}");
        }
        // A plain Hangul syllable, by contrast, is one code point with no modifier to merge:
        // string-level and per-code-point measurement already agreed on it before round 3, and
        // round 4's bound (2 per non-ASCII code point) charges it the same (18 × 2 = 36, + "x" +
        // `short_tail`'s 21 columns = 58, under the 60-column memo budget) — the control case
        // neither fix may regress: still shown whole, not cut, no byte suffix, exactly as before,
        // and still nowhere near 80 columns.
        let hangul = format!("x{}{short_tail}", "각".repeat(18));
        let shown = confirmation(Some("alice"), fp, "1.5 RAND", &hangul);
        let lines: Vec<&str> = shown.split('\n').collect();
        assert_eq!(lines.len(), 2, "{shown:?}");
        let cols = memo_display::display_width(lines[1]);
        assert!(cols <= 80, "{} is {} columns: {shown:?}", lines[1], cols);
        assert!(!lines[1].ends_with(" bytes)"), "under budget, so no byte suffix: {shown:?}");
        assert!(lines[1].contains("to alice"), "under budget, so shown whole: {shown:?}");
    }

    /// Reviewer's report: `rand history` printed the memo column ahead of the `to` column, so a
    /// hostile memo sat where a reader would expect the recipient. The header and every row must
    /// name `to` before `memo`.
    #[test]
    fn history_names_the_to_column_before_the_memo_column() {
        let header = history_header();
        let to_pos = header.find("to").expect("header names a to column");
        let memo_pos = header.find("memo").expect("header names a memo column");
        assert!(to_pos < memo_pos, "{header:?}");

        let row = history_row(3, "1.00000000", 42, "alice", "lunch");
        let alice_pos = row.find("alice").expect("row shows the recipient");
        let lunch_pos = row.find("lunch").expect("row shows the memo");
        assert!(alice_pos < lunch_pos, "{row:?}");
    }

    /// `rand notes`/`rand history`/`rand tx-key`'s memo column: sanitised first, then cut to 24
    /// characters, so 400 spaces or 120 ideographic spaces cannot push the real text out and an
    /// escape cannot be split or survive. `--memo` prints the whole memo, sanitised the same way.
    #[test]
    fn the_memo_column_is_sanitised_before_it_is_truncated() {
        assert_eq!(memo_column(&None, false), "-");
        assert_eq!(memo_column(&Some(format!("x{}to alice", " ".repeat(400))), false), "x to alice");
        for m in hostile() {
            for whole in [false, true] {
                let shown = memo_column(&Some(m.clone()), whole);
                assert!(!shown.contains('\n') && memo_display::is_displayable(&shown), "{shown:?}");
                if !whole {
                    assert!(shown.chars().count() <= 24, "{shown:?}");
                }
            }
        }
    }

    fn fresh_address() -> ShieldedAddress {
        randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey::random().viewing_key())
    }

    /// `rand send`'s TO, and `rand contacts add`'s TO, resolve the same way: a bare address
    /// first, a `randpay:` link second (carrying its own `amount`/`asset`/`memo` back for
    /// [`merge_uri`] to reconcile with any flags), and a saved contact's name last. Anything
    /// none of the three is refused.
    #[test]
    fn a_recipient_resolves_as_address_then_link_then_contact() {
        let a = fresh_address();
        let mut c = contacts::Contacts::default();
        c.add("bob", &a).unwrap();
        assert_eq!(resolve_recipient(&a.to_string(), &c).unwrap().0, a);
        let (x, uri, _) = resolve_recipient(&format!("randpay:{a}?amount=2"), &c).unwrap();
        assert_eq!((x, uri.unwrap().amount.as_deref()), (a.clone(), Some("2")));
        let (x, _, name) = resolve_recipient("bob", &c).unwrap();
        assert_eq!((x, name.as_deref()), (a.clone(), Some("bob")));
        assert!(resolve_recipient("carol", &c).is_err());
    }

    /// Final review B2: the confirmation names a saved contact whichever way its address arrived —
    /// typed by name, pasted bare, or inside a `randpay:` link — and names nobody for an address
    /// that is not saved.
    #[test]
    fn a_pasted_address_or_link_of_a_saved_contact_is_named() {
        let (a, stranger) = (fresh_address(), fresh_address());
        let mut c = contacts::Contacts::default();
        c.add("bob", &a).unwrap();
        assert_eq!(resolve_recipient(&a.to_string(), &c).unwrap().2.as_deref(), Some("bob"));
        assert_eq!(resolve_recipient(&format!("randpay:{a}?amount=2"), &c).unwrap().2.as_deref(), Some("bob"));
        assert_eq!(resolve_recipient(&stranger.to_string(), &c).unwrap().2, None);
    }

    /// [`merge_uri`]: a `--flag` and a link's own field agree if both are given, either alone if
    /// only one is, and a differing pair is refused rather than silently preferring one.
    #[test]
    fn a_flag_and_a_link_that_disagree_are_refused() {
        assert_eq!(merge_uri(Some("1".into()), None, "amount").unwrap(), Some("1".into()));
        assert_eq!(merge_uri(None, Some("1".into()), "amount").unwrap(), Some("1".into()));
        assert_eq!(merge_uri(Some("1".into()), Some("1".into()), "amount").unwrap(), Some("1".into()));
        assert!(merge_uri(Some("1".into()), Some("2".into()), "amount").is_err());
    }

    /// [`merge_uri`]'s mismatch error names both values, and a link's memo field is exactly as
    /// hostile as a memo shown anywhere else: a link built with a terminal-clearing escape in its
    /// `memo` field (reviewer's reproduction, `%0D%1B%5B2K` percent-decoded) must not put that
    /// escape on the terminal when the error prints — both sides go through
    /// [`memo_display::truncate`] first.
    #[test]
    fn a_memo_mismatch_error_shows_both_sides_sanitised() {
        let link_memo = "\r\x1b[2Krm -rf ~ # not really, but it could say anything";
        let err = merge_uri(Some("lunch".into()), Some(link_memo.into()), "memo").unwrap_err().to_string();
        assert!(err.contains("--memo lunch"), "{err:?}");
        assert!(err.contains("does not match the link's memo"), "{err:?}");
        assert!(!err.contains('\r') && !err.contains('\x1b'), "{err:?}");
        assert!(memo_display::is_displayable(&err), "{err:?}");
        // A long memo on either side is cut too, so the error line itself cannot run away.
        let long = "z".repeat(400);
        let err = merge_uri(Some(long.clone()), Some("short".into()), "memo").unwrap_err().to_string();
        assert!(err.chars().count() < long.chars().count(), "{err:?}");
    }

    /// Task review, fix round 1: every QR this wallet ever renders is a `randpay:` link, level M
    /// — never a bare address — so `rand contacts show --qr` cannot drift back to encoding the
    /// address text directly the way `rand address --qr` already never does.
    #[test]
    fn contacts_show_qrs_link_is_a_randpay_link_not_a_bare_address() {
        let a = fresh_address();
        let text = pay_link(&a);
        assert!(text.starts_with("randpay:"), "{text}");
        assert_eq!(PaymentUri::parse(&text).unwrap().address, a);
    }
}
