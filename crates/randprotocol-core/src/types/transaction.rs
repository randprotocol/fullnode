//! Transactions: a shielded bundle plus an optional action (design spec §3, §6).

use crate::bridge::{digest as attestation_digest, Attestation};
use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::ledger::program_state::Transition;
use crate::ledger::tokens::MintAuthority;
use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8, BUNDLE_SLOTS};
use crate::program::ProgramId;
use crate::types::actions::{
    AggregatorRegistration, CallEnvelope, InitialMint, Registration, SignedAggregateHeader, SignedHeader,
};
use crate::types::binding::BindingDomain;
use serde::{Deserialize, Serialize};

/// Native token symbol. The whitepaper (Draft 3) calls this RAND; rename here if needed.
pub const TOKEN_SYMBOL: &str = "RAND";
/// Smallest-unit decimals: 1 RAND = 10^9 units.
pub const TOKEN_DECIMALS: u32 = 9;
pub const UNITS_PER_RAND: u64 = 1_000_000_000;
/// Largest amount a single testnet faucet mint may create.
pub const FAUCET_MAX_UNITS: u64 = 100 * UNITS_PER_RAND;

/// Format smallest units as a decimal RAND string ("1.5").
pub fn format_amount(units: u64) -> String {
    let scale = 10u64.pow(TOKEN_DECIMALS);
    let whole = units / scale;
    let frac = units % scale;
    if frac == 0 {
        format!("{whole}")
    } else {
        let s = format!("{frac:0width$}", width = TOKEN_DECIMALS as usize);
        format!("{whole}.{}", s.trim_end_matches('0'))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AmountError {
    #[error("too many decimal places (max {TOKEN_DECIMALS})")]
    TooManyDecimals,
    #[error("not a number")]
    NotANumber,
    #[error("amount overflow")]
    Overflow,
}

/// Parse a decimal RAND string ("1.5", ".25") into smallest units.
pub fn parse_amount(s: &str) -> Result<u64, AmountError> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > TOKEN_DECIMALS as usize {
        return Err(AmountError::TooManyDecimals);
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::NotANumber);
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| AmountError::NotANumber)? };
    let frac_units: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<width$}", width = TOKEN_DECIMALS as usize).parse().map_err(|_| AmountError::NotANumber)?
    };
    whole
        .checked_mul(10u64.pow(TOKEN_DECIMALS))
        .and_then(|w| w.checked_add(frac_units))
        .ok_or(AmountError::Overflow)
}

/// What a transaction does besides moving shielded value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// A plain shielded transfer: the bundle is the whole transaction.
    None,
    /// Testnet faucet deposit (spec §6): a note of public `amount` created by a validator.
    /// Carried by a bundle-less transaction; `signature` is `minter`'s Dilithium2 signature over
    /// [`Transaction::mint_signing_hash`].
    ///
    /// The note's opening rides in the clear — owner `pk`, `time` and blinding `r`, with no
    /// sender and the native asset — and admission refuses a `cm` that is not the commitment of
    /// exactly that note at exactly `amount` (`TxError::MintCommitmentMismatch`), as a withdraw's
    /// and an aggregator payout's notes are derived. Before that check a validator could declare
    /// a small `amount` and append a `cm` opening to any value (audit v3, POOL-1). `time` is held
    /// to the bundle window, like a withdraw's.
    Mint {
        cm: Word8,
        pk: Word8,
        time: u32,
        r: Word8,
        envelope: Envelope,
        amount: u64,
        minter: PublicKey,
        signature: Signature,
    },
    /// Put a zkVM program on chain. Content addressed; see `program::program_id_with_public`.
    /// `public` is the program's public input, fixed at deploy (the call limits, spec §5): every
    /// call's proof commits to exactly these words. Empty for a program without one, which keeps
    /// the program's id what it was before public inputs existed.
    Deploy { base_pc: u32, words: Vec<u32>, public: Vec<u32> },
    /// A confidential call: a STARK proof that `program` ran on private inputs and published
    /// the eight public outputs carried in the proof. `input_envelope` is the optional
    /// encrypted transcript of those private inputs (spec §6.1); the chain checks only its size.
    Call {
        program: ProgramId,
        #[serde(with = "crate::crypto::wire_bytes")]
        proof: Vec<u8>,
        input_envelope: Option<CallEnvelope>,
    },
    /// Phase S2: add `amount` (burned by the bundle) to `validator`'s stake. `registration` is
    /// present exactly when the validator is not yet in the register.
    Bond { validator: Address, amount: u64, registration: Option<Registration> },
    /// Phase S2: move `amount` of `validator`'s stake into unbonding. Signed over
    /// [`crate::types::actions::unbond_message`]; rides without a bundle and pays no fee.
    Unbond { validator: Address, amount: u64, nonce: u64, signature: Signature },
    /// Phase S2: pay released stake and rewards into a deposit note the ledger computes itself
    /// from `r`, `time` and the register's payout address. Signed over
    /// [`crate::types::actions::withdraw_message`]; rides without a bundle, and pays the bundle
    /// base out of `amount` — the note is worth `amount - gas::BUNDLE_BASE`.
    ///
    /// `time` is the note's time word, and the sealing node chooses it: the envelope is sealed
    /// against the note *before* the transaction is submitted, so the note cannot be bound to
    /// the height that happens to apply it. Admission holds it to the same window a bundle's
    /// `time` gets (spec §7 item 5).
    Withdraw {
        validator: Address,
        amount: u64,
        nonce: u64,
        time: u32,
        r: Word8,
        envelope: Envelope,
        signature: Signature,
    },
    /// Phase S3: a guardian-signed bridge attestation, deposited as a note of the bridged
    /// asset to `recipient` with blinding `r`.
    ///
    /// `r` is not the submitter's choice (F1, from chain 14): admission requires it to be
    /// `bridge_notes::derive_deposit_r(mu)`, `blake3("rand-deposit-r-1" ‖ mu)` over the digest
    /// the guardians signed (`BridgeError::WrongDepositBlinding` otherwise, before any signature
    /// work). It stays on the wire so the transaction is self-describing and a wallet rebuilds the
    /// note from the public fields alone. With it fixed, two submitters of one attestation at one
    /// `time` name one note, and a copier of a pooled attest cannot swap in a note of its own.
    ///
    /// `time` is the deposit note's own `time` word, and it is on the action for the same reason
    /// a bundle carries one: the note's commitment is computed by the chain, so the depositor has
    /// to be able to predict it — and it cannot predict the height its transaction lands at.
    /// Admission holds it to the window a bundle's `time` gets (`Ledger::check_time`), so it is
    /// recent without having to be exact, and the envelope sealed for the recipient names exactly
    /// the note the ledger will append.
    ///
    /// `asset` is the token registry's index for the deposited asset — the word the envelope was
    /// sealed for — and it is on the action for the same reason `time` is: the depositor has to
    /// name the note it sealed against. It is always a fact, never a prediction: a bridged token
    /// is *listed* (at genesis, or by a governance message) before an attestation of it is
    /// admissible, and a listing's index never moves, so nothing can take it from a transaction
    /// while its bundle is being proved. Admission still refuses a mismatch
    /// (`TxError::AttestAssetMismatch`) — a transaction built against another chain's registry, or
    /// against a node that has not seen a listing yet, would otherwise deposit under a word no key
    /// of the recipient's opens. A rotation deposits no note and binds nothing here.
    ///
    /// `pq_signatures` (bridge hardening B3, the last field) is the guardians' Dilithium2
    /// co-signature quorum over `b"rand-bridge-pq-cosign-1" ‖ chain_id ‖ mu`
    /// ([`crate::bridge::pq`]), required on every attest, a rotation's included. It travels beside
    /// the attestation, whose wire format it leaves untouched, and it is inside the transaction
    /// binding — it is not a proof, so [`Action::blanked`] keeps it.
    BridgeAttest {
        #[serde(with = "crate::crypto::wire_bytes")]
        attestation: Vec<u8>,
        recipient: ShieldedAddress,
        r: Word8,
        time: u32,
        asset: u32,
        envelope: Envelope,
        pq_signatures: Vec<crate::bridge::PqSignature>,
    },
    /// Phase S3: burn `amount` of asset `asset` to a destination chain. Single-bundle since the
    /// hidden-asset bundle (spec §3.7): the transaction's one bundle spends the asset notes in
    /// its slots 0–1 and pays the RAND fee from slots 2–3, and it must publish
    /// `burn_asset == asset`, `burn_a == amount` and `burn_r == 0`.
    ///
    /// `token` is the source-chain token address being redeemed, and `(to_chain, token)` must be
    /// one of `asset`'s backings (spec §12): one bridged token is backed by several coins on
    /// several chains — zUSD by USDT and USDC on four of them — so a burn names *which* coin it
    /// wants released, and the outbound message carries that pair. It is bounded by that
    /// backing's own locked amount, not by the token's whole supply
    /// (`TokenError::InsufficientBacking`).
    BridgeBurn {
        asset: u32,
        amount: u64,
        relayer_fee: u64,
        to_chain: u16,
        token: [u8; 32],
        to: [u8; 32],
    },
    /// Block aggregation (spec §2.2): register the sender as an aggregator. Rides a bundle
    /// whose `burn_r` equals the genesis bond — the only aggregation action that carries one.
    RegisterAggregator { registration: AggregatorRegistration },
    /// Block aggregation: stop submitting and start the unbonding window. Bundle-less,
    /// validator-style signed over [`crate::types::actions::aggregator_unbond_message`].
    UnbondAggregator { aggregator: Address, nonce: u64, signature: Signature },
    /// Block aggregation: after the release height, withdraw the bond as a deposit note the
    /// ledger derives (`bond − BUNDLE_BASE`; the base goes to the proposer) — S2's `Withdraw`
    /// verbatim, one register over. Bundle-less; signed over
    /// [`crate::types::actions::aggregator_withdraw_message`].
    WithdrawAggregator { aggregator: Address, nonce: u64, time: u32, r: Word8, envelope: Envelope, signature: Signature },
    /// Block aggregation: the equivocation proof (spec §2.2) — two signed headers by the same
    /// aggregator at the same nonce with different content. Bundle-less, no fee, anyone may
    /// submit it; burns the bond and deletes the entry.
    SlashAggregator { a: Box<SignedAggregateHeader>, b: Box<SignedAggregateHeader> },
    /// Block aggregation (spec §3): one rVM proof covering `covers` bundle transactions of a
    /// finalised window, by a registered aggregator. Bundle-less; the public list is
    /// recomputed, not carried; the nine admission steps of spec §4.
    Aggregate {
        covers: Vec<Hash>,
        #[serde(with = "crate::crypto::wire_bytes")]
        proof: Vec<u8>,
        aggregator: Address,
        nonce: u64,
        time: u32,
        r: Word8,
        envelope: Envelope,
        signature: Signature,
    },
    /// RPL (spec §4): create a token. Permissionless — anyone who pays the bundle base plus the
    /// registry's `registration_fee` gets the next dense index — and content-addressed: the
    /// token's [`AssetId`] is `native_asset_id(name, symbol, decimals, authority, initial, salt)`
    /// — the **whole** `initial`, not just its amount, because this action is unsigned and anyone
    /// can pay for a copy with a fee bundle of their own (see [`InitialMint`]) — so the same
    /// declaration twice is the
    /// same asset and the second is refused, while a copy with the recipient swapped is a
    /// different token that can take nothing from the original.
    ///
    /// `authority` may only be [`MintAuthority::None`] (fixed supply, which then *must* carry an
    /// `initial`) or [`MintAuthority::Key`]: a bridged token is listed by genesis or governance
    /// and `Program` is reserved, so both are `TokenError::AuthorityNotAllowed` here.
    ///
    /// `index` is the registry index the creator sealed `initial`'s envelope for — the note's
    /// `asset` word — and it is on the action for [`Action::BridgeAttest`]'s reason, one step
    /// further along: unlike a listed bridged token's index, this one is *not* yet a fact when
    /// the transaction is built, because another registration can commit while this one's bundle
    /// is being proved. A mismatch with the registry's next index is `TokenError::IndexMismatch`,
    /// checked whether or not there is an `initial`, so a lost race costs a re-proof and never
    /// strands a note nobody can open. It is deliberately not part of the asset id: the identity
    /// is what was declared, not where it landed.
    ///
    /// [`AssetId`]: crate::bridge::AssetId
    /// [`MintAuthority::None`]: crate::ledger::tokens::MintAuthority::None
    /// [`MintAuthority::Key`]: crate::ledger::tokens::MintAuthority::Key
    RegisterToken {
        name: String,
        symbol: String,
        decimals: u8,
        authority: MintAuthority,
        initial: Option<InitialMint>,
        salt: [u8; 32],
        index: u32,
    },
    /// RPL (spec §4): mint `amount` of token `asset` to `recipient`, by its `Key` mint authority.
    ///
    /// The note is the chain's to compute, exactly as a bridge deposit's is
    /// (`ledger::tokens::mint_commitment`), and `signature` is the authority's over
    /// [`crate::types::actions::token_mint_message`] — which carries that very commitment, so the
    /// leaf the ledger appends is the leaf the authority signed for. `nonce` is the token's own
    /// `mint_nonce`, the whole of the replay protection: there are no accounts on this chain.
    ///
    /// `time` is the note's `time` word, chosen by the minter and held to the usual window, for
    /// [`InitialMint`]'s reason.
    TokenMint {
        asset: u32,
        amount: u64,
        recipient: ShieldedAddress,
        r: Word8,
        time: u32,
        envelope: Envelope,
        nonce: u64,
        signature: Signature,
    },
    /// RPL (spec §4): hand token `asset` to another key, or — with `new: None` — retire minting
    /// for good. Signed by the token's **current** `Key` authority over
    /// [`crate::types::actions::set_authority_message`]; any other authority kind is
    /// `TokenError::NotKeyAuthority`, which makes a renunciation final.
    SetAuthority { asset: u32, new: Option<PublicKey>, nonce: u64, signature: Signature },
    /// RPL (spec §4): destroy `amount` of token `asset` held in the pool, lowering its public
    /// `total_supply` by exactly that. Single-bundle (the hidden-asset bundle, spec §3.7): the
    /// transaction's one bundle must publish `burn_asset == asset`, `burn_a == amount` and
    /// `burn_r == 0`. (A *transfer* of any token is a plain [`Action::None`] bundle: the asset
    /// is private, so there is no token-transfer action.)
    ///
    /// Refused for a [`MintAuthority::Bridge`] token (`TokenError::BridgedToken`): a bridged
    /// token's supply moves only with one of its backings, so it leaves through
    /// [`Action::BridgeBurn`], which names the coin being released. Unsigned by design — burning
    /// needs no authority, only the notes, and the bundle's proof is what shows they were held.
    ///
    /// [`MintAuthority::Bridge`]: crate::ledger::tokens::MintAuthority::Bridge
    TokenBurn { asset: u32, amount: u64 },
    /// Bridge hardening B1: pause bridge minting. `signature` is the genesis `bridge.pause_key`'s
    /// Dilithium2 signature over [`crate::bridge::gov::pause_message`]`(chain_id, nonce)`, and
    /// `nonce` must be the bridge's `pause_nonce`. It can only pause: while paused every transfer
    /// `BridgeAttest` is refused, and burns and rotations stay open. Bundle-less and fee-less — a
    /// pause must work from a wallet holding no RAND at all.
    PauseMints { nonce: u64, signature: Signature },
    /// Bridge hardening B1: lift a pause. `pq_signatures` is a PQ guardian quorum (the
    /// co-signature's five rules, [`crate::bridge::pq`]) over
    /// [`crate::bridge::gov::unpause_message`]`(chain_id, nonce)`, `nonce` the bridge's
    /// `pause_nonce`. The pause key alone can never unpause. Bundle-less, like `PauseMints`.
    UnpauseMints { nonce: u64, pq_signatures: Vec<crate::bridge::PqSignature> },
    /// Bridge hardening B4: register a new bridged token after genesis — a `Bridge`-authority
    /// token at the registry's next index, eight decimals on Rand, under the genesis
    /// `mint_cap_per_day`, with one backing `(chain, token)` of `decimals` **source** decimals,
    /// unlocked. Its asset id is `tokens::bridged_asset_id(name, symbol, salt)`, the rule every
    /// bridged token's id follows. `pq_signatures` is a PQ guardian quorum over
    /// [`crate::bridge::gov::register_message`], `nonce` the bridge's `list_nonce`.
    ///
    /// Rides a RAND fee bundle paid by whoever submits it (zUSD's is a faucet-funded deployer),
    /// owing the bundle base plus the registry's `registration_fee`; the quorum, not the payer, is
    /// the authority, and a copy paid by someone else registers the same token.
    RegisterBridgedToken {
        name: String,
        symbol: String,
        salt: [u8; 32],
        chain: u16,
        token: [u8; 32],
        decimals: u8,
        nonce: u64,
        pq_signatures: Vec<crate::bridge::PqSignature>,
    },
    /// Bridge hardening B4: add the backing `(chain, token)` of `decimals` source decimals to the
    /// bridged token at `token_index`, unlocked. A PQ guardian quorum over
    /// [`crate::bridge::gov::list_message`], `nonce` the bridge's `list_nonce` (shared with
    /// `RegisterBridgedToken`). Rides a RAND fee bundle, owing the bundle base.
    ListBacking {
        token_index: u32,
        chain: u16,
        token: [u8; 32],
        decimals: u8,
        nonce: u64,
        pq_signatures: Vec<crate::bridge::PqSignature>,
    },
    /// Bridge rules v2 (audit v4 BRG-14): replace the whole PQ guardian set with
    /// `new_pq_guardians` — index-aligned with the current ECDSA set, every key a Dilithium2 key,
    /// no duplicates, not containing the pause key. `pq_signatures` is a PQ guardian quorum of the
    /// **current** set over [`crate::bridge::gov::rotate_pq_message`]`(chain_id, nonce, keys)`,
    /// `nonce` the bridge's `rotation_nonce` (shared with `RotatePauseKey`). Bundle-less and
    /// fee-less, like the pause. Refused `RulesV2Disabled` on a chain without `bridge.rules_v2`
    /// (chain 14), before anything else is read.
    RotatePqGuardians { new_pq_guardians: Vec<PublicKey>, nonce: u64, pq_signatures: Vec<crate::bridge::PqSignature> },
    /// Bridge rules v2: replace the pause key with `new_pause_key` — a Dilithium2 key that is no
    /// PQ guardian's. A PQ guardian quorum over
    /// [`crate::bridge::gov::rotate_pause_message`]`(chain_id, nonce, key)`, `nonce` the bridge's
    /// `rotation_nonce`. Bundle-less and fee-less; gated like `RotatePqGuardians`.
    RotatePauseKey { new_pause_key: PublicKey, nonce: u64, pq_signatures: Vec<crate::bridge::PqSignature> },
    /// Genesis vesting (spec §6.1): release `amount` (gross) of a vesting entry's unlocked RAND
    /// as a note of `amount − BUNDLE_BASE` to `to` (no sender, the native asset, `time` and `r`
    /// the note's, `envelope` sealed against it); the base goes to the proposer. Signed by the
    /// entry's beneficiary over [`crate::types::actions::claim_vested_message`]; `nonce` the
    /// entry's. Bundle-less and fee-less, like a `Withdraw`.
    ClaimVested {
        entry: [u8; 32],
        amount: u64,
        nonce: u64,
        to: ShieldedAddress,
        time: u32,
        r: Word8,
        envelope: Envelope,
        signature: Signature,
    },
    /// Genesis vesting (spec §6.2): revoke a revocable entry — stop its schedule at the applying
    /// block, so its whole unvested part leaves the holder's reach — and pay `unvested` of that
    /// part to `to` as a note of `unvested − BUNDLE_BASE`. `unvested` is the least the revokers
    /// expect to be unvested (refused if less is); what it leaves in the register is the
    /// treasury's and a later revoke pays it out (audit v6, STAKE-4). `nonce` is the entry's
    /// `revoke_nonce`. `to` must be the treasury the entry names in genesis, and `signatures` at
    /// least the entry's `threshold` of its revokers, each over
    /// [`crate::types::actions::revoke_vesting_message`] (audit v6, STAKE-3 — the shape changed
    /// from one `signature`; no chain has carried a `vesting` section, so none ever admitted one).
    RevokeVesting {
        entry: [u8; 32],
        unvested: u64,
        nonce: u64,
        to: ShieldedAddress,
        time: u32,
        r: Word8,
        envelope: Envelope,
        signatures: Vec<crate::types::actions::RevokerSignature>,
    },
    /// Genesis vesting, bond-from-lock (SAFT Schedule 2 §4): bond `amount` of an irrevocable
    /// entry's locked RAND as `validator`'s stake — a `Bond` whose value comes from the vesting
    /// register instead of a bundle's burn, `registration` present exactly when the validator
    /// is new. Signed by the beneficiary over [`crate::types::actions::bond_vested_message`].
    BondVested { entry: [u8; 32], validator: Address, amount: u64, registration: Option<Registration>, nonce: u64, signature: Signature },
    /// Genesis vesting: take `amount` of the entry's bonded stake back; it returns to the lock
    /// after `UNBONDING_EPOCHS`, never to a note. Signed by the beneficiary over
    /// [`crate::types::actions::unbond_vested_message`].
    UnbondVested { entry: [u8; 32], amount: u64, nonce: u64, signature: Signature },
    /// Audit v6, STAKE-2 (genesis `staking.admission_by_vote`): the validator set's vote to admit
    /// `candidate` to the register. Under the flag a `Bond` that would *register* a new key is
    /// refused unless the key's address is in the ledger's admitted set, and this action is the
    /// only thing that puts one there; the registration it permits consumes it.
    ///
    /// `signatures` is one `(validator key, signature)` per voter, over
    /// [`crate::types::actions::admit_validator_message`]`(genesis hash, candidate address)`, in
    /// strictly ascending order of the voters' addresses (one canonical encoding per voter set,
    /// and a repeated voter is refused by the order rule alone). Every listed voter must be in the
    /// voting set, every signature must verify, and the voters' combined weight must be strictly
    /// more than two thirds of the set's (`ValidatorSet::has_quorum`). Bundle-less and fee-less,
    /// like the bridge's governance actions: the vote, not a payer, is the authority. Refused
    /// `UnsupportedAction` on a chain without the flag (every chain through 18), before anything
    /// else is read. Appended last: bincode is positional, and chain 18's history must decode.
    AdmitValidator { candidate: PublicKey, signatures: Vec<(PublicKey, Signature)> },
    /// Audit v6, STAKE-1 (genesis `staking.slashing`): the evidence that a leader signed two
    /// different block headers for one view — two [`SignedHeader`]s with the same `view` and
    /// `proposer` and different hashes, each verifying under this chain's consensus signing
    /// domain, `first` the lower hash ([`SignedHeader::ordered`]). Self-authenticating: the
    /// offender's own two signatures are the proof, so it carries no signer, no nonce, no bundle
    /// and no fee, and anyone may submit it (every replica that saw both proposals builds the same
    /// one). Under the section the ledger destroys `equivocation_bps` of the offender's bonded and
    /// unbonding stake and jails the key (`docs/staking.md`); on a chain without it — every chain
    /// through 18 — it is refused `UnsupportedAction` before a byte of it is read. The whole
    /// transaction is capped at `staking::MAX_EVIDENCE_BYTES` (1 MiB). Appended last.
    SlashEquivocation { first: Box<SignedHeader>, second: Box<SignedHeader> },
    /// Audit v6, BRG-14 (genesis `bridge.rotation.needs_possession`): [`Action::RotatePqGuardians`]
    /// with a proof that every new key is held — `possession[i]` is new key `i`'s own Dilithium2
    /// signature over the same rotation message the quorum signs
    /// ([`crate::bridge::gov::rotate_pq_message`], or its genesis-bound form), one per key in key
    /// order, each exactly 2 420 bytes (a `Vec` so a wrong length is refused by name, as a
    /// `PqSignature`'s is). Required under the flag, refused without it. Under
    /// `bridge.rotation.delay_secs` the rotation is recorded as pending and takes effect later
    /// (`docs/bridge.md` §21.5).
    RotatePqGuardiansV2 {
        new_pq_guardians: Vec<PublicKey>,
        possession: Vec<Vec<u8>>,
        nonce: u64,
        pq_signatures: Vec<crate::bridge::PqSignature>,
    },
    /// BRG-14: [`Action::RotatePauseKey`] with the new pause key's own signature over the
    /// rotation message (`possession`, 2 420 bytes), gated and delayed like `RotatePqGuardiansV2`.
    RotatePauseKeyV2 { new_pause_key: PublicKey, possession: Vec<u8>, nonce: u64, pq_signatures: Vec<crate::bridge::PqSignature> },
    /// BRG-14 (genesis `bridge.rotation.delay_secs`): drop the pending rotation of `kind` (0 =
    /// the PQ set, 1 = the pause key) before it takes effect. Signed by the **current pause key**
    /// — the one key held apart from the PQ quorum — over
    /// [`crate::bridge::gov::cancel_rotation_message`]`(chain_id, nonce, kind)`, `nonce` the
    /// bridge's `rotation_nonce`, which the cancel spends. Bundle-less and fee-less, like the
    /// pause. Refused `RotationRulesDisabled` on a chain without the group.
    CancelRotation { kind: u8, nonce: u64, signature: Signature },
    /// RPL-2 (`docs/superpowers/specs/2026-09-30-rpl2-program-state-design.md`): a call whose
    /// proof vouches for one declared state `transition` of `program` — cells read and written,
    /// what the bundle's burn fields bring into the program's vault, what the vault pays out and
    /// what the program mints — which the ledger then applies. `proof` and `input_envelope` are
    /// a `Call`'s; the proof is made over `public ‖ call_binding ‖ transition.context(..)`. Rides
    /// a bundle, whose `burn_r` / `burn_a` / `burn_asset` are the value coming in. Gated on the
    /// genesis `program_state` section.
    Invoke {
        program: ProgramId,
        #[serde(with = "crate::crypto::wire_bytes")]
        proof: Vec<u8>,
        input_envelope: Option<CallEnvelope>,
        transition: Transition,
    },
    /// Multisig (spec 2026-10-08 §5): create an M-of-N account whose id is derived from these
    /// terms; the bundle's burn funds it. Gated on the genesis `multisig` section.
    CreateMultisig { salt: [u8; 32], signers: Vec<PublicKey>, threshold: u8 },
    /// Fund `account` with the bundle's `burn_r` / `burn_a` of `burn_asset`. Anyone, no signatures.
    MultisigDeposit { account: [u8; 32] },
    /// Pay `pays` out of `account`'s vault, the base out of its RAND row to the proposer. Signed by
    /// `threshold` of the account's signers over `multisig_pay_message`. Bundle-less.
    MultisigPay {
        account: [u8; 32],
        nonce: u64,
        time: u32,
        pays: Vec<crate::ledger::program_state::Payout>,
        signatures: Vec<crate::types::actions::SignerSignature>,
    },
    /// Replace the signer set and threshold. Signed over `multisig_rotate_message`. Bundle-less, fee-less.
    MultisigRotate {
        account: [u8; 32],
        nonce: u64,
        signers: Vec<PublicKey>,
        threshold: u8,
        signatures: Vec<crate::types::actions::SignerSignature>,
    },
}

impl Action {
    /// The name of this action if it rides *without* a bundle, `None` if it must carry one.
    ///
    /// The faucet `Mint` and the validator-signed staking actions started the list; block
    /// aggregation adds four: `UnbondAggregator`, `WithdrawAggregator`, `SlashAggregator` and
    /// `Aggregate` (an aggregator key owns no notes; the aggregate's proving share is collected
    /// from the covered bundles' excess, not from the author — spec §5.2). This is the one list
    /// of them: admission reads it for the shape rule and the name it reports, and
    /// [`crate::gas::fee_floor`] gives each of them a zero floor.
    pub fn bundle_less(&self) -> Option<&'static str> {
        match self {
            Action::Mint { .. } => Some("mint"),
            Action::Unbond { .. } => Some("unbond"),
            Action::Withdraw { .. } => Some("withdraw"),
            Action::UnbondAggregator { .. } => Some("unbond_aggregator"),
            Action::WithdrawAggregator { .. } => Some("withdraw_aggregator"),
            Action::SlashAggregator { .. } => Some("slash_aggregator"),
            Action::Aggregate { .. } => Some("aggregate"),
            Action::PauseMints { .. } => Some("pause_mints"),
            Action::UnpauseMints { .. } => Some("unpause_mints"),
            Action::RotatePqGuardians { .. } => Some("rotate_pq_guardians"),
            Action::RotatePauseKey { .. } => Some("rotate_pause_key"),
            Action::ClaimVested { .. } => Some("claim_vested"),
            Action::RevokeVesting { .. } => Some("revoke_vesting"),
            Action::BondVested { .. } => Some("bond_vested"),
            Action::UnbondVested { .. } => Some("unbond_vested"),
            Action::AdmitValidator { .. } => Some("admit_validator"),
            Action::SlashEquivocation { .. } => Some("slash_equivocation"),
            Action::RotatePqGuardiansV2 { .. } => Some("rotate_pq_guardians_v2"),
            Action::RotatePauseKeyV2 { .. } => Some("rotate_pause_key_v2"),
            Action::CancelRotation { .. } => Some("cancel_rotation"),
            Action::MultisigPay { .. } => Some("multisig_pay"),
            Action::MultisigRotate { .. } => Some("multisig_rotate"),
            _ => None,
        }
    }

    /// This action with every **proof** byte string replaced by the empty vector — what
    /// [`Transaction::binding`] hashes. Exactly one field is blanked: an `Aggregate`'s `proof`
    /// (since the hidden-asset bundle no action carries a bundle of its own). Every other field —
    /// envelopes, destination, validator, recipient, signatures, a guardian attestation, a
    /// signed header's `proof_hash` — is kept as it is, so the binding moves with it.
    ///
    /// **A `Call`'s `proof` is kept, deliberately** (Task 5b review, fix round 1). It is a proof,
    /// but not one of *this transaction's bundles*, and it exists before them: the wallet proves
    /// the call first and the fee bundle after. A program is public and stateless, so anyone can
    /// prove their own run of it; were the call proof outside the binding, an observer could swap
    /// theirs in under someone else's fee bundle — the victim pays, the receipt's outputs and
    /// `H_IN` become the attacker's, and the victim's input envelope (sealed to its own `H_IN`)
    /// no longer opens. Sealing prunes only `bundle.proof`, so nothing needs it blanked.
    ///
    /// The match is exhaustive and every arm names every field, with no wildcard and no `..`: a
    /// new variant, or a new field on an existing one, does not compile until it is classified
    /// here as a proof (blanked) or not (kept). That is deliberate — a field left out of the
    /// binding is a field a copier can change under someone else's proof.
    pub fn blanked(&self) -> Action {
        match self {
            Action::None => Action::None,
            Action::Mint { cm, pk, time, r, envelope, amount, minter, signature } => Action::Mint {
                cm: *cm,
                pk: *pk,
                time: *time,
                r: *r,
                envelope: envelope.clone(),
                amount: *amount,
                minter: minter.clone(),
                signature: signature.clone(),
            },
            Action::Deploy { base_pc, words, public } => {
                Action::Deploy { base_pc: *base_pc, words: words.clone(), public: public.clone() }
            }
            // Kept, not blanked: see the doc comment.
            Action::Call { program, proof, input_envelope } => {
                Action::Call { program: *program, proof: proof.clone(), input_envelope: input_envelope.clone() }
            }
            // An `Invoke`'s proof is a call proof and is kept for a `Call`'s reason; the transition
            // is what the proof is about and what the ledger applies, so it is kept whole.
            Action::Invoke { program, proof, input_envelope, transition } => Action::Invoke {
                program: *program,
                proof: proof.clone(),
                input_envelope: input_envelope.clone(),
                transition: transition.clone(),
            },
            // Multisig: no proof field; every field is kept so the binding moves with each.
            Action::CreateMultisig { salt, signers, threshold } => {
                Action::CreateMultisig { salt: *salt, signers: signers.clone(), threshold: *threshold }
            }
            Action::MultisigDeposit { account } => Action::MultisigDeposit { account: *account },
            Action::MultisigPay { account, nonce, time, pays, signatures } => Action::MultisigPay {
                account: *account,
                nonce: *nonce,
                time: *time,
                pays: pays.clone(),
                signatures: signatures.clone(),
            },
            Action::MultisigRotate { account, nonce, signers, threshold, signatures } => Action::MultisigRotate {
                account: *account,
                nonce: *nonce,
                signers: signers.clone(),
                threshold: *threshold,
                signatures: signatures.clone(),
            },
            Action::Bond { validator, amount, registration } => {
                Action::Bond { validator: *validator, amount: *amount, registration: registration.clone() }
            }
            Action::Unbond { validator, amount, nonce, signature } => Action::Unbond {
                validator: *validator,
                amount: *amount,
                nonce: *nonce,
                signature: signature.clone(),
            },
            Action::Withdraw { validator, amount, nonce, time, r, envelope, signature } => Action::Withdraw {
                validator: *validator,
                amount: *amount,
                nonce: *nonce,
                time: *time,
                r: *r,
                envelope: envelope.clone(),
                signature: signature.clone(),
            },
            // `pq_signatures` is kept: a co-signature is a signature, not a proof, and a copy
            // that stripped or swapped it must not keep the fee bundle's proof.
            Action::BridgeAttest { attestation, recipient, r, time, asset, envelope, pq_signatures } => {
                Action::BridgeAttest {
                    attestation: attestation.clone(),
                    recipient: recipient.clone(),
                    r: *r,
                    time: *time,
                    asset: *asset,
                    envelope: envelope.clone(),
                    pq_signatures: pq_signatures.clone(),
                }
            }
            Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to } => {
                Action::BridgeBurn {
                    asset: *asset,
                    amount: *amount,
                    relayer_fee: *relayer_fee,
                    to_chain: *to_chain,
                    token: *token,
                    to: *to,
                }
            }
            Action::RegisterAggregator { registration } => {
                Action::RegisterAggregator { registration: registration.clone() }
            }
            Action::UnbondAggregator { aggregator, nonce, signature } => Action::UnbondAggregator {
                aggregator: *aggregator,
                nonce: *nonce,
                signature: signature.clone(),
            },
            Action::WithdrawAggregator { aggregator, nonce, time, r, envelope, signature } => {
                Action::WithdrawAggregator {
                    aggregator: *aggregator,
                    nonce: *nonce,
                    time: *time,
                    r: *r,
                    envelope: envelope.clone(),
                    signature: signature.clone(),
                }
            }
            Action::SlashAggregator { a, b } => Action::SlashAggregator { a: a.clone(), b: b.clone() },
            Action::Aggregate { covers, proof: _, aggregator, nonce, time, r, envelope, signature } => {
                Action::Aggregate {
                    covers: covers.clone(),
                    proof: Vec::new(),
                    aggregator: *aggregator,
                    nonce: *nonce,
                    time: *time,
                    r: *r,
                    envelope: envelope.clone(),
                    signature: signature.clone(),
                }
            }
            Action::RegisterToken { name, symbol, decimals, authority, initial, salt, index } => {
                Action::RegisterToken {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    authority: authority.clone(),
                    initial: initial.clone(),
                    salt: *salt,
                    index: *index,
                }
            }
            Action::TokenMint { asset, amount, recipient, r, time, envelope, nonce, signature } => Action::TokenMint {
                asset: *asset,
                amount: *amount,
                recipient: recipient.clone(),
                r: *r,
                time: *time,
                envelope: envelope.clone(),
                nonce: *nonce,
                signature: signature.clone(),
            },
            Action::SetAuthority { asset, new, nonce, signature } => Action::SetAuthority {
                asset: *asset,
                new: new.clone(),
                nonce: *nonce,
                signature: signature.clone(),
            },
            Action::TokenBurn { asset, amount } => Action::TokenBurn { asset: *asset, amount: *amount },
            // Bundle-less, so no proof of this transaction's is bound to them; classified all the
            // same — signatures are kept.
            Action::PauseMints { nonce, signature } => Action::PauseMints { nonce: *nonce, signature: signature.clone() },
            Action::UnpauseMints { nonce, pq_signatures } => {
                Action::UnpauseMints { nonce: *nonce, pq_signatures: pq_signatures.clone() }
            }
            // B4: every field is kept — the quorum is a signature, not a proof, and a copy that
            // stripped or swapped it must not keep the fee bundle's proof.
            Action::RegisterBridgedToken { name, symbol, salt, chain, token, decimals, nonce, pq_signatures } => {
                Action::RegisterBridgedToken {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    salt: *salt,
                    chain: *chain,
                    token: *token,
                    decimals: *decimals,
                    nonce: *nonce,
                    pq_signatures: pq_signatures.clone(),
                }
            }
            Action::ListBacking { token_index, chain, token, decimals, nonce, pq_signatures } => Action::ListBacking {
                token_index: *token_index,
                chain: *chain,
                token: *token,
                decimals: *decimals,
                nonce: *nonce,
                pq_signatures: pq_signatures.clone(),
            },
            // Bridge rules v2: bundle-less, every field kept — the keys and the quorum are what
            // the transaction is.
            Action::RotatePqGuardians { new_pq_guardians, nonce, pq_signatures } => Action::RotatePqGuardians {
                new_pq_guardians: new_pq_guardians.clone(),
                nonce: *nonce,
                pq_signatures: pq_signatures.clone(),
            },
            Action::RotatePauseKey { new_pause_key, nonce, pq_signatures } => Action::RotatePauseKey {
                new_pause_key: new_pause_key.clone(),
                nonce: *nonce,
                pq_signatures: pq_signatures.clone(),
            },
            // Genesis vesting: no proofs, every field kept.
            Action::ClaimVested { entry, amount, nonce, to, time, r, envelope, signature } => Action::ClaimVested {
                entry: *entry,
                amount: *amount,
                nonce: *nonce,
                to: to.clone(),
                time: *time,
                r: *r,
                envelope: envelope.clone(),
                signature: signature.clone(),
            },
            Action::RevokeVesting { entry, unvested, nonce, to, time, r, envelope, signatures } => Action::RevokeVesting {
                entry: *entry,
                unvested: *unvested,
                nonce: *nonce,
                to: to.clone(),
                time: *time,
                r: *r,
                envelope: envelope.clone(),
                signatures: signatures.clone(),
            },
            Action::BondVested { entry, validator, amount, registration, nonce, signature } => Action::BondVested {
                entry: *entry,
                validator: *validator,
                amount: *amount,
                registration: registration.clone(),
                nonce: *nonce,
                signature: signature.clone(),
            },
            Action::UnbondVested { entry, amount, nonce, signature } => {
                Action::UnbondVested { entry: *entry, amount: *amount, nonce: *nonce, signature: signature.clone() }
            }
            // STAKE-2's admission vote: bundle-less, no proof, the candidate and every vote kept.
            Action::AdmitValidator { candidate, signatures } => {
                Action::AdmitValidator { candidate: candidate.clone(), signatures: signatures.clone() }
            }
            // STAKE-1's evidence: two signed headers, no proof; the signatures are the action.
            Action::SlashEquivocation { first, second } => {
                Action::SlashEquivocation { first: first.clone(), second: second.clone() }
            }
            // BRG-14: bundle-less, every field kept — the keys, the possession signatures and
            // the quorum are what the transaction is.
            Action::RotatePqGuardiansV2 { new_pq_guardians, possession, nonce, pq_signatures } => Action::RotatePqGuardiansV2 {
                new_pq_guardians: new_pq_guardians.clone(),
                possession: possession.clone(),
                nonce: *nonce,
                pq_signatures: pq_signatures.clone(),
            },
            Action::RotatePauseKeyV2 { new_pause_key, possession, nonce, pq_signatures } => Action::RotatePauseKeyV2 {
                new_pause_key: new_pause_key.clone(),
                possession: possession.clone(),
                nonce: *nonce,
                pq_signatures: pq_signatures.clone(),
            },
            Action::CancelRotation { kind, nonce, signature } => {
                Action::CancelRotation { kind: *kind, nonce: *nonce, signature: signature.clone() }
            }
        }
    }
}

/// `b` with both its proofs — `proof` and the split-authorisation `auth_proof` — replaced by the
/// empty vector and every other field kept, `auth_commit` among them — the bundle half of
/// [`Action::blanked`]. Every field is named, for the same reason: a new `Bundle` field does not
/// compile until it is classified. The auth proof is blanked because it is proved against this
/// binding (it cannot commit to itself); `auth_commit` is public and stays inside.
fn blank_bundle(b: &Bundle) -> Bundle {
    let Bundle {
        anchor,
        nullifiers,
        commitments,
        fee,
        burn_a,
        burn_r,
        burn_asset,
        time,
        envelopes,
        proof: _,
        auth_commit,
        auth_proof: _,
    } = b;
    Bundle {
        anchor: *anchor,
        nullifiers: *nullifiers,
        commitments: *commitments,
        fee: *fee,
        burn_a: *burn_a,
        burn_r: *burn_r,
        burn_asset: *burn_asset,
        time: *time,
        envelopes: envelopes.clone(),
        proof: Vec::new(),
        auth_commit: *auth_commit,
        auth_proof: Vec::new(),
    }
}

/// How many `u32` words [`Transaction::binding`] is: a 32-byte digest, as the eight words of the
/// public input segment every bundle proof of the transaction is proved with and verified against.
pub const TX_BINDING_WORDS: usize = 8;

/// The binding's hash domain.
pub const TX_BINDING_DOMAIN: &[u8] = b"rand-tx-bind-1";

/// [`Transaction::call_binding`]'s hash domain (INT-4, genesis `hardening_v6`).
pub const CALL_BINDING_DOMAIN: &[u8] = b"rand-call-bind-1";

/// BIND-1 (audit v6): the binding's hash domain on a chain whose genesis sets `binding_domain: 1`
/// — the genesis hash leads the preimage ([`crate::types::BindingDomain::Genesis`]).
pub const TX_BINDING_DOMAIN_V2: &[u8] = b"rand-tx-bind-2";

/// BIND-1: [`Transaction::call_binding`]'s hash domain under `binding_domain: 1`.
pub const CALL_BINDING_DOMAIN_V2: &[u8] = b"rand-call-bind-2";

/// A transaction: a shielded bundle, an action, or (for a faucet mint) an action alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub chain_id: u64,
    /// `None` exactly for the actions [`Action::bundle_less`] names.
    pub bundle: Option<Bundle>,
    pub action: Action,
}

impl Transaction {
    /// A bundle-carrying transaction; `Action::None` for a plain transfer.
    pub fn shielded(chain_id: u64, bundle: Bundle, action: Action) -> Transaction {
        Transaction { chain_id, bundle: Some(bundle), action }
    }

    /// What a faucet minter signs: the chain, the new note's commitment and opening, its envelope
    /// and the public amount. Binding the chain keeps a testnet mint off another chain.
    pub fn mint_signing_hash(
        chain_id: u64,
        cm: &Word8,
        pk: &Word8,
        time: u32,
        r: &Word8,
        envelope: &Envelope,
        amount: u64,
    ) -> Hash {
        let bytes = bincode::serialize(&(chain_id, cm, pk, time, r, envelope, amount)).expect("serializes");
        Hash::digest_domain(b"rand-mint-2", &bytes)
    }

    /// A faucet mint of `amount` to the note `(pk, no sender, amount, native asset, time, r)`,
    /// its commitment computed by `executor` exactly as admission recomputes it
    /// ([`crate::ledger::mint_commitment`]).
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        chain_id: u64,
        pk: Word8,
        time: u32,
        r: Word8,
        envelope: Envelope,
        amount: u64,
        minter: &Keypair,
        executor: &dyn crate::confidential::ConfidentialExecutor,
    ) -> Transaction {
        Self::mint_in(&BindingDomain::ChainId, chain_id, pk, time, r, envelope, amount, minter, executor)
    }

    /// [`Transaction::mint`] on a chain of `domain` (BIND-1): the minter signs
    /// [`BindingDomain::mint_signing_hash`], which under `binding_domain: 1` carries the genesis
    /// hash. What a node's faucet calls, with its ledger's own domain.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_in(
        domain: &BindingDomain,
        chain_id: u64,
        pk: Word8,
        time: u32,
        r: Word8,
        envelope: Envelope,
        amount: u64,
        minter: &Keypair,
        executor: &dyn crate::confidential::ConfidentialExecutor,
    ) -> Transaction {
        let cm = crate::ledger::mint_commitment(executor, &pk, amount, time, &r);
        let signature =
            minter.sign(domain.mint_signing_hash(chain_id, &cm, &pk, time, &r, &envelope, amount).as_bytes());
        Transaction {
            chain_id,
            bundle: None,
            action: Action::Mint { cm, pk, time, r, envelope, amount, minter: minter.public_key().clone(), signature },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Transaction, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Transaction id = hash of the full encoding.
    /// The transaction id. The bundle's proof enters by its digest, every other byte as is —
    /// so the pruned marker form (spec §6.2: `PRUNED_PROOF_MARKER` then that digest) hashes to
    /// the *same* id as the raw transaction, and the tx root a QC certifies binds a sealed
    /// block's pruned transactions whole: envelopes, action, everything but the proof bytes the
    /// covering aggregate stands in for (the pre-v0.1 review's M1). A bundle-less transaction
    /// hashes its bytes as is.
    ///
    /// Split authorisation (delegated proving Phase 2, domain `rand-txid-3`): the bundle's
    /// `auth_commit` enters as is and its `auth_proof` by its digest, like the bundle proof. The
    /// pruned form replaces only `proof`, never `auth_proof`, so it still hashes to the raw id.
    /// **Every transaction id changes** with this domain and view, on every chain the build runs
    /// — together with the wire change of the two `Bundle` fields, the reason the build carrying
    /// them (v0.6.3) runs chain 17 only.
    pub fn hash(&self) -> Hash {
        #[derive(Serialize)]
        struct BundleView<'a> {
            anchor: &'a Word8,
            nullifiers: &'a [Word8; BUNDLE_SLOTS],
            commitments: &'a [Word8; BUNDLE_SLOTS],
            fee: u64,
            burn_a: u64,
            burn_r: u64,
            burn_asset: u32,
            time: u32,
            envelopes: &'a [Envelope; BUNDLE_SLOTS],
            proof_hash: Hash,
            auth_commit: &'a Word8,
            auth_proof_hash: Hash,
        }
        #[derive(Serialize)]
        struct TxView<'a> {
            chain_id: u64,
            bundle: Option<BundleView<'a>>,
            action: &'a Action,
        }
        let bundle = self.bundle.as_ref().map(|b| BundleView {
            anchor: &b.anchor,
            nullifiers: &b.nullifiers,
            commitments: &b.commitments,
            fee: b.fee,
            burn_a: b.burn_a,
            burn_r: b.burn_r,
            burn_asset: b.burn_asset,
            time: b.time,
            envelopes: &b.envelopes,
            proof_hash: crate::notes::pruned_proof_hash(&b.proof).unwrap_or_else(|| Hash::digest(&b.proof)),
            auth_commit: &b.auth_commit,
            auth_proof_hash: Hash::digest(&b.auth_proof),
        });
        let view = TxView { chain_id: self.chain_id, bundle, action: &self.action };
        Hash::digest_domain(b"rand-txid-3", &bincode::serialize(&view).expect("Transaction serializes"))
    }

    /// What every bundle proof of this transaction is bound to: blake3 under
    /// [`TX_BINDING_DOMAIN`] of the canonical bincode of `(chain_id, bundle', action')`, where `'`
    /// means "with every proof byte string this transaction's bundle cannot commit to replaced by
    /// the empty vector" — `bundle.proof` and an `Aggregate`'s (see [`Action::blanked`]); a
    /// `Call`'s proof exists before the bundle is proved and stays inside — as eight
    /// little-endian `u32` words. Every public bundle field — the four nullifiers and
    /// commitments, `fee`, `burn_a`, `burn_r`, `burn_asset`, `time` and the four envelopes — is
    /// inside it.
    ///
    /// A bundle's proof is made over these words as its public input segment and verified
    /// against them (`ConfidentialExecutor::verify_bundle`), so a proof copied onto a
    /// transaction with any other field changed — the action, an envelope, the chain id — no
    /// longer verifies. Proofs are blanked because
    /// a proof cannot commit to itself; they are *replaced* by the empty vector, never skipped, so
    /// the encoding keeps its shape and a proof field cannot be confused with its neighbour.
    ///
    /// This is the one function both sides call — the wallet before proving, the ledger before
    /// verifying — and it hashes the *decoded* transaction, never received bytes. The bincode
    /// configuration is pinned here rather than inherited: fixed-width integers, little-endian,
    /// which is what `bincode::serialize` (and so [`Transaction::encode`]) writes today; a
    /// test holds the two equal.
    ///
    /// Not the transaction id: [`Transaction::hash`] is unchanged and still takes each bundle
    /// proof by its digest.
    ///
    /// BIND-1 (audit v6): `domain` is the chain's [`BindingDomain`] — the ledger's own
    /// (`Ledger::binding_domain`) on the verifying side, the wallet's on the proving side. Under
    /// `ChainId` the preimage and tag are the ones above, byte for byte; under `Genesis` the
    /// genesis hash leads the preimage, `(genesis, chain_id, bundle', action')`, under
    /// [`TX_BINDING_DOMAIN_V2`], so a proof made for one chain verifies on no other chain that
    /// shares its chain id.
    pub fn binding(&self, domain: &BindingDomain) -> [u32; TX_BINDING_WORDS] {
        self.binding_of(domain, TX_BINDING_DOMAIN, TX_BINDING_DOMAIN_V2, self.action.blanked())
    }

    /// What a call proof of this transaction is bound to under genesis `hardening_v6` (INT-4 of
    /// the 2026-09-27 zkVM/ISA review): [`Transaction::binding`]'s construction under its own
    /// domain, [`CALL_BINDING_DOMAIN`], with the `Call`'s proof blanked as well as the bundle's —
    /// a proof cannot commit to itself. Everything else is inside it: the chain id, the program,
    /// the call's input envelope, and every public field of the fee bundle (its four nullifiers
    /// among them). The call proof carries these words as its public input segment, after the
    /// program's deploy-time public input when it has one (issue #55,
    /// `program::hardened_call_segment`, `ConfidentialExecutor::verify_call_hardened`), so a copy
    /// of it attached to any other fee bundle no longer verifies, and since those nullifiers can
    /// be spent once, one call proof yields one receipt.
    ///
    /// The two bindings nest: the bundle's [`Transaction::binding`] keeps the call proof inside,
    /// so the wallet builds the transaction with both proofs empty, proves the call against this,
    /// fills it in, and only then takes the bundle's binding and proves the bundle. For any other
    /// action it is simply a second digest of the same transaction, which nothing checks.
    ///
    /// BIND-1: `domain` as in [`Transaction::binding`]; genesis-bound under
    /// [`CALL_BINDING_DOMAIN_V2`].
    pub fn call_binding(&self, domain: &BindingDomain) -> [u32; TX_BINDING_WORDS] {
        let action = match self.action.blanked() {
            Action::Call { program, input_envelope, .. } => Action::Call { program, proof: Vec::new(), input_envelope },
            // RPL-2: the transition stays in, so an invoke's proof commits to exactly the state
            // change, the payouts and the recipients the transaction declares.
            Action::Invoke { program, input_envelope, transition, .. } => {
                Action::Invoke { program, proof: Vec::new(), input_envelope, transition }
            }
            other => other,
        };
        self.binding_of(domain, CALL_BINDING_DOMAIN, CALL_BINDING_DOMAIN_V2, action)
    }

    /// `(chain_id, bundle', action)` under `tag`, as eight little-endian words: the bundle's
    /// proof blanked, the action as the caller blanked it. The one construction both bindings use.
    /// BIND-1: under [`BindingDomain::Genesis`] the preimage is `(genesis, chain_id, bundle',
    /// action)` under `tag_v2` — the same pinned bincode configuration, the genesis hash its first
    /// 32 bytes.
    fn binding_of(&self, domain: &BindingDomain, tag: &[u8], tag_v2: &[u8], action: Action) -> [u32; TX_BINDING_WORDS] {
        use bincode::Options;
        let bundle = self.bundle.as_ref().map(blank_bundle);
        let options = bincode::DefaultOptions::new().with_fixint_encoding().with_little_endian();
        let digest = match domain {
            BindingDomain::ChainId => {
                let bytes = options.serialize(&(self.chain_id, &bundle, &action)).expect("Transaction serializes");
                Hash::digest_domain(tag, &bytes)
            }
            BindingDomain::Genesis(genesis) => {
                let bytes =
                    options.serialize(&(genesis, self.chain_id, &bundle, &action)).expect("Transaction serializes");
                Hash::digest_domain(tag_v2, &bytes)
            }
        };
        std::array::from_fn(|i| u32::from_le_bytes(digest.0[4 * i..4 * i + 4].try_into().expect("four bytes")))
    }

    /// Wire size, used for block byte accounting.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// The bundle's fee, or zero for a bundle-less transaction.
    pub fn fee(&self) -> u64 {
        self.bundle.as_ref().map_or(0, |b| b.fee)
    }

    /// The nullifiers this transaction spends: its bundle's four, dummies included (every one
    /// is a real nullifier of a zero-amount note and goes through the same uniqueness rules).
    pub fn nullifiers(&self) -> Vec<Word8> {
        self.bundle.as_ref().map_or(Vec::new(), |b| b.nullifiers.to_vec())
    }

    /// Every note commitment this transaction creates: the bundle's four output slots in order
    /// (dummies included — each is appended to the tree), then a faucet mint's note.
    ///
    /// A `Withdraw`'s and a `BridgeAttest`'s deposit notes are deliberately absent — and so are
    /// RPL's two minted ones, a `TokenMint`'s and a `RegisterToken`'s `initial`: their commitment
    /// is not carried on the wire at all, it is computed by the ledger from the action's `r` and
    /// the amount it is paying out (spec §7). `Ledger::derived_commitment` is where a caller that
    /// needs them — the mempool's conflict index — gets them, and the node's `created_notes` is
    /// where the note index recomputes them for a committed block.
    pub fn commitments(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.commitments.to_vec());
        if let Action::Mint { cm, .. } = &self.action {
            v.push(*cm);
        }
        v
    }

    /// The attestation digests this transaction consumes: one for a `BridgeAttest`, none for
    /// anything else.
    ///
    /// A digest is a one-shot resource exactly like a nullifier — the bridge's `spent` set
    /// admits it once — but unlike a nullifier it is not a field of the transaction, it is the
    /// hash of the attestation body the guardians signed. Two relayers racing the same
    /// attestation therefore build two *entirely different* transactions (different fee bundles,
    /// possibly different `time`s) that share nothing [`Transaction::nullifiers`] or
    /// [`Transaction::commitments`] can see. Without this method the mempool would hold both,
    /// offer both, and lose the block when the second hit `Bridge(Replay)` — a permissionless
    /// relayer race being the normal operating mode of a bridge, not an attack.
    ///
    /// Naming it here also covers the sibling case: two attest transactions agreeing on
    /// recipient, amount, asset and `time` mint the identical deposit commitment (their `r` is
    /// the digest's since F1, so it agrees whenever the attestation does), which `commitments()`
    /// deliberately does not carry either.
    ///
    /// A malformed attestation claims nothing — it names no resource because it cannot be
    /// decoded, and `Ledger::validate` refuses it on its own.
    pub fn bridge_digests(&self) -> Vec<Hash> {
        match &self.action {
            Action::BridgeAttest { attestation, .. } => Attestation::body_bytes(attestation)
                .map(|body| vec![Hash(attestation_digest(body))])
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] }
    }

    fn bundle() -> Bundle {
        Bundle {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [12; 8], [13; 8]],
            commitments: [[4; 8], [5; 8], [14; 8], [15; 8]],
            fee: 1_000_000,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 9,
            envelopes: [env(), env(), env(), env()],
            proof: vec![9; 40],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        }
    }

    /// Split authorisation: the transaction id takes the auth proof by its digest, like the
    /// bundle proof (`rand-txid-3`), so two transactions differing only in their auth proof —
    /// or only in `auth_commit` — have different ids, while the pruned marker form (which
    /// replaces only `proof`) keeps the raw id. The binding blanks the auth proof and keeps
    /// `auth_commit`.
    #[test]
    fn txid_covers_the_auth_proof_by_digest() {
        let mut b = bundle();
        b.auth_commit = [0xc0; 8];
        b.auth_proof = vec![0xa0; 50];
        let t = Transaction::shielded(13, b, Action::None);
        let mut other_proof = t.clone();
        other_proof.bundle.as_mut().unwrap().auth_proof = vec![0xa1; 50];
        assert_ne!(other_proof.hash(), t.hash(), "the auth proof is inside the id");
        assert_eq!(other_proof.binding(&BindingDomain::ChainId), t.binding(&BindingDomain::ChainId), "and outside the binding it is proved against");
        let mut other_commit = t.clone();
        other_commit.bundle.as_mut().unwrap().auth_commit = [0xc1; 8];
        assert_ne!(other_commit.hash(), t.hash(), "auth_commit is inside the id");
        assert_ne!(other_commit.binding(&BindingDomain::ChainId), t.binding(&BindingDomain::ChainId), "and inside the binding");
        // By digest, not by bytes: the id is the digest of a view carrying `Hash::digest(auth_proof)`.
        let mut marker = t.clone();
        let bm = marker.bundle.as_mut().unwrap();
        let ph = Hash::digest(&bm.proof);
        bm.proof = [crate::notes::PRUNED_PROOF_MARKER, ph.as_bytes()].concat();
        assert_eq!(marker.hash(), t.hash(), "the pruned form keeps the raw id, auth proof and all");
        // And the domain moved: an id with empty auth fields is not the rand-txid-2 id of the
        // same bytes (every transaction id changes with this build — chain 17 only).
        let plain = Transaction::shielded(13, bundle(), Action::None);
        #[derive(serde::Serialize)]
        struct V2<'a> {
            chain_id: u64,
            bundle: Option<V2Bundle<'a>>,
            action: &'a Action,
        }
        #[derive(serde::Serialize)]
        struct V2Bundle<'a> {
            anchor: &'a Word8,
            nullifiers: &'a [Word8; BUNDLE_SLOTS],
            commitments: &'a [Word8; BUNDLE_SLOTS],
            fee: u64,
            burn_a: u64,
            burn_r: u64,
            burn_asset: u32,
            time: u32,
            envelopes: &'a [Envelope; BUNDLE_SLOTS],
            proof_hash: Hash,
        }
        let pb = plain.bundle.as_ref().unwrap();
        let v2 = V2 {
            chain_id: 13,
            bundle: Some(V2Bundle {
                anchor: &pb.anchor,
                nullifiers: &pb.nullifiers,
                commitments: &pb.commitments,
                fee: pb.fee,
                burn_a: pb.burn_a,
                burn_r: pb.burn_r,
                burn_asset: pb.burn_asset,
                time: pb.time,
                envelopes: &pb.envelopes,
                proof_hash: Hash::digest(&pb.proof),
            }),
            action: &plain.action,
        };
        assert_ne!(plain.hash(), Hash::digest_domain(b"rand-txid-2", &bincode::serialize(&v2).unwrap()));
    }

    /// The golden encodings (final review, item 3): the byte-vector fields that ride the CBOR
    /// sync wire serialize as bytes, not as a sequence of integers. Bincode writes both forms
    /// identically (a u64 length, then the bytes), so `encode()` and `hash()` of these fixtures
    /// were captured at b9026b3, *before* that change, and must never move: the transaction id
    /// and the consensus encoding are the same on either side of it.
    ///
    /// Re-pinned once, deliberately, for the hidden-asset bundle (chain 14, spec §3.6): the
    /// bundle's shape changed (four slots, `burn_a`/`burn_r`/`burn_asset` in place of
    /// `burn`/`asset`), so the call and attest fixtures — which carry a bundle — encode and hash
    /// differently. The bundle-less aggregate fixture did not move, and neither did any
    /// variant tag before `TokenBurn` (`TokenTransfer` was the one after `SetAuthority`).
    ///
    /// Re-pinned again, deliberately, for split authorisation (delegated proving Phase 2, the
    /// chain-17 hard fork): a bundle's encoding grows by `auth_commit` and an empty `auth_proof` —
    /// 40 zero bytes after the proof, exactly — so the call and attest encodings move, and every id
    /// moves with the `rand-txid-3` domain, the bundle-less aggregate's included (its encoding did
    /// not move). Before: call id `07801ac23f33f0d8b00d6e369f947ddee6afcab406f0d7905cd41bd3775bf1d5`,
    /// attest encoding `a6ec2084406fa08c02c05bd50142daf06a723fdbdda856d68cd41a34e02772c6` and id
    /// `a6fe97af73dda142415401c7e755f8532f081bd3fcacfae3fc833e057be1ea23`, aggregate id
    /// `a25cb696d9d92cecb09c0b4d4c818ae30c6e29ecda1d73944395843e3f350e0f`.
    #[test]
    fn the_consensus_encoding_and_txid_are_pinned() {
        let call = Transaction::shielded(
            13,
            bundle(),
            Action::Call {
                program: Hash([7; 32]),
                proof: (0..=255u8).collect(),
                input_envelope: Some(CallEnvelope {
                    kem_ct: vec![0xa1; 5],
                    to_sender: vec![0xb2; 3],
                    to_auditor: vec![0xc3; 2],
                    body: vec![0xd4; 7],
                }),
            },
        );
        let attest = Transaction::shielded(
            13,
            bundle(),
            Action::BridgeAttest {
                attestation: vec![1, 2, 3, 250],
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [5; 8],
                time: 9,
                asset: 1,
                envelope: env(),
                pq_signatures: Vec::new(),
            },
        );
        let aggregate = Transaction {
            chain_id: 13,
            bundle: None,
            action: Action::Aggregate {
                covers: vec![Hash([1; 32]), Hash([2; 32])],
                proof: vec![0xee; 300],
                aggregator: Address([3; 32]),
                nonce: 4,
                time: 5,
                r: [6; 8],
                envelope: env(),
                signature: Signature::empty(),
            },
        };
        let got = |tx: &Transaction| {
            assert_eq!(&Transaction::decode(&tx.encode()).unwrap(), tx);
            (hex::encode(tx.encode()), hex::encode(blake3::hash(&tx.encode()).as_bytes()), hex::encode(tx.hash().0))
        };
        let (call_hex, _, call_id) = got(&call);
        assert_eq!(call_hex, CALL_HEX);
        assert_eq!(call_id, CALL_ID);
        let (_, attest_digest, attest_id) = got(&attest);
        assert_eq!((attest_digest.as_str(), attest_id.as_str()), (ATTEST_ENCODING_BLAKE3, ATTEST_ID));
        let (_, aggregate_digest, aggregate_id) = got(&aggregate);
        assert_eq!((aggregate_digest.as_str(), aggregate_id.as_str()), (AGGREGATE_ENCODING_BLAKE3, AGGREGATE_ID));
    }

    const CALL_HEX: &str = concat!(
        "0d0000000000000001010000000100000001000000010000000100000001000000010000000100000002000000020000",
        "000200000002000000020000000200000002000000020000000300000003000000030000000300000003000000030000",
        "0003000000030000000c0000000c0000000c0000000c0000000c0000000c0000000c0000000c0000000d0000000d0000",
        "000d0000000d0000000d0000000d0000000d0000000d0000000400000004000000040000000400000004000000040000",
        "00040000000400000005000000050000000500000005000000050000000500000005000000050000000e0000000e0000",
        "000e0000000e0000000e0000000e0000000e0000000e0000000f0000000f0000000f0000000f0000000f0000000f0000",
        "000f0000000f00000040420f000000000000000000000000000000000000000000000000000900000008000000000000",
        "000101010101010101040000000000000002020202040000000000000003030303100000000000000004040404040404",
        "040404040404040404080000000000000001010101010101010400000000000000020202020400000000000000030303",
        "031000000000000000040404040404040404040404040404040800000000000000010101010101010104000000000000",
        "000202020204000000000000000303030310000000000000000404040404040404040404040404040408000000000000",
        "000101010101010101040000000000000002020202040000000000000003030303100000000000000004040404040404",
        "040404040404040404280000000000000009090909090909090909090909090909090909090909090909090909090909",
        "090909090909090909000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "000300000007070707070707070707070707070707070707070707070707070707070707070001000000000000000102",
        "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132",
        "333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162",
        "636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192",
        "939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2",
        "c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2",
        "f3f4f5f6f7f8f9fafbfcfdfeff010500000000000000a1a1a1a1a10300000000000000b2b2b20200000000000000c3c3",
        "0700000000000000d4d4d4d4d4d4d4",
    );
    const CALL_ID: &str = "fa79972d2125643097ccf253c9b4c326e33abc4c250cb64630787a4c90735282";
    /// Moved by the bridge hardening's B3, deliberately: `BridgeAttest` gained its last field,
    /// `pq_signatures`, so an attest's encoding grows by that list (here empty — an 8-byte zero
    /// length) and its id moves with it. A hard fork for a bridged chain only — no running chain
    /// has a bridge, and on a chain without one an attest is inadmissible. The values before, on
    /// the hidden-asset bundle, were
    /// `f0f13c7cec3d5fee1f3944c7725cf175f44e55d3787d0bcbd610bf956ed56b65` (encoding) and
    /// `04aa8e8f2dadcd9f93cdeeb79850f0f535f4ca901e7ea162d5e560f2d8f3d690` (id); the new encoding is
    /// exactly that one followed by the eight zero bytes. The call and the aggregate pins did not
    /// move.
    const ATTEST_ENCODING_BLAKE3: &str = "1de4200cee6184eec917fcf13ec968f926157cecaf1fe7c4b249fe00ee561836";
    const ATTEST_ID: &str = "2234de2343de1cb0ae0b758bc3765fce6b3d49e74ec7b8fd7abc6f0da87c2ef6";
    const AGGREGATE_ENCODING_BLAKE3: &str = "c5f06333b3d6f2e744f6edeb66b612723c1bc4fcf7f98fd8249b40226af64d64";
    const AGGREGATE_ID: &str = "da7be1091cabf0cc0489eb619aab0ad5801970c965ecef6e2912a3168845afb2";

    #[test]
    fn transactions_roundtrip_and_hash_their_full_encoding() {
        let tx = Transaction::shielded(7, bundle(), Action::None);
        let back = Transaction::decode(&tx.encode()).unwrap();
        assert_eq!(back, tx);
        assert_eq!(tx.fee(), 1_000_000);
        assert_eq!(tx.nullifiers(), vec![[2; 8], [3; 8], [12; 8], [13; 8]]);
        assert_eq!(tx.commitments(), vec![[4; 8], [5; 8], [14; 8], [15; 8]]);
        let mut other = tx.clone();
        other.bundle.as_mut().unwrap().fee += 1;
        assert_ne!(other.hash(), tx.hash());
    }

    /// The staking and faucet actions ride without a bundle — and so do B1's pause and unpause —
    /// and each names itself for the shape error admission reports when one arrives with a bundle
    /// anyway.
    #[test]
    fn only_a_mint_an_unbond_and_a_withdraw_are_bundle_less() {
        let v = Address([1; 32]);
        let minter = Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        let bundle_less = [
            (
                Action::Mint {
                    cm: [1; 8],
                    pk: [1; 8],
                    time: 0,
                    r: [1; 8],
                    envelope: env(),
                    amount: 1,
                    minter: minter.clone(),
                    signature: Signature::empty(),
                },
                "mint",
            ),
            (Action::Unbond { validator: v, amount: 1, nonce: 0, signature: Signature::empty() }, "unbond"),
            (
                Action::Withdraw {
                    validator: v,
                    amount: 1,
                    nonce: 0,
                    time: 0,
                    r: [0; 8],
                    envelope: env(),
                    signature: Signature::empty(),
                },
                "withdraw",
            ),
            (Action::PauseMints { nonce: 0, signature: Signature::empty() }, "pause_mints"),
            (Action::UnpauseMints { nonce: 0, pq_signatures: Vec::new() }, "unpause_mints"),
            (Action::RotatePqGuardians { new_pq_guardians: Vec::new(), nonce: 0, pq_signatures: Vec::new() }, "rotate_pq_guardians"),
            (Action::RotatePauseKey { new_pause_key: minter.clone(), nonce: 0, pq_signatures: Vec::new() }, "rotate_pause_key"),
            (Action::UnbondVested { entry: [0; 32], amount: 1, nonce: 0, signature: Signature::empty() }, "unbond_vested"),
            (Action::MultisigPay { account: [0; 32], nonce: 0, time: 0, pays: Vec::new(), signatures: Vec::new() }, "multisig_pay"),
            (
                Action::MultisigRotate { account: [0; 32], nonce: 0, signers: Vec::new(), threshold: 1, signatures: Vec::new() },
                "multisig_rotate",
            ),
            (Action::AdmitValidator { candidate: minter.clone(), signatures: Vec::new() }, "admit_validator"),
            (
                {
                    let h = SignedHeader {
                        header: crate::types::BlockHeader {
                            height: 1,
                            view: 1,
                            parent: Hash::ZERO,
                            proposer: minter.clone(),
                            timestamp_ms: 0,
                            tx_root: Hash::ZERO,
                            state_root: Hash::ZERO,
                            justify: crate::types::QuorumCertificate::genesis(Hash::ZERO),
                        },
                        signature: Signature::empty(),
                    };
                    Action::SlashEquivocation { first: Box::new(h.clone()), second: Box::new(h) }
                },
                "slash_equivocation",
            ),
            (
                Action::RotatePqGuardiansV2 { new_pq_guardians: Vec::new(), possession: Vec::new(), nonce: 0, pq_signatures: Vec::new() },
                "rotate_pq_guardians_v2",
            ),
            (
                Action::RotatePauseKeyV2 { new_pause_key: minter.clone(), possession: Vec::new(), nonce: 0, pq_signatures: Vec::new() },
                "rotate_pause_key_v2",
            ),
            (Action::CancelRotation { kind: 0, nonce: 0, signature: Signature::empty() }, "cancel_rotation"),
            (
                Action::BondVested { entry: [0; 32], validator: v, amount: 1, registration: None, nonce: 0, signature: Signature::empty() },
                "bond_vested",
            ),
            (
                Action::ClaimVested {
                    entry: [0; 32],
                    amount: 1,
                    nonce: 0,
                    to: ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
                    time: 0,
                    r: [0; 8],
                    envelope: env(),
                    signature: Signature::empty(),
                },
                "claim_vested",
            ),
            (
                Action::RevokeVesting {
                    entry: [0; 32],
                    unvested: 1,
                    nonce: 0,
                    to: ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
                    time: 0,
                    r: [0; 8],
                    envelope: env(),
                    signatures: Vec::new(),
                },
                "revoke_vesting",
            ),
        ];
        for (a, name) in &bundle_less {
            assert_eq!(a.bundle_less(), Some(*name), "{a:?}");
        }
        for a in [
            Action::None,
            Action::Deploy { base_pc: 0, words: vec![0x13], public: vec![] },
            Action::Call { program: Hash::ZERO, proof: vec![], input_envelope: None },
            Action::Bond { validator: v, amount: 1, registration: None },
        ] {
            assert_eq!(a.bundle_less(), None, "{a:?}");
        }
    }

    /// The hidden-asset bundle (spec §3.7): a `TokenBurn` is single-bundle, and like every
    /// bundle-carrying transaction it reports its bundle's four nullifiers and four commitments —
    /// dummies included — and nothing else. There is no second note set any more.
    #[test]
    fn a_token_burn_is_single_bundle_and_reports_its_four_notes() {
        let mut burning = bundle();
        burning.burn_a = 400;
        burning.burn_asset = 3;
        let b = Transaction::shielded(7, burning, Action::TokenBurn { asset: 3, amount: 400 });
        assert_eq!(b.nullifiers(), vec![[2; 8], [3; 8], [12; 8], [13; 8]]);
        assert_eq!(b.commitments(), vec![[4; 8], [5; 8], [14; 8], [15; 8]]);
        assert_eq!(Transaction::decode(&b.encode()).unwrap(), b);
        // JSON is self-describing and roundtrips the action too.
        assert_eq!(serde_json::from_str::<Action>(&serde_json::to_string(&b.action).unwrap()).unwrap(), b.action);
        // It rides a bundle: the RAND fee and the burned token are in the same one.
        assert!(b.action.bundle_less().is_none());
    }

    #[test]
    fn a_mint_is_signed_by_its_minter_and_has_no_bundle() {
        let k = Keypair::from_seed([5; 32]).unwrap();
        let tx = Transaction::mint(7, [8; 8], 0, [3; 8], env(), 100, &k, &crate::confidential::StubExecutor);
        assert!(tx.bundle.is_none());
        assert_eq!(tx.fee(), 0);
        let want = crate::ledger::mint_commitment(&crate::confidential::StubExecutor, &[8; 8], 100, 0, &[3; 8]);
        assert_eq!(tx.commitments(), vec![want]);
        let Action::Mint { cm, pk, time, r, envelope, amount, minter, signature } = &tx.action else { panic!() };
        let signed = |chain| Transaction::mint_signing_hash(chain, cm, pk, *time, r, envelope, *amount);
        assert!(minter.verify(signed(7).as_bytes(), signature));
        assert!(!minter.verify(signed(8).as_bytes(), signature));
    }

    /// A burn is single-bundle (spec §3.7): its one bundle's four nullifiers and four
    /// commitments are what the mempool's and the ledger's uniqueness checks see. A withdraw's
    /// deposit is not on the wire at all.
    #[test]
    fn a_bridge_burn_reports_its_one_bundle_and_a_withdraw_reports_no_deposit() {
        let mut burning = bundle();
        burning.burn_asset = 3;
        burning.burn_a = 400;
        let burn = Transaction::shielded(
            7,
            burning,
            Action::BridgeBurn { asset: 3, amount: 400, relayer_fee: 100, to_chain: 2, token: [7; 32], to: [1; 32] },
        );
        assert_eq!(burn.nullifiers(), vec![[2; 8], [3; 8], [12; 8], [13; 8]]);
        assert_eq!(burn.commitments(), vec![[4; 8], [5; 8], [14; 8], [15; 8]]);
        assert_eq!(Transaction::decode(&burn.encode()).unwrap(), burn);

        let withdraw = Action::Withdraw {
            validator: Address([1; 32]),
            amount: 9,
            nonce: 0,
            time: 9,
            r: [5; 8],
            envelope: env(),
            signature: Signature::empty(),
        };
        let w = Transaction { chain_id: 7, bundle: None, action: withdraw };
        assert!(w.commitments().is_empty(), "the ledger computes the deposit, the wire does not carry it");
        assert_eq!(Transaction::decode(&w.encode()).unwrap(), w);
        let a = Transaction::shielded(
            7,
            bundle(),
            Action::BridgeAttest {
                attestation: vec![1, 2, 3],
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [5; 8],
                time: 9,
                asset: 1,
                envelope: env(),
                pq_signatures: Vec::new(),
            },
        );
        assert_eq!(a.commitments(), vec![[4; 8], [5; 8], [14; 8], [15; 8]]);
        assert_eq!(a.nullifiers(), vec![[2; 8], [3; 8], [12; 8], [13; 8]]);
        // The deposit note is not on the wire, so the digest is the only resource an attest
        // claims — and `vec![1, 2, 3]` does not decode, so this one claims nothing.
        assert_eq!(a.bridge_digests(), Vec::new());
        assert_eq!(burn.bridge_digests(), Vec::new(), "only an attest consumes a digest");
    }

    /// The digest an attest consumes is the one the bridge's `spent` set keys on, and it does
    /// not depend on anything else in the transaction — which is the whole point: two relayers
    /// racing one attestation build different transactions that name the same digest, and the
    /// mempool needs to see that they collide.
    #[test]
    fn an_attest_claims_the_digest_of_the_attestation_body() {
        use crate::bridge::{Body, Payload, Transfer};
        let body = Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 2,
            emitter_address: [2; 32],
            sequence: 0,
            consistency_level: 0,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(1_000),
                token_address: [0xaa; 32],
                token_chain: 2,
                to: [9; 32],
                to_chain: 1,
                fee: Transfer::u256_from_u128(0),
            })
            .encode(),
        };
        let mu = Hash(crate::bridge::digest(&body.encode()));
        let attestation = Attestation { guardian_set_index: 0, signatures: Vec::new(), body }.encode();
        let attest = |r: Word8, cms: [Word8; 4]| {
            let mut b = bundle();
            b.commitments = cms;
            Transaction::shielded(
                7,
                b,
                Action::BridgeAttest {
                    attestation: attestation.clone(),
                    recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                    r,
                    time: 9,
                    asset: 1,
                    envelope: env(),
                    pq_signatures: Vec::new(),
                },
            )
        };
        let one = attest([5; 8], [[4; 8], [5; 8], [14; 8], [15; 8]]);
        let two = attest([6; 8], [[40; 8], [50; 8], [41; 8], [51; 8]]);
        assert_eq!(one.bridge_digests(), vec![mu]);
        assert_eq!(two.bridge_digests(), vec![mu], "a different relayer, the same digest");
        // They share nothing else the mempool indexes.
        assert_ne!(one.hash(), two.hash());
        assert!(one.commitments().iter().all(|cm| !two.commitments().contains(cm)));
    }

    /// Every new variant is on the wire, and a `Call`'s envelope is part of the transaction id.
    #[test]
    fn the_new_variants_roundtrip_and_a_call_envelope_is_bound_to_the_tx_hash() {
        let call = Action::Call { program: Hash::ZERO, proof: vec![1; 4], input_envelope: None };
        let plain = Transaction::shielded(7, bundle(), call);
        let sealed = Transaction::shielded(
            7,
            bundle(),
            Action::Call {
                program: Hash::ZERO,
                proof: vec![1; 4],
                input_envelope: Some(CallEnvelope {
                    kem_ct: vec![],
                    to_sender: vec![2; 48],
                    to_auditor: vec![],
                    body: vec![3; 64],
                }),
            },
        );
        assert_ne!(plain.hash(), sealed.hash());
        for t in [&plain, &sealed] {
            assert_eq!(&Transaction::decode(&t.encode()).unwrap(), t);
        }
        for action in [
            Action::Bond { validator: Address([1; 32]), amount: 5, registration: None },
            Action::Unbond { validator: Address([1; 32]), amount: 5, nonce: 3, signature: Signature::empty() },
        ] {
            let t = Transaction::shielded(7, bundle(), action);
            assert_eq!(Transaction::decode(&t.encode()).unwrap(), t);
        }
    }

    #[test]
    fn amounts_format_and_parse_in_rand() {
        assert_eq!(format_amount(1_500_000_000), "1.5");
        assert_eq!(parse_amount("0.000001").unwrap(), 1_000);
        assert!(parse_amount("1.0000000001").is_err());
        assert_eq!(parse_amount("1").unwrap(), UNITS_PER_RAND);
        assert_eq!(parse_amount(".25").unwrap(), 250_000_000);
        assert_eq!(parse_amount("abc"), Err(AmountError::NotANumber));
        assert_eq!(format_amount(42_000_000_000), "42");
        assert_eq!(format_amount(1), "0.000000001");
    }

    // ---- Task 5b: the transaction binding ------------------------------------------------------

    fn sig() -> Signature {
        Keypair::from_seed([3; 32]).unwrap().sign(b"x")
    }

    fn pk() -> PublicKey {
        Keypair::from_seed([3; 32]).unwrap().public_key().clone()
    }

    fn header() -> Box<SignedAggregateHeader> {
        Box::new(SignedAggregateHeader {
            aggregator: Address([4; 32]),
            nonce: 1,
            time: 2,
            r: [3; 8],
            covers: vec![Hash([5; 32])],
            proof_hash: Hash([6; 32]),
            signature: sig(),
        })
    }

    /// The number of `Action` variants, and each one's position — an exhaustive match with no
    /// wildcard, so a new variant fails to compile here until [`sample`] has a row for it (and
    /// [`Action::blanked`] has an arm).
    const VARIANTS: usize = 38;
    fn variant_index(a: &Action) -> usize {
        match a {
            Action::None => 0,
            Action::Mint { .. } => 1,
            Action::Deploy { .. } => 2,
            Action::Call { .. } => 3,
            Action::Bond { .. } => 4,
            Action::Unbond { .. } => 5,
            Action::Withdraw { .. } => 6,
            Action::BridgeAttest { .. } => 7,
            Action::BridgeBurn { .. } => 8,
            Action::RegisterAggregator { .. } => 9,
            Action::UnbondAggregator { .. } => 10,
            Action::WithdrawAggregator { .. } => 11,
            Action::SlashAggregator { .. } => 12,
            Action::Aggregate { .. } => 13,
            Action::RegisterToken { .. } => 14,
            Action::TokenMint { .. } => 15,
            Action::SetAuthority { .. } => 16,
            Action::TokenBurn { .. } => 17,
            Action::PauseMints { .. } => 18,
            Action::UnpauseMints { .. } => 19,
            Action::RegisterBridgedToken { .. } => 20,
            Action::ListBacking { .. } => 21,
            Action::RotatePqGuardians { .. } => 22,
            Action::RotatePauseKey { .. } => 23,
            Action::ClaimVested { .. } => 24,
            Action::RevokeVesting { .. } => 25,
            Action::BondVested { .. } => 26,
            Action::UnbondVested { .. } => 27,
            Action::AdmitValidator { .. } => 28,
            Action::SlashEquivocation { .. } => 29,
            Action::RotatePqGuardiansV2 { .. } => 30,
            Action::RotatePauseKeyV2 { .. } => 31,
            Action::CancelRotation { .. } => 32,
            Action::Invoke { .. } => 33,
            Action::CreateMultisig { .. } => 34,
            Action::MultisigDeposit { .. } => 35,
            Action::MultisigPay { .. } => 36,
            Action::MultisigRotate { .. } => 37,
        }
    }

    /// One action of variant `i` with every proof field set to `proof` and every other byte
    /// string non-empty — so blanking visibly empties the proofs and visibly keeps the rest.
    fn sample(i: usize, proof: Vec<u8>) -> Action {
        let reg = Registration { public_key: pk(), payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] }, signature: sig() };
        match i {
            0 => Action::None,
            1 => Action::Mint {
                cm: [1; 8],
                pk: [2; 8],
                time: 3,
                r: [4; 8],
                envelope: env(),
                amount: 1,
                minter: pk(),
                signature: sig(),
            },
            2 => Action::Deploy { base_pc: 0, words: vec![0x13, 0x13], public: vec![7] },
            3 => Action::Call {
                program: Hash([7; 32]),
                proof,
                input_envelope: Some(CallEnvelope {
                    kem_ct: vec![1; 4],
                    to_sender: vec![2; 4],
                    to_auditor: vec![3; 4],
                    body: vec![4; 4],
                }),
            },
            4 => Action::Bond { validator: Address([1; 32]), amount: 5, registration: Some(reg) },
            5 => Action::Unbond { validator: Address([1; 32]), amount: 5, nonce: 1, signature: sig() },
            6 => Action::Withdraw {
                validator: Address([1; 32]),
                amount: 5,
                nonce: 1,
                time: 2,
                r: [3; 8],
                envelope: env(),
                signature: sig(),
            },
            7 => Action::BridgeAttest {
                attestation: vec![1, 2, 3],
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [5; 8],
                time: 9,
                asset: 1,
                envelope: env(),
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 0, signature: vec![0x5c; 8] },
                    crate::bridge::PqSignature { index: 2, signature: vec![0x5d; 8] },
                ],
            },
            8 => Action::BridgeBurn {
                asset: 3,
                amount: 400,
                relayer_fee: 100,
                to_chain: 2,
                token: [7; 32],
                to: [1; 32],
            },
            9 => Action::RegisterAggregator {
                registration: AggregatorRegistration {
                    public_key: pk(),
                    payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
                    signature: sig(),
                },
            },
            10 => Action::UnbondAggregator { aggregator: Address([4; 32]), nonce: 1, signature: sig() },
            11 => Action::WithdrawAggregator {
                aggregator: Address([4; 32]),
                nonce: 1,
                time: 2,
                r: [3; 8],
                envelope: env(),
                signature: sig(),
            },
            12 => Action::SlashAggregator { a: header(), b: header() },
            13 => Action::Aggregate {
                covers: vec![Hash([1; 32])],
                proof,
                aggregator: Address([4; 32]),
                nonce: 1,
                time: 2,
                r: [3; 8],
                envelope: env(),
                signature: sig(),
            },
            14 => Action::RegisterToken {
                name: "Test Coin".into(),
                symbol: "TST".into(),
                decimals: 6,
                authority: MintAuthority::Key(pk()),
                initial: Some(InitialMint {
                    amount: 1,
                    recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                    r: [5; 8],
                    time: 9,
                    envelope: env(),
                }),
                salt: [3; 32],
                index: 1,
            },
            15 => Action::TokenMint {
                asset: 1,
                amount: 5,
                recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                r: [5; 8],
                time: 9,
                envelope: env(),
                nonce: 0,
                signature: sig(),
            },
            16 => Action::SetAuthority { asset: 1, new: Some(pk()), nonce: 0, signature: sig() },
            17 => Action::TokenBurn { asset: 3, amount: 5 },
            18 => Action::PauseMints { nonce: 4, signature: sig() },
            19 => Action::UnpauseMints {
                nonce: 5,
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 1, signature: vec![0x6c; 8] },
                    crate::bridge::PqSignature { index: 3, signature: vec![0x6d; 8] },
                ],
            },
            20 => Action::RegisterBridgedToken {
                name: "Shielded USD".into(),
                symbol: "zUSD".into(),
                salt: [0x27; 32],
                chain: 2,
                token: [0xda; 32],
                decimals: 6,
                nonce: 0,
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 0, signature: vec![0x7c; 8] },
                    crate::bridge::PqSignature { index: 4, signature: vec![0x7d; 8] },
                ],
            },
            21 => Action::ListBacking {
                token_index: 1,
                chain: 5,
                token: [0xc6; 32],
                decimals: 6,
                nonce: 6,
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 1, signature: vec![0x8c; 8] },
                    crate::bridge::PqSignature { index: 2, signature: vec![0x8d; 8] },
                ],
            },
            22 => Action::RotatePqGuardians {
                new_pq_guardians: vec![pk(), PublicKey::from_bytes(&[0x42; crate::crypto::PUBLIC_KEY_LEN]).unwrap()],
                nonce: 2,
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 0, signature: vec![0x9c; 8] },
                    crate::bridge::PqSignature { index: 3, signature: vec![0x9d; 8] },
                ],
            },
            23 => Action::RotatePauseKey {
                new_pause_key: PublicKey::from_bytes(&[0x43; crate::crypto::PUBLIC_KEY_LEN]).unwrap(),
                nonce: 3,
                pq_signatures: vec![
                    crate::bridge::PqSignature { index: 2, signature: vec![0xac; 8] },
                    crate::bridge::PqSignature { index: 5, signature: vec![0xad; 8] },
                ],
            },
            24 => Action::ClaimVested {
                entry: [0x51; 32],
                amount: 9,
                nonce: 1,
                to: ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] },
                time: 4,
                r: [7; 8],
                envelope: env(),
                signature: sig(),
            },
            25 => Action::RevokeVesting {
                entry: [0x52; 32],
                unvested: 9,
                nonce: 1,
                to: ShieldedAddress { pk: [5; 8], kem_ek: vec![6; 32] },
                time: 4,
                r: [7; 8],
                envelope: env(),
                signatures: vec![
                    crate::types::actions::RevokerSignature { index: 0, signature: sig() },
                    crate::types::actions::RevokerSignature { index: 2, signature: sig() },
                ],
            },
            26 => Action::BondVested {
                entry: [0x53; 32],
                validator: Address([0x54; 32]),
                amount: 9,
                registration: Some(reg.clone()),
                nonce: 1,
                signature: sig(),
            },
            27 => Action::UnbondVested { entry: [0x55; 32], amount: 9, nonce: 1, signature: sig() },
            28 => Action::AdmitValidator {
                candidate: PublicKey::from_bytes(&[0x44; crate::crypto::PUBLIC_KEY_LEN]).unwrap(),
                signatures: vec![(pk(), sig())],
            },
            29 => {
                let header = |view: u64| SignedHeader {
                    header: crate::types::BlockHeader {
                        height: 5,
                        view,
                        parent: Hash([0x61; 32]),
                        proposer: pk(),
                        timestamp_ms: 7,
                        tx_root: Hash([0x62; 32]),
                        state_root: Hash([0x63; 32]),
                        justify: crate::types::QuorumCertificate::genesis(Hash([0x64; 32])),
                    },
                    signature: sig(),
                };
                let (first, second) = SignedHeader::ordered(header(9), header(10));
                Action::SlashEquivocation { first, second }
            }
            30 => Action::RotatePqGuardiansV2 {
                new_pq_guardians: vec![pk(), PublicKey::from_bytes(&[0x42; crate::crypto::PUBLIC_KEY_LEN]).unwrap()],
                possession: vec![vec![0xb1; 8], vec![0xb2; 8]],
                nonce: 2,
                pq_signatures: vec![crate::bridge::PqSignature { index: 0, signature: vec![0x9c; 8] }],
            },
            31 => Action::RotatePauseKeyV2 {
                new_pause_key: PublicKey::from_bytes(&[0x43; crate::crypto::PUBLIC_KEY_LEN]).unwrap(),
                possession: vec![0xb3; 8],
                nonce: 3,
                pq_signatures: vec![crate::bridge::PqSignature { index: 2, signature: vec![0xac; 8] }],
            },
            32 => Action::CancelRotation { kind: 1, nonce: 4, signature: sig() },
            33 => {
                use crate::ledger::program_state::{Cell, Inflow, Payout, Transition};
                let payout = |asset: u32| Payout {
                    asset,
                    amount: 5,
                    recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                    r: [5; 8],
                    envelope: env(),
                };
                Action::Invoke {
                    program: Hash([7; 32]),
                    proof,
                    input_envelope: Some(CallEnvelope {
                        kem_ct: vec![1; 4],
                        to_sender: vec![2; 4],
                        to_auditor: vec![3; 4],
                        body: vec![4; 4],
                    }),
                    transition: Transition {
                        reads: vec![Cell { key: [1; 8], value: [2; 8] }],
                        writes: vec![Cell { key: [1; 8], value: [3; 8] }],
                        inflow: Inflow::Deposit,
                        pays: vec![payout(0)],
                        mints: vec![payout(2)],
                    },
                }
            }
            34 => Action::CreateMultisig { salt: [1; 32], signers: vec![pk()], threshold: 1 },
            35 => Action::MultisigDeposit { account: [2; 32] },
            36 => Action::MultisigPay {
                account: [2; 32],
                nonce: 3,
                time: 4,
                pays: vec![crate::ledger::program_state::Payout {
                    asset: 0,
                    amount: 5,
                    recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
                    r: [5; 8],
                    envelope: env(),
                }],
                signatures: vec![crate::types::actions::SignerSignature { index: 0, signature: sig() }],
            },
            37 => Action::MultisigRotate {
                account: [2; 32],
                nonce: 3,
                signers: vec![pk()],
                threshold: 1,
                signatures: vec![crate::types::actions::SignerSignature { index: 0, signature: sig() }],
            },
            _ => panic!("no variant {i}"),
        }
    }

    /// The classification [`Action::blanked`] makes, stated independently: exactly these variants
    /// carry a proof that is blanked, and blanking one empties exactly that proof and keeps
    /// everything else — every signature, envelope, attestation, destination and recipient
    /// stays inside the binding. A `Call` (variant 3) carries a proof that is *kept*: blanking
    /// leaves it whole and the binding moves with it.
    /// Table-driven over *every* variant: [`variant_index`] is exhaustive, so a new variant fails
    /// to compile until it has a row here, and `blanked` names every field of every variant, so a
    /// new field fails to compile until it is classified there.
    #[test]
    fn blanking_empties_exactly_the_proofs_of_every_variant() {
        // Since the hidden-asset bundle (spec §3.7) only an `Aggregate` carries a proof that is
        // blanked: `BridgeBurn` (8) and `TokenBurn` (17) no longer carry a bundle of their own.
        let blanked_proof = [13usize];
        // A `Call` (3) and an RPL-2 `Invoke` (33) carry a call proof, which is kept.
        let kept_proof = [3usize, 33];
        let mut seen = [false; VARIANTS];
        for (i, seen) in seen.iter_mut().enumerate() {
            let with = sample(i, vec![0x99; 7]);
            let without = sample(i, Vec::new());
            assert_eq!(variant_index(&with), i, "the table's row {i} is variant {i}");
            *seen = true;
            assert_eq!(with != without, blanked_proof.contains(&i) || kept_proof.contains(&i), "variant {i}: carries a proof field");
            assert_eq!(without.blanked(), without, "variant {i}: blanking is idempotent");
            let t = |a: Action| Transaction::shielded(7, bundle(), a);
            if kept_proof.contains(&i) {
                assert_eq!(with.blanked(), with, "variant {i}: its proof is kept whole");
                assert_ne!(t(with).binding(&BindingDomain::ChainId), t(without).binding(&BindingDomain::ChainId), "variant {i}: the binding moves with its proof");
            } else {
                assert_eq!(with.blanked(), without, "variant {i}: blanking keeps every non-proof field and empties the proofs");
                // The binding sees the blanked form only: the proof bytes never move it.
                assert_eq!(t(with).binding(&BindingDomain::ChainId), t(without).binding(&BindingDomain::ChainId), "variant {i}");
            }
        }
        assert!(seen.iter().all(|s| *s), "every variant has a row");
    }

    /// The binding ignores every blanked proof byte — the bundle's, an aggregate's, and a pruned
    /// marker in place of the bundle's — so a wallet can compute it before it proves its bundle,
    /// and the ledger after.
    #[test]
    fn the_binding_ignores_proof_bytes() {
        for i in [0usize, 8, 13, 17] {
            let base = Transaction::shielded(7, bundle(), sample(i, vec![1; 5]));
            let mut other = Transaction::shielded(7, bundle(), sample(i, vec![2; 900]));
            other.bundle.as_mut().unwrap().proof = vec![0xee; 3];
            assert_eq!(base.binding(&BindingDomain::ChainId), other.binding(&BindingDomain::ChainId), "variant {i}");
            let mut marker = base.clone();
            let mut pruned = crate::notes::PRUNED_PROOF_MARKER.to_vec();
            pruned.extend_from_slice(&[9; 32]);
            marker.bundle.as_mut().unwrap().proof = pruned;
            assert_eq!(base.binding(&BindingDomain::ChainId), marker.binding(&BindingDomain::ChainId), "variant {i}: the pruned form binds the same");
        }
    }

    /// A `Call`'s proof is *inside* the binding (fix round 1): a different call proof — another
    /// valid run of the same public program, say — is a different transaction to the bundle's
    /// proof, so it cannot be swapped in under someone else's fee bundle. The fee bundle's proof
    /// bytes still do not move it.
    #[test]
    fn the_binding_moves_when_the_call_proof_changes() {
        let base = Transaction::shielded(7, bundle(), sample(3, vec![1; 5]));
        let swapped = Transaction::shielded(7, bundle(), sample(3, vec![2; 5]));
        assert_ne!(base.binding(&BindingDomain::ChainId), swapped.binding(&BindingDomain::ChainId));
        let emptied = Transaction::shielded(7, bundle(), sample(3, Vec::new()));
        assert_ne!(base.binding(&BindingDomain::ChainId), emptied.binding(&BindingDomain::ChainId));
        let mut fee_proof = base.clone();
        fee_proof.bundle.as_mut().unwrap().proof = vec![0xee; 3];
        assert_eq!(base.binding(&BindingDomain::ChainId), fee_proof.binding(&BindingDomain::ChainId));
    }

    /// …and moves with every other field: the chain id, every bundle field — each of the four
    /// nullifiers, commitments and envelopes, `fee`, `burn_a`, `burn_r`, `burn_asset`, `time` —
    /// and every field of the actions the Task 5b attacks change.
    #[test]
    fn the_binding_moves_with_every_non_proof_field() {
        type Change = fn(&mut Transaction);
        fn burn(t: &mut Transaction) -> (&mut u32, &mut u64, &mut u64, &mut u16, &mut [u8; 32], &mut [u8; 32]) {
            let Action::BridgeBurn { asset, amount, relayer_fee, to_chain, token, to } = &mut t.action else {
                panic!("a burn")
            };
            (asset, amount, relayer_fee, to_chain, token, to)
        }
        fn b(t: &mut Transaction) -> &mut Bundle {
            t.bundle.as_mut().unwrap()
        }
        let burn_cases: Vec<(&str, Change)> = vec![
            ("chain_id", |t| t.chain_id += 1),
            ("anchor", |t| b(t).anchor[0] ^= 1),
            ("nullifier 0", |t| b(t).nullifiers[0][0] ^= 1),
            ("nullifier 1", |t| b(t).nullifiers[1][0] ^= 1),
            ("nullifier 2", |t| b(t).nullifiers[2][7] ^= 1),
            ("nullifier 3", |t| b(t).nullifiers[3][3] ^= 1),
            ("commitment 0", |t| b(t).commitments[0][0] ^= 1),
            ("commitment 1", |t| b(t).commitments[1][0] ^= 1),
            ("commitment 2", |t| b(t).commitments[2][5] ^= 1),
            ("commitment 3", |t| b(t).commitments[3][1] ^= 1),
            ("fee", |t| b(t).fee += 1),
            ("burn_a", |t| b(t).burn_a += 1),
            ("burn_r", |t| b(t).burn_r += 1),
            ("burn_asset", |t| b(t).burn_asset += 1),
            ("time", |t| b(t).time += 1),
            ("envelope 0", |t| b(t).envelopes[0].body[0] ^= 1),
            ("envelope 1", |t| b(t).envelopes[1].kem_ct.push(0)),
            ("envelope 2", |t| b(t).envelopes[2].to_sender.push(1)),
            ("envelope 3", |t| b(t).envelopes[3].to_receiver[0] ^= 1),
            ("burn asset", |t| *burn(t).0 += 1),
            ("burn amount", |t| *burn(t).1 += 1),
            ("burn relayer_fee", |t| *burn(t).2 += 1),
            ("burn to_chain", |t| *burn(t).3 += 1),
            ("burn token", |t| burn(t).4[0] ^= 1),
            ("burn to", |t| burn(t).5[31] ^= 1),
        ];
        let base = Transaction::shielded(7, bundle(), sample(8, vec![1; 5]));
        for (what, change) in burn_cases {
            let mut t = base.clone();
            change(&mut t);
            assert_ne!(t.binding(&BindingDomain::ChainId), base.binding(&BindingDomain::ChainId), "{what}");
        }
        // Every other action's fields, variant by variant: each row edits one field of `sample(i)`.
        let action_cases: Vec<(usize, &str, Change)> = vec![
            (34, "create salt", |t| {
                let Action::CreateMultisig { salt, .. } = &mut t.action else { panic!() };
                salt[0] ^= 1;
            }),
            (35, "deposit account", |t| {
                let Action::MultisigDeposit { account } = &mut t.action else { panic!() };
                account[0] ^= 1;
            }),
            (36, "pay nonce", |t| {
                let Action::MultisigPay { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (37, "rotate threshold", |t| {
                let Action::MultisigRotate { threshold, .. } = &mut t.action else { panic!() };
                *threshold += 1;
            }),
            (3, "call program", |t| {
                let Action::Call { program, .. } = &mut t.action else { panic!() };
                program.0[0] ^= 1;
            }),
            (3, "call input envelope", |t| {
                let Action::Call { input_envelope, .. } = &mut t.action else { panic!() };
                *input_envelope = None;
            }),
            (4, "bond validator", |t| {
                let Action::Bond { validator, .. } = &mut t.action else { panic!() };
                validator.0[0] ^= 1;
            }),
            (4, "bond registration", |t| {
                let Action::Bond { registration, .. } = &mut t.action else { panic!() };
                *registration = None;
            }),
            (7, "attest recipient", |t| {
                let Action::BridgeAttest { recipient, .. } = &mut t.action else { panic!() };
                recipient.pk[0] ^= 1;
            }),
            (7, "attest r", |t| {
                let Action::BridgeAttest { r, .. } = &mut t.action else { panic!() };
                r[0] ^= 1;
            }),
            (7, "attest time", |t| {
                let Action::BridgeAttest { time, .. } = &mut t.action else { panic!() };
                *time += 1;
            }),
            (7, "attest asset", |t| {
                let Action::BridgeAttest { asset, .. } = &mut t.action else { panic!() };
                *asset += 1;
            }),
            (7, "attest envelope", |t| {
                let Action::BridgeAttest { envelope, .. } = &mut t.action else { panic!() };
                envelope.body[0] ^= 1;
            }),
            (7, "attest attestation", |t| {
                let Action::BridgeAttest { attestation, .. } = &mut t.action else { panic!() };
                attestation[0] ^= 1;
            }),
            // B3: the PQ co-signatures are inside the binding — stripped, swapped or re-indexed,
            // a copy no longer carries the original's fee-bundle proof.
            (7, "attest pq signatures stripped", |t| {
                let Action::BridgeAttest { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures.clear();
            }),
            (7, "attest pq signature byte", |t| {
                let Action::BridgeAttest { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[1].signature[0] ^= 1;
            }),
            (7, "attest pq signature index", |t| {
                let Action::BridgeAttest { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[1].index = 1;
            }),
            (14, "register initial recipient", |t| {
                let Action::RegisterToken { initial: Some(m), .. } = &mut t.action else { panic!() };
                m.recipient.pk[0] ^= 1;
            }),
            (17, "token burn asset", |t| {
                let Action::TokenBurn { asset, .. } = &mut t.action else { panic!() };
                *asset += 1;
            }),
            (17, "token burn amount", |t| {
                let Action::TokenBurn { amount, .. } = &mut t.action else { panic!() };
                *amount += 1;
            }),
            // B1: the pause's nonce and signature, the unpause's nonce and quorum.
            (18, "pause nonce", |t| {
                let Action::PauseMints { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (18, "pause signature", |t| {
                let Action::PauseMints { signature, .. } = &mut t.action else { panic!() };
                *signature = Signature::empty();
            }),
            (19, "unpause nonce", |t| {
                let Action::UnpauseMints { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (19, "unpause pq signature byte", |t| {
                let Action::UnpauseMints { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[0].signature[0] ^= 1;
            }),
            (19, "unpause pq signature index", |t| {
                let Action::UnpauseMints { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[1].index = 2;
            }),
            // B4: every field of a registration and a listing, the quorum included.
            (20, "register name", |t| {
                let Action::RegisterBridgedToken { name, .. } = &mut t.action else { panic!() };
                name.push('!');
            }),
            (20, "register symbol", |t| {
                let Action::RegisterBridgedToken { symbol, .. } = &mut t.action else { panic!() };
                symbol.push('C');
            }),
            (20, "register salt", |t| {
                let Action::RegisterBridgedToken { salt, .. } = &mut t.action else { panic!() };
                salt[0] ^= 1;
            }),
            (20, "register chain", |t| {
                let Action::RegisterBridgedToken { chain, .. } = &mut t.action else { panic!() };
                *chain += 1;
            }),
            (20, "register token", |t| {
                let Action::RegisterBridgedToken { token, .. } = &mut t.action else { panic!() };
                token[31] ^= 1;
            }),
            (20, "register decimals", |t| {
                let Action::RegisterBridgedToken { decimals, .. } = &mut t.action else { panic!() };
                *decimals += 1;
            }),
            (20, "register nonce", |t| {
                let Action::RegisterBridgedToken { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (20, "register pq signatures stripped", |t| {
                let Action::RegisterBridgedToken { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures.clear();
            }),
            (21, "list token index", |t| {
                let Action::ListBacking { token_index, .. } = &mut t.action else { panic!() };
                *token_index += 1;
            }),
            (21, "list chain", |t| {
                let Action::ListBacking { chain, .. } = &mut t.action else { panic!() };
                *chain += 1;
            }),
            (21, "list token", |t| {
                let Action::ListBacking { token, .. } = &mut t.action else { panic!() };
                token[0] ^= 1;
            }),
            (21, "list decimals", |t| {
                let Action::ListBacking { decimals, .. } = &mut t.action else { panic!() };
                *decimals += 1;
            }),
            (21, "list nonce", |t| {
                let Action::ListBacking { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (21, "list pq signature byte", |t| {
                let Action::ListBacking { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[1].signature[0] ^= 1;
            }),
            // Bridge rules v2: the two rotations, every field, the quorum included.
            (22, "rotate pq set key", |t| {
                let Action::RotatePqGuardians { new_pq_guardians, .. } = &mut t.action else { panic!() };
                new_pq_guardians.pop();
            }),
            (22, "rotate pq nonce", |t| {
                let Action::RotatePqGuardians { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (22, "rotate pq signature byte", |t| {
                let Action::RotatePqGuardians { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[0].signature[0] ^= 1;
            }),
            (23, "rotate pause key", |t| {
                let Action::RotatePauseKey { new_pause_key, .. } = &mut t.action else { panic!() };
                *new_pause_key = pk();
            }),
            (23, "rotate pause nonce", |t| {
                let Action::RotatePauseKey { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (23, "rotate pause pq signature index", |t| {
                let Action::RotatePauseKey { pq_signatures, .. } = &mut t.action else { panic!() };
                pq_signatures[1].index = 4;
            }),
            // Genesis vesting: every field of the four, the signatures included.
            (24, "claim entry", |t| {
                let Action::ClaimVested { entry, .. } = &mut t.action else { panic!() };
                entry[0] ^= 1;
            }),
            (24, "claim amount", |t| {
                let Action::ClaimVested { amount, .. } = &mut t.action else { panic!() };
                *amount += 1;
            }),
            (24, "claim nonce", |t| {
                let Action::ClaimVested { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (24, "claim to", |t| {
                let Action::ClaimVested { to, .. } = &mut t.action else { panic!() };
                to.pk[0] ^= 1;
            }),
            (24, "claim time", |t| {
                let Action::ClaimVested { time, .. } = &mut t.action else { panic!() };
                *time += 1;
            }),
            (24, "claim r", |t| {
                let Action::ClaimVested { r, .. } = &mut t.action else { panic!() };
                r[0] ^= 1;
            }),
            (24, "claim envelope", |t| {
                let Action::ClaimVested { envelope, .. } = &mut t.action else { panic!() };
                envelope.body[0] ^= 1;
            }),
            (24, "claim signature", |t| {
                let Action::ClaimVested { signature, .. } = &mut t.action else { panic!() };
                *signature = Signature::empty();
            }),
            (25, "revoke unvested", |t| {
                let Action::RevokeVesting { unvested, .. } = &mut t.action else { panic!() };
                *unvested += 1;
            }),
            (25, "revoke to", |t| {
                let Action::RevokeVesting { to, .. } = &mut t.action else { panic!() };
                to.kem_ek[0] ^= 1;
            }),
            (25, "revoke signer index", |t| {
                let Action::RevokeVesting { signatures, .. } = &mut t.action else { panic!() };
                signatures[1].index = 1;
            }),
            (25, "revoke signature dropped", |t| {
                let Action::RevokeVesting { signatures, .. } = &mut t.action else { panic!() };
                signatures.pop();
            }),
            (26, "bond validator", |t| {
                let Action::BondVested { validator, .. } = &mut t.action else { panic!() };
                validator.0[0] ^= 1;
            }),
            (26, "bond registration", |t| {
                let Action::BondVested { registration, .. } = &mut t.action else { panic!() };
                *registration = None;
            }),
            (27, "unbond amount", |t| {
                let Action::UnbondVested { amount, .. } = &mut t.action else { panic!() };
                *amount += 1;
            }),
            // BRG-14: the possession signatures are inside the binding like the quorum's, and so
            // is a cancel's kind and signature.
            (30, "rotate pq v2 possession byte", |t| {
                let Action::RotatePqGuardiansV2 { possession, .. } = &mut t.action else { panic!() };
                possession[1][0] ^= 1;
            }),
            (30, "rotate pq v2 nonce", |t| {
                let Action::RotatePqGuardiansV2 { nonce, .. } = &mut t.action else { panic!() };
                *nonce += 1;
            }),
            (31, "rotate pause v2 possession byte", |t| {
                let Action::RotatePauseKeyV2 { possession, .. } = &mut t.action else { panic!() };
                possession[0] ^= 1;
            }),
            (32, "cancel kind", |t| {
                let Action::CancelRotation { kind, .. } = &mut t.action else { panic!() };
                *kind ^= 1;
            }),
            (32, "cancel signature", |t| {
                let Action::CancelRotation { signature, .. } = &mut t.action else { panic!() };
                *signature = Signature::empty();
            }),
        ];
        for (i, what, change) in action_cases {
            let base = Transaction::shielded(7, bundle(), sample(i, vec![1; 5]));
            let mut t = base.clone();
            change(&mut t);
            assert_ne!(t.binding(&BindingDomain::ChainId), base.binding(&BindingDomain::ChainId), "{what}");
        }
        // And the action as a whole: the same fee bundle under `None` and under an attest.
        let none = Transaction::shielded(7, bundle(), Action::None);
        let attest = Transaction::shielded(7, bundle(), sample(7, Vec::new()));
        assert_ne!(none.binding(&BindingDomain::ChainId), attest.binding(&BindingDomain::ChainId));
    }

    /// The pinned bincode configuration is exactly what `bincode::serialize` writes — the
    /// consensus encoding (`Transaction::encode`) — and a golden value pins the binding itself, so
    /// a wallet written against this function and a ledger built from it can never disagree
    /// silently, and a change to the blanking or the encoding shows up here as a hard fork.
    ///
    /// Re-pinned for split authorisation (the chain-17 hard fork): the blanked bundle carries
    /// `auth_commit` and an empty `auth_proof`. Before:
    /// `154da8ece535cc3502bbb5bc7280ae0cdbd768ac6f71a43a2fb515653ea248dd`.
    #[test]
    fn the_binding_encoding_is_pinned() {
        use bincode::Options;
        let tx = Transaction::shielded(13, bundle(), sample(8, vec![0x99; 7]));
        // The blanked transaction, written out by hand.
        let mut blank = tx.clone();
        blank.bundle.as_mut().unwrap().proof.clear();
        blank.bundle.as_mut().unwrap().auth_proof.clear();
        let pinned = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .serialize(&(blank.chain_id, &blank.bundle, &blank.action))
            .unwrap();
        assert_eq!(pinned, blank.encode(), "fixint little-endian is the consensus encoding");
        let digest = Hash::digest_domain(TX_BINDING_DOMAIN, &pinned);
        let words: [u32; TX_BINDING_WORDS] =
            std::array::from_fn(|i| u32::from_le_bytes(digest.0[4 * i..4 * i + 4].try_into().unwrap()));
        assert_eq!(tx.binding(&BindingDomain::ChainId), words);
        assert_eq!(hex::encode(digest.0), BURN_BINDING);
    }

    const BURN_BINDING: &str = "612f84f4a11155f511d1343bf06fb61e6c90ec8c3c266372db7441340e2bb457";
}
