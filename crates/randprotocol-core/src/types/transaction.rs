//! Transactions: a shielded bundle plus an optional action (design spec §3, §6).

use crate::bridge::{digest as attestation_digest, Attestation};
use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::ledger::tokens::MintAuthority;
use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8, BUNDLE_SLOTS};
use crate::program::ProgramId;
use crate::types::actions::{AggregatorRegistration, CallEnvelope, InitialMint, Registration, SignedAggregateHeader};
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
        }
    }
}

/// `b` with its `proof` replaced by the empty vector and every other field kept — the bundle
/// half of [`Action::blanked`]. Every field is named, for the same reason: a new `Bundle` field
/// does not compile until it is classified.
fn blank_bundle(b: &Bundle) -> Bundle {
    let Bundle { anchor, nullifiers, commitments, fee, burn_a, burn_r, burn_asset, time, envelopes, proof: _ } = b;
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
    }
}

/// How many `u32` words [`Transaction::binding`] is: a 32-byte digest, as the eight words of the
/// public input segment every bundle proof of the transaction is proved with and verified against.
pub const TX_BINDING_WORDS: usize = 8;

/// The binding's hash domain.
pub const TX_BINDING_DOMAIN: &[u8] = b"rand-tx-bind-1";

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
        let cm = crate::ledger::mint_commitment(executor, &pk, amount, time, &r);
        let signature =
            minter.sign(Self::mint_signing_hash(chain_id, &cm, &pk, time, &r, &envelope, amount).as_bytes());
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
        });
        let view = TxView { chain_id: self.chain_id, bundle, action: &self.action };
        Hash::digest_domain(b"rand-txid-2", &bincode::serialize(&view).expect("Transaction serializes"))
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
    pub fn binding(&self) -> [u32; TX_BINDING_WORDS] {
        use bincode::Options;
        let blanked = Transaction {
            chain_id: self.chain_id,
            bundle: self.bundle.as_ref().map(blank_bundle),
            action: self.action.blanked(),
        };
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .serialize(&(blanked.chain_id, &blanked.bundle, &blanked.action))
            .expect("Transaction serializes");
        let digest = Hash::digest_domain(TX_BINDING_DOMAIN, &bytes);
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
    /// different `r`) that share nothing [`Transaction::nullifiers`] or
    /// [`Transaction::commitments`] can see. Without this method the mempool would hold both,
    /// offer both, and lose the block when the second hit `Bridge(Replay)` — a permissionless
    /// relayer race being the normal operating mode of a bridge, not an attack.
    ///
    /// Naming it here also covers the sibling case: two attest transactions agreeing on
    /// recipient, amount, asset, height and `r` mint the identical deposit commitment, which
    /// `commitments()` deliberately does not carry either.
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
        }
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
        "090909090909090909030000000707070707070707070707070707070707070707070707070707070707070707000100",
        "0000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a",
        "2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a",
        "5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a",
        "8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9ba",
        "bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9ea",
        "ebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff010500000000000000a1a1a1a1a10300000000000000b2b2b20200",
        "000000000000c3c30700000000000000d4d4d4d4d4d4d4",
    );
    const CALL_ID: &str = "07801ac23f33f0d8b00d6e369f947ddee6afcab406f0d7905cd41bd3775bf1d5";
    /// Moved by the bridge hardening's B3, deliberately: `BridgeAttest` gained its last field,
    /// `pq_signatures`, so an attest's encoding grows by that list (here empty — an 8-byte zero
    /// length) and its id moves with it. A hard fork for a bridged chain only — no running chain
    /// has a bridge, and on a chain without one an attest is inadmissible. The values before, on
    /// the hidden-asset bundle, were
    /// `f0f13c7cec3d5fee1f3944c7725cf175f44e55d3787d0bcbd610bf956ed56b65` (encoding) and
    /// `04aa8e8f2dadcd9f93cdeeb79850f0f535f4ca901e7ea162d5e560f2d8f3d690` (id); the new encoding is
    /// exactly that one followed by the eight zero bytes. The call and the aggregate pins did not
    /// move.
    const ATTEST_ENCODING_BLAKE3: &str = "a6ec2084406fa08c02c05bd50142daf06a723fdbdda856d68cd41a34e02772c6";
    const ATTEST_ID: &str = "a6fe97af73dda142415401c7e755f8532f081bd3fcacfae3fc833e057be1ea23";
    const AGGREGATE_ENCODING_BLAKE3: &str = "c5f06333b3d6f2e744f6edeb66b612723c1bc4fcf7f98fd8249b40226af64d64";
    const AGGREGATE_ID: &str = "a25cb696d9d92cecb09c0b4d4c818ae30c6e29ecda1d73944395843e3f350e0f";

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
                    minter,
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
    const VARIANTS: usize = 22;
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
        let kept_proof = [3usize];
        let mut seen = [false; VARIANTS];
        for i in 0..VARIANTS {
            let with = sample(i, vec![0x99; 7]);
            let without = sample(i, Vec::new());
            assert_eq!(variant_index(&with), i, "the table's row {i} is variant {i}");
            seen[i] = true;
            assert_eq!(with != without, blanked_proof.contains(&i) || kept_proof.contains(&i), "variant {i}: carries a proof field");
            assert_eq!(without.blanked(), without, "variant {i}: blanking is idempotent");
            let t = |a: Action| Transaction::shielded(7, bundle(), a);
            if kept_proof.contains(&i) {
                assert_eq!(with.blanked(), with, "variant {i}: its proof is kept whole");
                assert_ne!(t(with).binding(), t(without).binding(), "variant {i}: the binding moves with its proof");
            } else {
                assert_eq!(with.blanked(), without, "variant {i}: blanking keeps every non-proof field and empties the proofs");
                // The binding sees the blanked form only: the proof bytes never move it.
                assert_eq!(t(with).binding(), t(without).binding(), "variant {i}");
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
            assert_eq!(base.binding(), other.binding(), "variant {i}");
            let mut marker = base.clone();
            let mut pruned = crate::notes::PRUNED_PROOF_MARKER.to_vec();
            pruned.extend_from_slice(&[9; 32]);
            marker.bundle.as_mut().unwrap().proof = pruned;
            assert_eq!(base.binding(), marker.binding(), "variant {i}: the pruned form binds the same");
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
        assert_ne!(base.binding(), swapped.binding());
        let emptied = Transaction::shielded(7, bundle(), sample(3, Vec::new()));
        assert_ne!(base.binding(), emptied.binding());
        let mut fee_proof = base.clone();
        fee_proof.bundle.as_mut().unwrap().proof = vec![0xee; 3];
        assert_eq!(base.binding(), fee_proof.binding());
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
            assert_ne!(t.binding(), base.binding(), "{what}");
        }
        // Every other action's fields, variant by variant: each row edits one field of `sample(i)`.
        let action_cases: Vec<(usize, &str, Change)> = vec![
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
        ];
        for (i, what, change) in action_cases {
            let base = Transaction::shielded(7, bundle(), sample(i, vec![1; 5]));
            let mut t = base.clone();
            change(&mut t);
            assert_ne!(t.binding(), base.binding(), "{what}");
        }
        // And the action as a whole: the same fee bundle under `None` and under an attest.
        let none = Transaction::shielded(7, bundle(), Action::None);
        let attest = Transaction::shielded(7, bundle(), sample(7, Vec::new()));
        assert_ne!(none.binding(), attest.binding());
    }

    /// The pinned bincode configuration is exactly what `bincode::serialize` writes — the
    /// consensus encoding (`Transaction::encode`) — and a golden value pins the binding itself, so
    /// a wallet written against this function and a ledger built from it can never disagree
    /// silently, and a change to the blanking or the encoding shows up here as a hard fork.
    #[test]
    fn the_binding_encoding_is_pinned() {
        use bincode::Options;
        let tx = Transaction::shielded(13, bundle(), sample(8, vec![0x99; 7]));
        // The blanked transaction, written out by hand.
        let mut blank = tx.clone();
        blank.bundle.as_mut().unwrap().proof.clear();
        let pinned = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .serialize(&(blank.chain_id, &blank.bundle, &blank.action))
            .unwrap();
        assert_eq!(pinned, blank.encode(), "fixint little-endian is the consensus encoding");
        let digest = Hash::digest_domain(TX_BINDING_DOMAIN, &pinned);
        let words: [u32; TX_BINDING_WORDS] =
            std::array::from_fn(|i| u32::from_le_bytes(digest.0[4 * i..4 * i + 4].try_into().unwrap()));
        assert_eq!(tx.binding(), words);
        assert_eq!(hex::encode(digest.0), BURN_BINDING);
    }

    const BURN_BINDING: &str = "154da8ece535cc3502bbb5bc7280ae0cdbd768ac6f71a43a2fb515653ea248dd";
}
