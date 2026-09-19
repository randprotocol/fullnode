//! Transactions: a shielded bundle plus an optional action (design spec §3, §6).

use crate::bridge::{digest as attestation_digest, Attestation};
use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::ledger::tokens::MintAuthority;
use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};
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
    BridgeAttest {
        #[serde(with = "crate::crypto::wire_bytes")]
        attestation: Vec<u8>,
        recipient: ShieldedAddress,
        r: Word8,
        time: u32,
        asset: u32,
        envelope: Envelope,
    },
    /// Phase S3: burn `amount` of asset `asset` to a destination chain. `asset_bundle` is the
    /// second bundle of the transaction — the one spending the asset notes; the transaction's
    /// own `bundle` pays the RAND fee.
    ///
    /// `token` is the source-chain token address being redeemed, and `(to_chain, token)` must be
    /// one of `asset`'s backings (spec §12): one bridged token is backed by several coins on
    /// several chains — zUSD by USDT and USDC on four of them — so a burn names *which* coin it
    /// wants released, and the outbound message carries that pair. It is bounded by that
    /// backing's own locked amount, not by the token's whole supply
    /// (`TokenError::InsufficientBacking`).
    BridgeBurn {
        asset_bundle: Bundle,
        asset: u32,
        amount: u64,
        relayer_fee: u64,
        to_chain: u16,
        token: [u8; 32],
        to: [u8; 32],
    },
    /// Block aggregation (spec §2.2): register the sender as an aggregator. Rides a bundle
    /// whose `burn` equals the genesis bond — the only aggregation action that carries one.
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
    /// — the **whole** `initial`, not just its amount, because this action is unsigned and its
    /// fee bundle is not bound to it (see [`InitialMint`]) — so the same declaration twice is the
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
            _ => None,
        }
    }
}

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
            nullifiers: &'a [Word8; 2],
            commitments: &'a [Word8; 2],
            fee: u64,
            burn: u64,
            asset: u32,
            time: u32,
            envelopes: &'a [Envelope; 2],
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
            burn: b.burn,
            asset: b.asset,
            time: b.time,
            envelopes: &b.envelopes,
            proof_hash: crate::notes::pruned_proof_hash(&b.proof).unwrap_or_else(|| Hash::digest(&b.proof)),
        });
        let view = TxView { chain_id: self.chain_id, bundle, action: &self.action };
        Hash::digest_domain(b"rand-txid-2", &bincode::serialize(&view).expect("Transaction serializes"))
    }

    /// Wire size, used for block byte accounting.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// The bundle's fee, or zero for a bundle-less transaction.
    pub fn fee(&self) -> u64 {
        self.bundle.as_ref().map_or(0, |b| b.fee)
    }

    /// The nullifiers this transaction spends: the fee bundle's, then — for a `BridgeBurn` —
    /// the asset bundle's, which are spent by the same transaction and must be just as unique.
    pub fn nullifiers(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.nullifiers.to_vec());
        if let Action::BridgeBurn { asset_bundle, .. } = &self.action {
            v.extend_from_slice(&asset_bundle.nullifiers);
        }
        v
    }

    /// Every note commitment this transaction creates: the bundle's two output slots in order,
    /// then a mint's note, then — for a `BridgeBurn` — the asset bundle's two slots.
    ///
    /// A `Withdraw`'s and a `BridgeAttest`'s deposit notes are deliberately absent — and so are
    /// RPL's two minted ones, a `TokenMint`'s and a `RegisterToken`'s `initial`: their commitment
    /// is not carried on the wire at all, it is computed by the ledger from the action's `r` and
    /// the amount it is paying out (spec §7). `Ledger::derived_commitment` is where a caller that
    /// needs them — the mempool's conflict index — gets them, and the node's `created_notes` is
    /// where the note index recomputes them for a committed block.
    pub fn commitments(&self) -> Vec<Word8> {
        let mut v: Vec<Word8> = self.bundle.as_ref().map_or(Vec::new(), |b| b.commitments.to_vec());
        match &self.action {
            Action::Mint { cm, .. } => v.push(*cm),
            Action::BridgeBurn { asset_bundle, .. } => v.extend_from_slice(&asset_bundle.commitments),
            _ => {}
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
            nullifiers: [[2; 8], [3; 8]],
            commitments: [[4; 8], [5; 8]],
            fee: 1_000_000,
            burn: 0,
            asset: 0,
            time: 9,
            envelopes: [env(), env()],
            proof: vec![9; 40],
        }
    }

    /// The golden encodings (final review, item 3): the byte-vector fields that ride the CBOR
    /// sync wire serialize as bytes, not as a sequence of integers. Bincode writes both forms
    /// identically (a u64 length, then the bytes), so `encode()` and `hash()` of these fixtures
    /// were captured at b9026b3, *before* that change, and must never move: the transaction id
    /// and the consensus encoding are the same on either side of it.
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
        "000300000003000000040000000400000004000000040000000400000004000000040000000400000005000000050000",
        "0005000000050000000500000005000000050000000500000040420f0000000000000000000000000000000000090000",
        "000800000000000000010101010101010104000000000000000202020204000000000000000303030310000000000000",
        "000404040404040404040404040404040408000000000000000101010101010101040000000000000002020202040000",
        "000000000003030303100000000000000004040404040404040404040404040404280000000000000009090909090909",
        "090909090909090909090909090909090909090909090909090909090909090909030000000707070707070707070707",
        "0707070707070707070707070707070707070707070001000000000000000102030405060708090a0b0c0d0e0f101112",
        "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142",
        "434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172",
        "737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2",
        "a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2",
        "d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff010500",
        "000000000000a1a1a1a1a10300000000000000b2b2b20200000000000000c3c30700000000000000d4d4d4d4d4d4d4",
    );
    const CALL_ID: &str = "4596e09bc519323974a0ac14f4679f70c6c6a66e141e7a1d47f44fc7d42f9a97";
    const ATTEST_ENCODING_BLAKE3: &str = "ad26f941abb2c5e3d320a4206dd9e8b3cd6e6de2dd5df3242d3379c20ba16642";
    const ATTEST_ID: &str = "ad1d1bb94f68f475e5b98cc49392f838d8ca0b569da812d747bd2f8350c6101a";
    const AGGREGATE_ENCODING_BLAKE3: &str = "c5f06333b3d6f2e744f6edeb66b612723c1bc4fcf7f98fd8249b40226af64d64";
    const AGGREGATE_ID: &str = "a25cb696d9d92cecb09c0b4d4c818ae30c6e29ecda1d73944395843e3f350e0f";

    #[test]
    fn transactions_roundtrip_and_hash_their_full_encoding() {
        let tx = Transaction::shielded(7, bundle(), Action::None);
        let back = Transaction::decode(&tx.encode()).unwrap();
        assert_eq!(back, tx);
        assert_eq!(tx.fee(), 1_000_000);
        assert_eq!(tx.nullifiers(), vec![[2; 8], [3; 8]]);
        assert_eq!(tx.commitments(), vec![[4; 8], [5; 8]]);
        let mut other = tx.clone();
        other.bundle.as_mut().unwrap().fee += 1;
        assert_ne!(other.hash(), tx.hash());
    }

    /// Exactly three actions ride without a bundle, and each names itself for the shape error
    /// admission reports when one arrives with a bundle anyway.
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

    /// A burn spends and creates through two bundles, so both must be visible to the mempool's
    /// and the ledger's uniqueness checks. A withdraw's deposit is not on the wire at all.
    #[test]
    fn a_bridge_burn_reports_both_bundles_and_a_withdraw_reports_no_deposit() {
        let mut asset_bundle = bundle();
        asset_bundle.nullifiers = [[6; 8], [7; 8]];
        asset_bundle.commitments = [[8; 8], [9; 8]];
        asset_bundle.asset = 3;
        asset_bundle.burn = 500;
        let burn = Transaction::shielded(
            7,
            bundle(),
            Action::BridgeBurn { asset_bundle, asset: 3, amount: 400, relayer_fee: 100, to_chain: 2, token: [7; 32], to: [1; 32] },
        );
        assert_eq!(burn.nullifiers(), vec![[2; 8], [3; 8], [6; 8], [7; 8]]);
        assert_eq!(burn.commitments(), vec![[4; 8], [5; 8], [8; 8], [9; 8]]);
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
            },
        );
        assert_eq!(a.commitments(), vec![[4; 8], [5; 8]]);
        assert_eq!(a.nullifiers(), vec![[2; 8], [3; 8]]);
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
        let attest = |r: Word8, cms: [Word8; 2]| {
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
                },
            )
        };
        let one = attest([5; 8], [[4; 8], [5; 8]]);
        let two = attest([6; 8], [[40; 8], [50; 8]]);
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
}
