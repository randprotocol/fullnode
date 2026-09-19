//! Limits and the v0 fee schedule for the shielded pool and confidential computation.

use crate::types::Action;

/// Largest program, in 32-bit words (16 KiB of code), on a chain whose genesis file does not set
/// `max_program_words` — every chain cut before v0.4, chain 12 included. The ledger holds the cap
/// its genesis gave it (`Ledger::max_program_words`); this is only the default.
pub const MAX_PROGRAM_WORDS: usize = 4096;
/// The largest `max_program_words` a genesis file may set: the zkVM's own limit. The CPU AIR
/// range-checks a program's word count to 16 bits (`rand_zkvm::machine::ProveError::ProgramTooLong`,
/// `isa::Program::from_flat_image`), so a longer program could be deployed and never called.
pub const MAX_PROGRAM_WORDS_LIMIT: usize = 65_535;
/// Largest proof accepted in a transaction.
///
/// Constraint set 5 (upstream `ffd9e1e`, milestone 4.2) restored the whitepaper's production FRI
/// profile — 80 queries, blowup 8, 20 proof-of-work bits — and with it the proof sizes the
/// whitepaper's parameter table implies: a keccak-free tier-10 proof measures ~1 202 416 bytes
/// and a tier-12 one ~1 252 338 bytes (upstream `research/docs/03-privacy.md`, measured on
/// `guests::fib`). The old 1 MiB cap rejected *every* production proof, so it is 2 MiB now.
///
/// 2 MiB is the smallest power-of-two cap above the measured sizes with room for the ~1%
/// run-to-run variation the hiding PCS's fresh per-proof entropy causes, and it is deliberately
/// *below* the ~3.11 MB a tier-10 proof that carries the optional keccak table costs: no guest
/// this chain deploys calls `SYS_KECCAK`, and admitting one at 4 MiB would put a single
/// transaction in reach of the whole block (see `MAX_BLOCK_BYTES`).
///
/// Re-measured at constraint set 6 (upstream `0200877`, the public input segment): the mandatory
/// `public` table and the cpu table's 51 new columns grow a keccak-free proof to 1 298 729 bytes at
/// tier 10 / 1 359 978 at tier 12 and the keccak-carrying one to 3 198 430 (`crates/randprotocol-zkvm`'s
/// `tests/e2e.rs::measure_production_profile_at_tier_10_and_12`, run `--ignored`). Both properties
/// above hold unchanged, so the cap does not move.
///
/// Since the call-limits change this is the *default*: a genesis file may set `max_proof_bytes`
/// (`MAX_PROOF_BYTES_MIN..=MAX_PROOF_BYTES_LIMIT`), and the ledger holds what it set
/// (`Ledger::max_proof_bytes`). Chain 12 and every chain without the field run this value.
pub const MAX_PROOF_BYTES: usize = 2 << 20;
/// The smallest `max_proof_bytes` a genesis file may set: 1 MiB, below every production proof.
pub const MAX_PROOF_BYTES_MIN: usize = 1 << 20;
/// The largest `max_proof_bytes` a genesis file may set: 32 MiB.
pub const MAX_PROOF_BYTES_LIMIT: usize = 32 << 20;
/// Largest bridge attestation accepted in a `BridgeAttest` transaction.
///
/// A real attestation is tiny: 6 envelope bytes, 66 per signature, a
/// 51-byte body header and a payload of 133 bytes (transfer) or
/// 5 + 20 * n (upgrade) — 520 bytes at the launch parameters (n = 6,
/// quorum 5). 16 KiB still admits a quorum of well over 200 guardians,
/// so it constrains nothing reachable while keeping an oversized blob
/// from buying decode and signature-recovery work at a zero fee.
pub const MAX_ATTESTATION_BYTES: usize = 16_384;
/// Transaction bytes per block. Under constraint set 5 a proof is ~1.2–1.3 MB (see
/// `MAX_PROOF_BYTES`), so 4 MiB admits **three** shielded transfers per block rather than the
/// nine the 27-query profile allowed.
///
/// Deliberately unchanged at 4 MiB: `docs/block-space.md` §5 records the decision. Raising the
/// cap buys throughput linearly and nothing else, while every validator pays the bandwidth and
/// the disk for it — a full 4 MiB block every ~2 s is already ~170 GB/day — and block-level
/// aggregation, not a bigger block, is the queued remedy (§6).
///
/// Since the call-limits change this is the *default*: a genesis file may set `max_block_bytes`
/// (`MAX_BLOCK_BYTES_MIN..=MAX_BLOCK_BYTES_LIMIT`, and at least `2 · max_proof_bytes +
/// BLOCK_PROOF_HEADROOM`), and the ledger holds what it set (`Ledger::max_block_bytes`).
pub const MAX_BLOCK_BYTES: usize = 4 << 20;
/// The smallest `max_block_bytes` a genesis file may set: today's 4 MiB.
pub const MAX_BLOCK_BYTES_MIN: usize = 4 << 20;
/// The largest `max_block_bytes` a genesis file may set: 64 MiB.
pub const MAX_BLOCK_BYTES_LIMIT: usize = 64 << 20;
/// What a block must hold beyond two worst-case proofs (the fee bundle's and a call's) when a
/// genesis file sets either size cap: `max_block_bytes ≥ 2 · max_proof_bytes + 1 MiB`, so the
/// largest proof the proof cap admits is one a transaction can actually carry.
pub const BLOCK_PROOF_HEADROOM: usize = 1 << 20;
/// The largest `max_call_envelope_bytes` a genesis file may set: 1 MiB. The smallest is today's
/// cap, [`crate::types::actions::MAX_CALL_ENVELOPE_BYTES`] (18 432), which stays the default.
pub const MAX_CALL_ENVELOPE_BYTES_LIMIT: usize = 1 << 20;
/// A program's public input, in words, on a chain whose genesis file does not set
/// `max_program_public_words`: none, today's behaviour.
pub const MAX_PROGRAM_PUBLIC_WORDS: usize = 0;
/// The largest `max_program_public_words` a genesis file may set: the zkVM's own limit, the
/// public table's 16-bit length (`rand_zkvm::machine::ProveError::PublicTooLong`).
pub const MAX_PROGRAM_PUBLIC_WORDS_LIMIT: usize = 65_535;
/// Transactions per block.
pub const MAX_BLOCK_TXS: usize = 2_000;
/// zkVM tiers (log2 of the CPU table height).
pub const MIN_TIER: u8 = 10;
pub const MAX_TIER: u8 = 20;

/// What every bundle pays before its action's own floor (0.001 RAND, spec §7 item 3).
pub const BUNDLE_BASE: u64 = 1_000_000;
/// What a `BridgeBurn` pays, all in: 0.01 RAND. It covers the bundle base for each of its two
/// bundles and the bridge's share of the validators' infrastructure. A deposit
/// (`BridgeAttest`) carries no such charge on purpose: a depositor holds no RAND until the
/// bridge has delivered their first note, so the bridge's RAND fee is collected on the way out.
pub const BRIDGE_BURN_FEE: u64 = 10 * BUNDLE_BASE;
pub const DEPLOY_PER_WORD: u64 = 100_000;
pub const CALL_BASE: u64 = 1_000_000;
pub const CALL_PER_TIER_STEP: u64 = 100_000;

/// Minimum fee to deploy a program of `words` words.
pub fn deploy_fee(words: usize) -> u64 {
    DEPLOY_PER_WORD * words as u64
}

/// The call bytes that ride free (spec §7): today's two caps, a 2 MiB proof and an 18 432-byte
/// input envelope. Every call a chain without the call limits admits is at or under this, so it
/// costs exactly what it cost before the byte term existed.
pub const CALL_FREE_BYTES: usize = 2_097_152 + 18_432;
/// What each KiB (or part of one) of call bytes past [`CALL_FREE_BYTES`] adds to a call's fee:
/// 1 000 base units, 0.000001 RAND per KiB (`UNITS_PER_RAND` = 10⁹). A testnet economics knob, not a security bound — the block
/// cap is the bound — so it is kept small (spec §7).
pub const CALL_PER_KIB: u64 = 1_000;

/// Minimum fee for a call proven at `tier` (10, 12, ..., 20) that carries `bytes` of call proof
/// and input envelope ([`call_bytes`]):
///
/// `CALL_BASE + CALL_PER_TIER_STEP·step(tier) + CALL_PER_KIB·ceil(max(0, bytes − CALL_FREE_BYTES)/1024)`
///
/// The byte term is what keeps a proof the raised `max_proof_bytes` admits from buying block
/// space at the price of a small one; at or under the allowance it is zero.
pub fn call_fee(tier: u8, bytes: usize) -> u64 {
    let steps = (tier.saturating_sub(MIN_TIER) / 2) as u64;
    let kib = bytes.saturating_sub(CALL_FREE_BYTES).div_ceil(1024) as u64;
    (CALL_BASE + CALL_PER_TIER_STEP * steps).saturating_add(CALL_PER_KIB.saturating_mul(kib))
}

/// The bytes a call's fee is charged on: its proof and its input envelope, each measured the way
/// its own cap measures it (`proof.len()`, [`crate::types::CallEnvelope::len`]).
pub fn call_bytes(proof: &[u8], envelope: Option<&crate::types::CallEnvelope>) -> usize {
    proof.len() + envelope.map_or(0, |e| e.len())
}

/// The floor a bundle must pay before the action's proof is verified. A call's tier-dependent
/// part is only known once its proof has been decoded, so it is charged afterwards
/// (`Ledger::validate`); this floor is what keeps that work from being bought for nothing.
///
/// An action that rides without a bundle ([`Action::bundle_less`]) has nothing to pay a fee
/// *from*, so its floor is zero: a mint and an `Unbond` are free, and a `Withdraw` pays the base
/// out of the amount it withdraws instead (`ledger::staking`).
pub fn fee_floor(action: &Action) -> u64 {
    match action {
        Action::Mint { .. } | Action::Unbond { .. } | Action::Withdraw { .. } => 0,
        Action::None => BUNDLE_BASE,
        // Public words are charged like code words (spec §5): the chain stores both.
        Action::Deploy { words, public, .. } => BUNDLE_BASE + deploy_fee(words.len() + public.len()),
        Action::Call { .. } => BUNDLE_BASE + CALL_BASE,
        // A bond is the one staking action that rides on a bundle — the bundle is what burns the
        // stake out of the pool — so it pays the plain base like a transfer.
        Action::Bond { .. } => BUNDLE_BASE,
        // An attestation's decode and guardian signature recovery are cheap next to a STARK
        // verify, and the bundle base already covers the one bundle it carries. No bridge
        // charge on top: the relayer pays this one, for a depositor who has no RAND yet.
        Action::BridgeAttest { .. } => BUNDLE_BASE,
        // Spec §7 item 3 charges the bundle base "for every bundle", and a `BridgeBurn` is the
        // one transaction that carries two: the RAND fee bundle and the asset bundle inside
        // the action. Both are verified, so both are paid for — and by this bundle, because the
        // asset bundle's `fee` must be zero (the guest's "`asset != 0` => `fee = 0`" rule).
        // [`BRIDGE_BURN_FEE`] is those two bases plus the bridge's charge, which falls on the
        // burn because that is the one bridge transaction whose sender is sure to hold RAND.
        Action::BridgeBurn { .. } => BRIDGE_BURN_FEE,
        // Block aggregation: registering burns the genesis bond through its bundle, so the
        // bundle pays the plain base like a transfer or a `Bond`. The four bundle-less
        // aggregation actions have nothing to pay *from* (this function's own rule for
        // bundle-less actions): the aggregate's proving share is collected from the covered
        // bundles' excess, not from the author (spec §5.2, ruling R5).
        Action::RegisterAggregator { .. } => BUNDLE_BASE,
        Action::UnbondAggregator { .. }
        | Action::WithdrawAggregator { .. }
        | Action::SlashAggregator { .. }
        | Action::Aggregate { .. } => 0,
        // RPL (spec §4): each of the three rides one RAND fee bundle, so each pays the plain
        // base. A `RegisterToken` owes the registry's `registration_fee` on top — a *ledger*
        // fact, and this function has no ledger — so `ledger::tokens::validate` charges it
        // (`TokenError::RegistrationFeeTooLow`), the way a call's tier-dependent part is charged
        // once its proof has been decoded. Nothing here is a lower floor than that check, so a
        // transaction under the base is still refused at step 3, before the action is reached.
        Action::RegisterToken { .. } | Action::TokenMint { .. } | Action::SetAuthority { .. } => BUNDLE_BASE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_fee_is_linear_in_words() {
        assert_eq!(deploy_fee(0), 0);
        assert_eq!(deploy_fee(1), 100_000);
        assert_eq!(deploy_fee(256), 25_600_000);
    }

    #[test]
    fn fee_floor_adds_the_bundle_base() {
        assert_eq!(fee_floor(&Action::None), 1_000_000);
        assert_eq!(fee_floor(&Action::Deploy { base_pc: 0, words: vec![0x13; 10], public: vec![] }), 1_000_000 + 1_000_000);
        assert_eq!(
            fee_floor(&Action::Deploy { base_pc: 0, words: vec![0x13; 10], public: vec![7; 3] }),
            BUNDLE_BASE + deploy_fee(13),
            "public words pay DEPLOY_PER_WORD too"
        );
        assert_eq!(
            fee_floor(&Action::Call { program: crate::crypto::Hash::ZERO, proof: vec![], input_envelope: None }),
            2_000_000
        );
        assert_eq!(
            fee_floor(&Action::Mint {
                cm: [0; 8],
                pk: [0; 8],
                time: 0,
                r: [0; 8],
                envelope: crate::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] },
                amount: 5,
                minter: crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
                signature: crate::crypto::Signature::empty(),
            }),
            0
        );
    }

    fn env() -> crate::notes::Envelope {
        crate::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] }
    }

    /// A bond rides on the bundle that burns its stake, so it pays the base like a transfer; the
    /// two validator-signed actions ride bundle-less and have nothing to pay a fee from at all.
    #[test]
    fn only_bond_of_the_staking_actions_pays_the_bundle_base() {
        use crate::crypto::{Address, Signature};
        let v = Address([1; 32]);
        assert_eq!(fee_floor(&Action::Bond { validator: v, amount: 1, registration: None }), BUNDLE_BASE);
        for a in [
            Action::Unbond { validator: v, amount: 1, nonce: 0, signature: Signature::empty() },
            Action::Withdraw {
                validator: v,
                amount: 1,
                nonce: 0,
                time: 0,
                r: [0; 8],
                envelope: env(),
                signature: Signature::empty(),
            },
        ] {
            assert_eq!(fee_floor(&a), 0, "{a:?}");
            assert!(a.bundle_less().is_some(), "a zero floor is only for an action with no bundle: {a:?}");
        }
    }

    /// A `BridgeAttest` — one bundle, sent by a relayer for a depositor with no RAND — pays the
    /// plain base. A `BridgeBurn` pays the bridge's 0.01 RAND, which has to cover the base for
    /// both of its bundles (spec §7 item 3) out of the one bundle allowed a non-zero fee.
    #[test]
    fn a_burn_pays_the_bridge_fee_and_an_attest_only_the_base() {
        let b = crate::notes::Bundle {
            anchor: [0; 8],
            nullifiers: [[0; 8], [1; 8]],
            commitments: [[2; 8], [3; 8]],
            fee: 0,
            burn: 0,
            asset: 0,
            time: 0,
            envelopes: [env(), env()],
            proof: vec![],
        };
        let attest = Action::BridgeAttest {
            attestation: vec![],
            recipient: crate::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
            r: [0; 8],
            time: 0,
            asset: 1,
            envelope: env(),
        };
        assert_eq!(fee_floor(&attest), BUNDLE_BASE);
        let burn =
            Action::BridgeBurn { asset_bundle: b, asset: 1, amount: 1, relayer_fee: 0, to_chain: 2, token: [9; 32], to: [0; 32] };
        assert_eq!(fee_floor(&burn), BRIDGE_BURN_FEE);
        assert_eq!(BRIDGE_BURN_FEE, 10_000_000, "0.01 RAND");
        assert!(BRIDGE_BURN_FEE >= 2 * BUNDLE_BASE, "both bundles are still paid for");
    }

    /// The three RPL actions each ride one RAND fee bundle, so each pays the plain bundle base
    /// here. A registration owes the registry's `registration_fee` on top — a *ledger* fact this
    /// function has no way to read, so `ledger::tokens::validate` charges it
    /// (`TokenError::RegistrationFeeTooLow`), exactly as a call's tier-dependent part is charged
    /// after its proof is decoded.
    #[test]
    fn the_three_token_actions_pay_the_bundle_base() {
        use crate::ledger::tokens::MintAuthority;
        use crate::notes::ShieldedAddress;
        let pk = crate::crypto::Keypair::from_seed([1; 32]).unwrap().public_key().clone();
        let register = Action::RegisterToken {
            name: "Test Coin".into(),
            symbol: "TST".into(),
            decimals: 6,
            authority: MintAuthority::Key(pk.clone()),
            initial: None,
            salt: [3; 32],
            index: 1,
        };
        let mint = Action::TokenMint {
            asset: 1,
            amount: 5,
            recipient: ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] },
            r: [7; 8],
            time: 0,
            envelope: env(),
            nonce: 0,
            signature: crate::crypto::Signature::empty(),
        };
        let authority =
            Action::SetAuthority { asset: 1, new: Some(pk), nonce: 0, signature: crate::crypto::Signature::empty() };
        for a in [register, mint, authority] {
            assert_eq!(fee_floor(&a), BUNDLE_BASE, "{a:?}");
            assert!(a.bundle_less().is_none(), "every token action rides a RAND fee bundle: {a:?}");
        }
    }

    #[test]
    fn call_fee_steps_every_two_tiers() {
        assert_eq!(call_fee(10, 0), 1_000_000);
        assert_eq!(call_fee(12, 0), 1_100_000);
        assert_eq!(call_fee(20, 0), 1_500_000);
        assert_eq!(call_fee(0, 0), 1_000_000, "below MIN_TIER saturates");
    }

    /// Spec §7: the byte term charges only above today's two caps, so every call a chain-12
    /// ledger admits costs exactly what it cost before, and each KiB (or part of one) past the
    /// allowance adds `CALL_PER_KIB`.
    #[test]
    fn the_call_fee_charges_only_bytes_past_todays_allowance() {
        assert_eq!(CALL_FREE_BYTES, 2_097_152 + 18_432);
        assert_eq!(CALL_FREE_BYTES, MAX_PROOF_BYTES + crate::types::actions::MAX_CALL_ENVELOPE_BYTES);
        assert_eq!(CALL_PER_KIB, 1_000);
        // Today's schedule, by tier alone.
        let today = |tier: u8| CALL_BASE + CALL_PER_TIER_STEP * (tier.saturating_sub(MIN_TIER) / 2) as u64;
        for tier in [0u8, 10, 12, 14, 16, 18, 20] {
            for bytes in [0, 77, 1 << 20, CALL_FREE_BYTES - 1, CALL_FREE_BYTES] {
                assert_eq!(call_fee(tier, bytes), today(tier), "tier {tier}, {bytes} B");
            }
            assert_eq!(call_fee(tier, CALL_FREE_BYTES + 1), today(tier) + 1_000, "a part-KiB is a KiB");
            assert_eq!(call_fee(tier, CALL_FREE_BYTES + 1024), today(tier) + 1_000, "one KiB over adds 1 000");
            assert_eq!(call_fee(tier, CALL_FREE_BYTES + 1025), today(tier) + 2_000);
            assert_eq!(call_fee(tier, CALL_FREE_BYTES + (6 << 20)), today(tier) + 6 * 1024 * 1_000);
        }
        // Monotonic in both arguments.
        let mut last = 0;
        for bytes in (0..(40usize << 20)).step_by(4093) {
            let f = call_fee(12, bytes);
            assert!(f >= last, "{bytes} B: {f} < {last}");
            last = f;
        }
        for tier in MIN_TIER..MAX_TIER {
            assert!(call_fee(tier + 1, 5 << 20) >= call_fee(tier, 5 << 20));
        }
        // No overflow at the largest transaction any genesis can admit, or beyond.
        assert!(call_fee(MAX_TIER, usize::MAX) > call_fee(MAX_TIER, MAX_BLOCK_BYTES_LIMIT));
    }

    /// What the byte term counts: the call proof and the input envelope, measured the way their
    /// caps measure them.
    #[test]
    fn call_bytes_counts_the_proof_and_the_envelope() {
        let e = crate::types::CallEnvelope { kem_ct: vec![1; 1088], to_sender: vec![2; 60], to_auditor: vec![], body: vec![3; 100] };
        assert_eq!(call_bytes(&[0; 500], None), 500);
        assert_eq!(call_bytes(&[0; 500], Some(&e)), 500 + e.len());
        assert_eq!(call_bytes(&[], Some(&e)), 1248);
    }
}

/// The most bundles one `Aggregate` may cover, the genesis default (spec §3.3 — the measured
/// per-N economics set it: production N=1 provable on the ≥ 64 GB batch machine, N=2/N=3
/// arriving with the GPU numbers).
pub const MAX_COVERS_DEFAULT: u32 = 3;

/// The `Aggregate` action's wire cap (spec §3.1): the proof cap plus the covers, the
/// recomputed interface list's length bound, an envelope and fixed overhead. The rVM proof at
/// production is estimated well under the 2 MiB proof cap already (`circuits`' M5.2 record).
pub const MAX_AGGREGATE_BYTES: usize =
    MAX_PROOF_BYTES + MAX_COVERS_DEFAULT as usize * 32 + (4 + 1 + 34 * MAX_COVERS_DEFAULT as usize) * 8 + 4_400;

/// The sealing block's minted subsidy (spec §5.1): `subsidy_base` per sealed block, halving
/// every `halving_blocks`, zero from the 64th halving. `n` is the ledger's `sealed_blocks`
/// counter, incremented per included aggregate, so an idle chain does not consume the schedule.
pub fn subsidy(n: u64, cfg: &crate::ledger::aggregation::AggregationConfig) -> u64 {
    if n / cfg.halving_blocks >= 64 {
        0
    } else {
        cfg.subsidy_base >> (n / cfg.halving_blocks)
    }
}
