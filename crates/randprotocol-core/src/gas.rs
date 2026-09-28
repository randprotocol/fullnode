//! Limits and the v0 fee schedule for the shielded pool and confidential computation.

use crate::types::Action;
use serde::{Deserialize, Serialize};

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
/// What a `BridgeBurn` pays, all in: 0.01 RAND. It covers the bundle base of its one bundle and
/// the bridge's share of the validators' infrastructure. A deposit
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

/// Spec 2026-09-28 §3.1: what a `KECCAK` row costs in gas — its cpu row plus the 32 keccak-table
/// rows (2 612 columns) and 100 memory rows it pulls in, ≈ 189 cycle-equivalents, rounded up.
pub const KECCAK_GAS: u64 = 192;
/// Its sha256 twin: one row plus 64 rows of 466 columns, ≈ 66 cycle-equivalents, rounded down
/// to the block size.
pub const SHA256_GAS: u64 = 64;
/// Spec §3.3: the default price of one gas, 10⁻⁷ RAND.
pub const GAS_PRICE_DEFAULT: u64 = 100;
/// Spec §3.3: the default price of one KiB of call proof and envelope, from byte 0 — a bare
/// 1.25 MB proof is ≈ 1 000 000 units, today's `CALL_BASE` under another name.
pub const BYTE_PRICE_DEFAULT: u64 = 800;

/// The gas no run under this proof header can exceed (spec §3.2, controller ruling from the
/// constraint-set-8 final review): the tier's cycle budget, plus the Poseidon2 absorb
/// surcharge, plus `KECCAK_GAS − 1` for every permutation the declared keccak table could hold
/// (one 32-row block each, `0` = no table) and `SHA256_GAS − 1` for every compression of the
/// sha256 table (64-row blocks). Phase 0 charges exactly this; Phase 1's in-circuit meter
/// charges a declared limit at or under it.
///
/// The absorb surcharge: the cpu table's gas accumulator (§4.2's `w = 1 + 2·IS_HASH_BLOCK + …`)
/// charges `+2` on every `POSEIDON2` absorb row beyond the `+1` every row already costs. The
/// bound on how many absorb rows a tier can hold is the Poseidon2 *table's* own capacity, not a
/// count of cpu rows: `Tier::poseidon2_height(t) = 2^(t+2)` rows
/// (`crates/randprotocol-zkvm/src/machine.rs`'s `Tier::for_workload`, the ZH1 note) at
/// `poseidon2::BLOCK = 32` rows per permutation block, so a tier holds at most
/// `2^(t+2) / 32 = 2^(t−3)` permutations — each contributing one absorb row. So the most the
/// accumulator can run over the plain cycle count `2^t − 1` is `2 · 2^(t−3) = 2^(t−2)` — the
/// term this ceiling was previously missing.
pub fn gas_max(tier: u8, keccak_log_height: u8, sha256_log_height: u8) -> u64 {
    let tier = tier.clamp(MIN_TIER, MAX_TIER);
    let cycles = (1u64 << tier) - 1;
    let absorb_surcharge = 1u64 << (tier - 2);
    let blocks = |log_height: u8, block: u64| if log_height == 0 { 0 } else { (1u64 << log_height.min(40)) / block };
    cycles
        .saturating_add(absorb_surcharge)
        .saturating_add(blocks(keccak_log_height, 32).saturating_mul(KECCAK_GAS - 1))
        .saturating_add(blocks(sha256_log_height, 64).saturating_mul(SHA256_GAS - 1))
}

/// The one `bundle_gas_limit` a genesis `gas` section may name (final-review I3): the bundle
/// guest's header ceiling `gas_max(BUNDLE_PROOF_TIER, 0, 0)` = 20 479 — what every hidden-asset
/// bundle proof declares, since a bundle is pinned to tier 14 with no hash tables.
pub fn bundle_gas_limit_pin() -> u64 {
    gas_max(crate::types::BUNDLE_PROOF_TIER, 0, 0)
}

/// A node's gas prices (spec §4.1, Phase 0): admission policy, not a ledger rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasPolicy {
    /// Units per gas.
    pub gas_price: u64,
    /// Units per KiB (or part) of call proof plus input envelope, from byte 0.
    pub byte_price: u64,
}

impl GasPolicy {
    pub const DEFAULT: GasPolicy = GasPolicy { gas_price: GAS_PRICE_DEFAULT, byte_price: BYTE_PRICE_DEFAULT };

    /// The policy two prices name, or `None` — no policy at all — when both are zero.
    pub fn from_prices(gas_price: u64, byte_price: u64) -> Option<GasPolicy> {
        (gas_price != 0 || byte_price != 0).then_some(GasPolicy { gas_price, byte_price })
    }

    /// `BUNDLE_BASE + gas_price·gas + byte_price·⌈bytes/1024⌉`, saturating.
    pub fn gas_floor(&self, gas: u64, bytes: usize) -> u64 {
        let kib = bytes.div_ceil(1024) as u64;
        BUNDLE_BASE.saturating_add(self.gas_price.saturating_mul(gas)).saturating_add(self.byte_price.saturating_mul(kib))
    }

    /// What a call with this proof header and these bytes must pay under this policy: the gas
    /// floor over [`gas_max`], but never under the ledger's own `BUNDLE_BASE + call_fee` — the
    /// validity rule this policy sits above.
    pub fn call_floor(&self, tier: u8, keccak_log_height: u8, sha256_log_height: u8, bytes: usize) -> u64 {
        let ledger = BUNDLE_BASE.saturating_add(call_fee(tier, bytes));
        ledger.max(self.gas_floor(gas_max(tier, keccak_log_height, sha256_log_height), bytes))
    }
}

/// Phase 2 (spec §7.1): the two live prices a chain with `gas.dynamic` moves once per block.
/// Consensus state (`Ledger::gas_prices`): folded into the state root under `rand-state-7` when
/// the controller is on, persisted beside `META_SUPPLY`, replay-audited. Without `dynamic` the
/// section's own prices, which never move; without a section, zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasPrices {
    /// Units per gas.
    pub gas_price: u64,
    /// Units per KiB (or part) of call proof plus input envelope.
    pub byte_price: u64,
}

/// Spec §7.1's controller: `max(min, price + ⌊price·adjust_bps·(used − target)/(10 000·target)⌋)`
/// with `used` first capped at `2·target`, so `adjust_bps` is the largest one-block move in
/// either direction (an empty block moves the price down by exactly `adjust_bps`, a block at or
/// past twice the target up by exactly as much — a block's gas can exceed twice its target, its
/// bytes cannot when the target is half the cap). **Floor** division (`div_euclid` by a positive divisor, so a fall rounds away from zero:
/// −125.125 is −126), clamped to `0..=u64::MAX`, never below `min`. A zero `target` is read as
/// 1 (genesis refuses one; this only keeps the division defined). Integers only, so every
/// validator computes the same price.
///
/// The product is computed in i128 with saturating multiplies. It is exact whenever
/// `price·adjust_bps·|used − target| < 2^127`; with `adjust_bps ≤ 5 000` (genesis) that needs
/// `price·|used − target|` above ~2^114 — a price past ~2^60 units (≈10⁹ RAND per gas or per
/// KiB) with a 2^54 gap from target — before it departs from the exact formula, and past that
/// point it only caps the step. Beyond reach on any chain this code runs, and still
/// deterministic if reached.
pub fn next_price(price: u64, min: u64, used: u64, target: u64, adjust_bps: u32) -> u64 {
    let target = target.max(1);
    let used = used.min(target.saturating_mul(2));
    let target = target as i128;
    let delta = (price as i128)
        .saturating_mul(adjust_bps as i128)
        .saturating_mul(used as i128 - target)
        .div_euclid(10_000 * target);
    let next = (price as i128).saturating_add(delta).clamp(0, u64::MAX as i128) as u64;
    next.max(min)
}

/// A call's floor on a chain with a `gas` section (spec §3.3, §7.1, §8): `BUNDLE_BASE +
/// gas_price·gas_limit + byte_price·⌈bytes/1024⌉`, saturating. The declared limit prices the
/// call, not the header's `gas_max` ceiling — [`GasPolicy::call_floor`] is Phase 0's node-policy
/// twin, over a decoded proof header rather than a declared bound.
pub fn circuit_call_floor(gas_price: u64, byte_price: u64, gas_limit: u64, bytes: usize) -> u64 {
    let kib = bytes.div_ceil(1024) as u64;
    BUNDLE_BASE.saturating_add(gas_price.saturating_mul(gas_limit)).saturating_add(byte_price.saturating_mul(kib))
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
        // Spec §7 item 3 charges the bundle base "for every bundle", and since the hidden-asset
        // bundle (spec §3.7) every action carries exactly one: a burn spends the token from its
        // bundle's slots 0–1 and pays the RAND fee from slots 2–3 of the same proof. A
        // `BridgeBurn` pays [`BRIDGE_BURN_FEE`]: the base plus the bridge's charge, which falls
        // on the burn because that is the one bridge transaction whose sender is sure to hold
        // RAND. RPL's `TokenBurn` pays the plain base like any other one-bundle action.
        Action::BridgeBurn { .. } => BRIDGE_BURN_FEE,
        Action::TokenBurn { .. } => BUNDLE_BASE,
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
        // Bridge hardening B1: bundle-less, so nothing to pay from — a pause must work from a
        // wallet with no RAND. Neither can be spammed: each needs the pause key's signature or a
        // PQ guardian quorum over the current `pause_nonce`, and each spends it.
        Action::PauseMints { .. } | Action::UnpauseMints { .. } => 0,
        // Bridge hardening B4: each rides one RAND fee bundle, paid by the submitter, so each
        // pays the plain base here. A `RegisterBridgedToken` also owes the registry's
        // `registration_fee` — a ledger fact, charged by `ledger::bridge_gov::validate`
        // (`TokenError::RegistrationFeeTooLow`) the way `RegisterToken`'s is.
        Action::RegisterBridgedToken { .. } | Action::ListBacking { .. } => BUNDLE_BASE,
        // Bridge rules v2: bundle-less like the pause, and unspammable for the same reason — each
        // needs a PQ guardian quorum over the current `rotation_nonce`, and each spends it.
        Action::RotatePqGuardians { .. } | Action::RotatePauseKey { .. } => 0,
        // Genesis vesting: a claim and a revoke pay the base out of what they release, like a
        // `Withdraw`; a bond and an unbond from the lock move no value into or out of the pool.
        Action::ClaimVested { .. } | Action::RevokeVesting { .. } | Action::BondVested { .. } | Action::UnbondVested { .. } => 0,
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

    /// Spec §7 item 3 charges the bundle base per *bundle*, and every action carries one (the
    /// hidden-asset bundle, spec §3.7). A `BridgeAttest` — sent by a relayer for a depositor with
    /// no RAND — pays the plain base. A `BridgeBurn` pays the bridge's 0.01 RAND. RPL's
    /// `TokenBurn` is single-bundle now and pays the plain base, no longer twice.
    #[test]
    fn a_burn_pays_the_bridge_fee_and_an_attest_and_a_token_burn_only_the_base() {
        let attest = Action::BridgeAttest {
            attestation: vec![],
            recipient: crate::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![] },
            r: [0; 8],
            time: 0,
            asset: 1,
            envelope: env(),
            pq_signatures: Vec::new(),
        };
        assert_eq!(fee_floor(&attest), BUNDLE_BASE);
        let burn = Action::BridgeBurn { asset: 1, amount: 1, relayer_fee: 0, to_chain: 2, token: [9; 32], to: [0; 32] };
        assert_eq!(fee_floor(&burn), BRIDGE_BURN_FEE);
        assert_eq!(BRIDGE_BURN_FEE, 10_000_000, "0.01 RAND");
        assert!(BRIDGE_BURN_FEE >= BUNDLE_BASE, "its one bundle is paid for");
        let token_burn = Action::TokenBurn { asset: 1, amount: 1 };
        assert_eq!(fee_floor(&token_burn), BUNDLE_BASE, "one bundle, one base");
        assert!(token_burn.bundle_less().is_none(), "it rides a bundle");
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

    /// Spec 2026-09-28 §3.2 (controller ruling, constraint-set-8 final review): the ceiling a
    /// proof header implies — the tier's cycle budget, plus the Poseidon2 absorb surcharge
    /// (`2^(t−2)`: every absorb row beyond its cycle costs `+2`, bounded by the Poseidon2
    /// table's own capacity of `2^(t−3)` permutation slots — `gas_max`'s doc comment — not a
    /// cpu-row count), plus the weight of every permutation and compression the declared hash
    /// tables could hold.
    #[test]
    fn gas_max_is_the_headers_ceiling() {
        assert_eq!(gas_max(10, 0, 0), 1_279);
        assert_eq!(gas_max(20, 0, 0), 1_310_719);
        // One keccak block (2^5 rows = 1 permutation) adds KECCAK_GAS − 1 beyond its cycle.
        assert_eq!(gas_max(10, 5, 0), 1_279 + 191);
        // One sha256 block (2^6 rows = 1 compression) adds SHA256_GAS − 1.
        assert_eq!(gas_max(10, 0, 6), 1_279 + 63);
        // The call caps: tier 14, keccak 2^12 (128 perms), sha256 2^13 (128 comps).
        assert_eq!(gas_max(14, 12, 13), 20_479 + 128 * 191 + 128 * 63);
        // Below MIN_TIER clamps up; above MAX_TIER clamps down.
        assert_eq!(gas_max(0, 0, 0), gas_max(10, 0, 0));
        assert_eq!(gas_max(99, 0, 0), gas_max(20, 0, 0));
    }

    /// Spec §3.3's calibration table, base included, and the rule that the policy floor never
    /// undercuts the ledger's validity floor.
    #[test]
    fn the_policy_floor_is_the_larger_of_the_two_floors() {
        let p = GasPolicy::DEFAULT;
        // tier-10 fib-sized, 1.30 MB: bytes 1 270 KiB · 800 = 1 016 000, gas 1 279 · 100.
        assert_eq!(p.call_floor(10, 0, 0, 1_300_000), BUNDLE_BASE + 127_900 + 1_016_000);
        // tier 20, 1.45 MB: 1 310 719 · 100 + 1 417 KiB · 800 (1 450 000 B is 16 B into its
        // 1 417th KiB, so the "or part of one" rule rounds up from 1 450 000 / 1024 = 1416.015625).
        assert_eq!(p.call_floor(20, 0, 0, 1_450_000), BUNDLE_BASE + 131_071_900 + 1_133_600);
        // A 32 MiB proof at tier 10: the old schedule's byte term is the higher floor.
        let big = 32 << 20;
        let old = BUNDLE_BASE + call_fee(10, big);
        assert!(p.gas_floor(gas_max(10, 0, 0), big) < old);
        assert_eq!(p.call_floor(10, 0, 0, big), old);
        // Zero bytes still pays the base and the gas.
        assert_eq!(p.gas_floor(1, 0), BUNDLE_BASE + 100);
        // Every call at every tier pays at least the old floor.
        for tier in [10u8, 12, 14, 16, 18, 20] {
            for bytes in [0usize, 1_300_000, 3_200_000, 8 << 20] {
                assert!(p.call_floor(tier, 0, 0, bytes) >= BUNDLE_BASE + call_fee(tier, bytes), "tier {tier} {bytes} B");
            }
        }
    }

    /// Spec §3.3's table row at 100/800: `BUNDLE_BASE + 100·3 000 + 800·⌈1 300 000/1024⌉`
    /// (1 300 000 B is 1 270 KiB, rounding up).
    #[test]
    fn circuit_call_floor_prices_the_declared_limit() {
        assert_eq!(circuit_call_floor(100, 800, 3_000, 1_300_000), BUNDLE_BASE + 300_000 + 1_016_000);
        // Zero bytes still pays the base and the gas term alone.
        assert_eq!(circuit_call_floor(100, 800, 0, 0), BUNDLE_BASE);
        // Saturates rather than overflows at absurd inputs.
        assert_eq!(circuit_call_floor(u64::MAX, u64::MAX, u64::MAX, usize::MAX), u64::MAX);
    }

    #[test]
    fn from_prices_is_none_only_when_both_are_zero() {
        assert_eq!(GasPolicy::from_prices(0, 0), None);
        assert_eq!(GasPolicy::from_prices(100, 0), Some(GasPolicy { gas_price: 100, byte_price: 0 }));
        assert_eq!(GasPolicy::from_prices(0, 800), Some(GasPolicy { gas_price: 0, byte_price: 800 }));
        assert_eq!(GasPolicy::from_prices(100, 800), Some(GasPolicy::DEFAULT));
    }

    /// Review focus 5: the largest header times the largest price saturates, never wraps.
    #[test]
    fn the_policy_saturates() {
        let p = GasPolicy { gas_price: u64::MAX, byte_price: u64::MAX };
        assert_eq!(p.gas_floor(gas_max(20, 20, 20), usize::MAX), u64::MAX);
        assert_eq!(p.call_floor(20, 20, 20, usize::MAX), u64::MAX);
        assert_eq!(gas_max(20, 255, 255), gas_max(20, 40, 40), "a height past 40 is clamped");
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
    MAX_PROOF_BYTES + MAX_COVERS_DEFAULT as usize * 32 + (4 + 1 + crate::types::pv::NUM * MAX_COVERS_DEFAULT as usize) * 8 + 4_400;

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

/// Genesis `gas` (design 2026-09-28 §4.2, §4.3, §7.1): a chain's declared prices, the bundle's
/// flat gas limit, and how gas is metered. A genesis parameter like `max_program_words` — outside
/// the state root and `Ledger`'s equality, restored by `reload_ledger` on every restart — bound
/// into the genesis hash only when the section is present, so a chain without one hashes
/// byte-for-byte as before. Unknown keys are refused (`deny_unknown_fields`): a misspelled
/// `dynamic` must not quietly mean fixed prices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasConfig {
    /// Units of RAND per gas (spec §3.1's unit; §3.3's default is [`GAS_PRICE_DEFAULT`]). A
    /// decimal string in the file, like every other genesis amount.
    #[serde(with = "crate::ledger::staking::amount_string")]
    pub gas_price: u64,
    /// Units of RAND per KiB (or part of one) of call proof and input envelope, from byte 0.
    #[serde(with = "crate::ledger::staking::amount_string")]
    pub byte_price: u64,
    /// The bundle guest's flat gas (spec §4.3): every bundle proof's declared `GAS_LIMIT` must
    /// equal this constant exactly, or the proof is refused. Must be [`bundle_gas_limit_pin`],
    /// `20 479` (`gas_max(14, 0, 0)` = `(2¹⁴ − 1) + 2¹²`) for today's tier-14 guest — `check`
    /// refuses anything else.
    pub bundle_gas_limit: u64,
    /// How gas is metered on this chain. `Circuit` (spec §4.2) is the only value the chain
    /// accepts today; the field exists so a later metering scheme has somewhere to be named.
    pub metering: GasMetering,
    /// Phase 2 (spec §7.1): the dynamic price controller. Absent means the fixed prices above
    /// never move.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicGas>,
}

/// How a chain meters gas (`GasConfig::metering`). Only `Circuit` — the in-circuit meter, spec
/// §4.2 — is accepted; the enum exists so a later scheme has a name to add beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GasMetering {
    Circuit,
}

/// Phase 2 (spec §7.1): the parameters of the per-block price controller. State derived from
/// this section (the live `gas_price`/`byte_price`) lives on the ledger, not here — this is only
/// the genesis file's declaration of how that state starts and moves. Unknown keys are refused,
/// as in [`GasConfig`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicGas {
    /// The block-bytes figure the controller targets: `byte_price` falls when a block is under
    /// this and rises when it is over. Must be `1..=max_block_bytes` (today's default when the
    /// genesis does not set one, [`MAX_BLOCK_BYTES`]); by convention half the chain's cap
    /// (chain 18: 10 485 760 of 20 MiB), so a full block is exactly twice the target.
    pub target_block_bytes: u64,
    /// The block-gas figure the controller targets, the same way for `gas_price`. Must be `> 0`.
    pub target_block_gas: u64,
    /// The largest one-block move, in basis points of the current price, in either direction
    /// (spec §7.1's formula; [`next_price`] caps `used` at `2·target`, so no block moves a price
    /// further). `1..=5000` (0.01 %..=50 % a block).
    pub adjust_bps: u32,
    /// The floor `gas_price` never falls under. Must be `<= gas_price` — a genesis file cannot
    /// declare a starting price its own floor already exceeds.
    #[serde(with = "crate::ledger::staking::amount_string")]
    pub min_gas_price: u64,
    /// The floor `byte_price` never falls under, the same way. Must be `<= byte_price`.
    #[serde(with = "crate::ledger::staking::amount_string")]
    pub min_byte_price: u64,
}

impl GasConfig {
    /// Every rule a `gas` section has to meet before it can seed a chain (spec §4.2, §4.3, §7.1).
    /// `max_block_bytes` is the ledger's effective cap — the genesis file's own
    /// `max_block_bytes`, or [`MAX_BLOCK_BYTES`] when it does not set one — which is what bounds
    /// `dynamic.target_block_bytes`.
    pub fn check(&self, max_block_bytes: usize) -> Result<(), String> {
        if self.gas_price == 0 {
            return Err("gas_price must be greater than 0".into());
        }
        if self.byte_price == 0 {
            return Err("byte_price must be greater than 0".into());
        }
        // Every bundle proof declares its header's ceiling (spec §4.3), and a bundle is pinned to
        // one tier, so any other value names a chain on which no bundle is ever admitted.
        let pin = bundle_gas_limit_pin();
        if self.bundle_gas_limit != pin {
            return Err(format!(
                "bundle_gas_limit {} must be {pin}, the tier-{} bundle guest's ceiling gas_max({}, 0, 0): \
                 every bundle proof declares exactly that",
                self.bundle_gas_limit,
                crate::types::BUNDLE_PROOF_TIER,
                crate::types::BUNDLE_PROOF_TIER
            ));
        }
        if let Some(d) = &self.dynamic {
            if d.adjust_bps == 0 || d.adjust_bps > 5000 {
                return Err(format!("adjust_bps {} is outside 1..=5000", d.adjust_bps));
            }
            if d.target_block_bytes == 0 || d.target_block_bytes as usize > max_block_bytes {
                return Err(format!(
                    "target_block_bytes {} must be 1..={max_block_bytes} (the chain's max_block_bytes)",
                    d.target_block_bytes
                ));
            }
            if d.target_block_gas == 0 {
                return Err("target_block_gas must be greater than 0".into());
            }
            if d.min_gas_price > self.gas_price {
                return Err(format!("min_gas_price {} cannot exceed the starting gas_price {}", d.min_gas_price, self.gas_price));
            }
            if d.min_byte_price > self.byte_price {
                return Err(format!("min_byte_price {} cannot exceed the starting byte_price {}", d.min_byte_price, self.byte_price));
            }
            // A price with `price·adjust_bps < 10 000` can never rise: a full step up floors to 0
            // (`next_price`). Every price stays at or above its floor, so a floor that meets this
            // keeps the controller able to lift every price it can reach.
            if (d.min_gas_price as u128) * (d.adjust_bps as u128) < 10_000 {
                return Err(format!(
                    "min_gas_price {} · adjust_bps {} is under 10 000: a price there could never rise",
                    d.min_gas_price, d.adjust_bps
                ));
            }
            if (d.min_byte_price as u128) * (d.adjust_bps as u128) < 10_000 {
                return Err(format!(
                    "min_byte_price {} · adjust_bps {} is under 10 000: a price there could never rise",
                    d.min_byte_price, d.adjust_bps
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod gas_config_tests {
    use super::*;

    fn ok() -> GasConfig {
        GasConfig { gas_price: 100, byte_price: 800, bundle_gas_limit: 20_479, metering: GasMetering::Circuit, dynamic: None }
    }

    #[test]
    fn a_well_formed_config_checks_clean() {
        assert!(ok().check(MAX_BLOCK_BYTES).is_ok());
        let d = DynamicGas {
            target_block_bytes: 2 << 20,
            target_block_gas: 1 << 18,
            adjust_bps: 1250,
            min_gas_price: 100,
            min_byte_price: 800,
        };
        let mut g = ok();
        g.dynamic = Some(d);
        assert!(g.check(MAX_BLOCK_BYTES).is_ok());
    }

    #[test]
    fn zero_prices_and_a_zero_limit_are_refused() {
        assert!(GasConfig { gas_price: 0, ..ok() }.check(MAX_BLOCK_BYTES).unwrap_err().contains("gas_price"));
        assert!(GasConfig { byte_price: 0, ..ok() }.check(MAX_BLOCK_BYTES).unwrap_err().contains("byte_price"));
        assert!(GasConfig { bundle_gas_limit: 0, ..ok() }.check(MAX_BLOCK_BYTES).unwrap_err().contains("bundle_gas_limit"));
        assert!(GasConfig { bundle_gas_limit: 20_478, ..ok() }.check(MAX_BLOCK_BYTES).unwrap_err().contains("20479"), "only the pin");
        assert_eq!(bundle_gas_limit_pin(), 20_479);
    }

    #[test]
    fn the_dynamic_controller_is_bounded() {
        let base = DynamicGas { target_block_bytes: 2 << 20, target_block_gas: 1 << 18, adjust_bps: 1250, min_gas_price: 100, min_byte_price: 800 };
        let bad = |d: DynamicGas| -> String {
            let mut g = ok();
            g.dynamic = Some(d);
            g.check(MAX_BLOCK_BYTES).unwrap_err()
        };
        assert!(bad(DynamicGas { adjust_bps: 0, ..base.clone() }).contains("adjust_bps"));
        assert!(bad(DynamicGas { adjust_bps: 5001, ..base.clone() }).contains("adjust_bps"));
        // A price with price·adjust_bps < 10 000 can never rise (the step floors to 0), so a floor
        // that low would let a price sink to where the controller can no longer lift it.
        assert!(bad(DynamicGas { adjust_bps: 99, ..base.clone() }).contains("min_gas_price"), "100 · 99 < 10 000");
        assert!(bad(DynamicGas { adjust_bps: 12, ..base.clone() }).contains("min_gas_price"));
        let mut low_byte = ok();
        low_byte.byte_price = 7;
        low_byte.dynamic = Some(DynamicGas { min_byte_price: 7, adjust_bps: 1250, ..base.clone() });
        assert!(low_byte.check(MAX_BLOCK_BYTES).unwrap_err().contains("min_byte_price"), "7 · 1250 < 10 000");
        let mut edge = ok();
        edge.dynamic = Some(DynamicGas { adjust_bps: 100, min_byte_price: 800, ..base.clone() });
        assert!(edge.check(MAX_BLOCK_BYTES).is_ok(), "100 · 100 = 10 000 exactly can rise");
        assert!(bad(DynamicGas { target_block_bytes: 0, ..base.clone() }).contains("target_block_bytes"));
        assert!(bad(DynamicGas { target_block_bytes: (MAX_BLOCK_BYTES as u64) + 1, ..base.clone() }).contains("target_block_bytes"));
        assert!(bad(DynamicGas { target_block_gas: 0, ..base.clone() }).contains("target_block_gas"));
        assert!(bad(DynamicGas { min_gas_price: 101, ..base.clone() }).contains("min_gas_price"), "the floor cannot exceed the starting price");
        assert!(bad(DynamicGas { min_byte_price: 801, ..base.clone() }).contains("min_byte_price"));
    }

    /// Spec §7.1: price' = max(min, price + price·adjust·(used − target)/(10 000·target)).
    #[test]
    fn the_controller_moves_prices_by_fullness() {
        let t = 2u64 << 20;
        assert_eq!(next_price(800, 800, t, t, 1250), 800, "at target: unchanged");
        assert_eq!(next_price(800, 800, 0, t, 1250), 800, "empty block at the floor stays at the floor");
        assert_eq!(next_price(1_000, 800, 0, t, 1250), 875, "empty block: −12.5 %");
        assert_eq!(next_price(1_001, 800, 0, t, 1250), 875, "floor division: −125.125 floors to −126, not −125");
        assert_eq!(next_price(1_000, 800, 2 * t, t, 1250), 1_125, "twice the target: +12.5 %");
        // `used` is capped at twice the target, so `adjust_bps` is the largest one-block move in
        // either direction: a block of gas three times the target (bytes cannot pass 2× a
        // half-cap target; gas can) moves the price exactly as far as one at twice the target.
        assert_eq!(next_price(1_000, 800, 3 * t, t, 1250), 1_125, "three times the target: capped at +12.5 %");
        assert_eq!(next_price(1_000, 800, u64::MAX, t, 1250), 1_125, "any overshoot: capped at +12.5 %");
        assert_eq!(next_price(1_000, 800, 2 * t + 1, t, 5000), 1_500, "just over twice the target at 50 %: +50 %, no more");
        assert_eq!(next_price(u64::MAX, 800, 2 * t, t, 5000), u64::MAX, "saturates");
        assert_eq!(next_price(100, 100, 0, 1 << 18, 1250), 100, "gas: floor holds");
    }
}
