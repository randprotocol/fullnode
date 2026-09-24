//! The bridge's Rand-only governance actions: B1's `PauseMints` and `UnpauseMints` (bridge
//! hardening spec §2) and B4's `RegisterBridgedToken` and `ListBacking` (spec §7) — the actions
//! the pause key or a PQ guardian quorum authorises without an attestation.
//!
//! **B1, the brake.** Neither action moves value. A pause flips
//! [`crate::bridge::BridgeState::mint_paused`] on — every transfer `BridgeAttest` is then refused
//! `MintsPaused` in `check_attest`, while burns and rotations stay open — and an unpause flips it
//! off. Both carry the bridge's `pause_nonce` and bump it, so neither message can be replayed;
//! each refuses the no-op (`AlreadyPaused`, `NotPaused`) rather than spend a nonce for nothing.
//! The asymmetry is the point: the one genesis `pause_key` can only pause (its message,
//! [`crate::bridge::gov::pause_message`], has no unpause twin it can sign), and lifting a pause
//! needs a PQ guardian quorum over [`crate::bridge::gov::unpause_message`], judged by exactly the
//! co-signature's five rules ([`crate::bridge::pq`]).
//!
//! **B4, listing after genesis.** A `RegisterBridgedToken` registers a `Bridge`-authority token at
//! the registry's next index (eight decimals on Rand, the genesis `mint_cap_per_day`) with its
//! first backing; a `ListBacking` adds a backing to one. Both carry `list_nonce` and bump it, both
//! pass the checks a genesis listing does (a registered emitter for the chain, a pair that backs
//! nothing yet, at most [`super::tokens::MAX_BACKINGS`] backings, source decimals ≤ 18, the
//! name/symbol rules), and both ride a RAND fee bundle their submitter pays — a registration owing
//! the registry's `registration_fee` on top of the base. The quorum is the authority, not the
//! payer. **List on Rand first, `setToken` on the endpoint second** (spec §7).
//!
//! **Bridge rules v2 (audit v4 BRG-14 / BR-4), gated on the genesis `bridge.rules_v2`.**
//! `RotatePqGuardians` replaces the whole PQ set and `RotatePauseKey` the pause key, each under a
//! PQ quorum of the *current* set over [`crate::bridge::gov::rotate_pq_message`] /
//! [`crate::bridge::gov::rotate_pause_message`] at the bridge's `rotation_nonce`, which both
//! spend. The new PQ set is held to the genesis rules — index-aligned with the current ECDSA set,
//! Dilithium2 keys, no duplicates, not the pause key — and the new pause key to its own (a
//! Dilithium2 key that is no guardian's). Bundle-less and fee-less like the pause. On a chain
//! without the section (chain 14) both are [`BridgeError::RulesV2Disabled`] before anything else
//! is read, so an old node's refusal of the unknown wire variant and a new node's refusal of the
//! action agree. Under the same gate a `RegisterBridgedToken` or `ListBacking` is refused
//! [`BridgeError::MintsPaused`] while minting is paused — after the nonce, before the quorum.
//!
//! Cheap before expensive, as everywhere in admission: the gate, the byte rules and the quorum's
//! structure (no signature work), the nonce and the state lookups, and the Dilithium2
//! verification last. Every refusal [`apply`] could make is made in [`validate`], so `apply` is
//! infallible on an admitted transaction — and two of them in one block are safe because block
//! application re-validates each against the ledger the ones before it left (the second's nonce
//! is stale).

use super::tokens::{
    bridged_asset_id, check_metadata, Backing, MintAuthority, TokenError, BRIDGE_DECIMALS,
    MAX_BACKING_DECIMALS,
};
use super::{Ledger, TxError};
use crate::bridge::gov::{list_message, pause_message, register_message, rotate_pause_message, rotate_pq_message, unpause_message};
use crate::bridge::pq::{check_pq_structure, verify_pq_message};
use crate::bridge::{BridgeError, BridgeState};
use crate::gas;
use crate::types::{Action, Transaction};

/// A registry refusal, reported the way the bridge's other registry verdicts are: through
/// [`BridgeError::Token`], since the action that hit it is the bridge's.
fn token(e: TokenError) -> TxError {
    TxError::Bridge(BridgeError::Token(e))
}

/// The two listing actions' shared state rules: the nonce, then — under bridge rules v2 — no
/// listing while minting is paused, then a registered emitter for the backing's chain.
fn check_listing(bridge: &BridgeState, nonce: u64, chain: u16) -> Result<(), TxError> {
    if nonce != bridge.list_nonce {
        return Err(TxError::Bridge(BridgeError::BadListNonce { expected: bridge.list_nonce, got: nonce }));
    }
    // Bridge rules v2 only: chain 14's ledger must keep accepting what it accepts today.
    if bridge.rules_v2.is_some() && bridge.mint_paused {
        return Err(TxError::Bridge(BridgeError::MintsPaused));
    }
    if !bridge.emitters.contains_key(&chain) {
        return Err(TxError::Bridge(BridgeError::NoEmitter { chain }));
    }
    Ok(())
}

/// The rotations' shared rules (bridge rules v2): the gate first — a chain without the section
/// refuses before it reads a byte — then the quorum's structure against the current PQ set, then
/// the nonce.
fn check_rotation(bridge: &BridgeState, nonce: u64, pq_signatures: &[crate::bridge::PqSignature]) -> Result<(), TxError> {
    if bridge.rules_v2.is_none() {
        return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
    }
    check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
    if nonce != bridge.rotation_nonce {
        return Err(TxError::Bridge(BridgeError::BadRotationNonce { expected: bridge.rotation_nonce, got: nonce }));
    }
    Ok(())
}

/// Spends one `rotation_nonce`: the last write of both rotations.
fn bump_rotation_nonce(bridge: &mut BridgeState) {
    bridge.rotation_nonce = bridge.rotation_nonce.saturating_add(1);
}

/// What a mis-routed action gets: only a routing mistake in `Ledger::validate_inner` can produce
/// one, and refusing is the safe answer.
const NOT_BRIDGE_GOV: TxError = TxError::UnsupportedAction("bridge governance");

/// The action step of admission (spec §7 step 7) for the bridge's governance actions.
pub(super) fn validate(ledger: &Ledger, tx: &Transaction, action: &Action) -> Result<(), TxError> {
    let bridge = || ledger.bridge().ok_or(TxError::Bridge(BridgeError::Disabled));
    match action {
        Action::PauseMints { nonce, signature } => {
            let bridge = bridge()?;
            let key = bridge.pause_key.as_ref().ok_or(TxError::Bridge(BridgeError::NoPauseKey))?;
            // The nonce first: a replayed pause is a replay whatever the flag now says.
            if *nonce != bridge.pause_nonce {
                return Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: bridge.pause_nonce, got: *nonce }));
            }
            if bridge.mint_paused {
                return Err(TxError::Bridge(BridgeError::AlreadyPaused));
            }
            // Last: one Dilithium2 verification, over the fixed-layout message for this chain.
            if !key.verify(&pause_message(tx.chain_id, *nonce), signature) {
                return Err(TxError::Bridge(BridgeError::BadPauseSignature));
            }
            Ok(())
        }
        Action::UnpauseMints { nonce, pq_signatures } => {
            let bridge = bridge()?;
            // The quorum's structure before anything that reads state or keys: count, index
            // order, index range, every length — the co-signature's rules 1-3.
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            if *nonce != bridge.pause_nonce {
                return Err(TxError::Bridge(BridgeError::BadPauseNonce { expected: bridge.pause_nonce, got: *nonce }));
            }
            if !bridge.mint_paused {
                return Err(TxError::Bridge(BridgeError::NotPaused));
            }
            // Rule 4 last: one verification per listed signature.
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &unpause_message(tx.chain_id, *nonce))
                .map_err(TxError::Bridge)
        }
        Action::RegisterBridgedToken { name, symbol, salt, chain, token: coin, decimals, nonce, pq_signatures } => {
            let bridge = bridge()?;
            let registry = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            // The bytes first: the registry's name/symbol rules at a bridged token's eight
            // decimals, the backing's source decimals, the quorum's structure.
            check_metadata(name, symbol, BRIDGE_DECIMALS).map_err(token)?;
            if *decimals > MAX_BACKING_DECIMALS {
                return Err(token(TokenError::BadBackingDecimals(*decimals)));
            }
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            // The state lookups: the nonce, the chain's emitter, the pair, the identity, room.
            check_listing(bridge, *nonce, *chain)?;
            if registry.bridged(*chain, coin).is_some() {
                return Err(token(TokenError::BackingTaken { chain: *chain }));
            }
            let id = bridged_asset_id(name, symbol, salt);
            if registry.get_by_id(&id).is_some() {
                return Err(token(TokenError::AlreadyRegistered(id)));
            }
            if registry.is_full() {
                return Err(token(TokenError::RegistryFull));
            }
            // The fee: the base `fee_floor` took at step 3, plus the registry's registration fee —
            // what any registration owes, whoever authorises it. Saturating, as `RegisterToken`'s.
            let min = gas::BUNDLE_BASE.saturating_add(registry.registration_fee);
            if tx.fee() < min {
                return Err(token(TokenError::RegistrationFeeTooLow { min, fee: tx.fee() }));
            }
            // Last: the quorum's Dilithium2 verifications over the fixed-layout message.
            let message = register_message(tx.chain_id, *nonce, name, symbol, salt, *chain, coin, *decimals)
                .expect("check_metadata bounds the name and the symbol well under 255 bytes");
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &message).map_err(TxError::Bridge)
        }
        Action::ListBacking { token_index, chain, token: coin, decimals, nonce, pq_signatures } => {
            let bridge = bridge()?;
            let registry = ledger.tokens().ok_or(TxError::Token(TokenError::Disabled))?;
            if *decimals > MAX_BACKING_DECIMALS {
                return Err(token(TokenError::BadBackingDecimals(*decimals)));
            }
            check_pq_structure(pq_signatures, bridge.pq_guardians.len()).map_err(TxError::Bridge)?;
            check_listing(bridge, *nonce, *chain)?;
            // Everything `add_backing` would refuse: the pair free, the token registered and
            // bridged, under the cap on backings. The fee is the plain base, taken at step 3.
            registry.check_add_backing(*token_index, *chain, coin, *decimals).map_err(token)?;
            verify_pq_message(
                pq_signatures,
                &bridge.pq_guardians,
                &list_message(tx.chain_id, *nonce, *token_index, *chain, coin, *decimals),
            )
            .map_err(TxError::Bridge)
        }
        Action::RotatePqGuardians { new_pq_guardians, nonce, pq_signatures } => {
            let bridge = bridge()?;
            check_rotation(bridge, *nonce, pq_signatures)?;
            // The new set's shape, the genesis rules over again (`genesis::check_bridge`): one
            // PQ key per guardian of the current ECDSA set, each exactly a Dilithium2 key, none
            // repeated, and the pause key held apart. Byte rules and set lookups, before the quorum.
            let expected = bridge.guardian_sets.get(&bridge.current_set).map_or(0, |s| s.keys.len());
            if new_pq_guardians.len() != expected {
                return Err(TxError::Bridge(BridgeError::PqSetLengthMismatch { expected, got: new_pq_guardians.len() }));
            }
            if let Some((index, k)) =
                new_pq_guardians.iter().enumerate().find(|(_, k)| k.as_bytes().len() != crate::bridge::PQ_PUBLIC_KEY_LEN)
            {
                return Err(TxError::Bridge(BridgeError::BadPqGuardianKey { index, len: k.as_bytes().len() }));
            }
            let unique: std::collections::BTreeSet<&[u8]> = new_pq_guardians.iter().map(|k| k.as_bytes()).collect();
            if unique.len() != new_pq_guardians.len() {
                return Err(TxError::Bridge(BridgeError::DuplicatePqGuardian));
            }
            if bridge.pause_key.as_ref().is_some_and(|p| new_pq_guardians.contains(p)) {
                return Err(TxError::Bridge(BridgeError::GuardianIsPauseKey));
            }
            // Last: the current set's quorum over the fixed-layout message.
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &rotate_pq_message(tx.chain_id, *nonce, new_pq_guardians))
                .map_err(TxError::Bridge)
        }
        Action::RotatePauseKey { new_pause_key, nonce, pq_signatures } => {
            let bridge = bridge()?;
            check_rotation(bridge, *nonce, pq_signatures)?;
            let len = new_pause_key.as_bytes().len();
            if len != crate::bridge::PQ_PUBLIC_KEY_LEN {
                return Err(TxError::Bridge(BridgeError::BadPauseKeyLength { len }));
            }
            if bridge.pq_guardians.contains(new_pause_key) {
                return Err(TxError::Bridge(BridgeError::PauseKeyIsGuardian));
            }
            verify_pq_message(pq_signatures, &bridge.pq_guardians, &rotate_pause_message(tx.chain_id, *nonce, new_pause_key))
                .map_err(TxError::Bridge)
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}

/// Spends one `list_nonce`: the last write of both listing actions.
fn bump_list_nonce(ledger: &mut Ledger) -> Result<(), TxError> {
    let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
    bridge.list_nonce = bridge.list_nonce.saturating_add(1);
    Ok(())
}

/// The apply step, in lockstep with [`validate`], which decided every refusal against this same
/// state.
pub(super) fn apply(ledger: &mut Ledger, _tx: &Transaction, action: &Action) -> Result<(), TxError> {
    match action {
        Action::PauseMints { .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            bridge.mint_paused = true;
            bridge.pause_nonce = bridge.pause_nonce.saturating_add(1);
            Ok(())
        }
        Action::UnpauseMints { .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            bridge.mint_paused = false;
            bridge.pause_nonce = bridge.pause_nonce.saturating_add(1);
            Ok(())
        }
        Action::RegisterBridgedToken { name, symbol, salt, chain, token: coin, decimals, .. } => {
            let height = ledger.height();
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            // The index `validate` checked room for, and the only place it is handed out;
            // `register` re-checks the metadata, the identity and the pair against this state.
            registry
                .register(
                    bridged_asset_id(name, symbol, salt),
                    name.clone(),
                    symbol.clone(),
                    BRIDGE_DECIMALS,
                    MintAuthority::Bridge { backings: vec![Backing::new(*chain, *coin, *decimals)] },
                    height,
                )
                .map_err(token)?;
            bump_list_nonce(ledger)
        }
        Action::ListBacking { token_index, chain, token: coin, decimals, .. } => {
            let registry = ledger.tokens_mut().ok_or(TxError::Token(TokenError::Disabled))?;
            registry.add_backing(*token_index, *chain, *coin, *decimals).map_err(token)?;
            bump_list_nonce(ledger)
        }
        Action::RotatePqGuardians { new_pq_guardians, .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            // The second lock on the gate: `validate` refused a chain without the section, and a
            // direct caller must not move a counter chain 14 has no root for.
            if bridge.rules_v2.is_none() {
                return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
            }
            bridge.pq_guardians = new_pq_guardians.clone();
            bump_rotation_nonce(bridge);
            Ok(())
        }
        Action::RotatePauseKey { new_pause_key, .. } => {
            let bridge = ledger.bridge_mut().ok_or(TxError::Bridge(BridgeError::Disabled))?;
            if bridge.rules_v2.is_none() {
                return Err(TxError::Bridge(BridgeError::RulesV2Disabled));
            }
            bridge.pause_key = Some(new_pause_key.clone());
            bump_rotation_nonce(bridge);
            Ok(())
        }
        _ => Err(NOT_BRIDGE_GOV),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::pq::tests::{hex32, vector_keys, vector_sigs, vectors};
    use crate::bridge::{guardian_address, BridgeConfig, PqSignature};
    use crate::confidential::{ConfidentialExecutor, StubExecutor};
    use crate::crypto::{Keypair, PublicKey};
    use crate::ledger::tokens::TokenRegistry;
    use crate::ledger::{BlockError, ValidatorEntry};
    use crate::notes::{Bundle, Envelope, ShieldedAddress, Word8};

    const HC: Word8 = [11; 8];
    const CHAIN: u64 = 7;
    const FEE: u64 = 1_000_000_000;

    /// zUSD as chain 14 registers it (the bridge repo's `docs/mainnet-launch.md` §5): the name,
    /// the symbol, the salt `keccak256("rand-zusd-shielded-usd-chain-14")`, and its seven coins in
    /// their 32-byte wire forms with their source decimals — Ethereum USDT first (the
    /// registration's own backing), then the six `ListBacking`s in launch order.
    const NAME: &str = "Shielded USD";
    const SYMBOL: &str = "zUSD";
    fn salt() -> [u8; 32] {
        hex32(&serde_json::json!("27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60"))
    }
    fn coins() -> Vec<(u16, [u8; 32], u8)> {
        [
            (2, "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", 6), // Ethereum USDT
            (2, "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6), // Ethereum USDC
            (3, "00000000000000000000000055d398326f99059ff775485246999027b3197955", 18), // BSC USDT
            (3, "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18), // BSC USDC
            (4, "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6), // Tron USDT
            (5, "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", 6), // Solana USDT
            (5, "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", 6), // Solana USDC
        ]
        .into_iter()
        .map(|(c, t, d)| (c, hex32(&serde_json::json!(t)), d))
        .collect()
    }

    fn proposer() -> Keypair {
        Keypair::from_seed([1; 32]).unwrap()
    }

    fn pq_keys() -> Vec<Keypair> {
        (0..6u8).map(|i| Keypair::from_seed([0x70 + i; 32]).unwrap()).collect()
    }

    /// A bridged ledger at height 1 on `chain_id` with `pq_guardians`, source emitters on chains
    /// 2..=5, and an empty token registry — what chain 14 starts with: genesis lists no token.
    fn ledger_on(chain_id: u64, pq_guardians: Vec<PublicKey>) -> Ledger {
        let k = proposer();
        let entry = ValidatorEntry {
            public_key: k.public_key().clone(),
            stake: 10,
            pending: Vec::new(),
            rewards: 0,
            payout: ShieldedAddress { pk: [1; 8], kem_ek: vec![2; 32] },
            nonce: 0,
            activation_epoch: 0,
        };
        let mut l = Ledger::new(chain_id, HC, [(k.address(), entry)].into_iter().collect(), &StubExecutor);
        let secrets: Vec<[u8; 32]> = (1u8..=6).map(|i| [i; 32]).collect();
        l.set_bridge(Some(BridgeState::from_config(&BridgeConfig {
            emitter: [1; 32],
            guardians: secrets.iter().map(guardian_address).collect(),
            emitters: (2u16..=5).map(|c| (c, [c as u8; 32])).collect(),
            pq_guardians,
            pause_key: Some(Keypair::from_seed([0x7f; 32]).unwrap().public_key().clone()),
            rules_v2: None,
        })));
        l.set_tokens(Some(TokenRegistry::new(FEE).with_mint_cap(100_000 * 100_000_000)));
        l.set_height(1);
        l.set_timestamp_ms(1_000_000);
        l
    }

    fn ledger() -> Ledger {
        ledger_on(CHAIN, pq_keys().iter().map(|k| k.public_key().clone()).collect())
    }

    /// A RAND fee bundle paying `fee`, burning nothing, whose four words start at `seed`; bound to
    /// the transaction by the stub executor.
    fn paid(l: &Ledger, seed: u32, fee: u64, action: Action) -> Transaction {
        let mut b = Bundle {
            anchor: l.anchors().back().expect("the genesis anchor").1,
            nullifiers: crate::notes::pad4([[seed; 8], [seed + 1; 8]]),
            commitments: crate::notes::pad4([[seed + 2; 8], [seed + 3; 8]]),
            fee,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: std::array::from_fn(|_| Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] }),
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        StubExecutor::bound(Transaction::shielded(l.chain_id(), b, action))
    }

    /// The PQ guardians at `indices` over `message`.
    fn quorum(indices: &[u8], message: &[u8]) -> Vec<PqSignature> {
        let keys = pq_keys();
        indices.iter().map(|&i| PqSignature { index: i, signature: keys[i as usize].sign(message).as_bytes().to_vec() }).collect()
    }

    fn register(nonce: u64, coin: (u16, [u8; 32], u8), salt: [u8; 32]) -> Action {
        let (chain, token, decimals) = coin;
        let m = register_message(CHAIN, nonce, NAME, SYMBOL, &salt, chain, &token, decimals).unwrap();
        Action::RegisterBridgedToken {
            name: NAME.into(),
            symbol: SYMBOL.into(),
            salt,
            chain,
            token,
            decimals,
            nonce,
            pq_signatures: quorum(&[0, 1, 2, 3, 4], &m),
        }
    }

    fn list(nonce: u64, token_index: u32, coin: (u16, [u8; 32], u8)) -> Action {
        let (chain, token, decimals) = coin;
        let m = list_message(CHAIN, nonce, token_index, chain, &token, decimals);
        Action::ListBacking { token_index, chain, token, decimals, nonce, pq_signatures: quorum(&[1, 2, 3, 4, 5], &m) }
    }

    /// zUSD's whole deployment on chain 14, by transaction: one `RegisterBridgedToken` (its first
    /// backing, `list_nonce` 0) and six `ListBacking`s (`list_nonce` 1..6), each paid by the
    /// deployer's fee bundle — the seven real wire forms. The token lands at index 1 (RAND is 0)
    /// under the RPL bridged id, eight decimals, the genesis cap; every coin starts unlocked and
    /// resolves to it; and a deposit of each is then admissible under the cap.
    #[test]
    fn zusd_registers_by_transaction_and_lists_its_six_other_backings() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        let reg = paid(&l, 10, gas::BUNDLE_BASE + FEE, register(0, coins[0], salt()));
        l.apply_tx(&reg, &p, &StubExecutor).unwrap();
        let info = l.tokens().unwrap().get(1).unwrap().clone();
        assert_eq!(info.id, bridged_asset_id(NAME, SYMBOL, &salt()), "the RPL rule for a bridged id");
        assert_eq!((info.name.as_str(), info.symbol.as_str(), info.decimals, info.total_supply), (NAME, SYMBOL, 8, 0));
        assert_eq!(info.registered_at, 1);
        assert_eq!(info.authority, MintAuthority::Bridge { backings: vec![Backing::new(coins[0].0, coins[0].1, 6)] });
        assert_eq!(l.bridge().unwrap().list_nonce, 1);
        for (i, coin) in coins.iter().enumerate().skip(1) {
            let tx = paid(&l, 10 + 10 * i as u32, gas::BUNDLE_BASE, list(i as u64, 1, *coin));
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        }
        assert_eq!(l.bridge().unwrap().list_nonce, 7);
        let tokens = l.tokens().unwrap();
        let MintAuthority::Bridge { backings } = &tokens.get(1).unwrap().authority else { panic!("bridged") };
        assert_eq!(backings.len(), 7);
        for (coin, b) in coins.iter().zip(backings) {
            assert_eq!(b, &Backing::new(coin.0, coin.1, coin.2), "every coin starts unlocked");
            assert_eq!(tokens.bridged(coin.0, &coin.1).unwrap().index, 1);
            assert_eq!(tokens.check_lock(1, coin.0, &coin.1, 100_000 * 100_000_000, 0), Ok(()), "mintable under the cap");
        }
        assert!(tokens.backing_invariant_holds());
        assert_eq!(tokens.next_index(), 2);
    }

    /// The bridge repo's own `register` and `list` vectors, end to end through `validate` and
    /// `apply_tx`, on a ledger with the vectors' chain id (99) and PQ guardian set: the files
    /// `rand-bridge-gov pq-register` and `pq-list` write are what this chain admits.
    #[test]
    fn the_register_and_list_vectors_are_admitted_on_their_chain() {
        let file = vectors();
        let chain_id = file["rand_chain_id"].as_u64().unwrap();
        let mut l = ledger_on(chain_id, vector_keys(&file));
        let p = proposer().address();
        let g = &file["governance"];
        let r = &g["register"];
        let register = Action::RegisterBridgedToken {
            name: r["name"].as_str().unwrap().into(),
            symbol: r["symbol"].as_str().unwrap().into(),
            salt: hex32(&r["salt"]),
            chain: r["chain"].as_u64().unwrap() as u16,
            token: hex32(&r["token"]),
            decimals: r["decimals"].as_u64().unwrap() as u8,
            nonce: r["list_nonce"].as_u64().unwrap(),
            pq_signatures: vector_sigs(&r["pq_signatures"]),
        };
        l.apply_tx(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register), &p, &StubExecutor).unwrap();
        let v = &g["list"];
        let listing = Action::ListBacking {
            token_index: v["token_index"].as_u64().unwrap() as u32,
            chain: v["chain"].as_u64().unwrap() as u16,
            token: hex32(&v["token"]),
            decimals: v["decimals"].as_u64().unwrap() as u8,
            nonce: v["list_nonce"].as_u64().unwrap(),
            pq_signatures: vector_sigs(&v["pq_signatures"]),
        };
        l.apply_tx(&paid(&l, 20, gas::BUNDLE_BASE, listing), &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 2);
        assert_eq!(l.tokens().unwrap().bridged(5, &hex32(&v["token"])).unwrap().index, 1);
    }

    /// Every refusal a listing can meet, each reached before the Dilithium2 verification (the
    /// quorums below are garbage of the right shape unless the point is the quorum): the gate, the
    /// nonce, the chain's emitter, a pair that already backs a token, an asset id already
    /// registered, an unknown or unbridged index, source decimals past 18, the name rules, the fee
    /// floor — and last, a quorum over another message.
    #[test]
    fn every_listing_refusal_comes_before_the_quorum_is_verified() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        let garbage = |mut a: Action| {
            match &mut a {
                Action::RegisterBridgedToken { pq_signatures, .. } | Action::ListBacking { pq_signatures, .. } => {
                    for s in pq_signatures.iter_mut() {
                        s.signature = vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN];
                    }
                }
                _ => unreachable!(),
            }
            a
        };
        let err = |l: &Ledger, tx: &Transaction| l.validate(tx, &StubExecutor).unwrap_err();
        let full = gas::BUNDLE_BASE + FEE;

        // Before anything is registered: the nonce, the emitter, the fee, the name.
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(1, coins[0], salt())))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 0, got: 1 })
        );
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(0, (6, [9; 32], 6), salt())))),
            TxError::Bridge(BridgeError::NoEmitter { chain: 6 })
        );
        assert_eq!(
            err(&l, &paid(&l, 10, full - 1, garbage(register(0, coins[0], salt())))),
            token(TokenError::RegistrationFeeTooLow { min: full, fee: full - 1 })
        );
        let mut long = garbage(register(0, coins[0], salt()));
        let Action::RegisterBridgedToken { name, .. } = &mut long else { panic!() };
        *name = "n".repeat(33);
        assert_eq!(err(&l, &paid(&l, 10, full, long)), token(TokenError::BadName));
        assert_eq!(
            err(&l, &paid(&l, 10, full, garbage(register(0, (2, [9; 32], 19), salt())))),
            token(TokenError::BadBackingDecimals(19))
        );
        // The quorum is the last thing looked at: a well-formed registration with a quorum over
        // another message (a listing's) is refused there, and only there.
        let mut swapped = register(0, coins[0], salt());
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut swapped else { panic!() };
        *pq_signatures = quorum(&[0, 1, 2, 3, 4], &list_message(CHAIN, 0, 1, coins[0].0, &coins[0].1, 6));
        assert_eq!(err(&l, &paid(&l, 10, full, swapped)), TxError::Bridge(BridgeError::PqBadSignature { index: 0 }));
        // A listing before any token exists names an unknown index.
        assert_eq!(err(&l, &paid(&l, 20, gas::BUNDLE_BASE, garbage(list(0, 1, coins[1])))), token(TokenError::UnknownToken(1)));

        l.apply_tx(&paid(&l, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        // The same registration again: its nonce is spent. At the right nonce, its identity is
        // taken (a different coin, so the pair is not what refuses it)…
        assert_eq!(
            err(&l, &paid(&l, 30, full, register(0, coins[0], salt()))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        assert_eq!(
            err(&l, &paid(&l, 30, full, garbage(register(1, coins[1], salt())))),
            token(TokenError::AlreadyRegistered(bridged_asset_id(NAME, SYMBOL, &salt())))
        );
        // …and a new token (another salt) cannot take a coin that already backs zUSD.
        assert_eq!(
            err(&l, &paid(&l, 30, full, garbage(register(1, coins[0], [1; 32])))),
            token(TokenError::BackingTaken { chain: 2 })
        );
        // A duplicate backing, an index that is not a token, too many source decimals, an
        // unregistered chain; and a listing's fee floor is the bundle base, taken at step 3.
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, coins[0])))), token(TokenError::BackingTaken { chain: 2 }));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 2, coins[1])))), token(TokenError::UnknownToken(2)));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, (3, [7; 32], 19))))), token(TokenError::BadBackingDecimals(19)));
        assert_eq!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(1, 1, (9, [7; 32], 6))))), TxError::Bridge(BridgeError::NoEmitter { chain: 9 }));
        assert_eq!(
            err(&l, &paid(&l, 40, gas::BUNDLE_BASE - 1, list(1, 1, coins[1]))),
            TxError::FeeTooLow { min: gas::BUNDLE_BASE, fee: gas::BUNDLE_BASE - 1 }
        );
        assert_eq!(
            err(&l, &paid(&l, 40, gas::BUNDLE_BASE, garbage(list(0, 1, coins[1])))),
            TxError::Bridge(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        // A short quorum is refused on its count, before any state is read.
        let mut short = list(1, 1, coins[1]);
        let Action::ListBacking { pq_signatures, .. } = &mut short else { panic!() };
        pq_signatures.truncate(4);
        assert!(matches!(err(&l, &paid(&l, 40, gas::BUNDLE_BASE, short)), TxError::Bridge(BridgeError::PqNoQuorum { have: 4, .. })));
        assert_eq!(l.validate(&paid(&l, 40, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), Ok(()));

        // A chain without a bridge refuses both before anything else.
        let mut plain = l.clone();
        plain.set_bridge(None);
        assert_eq!(err(&plain, &paid(&plain, 50, full, register(1, coins[1], [2; 32]))), TxError::Bridge(BridgeError::Disabled));
        assert_eq!(err(&plain, &paid(&plain, 50, gas::BUNDLE_BASE, list(1, 1, coins[1]))), TxError::Bridge(BridgeError::Disabled));
    }

    /// Audit v4 (TOK-1): a `RegisterBridgedToken` at a registry that holds `max_tokens` tokens is
    /// refused `RegistryFull` before its quorum is verified; a `ListBacking` adds no token and is
    /// still admitted at the cap.
    #[test]
    fn a_bridged_registration_at_max_tokens_is_refused_registry_full() {
        let mut l = ledger();
        l.set_tokens(Some(l.tokens().unwrap().clone().with_max_tokens(1)));
        let p = proposer().address();
        let coins = coins();
        let full = gas::BUNDLE_BASE + FEE;
        l.apply_tx(&paid(&l, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        assert!(l.tokens().unwrap().is_full());
        let mut garbage = register(1, coins[1], [2; 32]);
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut garbage else { panic!() };
        for s in pq_signatures.iter_mut() {
            s.signature = vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN];
        }
        assert_eq!(l.validate(&paid(&l, 20, full, garbage), &StubExecutor), Err(token(TokenError::RegistryFull)));
        l.apply_tx(&paid(&l, 30, gas::BUNDLE_BASE, list(1, 1, coins[1])), &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 2);
    }

    // ---- audit v4, bridge rules v2: rotation, the gate, no listing while paused -----------------

    /// [`ledger`] with `rules_v2` on: the bridge carries the section and the registry its windows.
    fn ledger_v2() -> Ledger {
        let mut l = ledger();
        let rules = crate::bridge::BridgeRulesV2 { global_mint_cap_per_window: 1_000_000 * 100_000_000, cap_window_secs: 86_400 };
        l.bridge_mut().unwrap().rules_v2 = Some(rules.clone());
        let tokens = l.tokens().unwrap().clone().with_rules_v2(rules.cap_window_secs, rules.global_mint_cap_per_window);
        l.set_tokens(Some(tokens));
        l
    }

    /// Six fresh Dilithium2 keys that are no guardian's and not the pause key.
    fn fresh_pq_set(n: usize) -> Vec<Keypair> {
        (0..n as u8).map(|i| Keypair::from_seed([0xa0 + i; 32]).unwrap()).collect()
    }

    fn pks(keys: &[Keypair]) -> Vec<PublicKey> {
        keys.iter().map(|k| k.public_key().clone()).collect()
    }

    /// The PQ quorum `keys[indices]` over `message`.
    fn quorum_of(keys: &[Keypair], indices: &[u8], message: &[u8]) -> Vec<PqSignature> {
        indices.iter().map(|&i| PqSignature { index: i, signature: keys[i as usize].sign(message).as_bytes().to_vec() }).collect()
    }

    fn rotate_pq_tx(l: &Ledger, new: Vec<PublicKey>, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePqGuardians { new_pq_guardians: new, nonce, pq_signatures } }
    }

    fn rotate_pause_tx(l: &Ledger, new: PublicKey, nonce: u64, pq_signatures: Vec<PqSignature>) -> Transaction {
        Transaction { chain_id: l.chain_id(), bundle: None, action: Action::RotatePauseKey { new_pause_key: new, nonce, pq_signatures } }
    }

    /// A `RotatePqGuardians` to `new` at the bridge's current `rotation_nonce`, signed by `signers`
    /// (the lowest five), applied.
    fn rotate_pq(l: &mut Ledger, new: Vec<PublicKey>, signers: &[Keypair]) -> Result<(), TxError> {
        let nonce = l.bridge().unwrap().rotation_nonce;
        let m = rotate_pq_message(l.chain_id(), nonce, &new);
        let tx = rotate_pq_tx(l, new, nonce, quorum_of(signers, &[0, 1, 2, 3, 4], &m));
        let p = proposer().address();
        l.apply_tx(&tx, &p, &StubExecutor).map(|_| ())
    }

    fn rotate_pause(l: &mut Ledger, new: PublicKey, signers: &[Keypair]) -> Result<(), TxError> {
        let nonce = l.bridge().unwrap().rotation_nonce;
        let m = rotate_pause_message(l.chain_id(), nonce, &new);
        let tx = rotate_pause_tx(l, new, nonce, quorum_of(signers, &[1, 2, 3, 4, 5], &m));
        let p = proposer().address();
        l.apply_tx(&tx, &p, &StubExecutor).map(|_| ())
    }

    fn bridge_err(e: BridgeError) -> Result<(), TxError> {
        Err(TxError::Bridge(e))
    }

    /// A `PublicKey` of `n` bytes, built the only way one can arrive: off the wire
    /// (`PublicKey::from_bytes` enforces the length; its `Deserialize` does not).
    fn wire_key(n: usize) -> PublicKey {
        bincode::deserialize(&bincode::serialize(&vec![7u8; n]).expect("bytes")).expect("a wire key")
    }

    /// A PQ rotation under the current PQ quorum moves the set and spends the rotation nonce;
    /// the superseded set can sign nothing further (its quorum over the next nonce is refused
    /// at the signature), and the new set can rotate again. Bundle-less, fee-less.
    #[test]
    fn a_pq_rotation_moves_the_set_and_the_old_set_cannot_sign_the_next_one() {
        let mut l = ledger_v2();
        let old = pq_keys();
        let new = fresh_pq_set(old.len());
        assert_eq!(rotate_pq(&mut l, pks(&new), &old), Ok(()));
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&new));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 1);
        let newer = fresh_pq_set(old.len()).into_iter().rev().collect::<Vec<_>>();
        assert_eq!(rotate_pq(&mut l, pks(&newer), &old), bridge_err(BridgeError::PqBadSignature { index: 0 }));
        assert_eq!(l.bridge().unwrap().pq_guardians, pks(&new), "refused, nothing moved");
        // A quorum signed for the spent nonce is refused on the nonce, before the signatures.
        let stale = rotate_pq_tx(&l, pks(&newer), 0, quorum_of(&new, &[0, 1, 2, 3, 4], &rotate_pq_message(CHAIN, 0, &pks(&newer))));
        assert_eq!(l.validate(&stale, &StubExecutor), bridge_err(BridgeError::BadRotationNonce { expected: 1, got: 0 }));
        assert_eq!(rotate_pq(&mut l, pks(&newer), &new), Ok(()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // The new set co-signs mints: a listing under it is admitted, one under the old set is not.
        let coins = coins();
        let nonce = l.bridge().unwrap().list_nonce;
        let m = register_message(CHAIN, nonce, NAME, SYMBOL, &salt(), coins[0].0, &coins[0].1, coins[0].2).unwrap();
        let mut reg = register(nonce, coins[0], salt());
        let Action::RegisterBridgedToken { pq_signatures, .. } = &mut reg else { panic!() };
        *pq_signatures = quorum_of(&newer, &[0, 1, 2, 3, 4], &m);
        assert_eq!(l.validate(&paid(&l, 10, gas::BUNDLE_BASE + FEE, reg), &StubExecutor), Ok(()));
        assert_eq!(
            l.validate(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register(nonce, coins[0], salt())), &StubExecutor),
            bridge_err(BridgeError::PqBadSignature { index: 0 })
        );
    }

    /// Every structural refusal of a PQ rotation, each before the quorum is verified (the quorums
    /// are garbage of the right shape): the set's length against the ECDSA set's, a key that is
    /// not a Dilithium2 key's length, a duplicate, the pause key inside the set, a carried bundle.
    #[test]
    fn a_pq_rotation_is_refused_on_its_shape_before_its_quorum() {
        let l = ledger_v2();
        let old = pq_keys();
        let garbage = |n: usize| (0..n as u8).map(|i| PqSignature { index: i, signature: vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN] }).collect::<Vec<_>>();
        let err = |new: Vec<PublicKey>| l.validate(&rotate_pq_tx(&l, new, 0, garbage(5)), &StubExecutor);
        let new = pks(&fresh_pq_set(6));
        assert_eq!(err(new[..5].to_vec()), bridge_err(BridgeError::PqSetLengthMismatch { expected: 6, got: 5 }));
        assert_eq!(err(Vec::new()), bridge_err(BridgeError::PqSetLengthMismatch { expected: 6, got: 0 }));
        let mut short = new.clone();
        short[2] = wire_key(31);
        assert_eq!(err(short), bridge_err(BridgeError::BadPqGuardianKey { index: 2, len: 31 }));
        let mut dup = new.clone();
        dup[4] = dup[1].clone();
        assert_eq!(err(dup), bridge_err(BridgeError::DuplicatePqGuardian));
        let mut with_pause = new.clone();
        with_pause[0] = l.bridge().unwrap().pause_key.clone().unwrap();
        assert_eq!(err(with_pause), bridge_err(BridgeError::GuardianIsPauseKey));
        // A well-formed set with a garbage quorum reaches the signatures, and only then.
        assert_eq!(err(new.clone()), bridge_err(BridgeError::PqBadSignature { index: 0 }));
        // A short quorum is refused on its count.
        assert!(matches!(
            l.validate(&rotate_pq_tx(&l, new.clone(), 0, garbage(4)), &StubExecutor),
            Err(TxError::Bridge(BridgeError::PqNoQuorum { have: 4, need: 5, n: 6 }))
        ));
        // Bundle-less by shape.
        let mut with_bundle = rotate_pq_tx(&l, new.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &rotate_pq_message(CHAIN, 0, &new)));
        with_bundle.bundle = paid(&l, 90, gas::BUNDLE_BASE, Action::None).bundle;
        assert_eq!(l.validate(&with_bundle, &StubExecutor), Err(TxError::ActionCarriesBundle("rotate_pq_guardians")));
        assert_eq!(gas::fee_floor(&with_bundle.action), 0);
    }

    /// The pause key rotates under the PQ quorum: the old key can no longer pause, the new one
    /// can; a new key that is a PQ guardian, or not a Dilithium2 key's length, is refused before
    /// the quorum; the rotation nonce is shared with the PQ rotation.
    #[test]
    fn a_pause_key_that_is_a_pq_guardian_is_refused() {
        let mut l = ledger_v2();
        let guardians = pq_keys();
        let p = proposer().address();
        let garbage = (0..5u8).map(|i| PqSignature { index: i, signature: vec![0x5a; crate::bridge::PQ_SIGNATURE_LEN] }).collect::<Vec<_>>();
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, guardians[0].public_key().clone(), 0, garbage.clone()), &StubExecutor),
            bridge_err(BridgeError::PauseKeyIsGuardian)
        );
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, wire_key(40), 0, garbage.clone()), &StubExecutor),
            bridge_err(BridgeError::BadPauseKeyLength { len: 40 })
        );
        let new_pause = Keypair::from_seed([0x99; 32]).unwrap();
        assert_eq!(
            l.validate(&rotate_pause_tx(&l, new_pause.public_key().clone(), 0, garbage), &StubExecutor),
            bridge_err(BridgeError::PqBadSignature { index: 0 })
        );
        assert_eq!(rotate_pause(&mut l, new_pause.public_key().clone(), &guardians), Ok(()));
        assert_eq!(l.bridge().unwrap().pause_key.as_ref(), Some(new_pause.public_key()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 1);
        // The old pause key's signature no longer pauses; the new key's does.
        let old_pause = Keypair::from_seed([0x7f; 32]).unwrap();
        let pause = |k: &Keypair| Transaction { chain_id: CHAIN, bundle: None, action: Action::PauseMints { nonce: 0, signature: k.sign(&pause_message(CHAIN, 0)) } };
        assert_eq!(l.validate(&pause(&old_pause), &StubExecutor), bridge_err(BridgeError::BadPauseSignature));
        l.apply_tx(&pause(&new_pause), &p, &StubExecutor).unwrap();
        assert!(l.bridge().unwrap().mint_paused);
        // The two rotations share one nonce: a PQ rotation now needs nonce 1.
        let new_set = fresh_pq_set(6);
        assert_eq!(rotate_pq(&mut l, pks(&new_set), &guardians), Ok(()));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 2);
        // And with the set rotated, the new pause key inside the new set is refused as a guardian.
        let stale = rotate_pause_tx(&l, new_set[3].public_key().clone(), 2, Vec::new());
        assert!(matches!(l.validate(&stale, &StubExecutor), Err(TxError::Bridge(BridgeError::PqNoQuorum { .. }))), "the structure first");
    }

    /// Chain 14's shape: without `rules_v2` both rotations are `RulesV2Disabled` — before the
    /// quorum's structure, the nonce or anything else is looked at — and a chain without a
    /// bridge refuses them `Disabled` first.
    #[test]
    fn rotations_are_refused_without_rules_v2() {
        let l = ledger();
        let old = pq_keys();
        let new = pks(&fresh_pq_set(6));
        let m = rotate_pq_message(CHAIN, 0, &new);
        let honest = rotate_pq_tx(&l, new.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &m));
        assert_eq!(l.validate(&honest, &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        let pause = Keypair::from_seed([0x99; 32]).unwrap().public_key().clone();
        let honest_pause = rotate_pause_tx(&l, pause.clone(), 0, quorum_of(&old, &[0, 1, 2, 3, 4], &rotate_pause_message(CHAIN, 0, &pause)));
        assert_eq!(l.validate(&honest_pause, &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        assert_eq!(l.validate(&rotate_pq_tx(&l, Vec::new(), 9, Vec::new()), &StubExecutor), bridge_err(BridgeError::RulesV2Disabled));
        let mut plain = l.clone();
        plain.set_bridge(None);
        assert_eq!(plain.validate(&honest, &StubExecutor), bridge_err(BridgeError::Disabled));
        assert_eq!(l.bridge().unwrap().rotation_nonce, 0);
    }

    /// While minting is paused, `RegisterBridgedToken` and `ListBacking` are refused `MintsPaused`
    /// under `rules_v2` — after the nonce, before the quorum — and admitted on a chain-14-shaped
    /// ledger, which must keep accepting what it accepts today. Unpaused, both are admitted again.
    #[test]
    fn listing_is_refused_while_paused_under_rules_v2_and_admitted_without() {
        let coins = coins();
        let p = proposer().address();
        let pause = |l: &mut Ledger| {
            let k = Keypair::from_seed([0x7f; 32]).unwrap();
            let nonce = l.bridge().unwrap().pause_nonce;
            let tx = Transaction { chain_id: CHAIN, bundle: None, action: Action::PauseMints { nonce, signature: k.sign(&pause_message(CHAIN, nonce)) } };
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        };
        let unpause = |l: &mut Ledger| {
            let nonce = l.bridge().unwrap().pause_nonce;
            let tx = Transaction { chain_id: CHAIN, bundle: None, action: Action::UnpauseMints { nonce, pq_signatures: quorum(&[0, 1, 2, 3, 4], &unpause_message(CHAIN, nonce)) } };
            l.apply_tx(&tx, &p, &StubExecutor).unwrap();
        };
        let full = gas::BUNDLE_BASE + FEE;

        let mut v2 = ledger_v2();
        v2.apply_tx(&paid(&v2, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        pause(&mut v2);
        assert_eq!(v2.validate(&paid(&v2, 20, full, register(1, coins[1], [2; 32])), &StubExecutor), bridge_err(BridgeError::MintsPaused));
        assert_eq!(v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), bridge_err(BridgeError::MintsPaused));
        // The nonce is judged before the pause, the quorum after it.
        assert_eq!(
            v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(0, 1, coins[1])), &StubExecutor),
            bridge_err(BridgeError::BadListNonce { expected: 1, got: 0 })
        );
        unpause(&mut v2);
        assert_eq!(v2.validate(&paid(&v2, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &StubExecutor), Ok(()));

        let mut v1 = ledger();
        v1.apply_tx(&paid(&v1, 10, full, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        pause(&mut v1);
        assert_eq!(v1.validate(&paid(&v1, 20, full, register(1, coins[1], [2; 32])), &StubExecutor), Ok(()));
        v1.apply_tx(&paid(&v1, 20, gas::BUNDLE_BASE, list(1, 1, coins[1])), &p, &StubExecutor).unwrap();
        assert_eq!(v1.bridge().unwrap().list_nonce, 2);
    }

    /// Two listings signed at the same nonce cannot share a block: the second is refused where it
    /// sits (its nonce is spent) and the block leaves the ledger as it was; in order, at
    /// consecutive nonces, both apply.
    #[test]
    fn two_listings_in_one_block_apply_in_nonce_order_only() {
        let mut l = ledger();
        let p = proposer().address();
        let coins = coins();
        l.apply_tx(&paid(&l, 10, gas::BUNDLE_BASE + FEE, register(0, coins[0], salt())), &p, &StubExecutor).unwrap();
        let a = paid(&l, 20, gas::BUNDLE_BASE, list(1, 1, coins[1]));
        let b = paid(&l, 30, gas::BUNDLE_BASE, list(1, 1, coins[2]));
        let before = l.clone();
        assert_eq!(
            l.apply_transactions(&[a.clone(), b], &p, &StubExecutor).unwrap_err(),
            BlockError::InvalidTx { index: 1, error: TxError::Bridge(BridgeError::BadListNonce { expected: 2, got: 1 }) }
        );
        assert_eq!((l.tokens(), l.bridge()), (before.tokens(), before.bridge()), "a refused block moved nothing");
        let c = paid(&l, 30, gas::BUNDLE_BASE, list(2, 1, coins[2]));
        l.apply_transactions(&[a, c], &p, &StubExecutor).unwrap();
        assert_eq!(l.bridge().unwrap().list_nonce, 3);
    }
}
