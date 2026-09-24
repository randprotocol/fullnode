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
use crate::bridge::gov::{list_message, pause_message, register_message, unpause_message};
use crate::bridge::pq::{check_pq_structure, verify_pq_message};
use crate::bridge::{BridgeError, BridgeState};
use crate::gas;
use crate::types::{Action, Transaction};

/// A registry refusal, reported the way the bridge's other registry verdicts are: through
/// [`BridgeError::Token`], since the action that hit it is the bridge's.
fn token(e: TokenError) -> TxError {
    TxError::Bridge(BridgeError::Token(e))
}

/// The two listing actions' shared state rules: the nonce, then a registered emitter for the
/// backing's chain.
fn check_listing(bridge: &BridgeState, nonce: u64, chain: u16) -> Result<(), TxError> {
    if nonce != bridge.list_nonce {
        return Err(TxError::Bridge(BridgeError::BadListNonce { expected: bridge.list_nonce, got: nonce }));
    }
    if !bridge.emitters.contains_key(&chain) {
        return Err(TxError::Bridge(BridgeError::NoEmitter { chain }));
    }
    Ok(())
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
            if registry.next_index() == u32::MAX {
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
