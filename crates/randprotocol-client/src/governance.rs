//! The bridge's Rand-only governance messages from the wallet's side: B1's
//! `rand bridge-pause --sig @file` and `rand bridge-unpause --pq @file`, and B4's
//! `rand token register-bridged … --pq @file` and `rand token list-backing … --pq @file`.
//!
//! The signatures are made elsewhere — the pause key's by `rand-bridge-gov pause`, a PQ guardian
//! quorum's by `rand-bridge-gov pq-unpause` — over the fixed layouts of
//! [`randprotocol_core::bridge::gov`], each for the nonce the bridge was at when it was signed.
//! This module reads that nonce from `rand_getBridgeState`, rebuilds the message, and checks the
//! file against it under the chain's own rules **before** anything is submitted, so a file signed
//! for another nonce, another chain or by another key is an error here, naming which, rather than
//! a refused transaction.
//!
//! A pause and an unpause ride without a bundle and pay no fee: a pause must work from a machine
//! that holds no RAND and no spend key at all. Neither needs this wallet's key file. A
//! registration and a listing ride a fee bundle this wallet pays (zUSD's deployer is a
//! faucet-funded wallet), so their actions are built here and proved by `wallet::submit`.

use crate::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::bridge::gov::{list_message, pause_message, register_message, unpause_message};
use randprotocol_core::bridge::{check_pq_quorum_message, BridgeError, PqSignature};
use randprotocol_core::ledger::tokens::{check_metadata, BRIDGE_DECIMALS, MAX_BACKING_DECIMALS};
use randprotocol_core::{Action, Hash, PublicKey, Signature, Transaction};
use serde_json::Value;
use std::collections::BTreeSet;

/// How far past the bridge's nonce [`signed_nonce`] looks when a file does not verify at it, to
/// say which nonce it *was* signed for. Governance nonces move a handful of times a year.
const NONCE_PROBE: u64 = 64;

/// The bridge's state as a governance message needs it: the chain's PQ guardian set, its pause
/// key, whether minting is paused, and the two nonces. `Err` on a chain without a bridge.
#[derive(Clone, Debug)]
pub struct GovState {
    pub pq_guardians: Vec<PublicKey>,
    pub pause_key: Option<PublicKey>,
    pub mint_paused: bool,
    pub pause_nonce: u64,
    pub list_nonce: u64,
    /// The source chains the bridge registers an emitter for — the only chains a backing can be on.
    pub emitter_chains: BTreeSet<u16>,
    /// The token registry's registration fee, which a `RegisterBridgedToken` owes past the bundle
    /// base; `None` from a node that does not serve it.
    pub registration_fee: Option<u64>,
}

impl GovState {
    /// Read from `rand_getBridgeState`'s answer. A node older than the pause (no `pause_nonce`)
    /// is an error rather than a guess at zero.
    pub fn from_bridge_state(v: &Value) -> Result<GovState> {
        if v["enabled"] != Value::Bool(true) {
            bail!("this chain has no bridge");
        }
        let key = |k: &Value| PublicKey::from_hex(k.as_str().unwrap_or_default()).map_err(|e| anyhow!("{e}"));
        let pq_guardians = v["pq_guardians"]
            .as_array()
            .ok_or_else(|| anyhow!("the node serves no pq_guardians (a node older than the PQ co-signature?)"))?
            .iter()
            .map(key)
            .collect::<Result<Vec<_>>>()
            .context("the node's pq_guardians entry is not a Dilithium2 key")?;
        let pause_key = match &v["pause_key"] {
            Value::Null => None,
            k => Some(key(k).context("the node's pause_key is not a Dilithium2 key")?),
        };
        let n = |f: &str| {
            v[f].as_u64().ok_or_else(|| anyhow!("the node serves no {f} (a node older than the mint pause?)"))
        };
        Ok(GovState {
            pq_guardians,
            pause_key,
            mint_paused: v["mint_paused"].as_bool().ok_or_else(|| anyhow!("the node serves no mint_paused"))?,
            pause_nonce: n("pause_nonce")?,
            list_nonce: n("list_nonce")?,
            emitter_chains: v["emitters"]
                .as_object()
                .map(|m| m.keys().filter_map(|k| k.parse().ok()).collect())
                .unwrap_or_default(),
            // Either encoding (node I3): a decimal string on chain 14, a number before it.
            registration_fee: crate::amount_field(&v["registration_fee"]),
        })
    }
}

/// The pause key's signature file `rand bridge-pause --sig` reads: a 2 420-byte Dilithium2
/// signature as hex (what `rand-bridge-gov pause` writes), whitespace and a `0x` allowed.
pub fn parse_pause_signature(text: &str) -> Result<Signature> {
    let compact: String = text.split_whitespace().collect();
    let bytes = hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).context("the pause signature is not hex")?;
    Signature::from_bytes(&bytes).map_err(|e| anyhow!("the pause signature is {} bytes, not a Dilithium2 signature: {e}", bytes.len()))
}

/// The first nonce in `0..=current + NONCE_PROBE` other than `current` that `verifies` accepts —
/// which nonce a file that does not verify at `current` was signed for, if any nearby.
fn signed_nonce(current: u64, verifies: impl Fn(u64) -> bool) -> Option<u64> {
    (0..=current.saturating_add(NONCE_PROBE)).filter(|n| *n != current).find(|n| verifies(*n))
}

/// The `PauseMints` a pause-key signature makes on this chain now: refused unless the bridge
/// has a pause key, minting is not already paused, and `signature` verifies under that key over
/// `M_pause(chain_id, pause_nonce)`. A signature made for another nonce says which.
pub fn pause_action(state: &GovState, chain_id: u64, signature: Signature) -> Result<Action> {
    let key = state.pause_key.as_ref().ok_or_else(|| anyhow!("this bridge has no pause key"))?;
    if state.mint_paused {
        bail!("bridge minting is already paused (pause_nonce {})", state.pause_nonce);
    }
    let nonce = state.pause_nonce;
    if !key.verify(&pause_message(chain_id, nonce), &signature) {
        return Err(match signed_nonce(nonce, |n| key.verify(&pause_message(chain_id, n), &signature)) {
            Some(n) => anyhow!("this pause signature was made for pause_nonce {n}; the bridge is at {nonce}: sign again"),
            None => anyhow!(
                "this pause signature does not verify for chain {chain_id} at pause_nonce {nonce} under the bridge's \
                 pause key (another chain, another key, or a nonce long past)"
            ),
        });
    }
    Ok(Action::PauseMints { nonce, signature })
}

/// The `UnpauseMints` a PQ guardian quorum makes on this chain now: refused unless minting is
/// paused and the quorum passes the co-signature's five rules over
/// `M_unpause(chain_id, pause_nonce)`. A quorum made for another nonce says which.
pub fn unpause_action(state: &GovState, chain_id: u64, pq_signatures: Vec<PqSignature>) -> Result<Action> {
    if !state.mint_paused {
        bail!("bridge minting is not paused (pause_nonce {})", state.pause_nonce);
    }
    let nonce = state.pause_nonce;
    check_quorum(state, &pq_signatures, nonce, "pause_nonce", |n| unpause_message(chain_id, n))?;
    Ok(Action::UnpauseMints { nonce, pq_signatures })
}

/// The `RegisterBridgedToken` a PQ guardian quorum makes on this chain now (B4): refused unless
/// the name and symbol pass the registry's rules, the source `decimals` is at most 18, the chain
/// has a registered emitter, and the quorum passes the five rules over `M_register` at the
/// bridge's `list_nonce`. A quorum made for another nonce says which.
#[allow(clippy::too_many_arguments)]
pub fn register_bridged_action(
    state: &GovState,
    chain_id: u64,
    name: &str,
    symbol: &str,
    salt: [u8; 32],
    chain: u16,
    token: [u8; 32],
    decimals: u8,
    pq_signatures: Vec<PqSignature>,
) -> Result<Action> {
    check_metadata(name, symbol, BRIDGE_DECIMALS).map_err(|e| anyhow!("{e}"))?;
    check_backing(state, chain, decimals)?;
    let nonce = state.list_nonce;
    check_quorum(state, &pq_signatures, nonce, "list_nonce", |n| {
        register_message(chain_id, n, name, symbol, &salt, chain, &token, decimals).expect("check_metadata bounds both")
    })?;
    Ok(Action::RegisterBridgedToken {
        name: name.into(),
        symbol: symbol.into(),
        salt,
        chain,
        token,
        decimals,
        nonce,
        pq_signatures,
    })
}

/// The `ListBacking` a PQ guardian quorum makes on this chain now (B4): the source `decimals` at
/// most 18, the chain with a registered emitter, and the quorum over `M_list` at `list_nonce`.
/// Whether `token_index` is a bridged token and the coin is free is the chain's to say.
pub fn list_backing_action(
    state: &GovState,
    chain_id: u64,
    token_index: u32,
    chain: u16,
    token: [u8; 32],
    decimals: u8,
    pq_signatures: Vec<PqSignature>,
) -> Result<Action> {
    check_backing(state, chain, decimals)?;
    let nonce = state.list_nonce;
    check_quorum(state, &pq_signatures, nonce, "list_nonce", |n| {
        list_message(chain_id, n, token_index, chain, &token, decimals)
    })?;
    Ok(Action::ListBacking { token_index, chain, token, decimals, nonce, pq_signatures })
}

fn check_backing(state: &GovState, chain: u16, decimals: u8) -> Result<()> {
    if decimals > MAX_BACKING_DECIMALS {
        bail!("--decimals {decimals} is over {MAX_BACKING_DECIMALS}: the backing's source decimals");
    }
    if !state.emitter_chains.contains(&chain) {
        bail!("chain {chain} has no registered emitter on this bridge (it has {:?})", state.emitter_chains);
    }
    Ok(())
}

/// The five rules over `message(nonce)`; on a signature that does not verify, probe the nearby
/// nonces to name the one the quorum was made for.
pub(crate) fn check_quorum(
    state: &GovState,
    sigs: &[PqSignature],
    nonce: u64,
    nonce_name: &str,
    message: impl Fn(u64) -> Vec<u8>,
) -> Result<()> {
    match check_pq_quorum_message(sigs, &state.pq_guardians, &message(nonce)) {
        Ok(()) => Ok(()),
        Err(BridgeError::PqBadSignature { index }) => {
            match signed_nonce(nonce, |n| check_pq_quorum_message(sigs, &state.pq_guardians, &message(n)).is_ok()) {
                Some(n) => bail!("this PQ quorum was made for {nonce_name} {n}; the bridge is at {nonce}: sign again"),
                None => bail!(
                    "the PQ quorum would be refused: co-signature {index} does not verify over this message at \
                     {nonce_name} {nonce} (another message, another chain, or another key)"
                ),
            }
        }
        Err(e) => bail!("the PQ quorum would be refused: {e}"),
    }
}

/// Submits a bundle-less governance transaction and, with `wait`, waits for it to commit.
pub async fn submit_bundle_less(rpc: &RpcClient, chain_id: u64, action: Action, wait: bool) -> Result<Hash> {
    if action.bundle_less().is_none() {
        bail!("this action rides a bundle and cannot be submitted bundle-less");
    }
    let tx = Transaction { chain_id, bundle: None, action };
    let hash = rpc.send_transaction(&tx).await?;
    if wait {
        rpc.wait_for_transaction(&hash, crate::wallet::COMMIT_TIMEOUT).await?;
    }
    Ok(hash)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_rpc::{scripted_rpc, Reply};
    use randprotocol_core::crypto::Keypair;
    use serde_json::json;

    /// The bridge repo's vectors (`vectors/pq-cosignatures.json` at ba01afb, the fixture core's
    /// tests read): the governance section, the six test PQ guardians and the chain id 99.
    pub(crate) fn vectors() -> Value {
        serde_json::from_str(include_str!("../../randprotocol-core/tests/fixtures/pq-cosignatures.json")).unwrap()
    }

    fn keys(file: &Value) -> Vec<String> {
        file["pq_guardians"].as_array().unwrap().iter().map(|g| g["public_key"].as_str().unwrap().to_string()).collect()
    }

    /// A `rand_getBridgeState` answer carrying the vectors' PQ set and pause key.
    pub(crate) fn bridge_state(paused: bool, pause_nonce: u64, list_nonce: u64) -> Value {
        let file = vectors();
        json!({
            "enabled": true,
            "emitters": { "2": "02", "3": "03", "4": "04", "5": "05" },
            "registration_fee": 1_000_000_000u64,
            "pq_guardians": keys(&file),
            "pause_key": file["governance"]["pause"]["pause_key"],
            "mint_paused": paused,
            "pause_nonce": pause_nonce,
            "list_nonce": list_nonce,
        })
    }

    pub(crate) fn pq_file(list: &Value) -> Vec<PqSignature> {
        crate::wallet::parse_pq_signatures(&list.to_string()).unwrap()
    }

    /// The vectors' `pause`: the signature file (hex, as `rand-bridge-gov pause` writes it)
    /// becomes a `PauseMints` at the bridge's nonce — and a bridge at another nonce names the one
    /// it was signed for, a paused bridge refuses, and another chain's id is refused.
    #[test]
    fn the_pause_vector_builds_the_pause_action_and_other_nonces_are_named() {
        let file = vectors();
        let v = &file["governance"]["pause"];
        let sig = parse_pause_signature(&format!("{}\n", v["signature"].as_str().unwrap())).unwrap();
        let state = GovState::from_bridge_state(&bridge_state(false, 0, 0)).unwrap();
        let action = pause_action(&state, 99, sig.clone()).unwrap();
        assert_eq!(action, Action::PauseMints { nonce: 0, signature: sig.clone() });
        let later = GovState::from_bridge_state(&bridge_state(false, 2, 0)).unwrap();
        let e = pause_action(&later, 99, sig.clone()).unwrap_err().to_string();
        assert!(e.contains("made for pause_nonce 0; the bridge is at 2"), "{e}");
        let paused = GovState::from_bridge_state(&bridge_state(true, 0, 0)).unwrap();
        assert!(pause_action(&paused, 99, sig.clone()).unwrap_err().to_string().contains("already paused"));
        assert!(pause_action(&state, 13, sig).unwrap_err().to_string().contains("does not verify for chain 13"));
        assert!(parse_pause_signature("abcd").unwrap_err().to_string().contains("2 bytes"));
    }

    /// The vectors' `unpause` (made at pause_nonce 1): an `UnpauseMints` at a paused bridge on
    /// nonce 1; at nonce 3 the error names nonce 1; an unpaused bridge refuses; a short list is
    /// refused under the chain's own rule.
    #[test]
    fn the_unpause_vector_builds_the_unpause_action() {
        let file = vectors();
        let v = &file["governance"]["unpause"];
        let sigs = pq_file(&v["pq_signatures"]);
        let state = GovState::from_bridge_state(&bridge_state(true, 1, 0)).unwrap();
        assert_eq!(unpause_action(&state, 99, sigs.clone()).unwrap(), Action::UnpauseMints { nonce: 1, pq_signatures: sigs.clone() });
        let later = GovState::from_bridge_state(&bridge_state(true, 3, 0)).unwrap();
        let e = unpause_action(&later, 99, sigs.clone()).unwrap_err().to_string();
        assert!(e.contains("made for pause_nonce 1; the bridge is at 3"), "{e}");
        let unpaused = GovState::from_bridge_state(&bridge_state(false, 1, 0)).unwrap();
        assert!(unpause_action(&unpaused, 99, sigs.clone()).unwrap_err().to_string().contains("not paused"));
        let e = unpause_action(&state, 99, sigs[..4].to_vec()).unwrap_err().to_string();
        assert!(e.contains("4 PQ co-signatures, need 5 of 6"), "{e}");
    }

    /// `rand bridge-pause` end to end against a scripted node: read the state and the chain id,
    /// check the signature, send the bundle-less transaction — whose bytes are exactly the
    /// `PauseMints` the vector makes — and return its hash.
    #[tokio::test]
    async fn a_pause_is_submitted_bundle_less_end_to_end() {
        let file = vectors();
        let v = &file["governance"]["pause"];
        let sig = parse_pause_signature(v["signature"].as_str().unwrap()).unwrap();
        let tx = Transaction { chain_id: 99, bundle: None, action: Action::PauseMints { nonce: 0, signature: sig.clone() } };
        let url = scripted_rpc(vec![
            ("rand_getBridgeState", Reply::Ok(bridge_state(false, 0, 0))),
            ("rand_chainId", Reply::Ok(json!(99))),
            ("rand_sendTransaction", Reply::Ok(json!(tx.hash().to_hex()))),
        ])
        .await;
        let rpc = RpcClient::new(url);
        let state = GovState::from_bridge_state(&rpc.bridge_state().await.unwrap()).unwrap();
        let chain_id = rpc.chain_id().await.unwrap();
        let action = pause_action(&state, chain_id, sig).unwrap();
        let hash = submit_bundle_less(&rpc, chain_id, action, false).await.unwrap();
        assert_eq!(hash, tx.hash());
        // The pause key the vector names is the one it derives from its seed, and it signs the
        // exact message the node will check.
        let seed: [u8; 32] = hex::decode(v["pause_key_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
        let key = Keypair::from_seed(seed).unwrap();
        assert_eq!(key.sign(&pause_message(99, 0)), tx_signature(&tx));
    }

    fn tx_signature(tx: &Transaction) -> Signature {
        let Action::PauseMints { signature, .. } = &tx.action else { panic!("a pause") };
        signature.clone()
    }

    fn hex32(v: &Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    /// The vectors' `register` (list_nonce 0) and `list` (list_nonce 1): each file builds exactly
    /// its action at the bridge's nonce; at another nonce the error names the one it was made
    /// for; the chain's rules on the arguments (an unregistered chain, decimals past 18, a bad
    /// symbol) refuse before the quorum is looked at, and a register quorum is not a list quorum.
    #[test]
    fn the_listing_vectors_build_their_actions() {
        let file = vectors();
        let g = &file["governance"];
        let r = &g["register"];
        let reg_sigs = pq_file(&r["pq_signatures"]);
        let (name, symbol, salt, token) =
            (r["name"].as_str().unwrap(), r["symbol"].as_str().unwrap(), hex32(&r["salt"]), hex32(&r["token"]));
        let at = |list_nonce| GovState::from_bridge_state(&bridge_state(false, 0, list_nonce)).unwrap();
        let build = |state: &GovState, sigs: Vec<PqSignature>| register_bridged_action(state, 99, name, symbol, salt, 2, token, 6, sigs);
        assert_eq!(
            build(&at(0), reg_sigs.clone()).unwrap(),
            Action::RegisterBridgedToken {
                name: name.into(),
                symbol: symbol.into(),
                salt,
                chain: 2,
                token,
                decimals: 6,
                nonce: 0,
                pq_signatures: reg_sigs.clone(),
            }
        );
        let e = build(&at(4), reg_sigs.clone()).unwrap_err().to_string();
        assert!(e.contains("made for list_nonce 0; the bridge is at 4"), "{e}");
        let e = register_bridged_action(&at(0), 99, name, symbol, salt, 7, token, 6, reg_sigs.clone()).unwrap_err().to_string();
        assert!(e.contains("chain 7 has no registered emitter"), "{e}");
        let e = register_bridged_action(&at(0), 99, name, symbol, salt, 2, token, 19, reg_sigs.clone()).unwrap_err().to_string();
        assert!(e.contains("over 18"), "{e}");
        assert!(register_bridged_action(&at(0), 99, name, "z USD", salt, 2, token, 6, reg_sigs.clone()).is_err());

        let v = &g["list"];
        let list_sigs = pq_file(&v["pq_signatures"]);
        let list_token = hex32(&v["token"]);
        assert_eq!(
            list_backing_action(&at(1), 99, 1, 5, list_token, 6, list_sigs.clone()).unwrap(),
            Action::ListBacking { token_index: 1, chain: 5, token: list_token, decimals: 6, nonce: 1, pq_signatures: list_sigs.clone() }
        );
        let e = list_backing_action(&at(0), 99, 1, 5, list_token, 6, list_sigs.clone()).unwrap_err().to_string();
        assert!(e.contains("made for list_nonce 1; the bridge is at 0"), "{e}");
        // Another index, or the registration's quorum, is no listing's quorum.
        assert!(list_backing_action(&at(1), 99, 2, 5, list_token, 6, list_sigs).unwrap_err().to_string().contains("does not verify"));
        assert!(list_backing_action(&at(1), 99, 1, 5, list_token, 6, reg_sigs).unwrap_err().to_string().contains("does not verify"));
    }
}
