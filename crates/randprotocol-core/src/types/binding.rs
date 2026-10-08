//! BIND-1 (audit v6, issue #79): what a transaction's proofs and its signed action messages bind.
//!
//! Votes, new-views and proposals have signed the genesis hash since `consensus_domain: 1`
//! ([`crate::types::SigningDomain`]), a v2 registration binds genesis, chain and address, and the
//! four vesting messages bind the genesis hash. Everything else a user or an operator signs or
//! proves bound the **chain id** alone: the eight-word digest every bundle, auth and call proof is
//! made over ([`crate::Transaction::binding`], [`crate::Transaction::call_binding`]), and the
//! signed messages of a faucet `Mint`, `Unbond`, `Withdraw`, an RPL token mint and authority
//! change, the aggregator register actions and the bridge's governance actions. Two chains
//! sharing a chain id — a re-cut, a private copy — would accept each other's proofs and
//! signatures; that chain ids have not repeated is the only thing that kept them apart.
//!
//! [`BindingDomain`] is the switch, taken from the genesis file's top-level `binding_domain`:
//!
//! - **`ChainId`** (the field absent or `0`; chains 14–19): exactly the messages this build's
//!   predecessors hashed, byte for byte — every method here returns what the free function it is
//!   named after returns.
//! - **`Genesis(hash)`** (`binding_domain: 1`): the genesis hash enters every preimage, first,
//!   under a fresh tag (the old tag with its version bumped), so a proof or a signature made for
//!   one chain verifies on no other, whatever its chain id.
//!
//! The binding words are a *public input* of the proofs — the wallet, a prover service and the
//! ledger compute them and hand them to the circuit — so this changes what those three hash and
//! nothing in any guest or verifier key. It is still a validity rule: a chain either carries the
//! field from its genesis or never does.
//!
//! The ledger holds its domain ([`crate::Ledger::binding_domain`]), set by `Genesis::build` once
//! the genesis block — whose hash it carries — exists, and restored by a reloading node from its
//! genesis file (`node::reload_ledger`): it is a genesis parameter, not state.

use crate::crypto::{Address, Hash, PublicKey};
use crate::notes::{Envelope, ShieldedAddress, Word8};
use crate::types::actions;
use crate::types::transaction::Transaction;

/// What this chain's transaction bindings and signed action messages are over (module docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingDomain {
    /// The genesis file has no `binding_domain` (or `0`): the chain id alone, today's messages.
    #[default]
    ChainId,
    /// `binding_domain: 1`: this genesis hash, then the chain id, under the `-N+1` tags.
    Genesis(Hash),
}

impl BindingDomain {
    /// The highest `binding_domain` this build computes; a genesis naming a higher one is refused.
    pub const MAX_VERSION: u32 = 1;

    /// The domain of a genesis whose file says `version` and whose hash is `genesis`.
    pub fn for_version(version: u32, genesis: Hash) -> BindingDomain {
        match version {
            0 => BindingDomain::ChainId,
            _ => BindingDomain::Genesis(genesis),
        }
    }

    /// `0` or `1`: what `rand_getLimits.binding_domain` serves.
    pub fn version(&self) -> u32 {
        match self {
            BindingDomain::ChainId => 0,
            BindingDomain::Genesis(_) => 1,
        }
    }

    /// The genesis hash bound, when one is.
    pub fn genesis(&self) -> Option<&Hash> {
        match self {
            BindingDomain::ChainId => None,
            BindingDomain::Genesis(g) => Some(g),
        }
    }

    /// `tag ‖ bincode(genesis, body…)` for the genesis-bound form of a bincode message: the v2
    /// registration's and the vesting messages' construction (`actions::registration_message_v2`).
    fn bound<T: serde::Serialize>(tag: &[u8], genesis: &Hash, body: &T) -> Hash {
        Hash::digest_domain(tag, &bincode::serialize(&(genesis, body)).expect("serializes"))
    }

    /// What a faucet minter signs ([`Transaction::mint_signing_hash`], `rand-mint-2`); genesis-bound
    /// under `rand-mint-3`.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_signing_hash(
        &self,
        chain_id: u64,
        cm: &Word8,
        pk: &Word8,
        time: u32,
        r: &Word8,
        envelope: &Envelope,
        amount: u64,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => Transaction::mint_signing_hash(chain_id, cm, pk, time, r, envelope, amount),
            BindingDomain::Genesis(g) => Self::bound(b"rand-mint-3", g, &(chain_id, cm, pk, time, r, envelope, amount)),
        }
    }

    /// What a validator signs to claim an address in the register. Under `ChainId` the v1 message
    /// ([`actions::registration_message`], chain and payout); genesis-bound it **is** the v2
    /// message ([`actions::registration_message_v2`]: genesis, chain, the validator's address and
    /// the payout) — a chain that binds the genesis everywhere else has no chain-id-only
    /// registration left, whether or not its `staking` section also says `registration_v2`.
    pub fn registration_message(&self, chain_id: u64, validator: &Address, payout: &ShieldedAddress) -> Hash {
        match self {
            BindingDomain::ChainId => actions::registration_message(chain_id, payout),
            BindingDomain::Genesis(g) => actions::registration_message_v2(g, chain_id, validator, payout),
        }
    }

    /// [`actions::unbond_message`] (`rand-unbond`); genesis-bound under `rand-unbond-2`.
    pub fn unbond_message(&self, chain_id: u64, validator: &Address, amount: u64, nonce: u64) -> Hash {
        match self {
            BindingDomain::ChainId => actions::unbond_message(chain_id, validator, amount, nonce),
            BindingDomain::Genesis(g) => Self::bound(b"rand-unbond-2", g, &(chain_id, validator, amount, nonce)),
        }
    }

    /// [`actions::withdraw_message`] (`rand-withdraw`); genesis-bound under `rand-withdraw-2`.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_message(
        &self,
        chain_id: u64,
        validator: &Address,
        amount: u64,
        nonce: u64,
        time: u32,
        r: &Word8,
        envelope: &Envelope,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => actions::withdraw_message(chain_id, validator, amount, nonce, time, r, envelope),
            BindingDomain::Genesis(g) => {
                Self::bound(b"rand-withdraw-2", g, &(chain_id, validator, amount, nonce, time, r, envelope))
            }
        }
    }

    /// [`actions::token_mint_message`] (`rand-rpl-mint-1`); genesis-bound under `rand-rpl-mint-2`.
    /// The envelope enters by its digest in both.
    pub fn token_mint_message(
        &self,
        chain_id: u64,
        asset_id: &crate::bridge::AssetId,
        nonce: u64,
        amount: u64,
        cm: &Word8,
        envelope: &Envelope,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => actions::token_mint_message(chain_id, asset_id, nonce, amount, cm, envelope),
            BindingDomain::Genesis(g) => Self::bound(
                b"rand-rpl-mint-2",
                g,
                &(chain_id, asset_id, nonce, amount, cm, actions::envelope_digest(envelope)),
            ),
        }
    }

    /// [`actions::set_authority_message`] (`rand-rpl-authority-1`); genesis-bound under
    /// `rand-rpl-authority-2`.
    pub fn set_authority_message(
        &self,
        chain_id: u64,
        asset_id: &crate::bridge::AssetId,
        nonce: u64,
        new: &Option<PublicKey>,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => actions::set_authority_message(chain_id, asset_id, nonce, new),
            BindingDomain::Genesis(g) => Self::bound(b"rand-rpl-authority-2", g, &(chain_id, asset_id, nonce, new)),
        }
    }

    /// [`actions::aggregator_register_message`] (`rand-aggregator-register`, chain and payout);
    /// genesis-bound under `rand-aggregator-register-2`, with the aggregator's address beside them
    /// as the validator's v2 registration names its own.
    pub fn aggregator_register_message(&self, chain_id: u64, aggregator: &Address, payout: &ShieldedAddress) -> Hash {
        match self {
            BindingDomain::ChainId => actions::aggregator_register_message(chain_id, payout),
            BindingDomain::Genesis(g) => Self::bound(b"rand-aggregator-register-2", g, &(chain_id, aggregator, payout)),
        }
    }

    /// [`actions::aggregator_unbond_message`]; genesis-bound under `rand-aggregator-unbond-2`.
    pub fn aggregator_unbond_message(&self, chain_id: u64, aggregator: &Address, nonce: u64) -> Hash {
        match self {
            BindingDomain::ChainId => actions::aggregator_unbond_message(chain_id, aggregator, nonce),
            BindingDomain::Genesis(g) => Self::bound(b"rand-aggregator-unbond-2", g, &(chain_id, aggregator, nonce)),
        }
    }

    /// [`actions::aggregator_withdraw_message`]; genesis-bound under `rand-aggregator-withdraw-2`.
    pub fn aggregator_withdraw_message(
        &self,
        chain_id: u64,
        aggregator: &Address,
        nonce: u64,
        time: u32,
        r: &Word8,
        envelope: &Envelope,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => actions::aggregator_withdraw_message(chain_id, aggregator, nonce, time, r, envelope),
            BindingDomain::Genesis(g) => {
                Self::bound(b"rand-aggregator-withdraw-2", g, &(chain_id, aggregator, nonce, time, r, envelope))
            }
        }
    }

    /// [`actions::aggregate_binding`] (`rand-aggregate-bind-1`), the eight words the rVM's
    /// aggregate program absorbs into its interface digest; genesis-bound under
    /// `rand-aggregate-bind-2`. Like the transaction binding these words are handed to the
    /// program, not computed by it: the registered aggregate program does not change.
    pub fn aggregate_binding(&self, chain_id: u64, aggregator: &Address, nonce: u64) -> [u32; 8] {
        match self {
            BindingDomain::ChainId => actions::aggregate_binding(chain_id, aggregator, nonce),
            BindingDomain::Genesis(g) => {
                let digest = Self::bound(b"rand-aggregate-bind-2", g, &(chain_id, aggregator, nonce));
                std::array::from_fn(|i| u32::from_le_bytes(digest.0[4 * i..4 * i + 4].try_into().expect("four bytes")))
            }
        }
    }

    /// [`actions::aggregate_signing_hash`] (`rand-aggregate-4`, with `payout_total`);
    /// genesis-bound under `rand-aggregate-5` (was `rand-aggregate-3` before `payout_total`).
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_signing_hash(
        &self,
        chain_id: u64,
        nonce: u64,
        time: u32,
        r: &Word8,
        covers: &[Hash],
        proof_hash: &Hash,
        envelope_digest: &Hash,
        payout_total: u64,
    ) -> Hash {
        match self {
            BindingDomain::ChainId => {
                actions::aggregate_signing_hash(chain_id, nonce, time, r, covers, proof_hash, envelope_digest, payout_total)
            }
            BindingDomain::Genesis(g) => Self::bound(
                b"rand-aggregate-5",
                g,
                &(chain_id, nonce, time, r, covers, proof_hash, envelope_digest, payout_total),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notes::Bundle;
    use crate::types::Action;

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

    fn words(w: [u32; 8]) -> String {
        hex::encode(w.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>())
    }

    fn call() -> Transaction {
        Transaction::shielded(13, bundle(), Action::Call { program: Hash([5; 32]), proof: vec![0x99; 7], input_envelope: None })
    }

    /// BIND-1, the half that must never go red: under `ChainId` — chains 14 to 19, and every
    /// genesis without `binding_domain` — both transaction bindings and every re-domained signed
    /// message are what the build before this one hashed. The values were captured on the
    /// unmodified tree (`6a39fd0`) before any of this existed; a change here is a change to what
    /// chain 18's wallets prove and sign.
    #[test]
    fn the_chain_id_domain_is_the_messages_chain_18_signs_byte_for_byte() {
        let d = BindingDomain::ChainId;
        assert_eq!(d, BindingDomain::default());
        assert_eq!((d.version(), d.genesis()), (0, None));
        let a = Address([1; 32]);
        let addr = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        assert_eq!(words(call().binding(&d)), "32810d042b3d8f85980b0c7aca4065515be099dfa03e3bf3495bffdab6bad0c1");
        assert_eq!(words(call().call_binding(&d)), "a1733aba701405cfa8f8a012c3a7d5c331fa5a07810c3faf87a18687555373ba");
        let pins = [
            (d.mint_signing_hash(13, &[1; 8], &[2; 8], 9, &[3; 8], &env(), 5), "fe426f154b458e69c3a4e1f9b7f26dd64dc20f686244d3473eb77a0637e9ba91"),
            (d.unbond_message(13, &a, 5, 1), "d5a587acc38930f964db6f85619e3ca1f681f6c39e94e696b7f2228cf3c3fbc8"),
            (d.withdraw_message(13, &a, 5, 1, 9, &[3; 8], &env()), "c31db5cd0a494407ee603a318a1e9851e9ef563b6f73740cd2451156c971a711"),
            (d.token_mint_message(13, &Hash([1; 32]), 1, 500, &[3; 8], &env()), "c7c04384a3b34d3017940994921a82380efd3e8d90015723fbba49453cc5c9ef"),
            (d.set_authority_message(13, &Hash([1; 32]), 1, &None), "40ea2453b45f88ec93a7a86c7120f1631e82f6f5a076add8ddb2094e316b2c43"),
            (d.registration_message(13, &a, &addr), "d1a9fdc922586f36ea4cddde6657623bc4105653532b287bb2a2d81d606dd741"),
            (d.aggregator_register_message(13, &a, &addr), "7b318075f1f309b9dde9117f89a2ed260c8ccc61492b786991e03ca76997e147"),
            (d.aggregator_unbond_message(13, &a, 1), "60cc13845a51baa6befe119044e2bb13eee608a75e6c2762f392a8d0d9c2ed90"),
            (d.aggregator_withdraw_message(13, &a, 1, 9, &[3; 8], &env()), "258f3dfcad893de8c234bb9b4cd9d38b6801b4eabcda2155a4b1d864bde66a18"),
            (
                // Moved 2026-10-09 with `payout_total` (`rand-aggregate-2` → `-4`); was
                // `9856f97b61bfabad548524c8a8c3cd55b3aea4b66588ae5cb6818ab74058b112`.
                d.aggregate_signing_hash(13, 1, 9, &[3; 8], &[Hash([7; 32])], &Hash([8; 32]), &Hash([9; 32]), 1_000),
                "6b7b7645f0db32b29351ed37f81f3657c4a2a9f33e8742bf003945829b84b7c7",
            ),
        ];
        for (i, (got, want)) in pins.iter().enumerate() {
            assert_eq!(got.to_hex(), *want, "message {i}");
        }
        assert_eq!(words(d.aggregate_binding(13, &a, 1)), "3fa1eee2c5ddeb21ef05dcab09e22f46c99e6a9063229c82573348a22fc415eb");
    }

    /// BIND-1: under `Genesis`, every binding and every message moves with the genesis hash — two
    /// chains sharing a chain id share none of them — and none equals its chain-id form, so a
    /// proof or signature made before the switch is never one after it.
    #[test]
    fn the_genesis_domain_binds_the_genesis_hash_into_every_message() {
        let (ga, gb) = (BindingDomain::Genesis(Hash([0xa; 32])), BindingDomain::Genesis(Hash([0xb; 32])));
        let v0 = BindingDomain::ChainId;
        assert_eq!((ga.version(), ga.genesis()), (1, Some(&Hash([0xa; 32]))));
        assert_eq!(BindingDomain::for_version(0, Hash([0xa; 32])), v0);
        assert_eq!(BindingDomain::for_version(1, Hash([0xa; 32])), ga);
        let a = Address([1; 32]);
        let addr = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        let all = |d: &BindingDomain| -> Vec<String> {
            vec![
                words(call().binding(d)),
                words(call().call_binding(d)),
                d.mint_signing_hash(13, &[1; 8], &[2; 8], 9, &[3; 8], &env(), 5).to_hex(),
                d.unbond_message(13, &a, 5, 1).to_hex(),
                d.withdraw_message(13, &a, 5, 1, 9, &[3; 8], &env()).to_hex(),
                d.token_mint_message(13, &Hash([1; 32]), 1, 500, &[3; 8], &env()).to_hex(),
                d.set_authority_message(13, &Hash([1; 32]), 1, &None).to_hex(),
                d.registration_message(13, &a, &addr).to_hex(),
                d.aggregator_register_message(13, &a, &addr).to_hex(),
                d.aggregator_unbond_message(13, &a, 1).to_hex(),
                d.aggregator_withdraw_message(13, &a, 1, 9, &[3; 8], &env()).to_hex(),
                d.aggregate_signing_hash(13, 1, 9, &[3; 8], &[Hash([7; 32])], &Hash([8; 32]), &Hash([9; 32]), 1_000).to_hex(),
                words(d.aggregate_binding(13, &a, 1)),
            ]
        };
        let (on_a, on_b, plain) = (all(&ga), all(&gb), all(&v0));
        for i in 0..plain.len() {
            assert_ne!(on_a[i], on_b[i], "message {i}: two genesis hashes, one chain id");
            assert_ne!(on_a[i], plain[i], "message {i}: never the chain-id form");
        }
        // No two kinds collide under one genesis either: thirteen messages, thirteen digests.
        let distinct: std::collections::BTreeSet<&String> = on_a.iter().collect();
        assert_eq!(distinct.len(), on_a.len());
        // The chain id is still inside: the genesis hash is added, nothing is taken out.
        assert_ne!(ga.unbond_message(13, &a, 5, 1), ga.unbond_message(14, &a, 5, 1));
        let mut other_chain = call();
        other_chain.chain_id = 14;
        assert_ne!(other_chain.binding(&ga), call().binding(&ga));
        assert_ne!(other_chain.call_binding(&ga), call().call_binding(&ga));
        // A genesis-bound registration is exactly the v2 message: one signature for both rules.
        assert_eq!(
            ga.registration_message(13, &a, &addr),
            actions::registration_message_v2(&Hash([0xa; 32]), 13, &a, &addr)
        );
        // The blanking is the chain-id binding's: a proof is outside its own binding.
        let mut other_proof = call();
        other_proof.bundle.as_mut().unwrap().proof = vec![7; 3];
        assert_eq!(other_proof.binding(&ga), call().binding(&ga));
        let mut other_call_proof = call();
        if let Action::Call { proof, .. } = &mut other_call_proof.action {
            *proof = vec![1, 2, 3];
        }
        assert_ne!(other_call_proof.binding(&ga), call().binding(&ga), "the call proof is inside the bundle's binding");
        assert_eq!(other_call_proof.call_binding(&ga), call().call_binding(&ga), "and outside its own");
    }
}
