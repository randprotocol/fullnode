//! THROWAWAY spike. Builds the same synthetic hidden-asset bundle as the fullnode's
//! `crates/randprotocol-zkvm/tests/shielded.rs::bundle_witness` (four inputs, four outputs, one
//! real spend), proves it against a fixed transaction binding, verifies it, and reports tier,
//! proof size and milliseconds. Nothing here is chain state.
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::notes::DEPTH;
use randprotocol_zkvm::executor::{prove_bundle, ZkExecutor};
use randprotocol_zkvm::hidden::{self, HiddenOutput};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{Note, SpendKey};

/// A transaction's binding (`Transaction::binding`): the words the bundle is proved against. Any
/// fixed value does for timing; the test uses the same one.
const BINDING: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
use wasm_bindgen::prelude::*;

fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64() * 1000.0
    }
}

pub fn demo_inputs() -> Vec<u32> {
    let sk = SpendKey::random();
    let vk = sk.viewing_key();
    let time = 5u32;
    let spent = Note::new(vk.pk(), [0; 8], 1_000, 0, time);
    let mut tree = randprotocol_zkvm::ledger::CommitmentTree::new();
    tree.append(spent.commitment());
    let (path, index) = tree.path_for(&spent.commitment()).unwrap();
    let anchor = tree.root();
    // Dummy inputs: amount 0, so the guest skips their checks; each with a fresh `r` so their
    // nullifiers differ.
    let dummy = || (Note::new(vk.pk(), [0; 8], 0, 0, time), [[0; 8]; DEPTH], 0u32);
    let ins = [dummy(), dummy(), (spent, path, index), dummy()];
    let fresh_r = || Note::new(vk.pk(), [0; 8], 0, 0, time).r;
    let outs = [
        HiddenOutput { pk: vk.pk(), amount: 0, r: fresh_r() },
        HiddenOutput { pk: vk.pk(), amount: 0, r: fresh_r() },
        HiddenOutput { pk: vk.pk(), amount: 600, r: fresh_r() },
        HiddenOutput { pk: vk.pk(), amount: 390, r: fresh_r() },
    ];
    hidden::hidden_bundle_inputs(&sk, &ins, &outs, anchor, 10, 0, 0, 0, time)
}

/// `production`: the chain's FRI profile (80 queries); otherwise the test profile.
pub fn run(production: bool, verify: bool) -> String {
    let profile = if production { FriProfile::Production } else { FriProfile::Test };
    let t0 = now_ms();
    let inputs = demo_inputs();
    let t1 = now_ms();
    let (proof, _digest, tier) = match prove_bundle(profile, &inputs, &BINDING, Backend::Cpu) {
        Ok(x) => x,
        Err(e) => return serde_json::json!({"error": e}).to_string(),
    };
    let t2 = now_ms();
    let verify_ms = if verify {
        let ex = ZkExecutor::new(profile);
        let r = ex.verify_bundle(&ZkExecutor::hc_bundle(), &proof, &BINDING);
        let t3 = now_ms();
        if r.is_err() { return serde_json::json!({"error": "verify failed"}).to_string(); }
        Some(t3 - t2)
    } else { None };
    serde_json::json!({
        "profile": if production { "production" } else { "test" },
        "tier": tier, "proof_bytes": proof.len(),
        "inputs_ms": t1 - t0, "prove_ms": t2 - t1, "verify_ms": verify_ms,
    }).to_string()
}

#[wasm_bindgen(js_name = proveDemoBundle)]
pub fn prove_demo_bundle_js(production: bool, verify: bool) -> String {
    run(production, verify)
}
