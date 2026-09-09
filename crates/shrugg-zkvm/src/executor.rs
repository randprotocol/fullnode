//! The chain-side verifier: implements shrugg-core's executor trait with the zkVM.
//!
//! Verifying a proof costs ~20 ms once the verifier key for its program is known; computing
//! that key (the preprocessed program + byte-table commitment, FRI-expanded) costs ~2 s. Keys
//! are therefore cached per (program, tier).

use crate::isa::{Instr, Program};
use crate::machine::{chips, Config, FriProfile, Machine, Proof, Tier, Val, TIERS};
use crate::tables::cpu::pv;
use p3_batch_stark::{verify_batch, CommonData};
use p3_field::PrimeCharacteristicRing;
use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::program::{CallOutcome, ProgramId, ProgramRecord};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const KEY_CACHE: usize = 64;

pub struct ZkExecutor {
    machine: Machine,
    keys: Mutex<HashMap<(ProgramId, usize), Arc<CommonData<Config>>>>,
}

impl ZkExecutor {
    pub fn new(profile: FriProfile) -> ZkExecutor {
        ZkExecutor { machine: Machine::new(profile), keys: Mutex::new(HashMap::new()) }
    }

    pub fn profile(&self) -> FriProfile {
        self.machine.profile
    }

    pub fn profile_from_str(s: &str) -> Option<FriProfile> {
        match s {
            "production" => Some(FriProfile::Production),
            "test" => Some(FriProfile::Test),
            _ => None,
        }
    }

    fn program(record: &ProgramRecord) -> Program {
        Program { base_pc: record.base_pc, words: record.words.clone() }
    }

    fn key_for(&self, record: &ProgramRecord, tier: Tier) -> Arc<CommonData<Config>> {
        let k = (record.id, tier.0);
        if let Some(c) = self.keys.lock().unwrap().get(&k) {
            return c.clone();
        }
        let key = Arc::new(self.machine.verifier_key(&Self::program(record), tier));
        let mut cache = self.keys.lock().unwrap();
        if cache.len() >= KEY_CACHE {
            cache.clear();
        }
        cache.insert(k, key.clone());
        key
    }

    /// Number of cached verifier keys (for tests and status).
    pub fn cached_keys(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

impl ConfidentialExecutor for ZkExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        if base_pc % 4 != 0 {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "base_pc not word aligned".into() });
        }
        if words.is_empty() {
            return Err(ConfidentialError::BadInstruction { index: 0, reason: "empty program".into() });
        }
        for (index, w) in words.iter().enumerate() {
            Instr::decode(*w).map_err(|e| ConfidentialError::BadInstruction { index, reason: format!("{e:?}") })?;
        }
        // The on-chain code commitment is the content id; the zkVM's Poseidon2 commitment is
        // what the verifier key holds and is computed by `warm`/`verify_call` (2 s), never here.
        Ok(shrugg_core::program::program_id(base_pc, words).0.to_vec())
    }

    fn warm(&self, record: &ProgramRecord) {
        let _ = self.key_for(record, Tier(TIERS[0]));
    }

    fn verify_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        let proof: Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if !TIERS.contains(&proof.tier.0) {
            return Err(ConfidentialError::InvalidProof("unknown tier".into()));
        }
        if proof.public_values.len() != pv::NUM {
            return Err(ConfidentialError::MalformedProof);
        }
        if proof.public_values[pv::PC_ENTRY] != record.base_pc as u64 {
            return Err(ConfidentialError::WrongProgram);
        }
        if proof.public_values[pv::TIER] != proof.tier.0 as u64 {
            return Err(ConfidentialError::InvalidProof("tier mismatch".into()));
        }
        let program = Self::program(record);
        if proof.batch.degree_bits != self.machine.log_ext_degrees_pub(&program, proof.tier) {
            return Err(ConfidentialError::InvalidProof("degree bits".into()));
        }
        let key = self.key_for(record, proof.tier);
        let airs = chips(&program);
        let pvals: Vec<Val> = proof.public_values.iter().map(|x| Val::from_u64(*x)).collect();
        let pvs: Vec<Vec<Val>> = (0..5).map(|i| if i == 1 { pvals.clone() } else { vec![] }).collect();
        verify_batch(&self.machine.config, &airs, &proof.batch, &pvs, &key)
            .map_err(|e| ConfidentialError::InvalidProof(format!("{e:?}")))?;
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() {
            let v = proof.public_values[pv::OUT0 + i];
            if v > u32::MAX as u64 {
                return Err(ConfidentialError::InvalidProof("output not a u32".into()));
            }
            *o = v as u32;
        }
        Ok(CallOutcome { tier: proof.tier.0 as u8, outputs })
    }
}

/// The zkVM's own commitment to a program (Poseidon2 Merkle root of the preprocessed
/// program and byte tables). Costs ~2 s; informational, e.g. for explorers.
pub fn zk_code_hash(profile: FriProfile, program: &Program) -> String {
    Machine::new(profile).code_hash(program, Tier(TIERS[0]))
}

/// Prover entry point for the wallet and tests. Returns (proof bytes, outputs, tier).
pub fn prove(profile: FriProfile, program: &Program, inputs: &[u32], tier: Option<u8>) -> Result<(Vec<u8>, [u32; 8], u8), String> {
    let m = Machine::new(profile);
    let (proof, exec) = m.prove(program, inputs, tier.map(|t| Tier(t as usize))).map_err(|e| format!("{e:?}"))?;
    Ok((proof.to_bytes(), exec.outputs, proof.tier.0 as u8))
}
