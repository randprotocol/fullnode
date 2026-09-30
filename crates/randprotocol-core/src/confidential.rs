//! Confidential computation: the executor the ledger calls to validate programs, verify call
//! proofs and reach every Poseidon2 hash the shielded pool needs. `randprotocol-zkvm` provides the
//! real implementation (`ZkExecutor`); `StubExecutor` is a crypto-free stand-in for fast tests.

use crate::crypto::Hash;
use crate::notes::{word8_from_bytes, word8_to_bytes, BundleDigestInput, Word8};
use crate::program::{CallOutcome, ProgramRecord};
use crate::types::{Transaction, TX_BINDING_WORDS};

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ConfidentialError {
    #[error("program word {index} does not decode: {reason}")]
    BadInstruction { index: usize, reason: String },
    #[error("malformed proof")]
    MalformedProof,
    #[error("proof does not verify: {0}")]
    InvalidProof(String),
    #[error("proof is for another program")]
    WrongProgram,
    /// A call proof's declared tier is above the highest one the chain admits for a call
    /// (`randprotocol_zkvm::executor::MAX_CALL_TIER`). Decided on the proof's header bytes alone,
    /// before any verifier key is built (deep scan 2026-09-24, zkvm): the key for a tier-20 header
    /// costs minutes and gigabytes to build, so an unbounded tier was an out-of-memory kill of
    /// the admitting node for the price of one fee bundle. A permanent admission verdict, like
    /// every other `InvalidProof`-class refusal — the tier is in the bytes.
    #[error("call proof declares tier {tier}, above the {max} this chain admits for a call: prove the call at tier {max} or below (a smaller input, a shorter program, or the work split across calls)")]
    CallTierTooHigh { tier: u8, max: u8 },
    #[error("bundle proof: {0}")]
    InvalidBundleProof(String),
    /// Block aggregation: the aggregate proof's interface digest does not match the covered
    /// bundles' recomputed list, or the rVM `Machine::verify` refused it (spec §4 steps 7–8).
    #[error("aggregate proof: {0}")]
    InvalidAggregateProof(String),
    /// Block aggregation: this executor does not build or verify aggregate proofs (the bare
    /// zkVM executor; the node wraps it with the rVM-backed aggregating one). Never a
    /// transaction's fault, so never a permanent admission verdict.
    #[error("this executor does not support aggregate proofs")]
    AggregationUnsupported,
    /// Block aggregation: the registered declared shape is one the rVM refuses to build a
    /// verifier for (`InnerShape::try_of`). A chain-configuration error, never a transaction's
    /// fault — never a permanent admission verdict either.
    #[error("the registered shape is not one a proof can have: {0}")]
    BadDeclaredShape(String),
    #[error("confidential computation is disabled on this chain")]
    Disabled,
}

pub trait ConfidentialExecutor: Send + Sync {
    /// Validate program code at deploy time (must be cheap: it runs inside block application)
    /// and return the code commitment recorded on chain.
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError>;
    /// CPU-1: the most program words any call can hold when its public segment is
    /// `public_segment_words` long — the call tier cap's Poseidon2 budget, less the digests every
    /// proof pays before it executes (`randprotocol_zkvm::executor::max_callable_program_words`).
    /// A program past it deploys and can never be proved. `None` (the default, and the stub's)
    /// is "no bound this executor knows of". The ledger asks only under genesis `hardening_v6`.
    fn max_callable_program_words(&self, _public_segment_words: usize) -> Option<usize> {
        None
    }
    /// Verify `proof` against `program`; on success return the tier and the eight outputs.
    ///
    /// The proof's public-input digest (`pv::PUB0..7`) must equal `program.public_digest`, or
    /// `public_digest(&[])` for a program deployed without a public input; a mismatch is
    /// `InvalidProof("PublicValues")`. The public words are never re-hashed here: the digest was
    /// computed once, at deploy.
    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError>;
    /// Decode `proof` against `program` and return exactly what [`Self::verify_call`] would
    /// return, but without the STARK verification. Called only for a transaction whose hash a
    /// [`crate::ledger::VerifiedProofs`] set vouches for — one this node already ran `verify_call`
    /// on, against this same record (a program's record is immutable once deployed) and this same
    /// proof (bound by the transaction hash) — so the answer is the one admission computed, and
    /// every check a validator that re-verifies would apply to the outcome (the tier's fee floor,
    /// the receipt's words) still runs here.
    ///
    /// The default is `verify_call` itself: an executor that cannot decode without verifying
    /// simply pays the full cost again, which is always correct.
    fn decode_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.verify_call(program, proof)
    }
    /// `verify_call` under genesis `hardening_v6` (INT-4 of the 2026-09-27 zkVM/ISA review): the
    /// same checks, but the call must carry `segment` as its public segment
    /// (`pv::PUB0..7 == H_PUB(segment)`) — the program's deploy-time public words followed by
    /// [`crate::types::Transaction::call_binding`] of the transaction it rides in
    /// ([`crate::program::hardened_call_segment`], built by the ledger, which keeps the words), so
    /// just the binding for a program without a public input, where today's rule wants the empty
    /// segment. A copy of the proof under any other fee bundle is then refused (`PublicValues`).
    /// Until issue #55 a program deployed with a public input kept its recorded digest and stayed
    /// unbound, because the ledger held only that digest; it holds the words now. A segment that is
    /// not `public_len + TX_BINDING_WORDS` long is refused the same way. And every call's program
    /// table is floored at 2^7 rows (PROGRAM-TABLE-LEAK: a smaller one publishes the call's fetch
    /// counts), so the declared height is `max(record height, 7)`, exactly. The default refuses
    /// every call: an executor that has not implemented the rules must not pass them by default.
    fn verify_call_hardened(
        &self,
        _program: &ProgramRecord,
        _proof: &[u8],
        _segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        Err(ConfidentialError::InvalidProof("this executor does not implement the hardening_v6 call rules".into()))
    }
    /// [`Self::decode_call`]'s twin for [`Self::verify_call_hardened`]: everything but the STARK
    /// verification, for a transaction the verified set vouches for. Defaults to the full verify.
    fn decode_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.verify_call_hardened(program, proof, segment)
    }
    /// Precompute whatever makes `verify_call` fast for `program` (the zkVM verifier key,
    /// ~2 s). Called from a background task after a deploy commits and at startup; may be a no-op.
    fn warm(&self, _program: &ProgramRecord) {}
    /// [`Self::warm`] for a chain whose genesis sets `hardening_v6`, where a call's shape follows
    /// the hardened rules (the call binding as a program's public segment, INT-4) and so needs
    /// other verifier keys. The node calls whichever its ledger runs. Defaults to `warm`.
    fn warm_hardened(&self, program: &ProgramRecord) {
        self.warm(program)
    }
    /// `H_PUB` of a public input (`randprotocol_zkvm::hash::public_digest`): what a call's proof
    /// publishes in `pv::PUB0..7`. The ledger calls it once per deploy with a non-empty public
    /// input and stores the result on the program's record.
    fn public_digest(&self, words: &[u32]) -> Word8;
    /// Poseidon2 tree-node hash `H(NODE, left || right)` — the hash `MERKLE_VERIFY` checks against.
    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8;
    /// The note commitment `H(CM, pk(8) from(8) amount_lo amount_hi asset time r(8))` — the
    /// 28-word note layout of the vendored `randprotocol_zkvm::notes::Note`.
    ///
    /// The ledger needs this for the deposits it creates itself rather than accepts on the
    /// wire: S2's `Withdraw` and S3's `BridgeAttest` publish only the blinding `r` and a public
    /// amount, and the chain computes the commitment, so a validator cannot declare one amount
    /// and mint a note for another.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8;
    /// The hidden-asset bundle digest (`randprotocol_zkvm::hidden::hidden_bundle_digest`, spec
    /// §3.4) over the public bundle fields with the taint word fixed to 0. No asset is among them.
    /// `input.auth_commit` is not read: this is the digest of bundle guests v1 and v2, which
    /// every chain without genesis `hc_auth` runs.
    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8;
    /// The digest bundle guest v3 publishes (split authorisation, delegated proving Phase 2;
    /// `randprotocol_zkvm::hidden::hidden_bundle_digest_v3`): [`Self::bundle_digest`]'s preimage
    /// with `input.auth_commit` before the taint word. The ledger recomputes this one, and only
    /// this one, on a chain whose genesis names `hc_auth`.
    fn bundle_digest_v3(&self, input: &BundleDigestInput) -> Word8;
    /// Cheap: decode `proof`, check its declared tier/heights/public-value canonicity against the
    /// bundle guest `hc_bundle` (the chain's genesis pin — each guest has its own pinned heights),
    /// and return the digest it publishes in `OUT0..OUT7`. Verifies nothing cryptographic.
    fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    /// Cheap: decode an auth proof (split authorisation), check its header against the auth
    /// guest's pinned shape, and return the commitment `c` it publishes in `OUT0..OUT7`. Verifies
    /// nothing cryptographic — the ledger compares the answer with the bundle's `auth_commit`
    /// before paying for [`Self::verify_auth`].
    fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError>;
    /// Expensive: the STARK verification of an auth proof against the pinned auth guest
    /// `hc_auth` (genesis) and against `binding` — the [`crate::types::Transaction::binding`] of
    /// the transaction it rides in, as its public input segment — returning the `c` it publishes.
    /// A proof made for another transaction, or by another guest, is refused; so an auth proof
    /// cannot be replayed onto a transaction its key holder never signed off.
    fn verify_auth(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; crate::types::TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError>;
    /// Constraint set 8: the gas limit a bundle proof declares (`pv::GAS`) — a decode, not a
    /// verification: the value is trusted only once [`Self::verify_bundle`] has accepted the
    /// same bytes (the circuit binds it, spec 2026-09-28 §4.2). `None` (the default) is "this
    /// executor's proofs carry no limit".
    fn bundle_gas_limit(&self, _proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        Ok(None)
    }
    /// Constraint set 8, split authorisation: the gas limit an auth proof declares (`pv::GAS`) —
    /// a decode at the auth guest's pinned shape, not a verification: trusted only once
    /// [`Self::verify_auth`] has accepted the same bytes. `None` (the default) is "this
    /// executor's proofs carry no limit".
    fn auth_gas_limit(&self, _proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        Ok(None)
    }
    /// Expensive: the STARK verification of a bundle proof against the pinned bundle guest (the
    /// hidden-asset guest since chain 14, `hc_bundle` in genesis), and
    /// against `binding` — the [`crate::types::Transaction::binding`] of the transaction the
    /// bundle rides in, which the proof must carry as its public input segment
    /// (`pv::PUB0..7 == H_PUB(binding)`). A proof made for any other transaction, or against the
    /// empty segment, is refused: that is what keeps a copied proof from riding a changed action,
    /// or changed envelopes.
    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; crate::types::TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError>;
    /// Precompute the bundle verifier key. May be a no-op.
    fn warm_bundle(&self) {}
    /// Precompute the auth guest's verifier key (split authorisation). May be a no-op. A node
    /// calls it only on a chain whose genesis names `hc_auth`; no earlier chain needs the key.
    fn warm_auth(&self) {}
    /// The v0.6 canonical-proof rules, for a bundle or a call proof alike: the first header or
    /// transcript field of `proof` that is not the value the honest prover writes, named, or
    /// `None`. A field the verifier does not bind to the statement lets anyone who relays a
    /// transaction re-encode its proof into a different transaction id for the same statement,
    /// and a shape the aggregate program was not built for can never be covered; the rules pin
    /// each such field (`randprotocol_zkvm::executor::non_canonical`). Cheap: a decode and a few
    /// compares, nothing verified. `None` for bytes that do not decode — those are refused
    /// elsewhere — and from the default (the stub's). The ledger asks only under genesis
    /// `hardening_v6`; every node's pool asks everywhere.
    fn non_canonical_proof(&self, _proof: &[u8]) -> Option<String> {
        None
    }

    /// The registered aggregate program's digest for an admitted shape (block aggregation,
    /// spec §2.3): a startup constant, recomputed from the shape alone. Cheap relative to
    /// verification (the DSL program build, not the proving key).
    fn aggregate_program_digest(&self, shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError>;
    /// The aggregate proof's header, alone and cheap (the interface review's INTERFACE-5): the
    /// decode, the canonical encoding and the admitted rVM tier — every refusal that needs no
    /// program. Admission runs it before step 7b's program build, so a proof at a tier the chain
    /// never admits buys nothing; `verify_aggregate` still checks all of it itself. The default
    /// (the stub, and any executor without the rVM) admits every header.
    fn check_aggregate_header(&self, _proof: &[u8]) -> Result<(), ConfidentialError> {
        Ok(())
    }
    /// spec §4 steps 7–8: the interface-list recompute and digest compare against the proof's
    /// batch public values, then the rVM `Machine::verify` of the aggregate proof against the
    /// registered aggregate program. Returns each covered bundle's `OUT0..7` in cover order.
    /// `binding` is [`crate::types::actions::aggregate_binding`] of the transaction's own
    /// `(chain, aggregator, nonce)` (audit v3, AGG-2): the interface list carries it between the
    /// count and the public values, so a proof made under any other triple is refused.
    /// Expensive: the rVM verify (~1–2 s warm at production; the first call at a shape pays the
    /// startup key-build).
    fn verify_aggregate(
        &self,
        shape: &crate::types::DeclaredShape,
        covered: &[crate::types::CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError>;
    /// Precompute the aggregate program and the rVM verifier key for an admitted shape (the
    /// startup key-build, ~30–70 s at production). Called once at node startup on a chain whose
    /// genesis has an `aggregation` section; may be a no-op.
    fn warm_aggregation(&self, _shape: &crate::types::DeclaredShape) {}
}

/// Test executor. A "proof" is `STUB` || tier (1 byte) || 8 outputs (LE u32) || `H_IN`
/// (8 LE u32) || `H_PUB` (8 LE u32) || blake3(program id)[..8] || the declared gas limit (LE
/// u64, constraint set 8's `pv::GAS`). Any code is accepted. Never use on a real chain.
#[derive(Debug, Default, Clone)]
pub struct StubExecutor;

pub const STUB_MARKER: &[u8; 4] = b"STUB";
const STUB_LEN: usize = 4 + 1 + 32 + 32 + 32 + 8 + 8;
/// Where the program binding starts inside a stub call proof (the gas limit follows it).
const STUB_PROGRAM_BINDING: usize = STUB_LEN - 16;
/// Stub bundle proof: `STUB` || 32-byte digest || blake3("rand-stub-bundle", hc_bundle bytes)[..8]
/// || the 8 binding words (32 bytes, little-endian) — the stand-in for a real proof's public
/// input segment, compared word for word by `verify_bundle` exactly as the zkVM compares `H_PUB`
/// — || the declared gas limit (LE u64, constraint set 8's `pv::GAS`).
const STUB_BUNDLE_LEN: usize = 4 + 32 + 8 + 32 + 8;
/// The tag of a stub aggregate proof that carries its binding (AGG-2), followed by the eight
/// binding words (32 bytes, little-endian).
const STUB_AGGREGATE_TAG: &[u8] = b"rand-stub-aggregate-bound";

/// Where the binding words start inside a stub bundle proof.
const STUB_BUNDLE_BINDING: usize = 4 + 32 + 8;
/// Stub auth proof: `auth:` || the 32-byte `c` || blake3("rand-stub-auth", hc_auth bytes)[..8] ||
/// the 8 binding words (32 bytes, little-endian) || the declared gas limit (8 bytes, little-endian)
/// — [`STUB_BUNDLE_LEN`]'s layout under its own tag.
const STUB_AUTH_MARKER: &[u8; 5] = b"auth:";
const STUB_AUTH_LEN: usize = 5 + 32 + 8 + 32 + 8;
/// Where the binding words start inside a stub auth proof.
const STUB_AUTH_BINDING: usize = 5 + 32 + 8;
/// Where the gas limit starts inside a stub auth proof: its last eight bytes.
const STUB_AUTH_GAS: usize = STUB_AUTH_BINDING + 32;
/// The gas limit a stub auth proof declares unless a test chooses one: `gas_max(10, 0, 0)`,
/// what every real auth proof declares (tier 10, no hash table).
pub const STUB_AUTH_GAS_LIMIT: u64 = 1_279;
/// Where the gas limit starts inside a stub bundle proof: its last eight bytes.
const STUB_BUNDLE_GAS: usize = STUB_BUNDLE_BINDING + 32;

impl StubExecutor {
    /// A stub call proof publishing an all-zero `H_IN` — what a test that is not about the
    /// input commitment wants. [`Self::make_proof_with_h_in`] is the same proof with a chosen one.
    pub fn make_proof(program: &Hash, tier: u8, outputs: [u32; 8]) -> Vec<u8> {
        Self::make_proof_with_h_in(program, tier, outputs, [0; 8])
    }

    /// A stub call proof publishing `h_in` as its private-input commitment (`pv::IN0..7` on a
    /// real proof) — what a call-input envelope is sealed against (spec §6.1).
    pub fn make_proof_with_h_in(program: &Hash, tier: u8, outputs: [u32; 8], h_in: Word8) -> Vec<u8> {
        Self::make_proof_full(program, tier, outputs, h_in, &[])
    }

    /// A stub call proof committed to the public input `public` (`pv::PUB0..7` on a real proof):
    /// what a call against a program deployed with that public input must carry.
    pub fn make_proof_with_public(program: &Hash, tier: u8, outputs: [u32; 8], public: &[u32]) -> Vec<u8> {
        Self::make_proof_full(program, tier, outputs, [0; 8], public)
    }

    /// A stub call proof declaring `gas_limit` (`pv::GAS` on a real proof) instead of the
    /// header's ceiling `gas_max(tier, 0, 0)`, which every other `make_proof*` declares.
    pub fn make_proof_with_gas(program: &Hash, tier: u8, outputs: [u32; 8], gas_limit: u64) -> Vec<u8> {
        let mut v = Self::make_proof_full(program, tier, outputs, [0; 8], &[]);
        v[STUB_LEN - 8..].copy_from_slice(&gas_limit.to_le_bytes());
        v
    }

    fn make_proof_full(program: &Hash, tier: u8, outputs: [u32; 8], h_in: Word8, public: &[u32]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.push(tier);
        for o in outputs {
            v.extend_from_slice(&o.to_le_bytes());
        }
        v.extend_from_slice(&word8_to_bytes(&h_in));
        v.extend_from_slice(&word8_to_bytes(&StubExecutor.public_digest(public)));
        v.extend_from_slice(&Hash::digest_domain(b"rand-stub-binding", program.as_bytes()).0[..8]);
        v.extend_from_slice(&crate::gas::gas_max(tier, 0, 0).to_le_bytes());
        v
    }

    /// Build a stub aggregate proof made under `binding` — the
    /// [`crate::types::actions::aggregate_binding`] of the `(chain, aggregator, nonce)` it was
    /// proved for (audit v3, AGG-2). The stub refuses it under any other binding, as the rVM
    /// does; stub aggregate proofs without this tag carry no binding and are accepted as before.
    pub fn make_aggregate_proof(binding: &[u32; 8]) -> Vec<u8> {
        let mut v = STUB_AGGREGATE_TAG.to_vec();
        v.extend_from_slice(&word8_to_bytes(binding));
        v
    }

    /// Build a stub bundle proof publishing `digest`, bound to the guest commitment `hc_bundle`
    /// and to `binding` — the [`Transaction::binding`] of the transaction it will ride in.
    pub fn make_bundle_proof(hc_bundle: &Word8, digest: &Word8, binding: &[u32; TX_BINDING_WORDS]) -> Vec<u8> {
        let mut v = STUB_MARKER.to_vec();
        v.extend_from_slice(&word8_to_bytes(digest));
        v.extend_from_slice(&Hash::digest_domain(b"rand-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8]);
        v.extend_from_slice(&word8_to_bytes(binding));
        // The gas limit a stub bundle proof declares unless a test chooses one (`with_bundle_gas`):
        // `gas_max(BUNDLE_PROOF_TIER, 0, 0)`, what every real hidden-asset bundle proof declares
        // (tier 14, no hash table) and the one `bundle_gas_limit` a genesis may name.
        v.extend_from_slice(&crate::gas::bundle_gas_limit_pin().to_le_bytes());
        v
    }

    /// Build a stub auth proof publishing the commitment `c`, made by the auth guest `hc_auth`
    /// and bound to `binding` — the [`Transaction::binding`] of the transaction it will ride in.
    pub fn make_auth_proof(hc_auth: &Word8, c: &Word8, binding: &[u32; TX_BINDING_WORDS]) -> Vec<u8> {
        let mut v = STUB_AUTH_MARKER.to_vec();
        v.extend_from_slice(&word8_to_bytes(c));
        v.extend_from_slice(&Hash::digest_domain(b"rand-stub-auth", &word8_to_bytes(hc_auth)).0[..8]);
        v.extend_from_slice(&word8_to_bytes(binding));
        v.extend_from_slice(&STUB_AUTH_GAS_LIMIT.to_le_bytes());
        v
    }

    /// Rewrite the gas limit a stub auth proof declares, as [`Self::with_bundle_gas`] does a
    /// bundle proof's. Anything that is not a well-formed stub auth proof is left untouched.
    pub fn with_auth_gas(proof: &mut [u8], gas_limit: u64) {
        if proof.len() == STUB_AUTH_LEN && &proof[..5] == STUB_AUTH_MARKER {
            proof[STUB_AUTH_GAS..].copy_from_slice(&gas_limit.to_le_bytes());
        }
    }

    /// Rewrite the gas limit a stub bundle proof declares. Anything that is not a well-formed
    /// stub bundle proof is left untouched, as [`Self::bind`] leaves it. The limit is not part of
    /// the transaction binding (the binding blanks the proof), so no re-bind is needed after.
    pub fn with_bundle_gas(proof: &mut [u8], gas_limit: u64) {
        if proof.len() == STUB_BUNDLE_LEN && &proof[..4] == STUB_MARKER {
            proof[STUB_BUNDLE_GAS..].copy_from_slice(&gas_limit.to_le_bytes());
        }
    }

    /// Re-bind the stub bundle proof `tx` carries to `tx.binding()`, leaving the proof's digest
    /// and guest commitment as they were, and leaving anything that is not a well-formed stub
    /// bundle proof (a pruned marker, deliberately broken bytes) untouched. What a test calls once
    /// it has finished assembling a transaction: the stub's analogue of a wallet proving after it
    /// has built everything but the proof.
    ///
    /// The binding blanks the bundle proof, so rewriting it does not move the binding. A stub
    /// auth proof (split authorisation) is re-bound the same way; the binding blanks it too.
    pub fn bind(tx: &mut Transaction) {
        Self::bind_in(tx, &crate::types::BindingDomain::ChainId)
    }

    /// [`Self::bind`] on a chain of `domain` (BIND-1): the stub proofs are re-bound to
    /// `tx.binding(domain)`, what a wallet on a `binding_domain: 1` chain proves against.
    pub fn bind_in(tx: &mut Transaction, domain: &crate::types::BindingDomain) {
        let binding = word8_to_bytes(&tx.binding(domain));
        if let Some(b) = tx.bundle.as_mut() {
            if b.proof.len() == STUB_BUNDLE_LEN && &b.proof[..4] == STUB_MARKER {
                b.proof[STUB_BUNDLE_BINDING..STUB_BUNDLE_GAS].copy_from_slice(&binding);
            }
            if b.auth_proof.len() == STUB_AUTH_LEN && &b.auth_proof[..5] == STUB_AUTH_MARKER {
                b.auth_proof[STUB_AUTH_BINDING..STUB_AUTH_GAS].copy_from_slice(&binding);
            }
        }
    }

    /// [`Self::bind`], by value.
    pub fn bound(mut tx: Transaction) -> Transaction {
        Self::bind(&mut tx);
        tx
    }

    /// [`Self::bind_in`], by value.
    pub fn bound_in(mut tx: Transaction, domain: &crate::types::BindingDomain) -> Transaction {
        Self::bind_in(&mut tx, domain);
        tx
    }

    /// `verify_call`'s body, and `verify_call_hardened`'s with `segment`: the expected `H_PUB` is
    /// the record's digest, or — for a program without a public input — the empty segment's; under
    /// the hardened rule it is the segment's (`public ‖ call_binding`), whose length must be the
    /// record's `public_len` plus the binding's.
    fn verify_stub_call(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: Option<&[u32]>,
    ) -> Result<CallOutcome, ConfidentialError> {
        if proof.len() != STUB_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        let expected = &Hash::digest_domain(b"rand-stub-binding", program.id.as_bytes()).0[..8];
        if &proof[STUB_PROGRAM_BINDING..STUB_LEN - 8] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        let tier = proof[4];
        let mut outputs = [0u32; 8];
        for (i, o) in outputs.iter_mut().enumerate() {
            *o = u32::from_le_bytes(proof[5 + 4 * i..9 + 4 * i].try_into().unwrap());
        }
        let h_in = word8_from_bytes(&proof[37..69]).expect("32 bytes");
        let h_pub = word8_from_bytes(&proof[69..101]).expect("32 bytes");
        let want = match (program.public_digest, segment) {
            (_, Some(s)) if s.len() != program.public_len as usize + TX_BINDING_WORDS => {
                return Err(ConfidentialError::InvalidProof("PublicValues".into()));
            }
            (_, Some(s)) => self.public_digest(s),
            (Some(d), None) => d,
            (None, None) => self.public_digest(&[]),
        };
        if h_pub != want {
            return Err(ConfidentialError::InvalidProof("PublicValues".into()));
        }
        let gas_limit = u64::from_le_bytes(proof[STUB_LEN - 8..].try_into().expect("8 bytes"));
        Ok(CallOutcome { tier, outputs, h_in, keccak_log_height: 0, sha256_log_height: 0, gas_limit })
    }

    fn hash_words(domain: &[u8], parts: &[&[u8]]) -> Word8 {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        word8_from_bytes(&Hash::digest_domain(domain, &buf).0).unwrap()
    }
}

impl ConfidentialExecutor for StubExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        Ok(crate::program::program_id(base_pc, words).0.to_vec())
    }

    /// The zkVM's own bound at its call tier cap (tier 14: 2 048 Poseidon2 slots, one for the
    /// empty input's salt row, `max(1, ⌈n/4⌉)` for an `n`-word public segment, four program words
    /// a slot), restated so the ledger's CPU-1 rule can be exercised without the zkVM.
    /// `randprotocol-zkvm`'s executor tests pin it to the real function.
    fn max_callable_program_words(&self, public_segment_words: usize) -> Option<usize> {
        Some(4 * 2048usize.saturating_sub(1 + public_segment_words.div_ceil(4).max(1)))
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.verify_stub_call(program, proof, None)
    }

    /// The stub's INT-4 rule, as the zkVM's: the segment's digest, `public ‖ call_binding`, where
    /// `verify_call` wants the record's (`make_proof_with_public(.., &segment)` makes such a
    /// proof).
    fn verify_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.verify_stub_call(program, proof, Some(segment))
    }

    /// A blake3 stand-in for `H_PUB`, length-prefixed like the real one's header, so the empty
    /// input has its own fixed, non-zero digest as it does in the zkVM.
    fn public_digest(&self, words: &[u32]) -> Word8 {
        let mut buf = (words.len() as u32).to_le_bytes().to_vec();
        for w in words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        Self::hash_words(b"rand-stub-public", &[&buf])
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        Self::hash_words(b"rand-stub-node", &[&word8_to_bytes(left), &word8_to_bytes(right)])
    }

    /// A blake3 stand-in over the same six fields. It is not the real note commitment and no
    /// note sealed against it will ever open on a real chain — but it is injective in exactly
    /// the fields the real one is, which is what the ledger's tests need.
    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        Self::hash_words(
            b"rand-stub-note",
            &[
                &word8_to_bytes(pk),
                &word8_to_bytes(from),
                &amount.to_le_bytes(),
                &asset.to_le_bytes(),
                &time.to_le_bytes(),
                &word8_to_bytes(r),
            ],
        )
    }

    /// A blake3 stand-in over every public field of the hidden-asset digest (spec §3.4), in the
    /// real one's order: anchor, the four nullifiers, the four commitments, `fee`, `burn_a`,
    /// `burn_r`, `burn_asset`, `time`. Injective in exactly those fields, like the real one.
    fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
        let mut parts: Vec<Vec<u8>> = vec![word8_to_bytes(&i.anchor).to_vec()];
        parts.extend(i.nullifiers.iter().map(|w| word8_to_bytes(w).to_vec()));
        parts.extend(i.commitments.iter().map(|w| word8_to_bytes(w).to_vec()));
        parts.push(i.fee.to_le_bytes().to_vec());
        parts.push(i.burn_a.to_le_bytes().to_vec());
        parts.push(i.burn_r.to_le_bytes().to_vec());
        parts.push(i.burn_asset.to_le_bytes().to_vec());
        parts.push(i.time.to_le_bytes().to_vec());
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Self::hash_words(b"rand-stub-hidden-bundle-digest", &refs)
    }

    /// The v1 stand-in's fields, then `auth_commit`, under its own domain — so a v3 digest never
    /// equals a v1 one, and it binds `auth_commit` as the real v3 preimage does.
    fn bundle_digest_v3(&self, i: &BundleDigestInput) -> Word8 {
        let v1 = self.bundle_digest(i);
        Self::hash_words(b"rand-stub-hidden-bundle-digest-v3", &[&word8_to_bytes(&v1), &word8_to_bytes(&i.auth_commit)])
    }

    /// The stub reads the digest whatever `hc_bundle` is: a stub proof's guest tag is checked by
    /// `verify_bundle`, as the zkVM's `hc` is.
    fn bundle_proof_digest(&self, _hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        if proof.len() != STUB_BUNDLE_LEN || &proof[..4] != STUB_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        Ok(word8_from_bytes(&proof[4..36]).unwrap())
    }

    fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        if proof.len() != STUB_AUTH_LEN || &proof[..5] != STUB_AUTH_MARKER {
            return Err(ConfidentialError::MalformedProof);
        }
        Ok(word8_from_bytes(&proof[5..37]).unwrap())
    }

    fn verify_auth(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError> {
        let c = self.auth_proof_digest(proof)?;
        let expected = &Hash::digest_domain(b"rand-stub-auth", &word8_to_bytes(hc_auth)).0[..8];
        if &proof[37..STUB_AUTH_BINDING] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        if proof[STUB_AUTH_BINDING..STUB_AUTH_GAS] != word8_to_bytes(binding) {
            return Err(ConfidentialError::InvalidProof("PublicValues".into()));
        }
        Ok(c)
    }

    fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.bundle_proof_digest(&[0; 8], proof)?;
        Ok(Some(u64::from_le_bytes(proof[STUB_BUNDLE_GAS..].try_into().expect("8 bytes"))))
    }

    fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.auth_proof_digest(proof)?;
        Ok(Some(u64::from_le_bytes(proof[STUB_AUTH_GAS..].try_into().expect("8 bytes"))))
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        self.bundle_proof_digest(hc_bundle, proof)?;
        let expected = &Hash::digest_domain(b"rand-stub-bundle", &word8_to_bytes(hc_bundle)).0[..8];
        if &proof[36..STUB_BUNDLE_BINDING] != expected {
            return Err(ConfidentialError::WrongProgram);
        }
        // The binding, as the zkVM checks `H_PUB`: a proof made for another transaction is
        // refused with the same words `Machine::verify_public` reports (`PublicValues`).
        if proof[STUB_BUNDLE_BINDING..STUB_BUNDLE_GAS] != word8_to_bytes(binding) {
            return Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        }
        Ok(())
    }

    fn aggregate_program_digest(&self, _shape: &crate::types::DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
        // A stand-in digest, not the real one — distinctive so a test that forgot to stub the
        // right thing notices, and deterministic so the rest can compare.
        Ok([0xa66_e6a7e_u64; 4])
    }

    fn verify_aggregate(
        &self,
        _shape: &crate::types::DeclaredShape,
        covered: &[crate::types::CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        if proof == b"reject" {
            return Err(ConfidentialError::InvalidAggregateProof("stub rejection".into()));
        }
        // A bound stub proof (AGG-2) verifies under its own binding only, as the rVM's does.
        if let Some(carried) = proof.strip_prefix(STUB_AGGREGATE_TAG) {
            if carried != word8_to_bytes(binding) {
                return Err(ConfidentialError::InvalidAggregateProof("BindingMismatch".into()));
            }
        }
        // The stub answers what the real one would for an honest aggregate: each covered
        // bundle's `OUT0..7` — pv words `pv::OUT0..OUT0+8` in cover order — so ledger tests
        // exercise the real control flow without any proving.
        Ok(covered
            .iter()
            .map(|c| {
                std::array::from_fn(|k| {
                    u32::try_from(c.public_values[crate::types::pv::OUT0 + k]).expect("stub OUT words are u32-range")
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: Hash) -> ProgramRecord {
        ProgramRecord { id, base_pc: 0, words: vec![0x13], code_hash: vec![], deployed_at: 0, public_digest: None, public_len: 0 }
    }

    /// The stub checks the proof's public-input digest against the record's exactly as the zkVM
    /// executor does: the deploy-time digest when there is one, the empty input's otherwise.
    #[test]
    fn stub_checks_the_public_digest_against_the_record() {
        let id = Hash::digest(b"p");
        let public = [7u32, 8, 9];
        let digest = StubExecutor.public_digest(&public);
        assert_ne!(digest, StubExecutor.public_digest(&[]));
        assert_ne!(StubExecutor.public_digest(&[]), [0; 8]);
        let with = ProgramRecord { public_digest: Some(digest), public_len: 3, ..record(id) };
        let proof = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &public);
        assert_eq!(StubExecutor.verify_call(&with, &proof).unwrap().outputs, [1; 8]);
        let bad = ConfidentialError::InvalidProof("PublicValues".into());
        let other = StubExecutor::make_proof_with_public(&id, 12, [1; 8], &[7, 8, 10]);
        assert_eq!(StubExecutor.verify_call(&with, &other), Err(bad.clone()));
        let empty = StubExecutor::make_proof(&id, 12, [1; 8]);
        assert_eq!(StubExecutor.verify_call(&with, &empty), Err(bad.clone()));
        // A program without a public input takes only the empty input's proofs.
        assert!(StubExecutor.verify_call(&record(id), &empty).is_ok());
        assert_eq!(StubExecutor.verify_call(&record(id), &proof), Err(bad));
    }

    #[test]
    fn stub_roundtrips_outputs_and_binds_program() {
        let id = Hash::digest(b"p");
        let proof = StubExecutor::make_proof(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9]);
        let out = StubExecutor.verify_call(&record(id), &proof).unwrap();
        assert_eq!(
            out,
            CallOutcome {
                tier: 12,
                outputs: [1, 0, 5, 0, 0, 0, 0, 9],
                h_in: [0; 8],
                keccak_log_height: 0,
                sha256_log_height: 0,
                gas_limit: crate::gas::gas_max(12, 0, 0),
            }
        );
        assert_eq!(out.gas_max(), crate::gas::gas_max(12, 0, 0), "a stub proof declares no hash table");
        // …and the H_IN a call-input envelope is sealed against travels in the proof, not beside it.
        let sealed = StubExecutor::make_proof_with_h_in(&id, 12, [1, 0, 5, 0, 0, 0, 0, 9], [7; 8]);
        assert_eq!(StubExecutor.verify_call(&record(id), &sealed).unwrap().h_in, [7; 8]);
        assert_eq!(StubExecutor.verify_call(&record(Hash::digest(b"q")), &proof), Err(ConfidentialError::WrongProgram));
        assert_eq!(StubExecutor.verify_call(&record(id), b"junk"), Err(ConfidentialError::MalformedProof));
    }

    /// Constraint set 8 (spec 2026-09-28 §4.2–4.3): a stub call proof carries its declared gas
    /// limit, `gas_max(tier, 0, 0)` unless chosen, and the outcome reports it.
    #[test]
    fn the_stub_call_proof_carries_its_gas_limit() {
        let id = Hash::digest(b"p");
        let p = StubExecutor::make_proof_with_gas(&id, 12, [1; 8], 777);
        assert_eq!(StubExecutor.verify_call(&record(id), &p).unwrap().gas_limit, 777);
        assert_eq!(StubExecutor.decode_call(&record(id), &p).unwrap().gas_limit, 777);
        let d = StubExecutor::make_proof(&id, 12, [1; 8]);
        assert_eq!(StubExecutor.verify_call(&record(id), &d).unwrap().gas_limit, crate::gas::gas_max(12, 0, 0));
        // The program binding still refuses another program's proof with the limit appended.
        assert_eq!(StubExecutor.verify_call(&record(Hash::digest(b"q")), &p), Err(ConfidentialError::WrongProgram));
    }

    /// A stub bundle proof declares `gas_max(14, 0, 0)` = 20 479 (what a real hidden-asset bundle
    /// proof declares); `with_bundle_gas` rewrites it, and binding the transaction keeps it.
    #[test]
    fn the_stub_bundle_proof_carries_its_gas_limit() {
        let hc = [3u32; 8];
        let digest = [5u32; 8];
        let binding = [6u32; 8];
        let mut b = StubExecutor::make_bundle_proof(&hc, &digest, &binding);
        assert_eq!(StubExecutor.bundle_gas_limit(&b).unwrap(), Some(crate::gas::gas_max(14, 0, 0)));
        assert_eq!(crate::gas::gas_max(14, 0, 0), 20_479, "(2^14 − 1) + 2^12, the absorb term included");
        StubExecutor::with_bundle_gas(&mut b, 20_480);
        assert_eq!(StubExecutor.bundle_gas_limit(&b).unwrap(), Some(20_480));
        assert_eq!(StubExecutor.bundle_proof_digest(&hc, &b).unwrap(), digest);
        assert_eq!(StubExecutor.verify_bundle(&hc, &b, &binding), Ok(()));
        assert_eq!(StubExecutor.bundle_gas_limit(b"junk"), Err(ConfidentialError::MalformedProof));
    }

    /// Binding a transaction rewrites the stub bundle proof's binding words only: the gas tail
    /// `with_bundle_gas` set survives `bound`, and binding a bound transaction again moves nothing.
    #[test]
    fn binding_keeps_the_bundle_proofs_gas_limit() {
        use crate::notes::Bundle;
        use crate::types::Action;
        let hc = [3u32; 8];
        let mut proof = StubExecutor::make_bundle_proof(&hc, &[5u32; 8], &[0; 8]);
        StubExecutor::with_bundle_gas(&mut proof, 777);
        let bundle = Bundle {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
            commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
            fee: 1,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: std::array::from_fn(|_| crate::notes::Envelope { kem_ct: vec![1], to_receiver: vec![2], to_sender: vec![3], body: vec![4] }),
            proof,
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let tx = StubExecutor::bound(Transaction::shielded(7, bundle, Action::None));
        let p = &tx.bundle.as_ref().unwrap().proof;
        assert_eq!(StubExecutor.bundle_gas_limit(p).unwrap(), Some(777), "bound keeps the gas tail");
        let binding = word8_to_bytes(&tx.binding(&crate::types::BindingDomain::ChainId));
        assert_eq!(&p[STUB_BUNDLE_BINDING..STUB_BUNDLE_GAS], &binding[..], "and the binding is this transaction's");
        assert_eq!(StubExecutor.verify_bundle(&hc, p, &tx.binding(&crate::types::BindingDomain::ChainId)), Ok(()));
        let again = StubExecutor::bound(tx.clone());
        assert_eq!(again, tx, "binding is idempotent");
    }

    #[test]
    fn stub_bundle_proof_carries_its_digest_and_binds_hc() {
        let hc = [3u32; 8];
        let d = [5u32; 8];
        let binding = [6u32; 8];
        let p = StubExecutor::make_bundle_proof(&hc, &d, &binding);
        assert_eq!(StubExecutor.bundle_proof_digest(&hc, &p).unwrap(), d);
        assert_eq!(StubExecutor.verify_bundle(&hc, &p, &binding), Ok(()));
        assert_eq!(StubExecutor.verify_bundle(&[4u32; 8], &p, &binding), Err(ConfidentialError::WrongProgram));
        // Task 5b: the stub enforces the binding as the zkVM does — another transaction's words
        // are refused, and so is a proof made against no transaction at all.
        let public_values = Err(ConfidentialError::InvalidBundleProof("PublicValues".into()));
        assert_eq!(StubExecutor.verify_bundle(&hc, &p, &[7u32; 8]), public_values);
        let unbound = StubExecutor::make_bundle_proof(&hc, &d, &[0; 8]);
        assert_eq!(StubExecutor.verify_bundle(&hc, &unbound, &binding), public_values);
        assert_eq!(StubExecutor.bundle_proof_digest(&hc, b"junk"), Err(ConfidentialError::MalformedProof));
        assert_ne!(StubExecutor.node_hash(&[1; 8], &[2; 8]), StubExecutor.node_hash(&[2; 8], &[1; 8]));
    }

    /// The stub bundle digest binds every public field of the hidden-asset bundle — each of the
    /// four nullifiers and commitments and all three burn fields — so a ledger test that changes
    /// one and keeps the proof sees `BadDigest`, as the real chain would.
    #[test]
    fn the_stub_bundle_digest_binds_every_hidden_field() {
        let base = BundleDigestInput {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
            commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
            fee: 10,
            burn_a: 11,
            burn_r: 12,
            burn_asset: 13,
            time: 14,
            auth_commit: [15; 8],
        };
        let d = StubExecutor.bundle_digest(&base);
        let mut changes: Vec<BundleDigestInput> = Vec::new();
        for k in 0..4 {
            let mut c = base;
            c.nullifiers[k][0] ^= 1;
            changes.push(c);
            let mut c = base;
            c.commitments[k][0] ^= 1;
            changes.push(c);
        }
        for f in [
            |c: &mut BundleDigestInput| c.anchor[0] ^= 1,
            |c: &mut BundleDigestInput| c.fee += 1,
            |c: &mut BundleDigestInput| c.burn_a += 1,
            |c: &mut BundleDigestInput| c.burn_r += 1,
            |c: &mut BundleDigestInput| c.burn_asset += 1,
            |c: &mut BundleDigestInput| c.time += 1,
        ] {
            let mut c = base;
            f(&mut c);
            changes.push(c);
        }
        for c in changes {
            assert_ne!(StubExecutor.bundle_digest(&c), d, "{c:?}");
        }
    }

    /// The v3 stand-in binds `auth_commit` and every v1 field, under a domain of its own; the v1
    /// one ignores `auth_commit` (a chain without `hc_auth` hashes as before).
    #[test]
    fn the_stub_v3_digest_binds_the_auth_commit_and_v1_ignores_it() {
        let base = BundleDigestInput {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
            commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
            fee: 10,
            burn_a: 11,
            burn_r: 12,
            burn_asset: 13,
            time: 14,
            auth_commit: [15; 8],
        };
        let mut other = base;
        other.auth_commit[3] ^= 1;
        assert_eq!(StubExecutor.bundle_digest(&other), StubExecutor.bundle_digest(&base));
        assert_ne!(StubExecutor.bundle_digest_v3(&other), StubExecutor.bundle_digest_v3(&base));
        assert_ne!(StubExecutor.bundle_digest_v3(&base), StubExecutor.bundle_digest(&base));
        let mut fee = base;
        fee.fee += 1;
        assert_ne!(StubExecutor.bundle_digest_v3(&fee), StubExecutor.bundle_digest_v3(&base));
    }

    #[test]
    fn stub_auth_proof_publishes_c_and_binds_hc_and_the_binding() {
        let (hca, c, binding) = ([21u32; 8], [0xc0u32; 8], [6u32; 8]);
        let p = StubExecutor::make_auth_proof(&hca, &c, &binding);
        assert_eq!(StubExecutor.auth_proof_digest(&p), Ok(c));
        assert_eq!(StubExecutor.verify_auth(&hca, &p, &binding), Ok(c));
        assert_eq!(StubExecutor.verify_auth(&[22; 8], &p, &binding), Err(ConfidentialError::WrongProgram));
        assert_eq!(
            StubExecutor.verify_auth(&hca, &p, &[7; 8]),
            Err(ConfidentialError::InvalidProof("PublicValues".into()))
        );
        assert_eq!(StubExecutor.auth_proof_digest(b"junk"), Err(ConfidentialError::MalformedProof));
        // A bundle proof is not an auth proof, nor the other way round.
        let bundle = StubExecutor::make_bundle_proof(&hca, &c, &binding);
        assert_eq!(StubExecutor.auth_proof_digest(&bundle), Err(ConfidentialError::MalformedProof));
        assert_eq!(StubExecutor.bundle_proof_digest(&hca, &p), Err(ConfidentialError::MalformedProof));
    }

    /// Every field the real commitment binds, the stand-in binds too — otherwise a ledger test
    /// could pass on a note the real chain would compute differently.
    #[test]
    fn the_stub_note_commitment_binds_every_field() {
        let base = StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[3; 8]);
        assert_eq!(base, StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[3; 8]), "deterministic");
        for other in [
            StubExecutor.note_commitment(&[9; 8], &[2; 8], 5, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[9; 8], 5, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 6, 0, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 1, 9, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 10, &[3; 8]),
            StubExecutor.note_commitment(&[1; 8], &[2; 8], 5, 0, 9, &[4; 8]),
        ] {
            assert_ne!(other, base);
        }
        // A different domain from the tree node hash, over the same-shaped input.
        assert_ne!(base, StubExecutor.node_hash(&[1; 8], &[2; 8]));
    }
}
