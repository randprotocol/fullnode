//! A node-local cache of proof-verification verdicts (compute-optimization §3.3,
//! `docs/superpowers/specs/2026-10-11-verify-cache-design.md`).
//!
//! [`CachingExecutor`] wraps the node's [`ConfidentialExecutor`] and remembers the `Ok` verdict
//! of each of the eight expensive STARK verifiers, keyed by a digest of every input the verifier
//! receives. A proof the node has already verified, through any path (admission, propose,
//! follower apply, sync, an aggregate's validation), is then answered without verifying it again.
//! Everything else a verdict depends on (the FRI profile, the compiled constraints, the pinned
//! heights) is fixed for the life of the process, so a hit returns exactly what the inner
//! executor would: two validators with different cache contents reach the same verdict.
//!
//! `Err` is never stored. Every other trait method, defaulted or not, forwards to the inner
//! executor unchanged: a default left in place here would silently replace `AggExecutor`'s
//! implementation (see the note on `AggExecutor::max_callable_program_words`).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use randprotocol_core::confidential::{AuthShape, ConfidentialError, ConfidentialExecutor};
use randprotocol_core::crypto::Hash;
use randprotocol_core::ledger::aggregation::{TreeConfig, TreeDigests};
use randprotocol_core::notes::{BundleDigestInput, Word8};
use randprotocol_core::program::{CallOutcome, ProgramRecord};
use randprotocol_core::types::{CoveredBundle, DeclaredShape, TX_BINDING_WORDS};

/// Three entries per transaction (bundle, auth, one call / invoke / perp) for the 8192
/// transactions the retired verified set held, rounded up to a power of two (spec
/// `docs/superpowers/specs/2026-10-12-verified-fold-design.md` §1). A verdict is a few hundred
/// bytes at most.
pub const VERIFY_CACHE_ENTRIES: usize = 32_768;

/// The domain every cache key is hashed under. A change to the key layout changes it.
const KEY_DOMAIN: &[u8] = b"rand-verify-cache-1";

/// Log the counters every this many lookups.
const LOG_EVERY: u64 = 1024;

/// A cached `Ok` value: what each of the eight verifiers returns.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Unit,
    Word(Word8),
    Outcome(CallOutcome),
    Outs(Vec<[u32; 8]>),
}

#[derive(Default)]
struct Entries {
    map: HashMap<Hash, Verdict>,
    /// Insertion order, for FIFO eviction; a hit does not reorder.
    order: VecDeque<Hash>,
}

/// A bounded, FIFO-evicting map from a verification key to its `Ok` verdict.
pub struct VerifyCache {
    entries: Mutex<Entries>,
    cap: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl VerifyCache {
    pub fn new(cap: usize) -> Self {
        Self { entries: Mutex::new(Entries::default()), cap, hits: AtomicU64::new(0), misses: AtomicU64::new(0) }
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// The entries held now (0 if the lock is poisoned).
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The verdict stored under `key`, projected by `from`, counting a hit or a miss. An entry of
    /// another variant (which cannot occur, since the tag differs) and a poisoned lock are misses.
    fn get<T>(&self, key: &Hash, from: fn(Verdict) -> Option<T>) -> Option<T> {
        let found = match self.entries.lock() {
            Ok(e) => e.map.get(key).cloned().and_then(from),
            Err(_) => None,
        };
        let (hits, misses) = if found.is_some() {
            (self.hits.fetch_add(1, Ordering::Relaxed) + 1, self.misses())
        } else {
            (self.hits(), self.misses.fetch_add(1, Ordering::Relaxed) + 1)
        };
        if (hits + misses).is_multiple_of(LOG_EVERY) {
            tracing::debug!("verify cache: {hits} hits, {misses} misses, {} entries", self.len());
        }
        found
    }

    /// Store `v` under `key`, evicting the oldest entry at the cap. A key already present is
    /// left as it is (two threads that missed the same key both verified; the first insert
    /// stands). A poisoned lock skips the insert.
    fn insert(&self, key: Hash, v: Verdict) {
        if self.cap == 0 {
            return;
        }
        let Ok(mut e) = self.entries.lock() else { return };
        if e.map.contains_key(&key) {
            return;
        }
        while e.map.len() >= self.cap {
            match e.order.pop_front() {
                Some(old) => {
                    e.map.remove(&old);
                }
                None => break,
            }
        }
        e.map.insert(key, v);
        e.order.push_back(key);
    }
}

/// The key hasher: `blake3(KEY_DOMAIN || tag || fields)`, fed field by field so a proof (up to
/// 8 MiB) is never copied. Every input the verifier receives is length-prefixed (`u64`
/// little-endian), words as little-endian bytes. The digest equals
/// `Hash::digest_domain(KEY_DOMAIN, tag || fields)`.
struct KeyBuf(blake3::Hasher);

impl KeyBuf {
    fn new(tag: u8) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(KEY_DOMAIN);
        h.update(&[tag]);
        Self(h)
    }

    /// Append `n` as a length prefix.
    fn prefix(mut self, n: usize) -> Self {
        self.0.update(&(n as u64).to_le_bytes());
        self
    }

    fn bytes(self, b: &[u8]) -> Self {
        let mut s = self.prefix(b.len());
        s.0.update(b);
        s
    }

    fn words(self, w: &[u32]) -> Self {
        let mut s = self.prefix(w.len());
        for x in w {
            s.0.update(&x.to_le_bytes());
        }
        s
    }

    fn u64s(self, w: &[u64]) -> Self {
        let mut s = self.prefix(w.len());
        for x in w {
            s.0.update(&x.to_le_bytes());
        }
        s
    }

    fn ser<T: serde::Serialize>(self, v: &T) -> Self {
        self.bytes(&bincode::serialize(v).expect("serializing a plain struct cannot fail"))
    }

    /// The count, then each cover's public values and its bincode-encoded shape.
    fn covered(self, covered: &[CoveredBundle]) -> Self {
        let mut s = self.prefix(covered.len());
        for c in covered {
            s = s.u64s(&c.public_values).ser(&c.shape);
        }
        s
    }

    fn finish(self) -> Hash {
        Hash(*self.0.finalize().as_bytes())
    }
}

/// Kind tags (spec §3.3). Distinct per method, so two methods never share an entry.
const TAG_BUNDLE: u8 = 1;
const TAG_AUTH: u8 = 2;
const TAG_CALL: u8 = 3;
const TAG_CALL_HARDENED: u8 = 4;
const TAG_INVOKE: u8 = 5;
const TAG_PERP: u8 = 6;
const TAG_AGGREGATE: u8 = 7;
const TAG_TREE: u8 = 8;

/// The verdict-caching decorator over the node's executor.
pub struct CachingExecutor {
    inner: Arc<dyn ConfidentialExecutor>,
    cache: VerifyCache,
}

impl CachingExecutor {
    pub fn new(inner: Arc<dyn ConfidentialExecutor>) -> Self {
        Self::with_capacity(inner, VERIFY_CACHE_ENTRIES)
    }

    pub fn with_capacity(inner: Arc<dyn ConfidentialExecutor>, cap: usize) -> Self {
        Self { inner, cache: VerifyCache::new(cap) }
    }

    pub fn cache(&self) -> &VerifyCache {
        &self.cache
    }

    /// The stored verdict for `key` if there is one of the right variant (another variant cannot
    /// occur, since the tag differs, and is counted and treated as a miss); otherwise `verify`
    /// (the inner call, made with no lock held), storing an `Ok` answer and never an `Err`.
    fn cached<T: Clone>(
        &self,
        key: Hash,
        from: fn(Verdict) -> Option<T>,
        into: fn(T) -> Verdict,
        verify: impl FnOnce() -> Result<T, ConfidentialError>,
    ) -> Result<T, ConfidentialError> {
        if let Some(v) = self.cache.get(&key, from) {
            return Ok(v);
        }
        let v = verify()?;
        self.cache.insert(key, into(v.clone()));
        Ok(v)
    }
}

fn as_unit(v: Verdict) -> Option<()> {
    matches!(v, Verdict::Unit).then_some(())
}

fn as_word(v: Verdict) -> Option<Word8> {
    match v {
        Verdict::Word(w) => Some(w),
        _ => None,
    }
}

fn as_outcome(v: Verdict) -> Option<CallOutcome> {
    match v {
        Verdict::Outcome(o) => Some(o),
        _ => None,
    }
}

fn as_outs(v: Verdict) -> Option<Vec<[u32; 8]>> {
    match v {
        Verdict::Outs(o) => Some(o),
        _ => None,
    }
}

// Every method of the trait is written out, defaulted ones included: see the module note. A
// method added to the trait must be added here too.
impl ConfidentialExecutor for CachingExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        self.inner.check_program(base_pc, words)
    }

    fn max_callable_program_words(&self, public_segment_words: usize) -> Option<usize> {
        self.inner.max_callable_program_words(public_segment_words)
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        let key = KeyBuf::new(TAG_CALL).ser(program).bytes(proof).finish();
        self.cached(key, as_outcome, Verdict::Outcome, || self.inner.verify_call(program, proof))
    }

    fn decode_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_call(program, proof)
    }

    fn verify_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        let key = KeyBuf::new(TAG_CALL_HARDENED).ser(program).bytes(proof).words(segment).finish();
        self.cached(key, as_outcome, Verdict::Outcome, || self.inner.verify_call_hardened(program, proof, segment))
    }

    fn decode_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_call_hardened(program, proof, segment)
    }

    fn verify_invoke(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        let key = KeyBuf::new(TAG_INVOKE).ser(program).bytes(proof).words(segment).finish();
        self.cached(key, as_outcome, Verdict::Outcome, || self.inner.verify_invoke(program, proof, segment))
    }

    fn decode_invoke(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_invoke(program, proof, segment)
    }

    fn verify_perp(
        &self,
        engine_hc: &Word8,
        max_tier: u8,
        segment: &[u32],
        proof: &[u8],
    ) -> Result<CallOutcome, ConfidentialError> {
        let key = KeyBuf::new(TAG_PERP).words(engine_hc).bytes(&[max_tier]).words(segment).bytes(proof).finish();
        self.cached(key, as_outcome, Verdict::Outcome, || self.inner.verify_perp(engine_hc, max_tier, segment, proof))
    }

    fn decode_perp(
        &self,
        engine_hc: &Word8,
        max_tier: u8,
        segment: &[u32],
        proof: &[u8],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_perp(engine_hc, max_tier, segment, proof)
    }

    fn warm(&self, program: &ProgramRecord) {
        self.inner.warm(program)
    }

    fn warm_hardened(&self, program: &ProgramRecord) {
        self.inner.warm_hardened(program)
    }

    fn public_digest(&self, words: &[u32]) -> Word8 {
        self.inner.public_digest(words)
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        self.inner.node_hash(left, right)
    }

    fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
        self.inner.hash_domain(domain, msg)
    }

    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        self.inner.note_commitment(pk, from, amount, asset, time, r)
    }

    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8 {
        self.inner.bundle_digest(input)
    }

    fn bundle_digest_v3(&self, input: &BundleDigestInput) -> Word8 {
        self.inner.bundle_digest_v3(input)
    }

    fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.inner.bundle_proof_digest(hc_bundle, proof)
    }

    fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.inner.auth_proof_digest(proof)
    }

    fn verify_auth(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError> {
        let key = KeyBuf::new(TAG_AUTH).words(hc_auth).bytes(proof).words(binding).finish();
        self.cached(key, as_word, Verdict::Word, || self.inner.verify_auth(hc_auth, proof, binding))
    }

    fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.inner.bundle_gas_limit(proof)
    }

    fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.inner.auth_gas_limit(proof)
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        let key = KeyBuf::new(TAG_BUNDLE).words(hc_bundle).bytes(proof).words(binding).finish();
        self.cached(key, as_unit, |()| Verdict::Unit, || self.inner.verify_bundle(hc_bundle, proof, binding))
    }

    fn warm_bundle(&self) {
        self.inner.warm_bundle()
    }

    fn warm_auth(&self) {
        self.inner.warm_auth()
    }

    fn install_msauth_vk(&self, blob: &[u8]) -> Result<(), String> {
        self.inner.install_msauth_vk(blob)
    }

    /// Forwarded: a wrapper that kept this to itself would leave the inner executor's msauth path
    /// shut on a chain naming `hc_auth_multisig`, and every multisig auth proof refused.
    fn enable_auth_multisig(&self) {
        self.inner.enable_auth_multisig()
    }

    fn build_msauth_key(&self) -> Result<(), String> {
        self.inner.build_msauth_key()
    }

    /// A decode, not a verdict: forwarded, never cached. A multisig proof's verify is
    /// `verify_auth` under kind 2, keyed by its `hc`, so nothing new is cached for it.
    fn auth_header(&self, proof: &[u8]) -> Result<(AuthShape, Word8, Option<u64>), ConfidentialError> {
        self.inner.auth_header(proof)
    }

    fn warm_auth_multisig(&self) {
        self.inner.warm_auth_multisig()
    }

    fn auth_multisig_key_ready(&self) -> bool {
        self.inner.auth_multisig_key_ready()
    }

    fn non_canonical_proof(&self, proof: &[u8]) -> Option<String> {
        self.inner.non_canonical_proof(proof)
    }

    fn aggregate_program_digest(&self, shape: &DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
        self.inner.aggregate_program_digest(shape)
    }

    fn check_aggregate_header(&self, proof: &[u8]) -> Result<(), ConfidentialError> {
        self.inner.check_aggregate_header(proof)
    }

    fn verify_aggregate(
        &self,
        shape: &DeclaredShape,
        covered: &[CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        let key = KeyBuf::new(TAG_AGGREGATE).ser(shape).covered(covered).bytes(proof).words(binding).finish();
        self.cached(key, as_outs, Verdict::Outs, || self.inner.verify_aggregate(shape, covered, proof, binding))
    }

    fn warm_aggregation(&self, shape: &DeclaredShape, max_covers: u32) {
        self.inner.warm_aggregation(shape, max_covers)
    }

    fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError> {
        self.inner.aggregate_proof_tier(proof)
    }

    fn tree_digests(&self, tree: &TreeConfig) -> Result<TreeDigests, ConfidentialError> {
        self.inner.tree_digests(tree)
    }

    fn verify_tree(
        &self,
        tree: &TreeConfig,
        covered: &[CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
        depth: u32,
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        let key = KeyBuf::new(TAG_TREE).ser(tree).covered(covered).bytes(proof).words(binding).words(&[depth]).finish();
        self.cached(key, as_outs, Verdict::Outs, || self.inner.verify_tree(tree, covered, proof, binding, depth))
    }

    fn warm_tree(&self, tree: &TreeConfig) {
        self.inner.warm_tree(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::ledger::aggregation::{RvmHeights, TreeStepPin};
    use randprotocol_core::types::{pv, FriProfile};
    use std::sync::atomic::AtomicUsize;

    /// The verifier kinds, one per cached method.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Bundle,
        Auth,
        Call,
        CallHardened,
        Invoke,
        Perp,
        Aggregate,
        Tree,
    }

    const KINDS: [Kind; 8] =
        [Kind::Bundle, Kind::Auth, Kind::Call, Kind::CallHardened, Kind::Invoke, Kind::Perp, Kind::Aggregate, Kind::Tree];

    /// Wraps `StubExecutor`, counts each verifier's calls, and answers every defaulted method
    /// with a value the trait default never gives, so a wrapper that dropped one is caught.
    #[derive(Default)]
    struct Counting {
        stub: StubExecutor,
        verifies: [AtomicUsize; 8],
        decodes: AtomicUsize,
        warms: Mutex<Vec<&'static str>>,
        fail_bundle: bool,
        /// `verify_auth` answers this without asking the stub (a fixed `Ok`).
        auth_ok: Option<Word8>,
        /// Answer the defaulted methods as the stub does, for a test that runs a real ledger
        /// (which would refuse `Counting`'s distinctive values); the verifiers still count.
        plain: bool,
        /// `enable_auth_multisig` calls.
        multisig_enables: AtomicUsize,
        /// `warm_auth_multisig` calls.
        multisig_warms: AtomicUsize,
    }

    /// `Counting`'s answer for every `decode_*`: no stub proof decodes to tier 77.
    const DECODED: CallOutcome =
        CallOutcome { tier: 77, outputs: [77; 8], h_in: [77; 8], keccak_log_height: 0, sha256_log_height: 0, gas_limit: 77 };

    impl Counting {
        fn count(&self, k: Kind) -> usize {
            self.verifies[k as usize].load(Ordering::SeqCst)
        }
        fn bump(&self, k: Kind) {
            self.verifies[k as usize].fetch_add(1, Ordering::SeqCst);
        }
        fn plain() -> Self {
            Self { plain: true, ..Self::default() }
        }
        fn decoded(&self) -> Result<CallOutcome, ConfidentialError> {
            self.decodes.fetch_add(1, Ordering::SeqCst);
            Ok(DECODED)
        }
        fn warmed(&self, what: &'static str) {
            self.warms.lock().unwrap().push(what);
        }
    }

    impl ConfidentialExecutor for Counting {
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
            self.stub.check_program(base_pc, words)
        }
        fn max_callable_program_words(&self, n: usize) -> Option<usize> {
            if self.plain {
                return self.stub.max_callable_program_words(n);
            }
            Some(31_337)
        }
        fn verify_call(&self, p: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            self.bump(Kind::Call);
            self.stub.verify_call(p, proof)
        }
        fn decode_call(&self, p: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            if self.plain {
                return self.stub.decode_call(p, proof);
            }
            self.decoded()
        }
        fn verify_call_hardened(&self, p: &ProgramRecord, proof: &[u8], s: &[u32]) -> Result<CallOutcome, ConfidentialError> {
            self.bump(Kind::CallHardened);
            self.stub.verify_call_hardened(p, proof, s)
        }
        fn decode_call_hardened(&self, p: &ProgramRecord, proof: &[u8], s: &[u32]) -> Result<CallOutcome, ConfidentialError> {
            if self.plain {
                return self.stub.decode_call_hardened(p, proof, s);
            }
            self.decoded()
        }
        fn verify_invoke(&self, p: &ProgramRecord, proof: &[u8], s: &[u32]) -> Result<CallOutcome, ConfidentialError> {
            self.bump(Kind::Invoke);
            self.stub.verify_invoke(p, proof, s)
        }
        fn decode_invoke(&self, p: &ProgramRecord, proof: &[u8], s: &[u32]) -> Result<CallOutcome, ConfidentialError> {
            if self.plain {
                return self.stub.decode_invoke(p, proof, s);
            }
            self.decoded()
        }
        fn verify_perp(&self, hc: &Word8, max_tier: u8, s: &[u32], proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            self.bump(Kind::Perp);
            self.stub.verify_perp(hc, max_tier, s, proof)
        }
        fn decode_perp(&self, hc: &Word8, max_tier: u8, s: &[u32], proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            if self.plain {
                return self.stub.decode_perp(hc, max_tier, s, proof);
            }
            self.decoded()
        }
        fn warm(&self, _: &ProgramRecord) {
            self.warmed("warm")
        }
        fn warm_hardened(&self, _: &ProgramRecord) {
            self.warmed("warm_hardened")
        }
        fn public_digest(&self, words: &[u32]) -> Word8 {
            self.stub.public_digest(words)
        }
        fn node_hash(&self, l: &Word8, r: &Word8) -> Word8 {
            self.stub.node_hash(l, r)
        }
        fn hash_domain(&self, d: u32, m: &[u32]) -> Word8 {
            self.stub.hash_domain(d, m)
        }
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            self.stub.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, i: &BundleDigestInput) -> Word8 {
            self.stub.bundle_digest(i)
        }
        fn bundle_digest_v3(&self, i: &BundleDigestInput) -> Word8 {
            self.stub.bundle_digest_v3(i)
        }
        fn bundle_proof_digest(&self, hc: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            self.stub.bundle_proof_digest(hc, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            self.stub.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc: &Word8, proof: &[u8], b: &[u32; TX_BINDING_WORDS]) -> Result<Word8, ConfidentialError> {
            self.bump(Kind::Auth);
            if let Some(c) = self.auth_ok {
                return Ok(c);
            }
            self.stub.verify_auth(hc, proof, b)
        }
        fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            if self.plain {
                return self.stub.bundle_gas_limit(proof);
            }
            Ok(Some(1_111))
        }
        fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
            if self.plain {
                return self.stub.auth_gas_limit(proof);
            }
            Ok(Some(2_222))
        }
        fn verify_bundle(&self, hc: &Word8, proof: &[u8], b: &[u32; TX_BINDING_WORDS]) -> Result<(), ConfidentialError> {
            self.bump(Kind::Bundle);
            if self.fail_bundle {
                return Err(ConfidentialError::InvalidBundleProof("counting".into()));
            }
            self.stub.verify_bundle(hc, proof, b)
        }
        fn warm_bundle(&self) {
            self.warmed("warm_bundle")
        }
        fn warm_auth(&self) {
            self.warmed("warm_auth")
        }
        fn install_msauth_vk(&self, blob: &[u8]) -> Result<(), String> {
            if self.plain {
                return self.stub.install_msauth_vk(blob);
            }
            Err(format!("counting: {} bytes", blob.len()))
        }
        fn enable_auth_multisig(&self) {
            self.multisig_enables.fetch_add(1, Ordering::SeqCst);
            if self.plain {
                self.stub.enable_auth_multisig()
            }
        }
        fn build_msauth_key(&self) -> Result<(), String> {
            if self.plain {
                return self.stub.build_msauth_key();
            }
            Err("counting: built".into())
        }
        fn auth_header(&self, proof: &[u8]) -> Result<(AuthShape, Word8, Option<u64>), ConfidentialError> {
            if self.plain {
                return self.stub.auth_header(proof);
            }
            Ok((AuthShape::Multisig, [0x5a; 8], Some(4242)))
        }
        fn warm_auth_multisig(&self) {
            self.multisig_warms.fetch_add(1, Ordering::SeqCst);
            if self.plain {
                self.stub.warm_auth_multisig()
            }
        }
        fn auth_multisig_key_ready(&self) -> bool {
            if self.plain {
                return self.stub.auth_multisig_key_ready();
            }
            false
        }
        fn non_canonical_proof(&self, proof: &[u8]) -> Option<String> {
            if self.plain {
                return self.stub.non_canonical_proof(proof);
            }
            Some("counting".into())
        }
        fn aggregate_program_digest(&self, s: &DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            self.stub.aggregate_program_digest(s)
        }
        fn check_aggregate_header(&self, proof: &[u8]) -> Result<(), ConfidentialError> {
            if self.plain {
                return self.stub.check_aggregate_header(proof);
            }
            Err(ConfidentialError::Disabled)
        }
        fn verify_aggregate(
            &self,
            s: &DeclaredShape,
            c: &[CoveredBundle],
            proof: &[u8],
            b: &[u32; 8],
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            self.bump(Kind::Aggregate);
            self.stub.verify_aggregate(s, c, proof, b)
        }
        fn warm_aggregation(&self, _: &DeclaredShape, _: u32) {
            self.warmed("warm_aggregation")
        }
        fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError> {
            if self.plain {
                return self.stub.aggregate_proof_tier(proof);
            }
            Ok(99)
        }
        fn tree_digests(&self, t: &TreeConfig) -> Result<TreeDigests, ConfidentialError> {
            if self.plain {
                return self.stub.tree_digests(t);
            }
            Ok(TreeDigests { vk_leaf: [9; 4], steps: vec![] })
        }
        fn verify_tree(
            &self,
            t: &TreeConfig,
            c: &[CoveredBundle],
            proof: &[u8],
            b: &[u32; 8],
            depth: u32,
        ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            self.bump(Kind::Tree);
            self.stub.verify_tree(t, c, proof, b, depth)
        }
        fn warm_tree(&self, _: &TreeConfig) {
            self.warmed("warm_tree")
        }
    }

    fn shape() -> DeclaredShape {
        DeclaredShape {
            profile: FriProfile::Test,
            tier: 14,
            program_log_height: 10,
            input_log_height: 7,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 7,
            mem_log_height: 12,
        }
    }

    fn heights(tier: u8) -> RvmHeights {
        RvmHeights { tier, reg_log_height: 10, ram_log_height: 10, poseidon2_log_height: 10, reduce_log_height: 10 }
    }

    fn cover(seed: u64) -> CoveredBundle {
        let mut public_values = [0u64; pv::NUM];
        for (i, v) in public_values.iter_mut().enumerate() {
            *v = seed * 100 + i as u64;
        }
        CoveredBundle { public_values, shape: shape() }
    }

    /// One passing input set for every kind. Each kind reads its own fields; `binding` is shared
    /// by bundle, auth, aggregate and tree.
    #[derive(Clone)]
    struct Inputs {
        hc_bundle: Word8,
        hc_auth: Word8,
        binding: [u32; 8],
        bundle_proof: Vec<u8>,
        auth_proof: Vec<u8>,
        record: ProgramRecord,
        call_proof: Vec<u8>,
        hardened_segment: Vec<u32>,
        hardened_proof: Vec<u8>,
        invoke_segment: Vec<u32>,
        invoke_proof: Vec<u8>,
        engine_hc: Word8,
        max_tier: u8,
        perp_segment: Vec<u32>,
        perp_proof: Vec<u8>,
        shape: DeclaredShape,
        covered: Vec<CoveredBundle>,
        aggregate_proof: Vec<u8>,
        tree: TreeConfig,
        tree_proof: Vec<u8>,
        depth: u32,
    }

    impl Inputs {
        fn new() -> Self {
            let hc_bundle = [1; 8];
            let hc_auth = [4; 8];
            let binding = [2; 8];
            let record = ProgramRecord {
                id: Hash([5; 32]),
                base_pc: 0,
                words: vec![0x13],
                code_hash: vec![],
                deployed_at: 0,
                public_digest: None,
                public_len: 0,
            };
            let hardened_segment = vec![6; TX_BINDING_WORDS];
            let invoke_segment = vec![7; TX_BINDING_WORDS + 2];
            let engine_hc = [8; 8];
            let perp_segment = vec![9; 4];
            let depth = 2;
            Self {
                bundle_proof: StubExecutor::make_bundle_proof(&hc_bundle, &[3; 8], &binding),
                auth_proof: StubExecutor::make_auth_proof(&hc_auth, &[3; 8], &binding),
                call_proof: StubExecutor::make_proof(&record.id, 10, [11; 8]),
                hardened_proof: StubExecutor::make_proof_with_public(&record.id, 10, [12; 8], &hardened_segment),
                invoke_proof: StubExecutor::make_proof_with_public(&record.id, 10, [13; 8], &invoke_segment),
                perp_proof: StubExecutor::make_perp_proof(&engine_hc, 12, [14; 8], &perp_segment),
                aggregate_proof: StubExecutor::make_aggregate_proof(&binding),
                tree_proof: StubExecutor::make_tree_proof(20, depth as u8, &binding),
                tree: TreeConfig {
                    shape: shape(),
                    leaf_size: 2,
                    max_depth: 4,
                    leaf: heights(18),
                    vk_leaf: [1; 4],
                    steps: vec![TreeStepPin { heights: heights(20), program_digest: [2; 4], key: [3; 4] }],
                },
                covered: vec![cover(1), cover(2)],
                shape: shape(),
                max_tier: 14,
                hc_bundle,
                hc_auth,
                binding,
                record,
                hardened_segment,
                invoke_segment,
                engine_hc,
                perp_segment,
                depth,
            }
        }
    }

    /// Call `kind`'s method on `ex` with `i`'s inputs, the answer as a `Verdict`.
    fn run(ex: &dyn ConfidentialExecutor, kind: Kind, i: &Inputs) -> Result<Verdict, ConfidentialError> {
        match kind {
            Kind::Bundle => ex.verify_bundle(&i.hc_bundle, &i.bundle_proof, &i.binding).map(|()| Verdict::Unit),
            Kind::Auth => ex.verify_auth(&i.hc_auth, &i.auth_proof, &i.binding).map(Verdict::Word),
            Kind::Call => ex.verify_call(&i.record, &i.call_proof).map(Verdict::Outcome),
            Kind::CallHardened => {
                ex.verify_call_hardened(&i.record, &i.hardened_proof, &i.hardened_segment).map(Verdict::Outcome)
            }
            Kind::Invoke => ex.verify_invoke(&i.record, &i.invoke_proof, &i.invoke_segment).map(Verdict::Outcome),
            Kind::Perp => ex.verify_perp(&i.engine_hc, i.max_tier, &i.perp_segment, &i.perp_proof).map(Verdict::Outcome),
            Kind::Aggregate => ex.verify_aggregate(&i.shape, &i.covered, &i.aggregate_proof, &i.binding).map(Verdict::Outs),
            Kind::Tree => ex.verify_tree(&i.tree, &i.covered, &i.tree_proof, &i.binding, i.depth).map(Verdict::Outs),
        }
    }

    fn setup() -> (Arc<Counting>, CachingExecutor) {
        let inner = Arc::new(Counting::default());
        let ex = CachingExecutor::new(inner.clone());
        (inner, ex)
    }

    #[test]
    fn each_kind_verifies_once() {
        let (inner, ex) = setup();
        let i = Inputs::new();
        for kind in KINDS {
            let first = run(&ex, kind, &i);
            assert!(first.is_ok(), "{kind:?}: the base inputs must verify: {first:?}");
            let second = run(&ex, kind, &i);
            assert_eq!(first, second, "{kind:?}");
            assert_eq!(inner.count(kind), 1, "{kind:?} reached inner twice");
        }
        assert_eq!(ex.cache().len(), 8);
    }

    /// A found entry of the wrong variant is a miss, not a hit (the projection decides).
    #[test]
    fn a_wrong_variant_entry_counts_as_a_miss() {
        let cache = VerifyCache::new(4);
        let key = Hash([1; 32]);
        cache.insert(key, Verdict::Unit);
        assert_eq!(cache.get(&key, as_word), None);
        assert_eq!((cache.hits(), cache.misses()), (0, 1));
        assert_eq!(cache.get(&key, as_unit), Some(()));
        assert_eq!((cache.hits(), cache.misses()), (1, 1));
    }

    #[test]
    fn hits_and_misses_count() {
        let (_inner, ex) = setup();
        let i = Inputs::new();
        for kind in KINDS {
            run(&ex, kind, &i).unwrap();
            run(&ex, kind, &i).unwrap();
        }
        assert_eq!(ex.cache().hits(), 8);
        assert_eq!(ex.cache().misses(), 8);
    }

    fn flip_byte(v: &mut [u8]) {
        let last = v.len() - 1;
        v[last] ^= 1;
    }

    #[test]
    fn every_input_is_in_the_key() {
        type Mutate = fn(&mut Inputs);
        let table: Vec<(Kind, &str, Mutate)> = vec![
            (Kind::Bundle, "hc_bundle", |i| i.hc_bundle[0] ^= 1),
            (Kind::Bundle, "proof", |i| flip_byte(&mut i.bundle_proof)),
            (Kind::Bundle, "binding", |i| i.binding[7] ^= 1),
            (Kind::Auth, "hc_auth", |i| i.hc_auth[0] ^= 1),
            (Kind::Auth, "proof", |i| flip_byte(&mut i.auth_proof)),
            (Kind::Auth, "binding", |i| i.binding[7] ^= 1),
            (Kind::Call, "record", |i| i.record.base_pc += 4),
            (Kind::Call, "record public_len", |i| i.record.public_len += 1),
            (Kind::Call, "record code_hash", |i| i.record.code_hash.push(1)),
            (Kind::Call, "record id", |i| i.record.id = Hash([6; 32])),
            (Kind::Call, "record public_digest", |i| i.record.public_digest = Some([7; 8])),
            (Kind::CallHardened, "record id", |i| i.record.id = Hash([6; 32])),
            (Kind::CallHardened, "record public_digest", |i| i.record.public_digest = Some([7; 8])),
            (Kind::Invoke, "record id", |i| i.record.id = Hash([6; 32])),
            (Kind::Invoke, "record public_digest", |i| i.record.public_digest = Some([7; 8])),
            (Kind::Call, "proof", |i| flip_byte(&mut i.call_proof)),
            (Kind::CallHardened, "record", |i| i.record.deployed_at += 1),
            (Kind::CallHardened, "proof", |i| flip_byte(&mut i.hardened_proof)),
            (Kind::CallHardened, "segment", |i| i.hardened_segment[0] ^= 1),
            (Kind::Invoke, "record", |i| i.record.words.push(0x13)),
            (Kind::Invoke, "proof", |i| flip_byte(&mut i.invoke_proof)),
            (Kind::Invoke, "segment", |i| i.invoke_segment[9] ^= 1),
            (Kind::Perp, "engine_hc", |i| i.engine_hc[0] ^= 1),
            (Kind::Perp, "max_tier", |i| i.max_tier += 2),
            (Kind::Perp, "segment", |i| i.perp_segment[3] ^= 1),
            (Kind::Perp, "proof", |i| flip_byte(&mut i.perp_proof)),
            (Kind::Aggregate, "shape", |i| i.shape.mem_log_height += 1),
            (Kind::Aggregate, "covered count", |i| {
                i.covered.pop();
            }),
            (Kind::Aggregate, "covered public value", |i| i.covered[1].public_values[pv::NUM - 1] ^= 1),
            (Kind::Aggregate, "covered shape", |i| i.covered[0].shape.tier += 1),
            (Kind::Aggregate, "proof", |i| flip_byte(&mut i.aggregate_proof)),
            (Kind::Aggregate, "binding", |i| i.binding[7] ^= 1),
            (Kind::Tree, "tree", |i| i.tree.leaf_size += 1),
            (Kind::Tree, "tree step", |i| i.tree.steps[0].key[3] ^= 1),
            (Kind::Tree, "covered count", |i| {
                i.covered.pop();
            }),
            (Kind::Tree, "covered public value", |i| i.covered[1].public_values[pv::NUM - 1] ^= 1),
            (Kind::Tree, "covered shape", |i| i.covered[0].shape.tier += 1),
            (Kind::Tree, "proof", |i| flip_byte(&mut i.tree_proof)),
            (Kind::Tree, "binding", |i| i.binding[7] ^= 1),
            (Kind::Tree, "depth", |i| i.depth += 1),
        ];
        // Every kind has a row for each of its §3.3 inputs.
        for kind in KINDS {
            assert!(table.iter().any(|(k, _, _)| *k == kind), "{kind:?} has no row");
        }
        for (kind, what, mutate) in table {
            let (inner, ex) = setup();
            let base = Inputs::new();
            run(&ex, kind, &base).unwrap_or_else(|e| panic!("{kind:?}: base must verify: {e:?}"));
            run(&ex, kind, &base).unwrap();
            assert_eq!(inner.count(kind), 1, "{kind:?}: the repeat must hit");
            let mut changed = base.clone();
            mutate(&mut changed);
            let _ = run(&ex, kind, &changed);
            assert_eq!(inner.count(kind), 2, "{kind:?}: a changed {what} must reach inner");
        }
    }

    #[test]
    fn streamed_key_equals_the_buffered_digest() {
        let i = Inputs::new();
        let le = |n: usize| (n as u64).to_le_bytes().to_vec();
        let words = |w: &[u32]| {
            let mut v = le(w.len());
            for x in w {
                v.extend_from_slice(&x.to_le_bytes());
            }
            v
        };
        let bytes = |b: &[u8]| {
            let mut v = le(b.len());
            v.extend_from_slice(b);
            v
        };
        // The old encoding: one Vec, then Hash::digest_domain.
        let mut old = vec![TAG_BUNDLE];
        old.extend(words(&i.hc_bundle));
        old.extend(bytes(&i.bundle_proof));
        old.extend(words(&i.binding));
        let new = KeyBuf::new(TAG_BUNDLE).words(&i.hc_bundle).bytes(&i.bundle_proof).words(&i.binding).finish();
        assert_eq!(new, Hash::digest_domain(b"rand-verify-cache-1", &old));

        let mut old = vec![TAG_CALL];
        old.extend(bytes(&bincode::serialize(&i.record).unwrap()));
        old.extend(bytes(&i.call_proof));
        let new = KeyBuf::new(TAG_CALL).ser(&i.record).bytes(&i.call_proof).finish();
        assert_eq!(new, Hash::digest_domain(b"rand-verify-cache-1", &old));
    }

    #[test]
    fn errors_are_not_cached() {
        let inner = Arc::new(Counting { fail_bundle: true, ..Counting::default() });
        let ex = CachingExecutor::new(inner.clone());
        let i = Inputs::new();
        let a = run(&ex, Kind::Bundle, &i);
        let b = run(&ex, Kind::Bundle, &i);
        assert_eq!(a, Err(ConfidentialError::InvalidBundleProof("counting".into())));
        assert_eq!(a, b);
        assert_eq!(inner.count(Kind::Bundle), 2);
        assert!(ex.cache().is_empty());
    }

    #[test]
    fn hc_separates_auth_entries() {
        let (inner, ex) = setup();
        let i = Inputs::new();
        run(&ex, Kind::Auth, &i).unwrap();
        let mut other = i.clone();
        other.hc_auth = [0xa0; 8];
        // The stub refuses the proof under another guest; either way it must reach inner.
        let _ = run(&ex, Kind::Auth, &other);
        assert_eq!(inner.count(Kind::Auth), 2);
    }

    #[test]
    fn bundle_and_auth_do_not_share() {
        // Auth accepts these bytes, so both kinds store an entry: were the tags shared, auth's
        // insert would find bundle's `Unit` under its key and the repeat would miss.
        let inner = Arc::new(Counting { auth_ok: Some([3; 8]), ..Counting::default() });
        let ex = CachingExecutor::new(inner.clone());
        let mut i = Inputs::new();
        i.hc_auth = i.hc_bundle;
        i.auth_proof = i.bundle_proof.clone();
        for _ in 0..2 {
            assert_eq!(run(&ex, Kind::Bundle, &i), Ok(Verdict::Unit));
            assert_eq!(run(&ex, Kind::Auth, &i), Ok(Verdict::Word([3; 8])));
        }
        assert_eq!(inner.count(Kind::Bundle), 1);
        assert_eq!(inner.count(Kind::Auth), 1);
        assert_eq!(ex.cache().len(), 2);
    }

    #[test]
    fn fifo_eviction_at_capacity() {
        let inner = Arc::new(Counting::default());
        let ex = CachingExecutor::with_capacity(inner.clone(), 4);
        let keyed = |k: u32| {
            let mut i = Inputs::new();
            i.binding[0] = k;
            i.bundle_proof = StubExecutor::make_bundle_proof(&i.hc_bundle, &[3; 8], &i.binding);
            i
        };
        for k in 1..=5 {
            run(&ex, Kind::Bundle, &keyed(k)).unwrap();
        }
        assert_eq!(inner.count(Kind::Bundle), 5);
        assert_eq!(ex.cache().len(), 4);
        run(&ex, Kind::Bundle, &keyed(5)).unwrap();
        assert_eq!(inner.count(Kind::Bundle), 5, "the newest key hits");
        run(&ex, Kind::Bundle, &keyed(1)).unwrap();
        assert_eq!(inner.count(Kind::Bundle), 6, "the oldest key was evicted");
        assert_eq!(ex.cache().len(), 4);
    }

    #[test]
    fn non_cached_methods_forward() {
        let (inner, ex) = setup();
        let i = Inputs::new();
        let stub = StubExecutor;
        // The defaulted methods: Counting's values, never the trait's.
        assert_eq!(ex.max_callable_program_words(8), Some(31_337));
        assert_eq!(ex.bundle_gas_limit(&i.bundle_proof), Ok(Some(1_111)));
        assert_eq!(ex.auth_gas_limit(&i.auth_proof), Ok(Some(2_222)));
        assert_eq!(ex.non_canonical_proof(&i.call_proof), Some("counting".into()));
        assert_eq!(ex.check_aggregate_header(&i.aggregate_proof), Err(ConfidentialError::Disabled));
        assert_eq!(ex.aggregate_proof_tier(&i.tree_proof), Ok(99));
        assert_eq!(ex.tree_digests(&i.tree), Ok(TreeDigests { vk_leaf: [9; 4], steps: vec![] }));
        // The private-multisig methods have no default; each must reach inner.
        assert_eq!(ex.install_msauth_vk(&[0; 3]), Err("counting: 3 bytes".into()));
        assert_eq!(ex.build_msauth_key(), Err("counting: built".into()));
        ex.enable_auth_multisig();
        assert_eq!(inner.multisig_enables.load(Ordering::SeqCst), 1);
        assert_eq!(ex.auth_header(&i.auth_proof), Ok((AuthShape::Multisig, [0x5a; 8], Some(4242))));
        ex.warm_auth_multisig();
        assert_eq!(inner.multisig_warms.load(Ordering::SeqCst), 1);
        assert!(!ex.auth_multisig_key_ready());
        // Every decode reaches inner, every time.
        for _ in 0..2 {
            assert_eq!(ex.decode_call(&i.record, &i.call_proof), Ok(DECODED));
            assert_eq!(ex.decode_call_hardened(&i.record, &i.hardened_proof, &i.hardened_segment), Ok(DECODED));
            assert_eq!(ex.decode_invoke(&i.record, &i.invoke_proof, &i.invoke_segment), Ok(DECODED));
            assert_eq!(ex.decode_perp(&i.engine_hc, i.max_tier, &i.perp_segment, &i.perp_proof), Ok(DECODED));
        }
        assert_eq!(inner.decodes.load(Ordering::SeqCst), 8);
        // Every warm reaches inner.
        ex.warm(&i.record);
        ex.warm_hardened(&i.record);
        ex.warm_bundle();
        ex.warm_auth();
        ex.warm_aggregation(&i.shape, 4);
        ex.warm_tree(&i.tree);
        assert_eq!(
            *inner.warms.lock().unwrap(),
            ["warm", "warm_hardened", "warm_bundle", "warm_auth", "warm_aggregation", "warm_tree"]
        );
        // The required methods answer as inner does.
        assert_eq!(ex.check_program(0, &[0x13]), stub.check_program(0, &[0x13]));
        assert_eq!(ex.public_digest(&[1, 2]), stub.public_digest(&[1, 2]));
        assert_eq!(ex.node_hash(&[1; 8], &[2; 8]), stub.node_hash(&[1; 8], &[2; 8]));
        assert_eq!(ex.hash_domain(3, &[4]), stub.hash_domain(3, &[4]));
        assert_eq!(ex.note_commitment(&[1; 8], &[2; 8], 3, 4, 5, &[6; 8]), stub.note_commitment(&[1; 8], &[2; 8], 3, 4, 5, &[6; 8]));
        let d = BundleDigestInput {
            anchor: [1; 8],
            nullifiers: [[2; 8]; 4],
            commitments: [[3; 8]; 4],
            fee: 4,
            burn_a: 5,
            burn_r: 6,
            burn_asset: 7,
            time: 8,
            auth_commit: [9; 8],
        };
        assert_eq!(ex.bundle_digest(&d), stub.bundle_digest(&d));
        assert_eq!(ex.bundle_digest_v3(&d), stub.bundle_digest_v3(&d));
        assert_eq!(ex.bundle_proof_digest(&i.hc_bundle, &i.bundle_proof), Ok([3; 8]));
        assert_eq!(ex.auth_proof_digest(&i.auth_proof), Ok([3; 8]));
        assert_eq!(ex.aggregate_program_digest(&i.shape), stub.aggregate_program_digest(&i.shape));
        // None of this touched a verifier or the cache.
        assert!(KINDS.iter().all(|k| inner.count(*k) == 0));
        assert_eq!(ex.cache().hits() + ex.cache().misses(), 0);
    }

    /// The plain `Counting` answers the private-multisig methods as the stub does, through the
    /// wrapper too.
    #[test]
    fn non_cached_msauth_methods_forward_plain() {
        let inner = Arc::new(Counting::plain());
        let ex = CachingExecutor::new(inner.clone());
        let stub = StubExecutor;
        assert_eq!(ex.install_msauth_vk(&[0; 3]), stub.install_msauth_vk(&[0; 3]));
        assert_eq!(ex.build_msauth_key(), stub.build_msauth_key());
        ex.enable_auth_multisig();
        assert_eq!(inner.multisig_enables.load(Ordering::SeqCst), 1);
        let msig = StubExecutor::make_msauth_proof(&[23; 8], &[1; 8], &[0; 8]);
        assert_eq!(ex.auth_header(&msig), stub.auth_header(&msig));
        ex.warm_auth_multisig();
        assert_eq!(inner.multisig_warms.load(Ordering::SeqCst), 1);
        assert_eq!(ex.auth_multisig_key_ready(), stub.auth_multisig_key_ready());
    }

    /// Spec §3.4: the three phase-4 methods forward, and a multisig verify is an ordinary kind-2
    /// (`verify_auth`) entry keyed by its `hc` — nothing new is cached. `Counting::plain()`, since
    /// the test needs the stub's answers (a ready key, a real multisig shape).
    #[test]
    fn the_phase_4_methods_forward_and_a_multisig_verify_is_its_own_kind_2_entry() {
        let inner = Arc::new(Counting::plain());
        let ex = CachingExecutor::new(inner.clone());
        let msig = StubExecutor::make_msauth_proof(&[23; 8], &[1; 8], &[0; 8]);
        assert_eq!(ex.auth_header(&msig).unwrap().0, AuthShape::Multisig);
        ex.warm_auth_multisig();
        assert!(ex.auth_multisig_key_ready());
        assert_eq!(ex.verify_auth(&[23; 8], &msig, &[0; 8]), Ok([1; 8]));
        assert_eq!(ex.verify_auth(&[23; 8], &msig, &[0; 8]), Ok([1; 8]));
        assert_eq!(inner.count(Kind::Auth), 1, "cached under (hc, proof, binding)");
        let _ = ex.verify_auth(&[21; 8], &msig, &[0; 8]);
        assert_eq!(inner.count(Kind::Auth), 2, "another hc is another entry");
    }

    /// Plan Task 3 review: the msauth gate opens THROUGH the caching wrapper. Today
    /// `node::load_genesis` opens it on the bare executor before the wrap; this pins the wrapper
    /// path so a refactor that enables after wrapping cannot silently turn private multisig off.
    #[test]
    fn enabling_auth_multisig_through_the_wrapper_opens_the_msauth_path() {
        use crate::agg_executor::AggExecutor;
        use randprotocol_zkvm::executor::ZkExecutor;
        let hcm = ZkExecutor::hc_auth_multisig();
        let disabled = ConfidentialError::InvalidProof("a multisig auth proof on a chain without hc_auth_multisig".into());
        let shut = CachingExecutor::new(Arc::new(AggExecutor::new(randprotocol_zkvm::machine::FriProfile::Test)));
        assert_eq!(shut.verify_auth(&hcm, b"junk", &[0; 8]), Err(disabled.clone()), "not enabled: refused before any decode");
        let open = CachingExecutor::new(Arc::new(AggExecutor::new(randprotocol_zkvm::machine::FriProfile::Test)));
        open.enable_auth_multisig();
        let got = open.verify_auth(&hcm, b"junk", &[0; 8]);
        assert_ne!(got, Err(disabled), "enabled through the wrapper: the msauth path decodes");
        assert_eq!(got, Err(ConfidentialError::MalformedProof));
    }

    // ---------------------------------- the reuse contract, through a real ledger (spec §4)

    use crate::storage::fixtures::{bundle_fee, bundle_tx, env, genesis_of, key, pad4, stub_pruned_facts, HC};
    use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use randprotocol_core::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
    use randprotocol_core::types::{Action, AggregateLayout};
    use randprotocol_core::{Keypair, Ledger, ShieldedAddress, Transaction};

    /// A one-validator stub-executor ledger at height 1 and a valid stub bundle over it.
    fn bundle_ledger() -> (Ledger, Transaction) {
        let mut l = genesis_of(7, &[&key(1)], vec![], 2).ledger;
        l.set_height(1);
        let tx = bundle_tx(&l, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        (l, tx)
    }

    /// Admission (`validate`) then apply (`apply_tx`, which verifies the proof again) through one
    /// cache: the bundle verifier runs once. The control, the same two calls on the bare executor,
    /// shows apply does verify: there it runs twice.
    #[test]
    fn a_ledger_apply_after_validate_reuses_the_bundle_verdict() {
        let (l, tx) = bundle_ledger();
        let proposer = key(1).address();

        let bare = Counting::plain();
        l.validate(&tx, &bare).unwrap();
        l.clone().apply_tx(&tx, &proposer, &bare).unwrap();
        assert_eq!(bare.count(Kind::Bundle), 2, "without the cache, apply verifies the bundle again");

        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        l.validate(&tx, &cx).unwrap();
        assert_eq!(inner.count(Kind::Bundle), 1, "admission verified the bundle");
        l.clone().apply_tx(&tx, &proposer, &cx).unwrap();
        assert_eq!(inner.count(Kind::Bundle), 1, "apply reused admission's verdict");
        assert_eq!((cx.cache().hits(), cx.cache().misses()), (1, 1));
    }

    /// The verified-set fold (spec `docs/superpowers/specs/2026-10-12-verified-fold-design.md`
    /// §2), on the node's real admission path: on the RPL-2 fixture chain (split authorisation,
    /// `hardening_v6`), `validate_for_pool` — what `pump_verify` runs — admits a split-auth
    /// transfer and a hardened call through one `CachingExecutor`, then a block holding both
    /// applies on the same ledger through it. Each inner verifier runs exactly once per proof:
    /// apply's verify of each is answered from admission's verdict.
    #[test]
    fn admission_then_apply_verifies_each_proof_once() {
        use crate::storage::fixtures::{make_block, rpl2_chain, rpl2_program, v3_bundle, v3_tx};
        const FEE: u64 = randprotocol_core::UNITS_PER_RAND;
        let (_dir, storage, _gs, ledger, b1) = rpl2_chain(7);
        let transfer = v3_tx(&ledger, 40, FEE, Action::None);
        let (program, _) = rpl2_program();
        let mut call = Transaction::shielded(
            ledger.chain_id(),
            v3_bundle(&ledger, 50, FEE, (0, 0, 0)),
            Action::Call { program, proof: Vec::new(), input_envelope: None },
        );
        let record = ledger.program(&program).expect("the fixture program is deployed");
        let segment = ledger.hardened_call_segment(record, &call.call_binding(ledger.binding_domain()));
        let proof = StubExecutor::make_proof_with_public(&program, 10, [1; 8], &segment);
        let Action::Call { proof: p, .. } = &mut call.action else { unreachable!() };
        *p = proof;
        let call = StubExecutor::bound(call);

        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        for tx in [&transfer, &call] {
            assert_eq!(crate::node::validate_for_pool(tx, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
        }
        let admitted = (inner.count(Kind::Bundle), inner.count(Kind::Auth), inner.count(Kind::CallHardened));
        assert_eq!(admitted, (2, 2, 1), "admission verified each proof");

        let block = make_block(&b1, &mut ledger.clone(), vec![transfer, call], &key(1));
        let receipts = ledger.clone().apply_block(&block.block, &cx).expect("the block applies");
        assert_eq!(receipts.len(), 1, "the call's receipt");
        let applied = (inner.count(Kind::Bundle), inner.count(Kind::Auth), inner.count(Kind::CallHardened));
        assert_eq!(applied, (2, 2, 1), "apply verified nothing again");
        // The sync / off-loop path (`apply_block_for_sync`) on another clone: the same.
        let synced = ledger.clone().apply_block_for_sync(&block.block, &std::collections::BTreeMap::new(), &[], &cx).expect("the block applies");
        assert_eq!(synced, receipts);
        let synced = (inner.count(Kind::Bundle), inner.count(Kind::Auth), inner.count(Kind::CallHardened));
        assert_eq!(synced, (2, 2, 1), "nor did the sync apply");
        assert_eq!(inner.count(Kind::Call) + inner.count(Kind::Invoke) + inner.count(Kind::Perp), 0);
        assert_eq!((cx.cache().hits(), cx.cache().misses()), (10, 5));
    }

    /// The two inner verifier counts the bundle-carrying tests below read.
    fn bundle_auth_counts(inner: &Counting) -> (usize, usize) {
        (inner.count(Kind::Bundle), inner.count(Kind::Auth))
    }

    /// An empty store for `validate_for_pool`, which reads it only for an `Aggregate`.
    fn scratch_store(gs: &randprotocol_core::genesis::GenesisState) -> (tempfile::TempDir, crate::storage::Storage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::open(dir.path()).unwrap();
        storage.init_genesis(gs).unwrap();
        (dir, storage)
    }

    /// The fold's review focus 1 and 3 for the two proof kinds that read more than the
    /// transaction: an RPL-2 `Invoke` (its segment carries the transition's context words) and an
    /// RPL-3 `PerpStateProof` admitted and applied on the same tip (its segment carries the
    /// ledger's proved root). Admitted through `validate_for_pool`, then applied as the next block
    /// through `apply_block` and `apply_block_for_sync`: `verify_invoke` and `verify_perp` each
    /// run exactly once.
    #[test]
    fn admission_then_apply_verifies_an_invoke_and_a_state_proof_once() {
        use crate::storage::fixtures::{make_block, make_perps_block, perp_state_proof_tx, perps_genesis, rpl2_chain, rpl2_invoke_tx};
        use randprotocol_core::ledger::program_state::{Cell, Inflow, Transition};
        use std::collections::BTreeMap;
        const FEE: u64 = randprotocol_core::UNITS_PER_RAND;

        // RPL-2: an invoke creating one cell.
        let (_dir, storage, _gs, ledger, b1) = rpl2_chain(7);
        let cell = Cell { key: [1, 0, 0, 0, 0, 0, 0, 0], value: [5, 0, 0, 0, 0, 0, 0, 1] };
        let transition = Transition { reads: vec![], writes: vec![cell], inflow: Inflow::None, pays: vec![], mints: vec![] };
        let invoke = rpl2_invoke_tx(&ledger, 60, FEE, (0, 0, 0), transition);
        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        assert_eq!(crate::node::validate_for_pool(&invoke, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
        assert_eq!(inner.count(Kind::Invoke), 1, "admission verified the invoke");
        let block = make_block(&b1, &mut ledger.clone(), vec![invoke], &key(1));
        let receipts = ledger.clone().apply_block(&block.block, &cx).expect("the block applies");
        assert_eq!(receipts.len(), 1, "the invoke's receipt");
        ledger.clone().apply_block_for_sync(&block.block, &BTreeMap::new(), &[], &cx).expect("the block applies");
        assert_eq!(inner.count(Kind::Invoke), 1, "apply verified the invoke again");
        assert_eq!(bundle_auth_counts(&inner), (1, 1));
        assert_eq!(inner.count(Kind::Call) + inner.count(Kind::CallHardened), 0, "an invoke is not a call");

        // RPL-3: a state proof of 0..=2, admitted at tip 2 and applied as block 3.
        let gs = perps_genesis(7);
        let (_dir, storage) = scratch_store(&gs);
        let mut ledger = gs.ledger.clone();
        let b1 = make_perps_block(&gs.block, &mut ledger, vec![], &key(1));
        let b2 = make_perps_block(&b1, &mut ledger, vec![], &key(1));
        let proof = perp_state_proof_tx(&ledger, 2, [7; 8], vec![], 0);
        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        assert_eq!(crate::node::validate_for_pool(&proof, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
        assert_eq!(inner.count(Kind::Perp), 1, "admission verified the state proof");
        let block = make_perps_block(&b2, &mut ledger.clone(), vec![proof], &key(1));
        ledger.clone().apply_block(&block.block, &cx).expect("the block applies");
        ledger.clone().apply_block_for_sync(&block.block, &BTreeMap::new(), &[], &cx).expect("the block applies");
        assert_eq!(inner.count(Kind::Perp), 1, "apply on the same tip verified the state proof again");
        assert_eq!((cx.cache().hits(), cx.cache().misses()), (2, 1));
    }

    /// Private multisig through the fold: a transfer whose auth proof is multisig-shaped
    /// (`auth_header` dispatches it to genesis `hc_auth_multisig`) is admitted and applied with
    /// one inner `verify_auth` — the cache key carries the multisig hc, and the stub's verify
    /// refuses any other guest (`WrongProgram`), so the applies' success shows the dispatch.
    #[test]
    fn admission_then_apply_verifies_a_multisig_auth_proof_once() {
        use crate::storage::fixtures::{make_block, rpl2_chain, v3_bundle};
        const HCM: Word8 = [23; 8];
        const C: Word8 = [0x0c; 8];
        let (_dir, storage, _gs, mut ledger, b1) = rpl2_chain(7);
        ledger.set_hc_auth_multisig(Some(HCM));
        let mut b = v3_bundle(&ledger, 70, randprotocol_core::UNITS_PER_RAND, (0, 0, 0));
        b.auth_commit = C;
        b.proof = StubExecutor::make_bundle_proof(&ledger.hc_bundle(), &StubExecutor.bundle_digest_v3(&b.digest_input()), &[0; 8]);
        b.auth_proof = StubExecutor::make_msauth_proof(&HCM, &C, &[0; 8]);
        let tx = StubExecutor::bound(Transaction::shielded(ledger.chain_id(), b, Action::None));
        assert_eq!(StubExecutor.auth_header(&tx.bundle.as_ref().unwrap().auth_proof).unwrap().0, AuthShape::Multisig);

        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        assert_eq!(crate::node::validate_for_pool(&tx, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
        assert_eq!(bundle_auth_counts(&inner), (1, 1), "admission verified both proofs");
        let block = make_block(&b1, &mut ledger.clone(), vec![tx], &key(1));
        ledger.clone().apply_block(&block.block, &cx).expect("the block applies");
        ledger.clone().apply_block_for_sync(&block.block, &std::collections::BTreeMap::new(), &[], &cx).expect("the block applies");
        assert_eq!(bundle_auth_counts(&inner), (1, 1), "apply verified neither again");
    }

    /// Review focus 5: eviction. Two one-proof transfers (a chain without split authorisation)
    /// admitted through a one-entry cache leave only the second's verdict; a block applying the
    /// second, then the first, costs exactly one inner verify more than the same run through an
    /// unbounded cache — the evicted verdict — and still applies.
    #[test]
    fn an_evicted_verdict_costs_one_verify_at_apply_and_the_block_still_applies() {
        use crate::storage::fixtures::make_block;
        let gs = genesis_of(7, &[&key(1)], vec![], 2);
        let (_dir, storage) = scratch_store(&gs);
        let ledger = gs.ledger.clone();
        let first = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let second = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let block = make_block(&gs.block, &mut ledger.clone(), vec![second.clone(), first.clone()], &key(1));
        let run = |cap: usize| {
            let inner = Arc::new(Counting::plain());
            let cx = CachingExecutor::with_capacity(inner.clone(), cap);
            for tx in [&first, &second] {
                assert_eq!(crate::node::validate_for_pool(tx, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
            }
            ledger.clone().apply_block(&block.block, &cx).expect("the block applies, evicted or not");
            (inner.count(Kind::Bundle), cx.cache().len())
        };
        assert_eq!(run(VERIFY_CACHE_ENTRIES), (2, 2), "unbounded: admission's two verifies, apply answered");
        assert_eq!(run(1), (3, 1), "one entry: the first's verdict was evicted and verified again");
    }

    /// Review focus 2: a pruned (aggregate-covered) bundle at apply. A split-auth transfer is
    /// admitted raw; its block then applies in the sealed form a pruning peer serves — the
    /// bundle proof replaced by the marker, the side table attesting it — through
    /// `apply_block_for_sync`. The auth proof is verified there and answered from the cache (one
    /// inner `verify_auth` in total); the bundle verifier is not called again.
    #[test]
    fn a_pruned_bundles_auth_proof_is_answered_from_the_cache_and_its_bundle_proof_is_untouched() {
        use crate::storage::{fixtures::{make_block, rpl2_chain, v3_tx}, PRUNED_PROOF_MARKER};
        let (_dir, storage, _gs, ledger, b1) = rpl2_chain(7);
        let raw = v3_tx(&ledger, 40, randprotocol_core::UNITS_PER_RAND, Action::None);
        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        assert_eq!(crate::node::validate_for_pool(&raw, &ledger, &storage, FriProfile::Test, &cx), Ok(()));
        assert_eq!(bundle_auth_counts(&inner), (1, 1), "admission verified both proofs");

        // The sealed form (as `storage`'s sealed-sync test builds it, over the v3 digest).
        let raw_cb = make_block(&b1, &mut ledger.clone(), vec![raw.clone()], &key(1));
        let bundle = raw.bundle.as_ref().unwrap();
        let digest = StubExecutor.bundle_digest_v3(&bundle.digest_input());
        let hpub = StubExecutor.public_digest(&raw.binding(ledger.binding_domain()));
        let mut public_values = vec![0u64; pv::NUM];
        public_values[pv::TIER] = 14;
        for k in 0..8 {
            public_values[pv::OUT0 + k] = digest[k] as u64;
            public_values[pv::PUB0 + k] = hpub[k] as u64;
        }
        let proof_hash = Hash::digest(&bundle.proof);
        let mut served = raw_cb.block.clone();
        served.transactions[0].bundle.as_mut().unwrap().proof = [PRUNED_PROOF_MARKER, proof_hash.as_bytes().as_slice()].concat();
        let side = randprotocol_core::consensus::PrunedBundle {
            tx_hash: raw.hash(),
            proof_hash,
            public_values,
            shape: stub_pruned_facts(&raw).shape,
        };
        let mut synced = ledger.clone();
        synced.apply_block_for_sync(&served, &std::collections::BTreeMap::new(), &[side], &cx).expect("the sealed form applies");
        assert_eq!(synced.state_root(), raw_cb.block.header.state_root);
        assert_eq!(bundle_auth_counts(&inner), (1, 1), "the auth proof from the cache, the bundle proof untouched");
        assert_eq!((cx.cache().hits(), cx.cache().misses()), (1, 2), "one hit: the auth verdict");
    }

    /// A ledger under an aggregation section that admits the stub bundle's shape, with `kp`
    /// registered as an aggregator and one applied bundle in the coverable set: the ledger, that
    /// bundle's hash and its covered record.
    fn aggregate_ledger(kp: &Keypair) -> (Ledger, Hash, CoveredBundle) {
        let (mut l, covered_tx) = bundle_ledger();
        let facts = stub_pruned_facts(&covered_tx);
        let ux = StubExecutor;
        l.set_aggregation(Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape: facts.shape,
                hc: Hash(randprotocol_core::notes::word8_to_bytes(&HC)),
                aggregate_program_digest: ux.aggregate_program_digest(&facts.shape).unwrap(),
            }],
        }));
        let proposer = key(1).address();
        l.apply_tx(&covered_tx, &proposer, &ux).unwrap();
        // The registration bundle burns exactly the bond.
        let mut b = randprotocol_core::notes::Bundle {
            anchor: l.anchors().back().expect("a ledger always has an anchor").1,
            nullifiers: pad4([[11; 8], [12; 8]]),
            commitments: pad4([[13; 8], [14; 8]]),
            fee: randprotocol_core::gas::BUNDLE_BASE,
            burn_a: 0,
            burn_r: 100 * randprotocol_core::UNITS_PER_RAND,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: [env(1), env(2), env(1), env(2)],
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = ux.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(l.chain_id(), &payout).as_bytes()),
        };
        let register = StubExecutor::bound(Transaction::shielded(l.chain_id(), b, Action::RegisterAggregator { registration }));
        l.apply_tx(&register, &proposer, &ux).unwrap();
        assert!(l.unsealed_fees().contains_key(&covered_tx.hash()), "the covered bundle is coverable");
        (l, covered_tx.hash(), facts)
    }

    /// An aggregate by `kp` at nonce 0 over `covers`, with a stub proof bound to its own
    /// `(chain, aggregator, nonce)`, signed for the payout `l` pays now.
    fn aggregate_tx(l: &Ledger, kp: &Keypair, covers: Vec<Hash>) -> Transaction {
        let (chain_id, nonce, time, r) = (l.chain_id(), 0, 1, [9; 8]);
        let aggregator = kp.public_key().address();
        let proof = StubExecutor::make_aggregate_proof(&l.binding_domain().aggregate_binding(chain_id, &aggregator, nonce));
        let payout_total = l.payout_total_for(&covers).unwrap();
        let envelope = env(9);
        let signature = kp.sign(
            aggregate_signing_hash(
                chain_id,
                nonce,
                time,
                &r,
                &covers,
                &Hash::digest(&proof),
                &randprotocol_core::types::actions::envelope_digest(&envelope),
                payout_total,
            )
            .as_bytes(),
        );
        Transaction {
            chain_id,
            bundle: None,
            action: Action::Aggregate {
                covers,
                proof,
                aggregator,
                nonce,
                time,
                r,
                envelope,
                signature,
                payout_total,
                layout: AggregateLayout::Flat,
            },
        }
    }

    /// An aggregate validated (admission) then applied (`apply_aggregate`, which validates
    /// again) through one cache: `verify_aggregate` reaches inner once. The control on the bare
    /// executor reaches it twice.
    #[test]
    fn an_aggregate_validated_then_applied_verifies_once() {
        let kp = key(7);
        let (l, cover, facts) = aggregate_ledger(&kp);
        let tx = aggregate_tx(&l, &kp, vec![cover]);
        let covered = [facts];

        let bare = Counting::plain();
        l.validate_aggregate(&tx, &covered, &bare).unwrap();
        l.clone().apply_aggregate(&tx, &covered, &bare).unwrap();
        assert_eq!(bare.count(Kind::Aggregate), 2, "without the cache, apply verifies the aggregate again");

        let inner = Arc::new(Counting::plain());
        let cx = CachingExecutor::new(inner.clone());
        l.validate_aggregate(&tx, &covered, &cx).unwrap();
        assert_eq!(inner.count(Kind::Aggregate), 1, "admission verified the aggregate");
        let mut applied = l.clone();
        applied.apply_aggregate(&tx, &covered, &cx).unwrap();
        assert_eq!(inner.count(Kind::Aggregate), 1, "apply reused admission's verdict");
        assert_eq!(applied.aggregators()[&kp.public_key().address()].nonce, 1, "and the aggregate applied");
    }
}
