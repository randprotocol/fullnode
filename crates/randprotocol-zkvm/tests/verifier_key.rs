//! HCS-1 (the 2026-09-27 zkVM review): a known-answer test on the verifier key itself.
//!
//! Every verifier key's preprocessed commitment — the range, nibble, Poseidon2 round-constant and
//! (when declared) keccak/sha256 periodic tables, committed through the *hiding* MMCS — is salted
//! from `StdRng::seed_from_u64(KEY_SEED)` (`machine::key_config`). The salts are not secret and need
//! not be: what matters is that every verifier draws the *same* ones, because the commitment is the
//! first thing the Fiat–Shamir transcript absorbs, and a verifier that recomputes a different cap
//! refuses every honest proof. `rand` documents `StdRng`'s output stream as free to change between
//! releases, so the stream is an unwritten part of the chain's consensus rules. `Cargo.toml` now pins
//! `rand`, `rand_core` and `chacha20` exactly; this file is the tripwire behind the pin — if any of
//! the three, or p3's salt draw, or the preprocessed tables, or the chip set, ever changes what a key
//! is, one of the digests below changes and CI goes red *before* a node is built with it.
//!
//! What is pinned, per shape and profile, is two SHA-256 digests (SHA-256 because it is an oracle this
//! crate's tests already carry and the thing hashed must not be hashed by the machine under test):
//!
//! - `commitment`: the postcard bytes of the global preprocessed commitment's Merkle cap — the part
//!   the `rand` stream decides;
//! - `common`: the cap plus every instance's preprocessed placement (matrix index, width, degree bits)
//!   and every instance's packed lookups — the whole of `CommonData`, i.e. everything a verifier
//!   derives from the header before it reads a byte of STARK data.
//!
//! The shapes are the three the review asked for: a small tier-10 call with no hash chip, the
//! 2-in/2-out bundle guest at tier 14 with the chain's eight-word transaction binding as its public
//! segment (keccak and sha256 absent, exactly as fullnode's `decode_and_check` pins a bundle header),
//! and a tier-10 call declaring one keccak block — plus one sha256 shape, since that chip's periodic
//! columns are committed too. **A red here is a consensus event, not a flaky test**: re-pinning it
//! means every node's keys change, i.e. a chain cut (`key_derivation_v2`'s module comment).
use p3_batch_stark::CommonData;
use randprotocol_zkvm::machine::{Config, FriProfile, Machine, Tier};
use randprotocol_zkvm::tables::{input, keccak, program, public, sha256};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// `(commitment, common)` — see the module comment.
fn digests(common: &CommonData<Config>) -> (String, String) {
    let pre = common.preprocessed.as_ref().expect("every shape commits the range/nibble/Poseidon2 tables");
    let cap = postcard::to_allocvec(&pre.commitment).expect("the cap serialises");
    let mut all = Sha256::new();
    all.update(&cap);
    for meta in &pre.instances {
        match meta {
            None => all.update([0u8]),
            Some(m) => {
                all.update([1u8]);
                for x in [m.matrix_index, m.width, m.degree_bits] {
                    all.update((x as u64).to_le_bytes());
                }
            }
        }
    }
    for i in &pre.matrix_to_instance {
        all.update((*i as u64).to_le_bytes());
    }
    all.update(postcard::to_allocvec(&common.lookups).expect("the lookups serialise"));
    (hex(&Sha256::digest(&cap)), hex(&all.finalize()))
}

/// One pinned shape: a name, the verifier-key arguments, and its `(commitment, common)` digests.
///
/// One pair serves both profiles, and that is measured, not assumed: the profile changes only the
/// FRI query count and grinding bits, which enter proving and verifying but not the preprocessed
/// commitment or the lookups, so the Test and Production keys of a shape are the same key. The test
/// checks both profiles against the one pair, so a future profile that did change the key would
/// show up here as a Production-only red.
struct Shape {
    name: &'static str,
    tier: Tier,
    plh: u8,
    ilh: u8,
    klh: u8,
    slh: u8,
    publh: u8,
    want: (&'static str, &'static str),
}

fn shapes() -> Vec<Shape> {
    // The bundle guest's own declared heights, derived the way fullnode's `pinned_heights` derives
    // them — so the pin follows the guest, and a guest change shows up as a changed shape here, not
    // as a silently different key.
    let bundle_plh = program::program_log_height(randprotocol_zkvm::guests::bundle().words.len());
    let bundle_ilh = input::input_log_height(randprotocol_zkvm::notes::bundle_input::COUNT);
    // The chain's transaction binding is eight words (`randprotocol_core::types::TX_BINDING_WORDS`).
    let binding_publh = public::public_log_height(8);
    vec![
        Shape {
            name: "tier 10, no hash chip, smallest program/input/public tables",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: 0,
            slh: 0,
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "743ae4284ab17fe155dd272fe6717f8290524b99a4b200e7132021b1dd1bfc02",
                "118596a0be5acbcf70872378f382e7f05ef8863b8695d4beb82c4f874abfb932",
            ),
        },
        Shape {
            name: "tier 14, the 2-in/2-out bundle guest, eight-word binding, no hash chip",
            tier: Tier(14),
            plh: bundle_plh,
            ilh: bundle_ilh,
            klh: 0,
            slh: 0,
            publh: binding_publh,
            want: (
                "de7f12d33cf24cb0088924d6c8141470c3dd4bf1d929a9ebeca4d6da5996d930",
                "2fc852ce01b8b97c8dd2add9aba20e0f634ed4dd7cc72e3659b0f236dc491148",
            ),
        },
        Shape {
            name: "tier 10, one keccak block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: keccak::keccak_log_height(1),
            slh: 0,
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "e5e6ce86bbbb8f8e8c53e8599c88e962d2e90c0a516845c1dffc3ae4fdc4b9b6",
                "e157ca301d4f16a614a29eb74c5580c7daaa88164ed98a9502a412c11a496542",
            ),
        },
        Shape {
            name: "tier 10, one sha256 block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: 0,
            slh: sha256::sha256_log_height(1),
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "b1387046ebc166cff216550539f7ec0bff6421555b28d9500ba7a89af256d5cb",
                "fb6e0b55f6c76af47a739a7392edfb2fcca008142482e2050fad6b521fd232da",
            ),
        },
    ]
}

#[test]
fn the_verifier_keys_answer_their_known_digests() {
    let mut failures = Vec::new();
    for profile in [FriProfile::Test, FriProfile::Production] {
        let m = Machine::new(profile);
        for s in shapes() {
            let common = m.verifier_key(s.tier, s.plh, s.ilh, s.klh, s.slh, s.publh);
            let (commitment, all) = digests(&common);
            eprintln!(
                "{profile:?} | {} (tier {}, plh {}, ilh {}, klh {}, slh {}, publh {}): (\"{commitment}\", \"{all}\")",
                s.name, s.tier.0, s.plh, s.ilh, s.klh, s.slh, s.publh
            );
            if (commitment.as_str(), all.as_str()) != s.want {
                failures.push(format!("{profile:?} | {}: got (\"{commitment}\", \"{all}\"), pinned {:?}", s.name, s.want));
            }
        }
    }
    assert!(failures.is_empty(), "verifier keys changed — a consensus change, see the module comment:\n{}", failures.join("\n"));
}

/// The key is a pure function of the declared shape: a second, independent `Machine` (whose proving
/// config drew fresh OS entropy) recomputes the identical key. This is the property the pin above
/// relies on — if it ever failed, the digests would be noise, not a known answer.
#[test]
fn two_machines_compute_the_same_key() {
    let (a, b) = (Machine::new(FriProfile::Test), Machine::new(FriProfile::Test));
    let d = |m: &Machine| digests(&m.verifier_key(Tier(10), program::MIN_LOG_HEIGHT, input::input_log_height(0), 0, 0, public::MIN_LOG_HEIGHT));
    assert_eq!(d(&a), d(&b));
}
