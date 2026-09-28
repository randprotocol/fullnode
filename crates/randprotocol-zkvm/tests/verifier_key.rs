//! HCS-1 (the 2026-09-27 zkVM review): a known-answer test on the verifier key itself.
//!
//! Every verifier key's preprocessed commitment — the range, nibble, Poseidon2 round-constant and
//! (when declared) keccak/sha256 periodic tables, committed through the *hiding* MMCS — is salted
//! from a deterministic stream (`machine::key_config`). The salts are not secret and need not be:
//! what matters is that every verifier draws the *same* ones, because the commitment is the first
//! thing the Fiat–Shamir transcript absorbs, and a verifier that recomputes a different cap refuses
//! every honest proof. Through constraint set 6 that stream was `StdRng::seed_from_u64(KEY_SEED)`,
//! which `rand` documents as free to change between releases; since constraint set 7 it is
//! `key_derivation_v2`'s Poseidon2 stream over this repository's own constants, so no dependency
//! update can move a key. This file stays the tripwire: if p3's salt draw, the preprocessed tables,
//! the chip set or the derivation ever changes what a key is, one of the digests below changes and
//! CI goes red *before* a node is built with it.
//!
//! What is pinned, per shape and profile, is two SHA-256 digests (SHA-256 because it is an oracle this
//! crate's tests already carry and the thing hashed must not be hashed by the machine under test):
//!
//! - `commitment`: the postcard bytes of the global preprocessed commitment's Merkle cap — the part
//!   the salt stream decides;
//! - `common`: the cap plus every instance's preprocessed placement (matrix index, width, degree bits)
//!   and every instance's packed lookups — the whole of `CommonData`, i.e. everything a verifier
//!   derives from the header before it reads a byte of STARK data.
//!
//! The shapes are the three the review asked for: a small tier-10 call with no hash chip, the
//! 2-in/2-out bundle guest at tier 14 with the chain's eight-word transaction binding as its public
//! segment (keccak and sha256 absent, exactly as fullnode's `decode_and_check` pins a bundle header),
//! and a tier-10 call declaring one keccak block — plus one sha256 shape, since that chip's periodic
//! columns are committed too. **A red here is a consensus event, not a flaky test**: re-pinning it
//! means every node's keys change, i.e. a chain cut.
//!
//! Re-pinned for constraint set 7 (chain 16), in two steps measured separately: the LogUp blind and
//! the `2^7` table floor (INT-2) moved every `common` digest and no `commitment` — the blind adds
//! columns and a bus to every instance's lookups, the floor raises the smallest shapes' program,
//! input and public heights to 7 — and HCS-1's switch to `key_derivation_v2` then moved every
//! `commitment` (and so every `common` again). On the integrated constraint-set-7 tree
//! (`feat/cs7`), ZKM-1 / ZKH-2's 32-bit range checks on the input, public and salt lanes add
//! RANGE8 lookups (the input and public tables widen 4 → 8, the salt row sends 16 from the cpu),
//! so every `common` moved once more and no `commitment` did: `e1d87ffc…`, `911d8e1a…`,
//! `fcf1f2f7…`, `1184e5ac…` were the blind + HCS-1 values without them, which is still what
//! `feat/cs7-logup-blind` alone measures. The constraint-set-6 pins were, in the order below:
//! `743ae428…`/`118596a0…`, `de7f12d3…`/`2fc852ce…`, `e5e6ce86…`/`e157ca30…`,
//! `b1387046…`/`fb6e0b55…`.
//!
//! Re-pinned for constraint set 8 (chain 18): the cpu table's GAS column and its four GD0..3 halt
//! limbs (`13dc769`) add four RANGE8 lookups to every shape's packed lookups but commit no new
//! preprocessed periodic table, so every `common` moved once more and no `commitment` did — the
//! same shape as the constraint-set-7 RANGE8 widening above. The constraint-set-7 `common` pins
//! this replaces were `fab9945e…`, `c207625a…`, `7a3a38e4…`, `8e6cd439…` (same order as the shapes
//! below); their `commitment` halves are unchanged and still pinned.
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
                "1442e70e1ddc7e9c6eabf1a6e29bd9ea37d1996d81f89768af967b77ddc3fd41",
                "fd2f4f49d948aa8744340b5374fc85163be8520a2a7e6d25f2d6dd29c8a98ea9",
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
                "54991bdde2fdf6112181fde865e25cf94fae6084cb31ef33d9f58cb4645a6cc4",
                "99eed72b1d1c904a39f9f5b2c209bfb169a8e3ea79e1c8c337a3c6d6a6811f36",
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
                "0337aeaecbd7d601ac4b502153c29589ae290f179e277b2f66e1f4c29d3c48cb",
                "8792f659dd527a6909ba962216caa889082aed4d8983646a9c6b0847a2aaa764",
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
                "c277ab160af3160092c4a33220724276fabc2cd26e6229c5dae535eb16ba3760",
                "9690b474c215b7b38683e341cfe25a4fd12dc19bb46fb87e7cb3c21e2f831042",
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
