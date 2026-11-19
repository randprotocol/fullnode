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
//!
//! MODQ (private multisig phase 3): cpu `SYS_MODQ` column, every key moved. The appended cpu column
//! and its `MODQ` lookup move every shape's packed lookups, so every `common` moved and no
//! `commitment` did (the cpu commits no preprocessed column). A fifth shape, "tier 10, one modq
//! block", pins the modq chip's 16 periodic columns. The key tuple is now 7 wide (`mlh`). The
//! constraint-set-8 `common` pins this replaces were `fd2f4f49…`, `99eed72b…`, `8792f659…`,
//! `9690b474…`.
//!
//! Constraint set 10 (ZKV-5) changed no digest here: it adds no column, lookup or preprocessed
//! table, only the weight of a row in the gas chain, and neither half of `CommonData` carries
//! ordinary constraints. A red-free run here is therefore not evidence that the AIR is unchanged.
//!
//! Re-pinned for constraint set 11 (ZKVM-202, the gas re-weighting): the cpu table's appended
//! `MODQ_W` column and the fourth field of the `MODQ` lookup (the call's per-op weight, cpu and modq
//! sides) change every shape's packed lookups — the modq-free shapes too, since the cpu declares its
//! `MODQ` lookup in every batch — so every `common` moved and no `commitment` did (no preprocessed
//! column changed). The weights themselves (`KECCAK_GAS`, `SHA256_GAS`, `POSEIDON2_ABSORB_GAS`) are
//! ordinary constraints and would not have moved a digest alone. The constraint-set-9/10 `common`
//! pins this replaces were `d945789b…`, `0adff627…`, `eed808f7…`, `52b999fc…`, `aa129c0d…` (same
//! order as the shapes below).
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

/// Constraint set 11 moved every key three ways at once: the Grain round constants (ZKVM-107: the
/// poseidon2 chip's preprocessed constants, and the `key_derivation_v2` salt stream, which is a
/// Poseidon2 stream), rate 1/4 (ZKVM-111: the preprocessed LDE is half as tall) and the declared
/// poseidon2 height (ZKVM-112: the shapes below are at the full `t + 2`, the height the six-height
/// `verifier_key_with_modq` builds; `the_floor_height_key_answers_its_known_digest` pins one at a
/// declared height). The set-10 pins were, in the order below: `1442e70e…`/`d58a149a…`,
/// `54991bdd…`/`56a30a19…`, `0337aeae…`/`815e7e5a…`, `c277ab16…`/`47561c55…`,
/// `91bffa9b…`/`b0f27590…`.
///
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
    mlh: u8,
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
            mlh: 0,
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "2a50a24cf337142b714149b0de3503cf6567db1ca44d9952e748bdec90df000f",
                "5a873066b05c1a892db19c0030ec6d710a93dbbb6051e62a73e6547c707c410f",
            ),
        },
        Shape {
            name: "tier 14, the 2-in/2-out bundle guest, eight-word binding, no hash chip",
            tier: Tier(14),
            plh: bundle_plh,
            ilh: bundle_ilh,
            klh: 0,
            slh: 0,
            mlh: 0,
            publh: binding_publh,
            want: (
                "c08d2086306e6cf6f002117515d4e295cfd8bdb006bb90688613281283e7527a",
                "1f0d48fc5db56bb9983605a55587633b98d3450ca5d817376fe7614192a6bed7",
            ),
        },
        Shape {
            name: "tier 10, one keccak block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: keccak::keccak_log_height(1),
            slh: 0,
            mlh: 0,
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "d7bf8d3eee2248ed67519b7a4aa23b3c1f33a5ed253ac66d5b1c70246033021c",
                "4cc1f18451868b12be1c2a51bb95d55ada8d2d1f72217a83a98601ecd5b68862",
            ),
        },
        Shape {
            name: "tier 10, one sha256 block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: 0,
            slh: sha256::sha256_log_height(1),
            mlh: 0,
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "a9c665d2cd830327f3958c35b493ef2c66eeef458c46c5526c57ce5b672ed749",
                "0db6e06751d45e1f230ebe71b6b36b5f686debec5a056f1a94acf83cba64a7bb",
            ),
        },
        Shape {
            name: "tier 10, one modq block",
            tier: Tier(10),
            plh: program::MIN_LOG_HEIGHT,
            ilh: input::input_log_height(0),
            klh: 0,
            slh: 0,
            mlh: randprotocol_zkvm::tables::modq::modq_log_height(1),
            publh: public::MIN_LOG_HEIGHT,
            want: (
                "f721b745ad2bc18852ad4d6f36ff2fd2d8459fb01f959b1edf80db7d92c6bbb4",
                "ae173971e14ce3c28862690e55ed1370f954efb343df1df8c50daa177a8f34c5",
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
            let common = m.verifier_key_with_modq(s.tier, s.plh, s.ilh, s.klh, s.slh, s.mlh, s.publh);
            let (commitment, all) = digests(&common);
            eprintln!(
                "{profile:?} | {} (tier {}, plh {}, ilh {}, klh {}, slh {}, mlh {}, publh {}): (\"{commitment}\", \"{all}\")",
                s.name, s.tier.0, s.plh, s.ilh, s.klh, s.slh, s.mlh, s.publh
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

/// Constraint set 11 (ZKVM-112): a key at a declared poseidon2 height — the first shape above with
/// the table at the floor, `2^8`, where a tier-10 call that hashes nothing lands. A different key
/// from the full-height one, pinned the same way.
#[test]
fn the_floor_height_key_answers_its_known_digest() {
    use randprotocol_zkvm::machine::VerifierKeyShape;
    let shape = VerifierKeyShape { poseidon2_log_height: 8, ..VerifierKeyShape::full_height(Tier(10), program::MIN_LOG_HEIGHT, input::input_log_height(0), 0, 0, 0, public::MIN_LOG_HEIGHT) };
    shape.check().unwrap();
    for profile in [FriProfile::Test, FriProfile::Production] {
        let (commitment, all) = digests(&Machine::new(profile).verifier_key_for(shape));
        eprintln!("{profile:?} | tier 10 floor shape, poseidon2 2^8: (\"{commitment}\", \"{all}\")");
        assert_eq!((commitment.as_str(), all.as_str()), FLOOR_WANT, "{profile:?}");
    }
}
const FLOOR_WANT: (&str, &str) = ("52ac2e89aac71f90257c5a232532f5bfef682f16a2d0faacd0448bb5eaf53cea", "49f058cabc95d34c894540edb71ff5c6c07e3011891f8c38b3aa2f9f2fb7b8ad");
