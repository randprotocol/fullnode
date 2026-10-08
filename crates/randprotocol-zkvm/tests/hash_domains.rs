//! `hash.rs`, `notes::hash` and `key_derivation_v2` as *constructions*: the sponge's overwrite
//! mode rebuilt by hand from the raw permutation, the three in-circuit digests' capacity
//! headers, domain separation across every digest family and every note-layer domain, the
//! length-binding variants, `split_digest`'s lo/hi split at the field's edge, and the
//! host reference hashes against known answers at their block boundaries.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_zkvm::hash::*;
use randprotocol_zkvm::machine::Val;
use randprotocol_zkvm::notes::{self, domain, Word8};

fn v(x: u32) -> Val { Val::from_u32(x) }
fn lanes(s: [Val; 8]) -> [u32; 8] { split_digest([s[0], s[1], s[2], s[3]]) }

// ─────────────────────────── the sponge, by hand ───────────────────────────

#[test]
fn a_one_block_sponge_is_one_permutation_of_the_rate_lanes() {
    let msg = [1u32, 2, 3, 4];
    let want = lanes(permute_state([v(1), v(2), v(3), v(4), Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO]));
    assert_eq!(sponge_hash(&msg), want);
    // Fewer than four words: the unused rate lanes stay zero in the first block.
    assert_eq!(sponge_hash(&[9]), lanes(permute_state([v(9), Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO])));
}

#[test]
fn a_partial_second_block_overwrites_only_the_absorbed_lanes() {
    // Overwrite mode: lane 0 takes the fifth word, lanes 1..3 carry the first permutation's
    // output forward — they are *not* zeroed and *not* XORed.
    let mut s = permute_state([v(1), v(2), v(3), v(4), Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO]);
    s[0] = v(5);
    assert_eq!(sponge_hash(&[1, 2, 3, 4, 5]), lanes(permute_state(s)));
    // An XOR-mode or zero-fill sponge would give a different answer.
    let mut xor = permute_state([v(1), v(2), v(3), v(4), Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO]);
    xor[0] += v(5);
    assert_ne!(sponge_hash(&[1, 2, 3, 4, 5]), lanes(permute_state(xor)));
}

#[test]
fn the_padding_free_sponge_cannot_tell_zero_extension_within_a_block() {
    assert_eq!(sponge_hash(&[]), [0; 8], "no block, no permutation");
    assert_eq!(sponge_hash(&[7]), sponge_hash(&[7, 0]));
    assert_eq!(sponge_hash(&[7]), sponge_hash(&[7, 0, 0, 0]));
    assert_ne!(sponge_hash(&[7]), sponge_hash(&[7, 0, 0, 0, 0]), "a fifth zero word is a second permutation");
    assert_eq!(sponge_hash(&[0]), sponge_hash(&[0, 0, 0, 0]), "one zero block");
    assert_ne!(sponge_hash(&[0]), [0; 8], "but a zero block is still a permutation of the zero state");
}

#[test]
fn the_length_bound_sponge_separates_lengths_and_the_plain_sponge() {
    assert_ne!(sponge_hash_len(&[]), [0; 8]);
    assert_eq!(sponge_hash_len(&[]), lanes(permute_state([Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO])), "n = 0 permutes the all-zero state once");
    assert_ne!(sponge_hash_len(&[7]), sponge_hash_len(&[7, 0]));
    assert_ne!(sponge_hash_len(&[7]), sponge_hash_len(&[7, 0, 0, 0]));
    for n in 0..9usize {
        let msg: Vec<u32> = (1..=n as u32).collect();
        assert_ne!(sponge_hash_len(&msg), sponge_hash(&msg), "n = {n}: the capacity header separates the two syscalls");
    }
    // By construction: `[0,0,0,0,n,0,0,0]` with the words overwritten into the rate.
    let msg = [1u32, 2, 3, 4, 5];
    let mut s = permute_state([v(1), v(2), v(3), v(4), v(5), Val::ZERO, Val::ZERO, Val::ZERO]);
    s[0] = v(5);
    assert_eq!(sponge_hash_len(&msg), lanes(permute_state(s)));
}

#[test]
fn split_digest_is_the_canonical_u64_split_into_lo_and_hi_words() {
    let p = Val::ORDER_U64;
    let d = split_digest([Val::from_u64(p - 1), Val::from_u64(1u64 << 32), Val::ZERO, Val::from_u64(0x1_2345_6789)]);
    assert_eq!(d, [0, 0xffff_ffff, 0, 1, 0, 0, 0x2345_6789, 1]);
    // p − 1 = 2^64 − 2^32: low word 0, high word all ones. And a non-canonical input is
    // reduced first: `from_u64(p)` is zero.
    assert_eq!(split_digest([Val::from_u64(p), Val::ZERO, Val::ZERO, Val::ZERO]), [0; 8]);
    for (i, e) in [Val::from_u64(p - 1), Val::from_u64(1u64 << 32), Val::ZERO, Val::from_u64(0x1_2345_6789)].iter().enumerate() {
        assert_eq!((d[2 * i + 1] as u64) << 32 | d[2 * i] as u64, e.as_canonical_u64());
    }
}

#[test]
fn permute_words_agrees_with_permute_state_on_a_small_state() {
    // Only the lanes that happen to be small are comparable — `permute_words` truncates.
    let state = [1u32, 2, 3, 4, 5, 6, 7, 8];
    let full = permute_state(state.map(v));
    assert_eq!(permute_words(state), full.map(|x| x.as_canonical_u64() as u32));
    assert!(full.iter().any(|x| x.as_canonical_u64() > u32::MAX as u64), "a permuted lane is a full field element");
}

// ─────────────────────────── the three in-circuit digests ───────────────────────────

#[test]
fn the_program_digest_seeds_its_capacity_with_domain_base_pc_and_length() {
    let words = [0x13u32, 0x73, 0x13];
    let rows = program_digest_rows(0x1000, &words);
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.state_in, [Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, v(domain::HC), v(0x1000), v(3), Val::ZERO]);
    assert_eq!((r.idx, r.left_before, r.active, r.words), (0, 3, [true, true, true, false], [0x13, 0x73, 0x13, 0]));
    // The fourth lane is inactive: it carries the seed state's lane 3 (zero) into the permutation.
    assert_eq!(r.state_out, permute_state([v(0x13), v(0x73), v(0x13), Val::ZERO, v(domain::HC), v(0x1000), v(3), Val::ZERO]));
    assert_eq!(program_digest(0x1000, &words), lanes(r.state_out));
    assert_eq!(randprotocol_zkvm::isa::Program::new(0x1000, words.to_vec()).digest(), program_digest(0x1000, &words));
}

#[test]
fn the_program_digest_chains_blocks_in_overwrite_mode() {
    let words: Vec<u32> = (1..=9).collect();
    let rows = program_digest_rows(0, &words);
    assert_eq!(rows.len(), 3);
    for i in 1..rows.len() {
        assert_eq!(rows[i].state_in, rows[i - 1].state_out, "row {i} starts where row {} ended", i - 1);
        assert_eq!(rows[i].idx, i as u32);
    }
    assert_eq!(rows.iter().map(|r| r.left_before).collect::<Vec<_>>(), [9, 5, 1]);
    assert_eq!(rows[2].active, [true, false, false, false]);
    // The last block's three inactive lanes keep the previous state's lanes 1..3.
    let mut merged = rows[1].state_out;
    merged[0] = v(9);
    assert_eq!(rows[2].state_out, permute_state(merged));
}

#[test]
fn the_program_digest_binds_length_and_base_pc_against_zero_extension() {
    assert_ne!(program_digest(0, &[7]), program_digest(0, &[7, 0]), "the length is in the header");
    assert_ne!(program_digest(0, &[7]), program_digest(4, &[7]), "so is base_pc");
    assert_ne!(program_digest(0, &[]), [0; 8], "the empty program is a header-only permutation");
    assert_eq!(program_digest_rows(0, &[]).len(), 1);
    assert_eq!(program_digest_rows(0, &[])[0].active, [false; 4]);
}

#[test]
fn the_input_digest_absorbs_the_salt_block_first_then_the_words() {
    let salt = [10u32, 20, 30, 40];
    let inputs = [1u32, 2, 3, 4, 5];
    let rows = input_digest_rows(salt, &inputs);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows.len(), input_digest_row_count(inputs.len()));
    let s = &rows[0];
    assert_eq!(s.state_in, [Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, v(domain::IN), v(5), Val::ZERO, Val::ZERO]);
    assert_eq!((s.idx, s.left_before, s.active, s.words), (0, 5, [true; 4], salt));
    assert_eq!(s.state_out, permute_state([v(10), v(20), v(30), v(40), v(domain::IN), v(5), Val::ZERO, Val::ZERO]));
    assert_eq!((rows[1].idx, rows[1].left_before, rows[1].words), (1, 5, [1, 2, 3, 4]));
    assert_eq!((rows[2].idx, rows[2].left_before, rows[2].active), (2, 1, [true, false, false, false]));
    assert_eq!(input_digest(salt, &inputs), lanes(rows[2].state_out));
}

#[test]
fn input_digest_row_counts_are_one_plus_ceil_n_over_four() {
    for (n, rows) in [(0usize, 1usize), (1, 2), (4, 2), (5, 3), (8, 3), (9, 4)] {
        assert_eq!(input_digest_row_count(n), rows, "n = {n}");
        assert_eq!(input_digest_rows([0; 4], &vec![1; n]).len(), rows);
    }
    for (n, rows) in [(0usize, 1usize), (1, 1), (4, 1), (5, 2), (8, 2), (9, 3)] {
        assert_eq!(public_digest_row_count(n), rows, "n = {n}");
        assert_eq!(public_digest_rows(&vec![1; n]).len(), rows);
    }
}

#[test]
fn the_public_digest_header_is_domain_and_length_only() {
    let rows = public_digest_rows(&[1, 2]);
    assert_eq!(rows[0].state_in, [Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, v(domain::PUB), v(2), Val::ZERO, Val::ZERO]);
    assert_eq!(public_digest_rows(&[])[0].state_in[5], Val::ZERO);
    assert_ne!(public_digest(&[]), public_digest(&[0]), "n is in the header");
    assert_ne!(public_digest(&[1, 2]), public_digest(&[2, 1]), "order");
}

#[test]
fn the_digest_families_are_pairwise_separated_on_the_same_words() {
    let w = [1u32, 2, 3, 4];
    let all: Vec<([u32; 8], &str)> = vec![
        (sponge_hash(&w), "sponge"),
        (sponge_hash_len(&w), "sponge_len"),
        (program_digest(0, &w), "hc"),
        (input_digest([0; 4], &w), "H_IN (zero salt)"),
        (public_digest(&w), "H_PUB"),
        (notes::hash(domain::HC, &w), "notes::hash(HC)"),
        (notes::hash(domain::IN, &w), "notes::hash(IN)"),
        (notes::hash(domain::PUB, &w), "notes::hash(PUB)"),
    ];
    for i in 0..all.len() {
        for j in 0..i {
            assert_ne!(all[i].0, all[j].0, "{} and {} collide", all[i].1, all[j].1);
        }
    }
}

// ─────────────────────────── the note layer's domains ───────────────────────────

const DOMAINS: [(u32, &str); 17] = [
    (domain::NK, "NK"), (domain::PK, "PK"), (domain::NF, "NF"), (domain::CM, "CM"), (domain::OVK, "OVK"),
    (domain::KEM_SEED, "KEM_SEED"), (domain::NODE, "NODE"), (domain::HC, "HC"), (domain::OUT, "OUT"),
    (domain::IN, "IN"), (domain::BUNDLE, "BUNDLE"), (domain::STORAGE_LEAF, "STORAGE_LEAF"),
    (domain::EVM_OUT, "EVM_OUT"), (domain::SBPF_OUT, "SBPF_OUT"), (domain::PUB, "PUB"),
    (domain::KEM_SEED_VERSION, "KEM_SEED_VERSION"), (domain::TEST, "TEST"),
];

#[test]
fn every_note_layer_domain_tag_is_distinct_and_separates_the_same_message() {
    let msg = [5u32; 8];
    for i in 0..DOMAINS.len() {
        for j in 0..i {
            assert_ne!(DOMAINS[i].0, DOMAINS[j].0, "{} and {} share a tag", DOMAINS[i].1, DOMAINS[j].1);
            assert_ne!(notes::hash(DOMAINS[i].0, &msg), notes::hash(DOMAINS[j].0, &msg), "{} and {} collide", DOMAINS[i].1, DOMAINS[j].1);
        }
    }
    assert_eq!(DOMAINS.iter().filter(|(d, _)| *d != domain::TEST).map(|(d, _)| *d).max(), Some(domain::KEM_SEED_VERSION), "the live tags are dense up to 16");
}

#[test]
fn notes_hash_is_the_sponge_over_the_tag_prefixed_message() {
    let msg = [1u32, 2, 3];
    assert_eq!(notes::hash(domain::CM, &msg), sponge_hash(&[domain::CM, 1, 2, 3]));
    assert_eq!(notes::hash(domain::TEST, &[]), sponge_hash(&[domain::TEST]));
    // A message is not confusable with a tag: `H(d, [x])` and `H(x, [d])` differ.
    assert_ne!(notes::hash(3, &[4]), notes::hash(4, &[3]));
}

#[test]
fn output_and_bundle_digests_are_bound_to_every_field_and_to_field_order() {
    let a: Word8 = [1; 8];
    let b: Word8 = [2; 8];
    let c: Word8 = [3; 8];
    let base = notes::output_digest(&a, &b, &c, 9);
    assert_ne!(base, notes::output_digest(&b, &a, &c, 9), "anchor/nf swapped");
    assert_ne!(base, notes::output_digest(&a, &c, &b, 9), "nf/cm swapped");
    assert_ne!(base, notes::output_digest(&a, &b, &c, 10), "time");
    let mut a2 = a; a2[7] ^= 1;
    assert_ne!(base, notes::output_digest(&a2, &b, &c, 9), "last anchor word");
    assert_eq!(base, sponge_hash(&[&[domain::OUT][..], &a, &b, &c, &[9]].concat()));

    let d: Word8 = [4; 8];
    let e: Word8 = [5; 8];
    let bd = notes::bundle_digest(&a, &b, &c, &d, &e, 1, 2, 3, 4);
    assert_ne!(bd, notes::bundle_digest(&a, &c, &b, &d, &e, 1, 2, 3, 4), "nf1/nf2 order");
    assert_ne!(bd, notes::bundle_digest(&a, &b, &c, &e, &d, 1, 2, 3, 4), "cm1/cm2 order");
    assert_ne!(bd, notes::bundle_digest(&a, &b, &c, &d, &e, 2, 1, 3, 4), "fee/burn swapped");
    assert_ne!(bd, notes::bundle_digest(&a, &b, &c, &d, &e, 1 | 1 << 32, 2, 3, 4), "fee high word");
    assert_ne!(bd, notes::bundle_digest(&a, &b, &c, &d, &e, 1, 2, 4, 3), "asset/time swapped");
    let mut msg = vec![domain::BUNDLE];
    for w in [a, b, c, d, e] { msg.extend_from_slice(&w); }
    msg.extend_from_slice(&[1, 0, 2, 0, 3, 4, 0]);
    assert_eq!(bd, sponge_hash(&msg), "bad = 0 is the 47th word");
}

// ─────────────────────────── the wide hashes behind the viewing keys ───────────────────────────

#[test]
fn ovk_and_kem_seed_are_counter_mode_squeezes_of_nk() {
    let vk = notes::SpendKey([3, 1, 4, 1, 5, 9, 2, 6]).viewing_key();
    let chunk = |d: u32, msg: &[u32], ctr: u32| sponge_hash(&[&[d][..], msg, &[ctr]].concat());
    assert_eq!(vk.ovk().to_vec(), notes::words_to_bytes(&chunk(domain::OVK, &vk.nk, 0)));
    let seed: Vec<u8> = [chunk(domain::KEM_SEED, &vk.nk, 0), chunk(domain::KEM_SEED, &vk.nk, 1)].iter().flat_map(|c| notes::words_to_bytes(c)).collect();
    assert_eq!(vk.kem_seed().to_vec(), seed);
    assert_eq!(vk.kem_seed_at(0), vk.kem_seed());
    let mut m = vk.nk.to_vec(); m.push(7);
    let seed7: Vec<u8> = [chunk(domain::KEM_SEED_VERSION, &m, 0), chunk(domain::KEM_SEED_VERSION, &m, 1)].iter().flat_map(|c| notes::words_to_bytes(c)).collect();
    assert_eq!(vk.kem_seed_at(7).to_vec(), seed7);
    assert_ne!(vk.kem_seed_at(1), vk.kem_seed_at(2));
    assert_ne!(&vk.kem_seed()[..32], &vk.ovk()[..], "different domains");
    assert_eq!(vk.pk(), notes::hash(domain::PK, &vk.nk));
}

// ─────────────────────────── key derivation v2 ───────────────────────────

#[test]
fn key_rng_v2_reads_one_stream_whichever_width_is_asked() {
    use rand::Rng;
    use randprotocol_zkvm::key_derivation_v2::KeyRngV2;
    let mut by_u32 = KeyRngV2::from_label(b"probe");
    let mut by_u64 = KeyRngV2::from_label(b"probe");
    let mut by_bytes = KeyRngV2::from_label(b"probe");
    let words: Vec<u32> = (0..6).map(|_| by_u32.next_u32()).collect();
    let u64s: Vec<u64> = (0..3).map(|_| by_u64.next_u64()).collect();
    for i in 0..3 {
        assert_eq!(u64s[i], words[2 * i] as u64 | (words[2 * i + 1] as u64) << 32, "low word first");
    }
    // An odd-length fill takes whole words and drops the tail of the last one.
    let mut b = [0u8; 7];
    by_bytes.fill_bytes(&mut b);
    assert_eq!(b[..4], words[0].to_le_bytes());
    assert_eq!(b[4..], words[1].to_le_bytes()[..3]);
    assert_eq!(by_bytes.next_u32(), words[2], "the partial word is consumed, not resumed");
}

#[test]
fn key_rng_v2_labels_differ_from_seeds_with_the_same_bytes() {
    use rand::{Rng, SeedableRng};
    use randprotocol_zkvm::key_derivation_v2::KeyRngV2;
    let bytes = [7u8; 32];
    let mut from_seed = KeyRngV2::from_seed(bytes);
    let mut from_label = KeyRngV2::from_label(&bytes);
    assert_ne!(from_seed.next_u64(), from_label.next_u64(), "the marker word separates the two constructors");
    // The first squeeze happens on the first draw: two fresh instances agree word for word.
    let (mut a, mut b) = (KeyRngV2::from_seed(bytes), KeyRngV2::from_seed(bytes));
    assert_eq!((0..9).map(|_| a.next_u32()).collect::<Vec<_>>(), (0..9).map(|_| b.next_u32()).collect::<Vec<_>>());
}

// ─────────────────────────── keccak and sha256 known answers ───────────────────────────

#[test]
fn keccak256_known_answers_at_short_and_block_boundary_lengths() {
    use randprotocol_zkvm::keccak::keccak256;
    assert_eq!(hex::encode(keccak256(b"hello")), "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
    assert_eq!(hex::encode(keccak256(b"testing")), "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02");
    assert_eq!(hex::encode(keccak256(b"The quick brown fox jumps over the lazy dog")), "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15");
    // Padding at the rate boundary is a sponge of its own: 135, 136 and 137 bytes are one, two
    // and two blocks, and all three differ — and 136 zero bytes is not the empty message's
    // digest with a block prepended.
    let d: Vec<[u8; 32]> = [135usize, 136, 137, 271, 272, 273].iter().map(|n| keccak256(&vec![0xa5u8; *n])).collect();
    for i in 0..d.len() { for j in 0..i { assert_ne!(d[i], d[j]); } }
}

#[test]
fn keccak_f_of_the_zero_state_matches_the_published_vector() {
    use randprotocol_zkvm::keccak::keccak_f;
    let mut s = [0u64; 25];
    keccak_f(&mut s);
    // FIPS 202 / XKCP "KeccakF-1600-IntermediateValues", the state after one permutation of
    // all zeros, first lanes.
    assert_eq!(s[0], 0xf125_8f79_40e1_dde7);
    assert_eq!(s[1], 0x84d5_ccf9_33c0_478a);
    assert_eq!(s[2], 0xd598_261e_a65a_a9ee);
    assert_eq!(s[24], 0xeaf1_ff7b_5cec_a249);
}

#[test]
fn sha256_known_answers_at_the_padding_boundaries() {
    use randprotocol_zkvm::sha256::{bytes_to_words, compress, sha256, IV};
    use sha2::Digest;
    assert_eq!(hex::encode(sha256(b"The quick brown fox jumps over the lazy dog")), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    // 55 bytes pads in one block, 56 needs a second, 64 is a full block plus a padding block.
    for n in [55usize, 56, 57, 63, 64, 65, 119, 120, 128] {
        let msg = vec![0x61u8; n];
        assert_eq!(sha256(&msg), <[u8; 32]>::from(sha2::Sha256::digest(&msg)), "len {n}");
    }
    // One million 'a's (FIPS 180-2 test 3).
    assert_eq!(hex::encode(sha256(&vec![b'a'; 1_000_000])), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    // `compress` on the padded "abc" block from IV is the whole hash.
    let mut block = [0u8; 64];
    block[..3].copy_from_slice(b"abc");
    block[3] = 0x80;
    block[63] = 24;
    let mut h = IV;
    compress(&mut h, &bytes_to_words(&block));
    let out: Vec<u8> = h.iter().flat_map(|w| w.to_be_bytes()).collect();
    assert_eq!(hex::encode(out), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // Words are big-endian: the first word of that block is "abc" ‖ 0x80.
    assert_eq!(bytes_to_words(&block)[0], 0x6162_6380);
}
