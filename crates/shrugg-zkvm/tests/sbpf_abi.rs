//! The sBPF guest's ABI (M4.4 Task 5): the *aligned* serialized instruction input
//! `solana_program::entrypoint::deserialize` reads, the three SHA-256 digests that bind a run, and
//! the eight public output words.

mod common;
use common::sbpf_elf_builder::build_elf;
use common::sbpf_oracle as oracle;

use shrugg_zkvm::notes;
use shrugg_zkvm::sbpf::{self, asm, insn, lddw, Account, HostRef};
use sbpf_core::abi;
use sbpf_core::interp::Halt;
use sbpf_core::isa::opc;

const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

fn account(seed: u8, data_len: usize) -> Account {
    Account {
        key: [seed; 32],
        owner: [seed.wrapping_add(1); 32],
        lamports: 1_000 + u64::from(seed),
        data: (0..data_len).map(|i| (i as u8).wrapping_add(seed)).collect(),
        is_signer: seed % 2 == 0,
        is_writable: seed % 3 == 0,
        executable: false,
        rent_epoch: 0xffff_ffff_ffff_ffff,
    }
}

#[test]
fn serialize_aligned_matches_the_documented_offsets() {
    // Two accounts, the second a duplicate of the first, the first carrying 165 bytes of data (an
    // SPL Token account).
    let a = account(7, 165);
    let ix_data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let program_id = [0x42u8; 32];
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], &ix_data, &program_id);

    // `u64 n_accounts`.
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 2);

    // Account 0, not a duplicate: the 0xff marker, three flag bytes, four bytes of padding (the
    // `original_data_len` slot), the key, the owner, lamports, data_len, the data.
    assert_eq!(buf[8], 0xff);
    assert_eq!(buf[9], u8::from(a.is_signer));
    assert_eq!(buf[10], u8::from(a.is_writable));
    assert_eq!(buf[11], u8::from(a.executable));
    assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
    assert_eq!(&buf[16..48], &a.key);
    assert_eq!(&buf[48..80], &a.owner);
    assert_eq!(u64::from_le_bytes(buf[80..88].try_into().unwrap()), a.lamports);
    assert_eq!(u64::from_le_bytes(buf[88..96].try_into().unwrap()), 165);
    assert_eq!(&buf[96..96 + 165], &a.data[..]);

    // 10 240 bytes of realloc padding, then padding up to an 8-byte boundary (96 + 165 + 10 240 =
    // 10 501, so three bytes), then `u64 rent_epoch`.
    let after_data = 96 + 165;
    let after_realloc = after_data + MAX_PERMITTED_DATA_INCREASE;
    assert_eq!(after_realloc, 10_501);
    assert_eq!(&buf[after_data..after_realloc], &[0u8; MAX_PERMITTED_DATA_INCREASE][..]);
    assert_eq!(&buf[after_realloc..10_504], &[0, 0, 0]);
    assert_eq!(u64::from_le_bytes(buf[10_504..10_512].try_into().unwrap()), a.rent_epoch);

    // Account 1 is a duplicate of account 0: its index, then seven bytes of padding, and nothing
    // else at all.
    assert_eq!(buf[10_512], 0);
    assert_eq!(&buf[10_513..10_520], &[0u8; 7]);

    // Then `u64 data_len`, the instruction data, and the 32-byte program id.
    assert_eq!(u64::from_le_bytes(buf[10_520..10_528].try_into().unwrap()), 9);
    assert_eq!(&buf[10_528..10_537], &ix_data);
    assert_eq!(&buf[10_537..10_569], &program_id);
    assert_eq!(buf.len(), 10_569);

    // And the whole thing round-trips: a duplicate comes back as a copy of what it duplicates.
    let back = sbpf::deserialize_accounts(&buf);
    assert_eq!(back, vec![a.clone(), a]);
}

#[test]
fn serialize_aligned_round_trips_several_shapes() {
    // A zero-length account's data section is empty and its rent epoch is still 8-byte aligned;
    // an account whose data length is already a multiple of 8 needs no boundary padding at all.
    for lens in [vec![0usize], vec![8], vec![1, 7, 8, 9], vec![], vec![165, 82, 0]] {
        let accounts: Vec<Account> =
            lens.iter().enumerate().map(|(i, &n)| account(i as u8, n)).collect();
        let buf = sbpf::serialize_aligned(&accounts, b"ix", &[9u8; 32]);
        // Every account's `rent_epoch` lands on an 8-byte boundary, so the region up to the
        // instruction data is always a whole number of words.
        assert_eq!((buf.len() - 32 - 2) % 8, 0);
        assert_eq!(sbpf::deserialize_accounts(&buf), accounts);
    }
}

#[test]
fn output_hash_covers_lamports_and_data_of_every_account() {
    let mut h = HostRef;
    let a = account(1, 40);
    let b = account(2, 40);
    // `b` is not writable (seed 2 is not a multiple of 3) and must still be covered.
    assert!(!b.is_writable);
    let base = sbpf::serialize_aligned(&[a.clone(), b.clone()], b"ix", &[0u8; 32]);
    let h0 = abi::output_hash(&mut h, &base);

    // One data byte of the writable account changes the hash.
    let mut a2 = a.clone();
    a2.data[7] ^= 1;
    let buf = sbpf::serialize_aligned(&[a2, b.clone()], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // One data byte of the *non-writable* account changes it too.
    let mut b2 = b.clone();
    b2.data[0] ^= 1;
    let buf = sbpf::serialize_aligned(&[a.clone(), b2], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // So do lamports.
    let mut b3 = b.clone();
    b3.lamports += 1;
    let buf = sbpf::serialize_aligned(&[a.clone(), b3], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // The instruction data and the program id are *not* part of the output hash — they are the
    // input, bound by `input_hash` instead.
    let buf = sbpf::serialize_aligned(&[a.clone(), b.clone()], b"other", &[1u8; 32]);
    assert_eq!(abi::output_hash(&mut h, &buf), h0);

    // And it is exactly the documented preimage: per account in order, lamports and data_len as
    // eight little-endian bytes each, then the data.
    let mut msg = Vec::new();
    for acc in [&a, &b] {
        msg.extend_from_slice(&acc.lamports.to_le_bytes());
        msg.extend_from_slice(&(acc.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&acc.data);
    }
    assert_eq!(h0, shrugg_zkvm::sha256::sha256(&msg));

    // A duplicate account entry is hashed again, at the position it occupies.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &[0u8; 32]);
    let mut msg = Vec::new();
    for _ in 0..2 {
        msg.extend_from_slice(&a.lamports.to_le_bytes());
        msg.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&a.data);
    }
    assert_eq!(abi::output_hash(&mut h, &buf), shrugg_zkvm::sha256::sha256(&msg));

    // A region that is not a serialized instruction at all yields a digest rather than a panic:
    // the walk stops where the bytes run out. (Both the pre- and post-state hashes go through
    // this same walk, so a run over a malformed region still binds consistently.)
    for junk in [&[][..], &[0xff][..], &[7, 0, 0, 0, 0, 0, 0, 0][..], &[0xff; 200][..]] {
        let _ = abi::output_hash(&mut h, junk);
    }
}

#[test]
fn the_public_output_binds_the_input_and_the_post_state() {
    let mut h = HostRef;
    let input_hash = shrugg_zkvm::sha256::sha256(b"an input");
    let out_hash = shrugg_zkvm::sha256::sha256(b"a post-state");
    let out = abi::public_output(&mut h, 1, &input_hash, &out_hash);

    // `out0` is the status word; `out1..7` are words 0..6 of the domain-tagged Poseidon2 sponge
    // over the **16**-word preimage (M4.4's was 24: the `program_hash` group is gone, because the
    // ELF is in the public segment and `H_PUB` binds it), mirrored here with `notes::hash`.
    assert_eq!(out[0], 1);
    let mut msg = [0u32; 16];
    for (i, bytes) in [input_hash, out_hash].iter().enumerate() {
        for j in 0..8 {
            msg[8 * i + j] = u32::from_le_bytes(bytes[4 * j..4 * j + 4].try_into().unwrap());
        }
    }
    let d = notes::hash(notes::domain::SBPF_OUT, &msg);
    assert_eq!(&out[1..8], &d[..7]);
    assert_eq!(notes::domain::SBPF_OUT, 14);
    assert_eq!(abi::SBPF_OUT_DOMAIN, notes::domain::SBPF_OUT);

    // Both digests, and the status word, are bound: changing any one changes the output.
    assert_ne!(abi::public_output(&mut h, 0, &input_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 2, &input_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 1, &out_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 1, &input_hash, &input_hash), out);
    // And the two are not interchangeable: swapping them is a different preimage.
    assert_ne!(abi::public_output(&mut h, 1, &out_hash, &input_hash), out);
    // The status word is `out0` only: it does not enter the digest, so the low seven words of two
    // runs that differ only in status are the same.
    let zero = abi::public_output(&mut h, 0, &input_hash, &out_hash);
    assert_eq!(&zero[1..], &out[1..]);
}

#[test]
fn the_two_input_vectors_round_trip_through_their_cursors() {
    // Public `[n_elf, elf bytes…]` and private `[n_input, input bytes…]`, each byte string four per
    // word little-endian and zero-padded. The instruction is a real serialized region, because
    // `decode_input` refuses one that is not (`abi::check_region`).
    let region = sbpf::serialize_aligned(&[account(5, 3)], b"ix", &[7u8; 32]);
    let call = sbpf::SbpfCall { elf: (0..=250u8).collect(), input: region.clone() };
    let public = call.public_words();
    let private = call.input_words();
    assert_eq!(public[0], 251);
    assert_eq!(public[1], u32::from_le_bytes([0, 1, 2, 3]));
    assert_eq!(public.len(), 1 + 251usize.div_ceil(4));
    assert_eq!(private[0] as usize, region.len());
    assert_eq!(private.len(), 1 + region.len().div_ceil(4));

    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut pc = abi::InputCursor::new(|i| public[i as usize], public.len() as u32);
    let mut sc = abi::InputCursor::new(|i| private[i as usize], private.len() as u32);
    abi::decode_input(&mut ws.input, &mut pc, &mut sc).unwrap();
    assert_eq!(&ws.input.elf[..ws.input.elf_len], &call.elf[..]);
    assert_eq!(&ws.input.input[..ws.input.input_len], &call.input[..]);

    // A vector that ends before its layout does is a parse error, not a panic — and it is the same
    // error whichever of the two segments runs out.
    let mut pc = abi::InputCursor::new(|i| public[i as usize], 3);
    let mut sc = abi::InputCursor::new(|i| private[i as usize], private.len() as u32);
    assert_eq!(
        abi::decode_input(&mut ws.input, &mut pc, &mut sc),
        Err(abi::ParseError::Truncated)
    );
    let mut pc = abi::InputCursor::new(|i| public[i as usize], public.len() as u32);
    let mut sc = abi::InputCursor::new(|i| private[i as usize], 1);
    assert_eq!(
        abi::decode_input(&mut ws.input, &mut pc, &mut sc),
        Err(abi::ParseError::Truncated)
    );
    // A private vector that parses but is not a serialized instruction is refused too — the cursors
    // are only half of what makes a pair of vectors a call.
    let not_a_region = sbpf::SbpfCall { elf: call.elf.clone(), input: b"the input".to_vec() };
    let junk = not_a_region.input_words();
    let mut pc = abi::InputCursor::new(|i| public[i as usize], public.len() as u32);
    let mut sc = abi::InputCursor::new(|i| junk[i as usize], junk.len() as u32);
    assert_eq!(
        abi::decode_input(&mut ws.input, &mut pc, &mut sc),
        Err(abi::ParseError::MalformedRegion)
    );
    // An ELF or input length above its cap is refused without ever reading that many words.
    let big = [u32::MAX];
    let mut pc = abi::InputCursor::new(|i| big[i as usize], 1);
    let mut sc = abi::InputCursor::new(|i| private[i as usize], private.len() as u32);
    assert_eq!(
        abi::decode_input(&mut ws.input, &mut pc, &mut sc),
        Err(abi::ParseError::ElfTooLong)
    );
    let mut pc = abi::InputCursor::new(|i| public[i as usize], public.len() as u32);
    let mut sc = abi::InputCursor::new(|i| big[i as usize], 1);
    assert_eq!(
        abi::decode_input(&mut ws.input, &mut pc, &mut sc),
        Err(abi::ParseError::InputTooLong)
    );
}

#[test]
fn a_malformed_input_vector_is_status_two_with_a_canonical_digest() {
    let mut h = HostRef;
    let mut ws = Box::new(abi::Workspace::ZERO);
    let words = [7u32, 0];
    let z = [0u8; 32];
    // The canonical malformed output: status 2 over two all-zero digests, so a verifier that
    // recomputes the digest from the instruction it meant to run gets something else.
    let want = abi::public_output(&mut h, 2, &z, &z);
    // A public vector that ends mid-ELF…
    let out = abi::run_call(
        &mut h,
        &mut ws,
        |i| words[i as usize],
        words.len() as u32,
        |_| 0,
        1,
    );
    assert_eq!(out[0], 2);
    assert_eq!(out, want);
    // …and a private one that ends mid-instruction, which is the same non-call.
    let out = abi::run_call(&mut h, &mut ws, |_| 0, 1, |i| words[i as usize], words.len() as u32);
    assert_eq!(out, want);
}

/// The documented preimage, computed independently of `abi::output_hash`: per **entry** in the
/// order the region lists them (a duplicate entry contributing the account it duplicates),
/// lamports and data_len as eight little-endian bytes each, then the data.
fn expected_output_hash(entries: &[&Account]) -> [u8; 32] {
    let mut msg = Vec::new();
    for a in entries {
        msg.extend_from_slice(&a.lamports.to_le_bytes());
        msg.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&a.data);
    }
    shrugg_zkvm::sha256::sha256(&msg)
}

#[test]
fn output_hash_resolves_a_duplicate_against_the_full_entry_list() {
    // A duplicate's marker byte indexes **all** entries seen so far, duplicates included — the
    // index space `solana_program::entrypoint::deserialize` pushes into
    // (`accounts.push(accounts[dup_info].clone())` over a `Vec` that already holds duplicates).
    // Resolving it against the non-duplicate entries instead is silently wrong, and these two
    // shapes are what tell the two apart.
    let mut h = HostRef;
    let (a, b, c) = (account(1, 16), account(2, 24), account(3, 32));

    // `[A, A, B, B]`: the fourth entry's marker is 2. Against the full list that is `B`; against
    // the non-duplicate list there is no index 2 at all, so a walk over that index space runs out
    // and silently hashes a three-entry prefix.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone(), b.clone(), b.clone()], b"ix", &[0; 32]);
    assert_eq!(sbpf::deserialize_accounts(&buf), vec![a.clone(), a.clone(), b.clone(), b.clone()]);
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &b]));
    // And it is genuinely four entries, not the three-entry prefix the bug produced.
    assert_ne!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b]));

    // `[A, A, B, C, B]`: the fifth entry's marker is 2. Against the full list that is `B`; against
    // the non-duplicate list index 2 is `C` — the wrong account, hashed without any error.
    let buf = sbpf::serialize_aligned(
        &[a.clone(), a.clone(), b.clone(), c.clone(), b.clone()],
        b"ix",
        &[0; 32],
    );
    assert_eq!(
        sbpf::deserialize_accounts(&buf),
        vec![a.clone(), a.clone(), b.clone(), c.clone(), b.clone()]
    );
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &c, &b]));
    assert_ne!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &c, &c]));

    // A duplicate *of a duplicate* lands on the same account either way: `[A, A, A]`'s third entry
    // carries the byte 1, which is itself a duplicate entry.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone(), a.clone()], b"ix", &[0; 32]);
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &a]));

    // A marker pointing at an entry that does not exist yet (its own ordinal, or beyond) is not a
    // duplicate of anything: the walk stops rather than reading a slot it never filled.
    let mut buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &[0; 32]);
    let dup_at = buf.len() - 32 - 8 - 2 - 8;
    assert_eq!(buf[dup_at], 0, "the second entry's marker byte");
    buf[dup_at] = 1; // its own ordinal
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
    buf[dup_at] = 200;
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
}

/// `canonical_input_hash` drives the *same* walk `output_hash` does, so the two can never disagree
/// about which account a duplicate entry means — the failure mode that made the walk worth sharing.
/// Checked against the host twin, which resolves duplicates by cloning the deserialized account.
#[test]
fn canonical_input_hash_walks_duplicates_exactly_as_output_hash_does() {
    let mut h = HostRef;
    let (a, b, c) = (account(1, 16), account(2, 24), account(3, 32));
    let id = [0x42u8; 32];
    for shape in [
        vec![a.clone()],
        vec![a.clone(), a.clone()],
        vec![a.clone(), a.clone(), b.clone(), b.clone()],
        vec![a.clone(), a.clone(), b.clone(), c.clone(), b.clone()],
        vec![a.clone(), a.clone(), a.clone()],
    ] {
        let buf = sbpf::serialize_aligned(&shape, b"ix data", &id);
        assert_eq!(abi::program_id(&buf), id);
        assert_eq!(
            abi::canonical_input_hash(&mut h, &buf, &id),
            sbpf::canonical_input_hash_of(&buf),
            "{} entries",
            shape.len()
        );
        // The encoding really does re-encode a duplicate in full, at the position it occupies: its
        // length is the sum over *entries*, not over distinct accounts.
        let want: usize = 32
            + 8
            + shape.iter().map(|x| 1 + 32 + 32 + 8 + 8 + x.data.len() + 3 + 8).sum::<usize>()
            + 8
            + 7;
        assert_eq!(sbpf::canonical_preimage(&buf).len(), want);
    }

    // `rent_epoch` is in the preimage: a running program reads it through its `AccountInfo`, so a
    // prover must not be able to vary it under a digest the verifier still accepts. (This assertion
    // is the inverse of the one M4.4's first cut had, which pinned its *exclusion*.)
    let mut other = a.clone();
    other.rent_epoch = 7;
    let base = sbpf::serialize_aligned(&[a.clone()], b"ix data", &id);
    assert_ne!(a.rent_epoch, 7, "the fixture would not otherwise prove anything");
    assert_ne!(
        abi::canonical_input_hash(&mut h, &sbpf::serialize_aligned(&[other], b"ix data", &id), &id),
        abi::canonical_input_hash(&mut h, &base, &id),
    );
    let mut flagged = a.clone();
    flagged.is_writable = !a.is_writable;
    assert_ne!(
        abi::canonical_input_hash(
            &mut h,
            &sbpf::serialize_aligned(&[flagged], b"ix data", &id),
            &id
        ),
        abi::canonical_input_hash(&mut h, &base, &id),
    );
    // …and so are the instruction data and the program id, which `output_hash` deliberately omits.
    assert_ne!(
        abi::canonical_input_hash(
            &mut h,
            &sbpf::serialize_aligned(&[a.clone()], b"ix dat!", &id),
            &id
        ),
        abi::canonical_input_hash(&mut h, &base, &id),
    );
    assert_ne!(
        abi::canonical_input_hash(&mut h, &base, &[7u8; 32]),
        abi::canonical_input_hash(&mut h, &base, &id),
    );

    // A region that is not a serialized instruction yields a digest rather than a panic, exactly as
    // `output_hash` does, and an unparseable one has no program id to find.
    for junk in [&[][..], &[0xff][..], &[7, 0, 0, 0, 0, 0, 0, 0][..], &[0xff; 200][..]] {
        let _ = abi::canonical_input_hash(&mut h, junk, &abi::program_id(junk));
        assert_eq!(abi::program_id(junk), [0u8; 32]);
    }
}

/// Every byte of an accepted region is either in the canonical preimage or pinned to zero. The
/// bytes nothing hashes — the `original_data_len` slot, the 10 240-byte realloc headroom, the
/// alignment padding, a duplicate entry's seven padding bytes, anything past the program id — are
/// all inside the region `r1` points at, so a prover free to choose them could change what an
/// honest-looking run does while the verifier's recomputed `input_hash` still matched. The runtime
/// writes zeros there; the guest refuses anything else, and so does the host twin.
#[test]
fn a_region_with_a_non_zero_pinned_byte_is_refused_by_guest_and_host() {
    let a = account(5, 4);
    let id = [7u8; 32];
    let elf = build_elf(
        &asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );
    let base = sbpf::serialize_aligned(&[a.clone()], b"ix", &id);
    // The honest region is accepted, by both, and runs.
    assert_eq!(abi::check_region(&base), Ok(()));
    assert!(sbpf::try_canonical_preimage(&base).is_some());
    assert_eq!(run(&elf, &base).0[0], 1);

    // account 0's data ends at 8 (count) + 88 (header) + 4 (data).
    let data_end = 8 + 88 + a.data.len();
    let headroom_end = data_end + MAX_PERMITTED_DATA_INCREASE;
    let padded_end = (headroom_end + 7) & !7;
    assert!(padded_end > headroom_end, "the fixture must exercise alignment padding too");
    let dup = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &id);
    let dup_at = dup.len() - 32 - 2 - 8 - 8; // the second entry's marker byte

    for (what, region) in [
        ("the original_data_len slot", {
            let mut b = base.clone();
            b[12] = 1;
            b
        }),
        ("the first realloc headroom byte", {
            let mut b = base.clone();
            b[data_end] = 1;
            b
        }),
        ("the last realloc headroom byte", {
            let mut b = base.clone();
            b[headroom_end - 1] = 1;
            b
        }),
        ("the alignment padding", {
            let mut b = base.clone();
            b[padded_end - 1] = 1;
            b
        }),
        ("a duplicate entry's padding", {
            let mut b = dup.clone();
            assert_eq!(b[dup_at], 0, "the second entry's marker");
            b[dup_at + 3] = 1;
            b
        }),
        ("a flag byte above 1", {
            let mut b = base.clone();
            b[9] = 2; // is_signer
            b
        }),
        ("the executable flag above 1", {
            let mut b = base.clone();
            b[11] = 3;
            b
        }),
        ("a byte past the program id", {
            let mut b = base.clone();
            b.push(0);
            b
        }),
        ("a truncated tail", {
            let mut b = base.clone();
            b.truncate(b.len() - 1);
            b
        }),
    ] {
        assert_eq!(
            abi::check_region(&region),
            Err(abi::ParseError::MalformedRegion),
            "the guest must refuse {what}"
        );
        assert!(sbpf::try_canonical_preimage(&region).is_none(), "the host must refuse {what}");
        // And it is a status-2 call, not a run over a region nobody checked.
        let (out, result, _) = run(&elf, &region);
        assert_eq!(out[0], 2, "{what}");
        assert_eq!(result, Err(Halt::BadElf), "{what}");
        let z = [0u8; 32];
        assert_eq!(out, abi::public_output(&mut HostRef, 2, &z, &z), "{what}");
    }
}

/// The *shape* of the account list is bound, not just its contents: a duplicate entry aliases the
/// buffer it duplicates, a repeated full entry does not, and the program can tell the two apart. So
/// two regions whose accounts deserialize identically must still hash differently when their entry
/// markers differ — which is what hashing the raw marker byte per entry buys.
#[test]
fn a_duplicate_entry_and_a_repeated_full_entry_are_different_calls() {
    let mut h = HostRef;
    let a = account(5, 4);
    let id = [7u8; 32];
    // `serialize_aligned` deduplicates by key, so `[a, a]` is a full entry then a duplicate of it.
    let with_dup = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &id);
    // The same two accounts as two *full* entries: serialize them with distinct keys, then patch
    // the second entry's fields back so every account field matches the duplicate region's.
    let mut two_full = sbpf::serialize_aligned(&[a.clone(), account(6, 4)], b"ix", &id);
    let off1 = ((8 + 88 + a.data.len() + MAX_PERMITTED_DATA_INCREASE + 7) & !7) + 8;
    assert_eq!(two_full[off1], 0xff, "the second entry must be a full one");
    two_full[off1 + 8..off1 + 40].copy_from_slice(&a.key);
    two_full[off1 + 40..off1 + 72].copy_from_slice(&a.owner);
    two_full[off1 + 72..off1 + 80].copy_from_slice(&a.lamports.to_le_bytes());
    two_full[off1 + 88..off1 + 88 + a.data.len()].copy_from_slice(&a.data);
    two_full[off1 + 1] = u8::from(a.is_signer);
    two_full[off1 + 2] = u8::from(a.is_writable);
    two_full[off1 + 3] = u8::from(a.executable);

    // Both are canonical, and both deserialize to the same two accounts…
    assert_eq!(abi::check_region(&with_dup), Ok(()));
    assert_eq!(abi::check_region(&two_full), Ok(()));
    assert_eq!(
        sbpf::deserialize_accounts(&with_dup),
        sbpf::deserialize_accounts(&two_full),
        "the fixture only proves something if the account fields match"
    );
    // …but they are not the same call, on the guest or on the host.
    assert_ne!(
        abi::canonical_input_hash(&mut h, &with_dup, &id),
        abi::canonical_input_hash(&mut h, &two_full, &id),
    );
    assert_ne!(
        sbpf::canonical_input_hash_of(&with_dup),
        sbpf::canonical_input_hash_of(&two_full),
    );
    // The markers are what differ, and the host twin reports them.
    let markers = |r: &[u8]| {
        sbpf::try_deserialize_entries(r).unwrap().iter().map(|(m, _)| *m).collect::<Vec<u8>>()
    };
    assert_eq!(markers(&with_dup), vec![0xff, 0]);
    assert_eq!(markers(&two_full), vec![0xff, 0xff]);

    // And a duplicate *of a duplicate* is a third shape: `serialize_aligned` points every duplicate
    // at the first entry with that key, so `[A, A, A]`'s last marker is 0; pointing it at entry 1
    // instead resolves to the same account through a different chain, and is not the same region.
    let mut chain = sbpf::serialize_aligned(&[a.clone(), a.clone(), a.clone()], b"ix", &id);
    let last = chain.len() - 32 - 2 - 8 - 8;
    assert_eq!(chain[last], 0, "the third entry duplicates the first");
    let via_first = abi::canonical_input_hash(&mut h, &chain, &id);
    assert_eq!(via_first, sbpf::canonical_input_hash_of(&chain));
    chain[last] = 1;
    assert_eq!(abi::check_region(&chain), Ok(()));
    let via_second = abi::canonical_input_hash(&mut h, &chain, &id);
    assert_eq!(sbpf::deserialize_accounts(&chain), vec![a.clone(), a.clone(), a.clone()]);
    assert_ne!(via_first, via_second);
    assert_eq!(via_second, sbpf::canonical_input_hash_of(&chain));
}

/// An account count above `MAX_ACCOUNTS` is refused, never clamped: clamping made a region claiming
/// 64 and one claiming 2^40 hash identically, because the preimage carried the clamped number.
#[test]
fn an_account_count_above_the_maximum_is_refused_rather_than_clamped() {
    let a = account(5, 4);
    let id = [7u8; 32];
    let elf = build_elf(
        &asm(&[insn(opc::MOV64_IMM, 0, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );
    // 64 entries that fit the input cap: one real account and 63 duplicates of it, 8 bytes each.
    let shape: Vec<Account> = core::iter::repeat(a.clone()).take(abi::MAX_ACCOUNTS).collect();
    let mut buf = sbpf::serialize_aligned(&shape, b"ix", &id);
    assert!(buf.len() <= abi::MAX_INPUT_BYTES, "{} bytes", buf.len());
    // Exactly `MAX_ACCOUNTS` is fine, at the boundary.
    assert_eq!(abi::check_region(&buf), Ok(()));
    assert_eq!(sbpf::try_deserialize_accounts(&buf).map(|v| v.len()), Some(abi::MAX_ACCOUNTS));
    assert_eq!(run(&elf, &buf).0[0], 1);

    for claimed in [abi::MAX_ACCOUNTS as u64 + 1, 1 << 40, u64::MAX] {
        buf[0..8].copy_from_slice(&claimed.to_le_bytes());
        assert_eq!(abi::check_region(&buf), Err(abi::ParseError::MalformedRegion));
        assert!(sbpf::try_deserialize_accounts(&buf).is_none());
        assert!(sbpf::try_canonical_preimage(&buf).is_none());
        assert_eq!(run(&elf, &buf).0[0], 2, "claimed {claimed}");
    }
}

#[test]
fn output_hash_refuses_an_account_count_that_would_truncate() {
    // A count above `u32::MAX` must not be narrowed into a small, plausible-looking number on the
    // 32-bit target: it is clamped in `u64`, so the walk simply runs out of region.
    let mut h = HostRef;
    let a = account(1, 8);
    let mut buf = sbpf::serialize_aligned(&[a.clone()], b"ix", &[0; 32]);
    buf[0..8].copy_from_slice(&(u64::from(u32::MAX) + 2).to_le_bytes());
    // The one real entry is hashed, then the region runs out — never a panic, and never a walk
    // that believed there was exactly one account because the count truncated to 1.
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
    buf[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
}

// ---- the whole call: `run_call_with` over a hand-built ELF ------------------------------------

/// The offset of account 0's `lamports` in a serialized region: the count, then the marker, three
/// flag bytes, the `original_data_len` slot, the key and the owner.
const LAMPORTS_AT: i16 = 8 + 8 + 32 + 32;

/// A program that stores `lamports` into account 0 and then does `tail`.
fn lamports_writer(lamports: u64, tail: &[[u8; 8]]) -> Vec<u8> {
    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, lamports));
    p.push(insn(opc::ST_DW_REG, 1, 2, LAMPORTS_AT, 0)); // r1 is the input region's base
    p.extend_from_slice(tail);
    asm(&p)
}

/// Runs one whole call the way the guest will: the input vector through `abi::run_call_with`.
fn run(elf: &[u8], input: &[u8]) -> ([u32; 8], Result<u64, Halt>, Vec<u8>) {
    let call = sbpf::SbpfCall { elf: elf.to_vec(), input: input.to_vec() };
    let public = call.public_words();
    let private = call.input_words();
    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut h = HostRef;
    let (out, result) = abi::run_call_with(
        &mut h,
        &mut ws,
        |i| public[i as usize],
        public.len() as u32,
        |i| private[i as usize],
        private.len() as u32,
    );
    (out, result, ws.input.input[..ws.input.input_len].to_vec())
}

#[test]
fn a_successful_run_publishes_status_one_and_the_post_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Ok(0));
    assert_eq!(out[0], 1, "r0 == 0 is status 1");

    // The mutation is real and readable back out of the workspace.
    let post_accounts = sbpf::deserialize_accounts(&post);
    assert_eq!(post_accounts[0].lamports, 999);
    assert_ne!(a.lamports, 999, "the fixture would not otherwise prove anything");
    // Everything but the lamports word is untouched.
    let mut expected_post = a.clone();
    expected_post.lamports = 999;
    assert_eq!(post_accounts, vec![expected_post.clone()]);

    // And the digest is over the POST-state, which is not the pre-state.
    let pre_hash = abi::output_hash(&mut h, &input);
    let post_hash = abi::output_hash(&mut h, &post);
    assert_ne!(post_hash, pre_hash);
    assert_eq!(post_hash, expected_output_hash(&[&expected_post]));
    assert_eq!(
        out,
        abi::public_output(&mut h, 1, &sbpf::canonical_input_hash_of(&input), &post_hash)
    );
}

#[test]
fn a_nonzero_return_publishes_status_zero_over_the_pre_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    // Mutates the account, *then* returns a `ProgramError`: the effect must not be published.
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 42), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Ok(42));
    assert_eq!(out[0], 0, "a non-zero r0 is status 0");
    // The run really did change the region — the rule is about what is *bound*, not about undoing.
    assert_eq!(sbpf::deserialize_accounts(&post)[0].lamports, 999);
    let pre_hash = abi::output_hash(&mut h, &input);
    assert_eq!(
        out,
        abi::public_output(
            &mut h,
            0,
            &sbpf::canonical_input_hash_of(&input),
            &pre_hash, // the PRE-state
        )
    );
    // The error code itself is not published (the seven digest words are spoken for), so two
    // different non-zero returns are indistinguishable in the output.
    let other = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 43), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );
    let (out_other, result_other, _) = run(&other, &input);
    assert_eq!(result_other, Ok(43));
    // And since the ELF left the digest's preimage, two *different programs* over the same
    // instruction publish the same eight words when both fail: what distinguishes them is `H_PUB`
    // over the public segment, which the chain checks against the ELF it published — not anything
    // the guest computes.
    assert_eq!(out_other, out);
}

#[test]
fn an_exceptional_halt_publishes_status_two_over_the_pre_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    // Mutates the account and *then* halts — a load through r0, which is zero, so address 0. This
    // is the rule that stops a partial effect being published: whatever the program managed to do
    // before it died, the digest says nothing happened.
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::LD_DW_REG, 3, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Err(Halt::AccessViolation(0)));
    assert_eq!(out[0], 2, "an exceptional halt is status 2");
    assert_eq!(sbpf::deserialize_accounts(&post)[0].lamports, 999, "the write did happen");
    let pre_hash = abi::output_hash(&mut h, &input);
    let want = abi::public_output(
        &mut h,
        2,
        &sbpf::canonical_input_hash_of(&input),
        &pre_hash, // the PRE-state, not the mutated region
    );
    assert_eq!(out, want);

    // An ELF that does not load at all is status 2 the same way, over the same pre-state — and now
    // that the ELF is not in the preimage, byte-identically so.
    let mut broken = elf.clone();
    broken[18] = 0xff; // e_machine
    let (out, result, _) = run(&broken, &input);
    assert_eq!(result, Err(Halt::BadElf));
    assert_eq!(out[0], 2);
    assert_eq!(out, want);
}

#[test]
fn the_run_starts_at_the_elf_entrypoint_and_sees_the_whole_input_region() {
    // The guest's `r1` is the input region's base and the region is exactly `input_len` bytes: a
    // program that reads the last byte succeeds and one that reads the next byte halts.
    let a = account(5, 4);
    let input = sbpf::serialize_aligned(&[a], b"ix", &[7u8; 32]);
    let last = (input.len() - 1) as u64;

    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, last));
    p.push(insn(opc::ADD64_REG, 1, 2, 0, 0));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let (out, result, _) = run(&build_elf(&asm(&p), &[], &[], &[], 0), &input);
    assert_eq!(result, Ok(0));
    assert_eq!(out[0], 1);

    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, last + 1));
    p.push(insn(opc::ADD64_REG, 1, 2, 0, 0));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let (out, result, _) = run(&build_elf(&asm(&p), &[], &[], &[], 0), &input);
    assert!(matches!(result, Err(Halt::AccessViolation(_))), "{result:?}");
    assert_eq!(out[0], 2);

    // A non-zero entrypoint is honoured: two separate two-slot routines, each with its own `exit`,
    // so entering at slot 0 cannot fall through into the one at slot 2.
    let text = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::EXIT, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 0), &input).1, Ok(1));
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 2), &input).1, Ok(0));
    // And the status word follows: a non-zero `r0` is status 0, a zero one status 1.
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 0), &input).0[0], 0);
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 2), &input).0[0], 1);
}

#[test]
fn a_workspace_can_be_reused_without_carrying_state_over() {
    // The guest holds one `Workspace` in `.bss`; a host test that runs two calls through one must
    // get the same answers as two fresh ones, or the stack/heap zeroing is not doing its job.
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a], b"ix", &[7u8; 32]);
    // Reads a stack slot it never wrote, so a workspace carrying a previous run's frame would
    // answer differently.
    let leaky = build_elf(
        &asm(&[
            insn(opc::LD_DW_REG, 0, 10, -8, 0),
            insn(opc::EXIT, 0, 0, 0, 0),
        ]),
        &[],
        &[],
        &[],
        0,
    );
    let writer = build_elf(
        &asm(&[
            insn(opc::MOV64_IMM, 2, 0, 0, 0x5eed),
            insn(opc::ST_DW_REG, 10, 2, -8, 0),
            insn(opc::MOV64_IMM, 0, 0, 0, 0),
            insn(opc::EXIT, 0, 0, 0, 0),
        ]),
        &[],
        &[],
        &[],
        0,
    );

    let fresh = run(&leaky, &input);
    assert_eq!(fresh.1, Ok(0), "an unwritten stack slot reads as zero");

    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut h = HostRef;
    for elf in [&writer, &leaky] {
        let call = sbpf::SbpfCall { elf: elf.clone(), input: input.clone() };
        let public = call.public_words();
        let private = call.input_words();
        let (out, result) = abi::run_call_with(
            &mut h,
            &mut ws,
            |i| public[i as usize],
            public.len() as u32,
            |i| private[i as usize],
            private.len() as u32,
        );
        if elf == &leaky {
            assert_eq!(result, Ok(0), "the previous run's frame did not leak into this one");
            assert_eq!(out, fresh.0);
        }
    }
}

/// The exit-test fixture, run natively before anything is proved: the committed SPL Token ELF
/// really does execute a `Transfer` under `sbpf-core`, the balances move, and the eight public
/// output words are the documented function of the pre- and post-state. This is also where the
/// numbers the M4.4 plan asks Task 6 to *measure* rather than assume come from — the sBPF
/// instruction count and the frame-depth high-water mark against the 8 × 4 KiB stack.
#[test]
fn the_spl_token_transfer_fixture_runs_natively() {
    use shrugg_zkvm::sbpf::{
        deserialize_accounts, deserialize_instruction, spl_transfer, SPL_TOKEN_ELF, SPL_TOKEN_ID,
        SPL_TRANSFER_DEST_BALANCE, SPL_TRANSFER_SOURCE_BALANCE, TOKEN_AMOUNT_AT, TRANSFER_TAG,
    };
    let amount = 250u64;
    let call = spl_transfer(amount);
    assert_eq!(call.elf, SPL_TOKEN_ELF);
    assert!(call.input.len() <= abi::MAX_INPUT_BYTES, "{} bytes", call.input.len());

    // The region really is the instruction it claims to be.
    let (data, id) = deserialize_instruction(&call.input);
    assert_eq!(id, SPL_TOKEN_ID);
    assert_eq!(data[0], TRANSFER_TAG);
    assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), amount);
    let pre = deserialize_accounts(&call.input);
    assert_eq!(pre.len(), 4);
    assert!(pre[0].is_writable && pre[1].is_writable && pre[2].is_signer && !pre[3].is_writable);

    let (out, r0, post) = call.expected();
    assert_eq!(r0, Ok(0), "the transfer must succeed");
    assert_eq!(out[0], 1, "status 1");

    // The only thing that changed is the two balances.
    let bal = |a: &Account| u64::from_le_bytes(a.data[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].try_into().unwrap());
    assert_eq!(bal(&pre[0]), SPL_TRANSFER_SOURCE_BALANCE);
    assert_eq!(bal(&pre[1]), SPL_TRANSFER_DEST_BALANCE);
    assert_eq!(bal(&post[0]), SPL_TRANSFER_SOURCE_BALANCE - amount);
    assert_eq!(bal(&post[1]), SPL_TRANSFER_DEST_BALANCE + amount);
    for i in 0..4 {
        assert_eq!(post[i].lamports, pre[i].lamports, "account {i}'s lamports must not move");
        assert_eq!(post[i].key, pre[i].key);
        assert_eq!(post[i].owner, pre[i].owner);
        assert_eq!(post[i].data.len(), pre[i].data.len());
        if i >= 2 {
            assert_eq!(post[i].data, pre[i].data, "account {i} is not written by Transfer");
        }
    }
    // Everything but the amounts is byte-identical in the two token accounts too.
    for i in 0..2 {
        let (mut a, mut b) = (pre[i].data.clone(), post[i].data.clone());
        a[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].fill(0);
        b[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].fill(0);
        assert_eq!(a, b, "account {i}: something other than the amount changed");
    }

    // The eight output words are the documented function of the digests, recomputed here from the
    // post-state region rather than taken from the run.
    // The post-state region is the post accounts re-serialized: the same bytes the run left behind.
    let mut h = HostRef;
    let post_region = sbpf::serialize_aligned(&post, &data, &id);
    assert_eq!(post_region, call.input_post_state(), "the run left exactly these bytes");
    // `input_hash` is the canonical unpadded encoding, built here from the deserialized accounts
    // rather than by `sbpf-core`'s walk; `output_hash` is over the post-state region.
    let input_hash = sbpf::canonical_input_hash_of(&call.input);
    assert_eq!(input_hash, abi::canonical_input_hash(&mut h, &call.input, &SPL_TOKEN_ID));
    assert_eq!(abi::program_id(&call.input), SPL_TOKEN_ID);
    let out_hash = abi::output_hash(&mut h, &post_region);
    let want = abi::public_output(&mut h, 1, &input_hash, &out_hash);
    assert_eq!(out, want);
    assert_ne!(out[1..], [0u32; 7], "the digest words must not be zero");

    // ---- the differential: `solana-sbpf` 0.11.1 on the same ELF and the same region -----------
    //
    // The whole run, not a hand-built program: 143 instructions is a surprisingly small number for
    // a full SPL Token transfer (the release build inlines `deserialize`, `Processor::process` and
    // `process_transfer` into one frame), so "it produced the right balances" is checked against
    // the reference interpreter rather than against this crate's own idea of the semantics.
    let (their_r0, their_region) = oracle::run_elf(SPL_TOKEN_ELF, &call.input);
    assert_eq!(their_r0, Ok(0), "solana-sbpf must run the transfer too");
    assert_eq!(
        their_region.len(),
        post_region.len(),
        "the oracle's input region changed length"
    );
    assert_eq!(their_region, post_region, "the two interpreters left different bytes behind");

    // Measured, for `docs/04-guests.md` and the task report.
    let o = sbpf::run_elf(&mut call.elf.clone(), &mut call.input.clone());
    assert_eq!(o.result, Ok(0));
    assert!(
        o.max_depth < sbpf_core::memory::MAX_CALL_DEPTH,
        "frame high-water {} against MAX_CALL_DEPTH {}",
        o.max_depth,
        sbpf_core::memory::MAX_CALL_DEPTH
    );
    eprintln!(
        "spl transfer (native): input {} bytes, {} sBPF instructions, frame high-water {} of {} ({} B frames)",
        call.input.len(),
        o.instructions,
        o.max_depth,
        sbpf_core::memory::MAX_CALL_DEPTH,
        sbpf_core::memory::STACK_FRAME,
    );
}

/// The same fixture with an amount above the source's balance: `TokenError::InsufficientFunds`, a
/// non-zero `r0`, status 0, and the **pre**-state bound as the post-state — nothing moved.
#[test]
fn an_spl_token_transfer_of_too_much_changes_nothing() {
    use shrugg_zkvm::sbpf::{deserialize_accounts, spl_transfer};
    let call = spl_transfer(u64::MAX / 2);
    let (out, r0, post) = call.expected();
    // The same answer from `solana-sbpf`, including that the region is untouched.
    let (their_r0, their_region) =
        oracle::run_elf(shrugg_zkvm::sbpf::SPL_TOKEN_ELF, &call.input);
    assert_eq!(their_r0.map(|c| c != 0), Ok(true), "solana-sbpf must also return non-zero");
    assert_eq!(their_region, call.input, "a failed transfer must leave the region alone");
    match r0 {
        Ok(code) => assert_ne!(code, 0, "InsufficientFunds is a non-zero return, not a fault"),
        Err(e) => panic!("the program must return cleanly, not halt: {e:?}"),
    }
    assert_eq!(out[0], 0, "status 0");
    assert_eq!(post, deserialize_accounts(&call.input), "nothing may have moved");

    // And the digest really is the pre-state's: the same eight words a *zero*-amount-effect run
    // would publish, but with status 0 rather than 1 — which is what makes the failure legible.
    let ok = spl_transfer(0);
    assert_ne!(ok.expected().0, out);
}

/// The canonical input encoding, field by field, against a hand-built expectation — and the
/// measurement that justifies it: the aligned region's 98 % realloc padding is gone.
#[test]
fn canonical_input_hash_is_the_unpadded_encoding_and_is_two_orders_smaller() {
    use shrugg_zkvm::sbpf::{
        call_instruction_data_len, canonical_preimage, deserialize_accounts, spl_transfer,
        SPL_TOKEN_ID,
    };
    let call = spl_transfer(250);
    let pre = canonical_preimage(&call.input);
    // program id, u64 n_accounts, then per entry marker‖key‖owner‖lamports‖data_len‖data‖3 flag
    // bytes‖rent_epoch, then u64 instruction_data_len ‖ instruction data.
    assert_eq!(&pre[..32], &SPL_TOKEN_ID[..]);
    let accounts = deserialize_accounts(&call.input);
    assert_eq!(u64::from_le_bytes(pre[32..40].try_into().unwrap()), accounts.len() as u64);
    let want: usize = 32
        + 8
        + accounts.iter().map(|a| 1 + 32 + 32 + 8 + 8 + a.data.len() + 3 + 8).sum::<usize>()
        + 8
        + call_instruction_data_len(&call.input);
    assert_eq!(pre.len(), want);
    // The number this change exists for: 41 825 aligned bytes -> under a kilobyte.
    assert!(pre.len() < 1_024, "canonical preimage is {} bytes", pre.len());
    assert!(pre.len().div_ceil(64) + 1 <= 16, "at most ~14 compressions, was 654");
}

/// Two segments: the ELF is read with `read_public`, the instruction with `read_input`, and the
/// guest's eight output words are the digest over the *two* hashes, not three.
#[test]
fn the_sbpf_abi_reads_the_elf_from_the_public_segment() {
    use shrugg_zkvm::sbpf::spl_transfer;
    let call = spl_transfer(250);
    let public = call.public_words();
    let private = call.input_words();
    assert_eq!(public[0] as usize, call.elf.len());
    assert_eq!(private[0] as usize, call.input.len());
    assert!(
        private.len() < 12_000,
        "the ELF is no longer on the private tape: {} words",
        private.len()
    );
    let (out, r0, _post) = call.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(out[0], 1);
    // out1..7 is hash(SBPF_OUT, [input_hash ‖ output_hash]) — 16 words, not 24.
    let mut h = shrugg_zkvm::sbpf::HostRef;
    let want = sbpf_core::abi::public_output(
        &mut h,
        1,
        &shrugg_zkvm::sbpf::canonical_input_hash_of(&call.input),
        &shrugg_zkvm::sbpf::output_hash_of(&call.input_post_state()),
    );
    assert_eq!(out, want);
}
