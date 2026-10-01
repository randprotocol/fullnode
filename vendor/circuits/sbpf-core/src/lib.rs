//! `sbpf-core`: the SBPF interpreter the Rand zkVM's Solana guest runs, as a `no_std` library with
//! no allocation outside a fixed heap array, generic over a [`Host`] for the two things a guest
//! cannot compute itself — the SHA-256 compression function and the Poseidon2 sponge. On the
//! target both are syscalls (`guest_sdk::sha256_compress`, `guest_sdk::poseidon2`); on the host
//! they are the research crate's own reference functions (`sha256::compress`, `hash::sponge_hash`),
//! so every opcode, the memory regions, the syscalls and the ELF loader are unit-tested natively
//! and differentially against `solana-sbpf` 0.11.1, and the guest binary is a thin wrapper over
//! the same code (`docs/superpowers/plans/2026-09-12-zkvm-m4-4.md`, Task 5).
//!
//! # Which "v1"?
//!
//! The M4.4 plan's "SBPF v1" is the encoding a non-upgradeable BPFLoader2 program (SPL Token) is
//! built for: **fixed** stack frames, `lddw`, `le`/`be`, `neg`, and no `BPF_PQR` class. In
//! `solana-sbpf` 0.11.1's own enum that is `SBPFVersion::V0` — its `V1` is SIMD-0166's *dynamic*
//! stack frames, which came later. Everything here implements the plan's v1 = the crate's V0, and
//! `research/tests/common/sbpf_oracle.rs`'s `config()` pins the oracle to the same machine.
//!
//! # No panics on guest input
//!
//! Every length, offset and pointer this crate handles comes from the prover: the ELF bytes, the
//! serialized instruction, and every register the program computes. A panicking guest aborts
//! without producing a proof at all, so nothing here indexes a slice without a bounds check —
//! every violation is a [`interp::Halt`], which [`abi::run_call`] turns into status 2.

#![no_std]
#![forbid(unsafe_code)]

pub mod abi;
pub mod elf;
pub mod interp;
pub mod isa;
pub mod memory;
pub mod syscalls;

/// The two things a guest cannot compute itself. Both operate in place on 32-bit words.
pub trait Host {
    /// One SHA-256 compression of the 24-word `SYS_SHA256` argument: words `0..16` are the 512-bit
    /// message block as sixteen big-endian-*valued* words, words `16..24` the chaining state `H`.
    /// `H ← H + f(H, W)` is written back over words `16..24`; the block is left untouched.
    fn sha256_compress(&mut self, words: &mut [u32; 24]);
    /// The Poseidon2 sponge over `words[..n]`, digest written to `words[..8]` (`POSEIDON2` syscall
    /// semantics).
    fn poseidon2(&mut self, words: &mut [u32], n: usize);
}

/// SHA-256's initial hash value `H(0)` (FIPS 180-4 §5.3.3).
pub const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 (FIPS 180-4) as a Merkle–Damgård loop over the host's compression: the padding and the
/// chaining are this crate's, the compression is the host's. Byte-identical to `guest_sdk::sha256`
/// and to research's `sha256::sha256`.
///
/// Streaming, because two of its callers hash something they cannot hold: `sol_sha256` hashes the
/// concatenation of a program-chosen list of scattered slices, and
/// [`abi::output_hash`](crate::abi::output_hash) hashes every account's lamports, length and data
/// in turn. One 24-word buffer serves the whole message — words `16..24` hold the running state
/// across calls, words `0..16` are overwritten with each block — and one 64-byte block buffer
/// holds the partial tail, so the whole hasher is 160 bytes however long the message is.
pub struct Sha256 {
    /// `0..16` the current block as big-endian words, `16..24` the chaining state.
    buf: [u32; 24],
    /// The bytes of the block not yet compressed.
    block: [u8; 64],
    fill: usize,
    /// Total message bytes absorbed, for the length suffix.
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        let mut buf = [0u32; 24];
        let mut i = 0;
        while i < 8 {
            buf[16 + i] = SHA256_IV[i];
            i += 1;
        }
        Sha256 { buf, block: [0; 64], fill: 0, len: 0 }
    }

    /// Absorbs `bytes`, compressing every whole block it completes.
    ///
    /// A block that is already aligned in `bytes` is packed **straight out of the caller's slice**
    /// rather than copied into `self.block` first. That is not a micro-optimisation: on
    /// `riscv32im-unknown-none-elf` the copy goes through `compiler_builtins::mem::memcpy`, whose
    /// byte-at-a-time loop measured **9.5 cycles per byte** — 1.45 M of the SPL Token exit test's
    /// first 3.85 M cycles, 38 % of the whole run, to move bytes that are then read once
    /// (`docs/04-guests.md`). The partial-block path below is unchanged and still the one
    /// `sol_sha256` and `output_hash` take for their short, scattered pieces.
    pub fn update<H: Host>(&mut self, h: &mut H, bytes: &[u8]) {
        self.len = self.len.wrapping_add(bytes.len() as u64);
        let mut off = 0;
        // Fill out a partial block first, so the fast path below always starts block-aligned.
        if self.fill != 0 {
            let take = core::cmp::min(64 - self.fill, bytes.len());
            self.block[self.fill..self.fill + take].copy_from_slice(&bytes[..take]);
            self.fill += take;
            off = take;
            if self.fill == 64 {
                self.compress(h);
                self.fill = 0;
            }
        }
        // Whole blocks, packed from `bytes` with no intermediate copy. The `else { break }` is what
        // makes the impossible branch total rather than silent: `pack` must never be skipped while
        // the compression still runs, or a block would be hashed twice and the digest would be
        // quietly wrong. (This crate cannot `unwrap`: a panicking guest produces no proof at all.)
        while off + 64 <= bytes.len() {
            let Ok(block) = <&[u8; 64]>::try_from(&bytes[off..off + 64]) else { break };
            self.pack(block);
            h.sha256_compress(&mut self.buf);
            off += 64;
        }
        // The tail, which stays in `self.block` until a later `update` or `finish` completes it.
        let rest = bytes.len() - off;
        if rest != 0 {
            self.block[..rest].copy_from_slice(&bytes[off..]);
            self.fill = rest;
        }
    }

    /// Pads (`0x80`, zeros, the big-endian bit length) and returns the digest, big-endian.
    pub fn finish<H: Host>(mut self, h: &mut H) -> [u8; 32] {
        let rest = self.fill;
        self.block[rest..].fill(0);
        self.block[rest] = 0x80;
        if rest >= 56 {
            self.compress(h);
            self.block.fill(0);
        }
        let bits = self.len.wrapping_mul(8);
        self.block[56..].copy_from_slice(&bits.to_be_bytes());
        self.compress(h);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.buf[16 + i].to_be_bytes());
        }
        out
    }

    /// Packs a 64-byte block into `buf[0..16]` big-endian — the word order `SYS_SHA256` reads them
    /// in. Takes the block as a fixed-size **array** reference rather than a slice so both index
    /// bounds are static: with a `&[u8]` the compiler cannot fold the 64 byte-index checks or the 16
    /// writes to `buf`, and on RV32 (where `-unaligned-scalar-mem` is off, so every word comes from
    /// four `lbu`s) those checks are most of the instruction count. [`Sha256::update`] hands the
    /// caller's own bytes straight in.
    fn pack(&mut self, block: &[u8; 64]) {
        for i in 0..16 {
            self.buf[i] =
                u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
    }

    /// Packs `self.block` and compresses in place.
    fn compress<H: Host>(&mut self, h: &mut H) {
        let block = self.block;
        self.pack(&block);
        h.sha256_compress(&mut self.buf);
    }
}

/// `sha256(msg)` in one call.
pub fn sha256<H: Host>(h: &mut H, msg: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(h, msg);
    s.finish(h)
}

/// `word[i] = LE(bytes[4i..4i+4])` — how a 32-byte SHA-256 digest enters a sponge message, the
/// packing M4.3's `evm-core` uses for a Keccak digest.
pub fn hash_words(h: &[u8; 32]) -> [u32; 8] {
    [
        u32::from_le_bytes([h[0], h[1], h[2], h[3]]),
        u32::from_le_bytes([h[4], h[5], h[6], h[7]]),
        u32::from_le_bytes([h[8], h[9], h[10], h[11]]),
        u32::from_le_bytes([h[12], h[13], h[14], h[15]]),
        u32::from_le_bytes([h[16], h[17], h[18], h[19]]),
        u32::from_le_bytes([h[20], h[21], h[22], h[23]]),
        u32::from_le_bytes([h[24], h[25], h[26], h[27]]),
        u32::from_le_bytes([h[28], h[29], h[30], h[31]]),
    ]
}

/// The longest `dhash` message this crate hashes: the 24-word public-output preimage plus its
/// domain word.
const DHASH_MAX_WORDS: usize = 32;

/// `hash(domain, msg) = poseidon2([domain, msg…])` — the domain-tagged sponge, byte-identical to
/// research's `notes::hash`. `1 + msg.len()` must be at most [`DHASH_MAX_WORDS`]; a longer message
/// is truncated rather than panicking, which no call site here can reach (the one caller passes a
/// fixed 24-word array).
pub fn dhash<H: Host>(h: &mut H, domain: u32, msg: &[u32]) -> [u32; 8] {
    let n = if 1 + msg.len() > DHASH_MAX_WORDS { DHASH_MAX_WORDS } else { 1 + msg.len() };
    debug_assert_eq!(n, 1 + msg.len());
    let mut buf = [0u32; DHASH_MAX_WORDS];
    buf[0] = domain;
    buf[1..n].copy_from_slice(&msg[..n - 1]);
    h.poseidon2(&mut buf, n);
    let mut out = [0u32; 8];
    out.copy_from_slice(&buf[..8]);
    out
}
