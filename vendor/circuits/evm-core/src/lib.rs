//! `evm-core`: the EVM interpreter the Rand zkVM's EVM guest runs, as a `no_std` library with no
//! allocation, generic over a [`Host`] for the two things a guest cannot compute itself — the
//! Keccak-f[1600] permutation and the Poseidon2 sponge. On the target both are syscalls
//! (`guest_sdk::keccak`, `guest_sdk::poseidon2`); on the host they are the research crate's own
//! reference functions (`keccak::keccak_f`, `hash::sponge_hash`), so every opcode, the 256-bit
//! arithmetic and the storage tree are unit-tested natively and the guest binary is a thin
//! wrapper over the same code (`docs/superpowers/plans/2026-09-12-zkvm-m4-3.md`).

#![no_std]

pub mod abi;
pub mod interp;
pub mod storage;
pub mod u256;

/// The two things a guest cannot compute itself. Both operate in place on 32-bit words.
pub trait Host {
    /// One Keccak-f[1600] permutation of the 50-word state (lane i: low word 2i, high word 2i+1).
    fn keccak_f(&mut self, state: &mut [u32; 50]);
    /// The Poseidon2 sponge over `words[..n]`, digest written to `words[..8]` (POSEIDON2 syscall
    /// semantics).
    fn poseidon2(&mut self, words: &mut [u32], n: usize);
}

/// The rate of Keccak-256 in bytes: 136, the low 34 words of the 50-word state.
const KECCAK_RATE: usize = 136;

/// keccak256 over the host's permutation: rate 136, pad `0x01`…`0x80`, little-endian lanes.
/// Byte-identical to `guest_sdk::keccak256` (M4.2) and to research's `keccak::keccak256` — the
/// padding and absorption are this function's, the permutation is the host's.
///
/// A message whose length is an exact multiple of 136 (zero included) still needs a whole extra
/// all-padding block; the loop gets that from `take == 0` on its final pass, since `last` is set
/// by `take < 136` rather than by exhausting the message.
pub fn keccak256<H: Host>(h: &mut H, msg: &[u8]) -> [u8; 32] {
    let mut state = [0u32; 50];
    let mut off = 0;
    // Full blocks are absorbed straight out of `msg`. Staging every block in a 136-byte buffer
    // first — zero it, copy into it, then read it back word by word — cost two `memcpy`-class
    // passes per block for nothing: only the *last* block, which carries the padding, needs a
    // buffer of its own. Hashing the ERC-20's 1 296 bytes of code for `codehash` is ten blocks, and
    // this is ~8 000 guest cycles of the M4.3 measurement.
    while msg.len() - off >= KECCAK_RATE {
        for i in 0..KECCAK_RATE / 4 {
            let p = off + 4 * i;
            state[i] ^= u32::from_le_bytes([msg[p], msg[p + 1], msg[p + 2], msg[p + 3]]);
        }
        h.keccak_f(&mut state);
        off += KECCAK_RATE;
    }
    // The final block: what is left of the message (possibly nothing — a length that is an exact
    // multiple of the rate still needs a whole all-padding block) plus `0x01`…`0x80`.
    let take = msg.len() - off;
    let mut block = [0u8; KECCAK_RATE];
    block[..take].copy_from_slice(&msg[off..]);
    block[take] ^= 0x01;
    block[KECCAK_RATE - 1] ^= 0x80;
    for i in 0..KECCAK_RATE / 4 {
        state[i] ^= u32::from_le_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    h.keccak_f(&mut state);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// The longest `dhash` message this crate hashes: the 40-word public-output preimage plus its
/// domain word.
const DHASH_MAX_WORDS: usize = 41;

/// `hash(domain, msg) = poseidon2([domain, msg…])` — the domain-tagged sponge every leaf, node
/// and digest here is built from, byte-identical to research's `notes::hash`. `1 + msg.len()`
/// must be at most 41 words.
///
/// This is the *general* form, used once per call for the public-output digest. Every leaf and
/// node goes through [`hash_pair`] instead, which is the same sponge with none of the copying —
/// see there for why that matters.
pub fn dhash<H: Host>(h: &mut H, domain: u32, msg: &[u32]) -> [u32; 8] {
    let n = 1 + msg.len();
    debug_assert!(n <= DHASH_MAX_WORDS);
    let mut buf = [0u32; DHASH_MAX_WORDS];
    buf[0] = domain;
    buf[1..n].copy_from_slice(msg);
    h.poseidon2(&mut buf, n);
    let mut out = [0u32; 8];
    out.copy_from_slice(&buf[..8]);
    out
}

/// `hash(domain, [a(8) ‖ b(8)])` — the 17-word sponge call every storage leaf and tree node is,
/// marshalled **in place**: one 17-word buffer, filled once, hashed where it lies.
///
/// Identical in output to `dhash(h, domain, &[a ‖ b])` (`tests/evm_storage.rs` checks leaf and node
/// hashes against research's `notes::hash` directly, on both paths). The difference is cycles, and
/// it is the single biggest cost in an EVM call: a `transfer` makes 132 of these calls (four
/// 32-level Merkle walks), and the first cut of M4.3 spent ~850 guest cycles on each — of which
/// about eight were the `POSEIDON2` syscall and the rest was building a 16-word message array,
/// zeroing a 48-word buffer and copying the message into it. A 17-word buffer written field by
/// field removes all three (M4.3 measurement: 112 298 → 44 132 cycles for the storage part of a
/// transfer).
pub fn hash_pair<H: Host>(h: &mut H, domain: u32, a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut buf = [0u32; 17];
    buf[0] = domain;
    // Indexed loops, not `copy_from_slice`: a slice copy of eight words compiles to a `memcpy`
    // *call* in the guest (`compiler_builtins`), and three of those per sponge call were most of
    // what a Merkle level cost. Unrolled loads and stores have no call and no length check.
    let mut k = 0;
    while k < 8 {
        buf[1 + k] = a[k];
        buf[9 + k] = b[k];
        k += 1;
    }
    h.poseidon2(&mut buf, 17);
    let mut out = [0u32; 8];
    let mut k = 0;
    while k < 8 {
        out[k] = buf[k];
        k += 1;
    }
    out
}

// The C ABI for `evm2rv`'s translated contracts, behind the `ffi` feature, which only their shims
// enable. Not merely unused in the interpreter's guest but *absent* from it: compiled in, its
// `#[no_mangle]` functions are dropped by the linker yet still move the `evm` guest's pinned image
// (same length, different layout), so the module is cfg'd out rather than left to LTO. Declared
// last, not beside `abi`, so no line of this file moves either: that image embeds the source line
// of each bounds-check panic location.
#[cfg(feature = "ffi")]
pub mod ffi;
