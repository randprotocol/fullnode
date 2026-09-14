//! SHA-256 (FIPS 180-4) as the `SHA256` syscall and chip compute it, for host-side use (the
//! emulator's reference, trace generation, guest-side sponge tests). The chip proves the same
//! compression round by round (`tables::sha256`); this module has no columns and no AIR.

/// Rounds per compression, and the row count of one block in the chip's trace.
pub const ROUNDS: usize = 64;
/// Words in one 512-bit message block.
pub const BLOCK_WORDS: usize = 16;
/// Words in the chaining state `H`.
pub const STATE_WORDS: usize = 8;
/// Words in the syscall's `SHA256_WORDS` pointer argument: a block followed by a state.
pub const WORDS: usize = 24;

/// Round constants `K[0..64]` (FIPS 180-4 §4.2.2).
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash value `H(0)` (FIPS 180-4 §5.3.3).
pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// `u32::from_be_bytes` per 4 bytes: the block's words are big-endian-valued.
pub fn bytes_to_words(block: &[u8; 64]) -> [u32; 16] {
    core::array::from_fn(|i| u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]))
}

/// The message schedule `W[0..64]` (FIPS 180-4 §6.2.2 step 1).
pub fn schedule(block: &[u32; 16]) -> [u32; 64] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16].wrapping_add(s0).wrapping_add(w[t - 7]).wrapping_add(s1);
    }
    w
}

/// One round on the working variables `v = [a, b, c, d, e, f, g, h]`.
pub fn round(v: &mut [u32; 8], w: u32, k: u32) {
    let [a, b, c, d, e, f, g, h] = *v;
    let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ (!e & g);
    let t1 = h.wrapping_add(big_sigma1).wrapping_add(ch).wrapping_add(k).wrapping_add(w);
    let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = big_sigma0.wrapping_add(maj);
    *v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
}

/// One compression: `schedule`, 64 rounds, add back into `state`.
pub fn compress(state: &mut [u32; 8], block: &[u32; 16]) {
    let w = schedule(block);
    let mut v = *state;
    for t in 0..ROUNDS {
        round(&mut v, w[t], K[t]);
    }
    for i in 0..8 {
        state[i] = state[i].wrapping_add(v[i]);
    }
}

/// `msg ‖ 0x80 ‖ zeros ‖ be64(bit length)`, padded + `IV` + compressions, big-endian output.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = IV;
    for block in padded.chunks_exact(64) {
        let block: [u8; 64] = block.try_into().unwrap();
        compress(&mut state, &bytes_to_words(&block));
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
