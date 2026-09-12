//! Keccak-f[1600] as the `KECCAK` syscall and chip compute it, for host-side use (the
//! emulator's reference, trace generation, guest-side sponge tests). The chip proves the same
//! permutation round by round (`tables::keccak`); this module has no columns and no AIR.
use p3_symmetric::Permutation;

pub const LANES: usize = 25;
pub const WORDS: usize = 50;
pub const ROUNDS: usize = 24;

/// ι round constants (FIPS 202 Table 2 order).
pub const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// ρ rotation offsets, `ROT[x][y]`.
pub const ROT: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

pub fn keccak_f(state: &mut [u64; 25]) {
    p3_keccak::KeccakF.permute_mut(state);
}

pub fn state_to_words(s: &[u64; 25]) -> [u32; 50] {
    std::array::from_fn(|w| if w % 2 == 0 { s[w / 2] as u32 } else { (s[w / 2] >> 32) as u32 })
}

pub fn words_to_state(w: &[u32; 50]) -> [u64; 25] {
    std::array::from_fn(|i| w[2 * i] as u64 | ((w[2 * i + 1] as u64) << 32))
}

/// Keccak-256 (the Ethereum variant: `0x01` domain padding, rate 136).
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut padded = msg.to_vec();
    padded.push(0x01);
    while padded.len() % RATE != 0 { padded.push(0); }
    let last = padded.len() - 1;
    padded[last] |= 0x80;
    for block in padded.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            state[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        keccak_f(&mut state);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}
