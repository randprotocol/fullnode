//! SHAKE128/SHAKE256 over a [`Keccak`] permutation (FIPS 202), ported from
//! `crystals-dilithium` 2.0.0's `fips202.rs` with the permutation abstracted. The state is the
//! `KECCAK` syscall's 50-word layout (`Keccak::permute_words`), so the guest never joins or splits
//! lanes; words and bytes are little-endian views of one stream.
use crate::Keccak;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// An incremental SHAKE sponge that owns its permutation.
pub struct Shake<K: Keccak> {
    k: K,
    s: [u32; 50],
    /// Byte position in the rate.
    pos: usize,
    rate: usize,
    finalized: bool,
}

impl<K: Keccak> Shake<K> {
    pub fn new128(k: K) -> Self {
        Self { k, s: [0; 50], pos: 0, rate: SHAKE128_RATE, finalized: false }
    }

    pub fn new256(k: K) -> Self {
        Self { k, s: [0; 50], pos: 0, rate: SHAKE256_RATE, finalized: false }
    }

    /// Absorb `input`. Must not be called after `finalize`.
    pub fn absorb(&mut self, input: &[u8]) {
        debug_assert!(!self.finalized, "absorb after finalize");
        let mut input = input;
        while !input.is_empty() {
            if self.pos & 3 == 0 && input.len() >= 4 {
                // Aligned: one whole word at a time.
                self.s[self.pos >> 2] ^= u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
                self.pos += 4;
                input = &input[4..];
            } else {
                // Ragged head or tail.
                self.s[self.pos >> 2] ^= (input[0] as u32) << (8 * (self.pos & 3));
                self.pos += 1;
                input = &input[1..];
            }
            if self.pos == self.rate {
                self.k.permute_words(&mut self.s);
                self.pos = 0;
            }
        }
    }

    /// Absorb the little-endian bytes of `input`: the same as `absorb` on them, a word per step
    /// when the position is word-aligned.
    pub fn absorb_words(&mut self, input: &[u32]) {
        debug_assert!(!self.finalized, "absorb after finalize");
        if self.pos & 3 != 0 {
            for w in input {
                self.absorb(&w.to_le_bytes());
            }
            return;
        }
        let mut input = input;
        while !input.is_empty() {
            // Up to the end of the rate or of the input: a plain zipped XOR, one bounds check.
            let start = self.pos >> 2;
            let n = core::cmp::min(self.rate / 4 - start, input.len());
            let (head, rest) = input.split_at(n);
            // Four words to a loop pass: the loop control is most of the per-word cost otherwise.
            let (sq, sr) = self.s[start..start + n].as_chunks_mut::<4>();
            let (hq, hr) = head.as_chunks::<4>();
            for (s, w) in sq.iter_mut().zip(hq) {
                s[0] ^= w[0];
                s[1] ^= w[1];
                s[2] ^= w[2];
                s[3] ^= w[3];
            }
            for (s, w) in sr.iter_mut().zip(hr) {
                *s ^= *w;
            }
            self.pos += 4 * n;
            input = rest;
            if self.pos == self.rate {
                self.k.permute_words(&mut self.s);
                self.pos = 0;
            }
        }
    }

    /// Pad (domain byte 0x1f, final bit 0x80) and switch to squeezing.
    pub fn finalize(&mut self) {
        debug_assert!(!self.finalized, "finalize twice");
        self.s[self.pos >> 2] ^= 0x1fu32 << (8 * (self.pos & 3));
        self.s[self.rate / 4 - 1] ^= 1u32 << 31;
        self.pos = self.rate;
        self.finalized = true;
    }

    /// Squeeze `out.len()` bytes; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.finalized, "squeeze before finalize");
        let mut out = out;
        while !out.is_empty() {
            if self.pos == self.rate {
                self.k.permute_words(&mut self.s);
                self.pos = 0;
            }
            let word = self.s[self.pos >> 2];
            if self.pos & 3 == 0 && out.len() >= 4 {
                let (head, rest) = out.split_at_mut(4);
                head.copy_from_slice(&word.to_le_bytes());
                self.pos += 4;
                out = rest;
            } else {
                out[0] = (word >> (8 * (self.pos & 3))) as u8;
                self.pos += 1;
                out = &mut out[1..];
            }
        }
    }

    /// Squeeze `out.len()` words: the same stream as `squeeze` on `4 * out.len()` bytes.
    pub fn squeeze_words(&mut self, out: &mut [u32]) {
        debug_assert!(self.finalized, "squeeze before finalize");
        if self.pos & 3 != 0 {
            for o in out.iter_mut() {
                let mut b = [0u8; 4];
                self.squeeze(&mut b);
                *o = u32::from_le_bytes(b);
            }
            return;
        }
        for o in out.iter_mut() {
            if self.pos == self.rate {
                self.k.permute_words(&mut self.s);
                self.pos = 0;
            }
            *o = self.s[self.pos >> 2];
            self.pos += 4;
        }
    }
}

/// One-shot SHAKE256 over the concatenation of `input`.
pub fn shake256<K: Keccak>(k: &mut K, input: &[&[u8]], out: &mut [u8]) {
    let mut sh = Shake::new256(k);
    for part in input {
        sh.absorb(part);
    }
    sh.finalize();
    sh.squeeze(out);
}
