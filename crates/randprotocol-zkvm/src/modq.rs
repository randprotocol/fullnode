//! `MODQ` (private multisig phase 3): the host reference semantics of the mod-q coprocessor.
//!
//! Every later piece (the emulator syscall, the chip's AIR, the Dilithium verifier backend) is
//! checked against these functions. All arithmetic is exact `u64` over canonical residues: inputs
//! are any word below [`INPUT_BOUND`] (read mod q), and every output is canonical (`< Q`).
//!
//! - `ntt` is the Dilithium forward NTT (Cooley-Tukey, the reference's loop order, output in
//!   bit-reversed order) with plain twiddles `ζ_k = 1753^{brv8(k)} mod q` instead of Montgomery
//!   ones. `ntt(a)[i] = a(ψ^{2·brv8(i)+1})` with `ψ = 1753`.
//! - `intt` is the exact inverse, `n⁻¹` included and fused into the last stage's butterfly (spec
//!   §3.3), so `intt(ntt(a)) = a mod q`. The reference's `invntt_tomont` is `2^32 · intt`.
//! - `dot4` / `msub4` are schoolbook pointwise products mod q.
//!
//! The syscall ABI (spec §3.1): `a1 = op | OUT << 8 | A << 16 | B << 24`, poly `i` of the arena at
//! `BASE` is words `BASE + 256·i .. BASE + 256·i + 255`.

/// The Dilithium prime `2^23 − 2^13 + 1`.
pub const Q: u32 = 8_380_417;
/// Coefficients per polynomial.
pub const N: usize = 256;
/// `256⁻¹ mod q`.
pub const N_INV: u32 = 8_347_681;
/// Every input word must be below this (three byte limbs in the AIR).
pub const INPUT_BOUND: u32 = 1 << 24;
/// The primitive 512th root of unity mod q used by Dilithium.
const PSI: u64 = 1753;

/// A polynomial as 256 words.
pub type Poly = [u32; N];

const QU: u64 = Q as u64;

fn pow_mod(b: u64, mut e: u64) -> u64 {
    let (mut r, mut b) = (1u64, b % QU);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % QU;
        }
        b = b * b % QU;
        e >>= 1;
    }
    r
}

/// `ζ_k = 1753^{brv8(k)} mod q`, canonical (`k` in `1..256`; `k = 0` gives 1).
pub fn zeta(k: usize) -> u32 {
    assert!(k < 256, "zeta index {k} out of range");
    pow_mod(PSI, (k as u8).reverse_bits() as u64) as u32
}

/// The forward NTT's states: `[0]` is the input as given, `[p + 1]` is after stage `p`, `[8]` is
/// `ntt(a)`. Stage `p`: `len = 128 >> p`, group `g` uses `ζ_{2^p + g}`; the butterfly is
/// `(u + ζv, u − ζv) mod q`, with `u`, `v` reduced mod q inside it.
pub fn ntt_stages(a: &Poly) -> [Poly; 9] {
    let mut s = [[0u32; N]; 9];
    s[0] = *a;
    for p in 0..8 {
        let len = 128usize >> p;
        let (cur, nxt) = (s[p], &mut s[p + 1]);
        for g in 0..(1usize << p) {
            let z = zeta((1 << p) + g) as u64;
            let start = 2 * len * g;
            for j in start..start + len {
                let u = cur[j] as u64 % QU;
                let v = cur[j + len] as u64 % QU;
                let t = z * v % QU;
                nxt[j] = ((u + t) % QU) as u32;
                nxt[j + len] = ((u + QU - t) % QU) as u32;
            }
        }
    }
    s
}

/// The inverse NTT's states: `[0]` is the input as given, `[8]` is `intt(a)`. Stage `p`:
/// `len = 1 << p`, group `g` uses `ζ' = q − ζ_k`, `k = (256 >> p) − 1 − g` (the reference's GS
/// order); the butterfly is `(u + v, ζ'·(u − v)) mod q`, and stage 7 multiplies both outputs by
/// `n⁻¹` inside the same butterfly.
pub fn intt_stages(a: &Poly) -> [Poly; 9] {
    let mut s = [[0u32; N]; 9];
    s[0] = *a;
    for p in 0..8 {
        let len = 1usize << p;
        let f = if p == 7 { N_INV as u64 } else { 1 };
        let (cur, nxt) = (s[p], &mut s[p + 1]);
        for g in 0..(128usize >> p) {
            let zp = (QU - zeta((256 >> p) - 1 - g) as u64) % QU;
            let start = 2 * len * g;
            for j in start..start + len {
                let u = cur[j] as u64 % QU;
                let v = cur[j + len] as u64 % QU;
                nxt[j] = (f * ((u + v) % QU) % QU) as u32;
                nxt[j + len] = (f * (zp * ((u + QU - v) % QU) % QU) % QU) as u32;
            }
        }
    }
    s
}

/// Forward NTT in place. Inputs `< 2^24`, outputs canonical.
pub fn ntt(a: &mut Poly) {
    *a = ntt_stages(a)[8];
}

/// Inverse NTT in place, `n⁻¹` included: `intt(ntt(a)) = a mod q`. Outputs canonical.
pub fn intt(a: &mut Poly) {
    *a = intt_stages(a)[8];
}

/// `out[c] = Σ_k a[k][c]·b[k][c] mod q`.
pub fn dot4(a: &[Poly; 4], b: &[Poly; 4]) -> Poly {
    core::array::from_fn(|c| {
        let mut acc = 0u64;
        for k in 0..4 {
            acc = (acc + (a[k][c] as u64 % QU) * (b[k][c] as u64 % QU)) % QU;
        }
        acc as u32
    })
}

/// `w[k][c] = w[k][c] − c[c]·t[k][c] mod q`, canonical.
pub fn msub4(w: &mut [Poly; 4], c: &Poly, t: &[Poly; 4]) {
    for k in 0..4 {
        for i in 0..N {
            let sub = (c[i] as u64 % QU) * (t[k][i] as u64 % QU) % QU;
            w[k][i] = ((w[k][i] as u64 % QU + QU - sub) % QU) as u32;
        }
    }
}

/// The four operations, numbered as in `a1`'s low bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Ntt = 0,
    Intt = 1,
    Dot4 = 2,
    Msub4 = 3,
}

/// A decoded `a1`: the op and three 5-bit poly indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Args {
    pub op: Op,
    pub out: u32,
    pub a: u32,
    pub b: u32,
}

/// The bits `a1` may set: op `0..2`, `OUT` `8..13`, `A` `16..21`, `B` `24..29`.
const ARGS_MASK: u32 = 0b11 | 0x1f << 8 | 0x1f << 16 | 0x1f << 24;

impl Args {
    /// `op | out << 8 | a << 16 | b << 24`. Fields are expected `< 32`; a wider one spills into a
    /// reserved bit and `decode` refuses it.
    pub fn encode(self) -> u32 {
        assert!(self.out < 32 && self.a < 32 && self.b < 32, "poly index past 5 bits: {self:?}");
        self.op as u32 | self.out << 8 | self.a << 16 | self.b << 24
    }

    /// `None` on any reserved bit, or on a transform naming `A` or `B`.
    pub fn decode(a1: u32) -> Option<Args> {
        if a1 & !ARGS_MASK != 0 {
            return None;
        }
        let op = match a1 & 0b11 {
            0 => Op::Ntt,
            1 => Op::Intt,
            2 => Op::Dot4,
            _ => Op::Msub4,
        };
        let (out, a, b) = (a1 >> 8 & 0x1f, a1 >> 16 & 0x1f, a1 >> 24 & 0x1f);
        if matches!(op, Op::Ntt | Op::Intt) && (a != 0 || b != 0) {
            return None;
        }
        Some(Args { op, out, a, b })
    }

    /// The valid fields of `a1`, reserved bits ignored and a transform's `A`/`B` kept — what the
    /// cheating suite's `call_unchecked` and `tables::modq::forge_block` decode.
    pub(crate) fn decode_fields(a1: u32) -> Args {
        let op = match a1 & 0b11 {
            0 => Op::Ntt,
            1 => Op::Intt,
            2 => Op::Dot4,
            _ => Op::Msub4,
        };
        Args { op, out: a1 >> 8 & 0x1f, a: a1 >> 16 & 0x1f, b: a1 >> 24 & 0x1f }
    }

    /// The aliasing rules (spec §5): no word is read twice at one timestamp.
    /// - `DOT4`: the two read spans `[a, a+4)` and `[b, b+4)` are disjoint (`out` is only written).
    /// - `MSUB4`: `[out, out+4)`, `[b, b+4)` and `{a}` are pairwise disjoint.
    pub fn aliasing_ok(self) -> bool {
        let within = |x: u32, lo: u32| x >= lo && x < lo + 4;
        match self.op {
            Op::Ntt | Op::Intt => true,
            Op::Dot4 => self.a.abs_diff(self.b) >= 4,
            Op::Msub4 => {
                self.out.abs_diff(self.b) >= 4 && !within(self.a, self.out) && !within(self.a, self.b)
            }
        }
    }
}

/// Why `call` refuses: each carries the `a1` word, or the offending read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModqError {
    Args(u32),
    Alias(u32),
    Coefficient { addr: u32, value: u32 },
}

/// One call's full I/O.
/// - `inputs`: `NTT`/`INTT` `[p]`; `DOT4` `[a0..a3, b0..b3]`; `MSUB4` `[w0..w3, c, t0..t3]`.
/// - `reads` / `writes`: `(word address, value)`, each address once, poly-major in `inputs` order
///   (reads) and output-poly order (writes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallIo {
    pub args: Args,
    pub inputs: Vec<Poly>,
    pub reads: Vec<(u32, u32)>,
    pub writes: Vec<(u32, u32)>,
}

fn poly_addr(base: u32, poly: u32, c: usize) -> u32 {
    base.wrapping_add(256 * poly).wrapping_add(c as u32)
}

/// The syscall's semantics: decode `a1`, check aliasing, read every input word (refusing the
/// first `≥ 2^24`), compute, and list the writes. Reads all happen before any write, so an
/// in-place op sees the pre-call state.
pub fn call(base: u32, a1: u32, read: impl FnMut(u32) -> u32) -> Result<CallIo, ModqError> {
    let args = Args::decode(a1).ok_or(ModqError::Args(a1))?;
    if !args.aliasing_ok() {
        return Err(ModqError::Alias(a1));
    }
    call_args(base, args, read)
}

/// Cheating-suite hook (spec §5; `cheating` feature only): `call` without the `Args` and `Alias` refusals — reserved bits
/// ignored, a transform's `A`/`B` ignored by the computation, overlapping operands read twice — so
/// a test can reach the chip with what the emulator refuses. Still refuses coefficients `>= 2^24`.
#[cfg(feature = "cheating")]
#[doc(hidden)]
pub fn call_unchecked(base: u32, a1: u32, read: impl FnMut(u32) -> u32) -> Result<CallIo, ModqError> {
    call_args(base, Args::decode_fields(a1), read)
}

pub(crate) fn call_args(base: u32, args: Args, mut read: impl FnMut(u32) -> u32) -> Result<CallIo, ModqError> {
    let in_polys: Vec<u32> = match args.op {
        Op::Ntt | Op::Intt => vec![args.out],
        Op::Dot4 => (0..4).map(|k| args.a + k).chain((0..4).map(|k| args.b + k)).collect(),
        Op::Msub4 => (0..4)
            .map(|k| args.out + k)
            .chain(core::iter::once(args.a))
            .chain((0..4).map(|k| args.b + k))
            .collect(),
    };
    let mut inputs = Vec::with_capacity(in_polys.len());
    let mut reads = Vec::with_capacity(in_polys.len() * N);
    for &p in &in_polys {
        let mut poly = [0u32; N];
        for (c, slot) in poly.iter_mut().enumerate() {
            let addr = poly_addr(base, p, c);
            let value = read(addr);
            if value >= INPUT_BOUND {
                return Err(ModqError::Coefficient { addr, value });
            }
            *slot = value;
            reads.push((addr, value));
        }
        inputs.push(poly);
    }
    let outputs: Vec<(u32, Poly)> = match args.op {
        Op::Ntt => {
            let mut x = inputs[0];
            ntt(&mut x);
            vec![(args.out, x)]
        }
        Op::Intt => {
            let mut x = inputs[0];
            intt(&mut x);
            vec![(args.out, x)]
        }
        Op::Dot4 => {
            let a: [Poly; 4] = core::array::from_fn(|k| inputs[k]);
            let b: [Poly; 4] = core::array::from_fn(|k| inputs[4 + k]);
            vec![(args.out, dot4(&a, &b))]
        }
        Op::Msub4 => {
            let mut w: [Poly; 4] = core::array::from_fn(|k| inputs[k]);
            let t: [Poly; 4] = core::array::from_fn(|k| inputs[5 + k]);
            msub4(&mut w, &inputs[4], &t);
            (0..4u32).map(|k| (args.out + k, w[k as usize])).collect()
        }
    };
    let writes = outputs
        .iter()
        .flat_map(|(p, poly)| poly.iter().enumerate().map(move |(c, &v)| (poly_addr(base, *p, c), v)))
        .collect();
    Ok(CallIo { args, inputs, reads, writes })
}
