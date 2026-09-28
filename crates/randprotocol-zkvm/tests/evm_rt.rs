//! `evm-rt` (the C runtime `evm2rv`'s translated contracts run on) against the interpreter it
//! must match, from the Rust side:
//!
//! * `test/u256_vectors.h` — the known answers `evm-rt/test/u256_test.c` checks the C `u256`
//!   library against — is generated here from `evm_core::u256::U256` (itself checked against
//!   `num-bigint` in `evm_u256.rs`), and this test fails if the committed file differs from what
//!   it generates. Regenerate with `EVM_RT_REGEN=1 cargo test --release --test evm_rt`. The
//!   operands come from a fixed edge list and a self-contained SplitMix64, so the file depends on
//!   nothing but this source and `U256`.
//! * The halt codes and the gas constants in `evm_rt.h` are compared, as text, with `ffi.rs`'s
//!   `HALT_*` and `interp.rs`'s `G_*`/limits, so neither table can drift from the Rust.
//! * The C suite itself is compiled with the host `cc` and run.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use evm_core::ffi;
use evm_core::u256::U256;

fn rt_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../evm-rt")
}

// ---------------------------------------------------------------------------------------------
// The vectors.

/// The operation codes `u256_test.c` dispatches on — the order is the header's `V_*` defines.
const OPS: &[&str] = &[
    "ADD", "SUB", "MUL", "DIV", "MOD", "SDIV", "SMOD", "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND",
    "LT", "GT", "SLT", "SGT", "EQ", "ISZERO", "AND", "OR", "XOR", "NOT", "BYTE", "SHL", "SHR",
    "SAR", "BIT_LEN", "BYTE_LEN",
];

fn op_code(name: &str) -> u8 {
    OPS.iter().position(|o| *o == name).unwrap() as u8 + 1
}

fn bool_word(b: bool) -> U256 {
    if b {
        U256::ONE
    } else {
        U256::ZERO
    }
}

/// The interpreter's semantics, operand order as `u256.h` documents it (the receiver first).
fn apply(op: &str, a: &U256, b: &U256, c: &U256) -> U256 {
    match op {
        "ADD" => a.add(b),
        "SUB" => a.sub(b),
        "MUL" => a.mul(b),
        "DIV" => a.div(b),
        "MOD" => a.rem(b),
        "SDIV" => a.sdiv(b),
        "SMOD" => a.smod(b),
        "ADDMOD" => a.addmod(b, c),
        "MULMOD" => a.mulmod(b, c),
        "EXP" => a.exp(b),
        "SIGNEXTEND" => a.signextend(b),
        "LT" => bool_word(a.lt(b)),
        "GT" => bool_word(b.lt(a)),
        "SLT" => bool_word(a.slt(b)),
        "SGT" => bool_word(b.slt(a)),
        "EQ" => bool_word(a == b),
        "ISZERO" => bool_word(a.is_zero()),
        "AND" => a.and(b),
        "OR" => a.or(b),
        "XOR" => a.xor(b),
        "NOT" => a.not(),
        "BYTE" => a.byte(b),
        "SHL" => a.shl(b),
        "SHR" => a.shr(b),
        "SAR" => a.sar(b),
        "BIT_LEN" => U256::from_u32(a.bit_len()),
        "BYTE_LEN" => U256::from_u32(a.byte_len()),
        _ => unreachable!("{op}"),
    }
}

/// SplitMix64: a fixed, dependency-free stream, so the vectors never move with a `rand` upgrade.
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    /// A mixture that hits every carry path: full width, small, just below 2^256, top+bottom
    /// limbs only, and a negative small value.
    fn word(&mut self) -> U256 {
        match self.below(5) {
            0 => U256(core::array::from_fn(|_| self.next() as u32)),
            1 => U256::from_u64(self.next()),
            2 => U256::MAX.sub(&U256::from_u32((self.next() % 5) as u32)),
            3 => {
                let mut l = [0u32; 8];
                l[7] = self.next() as u32;
                l[0] = self.next() as u32;
                U256(l)
            }
            _ => U256::ZERO.sub(&U256::from_u64(self.next() >> 20)),
        }
    }
}

fn pow2(k: u32) -> U256 {
    U256::ONE.shl(&U256::from_u32(k))
}

fn hex(v: &U256) -> String {
    let mut s = String::new();
    for limb in v.0.iter().rev() {
        write!(s, "{limb:08x}").unwrap();
    }
    let t = s.trim_start_matches('0');
    if t.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

/// The whole header, deterministic.
fn vectors_header() -> String {
    let min = pow2(255);
    // The edge operands, the brief's (0, 1, 2^255, 2^256-1) among them.
    let edges: Vec<U256> = vec![
        U256::ZERO,
        U256::ONE,
        U256::from_u32(2),
        U256::from_u32(3),
        U256::from_u32(7),
        U256::from_u32(0x80),
        U256::from_u32(0xff),
        U256::from_u32(0x8000_0000),
        U256::from_u32(u32::MAX),
        pow2(32),
        U256::from_u64(u64::MAX),
        pow2(128),
        min.sub(&U256::ONE), // the largest positive
        min,                 // MIN
        min.add(&U256::ONE),
        U256::MAX.sub(&U256::ONE), // -2
        U256::MAX,                 // -1
        U256([
            0x89ab_cdef, 0x0123_4567, 0xfedc_ba98, 0x7654_3210, 0x0f1e_2d3c, 0x4b5a_6978,
            0x8796_a5b4, 0xc3d2_e1f0,
        ]),
    ];
    // Shift amounts and byte indices, the brief's 0/255/256 and every byte boundary.
    let mut amounts: Vec<U256> = (0..=33).map(U256::from_u32).collect();
    for k in [63u32, 64, 65, 127, 128, 200, 247, 248, 254, 255, 256, 257, 1000] {
        amounts.push(U256::from_u32(k));
    }
    amounts.push(pow2(32)); // low limb 0, but >= 256
    amounts.push(pow2(32).add(&U256::ONE));
    amounts.push(min);
    amounts.push(U256::MAX);

    let mut mix = Mix(0x6576_6d2d_7274); // "evm-rt"
    let randoms: Vec<U256> = (0..24).map(|_| mix.word()).collect();

    // One operand table; vectors refer to it by index.
    let mut table: Vec<U256> = Vec::new();
    let idx = |v: &U256, table: &mut Vec<U256>| -> usize {
        if let Some(i) = table.iter().position(|t| t == v) {
            i
        } else {
            table.push(*v);
            table.len() - 1
        }
    };
    let mut vecs: Vec<(u8, usize, usize, usize, U256)> = Vec::new();
    let mut add = |op: &str, a: &U256, b: &U256, c: &U256, table: &mut Vec<U256>| {
        let r = apply(op, a, b, c);
        let (ia, ib, ic) = (idx(a, table), idx(b, table), idx(c, table));
        vecs.push((op_code(op), ia, ib, ic, r));
    };

    let all: Vec<U256> = edges.iter().chain(randoms.iter()).copied().collect();
    let z = U256::ZERO;
    // The pairwise product: the brief's edges (0, 1, 2^255, 2^256-1) and their neighbours.
    let pair_core: Vec<U256> =
        [0usize, 1, 2, 7, 8, 9, 12, 13, 14, 15, 16, 17].iter().map(|&i| edges[i]).collect();
    for op in [
        "ADD", "SUB", "MUL", "DIV", "MOD", "SDIV", "SMOD", "EXP", "LT", "GT", "SLT", "SGT", "EQ",
        "AND", "OR", "XOR",
    ] {
        for a in &pair_core {
            for b in &pair_core {
                add(op, a, b, &z, &mut table);
            }
        }
        for _ in 0..40 {
            let (a, b) = (all[mix.below(all.len())], all[mix.below(all.len())]);
            add(op, &a, &b, &z, &mut table);
        }
    }
    // Division's hard cases: divisors of every significant-limb count, and a quotient digit the
    // estimate overshoots (the add-back path).
    for i in 0..48 {
        let a = mix.word();
        let mut d = mix.word();
        let keep = 1 + i % 8;
        for l in keep..8 {
            d.0[l] = 0;
        }
        for op in ["DIV", "MOD", "SDIV", "SMOD"] {
            add(op, &a, &d, &z, &mut table);
        }
    }
    let knuth_a = U256([0, 0, 0, 0x8000_0000, 0x7fff_ffff, 0, 0, 0]);
    let knuth_d = U256([1, 0, 0x8000_0000, 0, 0, 0, 0, 0]);
    for op in ["DIV", "MOD"] {
        add(op, &knuth_a, &knuth_d, &z, &mut table);
    }
    // The add-back with a non-zero normalising shift (the review's pair): the remainder's
    // denormalisation reads `un[dn]`, so a wrong carry into the top window limb shows (a mod d
    // = 0x3ffffffff800054f000a8d27; dropping that carry gives 0xbffffffff800054f000a8d27). The
    // pair case above has s = 0 and never reads it.
    let addback_a = U256([0x000a_8d47, 0x3800_0546, 0x4000_0000, 0x3fff_fff8, 0, 0, 0, 0]);
    let addback_d = U256([0x3fff_ffff, 0, 0x4000_0000, 0, 0, 0, 0, 0]);
    assert_eq!(hex(&addback_a), "3ffffff84000000038000546000a8d47");
    assert_eq!(hex(&addback_d), "40000000000000003fffffff");
    assert_eq!(hex(&addback_a.rem(&addback_d)), "3ffffffff800054f000a8d27");
    for op in ["DIV", "MOD", "SDIV", "SMOD"] {
        add(op, &addback_a, &addback_d, &z, &mut table);
    }
    // ... and as ADDMOD/MULMOD's modulus, where the numerator is 16 limbs wide.
    add("ADDMOD", &addback_a, &U256::ZERO, &addback_d, &mut table);
    add("ADDMOD", &addback_a, &U256::MAX, &addback_d, &mut table);
    add("MULMOD", &addback_a, &U256::ONE, &addback_d, &mut table);
    add("MULMOD", &addback_a, &U256::MAX, &addback_d, &mut table);
    let core: Vec<U256> = [0usize, 1, 2, 8, 13, 16].iter().map(|&i| edges[i]).collect();
    for op in ["ADDMOD", "MULMOD"] {
        for a in &core {
            for b in &core {
                for m in &core {
                    add(op, a, b, m, &mut table);
                }
            }
        }
        for _ in 0..64 {
            let (a, b, m) =
                (all[mix.below(all.len())], all[mix.below(all.len())], all[mix.below(all.len())]);
            add(op, &a, &b, &m, &mut table);
        }
    }
    // Shifts, BYTE and SIGNEXTEND: a spread of values against every amount.
    let shifted: Vec<U256> = [1usize, 5, 12, 13, 16, 17]
        .iter()
        .map(|&i| edges[i])
        .chain(randoms[..2].iter().copied())
        .collect();
    for op in ["SHL", "SHR", "SAR", "BYTE", "SIGNEXTEND"] {
        for x in &shifted {
            for n in &amounts {
                add(op, x, n, &z, &mut table);
            }
        }
    }
    for op in ["ISZERO", "NOT", "BIT_LEN", "BYTE_LEN"] {
        for a in &all {
            add(op, a, &z, &z, &mut table);
        }
    }

    let mut s = String::new();
    s.push_str(
        "/* GENERATED by research/tests/evm_rt.rs from evm_core::u256::U256 — do not edit.\n \
         * Regenerate: (cd research && EVM_RT_REGEN=1 cargo test --release --test evm_rt).\n \
         * Values are big-endian hex without leading zeros; a vector is {op, a, b, c, result},\n \
         * the operands as indices into U256_VALUES, in u256.h's operand order. */\n",
    );
    for (i, op) in OPS.iter().enumerate() {
        writeln!(s, "#define V_{op} {}", i + 1).unwrap();
    }
    s.push_str("static const char *const U256_VALUES[] = {\n");
    for v in &table {
        writeln!(s, "    \"{}\",", hex(v)).unwrap();
    }
    s.push_str("};\n");
    s.push_str(
        "static const struct { unsigned char op; unsigned short a, b, c; const char *r; } \
         U256_VECTORS[] = {\n",
    );
    for (op, a, b, c, r) in &vecs {
        writeln!(s, "    {{{op}, {a}, {b}, {c}, \"{}\"}},", hex(r)).unwrap();
    }
    s.push_str("};\n");
    s
}

#[test]
fn the_committed_u256_vectors_are_what_the_interpreter_computes() {
    let path = rt_dir().join("test/u256_vectors.h");
    let want = vectors_header();
    if std::env::var_os("EVM_RT_REGEN").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        have == want,
        "{} is stale; regenerate with EVM_RT_REGEN=1 cargo test --release --test evm_rt",
        path.display()
    );
}

// ---------------------------------------------------------------------------------------------
// The tables that must not drift.

/// Every `#define <prefix><NAME> <decimal>` in `text`; a matching define whose value is anything
/// but a plain decimal literal panics.
fn c_defines(text: &str, prefix: &str) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        // A trailing `/* ... */` or `// ...` comment is not part of the value.
        let code = line.split("/*").next().unwrap().split("//").next().unwrap();
        let mut w = code.split_whitespace();
        if w.next() != Some("#define") {
            continue;
        }
        let (Some(name), Some(val)) = (w.next(), w.next()) else { continue };
        if let Some(rest) = name.strip_prefix(prefix) {
            // A plain decimal literal and nothing else: a hex value, a suffix, an expression or a
            // value that is not there fails the test instead of being skipped.
            let bare = val.chars().all(|c| c.is_ascii_digit()) && w.next().is_none();
            let n = val.parse().ok().filter(|_| bare);
            let n = n.unwrap_or_else(|| panic!("`{}`: not a plain decimal literal", line.trim()));
            m.insert(rest.to_string(), n);
        }
    }
    m
}

#[test]
fn the_c_halt_codes_are_ffi_rs_table() {
    let h = std::fs::read_to_string(rt_dir().join("evm_rt.h")).unwrap();
    let c = c_defines(&h, "EVM_HALT_");
    let rust: BTreeMap<String, u64> = [
        ("OK", 0),
        ("STOP", ffi::HALT_STOP),
        ("RETURN", ffi::HALT_RETURN),
        ("REVERT", ffi::HALT_REVERT),
        ("OUT_OF_GAS", ffi::HALT_OUT_OF_GAS),
        ("STACK_UNDERFLOW", ffi::HALT_STACK_UNDERFLOW),
        ("STACK_OVERFLOW", ffi::HALT_STACK_OVERFLOW),
        ("BAD_JUMP", ffi::HALT_BAD_JUMP),
        ("INVALID", ffi::HALT_INVALID),
        ("TRAP", ffi::HALT_TRAP),
        ("NO_WITNESS", ffi::HALT_NO_WITNESS),
        ("BAD_WITNESS", ffi::HALT_BAD_WITNESS),
        ("OUT_OF_BOUNDS", ffi::HALT_OUT_OF_BOUNDS),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v as u64))
    .collect();
    assert_eq!(c, rust, "evm_rt.h's EVM_HALT_* against ffi.rs's HALT_*");
    // And that list is the whole Rust table: every code it names decodes, nothing past it does.
    for code in 1..=12u32 {
        assert!(ffi::halt_from_code(code, 0).is_some(), "{code}");
    }
    for code in (13..=300u32).chain([0]) {
        assert!(ffi::halt_from_code(code, 0).is_none(), "{code}");
    }
}

#[test]
fn the_c_gas_constants_and_limits_are_interp_rs() {
    let interp = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../guests-compiled/evm-core/src/interp.rs"),
    )
    .unwrap();
    let h = std::fs::read_to_string(rt_dir().join("evm_rt.h")).unwrap();
    // `const NAME: u64 = 1_234;` and `pub const NAME: usize = 1_234;`.
    let mut rust = BTreeMap::new();
    for line in interp.lines() {
        let l = line.trim_start().trim_start_matches("pub ");
        let Some(rest) = l.strip_prefix("const ") else { continue };
        let Some((name, rhs)) = rest.split_once(':') else { continue };
        let Some((_, val)) = rhs.split_once('=') else { continue };
        let digits: String =
            val.trim().chars().take_while(|c| c.is_ascii_digit() || *c == '_').collect();
        if let Ok(n) = digits.replace('_', "").parse::<u64>() {
            rust.insert(name.trim().to_string(), n);
        }
    }
    let g_rust: BTreeMap<_, _> = rust.iter().filter(|(k, _)| k.starts_with("G_")).collect();
    let g_c: BTreeMap<String, u64> =
        c_defines(&h, "G_").into_iter().map(|(k, v)| (format!("G_{k}"), v)).collect();
    let g_c: BTreeMap<_, _> = g_c.iter().collect();
    assert_eq!(g_c, g_rust, "evm_rt.h's G_* against interp.rs's");
    assert_eq!(g_rust.len(), 18);
    for name in [
        "STACK_LIMIT", "MAX_MEMORY_BYTES", "MAX_CODE_BYTES", "MAX_CALLDATA_BYTES",
        "MAX_RETURN_BYTES", "MAX_LOGS", "MAX_TOPICS",
    ] {
        let c = c_defines(&h, name).remove("").unwrap_or_else(|| panic!("{name} not in evm_rt.h"));
        assert_eq!(Some(&c), rust.get(name), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// The C suite.

#[test]
fn the_c_suite_passes_on_the_host() {
    let dir = rt_dir();
    let out = std::env::temp_dir().join(format!("evm_rt_test_{}", std::process::id()));
    let mut srcs: Vec<PathBuf> = Vec::new();
    for sub in [dir.clone(), dir.join("test")] {
        for e in std::fs::read_dir(&sub).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "c") {
                srcs.push(p);
            }
        }
    }
    srcs.sort();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let st = Command::new(&cc)
        .args(["-O1", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&out)
        .args(&srcs)
        .status()
        .expect("the host C compiler (`cc`, or $CC)");
    assert!(st.success(), "compiling the evm-rt suite");
    let run = Command::new(&out).output().unwrap();
    let _ = std::fs::remove_file(&out);
    let text = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "the evm-rt suite failed:\n{text}{}", String::from_utf8_lossy(&run.stderr));
    assert!(text.contains(" 0 failed"), "{text}");
}
