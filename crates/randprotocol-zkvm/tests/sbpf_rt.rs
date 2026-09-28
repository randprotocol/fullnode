//! `sbpf-rt` (the C runtime `sbpf2rv`'s translated programs run on) against the interpreter it must
//! match, from the Rust side:
//!
//! * The halt table: `sbpf_rt.h`'s `SBPF_HALT_*` codes are `interp.rs`'s `Halt` variants, by name
//!   and declaration order, read from both sources as text — so a variant added, removed or moved
//!   on either side fails here — plus an exhaustive `match` over the compiled enum, so a new
//!   variant cannot even compile until it has a code. Likewise the `Halt::Trap` strings
//!   (`SBPF_TRAP_*`), the twelve syscall hashes against `syscalls::SUPPORTED` (and one
//!   `sbpf_sys_<name>` declared for each), and the machine's constants.
//! * The differential: every region access and syscall in a directed list plus a seeded random
//!   stream runs through `sbpf-core` (`Memory::load`/`store`, `syscalls::dispatch` on a `Vm` over
//!   the same regions) and through the runtime (`sbpf-rt/test/driver.c`, compiled here with the host
//!   `cc`), and the two transcripts — every result or halt with its payload, the input region's
//!   bytes, digests of the stack and heap, the allocator's cursor — must be identical.
//! * The C suite `sbpf-rt/test/host_test.c` is compiled and run, in both `usize` widths.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use randprotocol_zkvm::sbpf::HostRef;
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, Vm, MAX_INSTRUCTIONS};
use sbpf_core::memory::{
    Memory, HEAP_BYTES, MAX_CALL_DEPTH, REGION_HEAP, REGION_INPUT, REGION_PROGRAM, REGION_STACK,
    STACK_BYTES, STACK_FRAME,
};
use sbpf_core::syscalls::{self, murmur3_32, SUPPORTED};

fn rt_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../sbpf-rt")
}
fn core_src(f: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guests-compiled/sbpf-core/src").join(f);
    std::fs::read_to_string(p).unwrap()
}
fn header() -> String {
    std::fs::read_to_string(rt_dir().join("sbpf_rt.h")).unwrap()
}
/// The software signature checks' header (`sbpf_crypto.h`): their two syscall hashes, which the
/// interpreter does not implement.
fn crypto_header() -> String {
    std::fs::read_to_string(rt_dir().join("sbpf_crypto.h")).unwrap()
}

/// `#define <prefix><NAME> <value> …` lines, in order: (NAME, value text, rest of the line).
fn defines(h: &str, prefix: &str) -> Vec<(String, String, String)> {
    h.lines()
        .filter_map(|l| l.strip_prefix("#define "))
        .filter_map(|l| l.strip_prefix(prefix))
        .map(|l| {
            let mut it = l.splitn(3, char::is_whitespace);
            let name = it.next().unwrap().to_string();
            let rest = it.next().unwrap_or("").trim().to_string();
            let tail = it.next().unwrap_or("").trim().to_string();
            (name, rest, tail)
        })
        .collect()
}

fn parse_num(s: &str) -> u64 {
    let s = s.trim_end_matches(|c| c == 'u' || c == 'l');
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

/// `AccessViolation` → `ACCESS_VIOLATION`.
fn screaming(camel: &str) -> String {
    let mut s = String::new();
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() && i != 0 {
            s.push('_');
        }
        s.push(c.to_ascii_uppercase());
    }
    s
}

/// The compiled enum's variants, by name. No wildcard: a new `Halt` variant is a compile error
/// here until it is given a name (and so a code, which the test below then demands of the header).
fn halt_name(h: &Halt) -> &'static str {
    match h {
        Halt::Exit => "Exit",
        Halt::AccessViolation(_) => "AccessViolation",
        Halt::BadInsn(_) => "BadInsn",
        Halt::DivByZero => "DivByZero",
        Halt::UnknownSyscall(_) => "UnknownSyscall",
        Halt::CallDepth => "CallDepth",
        Halt::InstructionLimit => "InstructionLimit",
        Halt::BadElf => "BadElf",
        Halt::BadJump => "BadJump",
        Halt::StackOverflow => "StackOverflow",
        Halt::Trap(_) => "Trap",
    }
}

/// `Halt` variant names in `interp.rs`'s declaration order, read from the source.
fn halt_variants_in_source() -> Vec<String> {
    let src = core_src("interp.rs");
    let start = src.find("pub enum Halt {").expect("interp.rs declares `pub enum Halt`");
    let body = &src[start..];
    let body = &body[..body.find("\n}").unwrap()];
    body.lines()
        .skip(1)
        .filter_map(|l| l.strip_prefix("    "))
        .filter(|l| l.starts_with(|c: char| c.is_ascii_uppercase()))
        .map(|l| l.split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap().to_string())
        .collect()
}

/// `Halt::Trap("…")` strings in `syscalls.rs`, in order of first appearance.
fn trap_strings_in_source() -> Vec<String> {
    let src = core_src("syscalls.rs");
    let mut out: Vec<String> = Vec::new();
    for piece in src.split("Halt::Trap(\"").skip(1) {
        let s = piece[..piece.find('"').unwrap()].to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// `sbpf_rt.h`'s `SBPF_TRAP_*` table: (index, string).
fn header_traps() -> Vec<(u64, String)> {
    defines(&header(), "SBPF_TRAP_")
        .into_iter()
        .map(|(_, v, tail)| {
            let s = tail.split('"').nth(1).expect("each SBPF_TRAP_ names its string").to_string();
            (parse_num(&v), s)
        })
        .collect()
}

#[test]
fn the_halt_codes_are_the_interpreters_variants_in_order() {
    let src = halt_variants_in_source();
    let hdr = defines(&header(), "SBPF_HALT_");
    let hdr_names: Vec<String> = hdr.iter().map(|(n, _, _)| n.clone()).collect();
    let want: Vec<String> = src.iter().map(|v| screaming(v)).collect();
    assert_eq!(hdr_names, want, "sbpf_rt.h's SBPF_HALT_* against interp.rs's `Halt`");
    for (i, (name, v, _)) in hdr.iter().enumerate() {
        assert_eq!(parse_num(v), i as u64, "SBPF_HALT_{name} is not its declaration index");
    }
    // And the compiled enum: one sample of every variant, each named as the source names it.
    let samples = [
        Halt::Exit,
        Halt::AccessViolation(0),
        Halt::BadInsn(0),
        Halt::DivByZero,
        Halt::UnknownSyscall(0),
        Halt::CallDepth,
        Halt::InstructionLimit,
        Halt::BadElf,
        Halt::BadJump,
        Halt::StackOverflow,
        Halt::Trap(""),
    ];
    let compiled: Vec<&str> = samples.iter().map(halt_name).collect();
    assert_eq!(compiled, src.iter().map(String::as_str).collect::<Vec<_>>());
}

#[test]
fn the_trap_strings_are_the_interpreters() {
    let hdr = header_traps();
    let src = trap_strings_in_source();
    assert_eq!(hdr.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>(), src);
    for (i, (v, s)) in hdr.iter().enumerate() {
        assert_eq!(*v, i as u64, "SBPF_TRAP_ for {s:?}");
    }
}

/// The name `sbpf_rt.h` gives a syscall's function: a leading `sol_` and a trailing `_` removed.
fn c_name(name: &str) -> String {
    let n = name.strip_prefix("sol_").unwrap_or(name);
    n.strip_suffix('_').unwrap_or(n).to_string()
}

#[test]
fn the_syscall_table_is_supported_and_each_has_a_function() {
    let h = header();
    let hdr = defines(&h, "SBPF_SYSCALL_");
    // Exactly `SUPPORTED`, in its order; each comment names the syscall.
    assert_eq!(hdr.len(), SUPPORTED.len());
    for (i, &(hash, name)) in SUPPORTED.iter().enumerate() {
        let (_, v, tail) = &hdr[i];
        assert_eq!(parse_num(v), u64::from(hash), "{name}");
        assert_eq!(tail.trim_start_matches("/*").split_whitespace().next(), Some(name), "{name}");
        let decl = format!("uint64_t sbpf_sys_{}(uint64_t r1,", c_name(name));
        assert!(h.contains(&decl), "sbpf_rt.h declares no {decl}");
    }
    // `sbpf_crypto.h`'s are the software signature checks: murmur3 of their names, and *not*
    // supported by the interpreter (so `sbpf_syscall` must trap on them, as `dispatch` does).
    let crypto = defines(&crypto_header(), "SBPF_SYSCALL_");
    assert_eq!(crypto.len(), 2);
    for (_, v, tail) in &crypto {
        let name = tail.trim_start_matches("/*").split_whitespace().next().unwrap();
        assert_eq!(parse_num(v), u64::from(murmur3_32(name.as_bytes(), 0)), "{name}");
        assert!(!SUPPORTED.iter().any(|(_, n)| *n == name), "{name}");
    }
}

#[test]
fn the_machine_constants_are_the_interpreters() {
    let h = header();
    let get = |n: &str| -> u64 {
        let d = defines(&h, "SBPF_");
        parse_num(&d.iter().find(|(name, _, _)| name == n).unwrap_or_else(|| panic!("SBPF_{n}")).1)
    };
    assert_eq!(get("REGION_PROGRAM"), REGION_PROGRAM);
    assert_eq!(get("REGION_STACK"), REGION_STACK);
    assert_eq!(get("REGION_HEAP"), REGION_HEAP);
    assert_eq!(get("REGION_INPUT"), REGION_INPUT);
    assert_eq!(get("STACK_FRAME"), STACK_FRAME as u64);
    assert_eq!(get("MAX_CALL_DEPTH"), MAX_CALL_DEPTH as u64);
    assert_eq!(get("STACK_BYTES"), STACK_BYTES as u64);
    assert_eq!(get("HEAP_BYTES"), HEAP_BYTES as u64);
    assert_eq!(get("MAX_INSTRUCTIONS"), MAX_INSTRUCTIONS);
}

// ---------------------------------------------------------------------------------------------
// The differential.

#[derive(Clone, Debug)]
enum Op {
    Ld(u64, u64),
    St(u64, u64, u64),
    Sys(u32, [u64; 5]),
}

#[derive(Clone, Debug)]
struct Case {
    text: Vec<u8>,
    text_va: u64,
    rodata: Vec<u8>,
    rodata_va: u64,
    input: Vec<u8>,
    ops: Vec<Op>,
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &x in b {
        h = (h ^ u64::from(x)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A halt as the runtime reports it: (code, payload). The code is the variant's index in the
/// header, checked against the source by the tests above.
fn halt_code(h: &Halt) -> (u32, u64) {
    let names = halt_variants_in_source();
    let code = names.iter().position(|n| n == halt_name(h)).unwrap() as u32;
    let arg = match *h {
        Halt::AccessViolation(a) => a,
        Halt::BadInsn(o) => u64::from(o),
        Halt::UnknownSyscall(x) => u64::from(x),
        Halt::Trap(s) => header_traps().iter().find(|(_, t)| t == s).unwrap_or_else(|| panic!("{s}")).0,
        _ => 0,
    };
    (code, arg)
}

/// One case through `sbpf-core`, printed as `driver.c` prints it.
fn interpret(c: &Case) -> String {
    let program = Program {
        text: &c.text,
        text_va: c.text_va,
        rodata: &c.rodata,
        rodata_va: c.rodata_va,
        entry_pc: 0,
        relocs_applied: false,
    };
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let mut input = c.input.clone();
    let mut out = String::new();
    let heap_used;
    {
        let mem = Memory {
            text: program.text,
            text_va: program.text_va,
            rodata: program.rodata,
            rodata_base: program.rodata_va,
            stack: (&mut stack[..]).try_into().unwrap(),
            heap: (&mut heap[..]).try_into().unwrap(),
            input: &mut input,
        };
        let mut host = HostRef;
        let mut vm = Vm::new(&mut host, &program, mem);
        for op in &c.ops {
            let r = match *op {
                Op::Ld(a, n) => vm.mem.load(a, n as usize),
                Op::St(a, n, v) => vm.mem.store(a, n as usize, v).map(|_| 0),
                Op::Sys(hash, args) => {
                    vm.regs[1..6].copy_from_slice(&args);
                    syscalls::dispatch(&mut vm, hash).map(|_| vm.regs[0])
                }
            };
            match r {
                Ok(v) => writeln!(out, "ok {v}").unwrap(),
                Err(h) => {
                    let (code, arg) = halt_code(&h);
                    writeln!(out, "halt {code} {arg}").unwrap();
                    break;
                }
            }
        }
        heap_used = vm.heap_used;
    }
    writeln!(out, "input {}", hex(&input)).unwrap();
    writeln!(out, "stack {:016x}\nheap {:016x}\nheap_used {heap_used}", fnv(&stack), fnv(&heap)).unwrap();
    out
}

fn case_text(c: &Case) -> String {
    let mut s = String::new();
    writeln!(s, "case\ntext {}\ntext_va {}", hex(&c.text), c.text_va).unwrap();
    writeln!(s, "rodata {}\nrodata_va {}\ninput {}", hex(&c.rodata), c.rodata_va, hex(&c.input)).unwrap();
    for op in &c.ops {
        match *op {
            Op::Ld(a, n) => writeln!(s, "ld {a} {n}").unwrap(),
            Op::St(a, n, v) => writeln!(s, "st {a} {n} {v}").unwrap(),
            Op::Sys(h, a) => writeln!(s, "sys {h} {} {} {} {} {}", a[0], a[1], a[2], a[3], a[4]).unwrap(),
        }
    }
    s.push_str("end\n");
    s
}

/// Whether a host C compiler (`cc`) runs. The two tests that compile `sbpf-rt` for the host skip,
/// saying why, without one — this crate's default suite must not need a C toolchain, as
/// `rand-guest/tests/sbpf_rt.rs` skips without a RISC-V clang.
fn host_cc() -> bool {
    let found = Command::new("cc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        eprintln!("no host C compiler (`cc`); skipping the sbpf-rt host build");
    }
    found
}

/// Warnings are shown, not fatal: which ones fire depends on the host compiler and its version, and
/// a new one must not fail this suite on someone else's machine.
fn cc(out: &Path, extra: &[&str], srcs: &[&str]) {
    let d = rt_dir();
    let mut cmd = Command::new("cc");
    cmd.args(["-O1", "-Wall", "-Wextra", "-o"]).arg(out).args(extra);
    for s in srcs {
        cmd.arg(d.join(s));
    }
    let o = cmd.output().expect("a host C compiler (`cc`)");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// Runs every case through the driver in one process; returns each case's transcript.
fn drive(cases: &[Case]) -> Vec<String> {
    let tmp = tempfile_dir();
    let exe = tmp.join("sbpf_rt_driver");
    cc(&exe, &[], &["test/driver.c", "test/host_glue.c", "sbpf_rt.c"]);
    let mut child = Command::new(&exe).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    // Written from another thread: the driver answers as it reads, and a pipe full both ways
    // would otherwise deadlock.
    let mut stdin = child.stdin.take().unwrap();
    let input: String = cases.iter().map(case_text).collect();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let o = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap();
    // Each case's transcript ends with its `heap_used` line.
    let mut out = Vec::new();
    let mut cur = String::new();
    for l in text.lines() {
        cur.push_str(l);
        cur.push('\n');
        if l.starts_with("heap_used ") {
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

fn tempfile_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbpf_rt_{}_{:?}", std::process::id(), std::thread::current().id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// SplitMix64: a fixed stream, so the random cases never move with a `rand` upgrade.
struct Mix(u64);
impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

const TV: u64 = REGION_PROGRAM + 0x120;
const RV: u64 = REGION_PROGRAM + 0x100;
const IN: u64 = REGION_INPUT;

/// The v1 shape (the rodata run contains the text) or the text placed after the rodata.
fn layout(split: bool, input_len: usize) -> Case {
    let rodata: Vec<u8> = (0..256u32).map(|i| (0xa0 ^ i) as u8).collect();
    let (text, text_va) = if split {
        ((0..64u8).map(|i| 0x50 + i).collect(), REGION_PROGRAM + 0x200)
    } else {
        (rodata[0x20..0x60].to_vec(), TV)
    };
    Case { text, text_va, rodata, rodata_va: RV, input: (0..input_len).map(|i| i as u8).collect(), ops: vec![] }
}

fn pair(ptr: u64, len: u64) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..8].copy_from_slice(&ptr.to_le_bytes());
    p[8..].copy_from_slice(&len.to_le_bytes());
    p
}

fn directed() -> Vec<Case> {
    use syscalls::*;
    let mut v = Vec::new();
    fn c_(v: &mut Vec<Case>, split: bool, n: usize, ops: Vec<Op>) {
        let mut k = layout(split, n);
        k.ops = ops;
        v.push(k);
    }
    let s = |h: u32, a: &[u64]| {
        let mut r = [0u64; 5];
        r[..a.len()].copy_from_slice(a);
        Op::Sys(h, r)
    };
    // Region edges, every width, both layouts, and an empty input region.
    for split in [false, true] {
        let mut ops = vec![];
        for addr in [
            0x10,
            RV - 1,
            RV,
            RV + 0xf8,
            RV + 0xf9,
            RV + 0xfc,
            RV + 0x100,
            TV,
            REGION_PROGRAM + 0x238,
            REGION_PROGRAM + 0x239,
            REGION_STACK + STACK_BYTES as u64 - 8,
            REGION_STACK + STACK_BYTES as u64 - 7,
            REGION_HEAP + HEAP_BYTES as u64 - 1,
            REGION_HEAP + HEAP_BYTES as u64,
            IN + 120,
            IN + 121,
            IN + 0xffff_fffc,
            0x5_0000_0000,
            u64::MAX,
        ] {
            for n in [1, 2, 4, 8] {
                c_(&mut v, split, 128, vec![Op::Ld(addr, n)]);
                c_(&mut v, split, 128, vec![Op::St(addr, n, 0x1122_3344_5566_7788), Op::Ld(addr, n)]);
            }
        }
        ops.push(Op::Ld(IN, 1));
        c_(&mut v, split, 0, ops);
    }
    c_(&mut v, false, 0, vec![s(SOL_MEMSET, &[IN, 1, 0])]);
    c_(&mut v, false, 0, vec![s(SOL_MEMSET, &[IN + 1, 1, 0])]);
    // The memory syscalls: research/tests/sbpf_interp.rs's list against solana-sbpf, and more.
    let at = |o: u64| IN + o;
    for a in [
        [at(0), 0xab, 8],
        [at(0), 0x1ab, 0],
        [at(120), 0xab, 9],
        [at(0), 0xab, 1 << 40],
        [at(0), 0xab, u64::MAX],
        [0, 0xab, 4],
        [at(126), 0xab, 4],
        [at(128), 0xab, 0],
        [at(129), 0xab, 0],
        [RV, 0, 1],
        [REGION_HEAP + 100, 7, 200],
    ] {
        c_(&mut v, false, 128, vec![s(SOL_MEMSET, &a)]);
    }
    for h in [SOL_MEMCPY, SOL_MEMMOVE] {
        for a in [
            [at(64), at(0), 32],
            [at(8), at(0), 8],
            [at(7), at(0), 8],
            [at(4), at(0), 8],
            [at(0), at(4), 8],
            [at(120), at(0), 9],
            [at(4), at(0), 100],
            [at(0), at(4), 100],
            [at(60), at(0), 68],
            [at(0), at(0), 128],
            [at(0), at(64), 100],
            [0x10, 0x11, 8],
            [0x10, at(200), 8],
            [at(121), at(0), 8],
            [RV, at(0), 8],
            [at(0), RV, 8],
            [at(0), TV, 64],
            [at(128), at(0), 0],
            [at(129), at(0), 0],
            [REGION_HEAP, at(0), 128],
            [at(0), at(1), 1 << 40],
            [at(0), at(1), u64::MAX],
            [REGION_STACK + 5, REGION_STACK, 4000],
        ] {
            c_(&mut v, false, 128, vec![s(h, &a)]);
        }
    }
    let mut lt = layout(false, 128);
    lt.input[0] = 5;
    lt.input[64] = 9;
    for a in [
        [at(0), at(64), 8, at(100)],
        [at(0), at(64), 8, at(126)],
        [at(0), at(64), 8, at(124)],
        [at(0), at(64), 100, at(100)],
        [at(100), at(0), 100, at(0)],
        [at(0), at(0), 8, RV],
        [RV, TV, 8, at(0)],
        [at(0), at(64), 0, at(0)],
        [at(64), at(0), 64, at(0)],
        [at(0), at(1), 1 << 40, at(0)],
    ] {
        let mut k = lt.clone();
        k.ops = vec![s(SOL_MEMCMP, &a)];
        v.push(k);
    }
    let mut late = layout(false, 128);
    for i in 0..64 {
        late.input[64 + i] = late.input[i];
    }
    late.input[70] = 0xff;
    late.ops = vec![s(SOL_MEMCMP, &[at(0), at(64), 64, at(0)]), s(SOL_MEMCMP, &[at(64), at(0), 64, at(4)])];
    v.push(late);
    // The allocator, one call and sequences.
    for size in [0u64, 1, 7, 8, 9, 4096, HEAP_BYTES as u64, HEAP_BYTES as u64 + 1, 1 << 32, (1 << 32) + 8, 1 << 40, u64::MAX] {
        let mut k = layout(false, 128);
        k.ops = vec![s(SOL_ALLOC_FREE, &[size, 0]), s(SOL_ALLOC_FREE, &[1, 0])];
        v.push(k);
        // With the cursor already moved, so `base + size` wraps for the largest sizes: only the
        // interpreter's `checked_add` / `size <= HEAP_BYTES` stops those being taken as small.
        let mut k = layout(false, 128);
        k.ops = vec![s(SOL_ALLOC_FREE, &[1, 0]), s(SOL_ALLOC_FREE, &[size, 0]), s(SOL_ALLOC_FREE, &[1, 0])];
        v.push(k);
    }
    let mut k = layout(false, 128);
    k.ops = vec![s(SOL_ALLOC_FREE, &[1, 0]), s(SOL_ALLOC_FREE, &[u64::MAX - 7, 0]), s(SOL_ALLOC_FREE, &[1, 0])];
    v.push(k);
    let mut k = layout(false, 128);
    k.ops = vec![
        s(SOL_ALLOC_FREE, &[1, 0]),
        s(SOL_ALLOC_FREE, &[1, 0]),
        s(SOL_ALLOC_FREE, &[0, 0]),
        s(SOL_ALLOC_FREE, &[9, 0]),
        s(SOL_ALLOC_FREE, &[8, REGION_HEAP + 16]),
        s(SOL_ALLOC_FREE, &[HEAP_BYTES as u64 - 32, 0]),
        s(SOL_ALLOC_FREE, &[1, 0]),
        s(SOL_ALLOC_FREE, &[0, 0]),
    ];
    v.push(k);
    // Logs, aborts, the unknown.
    for a in [[at(0), 13], [at(120), 9], [at(128), 0], [RV, 8], [at(0), 1 << 32], [0x10, 0]] {
        c_(&mut v, false, 128, vec![s(SOL_LOG, &a)]);
    }
    for a in [at(96), at(97), 0] {
        c_(&mut v, false, 128, vec![s(SOL_LOG_PUBKEY, &[a])]);
    }
    c_(&mut v, false, 128, vec![s(SOL_LOG_64, &[1, 2, 3, 4, 5]), s(SOL_LOG_COMPUTE_UNITS, &[0x10])]);
    c_(&mut v, false, 128, vec![s(ABORT, &[]), s(SOL_LOG_64, &[])]);
    c_(&mut v, false, 128, vec![s(SOL_PANIC, &[0, 1 << 40, 0, 0])]);
    for h in [1u32, murmur3_32(b"sol_invoke_signed_c", 0), murmur3_32(b"sol_invoke_signed_rust", 0),
              murmur3_32(b"sol_secp256k1_recover", 0), murmur3_32(b"sol_set_return_data", 0)] {
        c_(&mut v, false, 128, vec![s(h, &[])]);
    }
    // sol_sha256: pieces across regions, the empty cases, the order of the checks.
    let mut k = layout(false, 128);
    k.input[32..35].copy_from_slice(b"abc");
    k.input[..16].copy_from_slice(&pair(at(32), 2));
    k.input[16..32].copy_from_slice(&pair(RV + 3, 5));
    k.ops = vec![
        s(SOL_SHA256, &[at(0), 2, at(64)]),
        s(SOL_SHA256, &[at(0), 0, at(96)]),
        s(SOL_SHA256, &[at(0), 1, at(96)]),
    ];
    v.push(k);
    for a in [
        [at(120), 1, at(200)],
        [at(0), 1, at(100)],
        [at(0), 9, at(64)],
        [at(0), 1, RV],
        [at(0), 1 << 32, at(64)],
        [at(0), u64::MAX / 16 + 1, at(64)],
    ] {
        let mut k = layout(false, 128);
        k.input[..16].copy_from_slice(&pair(at(200), 1));
        k.ops = vec![s(SOL_SHA256, &a)];
        v.push(k);
    }
    let mut k = layout(false, 128);
    k.input[..16].copy_from_slice(&pair(at(32), 1 << 32));
    k.ops = vec![s(SOL_SHA256, &[at(0), 1, at(64)])];
    v.push(k);
    // Many pairs, laid out in the heap by memmove/memset first, crossing block boundaries.
    let mut k = layout(false, 128);
    let mut ops = vec![s(SOL_MEMSET, &[REGION_HEAP + 4096, b'a' as u64, 1000])];
    for i in 0..40u64 {
        let p = pair(REGION_HEAP + 4096 + i, 17 + 3 * i);
        for (j, b) in p.iter().enumerate() {
            ops.push(Op::St(REGION_HEAP + 16 * i + j as u64, 1, u64::from(*b)));
        }
    }
    ops.push(s(SOL_SHA256, &[REGION_HEAP, 40, at(0)]));
    ops.push(s(SOL_SHA256, &[REGION_HEAP, 39, at(32)]));
    k.ops = ops;
    v.push(k);
    v
}

/// Random ops: addresses at and around every region's edges, lengths at the chunk and region
/// boundaries and past `u32`, over random region bytes with (ptr, len) pairs sprinkled in.
fn random(n: usize) -> Vec<Case> {
    use syscalls::*;
    let mut m = Mix(0x7362_7066_2d72_74); // "sbpf-rt"
    let mut out = Vec::new();
    for _ in 0..n {
        let split = m.below(2) == 1;
        let input_len = m.pick(&[0usize, 1, 16, 128, 200]);
        let mut c = layout(split, input_len);
        for b in c.input.iter_mut() {
            *b = m.next() as u8;
        }
        let bases: [(u64, u64); 6] = [
            (0, 64),
            (RV, 256),
            (REGION_STACK, STACK_BYTES as u64),
            (REGION_HEAP, HEAP_BYTES as u64),
            (IN, input_len as u64),
            (0x5_0000_0000, 64),
        ];
        let ptr = |m: &mut Mix| -> u64 {
            let (b, len) = m.pick(&bases);
            let off = match m.below(6) {
                0 => 0,
                1 => len.saturating_sub(m.below(9)),
                2 => len + m.below(3),
                3 => m.below(len.max(1)),
                4 => 0xffff_ffff - m.below(8),
                _ => m.below(0x40),
            };
            if m.below(40) == 0 { m.next() } else { b + off }
        };
        let len = |m: &mut Mix| -> u64 {
            match m.below(8) {
                0 => m.pick(&[0, 1, 8, 16, 32, 63, 64, 65, 100, 128, 129]),
                1 => m.pick(&[1u64 << 32, (1 << 32) + 3, 1 << 40, u64::MAX, u64::MAX / 16 + 1]),
                2 => HEAP_BYTES as u64 - m.below(16),
                _ => m.below(140),
            }
        };
        // Sprinkle (ptr, len) pairs into the input for sol_sha256 to find.
        let mut i = 0;
        while i + 16 <= c.input.len() && m.below(3) != 0 {
            let p = pair(ptr(&mut m), m.below(80));
            c.input[i..i + 16].copy_from_slice(&p);
            i += 16;
        }
        for _ in 0..1 + m.below(6) {
            let op = match m.below(11) {
                0 => Op::Ld(ptr(&mut m), m.pick(&[1, 2, 4, 8])),
                1 => Op::St(ptr(&mut m), m.pick(&[1, 2, 4, 8]), m.next()),
                2 => Op::Sys(SOL_MEMCPY, [ptr(&mut m), ptr(&mut m), len(&mut m), 0, 0]),
                3 => Op::Sys(SOL_MEMMOVE, [ptr(&mut m), ptr(&mut m), len(&mut m), 0, 0]),
                4 => Op::Sys(SOL_MEMSET, [ptr(&mut m), m.next(), len(&mut m), 0, 0]),
                5 => Op::Sys(SOL_MEMCMP, [ptr(&mut m), ptr(&mut m), len(&mut m), ptr(&mut m), 0]),
                6 => Op::Sys(SOL_ALLOC_FREE, [len(&mut m), if m.below(4) == 0 { m.next() } else { 0 }, 0, 0, 0]),
                7 => Op::Sys(SOL_SHA256, [ptr(&mut m), m.pick(&[0, 1, 2, 3, 1 << 32]), ptr(&mut m), 0, 0]),
                8 => Op::Sys(SOL_LOG, [ptr(&mut m), len(&mut m), 0, 0, 0]),
                9 => Op::Sys(SOL_LOG_PUBKEY, [ptr(&mut m), 0, 0, 0, 0]),
                _ => {
                    let other = m.next() as u32;
                    let h = m.pick(&[ABORT, SOL_PANIC, SOL_LOG_64, SOL_LOG_COMPUTE_UNITS, other]);
                    Op::Sys(h, [m.next(), m.next(), 0, 0, 0])
                }
            };
            c.ops.push(op);
        }
        out.push(c);
    }
    out
}

#[test]
fn every_region_access_and_syscall_matches_the_interpreter() {
    if !host_cc() {
        return;
    }
    let mut cases = directed();
    let n_directed = cases.len();
    cases.extend(random(4000));
    let got = drive(&cases);
    assert_eq!(got.len(), cases.len(), "the driver printed one transcript per case");
    let mut halts = [0usize; 11];
    for (i, (c, g)) in cases.iter().zip(&got).enumerate() {
        let want = interpret(c);
        assert_eq!(*g, want, "case {i} ({}):\n{}", if i < n_directed { "directed" } else { "random" }, case_text(c));
        for l in want.lines().filter_map(|l| l.strip_prefix("halt ")) {
            halts[l.split(' ').next().unwrap().parse::<usize>().unwrap()] += 1;
        }
    }
    // The stream must actually reach the halts it is meant to compare.
    let names = halt_variants_in_source();
    for (code, name) in [(1, "AccessViolation"), (4, "UnknownSyscall"), (10, "Trap")] {
        assert_eq!(names[code], name);
        assert!(halts[code] > 20, "only {} {name} halts", halts[code]);
    }
    eprintln!("{} cases ({n_directed} directed); halts by code {halts:?}", cases.len());
}

#[test]
fn the_c_suite_passes_in_both_usize_widths() {
    if !host_cc() {
        return;
    }
    let tmp = tempfile_dir();
    let srcs = ["test/host_test.c", "test/host_glue.c", "sbpf_rt.c", "sbpf_bn.c", "sbpf_ed25519.c", "sbpf_secp256k1.c"];
    for (name, extra) in [("host64", vec![]), ("host32", vec!["-DSBPF_USIZE_MAX=0xffffffffu"])] {
        let exe = tmp.join(name);
        cc(&exe, &extra, &srcs);
        let o = Command::new(&exe).current_dir(rt_dir()).output().unwrap();
        let s = String::from_utf8_lossy(&o.stdout);
        assert!(o.status.success() && s.contains(" 0 failures"), "{name}:\n{s}");
    }
}
