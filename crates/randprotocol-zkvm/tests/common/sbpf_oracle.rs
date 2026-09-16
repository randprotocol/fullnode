//! `solana-sbpf` 0.11.1 as the differential oracle for `sbpf-core` (M4.4 Task 5).
//!
//! It lives here rather than in `randprotocol_zkvm::sbpf` because it is a dev-dependency: the library's
//! `src/sbpf.rs` is part of the public API and cannot name it.
//!
//! The oracle is pinned to the same machine `sbpf-core` models: `SBPFVersion::V0` — which is what
//! the M4.4 plan calls "SBPF v1", the fixed-frame format a non-upgradeable BPFLoader2 program is
//! built for; the crate's own `V1` is SIMD-0166's *dynamic* frames, which came later. The geometry
//! comes from `sbpf_core::memory` rather than being written down twice — `STACK_FRAME` times
//! `MAX_CALL_DEPTH`, no gaps between frames — plus the 200 000-instruction meter.
//!
//! Only the interpreter is used, never the JIT (`default-features = false` keeps it out of the
//! build entirely), so the comparison is interpreter against interpreter.

use std::cell::Cell;
use std::sync::Arc;

use solana_sbpf::declare_builtin_function;
use solana_sbpf::ebpf;
use solana_sbpf::elf::Executable;
use solana_sbpf::error::{EbpfError, ProgramResult};
use solana_sbpf::memory_region::{MemoryMapping, MemoryRegion};
use solana_sbpf::program::{BuiltinProgram, FunctionRegistry, SBPFVersion};
use solana_sbpf::vm::{Config, ContextObject, EbpfVm};

use sbpf_core::interp::MAX_INSTRUCTIONS;
use sbpf_core::memory::{HEAP_BYTES, MAX_CALL_DEPTH, STACK_BYTES, STACK_FRAME};

/// The instruction meter, as a `ContextObject`. `solana-sbpf`'s own `TestContextObject` lives in
/// the crate's test-only `test_utils` module and is not published, so this is the same thing: a
/// countdown with no tracing.
pub struct Meter {
    remaining: u64,
}

impl ContextObject for Meter {
    fn trace(&mut self, _state: [u64; 12]) {}
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }
    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

type Ctx = Meter;
type SyscallResult = Result<u64, Box<dyn std::error::Error>>;

/// The one configuration every oracle run uses: SBPF v1's semantics on `sbpf-core`'s geometry.
pub fn config() -> Config {
    Config {
        max_call_depth: MAX_CALL_DEPTH,
        stack_frame_size: STACK_FRAME,
        enable_stack_frame_gaps: false,
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V0,
        ..Config::default()
    }
}

// The bump allocator `sol_alloc_free_` hands out of, as a thread-local cursor: the oracle's
// context object has nowhere to keep it, and an oracle run is single-threaded.
thread_local! {
    static HEAP_USED: Cell<usize> = const { Cell::new(0) };
}

// The syscalls, mirroring `sbpf_core::syscalls` exactly. Every one goes through the safe
// `MemoryMapping::load`/`store` API rather than raw host pointers, which is slower than the real
// runtime's and irrelevant: what is compared is the answer.
declare_builtin_function!(
    SyscallAbort,
    fn rust(_ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64, _m: &mut MemoryMapping,
    ) -> SyscallResult {
        Err("abort".into())
    }
);

declare_builtin_function!(
    SyscallPanic,
    fn rust(_ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64, _m: &mut MemoryMapping,
    ) -> SyscallResult {
        Err("sol_panic_".into())
    }
);

declare_builtin_function!(
    SyscallLog,
    fn rust(_ctx: &mut Ctx, addr: u64, len: u64, _c: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        validate(m, addr, len)?;
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallLogPubkey,
    fn rust(_ctx: &mut Ctx, addr: u64, _b: u64, _c: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        validate(m, addr, 32)?;
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallNoop,
    fn rust(_ctx: &mut Ctx, _a: u64, _b: u64, _c: u64, _d: u64, _e: u64, _m: &mut MemoryMapping,
    ) -> SyscallResult {
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallMemcpy,
    fn rust(_ctx: &mut Ctx, dst: u64, src: u64, n: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        if !nonoverlapping(dst, src, n) {
            return Err("sol_memcpy_ overlap".into());
        }
        copy(m, dst, src, n)
    }
);

declare_builtin_function!(
    SyscallMemmove,
    fn rust(_ctx: &mut Ctx, dst: u64, src: u64, n: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        copy(m, dst, src, n)
    }
);

declare_builtin_function!(
    SyscallMemset,
    fn rust(_ctx: &mut Ctx, dst: u64, c: u64, n: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        validate(m, dst, n)?;
        for i in 0..n {
            store_u8(m, dst.wrapping_add(i), c as u8)?;
        }
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallMemcmp,
    fn rust(_ctx: &mut Ctx, a: u64, b: u64, n: u64, out: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        // Agave translates both inputs as whole slices and the result as a whole `&mut i32` before
        // comparing a single byte, so a range that runs out — or a four-byte result that does not
        // fit — fails with nothing written. Validating lazily instead would let this oracle write a
        // partial result that the real runtime never would (which is how the first run of
        // `the_memory_syscalls_agree_with_solana_sbpf` caught this).
        validate(m, a, n)?;
        validate(m, b, n)?;
        validate(m, out, 4)?;
        let mut result = 0i32;
        for i in 0..n {
            let x = load_u8(m, a.wrapping_add(i))?;
            let y = load_u8(m, b.wrapping_add(i))?;
            if x != y {
                result = i32::from(x) - i32::from(y);
                break;
            }
        }
        match m.store::<u32>(result as u32, out) {
            ProgramResult::Ok(_) => Ok(0),
            ProgramResult::Err(e) => Err(Box::new(e)),
        }
    }
);

declare_builtin_function!(
    SyscallAllocFree,
    fn rust(_ctx: &mut Ctx, size: u64, free: u64, _c: u64, _d: u64, _e: u64, _m: &mut MemoryMapping,
    ) -> SyscallResult {
        if free != 0 {
            return Ok(0);
        }
        let base = (HEAP_USED.get() + 7) & !7;
        match base.checked_add(size as usize) {
            Some(end) if end <= HEAP_BYTES && size <= HEAP_BYTES as u64 => {
                HEAP_USED.set(end);
                Ok(ebpf::MM_HEAP_START + base as u64)
            }
            _ => Ok(0),
        }
    }
);

declare_builtin_function!(
    SyscallSha256,
    fn rust(_ctx: &mut Ctx, vals: u64, n: u64, out: u64, _d: u64, _e: u64, m: &mut MemoryMapping,
    ) -> SyscallResult {
        // As above: the pairs array and the 32-byte result are translated whole before anything is
        // read or written, so a partial digest is never left behind.
        validate(m, vals, n.saturating_mul(16))?;
        validate(m, out, 32)?;
        let mut msg: Vec<u8> = Vec::new();
        for p in 0..n {
            let at = vals.wrapping_add(16 * p);
            let mut pair = [0u8; 16];
            for (i, byte) in pair.iter_mut().enumerate() {
                *byte = load_u8(m, at.wrapping_add(i as u64))?;
            }
            let ptr = u64::from_le_bytes(pair[0..8].try_into().unwrap());
            let len = u64::from_le_bytes(pair[8..16].try_into().unwrap());
            for i in 0..len {
                msg.push(load_u8(m, ptr.wrapping_add(i))?);
            }
        }
        let digest = randprotocol_zkvm::sha256::sha256(&msg);
        for (i, byte) in digest.iter().enumerate() {
            store_u8(m, out.wrapping_add(i as u64), *byte)?;
        }
        Ok(0)
    }
);

fn nonoverlapping(a: u64, b: u64, n: u64) -> bool {
    if a > b {
        a - b >= n
    } else {
        b - a >= n
    }
}

fn copy(m: &mut MemoryMapping, dst: u64, src: u64, n: u64) -> SyscallResult {
    // Validate both ranges before moving a byte, as `sbpf-core` and Agave both do.
    validate(m, src, n)?;
    validate(m, dst, n)?;
    let bytes: Vec<u8> = (0..n).map(|i| load_u8(m, src.wrapping_add(i)).unwrap()).collect();
    for (i, byte) in bytes.iter().enumerate() {
        store_u8(m, dst.wrapping_add(i as u64), *byte)?;
    }
    Ok(0)
}

/// Every byte of `addr..addr + n` is readable — the whole-range translation Agave's syscalls do
/// before they touch anything, so a syscall either does all of its work or none of it.
fn validate(m: &MemoryMapping, addr: u64, n: u64) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..n {
        load_u8(m, addr.wrapping_add(i))?;
    }
    Ok(())
}

fn load_u8(m: &MemoryMapping, addr: u64) -> Result<u8, Box<dyn std::error::Error>> {
    match m.load::<u8>(addr) {
        ProgramResult::Ok(v) => Ok(v as u8),
        ProgramResult::Err(e) => Err(Box::new(e)),
    }
}

fn store_u8(m: &MemoryMapping, addr: u64, v: u8) -> Result<(), Box<dyn std::error::Error>> {
    match m.store::<u8>(v, addr) {
        ProgramResult::Ok(_) => Ok(()),
        ProgramResult::Err(e) => Err(Box::new(e)),
    }
}

/// The loader every oracle run shares: the config above plus the twelve syscalls `sbpf-core`
/// implements, registered under exactly the names whose murmur3 hashes the ELF's `call` immediates
/// carry.
fn loader() -> Arc<BuiltinProgram<Ctx>> {
    let mut l = BuiltinProgram::new_loader(config());
    l.register_function("abort", SyscallAbort::vm).unwrap();
    l.register_function("sol_panic_", SyscallPanic::vm).unwrap();
    l.register_function("sol_log_", SyscallLog::vm).unwrap();
    l.register_function("sol_log_64_", SyscallNoop::vm).unwrap();
    l.register_function("sol_log_compute_units_", SyscallNoop::vm).unwrap();
    l.register_function("sol_log_pubkey", SyscallLogPubkey::vm).unwrap();
    l.register_function("sol_memcpy_", SyscallMemcpy::vm).unwrap();
    l.register_function("sol_memmove_", SyscallMemmove::vm).unwrap();
    l.register_function("sol_memset_", SyscallMemset::vm).unwrap();
    l.register_function("sol_memcmp_", SyscallMemcmp::vm).unwrap();
    l.register_function("sol_alloc_free_", SyscallAllocFree::vm).unwrap();
    l.register_function("sol_sha256", SyscallSha256::vm).unwrap();
    Arc::new(l)
}

/// What the oracle's loader made of an ELF, in the terms `sbpf_core::elf::Program` uses.
pub struct Loaded {
    pub entry_pc: usize,
    pub text_va: u64,
    pub text: Vec<u8>,
    pub rodata_va: u64,
    pub rodata: Vec<u8>,
}

/// Loads `elf` through `solana-sbpf`'s own loader, relocations applied.
pub fn load(elf: &[u8]) -> Result<Loaded, String> {
    let exe = Executable::<Ctx>::from_elf(elf, loader()).map_err(|e| format!("{e:?}"))?;
    let (text_va, text) = exe.get_text_bytes();
    let ro = exe.get_ro_region();
    // `MemoryRegion`'s host span is what the region serves; read it back through the mapping so
    // nothing here needs a raw pointer.
    let rodata_va = ro.vm_addr;
    let rodata_len = (ro.vm_addr_end - ro.vm_addr) as usize;
    let mapping = MemoryMapping::new(vec![ro], exe.get_config(), exe.get_sbpf_version())
        .map_err(|e| format!("{e:?}"))?;
    let mut rodata = Vec::with_capacity(rodata_len);
    for i in 0..rodata_len {
        match mapping.load::<u8>(rodata_va + i as u64) {
            ProgramResult::Ok(v) => rodata.push(v as u8),
            ProgramResult::Err(e) => return Err(format!("{e:?}")),
        }
    }
    Ok(Loaded { entry_pc: exe.get_entrypoint_instruction_offset(), text_va, text: text.to_vec(), rodata_va, rodata })
}

/// Runs a bare text section, and returns `r0` (or the fault) with the input region's post-state.
pub fn run_text(text: &[u8], input: &[u8]) -> (Result<u64, String>, Vec<u8>) {
    run_text_with_calls(text, &[], input)
}

/// The immediate `solana-sbpf` expects in a `call` to slot `target_pc` of a bare text section: the
/// murmur3 hash of the target pc's little-endian bytes, which is the key its ELF loader registers a
/// SBPF v1 function under (`FunctionRegistry::register_function_hashed_legacy`).
///
/// `sbpf-core` uses a slot-relative immediate instead (see `sbpf_core::interp`), so a call
/// differential has to assemble the same program twice, once in each convention — which is exactly
/// what makes it a test of the *frames*, not of the encoding.
pub fn call_imm_for(target_pc: usize) -> i32 {
    ebpf::hash_symbol_name(&target_pc.to_le_bytes()) as i32
}

/// [`run_text`] with `targets` registered as callable slots, so `call` immediates produced by
/// [`call_imm_for`] resolve.
pub fn run_text_with_calls(
    text: &[u8],
    targets: &[usize],
    input: &[u8],
) -> (Result<u64, String>, Vec<u8>) {
    let mut registry = FunctionRegistry::<usize>::default();
    registry
        .register_function(ebpf::hash_symbol_name(b"entrypoint"), "entrypoint", 0)
        .unwrap();
    for &pc in targets {
        registry
            .register_function(ebpf::hash_symbol_name(&pc.to_le_bytes()), "", pc)
            .unwrap();
    }
    let exe = match Executable::<Ctx>::from_text_bytes(text, loader(), SBPFVersion::V0, registry) {
        Ok(e) => e,
        Err(e) => return (Err(format!("{e:?}")), input.to_vec()),
    };
    execute(exe, input)
}

/// Loads and runs an ELF, and returns `r0` (or the fault) with the input region's post-state.
pub fn run_elf(elf: &[u8], input: &[u8]) -> (Result<u64, String>, Vec<u8>) {
    let exe = match Executable::<Ctx>::from_elf(elf, loader()) {
        Ok(e) => e,
        Err(e) => return (Err(format!("{e:?}")), input.to_vec()),
    };
    execute(exe, input)
}

fn execute(exe: Executable<Ctx>, input: &[u8]) -> (Result<u64, String>, Vec<u8>) {
    HEAP_USED.set(0);
    let config = exe.get_config();
    let mut stack = vec![0u8; STACK_BYTES];
    let mut heap = vec![0u8; HEAP_BYTES];
    let mut mem = input.to_vec();
    let mut ctx = Meter { remaining: MAX_INSTRUCTIONS };
    let result = {
        let regions = vec![
            exe.get_ro_region(),
            MemoryRegion::new_writable(&mut stack, ebpf::MM_STACK_START),
            MemoryRegion::new_writable(&mut heap, ebpf::MM_HEAP_START),
            MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START),
        ];
        let mapping = match MemoryMapping::new(regions, config, exe.get_sbpf_version()) {
            Ok(m) => m,
            Err(e) => return (Err(format!("{e:?}")), input.to_vec()),
        };
        let stack_len = STACK_BYTES;
        let mut vm =
            EbpfVm::new(exe.get_loader().clone(), exe.get_sbpf_version(), &mut ctx, mapping, stack_len);
        let (_count, result) = vm.execute_program(&exe, true);
        match result {
            ProgramResult::Ok(r0) => Ok(r0),
            ProgramResult::Err(e) => Err(describe(&e)),
        }
    };
    (result, mem)
}

fn describe(e: &EbpfError) -> String {
    format!("{e:?}")
}
