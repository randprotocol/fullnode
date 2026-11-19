//! The entry point of an image that carries its own program (`sbpf2rv`, ZKVM-117): [`abi`]'s harness
//! with no ELF in it.
//!
//! The interpreter's public vector is `[n_elf, elf bytes…, n_sysvars, sysvar bytes…]` and its
//! harness parses, relocates and loads the ELF before it runs anything. A translated image has
//! the program in it — the code as RV32, and the read-only data that code may load
//! ([`baked_rodata`] of the source program: for SPL Token 2 848 bytes of a 108 600-byte ELF) as
//! image data — so its public vector is the sysvar block alone:
//!
//! ```text
//! public:  [n_sysvars, sysvar bytes…]
//! private: [n_input, input bytes…]
//! ```
//!
//! Everything else is [`abi`]'s, unchanged: `check_region`, the three digests, the status mapping.
//! So the eight output words are the ones the interpreter publishes for the same program and
//! instruction.
//!
//! What binds the program: all of it — code, entry, addresses, read-only data — is in the image,
//! so `hc` binds it and nothing else has to. There is no ELF for `H_PUB` to bind and no guard to
//! tie tape bytes to the image; `H_PUB` binds the sysvars, which is all the tape carries.
//!
//! This is a module of its own, declared last in `lib.rs`, on purpose: the interpreter guest's
//! image carries panic locations (file, line, column) of `abi.rs` and `lib.rs`, so a line added
//! above existing code in either moves `sbpf.bin`, which a translated image's entry point has no
//! business doing.

use crate::abi::{
    canonical_input_hash, check_region, malformed_output, output_hash, program_id, public_output,
    read_sysvars, CallEnv, CallInput, Executor, InputCursor, Workspace, EMPTY_RETURN_HASH,
};
use crate::elf::Program;
use crate::interp::Halt;
use crate::memory::Memory;
use crate::{sha256, Host};

/// What a translated image knows of its program without loading an ELF.
///
/// The program has **no text bytes**: its code is the image's own RV32, so `text` is empty and a
/// load from the program's own instructions is an access violation, where the interpreter (which
/// holds them) would return them. `entry_pc` is 0 and unread: the image starts at its baked entry.
#[derive(Clone, Copy)]
pub struct Baked {
    /// The virtual address of the program's first instruction: `callx` resolves a target as
    /// `(addr - text_va) / 8`.
    pub text_va: u64,
    /// The virtual address of the image's first read-only byte.
    pub rodata_va: u64,
}

impl Baked {
    /// The program over `rodata`, the image's copy of the read-only bytes.
    #[inline]
    pub fn program<'a>(&self, rodata: &'a [u8]) -> Program<'a> {
        Program {
            text: &[],
            text_va: self.text_va,
            rodata,
            rodata_va: self.rodata_va,
            entry_pc: 0,
            relocs_applied: true,
        }
    }
}

/// The part of a loaded program's read-only run a translated image carries, and its virtual
/// address: the run without the text when the text is the run's first bytes (every
/// SBPF v1 file: the run begins at `.text`), since translated code never reads the instructions it
/// was translated from — and the whole run otherwise.
#[inline]
pub fn baked_rodata<'a>(p: &Program<'a>) -> (u64, &'a [u8]) {
    let text_leads = p.text_va == p.rodata_va && core::ptr::eq(p.text.as_ptr(), p.rodata.as_ptr());
    match p.rodata.get(p.text.len()..) {
        Some(rest) if text_leads => (p.rodata_va.wrapping_add(p.text.len() as u64), rest),
        _ => (p.rodata_va, p.rodata),
    }
}

/// `abi::run_call_with_executor` for an image that carries its own program: `rodata` is the image's
/// copy of [`baked_rodata`], `baked` its two addresses, and the public vector is the sysvar block
/// alone.
///
/// # Single use
///
/// `ws.stack` and `ws.heap` must be **all zero** on entry, and this function does not make them
/// so: an sBPF program may read a stack slot or a heap byte it never wrote, and what it reads must
/// be zero as it is on the interpreter, which zeroes both before every run. In a guest that is
/// free — the workspace is one `static` in `.bss`, RAM starts zero (`research/docs/01-isa.md`,
/// "RAM starts zero"), and `main` makes exactly one call — which is the only way a translated
/// image calls this. A host caller must pass a fresh `Workspace::ZERO` each time.
#[allow(clippy::too_many_arguments)]
pub fn run_call_baked<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read_public: FP,
    n_public: u32,
    read_private: FS,
    n_private: u32,
    baked: Baked,
    rodata: &[u8],
    exec: Executor<'_, H>,
) -> ([u32; 8], Result<u64, Halt>) {
    let mut pub_c = InputCursor::new(read_public, n_public);
    let mut in_c = InputCursor::new(read_private, n_private);
    // `abi::decode_input` without the ELF: the sysvar block from the public cursor, the instruction
    // from the private one, each refused as the interpreter refuses it — a length above its cap, a
    // vector that ends early, a region that is not the canonical aligned encoding.
    ws.input.elf_len = 0;
    ws.input.input_len = 0;
    ws.input.sysvars_len = 0;
    let decoded = (|| {
        ws.input.sysvars_len = read_sysvars(&mut ws.input.sysvars, &mut pub_c).ok()?;
        ws.input.input_len = in_c.bytes(&mut ws.input.input)?;
        if pub_c.truncated() || in_c.truncated() {
            return None;
        }
        check_region(ws.input.input.get(..ws.input.input_len)?).ok()
    })();
    if decoded.is_none() {
        return (malformed_output(h), Err(Halt::BadElf));
    }
    // `abi::run_decoded`'s body with the load replaced by `Baked::program`; duplicated rather than
    // shared so that the interpreter's own path is not touched.
    let Workspace {
        input: CallInput { input, input_len, sysvars, sysvars_len, .. },
        stack,
        heap,
        return_data,
        return_len,
    } = ws;
    let input_len = *input_len;
    *return_len = 0;

    let id = program_id(&input[..input_len]);
    let input_hash = canonical_input_hash(h, &input[..input_len], &id);
    // The pre-state digest, taken before anything runs: what a status of 0 or 2 binds.
    let pre_output = output_hash(h, &input[..input_len]);

    // No zeroing of the stack and heap: see the `# Single use` note on this function. In the
    // interpreter's harness it is 64 KiB of stores, about 49 000 cycles of a 300 000-cycle call.

    let result = {
        let program = baked.program(rodata);
        let mem = Memory {
            text: program.text,
            text_va: program.text_va,
            rodata: program.rodata,
            rodata_base: program.rodata_va,
            stack,
            heap,
            input: &mut input[..input_len],
        };
        let mut env = CallEnv {
            sysvars: sysvars.get(..*sysvars_len).unwrap_or(&[]),
            program_id: &id,
            return_data,
            return_len,
        };
        exec(h, &program, mem, &mut env)
    };

    let status = match result {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(_) => 2,
    };
    // A status other than 1 binds the pre-state and no return data: nothing happened.
    let (post_output, returned): ([u8; 32], &[u8]) = if status == 1 {
        (output_hash(h, &input[..input_len]), return_data.get(..*return_len).unwrap_or(&[]))
    } else {
        (pre_output, &[])
    };
    let return_hash = if returned.is_empty() { EMPTY_RETURN_HASH } else { sha256(h, returned) };
    (public_output(h, status, &input_hash, &post_output, &return_hash), result)
}
