//! Block context (fullnode issue #168, `docs/evm-block-context.md`; constraint set 11, chain 22):
//! the block-context opcodes read the **public** segment an `InvokeAt` is proved over, never the
//! private input, because a private word is bound only to the salted `H_IN`, which no verifier
//! opens. The ledger builds those words itself from the block the transaction names, so a proof
//! made against any other facts fails `verify_invoke`.
//!
//! # Where the words are
//!
//! An invoke's public segment is `public ‖ call_binding ‖ context`. An EVM program is deployed
//! with an empty `public`, so the context starts at public word [`CONTEXT_BASE`] = 8, after the
//! eight binding words. Offsets below are from the start of the context, as the node's `CTX_*`
//! constants are (`ledger::program_state`):
//!
//! | words | field |
//! |---|---|
//! | 0 | version: 1 for an `Invoke`, **2** ([`CONTEXT_VERSION_BLOCK`]) for an `InvokeAt` |
//! | 11, 12 | `ref_height`, low word then high |
//! | 13, 14 | the reference block's time in seconds (`timestamp_ms / 1000`), low, high |
//! | 15, 16 | the genesis `chain_id`, low, high |
//! | 17, 18 | `basefee`: RAND base units per unit of gas the block's calls paid, low, high |
//! | 19 | `has_randomness`: 1 when 20–27 hold a beacon value, 0 on a chain without the beacon |
//! | 20–27 | the beacon's 32 bytes after block `ref_height`'s reveal, as eight little-endian words |
//!
//! # What each opcode pushes
//!
//! Only under a version-2 context. Under any other version — an ordinary `Invoke` (version 1) —
//! [`value`] is `None` and the opcode traps exactly as it did before this module existed:
//! `Trap(op)`, status 2, the whole limit spent, nothing charged first.
//!
//! | opcode | pushes |
//! |---|---|
//! | `NUMBER` | `ref_height` |
//! | `TIMESTAMP` | the reference block's time, seconds |
//! | `CHAINID` | `chain_id` (the interpreter; a translation keeps its baked `--chain-id`) |
//! | `BASEFEE`, `GASPRICE` | `basefee` (no tips, so the two are equal) |
//! | `PREVRANDAO` | the beacon value, the 32 bytes read big-endian as `bytes32(block.prevrandao)` reads them; **traps** while word 19 is not 1 |
//! | `COINBASE` | 0: fees go to the proposer's register entry, which has no EVM address |
//! | `GASLIMIT` | [`BLOCK_GAS_LIMIT`], the most gas one call's input can carry |
//!
//! `BLOCKHASH`, `SELFBALANCE`, `BLOBHASH` and `BLOBBASEFEE` are not here: they trap whatever the
//! context. `ORIGIN` is `CALLER` under a version-2 context (the interpreter's own arm).
//!
//! # A segment with no context
//!
//! A `Call`'s segment has no context, and a `READ_PUBLIC` past the segment's end can never be
//! satisfied: such a run has **no proof at all**. So the words are read only when one of these
//! opcodes executes, never up front, and a contract that does not reach one behaves exactly as
//! before on every kind of call. A contract that does reach one under a `Call` cannot be proved,
//! where it used to prove a status-2 halt. The host's [`Host::read_public`] cannot model "no
//! proof"; research's `HostRef` answers 0, which is no context version, so on the host such an
//! opcode traps as under a version-1 context.

use crate::u256::U256;
use crate::Host;

/// The first context word's index in the public segment: an EVM program's deploy-time public
/// input is empty, and the eight call-binding words come before the context.
pub const CONTEXT_BASE: u32 = 8;
/// Word 0 of an `InvokeAt`'s context (the node's `CONTEXT_VERSION_BLOCK`).
pub const CONTEXT_VERSION_BLOCK: u32 = 2;
/// The node's `CTX_*` offsets, from the start of the context.
pub const CTX_REF_HEIGHT: u32 = 11;
pub const CTX_TIMESTAMP: u32 = 13;
pub const CTX_CHAIN_ID: u32 = 15;
pub const CTX_BASEFEE: u32 = 17;
pub const CTX_HAS_RANDOMNESS: u32 = 19;
pub const CTX_RANDOMNESS: u32 = 20;
/// What `GASLIMIT` pushes under a version-2 context: a call's `gas_limit` is one input word, so
/// no call can be given more than this, which is the one property a contract may rely on in a
/// block gas limit. Rand has no EVM block gas limit of its own (a block is priced in Rand gas, a
/// cycle-based unit).
pub const BLOCK_GAS_LIMIT: u64 = u32::MAX as u64;

/// Whether the public segment carries a version-2 context: word 0 of the context is 2.
pub fn is_block_context<H: Host>(h: &mut H) -> bool {
    h.read_public(CONTEXT_BASE) == CONTEXT_VERSION_BLOCK
}

/// Context words `at` and `at + 1` as a u64, low word first.
fn u64_at<H: Host>(h: &mut H, at: u32) -> u64 {
    let lo = h.read_public(CONTEXT_BASE + at) as u64;
    let hi = h.read_public(CONTEXT_BASE + at + 1) as u64;
    lo | hi << 32
}

/// What block-context opcode `op` pushes, or `None` when it traps: any context version but 2,
/// `PREVRANDAO` without a beacon value, and every opcode this module does not define.
pub fn value<H: Host>(h: &mut H, op: u8) -> Option<U256> {
    if !is_block_context(h) {
        return None;
    }
    Some(match op {
        0x3a | 0x48 => U256::from_u64(u64_at(h, CTX_BASEFEE)),
        0x41 => U256::ZERO,
        0x42 => U256::from_u64(u64_at(h, CTX_TIMESTAMP)),
        0x43 => U256::from_u64(u64_at(h, CTX_REF_HEIGHT)),
        0x44 => {
            if h.read_public(CONTEXT_BASE + CTX_HAS_RANDOMNESS) != 1 {
                return None;
            }
            // Word i is bytes 4i..4i+4 of the beacon value, little-endian; the opcode's word is
            // those 32 bytes read big-endian (`U256::from_be_bytes`), so limb 7 − i (limbs are
            // least significant first) is word i with its bytes swapped. Built without indexing,
            // so no bounds check (and no panic path) is linked into the guest.
            let mut r = |i: u32| h.read_public(CONTEXT_BASE + CTX_RANDOMNESS + i).swap_bytes();
            let (w0, w1, w2, w3) = (r(0), r(1), r(2), r(3));
            let (w4, w5, w6, w7) = (r(4), r(5), r(6), r(7));
            U256([w7, w6, w5, w4, w3, w2, w1, w0])
        }
        0x45 => U256::from_u64(BLOCK_GAS_LIMIT),
        0x46 => U256::from_u64(u64_at(h, CTX_CHAIN_ID)),
        _ => return None,
    })
}
