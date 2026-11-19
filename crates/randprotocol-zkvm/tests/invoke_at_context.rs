//! Issue #168 end to end, node side against guest side: the version-2 context an `InvokeAt` is
//! proved over is built by the node's own ledger code (`program_state::Transition::context_at`
//! over `BlockFacts::context_words`, then `invoke_segment`), and the EVM guest decodes it with
//! `evm_core::block` (circuits `41d64acd`, PR #27). These tests feed the one to the other:
//!
//! - the vendored `evm_core` interpreter, over the node-built segment, pushes exactly the facts
//!   for every block-context opcode (NUMBER, TIMESTAMP, CHAINID, BASEFEE/GASPRICE, PREVRANDAO),
//!   traps on PREVRANDAO without a beacon, and traps on all of them under a version-1 context;
//! - a Test-profile STARK of a small RV32 program reading the words at `evm_core::block`'s own
//!   offsets verifies under `verify_invoke` on the node-built segment, and is refused on the
//!   segment of any other block.
//!
//! Hand-maintained on this side (`deploy/sync-zkvm.sh` excludes it): circuits has no copy of the
//! node's context builder.

use evm_core::block::{CONTEXT_BASE, CONTEXT_VERSION_BLOCK, CTX_BASEFEE, CTX_CHAIN_ID, CTX_HAS_RANDOMNESS, CTX_RANDOMNESS, CTX_REF_HEIGHT, CTX_TIMESTAMP};
use evm_core::interp::{Buffers, Env, Halt, Interpreter, Outcome};
use evm_core::storage::StorageTree;
use evm_core::u256::U256;
use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::program::ProgramRecord;
use randprotocol_core::ledger::program_state::{self as ps, invoke_segment, BlockFacts, Cell, Inflow, Transition};
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::evm::{empty_root, HostPublic};
use randprotocol_zkvm::executor::{prove_invoke, ZkExecutor};
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::FriProfile;

/// RISC-V `t0` (x5).
const T0: u32 = 5;
const BINDING: [u32; 8] = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8];
/// Chain id with a high word, so a lost high word shows.
const CHAIN_ID: u64 = 0x0000_0001_0000_0016;

fn beacon() -> [u8; 32] {
    std::array::from_fn(|i| 0x11u8.wrapping_mul(i as u8 + 1) ^ 0x80)
}

/// Every u64 over 32 bits.
fn facts(randomness: Option<[u8; 32]>) -> BlockFacts {
    BlockFacts { height: 0x0000_0003_0000_0019, timestamp_ms: 0x0000_0123_4567_89ab, basefee: 0x0000_0002_0000_0064, randomness }
}

/// A transition with a read and a write, so the header counts and the cells after the block
/// words are not all zero: the guest must find the block words at their fixed offsets anyway.
fn transition() -> Transition {
    Transition {
        reads: vec![Cell { key: [1, 0, 0, 0, 0, 0, 0, 0], value: [7, 0, 0, 0, 0, 0, 0, 0] }],
        writes: vec![Cell { key: [1, 0, 0, 0, 0, 0, 0, 0], value: [8, 0, 0, 0, 0, 0, 0, 0] }],
        inflow: Inflow::None,
        pays: vec![],
        mints: vec![],
    }
}

/// The segment the ledger rebuilds for an `InvokeAt` of an EVM program (deploy-time public input
/// empty) naming a block with these facts.
fn node_segment(f: &BlockFacts) -> Vec<u32> {
    let context = transition().context_at(0, 0, 0, &f.context_words(CHAIN_ID));
    invoke_segment(&[], &BINDING, &context)
}

fn env() -> Env {
    Env { address: U256::from_u32(0xaaaa), caller: U256::from_u32(0xcafe), callvalue: U256::ZERO, gas_limit: 1_000_000 }
}

/// `op`, then its word returned: `op; PUSH0; MSTORE; PUSH1 32; PUSH0; RETURN`.
fn run_op(op: u8, public: &[u32]) -> Outcome {
    let code = [op, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let mut h = HostPublic(public);
    let mut st = StorageTree::new(empty_root());
    let mut b = Box::new(Buffers::ZERO);
    Interpreter::new(&mut h, &code, &[], env(), &mut st, &mut b).run()
}

fn word(o: &Outcome) -> U256 {
    assert_eq!(o.halt, Halt::Return);
    U256::from_be_bytes(o.ret[..32].try_into().unwrap())
}

#[test]
fn the_node_context_is_where_the_evm_guest_reads_it() {
    // The two sides' offsets are one table (the guest's are from the start of the context, as
    // the node's `CTX_*` are), and the context starts after the eight binding words.
    assert_eq!(
        [CTX_REF_HEIGHT, CTX_TIMESTAMP, CTX_CHAIN_ID, CTX_BASEFEE, CTX_HAS_RANDOMNESS, CTX_RANDOMNESS].map(|c| c as usize),
        [ps::CTX_REF_HEIGHT, ps::CTX_TIMESTAMP, ps::CTX_CHAIN_ID, ps::CTX_BASEFEE, ps::CTX_HAS_RANDOMNESS, ps::CTX_RANDOMNESS]
    );
    assert_eq!(CONTEXT_VERSION_BLOCK, ps::CONTEXT_VERSION_BLOCK);
    assert_eq!(CONTEXT_BASE as usize, BINDING.len());
    // Research's mirror of the ledger's block words is the ledger's.
    let f = facts(Some(beacon()));
    let mirror = randprotocol_zkvm::evm::BlockFacts {
        height: f.height,
        timestamp_ms: f.timestamp_ms,
        chain_id: CHAIN_ID,
        basefee: f.basefee,
        randomness: f.randomness,
    };
    assert_eq!(mirror.words(), f.context_words(CHAIN_ID));
}

#[test]
fn the_evm_interpreter_pushes_the_node_built_block_facts() {
    let f = facts(Some(beacon()));
    let seg = node_segment(&f);
    for (op, want) in [
        (0x43, U256::from_u64(f.height)),               // NUMBER = ref_height
        (0x42, U256::from_u64(f.timestamp_ms / 1000)),  // TIMESTAMP, seconds
        (0x46, U256::from_u64(CHAIN_ID)),               // CHAINID
        (0x48, U256::from_u64(f.basefee)),              // BASEFEE
        (0x3a, U256::from_u64(f.basefee)),              // GASPRICE = BASEFEE
        (0x44, U256::from_be_bytes(&beacon())),         // PREVRANDAO: bytes32 is the beacon value
    ] {
        assert_eq!(word(&run_op(op, &seg)), want, "opcode {op:#04x}");
    }
    // Without the beacon section: PREVRANDAO traps, the rest still push.
    let none = node_segment(&facts(None));
    assert_eq!(run_op(0x44, &none).halt, Halt::Trap(0x44));
    assert_eq!(word(&run_op(0x43, &none)), U256::from_u64(f.height));
    // Under a version-1 context (an ordinary `Invoke`) every block opcode traps as before.
    let v1 = invoke_segment(&[], &BINDING, &transition().context(0, 0, 0));
    for op in [0x42, 0x43, 0x44, 0x46, 0x48] {
        assert_eq!(run_op(op, &v1).halt, Halt::Trap(op), "opcode {op:#04x} under version 1");
    }
}

/// Reads the version word and seven block words at `evm_core::block`'s offsets into the eight
/// outputs.
fn block_reader() -> Program {
    let at = |c: u32| CONTEXT_BASE + c;
    let mut a = Assembler::new(0);
    for (slot, idx) in [
        at(0),
        at(CTX_REF_HEIGHT),
        at(CTX_REF_HEIGHT + 1),
        at(CTX_TIMESTAMP),
        at(CTX_CHAIN_ID + 1),
        at(CTX_BASEFEE),
        at(CTX_HAS_RANDOMNESS),
        at(CTX_RANDOMNESS + 7),
    ]
    .into_iter()
    .enumerate()
    {
        // `write_output` loads the slot into a0 before it moves the value, so the word goes
        // through t0 first.
        a.extend(read_public(idx));
        a.push(mv(T0, randprotocol_zkvm::isa::REG_A0));
        a.extend(write_output(slot as u32, T0));
    }
    a.extend(halt());
    a.assemble()
}

#[test]
fn an_invoke_at_proof_over_the_node_built_context_verifies_and_no_other_block_does() {
    let program = block_reader();
    let zk = ZkExecutor::new(FriProfile::Test);
    let record = ProgramRecord {
        id: randprotocol_core::program::program_id(program.base_pc, &program.words),
        base_pc: program.base_pc,
        words: program.words.clone(),
        code_hash: zk.check_program(program.base_pc, &program.words).unwrap(),
        deployed_at: 0,
        public_digest: None,
        public_len: 0,
    };
    let f = facts(Some(beacon()));
    let block = f.context_words(CHAIN_ID);
    let context = transition().context_at(0, 0, 0, &block);
    let segment = invoke_segment(&[], &BINDING, &context);
    let (proof, outputs, _) = prove_invoke(FriProfile::Test, &program, &[], &[], &BINDING, &context, [1, 2, 3, 4], None, None).unwrap();
    let r = |c: usize| block[c - ps::CONTEXT_HEADER_WORDS];
    assert_eq!(
        outputs,
        [
            CONTEXT_VERSION_BLOCK,
            f.height as u32,
            (f.height >> 32) as u32,
            (f.timestamp_ms / 1000) as u32,
            (CHAIN_ID >> 32) as u32,
            f.basefee as u32,
            1,
            r(ps::CTX_RANDOMNESS + 7),
        ]
    );
    assert_eq!(r(ps::CTX_RANDOMNESS + 7), u32::from_le_bytes(beacon()[28..32].try_into().unwrap()));
    let outcome = zk.verify_invoke(&record, &proof, &segment).expect("the node-built segment");
    assert_eq!(outcome.outputs, outputs);
    // The same proof against the segment of any other block is a public-values mismatch.
    let refused = Err(ConfidentialError::InvalidProof(format!("{:?}", randprotocol_zkvm::machine::VerifyError::PublicValues)));
    let later = BlockFacts { timestamp_ms: f.timestamp_ms + 2_000, ..f };
    assert_eq!(zk.verify_invoke(&record, &proof, &node_segment(&later)), refused, "another block's time");
    let reroll = BlockFacts { randomness: Some([0x5a; 32]), ..f };
    assert_eq!(zk.verify_invoke(&record, &proof, &node_segment(&reroll)), refused, "another beacon value");
    let v1 = invoke_segment(&[], &BINDING, &transition().context(0, 0, 0));
    assert_eq!(zk.verify_invoke(&record, &proof, &v1), refused, "a version-1 context");
}
