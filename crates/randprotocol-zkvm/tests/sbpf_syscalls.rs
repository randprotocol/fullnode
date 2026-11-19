//! ZKVM-116: the syscalls and the compute-unit meter the sBPF guest gained, on real programs.
//!
//! * SPL Token's `InitializeAccount`, `InitializeAccount3`, `GetAccountDataSize` and
//!   `AmountToUiAmount` — the instructions the committed ELF could not run before, because they
//!   need `sol_get_sysvar` (rent) or `sol_set_return_data` — through `sbpf-core` natively and
//!   through the committed guest image `sbpf.bin` on the emulator, with equal public outputs. The
//!   translated image's half of the same vectors is `sbpf2rv/tests/parity.rs`.
//! * What binds what: the return data is in the public output's preimage, and the rent
//!   `InitializeAccount3` reads comes from the **public** tape, so the same private instruction
//!   gives a different answer under a different public sysvar block and none at all without one.
//! * The meter: a syscall is charged Agave's cost on the instruction meter, so a program runs out
//!   of budget where it would on Solana.
//!
//! The per-syscall reference vectors (and the interpreter-against-C-runtime differential) are in
//! `tests/sbpf_rt.rs`.

mod common;

use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::sbpf::{
    self, asm, deserialize_accounts, insn, run_text, sysvar_block, Rent, SbpfCall, DEFAULT_RENT,
    FIXTURE_CLOCK, HostRef, TOKEN_ACCOUNT_LEN,
};
use sbpf_core::abi;
use sbpf_core::interp::{Halt, MAX_INSTRUCTIONS};
use sbpf_core::isa::opc;
use sbpf_core::syscalls;

const CAP: usize = 4_000_000;

/// `TokenError::NotRentExempt` (custom error 0) as the entrypoint returns it: `(code + 1) << 32`
/// is `ProgramError::Custom`'s encoding, and for code 0 that is `1 << 32`.
const NOT_RENT_EXEMPT: u64 = 1 << 32;

/// The call through the committed `sbpf.bin` on the emulator: its eight public outputs.
fn through_the_guest(call: &SbpfCall) -> [u32; 8] {
    let p = guests::compiled::sbpf();
    let exec = execute(&p, &call.input_words(), &call.public_words(), CAP).unwrap();
    exec.outputs
}

/// The public output recomputed from its three parts, the way a verifier does.
fn output_of(status: u32, call: &SbpfCall, post_region: &[u8], returned: &[u8]) -> [u32; 8] {
    abi::public_output(
        &mut HostRef,
        status,
        &sbpf::canonical_input_hash_of(&call.input),
        &sbpf::output_hash_of(post_region),
        &sbpf::return_hash_of(returned),
    )
}

#[test]
fn spl_token_initialize_account_runs_natively_and_in_the_guest() {
    let min = DEFAULT_RENT.minimum_balance(TOKEN_ACCOUNT_LEN);
    assert_eq!(min, 2_039_280, "Solana's rent-exempt minimum for a 165-byte account");
    let (owner, mint) = sbpf::spl_initialize_account_owner_and_mint();

    // Rent-exempt: the account becomes an initialized, empty token account of `mint` owned by
    // `owner`, and nothing else changes.
    let ok = sbpf::spl_initialize_account(min, &DEFAULT_RENT);
    let (out, r0, post) = ok.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(out[0], 1);
    let pre = deserialize_accounts(&ok.input);
    assert_eq!(pre[0].data, vec![0u8; TOKEN_ACCOUNT_LEN]);
    assert_eq!(post[0].data, sbpf::token_account_data(mint, owner, 0));
    assert_eq!(post[1..], pre[1..]);
    assert_eq!(post[0].lamports, min);
    assert!(ok.return_data().is_empty());
    assert_eq!(out, output_of(1, &ok, &ok.input_post_state(), &[]));
    assert_eq!(through_the_guest(&ok), out);

    // One lamport short: `TokenError::NotRentExempt`, status 0, the pre-state bound.
    let poor = sbpf::spl_initialize_account(min - 1, &DEFAULT_RENT);
    let (out_poor, r0, post) = poor.expected();
    assert_eq!(r0, Ok(NOT_RENT_EXEMPT));
    assert_eq!(out_poor[0], 0);
    assert_eq!(post, deserialize_accounts(&poor.input));
    assert_eq!(out_poor, output_of(0, &poor, &poor.input, &[]));
    assert_eq!(through_the_guest(&poor), out_poor);

    // This instruction reads rent from its fourth *account*, which `input_hash` binds like any
    // other: a dearer rent in that account turns the same balance down.
    let dear = Rent { lamports_per_byte_year: 2 * DEFAULT_RENT.lamports_per_byte_year, ..DEFAULT_RENT };
    let (out_dear, r0, _) = sbpf::spl_initialize_account(min, &dear).expected();
    assert_eq!(r0, Ok(NOT_RENT_EXEMPT));
    assert_ne!(out_dear[1..], out[1..]);
}

#[test]
fn spl_token_initialize_account3_reads_rent_from_the_public_tape() {
    let min = DEFAULT_RENT.minimum_balance(TOKEN_ACCOUNT_LEN);
    let (owner, mint) = sbpf::spl_initialize_account_owner_and_mint();
    let block = sysvar_block(&FIXTURE_CLOCK, &DEFAULT_RENT);

    let ok = sbpf::spl_initialize_account3(min, Some(block));
    let (out, r0, post) = ok.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(out[0], 1);
    assert_eq!(post[0].data, sbpf::token_account_data(mint, owner, 0));
    assert_eq!(through_the_guest(&ok), out);

    let poor = sbpf::spl_initialize_account3(min - 1, Some(block));
    let (out_poor, r0, _) = poor.expected();
    assert_eq!(r0, Ok(NOT_RENT_EXEMPT));
    assert_eq!(out_poor[0], 0);
    assert_eq!(through_the_guest(&poor), out_poor);

    // The same private instruction under a different public sysvar block: the chain's rent is twice
    // as dear, so the same balance is no longer exempt. The instruction — and so `input_hash` — is
    // identical; only the public tape, which `H_PUB` binds, differs.
    let dear = Rent { lamports_per_byte_year: 2 * DEFAULT_RENT.lamports_per_byte_year, ..DEFAULT_RENT };
    let under_dear = sbpf::spl_initialize_account3(min, Some(sysvar_block(&FIXTURE_CLOCK, &dear)));
    assert_eq!(under_dear.input, ok.input);
    assert_eq!(under_dear.input_words(), ok.input_words());
    assert_ne!(under_dear.public_words(), ok.public_words());
    let (out_dear, r0, _) = under_dear.expected();
    assert_eq!(r0, Ok(NOT_RENT_EXEMPT));
    assert_eq!(out_dear[0], 0);
    assert_eq!(through_the_guest(&under_dear), out_dear);
    // The clock is in the block too, and SPL Token does not read it: a different clock is a
    // different public tape and the same output.
    let later = sbpf::Clock { slot: FIXTURE_CLOCK.slot + 1, ..FIXTURE_CLOCK };
    let under_later = sbpf::spl_initialize_account3(min, Some(sysvar_block(&later, &DEFAULT_RENT)));
    assert_ne!(under_later.public_words(), ok.public_words());
    assert_eq!(under_later.expected().0, out);

    // No sysvar block: there is no rent to read, and the run halts rather than inventing one.
    let none = sbpf::spl_initialize_account3(min, None);
    let (out_none, r0, post) = none.expected();
    assert_eq!(r0, Err(Halt::Trap("sysvar unavailable")));
    assert_eq!(out_none[0], 2);
    assert_eq!(post, deserialize_accounts(&none.input));
    assert_eq!(out_none, output_of(2, &none, &none.input, &[]));
    assert_eq!(through_the_guest(&none), out_none);
}

#[test]
fn spl_token_get_account_data_size_returns_165_and_the_output_binds_it() {
    let call = sbpf::spl_get_account_data_size();
    let (out, r0, post) = call.expected();
    assert_eq!(r0, Ok(0));
    assert_eq!(out[0], 1);
    assert_eq!(post, deserialize_accounts(&call.input), "it changes no account");
    let returned = call.return_data();
    assert_eq!(returned, (TOKEN_ACCOUNT_LEN as u64).to_le_bytes());
    // The answer is only in the return data, so the output must bind it: the digest is the one
    // over `sha256(return data)`, and not the one a run that returned nothing publishes.
    assert_eq!(out, output_of(1, &call, &call.input, &returned));
    assert_ne!(out, output_of(1, &call, &call.input, &[]));
    assert_ne!(out, output_of(1, &call, &call.input, &164u64.to_le_bytes()));
    assert_eq!(through_the_guest(&call), out);
}

#[test]
fn spl_token_amount_to_ui_amount_returns_the_decimal_string() {
    for (amount, text) in [(1_234_567u64, "1.234567"), (5_000_000, "5"), (1, "0.000001"), (0, "0")] {
        let call = sbpf::spl_amount_to_ui_amount(amount);
        let (out, r0, _) = call.expected();
        assert_eq!(r0, Ok(0), "{amount}");
        let returned = call.return_data();
        assert_eq!(String::from_utf8(returned.clone()).unwrap(), text);
        assert_eq!(out, output_of(1, &call, &call.input, &returned));
        if amount == 1_234_567 {
            assert_eq!(through_the_guest(&call), out);
        }
    }
}

#[test]
fn a_failed_run_binds_no_return_data() {
    // set_return_data(input, 8), then return 1: status 0, and the output is the one over the empty
    // return data — what was set by a run that then failed is not published.
    let set = |ret: i32| {
        let mut p = sbpf::lddw(1, sbpf_core::memory::REGION_INPUT).to_vec();
        p.push(insn(opc::MOV64_IMM, 2, 0, 0, 8));
        // An unresolved call in the file: the relocation below names the syscall (slot 3 — the
        // `lddw` is two).
        p.push(insn(opc::CALL_IMM, 0, 0, 0, -1));
        p.push(insn(opc::MOV64_IMM, 0, 0, 0, ret));
        p.push(insn(opc::EXIT, 0, 0, 0, 0));
        asm(&p)
    };
    let elf = |text: &[u8]| {
        use common::sbpf_elf_builder::{build_elf, Rel, Sym, R_BPF_64_32, TEXT_ADDR};
        let syms = [Sym { name: "sol_set_return_data", info: 0x10, value: 0 }];
        let relocs = [Rel { offset: TEXT_ADDR + 3 * 8, sym: 1, kind: R_BPF_64_32 }];
        build_elf(text, &[], &syms, &relocs, 0)
    };
    let input = sbpf::serialize_aligned(&[], b"12345678", &[9u8; 32]);
    let ok = SbpfCall { elf: elf(&set(0)), input: input.clone(), sysvars: None };
    let failed = SbpfCall { elf: elf(&set(1)), input, sysvars: None };
    // The region starts with the account count (0) — eight zero bytes.
    assert_eq!(ok.return_data(), [0u8; 8]);
    assert_eq!(ok.expected().0, output_of(1, &ok, &ok.input, &[0u8; 8]));
    assert_eq!(failed.return_data(), [0u8; 8], "it was set");
    assert_eq!(failed.expected().0, output_of(0, &failed, &failed.input, &[]), "and is not bound");
    assert_eq!(through_the_guest(&ok), ok.expected().0);
    assert_eq!(through_the_guest(&failed), failed.expected().0);
}

#[test]
fn a_syscall_is_charged_on_the_instruction_meter() {
    // `loop: call sol_log_64_; ja loop` — two instructions and 100 units a trip. 1 960 trips are
    // 199 920 units; the next `call` is one more, and its 100-unit charge does not fit.
    let text = asm(&[
        insn(opc::CALL_IMM, 0, 1, 0, syscalls::SOL_LOG_64 as i32),
        insn(opc::JA, 0, 0, -2, 0),
    ]);
    let o = run_text(&text, &mut []);
    assert_eq!(o.result, Err(Halt::InstructionLimit));
    assert_eq!(o.instructions, 1960 * 2 + 1);
    assert_eq!(MAX_INSTRUCTIONS, 200_000);

    // Without the syscall the same loop runs the whole budget in instructions.
    let text = asm(&[insn(opc::MOV64_IMM, 1, 0, 0, 0), insn(opc::JA, 0, 0, -2, 0)]);
    let o = run_text(&text, &mut []);
    assert_eq!(o.result, Err(Halt::InstructionLimit));
    assert_eq!(o.instructions, MAX_INSTRUCTIONS);

    // A charge that lands exactly on the budget fits (Agave's `consume_checked`): 1 999 calls of
    // 100 units are 199 900 with 1 999 instructions… so pad to land `exit` on unit 200 000.
    // 1 980 × (1 + 100) = 199 980, then 19 `mov`s and `exit` = 200 000 exactly.
    let mut p = Vec::new();
    for _ in 0..1980 {
        p.push(insn(opc::CALL_IMM, 0, 1, 0, syscalls::SOL_LOG_COMPUTE_UNITS as i32));
    }
    for _ in 0..19 {
        p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    }
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let o = run_text(&asm(&p), &mut []);
    assert_eq!(o.result, Ok(0));
    assert_eq!(o.instructions, 2000);
    // One more instruction and the budget is gone before `exit`.
    p.insert(1980, insn(opc::MOV64_IMM, 0, 0, 0, 0));
    assert_eq!(run_text(&asm(&p), &mut []).result, Err(Halt::InstructionLimit));
}

#[test]
fn the_spl_token_vectors_cost_what_their_instructions_and_syscalls_cost() {
    // Measured, and pinned so a change in the meter is seen: instructions + syscall charges.
    let block = sysvar_block(&FIXTURE_CLOCK, &DEFAULT_RENT);
    let min = DEFAULT_RENT.minimum_balance(TOKEN_ACCOUNT_LEN);
    // `Transfer` and `InitializeAccount` make no syscall. `InitializeAccount3` makes one
    // `sol_get_sysvar` (110), `GetAccountDataSize` one `sol_set_return_data` (100), and
    // `AmountToUiAmount` one `sol_set_return_data` and two memory syscalls (100 + 10 + 10).
    for (name, call, instructions, units) in [
        ("Transfer", sbpf::spl_transfer(250), 143, 143),
        ("InitializeAccount", sbpf::spl_initialize_account(min, &DEFAULT_RENT), 153, 153),
        ("InitializeAccount3", sbpf::spl_initialize_account3(min, Some(block)), 127, 237),
        ("GetAccountDataSize", sbpf::spl_get_account_data_size(), 79, 179),
        ("AmountToUiAmount", sbpf::spl_amount_to_ui_amount(1_234_567), 292, 412),
    ] {
        let m = sbpf::measure(&call);
        eprintln!(
            "{name}: {} instructions, {} compute units ({} syscall base, {} length-dependent)",
            m.instructions, m.compute_units, m.syscall_base_units, m.syscall_extra_units
        );
        assert_eq!(m.result, Ok(0), "{name}");
        assert_eq!(m.compute_units, m.instructions + m.syscall_base_units + m.syscall_extra_units, "{name}");
        assert_eq!((m.instructions, m.compute_units), (instructions, units), "{name}");
    }
}
