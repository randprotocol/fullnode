# How things work on SHRUGG, in five questions

Short, end-to-end answers for someone arriving at the shielded chain with a wallet and a
program. Each one points at the page with the detail. Written 2026-09-12 against phase S1 with
the S2/S3 additions marked.

## 1. What do I need to see the balance of an address?

The chain cannot answer this for anyone. You need:

- the **viewing key** `nk` of that address (32 bytes; the wallet derives it from the spend key
  in its key file), and
- a node to scan against.

`shrugg balance` walks `shrugg_getCommitments` from the wallet's last index, trial-decrypts every
envelope with `nk` (receiver path) and the outgoing key `ovk` (sender path), keeps the notes
whose owner field is `pk = H_PK(nk)`, marks the ones whose nullifier `H_NF(nk, cm)` appears in
`shrugg_getNullifiers`, and sums the rest. Anyone else, an explorer included, sees commitments
and ciphertexts only. Hand a party the viewing key and they can run the same scan and see
everything the address ever received or sent; hand them a per-transaction `TxKey` and they see
one transaction; hand them nothing and they see nothing. `docs/shielded.md` §2–3.

## 2. How do I deploy a program?

Build the RV32IM words — `shrugg program build <guest>` for a hand-assembled guest, or a
compiled `.bin` from `guest-sdk` and `llvm-objcopy` — then `shrugg program deploy <file>`. The
wallet builds a bundle from its own notes that pays the deploy floor, attaches
`Action::Deploy { base_pc, words }`, proves the bundle and submits it. The node checks every
word decodes, computes the in-circuit digest `hc`, and stores the record under the
content-addressed id `blake3(base_pc || words)`. The code is public; who paid for it is not.
Deploying the same words twice is idempotent. For an EVM contract (milestone M4.3) the
interpreter guest is deployed once and the contract's bytecode is a private input committed by
`H_IN`, so "deploying a confidential contract" is publishing `(hc_evm, H_IN)`.
`docs/confidential.md`, `docs/zkvm.md` §6.

## 3. How does a transfer work?

`shrugg send <shrugg1…> 1.5`:

1. scan (as in question 1) and pick the largest one or two unspent notes covering
   amount + fee; if only one is needed, the second input is a dummy (amount 0, owned by
   yourself, membership skipped in circuit, nullifier still published so the bundle looks like
   any other);
2. ask the node for the Merkle witness of each real input against the current anchor;
3. build two outputs: the recipient's note and your change note (present even at zero);
4. prove the `bundle` guest on the 612-word private input — tier 14, about 100 s on a laptop —
   which shows ownership, membership, the nullifiers and `Σ in = Σ out + fee + burn`;
5. seal each output in an envelope (ML-KEM-768 to the recipient, plus a copy under your `ovk`)
   and submit `Transaction { chain_id, bundle, action: None }`.

Every validator re-hashes the public fields, verifies the proof (about 16 ms warm), rejects any
reused nullifier and appends the two commitments. The recipient's next scan finds the note; the
change comes back to you the same way. The chain saw a fee, a proof, two nullifiers, two
commitments and two ciphertexts. `docs/shielded.md` §4–5.

## 4. How do I check that a program is deployed?

`shrugg program show <id>` calls `shrugg_getProgram(id)`: the id, `code_hash` (the in-circuit
`hc` that calls are verified against), `base_pc`, the word count and `deployed_at`;
`shrugg_getProgramCode` returns the words. `shrugg tx <hash>` shows the deploying transaction
with `action: { kind: "deploy", program, words }`. An unknown id answers `null`, and a `Call`
naming it is rejected as `UnknownProgram`. `docs/rpc.md`.

## 5. What is the gas calculation?

There is none. Fees are flat floors (`BUNDLE_BASE` = 0.001 SHRUGG per bundle, plus a per-word
deploy fee or a small per-tier call fee) because a node's cost is one STARK verification of
nearly constant cost. The only variable cost, proving, is paid by the sender's own machine and
scales with the tier the run needs. `docs/fees.md` has the schedule, the proving-cost factors,
and why Ethereum needs gas and this chain does not.

## 6. What language are programs written in?

Two ways today, both producing RV32IM machine code:

- **Rust, `no_std`, for `riscv32im-unknown-none-elf`**: a small crate depending on `guest-sdk`
  (syscalls `read_input`, `write_output`, `poseidon2`, `keccak`, `keccak256`, `halt`), built with
  the pinned toolchain, linked with `guest.ld` at `0x1000`, flattened with `llvm-objcopy`. No
  allocator, no floating point, nothing outside RV32IM (it fails at load, not at run time).
  `guests-compiled/fib` and `guests-compiled/keccak256` are the committed examples.
- **Hand-written assembly** through the research crate's `asm.rs` mnemonic helpers, which is how
  the chain's own guests (`bundle`, `private_payment`) are written.

With M4.3 and M4.4, Solidity and Solana-style Rust follow indirectly: an EVM or sBPF interpreter
compiled from `no_std` Rust becomes one deployed guest, and the contract's bytecode is a private
input. `docs/zkvm.md` §3–6.
