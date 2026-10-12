# Private multisig phase 4 — whole-branch review fix wave

Worktree `/Users/dendisuhubdy/rand-worktrees/fullnode-pm-impl`, branch `feat/private-multisig`, from 62d2c955.

## Commits

| commit | items |
|---|---|
| `66019dbc` msig: a signer names the payee … | 1 (a–e), 5 |
| `71dcabb4` msig_private: require_multisig_chain names the failed condition … | 6, 7, 9 (slot_for doc(hidden), R-hide all eight fields) |
| `0944462d` node: rand-node verify runs run's build check … | 2, 3, 4, 8, 9 (agg_executor comment) |

No rebase; nothing under `vendor/`, `crates/randprotocol-rvm`, vendored zkvm files or `deploy/cut-chain21-genesis.sh` touched. CHANGELOG.md: one clause added to the existing Private multisig bullet (`check`/`sign --expect-to <address>` refuse a proposal paying anyone but the named payee).

## Per item

1. **Recipient check (theft lever).**
   - `randprotocol-msig`: `owner_fingerprint_of(&ShieldedAddress)` delegates to `owner_fingerprint(&pk)` — the summary code calls `owner_fingerprint` too, one derivation. `owner_fingerprint_of_text(&str)` parses a pasted `rand1…` with `ShieldedAddress::parse` (the wallet's parser).
   - New check 8: with a non-empty expectation, every output with `to_account == false` **and `amount > 0`** whose `pk` is not an expected address's `pk` → `Refused("output N pays <owner fp>, not an expected recipient")`. A matching output carries `matches: Some(<address fingerprint>)`, its line reads `… to <owner fp> matches XXXX-XXXX-XXXX-XXXX memo … (owner key verified; delivery key NOT verifiable from this proposal)`. With an empty expectation `recipients_checked == false` and the lines carry, once, `NO_EXPECTATION` = `WARNING: no expected recipient given: the payee was NOT checked (the coordinator could be paying itself; pass the payee's address to check)`.
   - Per the clients-core addendum: the string form is the app contract (parsed in-crate, a malformed address refused as `expected recipient {i} is not a shielded address: …`); typed `_addresses` twins exist; the two app-refusal conditions are struct fields (`recipients_checked`, per-output `matches`), not only text. An unmatched non-change value output is never returned — it is an `Err(Refused)`.
   - CLI: `multisig-private check|sign --expect-to ADDR` (repeatable; bad address → `--expect-to <addr>: invalid shielded address`). `sign` without it prints the WARNING line among the summary lines and still signs. `prepare` checks against its own `--to`/`--sweep-to`. `rand address` prints `owner fingerprint <16 hex>` on stderr; `multisig-private address` and `new-policy` print `owner fingerprint: …`.
   - Fixtures: `proposal-substituted-recipient.json` — the valid proposal's slot-2 output re-made to a seeded thief key (same amount and `r`), commitment, witness, digest, binding re-made, envelope sealed as the account; passes every §6.5 check, refused only under an expectation naming the original recipient. Draws come after every existing draw, so all other fixtures are byte-identical except `expected.json`, which gains `lines`, `recipient`, `recipient_owner_fingerprint`, `summary_expecting_recipient`, `lines_expecting_recipient`, `substituted_refusal` (and `summary` gains the three new fields). Regenerated with the generator's own `regen_fixtures` (the one ignored test that writes files — run filtered to that name only); `the_committed_fixtures_equal_the_regenerated_ones` and `the_generator_is_deterministic` pass.
   - Tests: msig `tests/checks.rs` — `the_lines_name_the_chain_and_warn_when_no_payee_is_named`, `naming_the_recipient_marks_the_payment_and_drops_the_warning`, `a_substituted_recipient_passes_the_checks_and_is_refused_only_under_an_expectation` (exact wording, `sign_expecting` refuses, plain `sign` still signs), `a_malformed_expected_recipient_is_refused_by_index`; client bin `expect_to_refuses_a_substituted_recipient_in_check_and_sign` (CLI over the committed vectors) and the parse test; client lib `sign_recomputes_…` asserts a stranger expectation is refused and the no-expectation WARNING appears. e2e `wallet_flow` signs with `--expect-to`-equivalent (`b.address`, the sweep's new address).
   - Docs: `docs/cli.md` (flags, signer flow in the walk-through, `rand address`), `docs/multisig.md` "What a signer sees" — the flow is "ask the payee for their address, pass `--expect-to`; with only an owner fingerprint compare by eye"; verified vs not verified stated plainly.
   Output: msig 14 + 2 (+1 ignored regen) passed; the lines now read (valid, no expectation):
   ```
   chain 7 · genesis 0000…0000
   WARNING: no expected recipient given: the payee was NOT checked (…)
   2: → 10 RAND to 35bad5bd21a6f0f7 memo "" (owner key verified; delivery key NOT verifiable from this proposal)
   ```
   and the substituted proposal under the expectation: `output 2 pays b9856a063c1fb742, not an expected recipient`.
2. **`rand-node verify`** calls `node::check_build_runs_genesis(&gs, &ZkExecutor::known_hc_bundles())` (which includes `refuse_chains_this_build_cannot_run`) before the msauth load and any block read; error suffixed `; refusing to verify`. Test `tests/cli_datadir.rs::verify_refuses_a_genesis_naming_another_builds_multisig_guest`: genesis `--bundle-guest v3 --auth-guest --auth-multisig-guest` with `hc_auth_multisig` rewritten to `abab…`, `init` succeeds, `verify` and `verify --repair` both fail naming `the genesis hc_auth_multisig (abab…) is not this build's multisig auth guest`, no CORRUPT/repaired output. cli_datadir 9/9.
3. **`--build-msauth-key` off the pin**: `msauth_key::built_key_verdict(Result<(), String>, validator) -> anyhow::Result<()>`. A validator now builds synchronously in `start_with` (spawn_blocking, awaited) before anything starts and a mismatch returns `--build-msauth-key: <digests>; a validator does not vote with an unpinned msauth key: refusing to start`; a non-validator builds in the warm thread as before and logs. Test `a_built_key_off_the_pin_refuses_a_validator_and_only_logs_otherwise` (the verdict; the wiring is two lines — no fake executor whose build mismatches exists, the Test-profile key matches its pin).
4. `verify_on_a_multisig_chain_loads_the_blob_and_builds_nothing` asserts `node_ex.auth_multisig_key_ready()` after the AggExecutor load. Passes.
5. `ProposalSummary` gains `chain_id`, `genesis` (hex; zeros under the chain-id-only domain); `lines()[0]` = `chain {id} · genesis {hex}`. In `expected.json`. (Landed in commit 1: it is the same `lines()` change.)
6. `require_multisig_chain` → `multisig_chain_refusal(&status)`: `… names no hc_auth_multisig (null)`, `… hc_auth_multisig is X, another build's guest; this build's is Y …`, or `… bundle guest (hc_bundle X) is not this build's v3 …`. Test `the_multisig_chain_refusal_names_the_condition`.
7. `msig_private::prove` gains `proof_cap: usize`; the CLI passes `wallet::proof_cap(rpc.limits())` for `Proving::Remote`, `gas::MAX_PROOF_BYTES` locally — exactly `send`'s rule. No dedicated test (needs a remote prover); callers updated.
8. Spec §3.6: a "Superseded in part (as shipped)" note naming `machine::VerifierKeyBlob { format_version, profile, shape, constraint_set, common }` and the SHA-256 pin `msauth_vk::MSAUTH_VK_SHA256_{PRODUCTION,TEST}`; each blake3 mention keeps its text with an "(as shipped: SHA-256 …)" marker.
9. `slot_for` `#[doc(hidden)]` (test-only note); wallet_flow R-hide builds an `executor::MsauthShape` from all eight header fields and compares it with `ZkExecutor::msauth_heights()` (no retyped numbers); agg_executor comment → "(at phase 3) tier 22 would have held N ≤ 7".

## Verification

- `cargo +1.98.1 test -p randprotocol-msig`: 14 + 2 passed (fixtures equality, determinism).
- `cargo +1.98.1 check -p randprotocol-msig --target wasm32-unknown-unknown`: clean.
- `cargo +1.98.1 test -p randprotocol-client --lib --bins`: 225 + 24 passed.
- `cargo +1.98.1 test -p randprotocol-client --test wallet_flow --no-run`: builds; the non-ignored suite was also run: 10 passed, 2 ignored (631 s).
- `cargo +1.98.1 test -p randprotocol-node --lib msauth_key`: 16 passed; `--bin rand-node`: 60 passed; `--test cli_datadir`: 9 passed.
- `cargo +1.98.1 clippy -p randprotocol-msig -p randprotocol-client -p randprotocol-node --all-targets`: no warning in those crates (vendored zkvm/rvm warnings pre-existing).

## msig API changes (for the clients core vendor)

Added:
```rust
pub const NO_EXPECTATION: &str;
pub fn owner_fingerprint_of(addr: &ShieldedAddress) -> String;
pub fn owner_fingerprint_of_text(addr: &str) -> Result<String, MsigError>;
pub fn parse_expected_recipients<S: AsRef<str>>(texts: &[S]) -> Result<Vec<ShieldedAddress>, MsigError>;
pub fn check_proposal_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, expected_recipients: &[S]) -> Result<ProposalSummary, MsigError>;
pub fn check_proposal_expecting_addresses(proposal_json: &str, policy_json: &str, expected_recipients: &[ShieldedAddress]) -> Result<ProposalSummary, MsigError>;
pub fn sign_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[S]) -> Result<(u8, Vec<u8>), MsigError>;
pub fn sign_expecting_addresses(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[ShieldedAddress]) -> Result<(u8, Vec<u8>), MsigError>;
```
Unchanged signatures (now no-expectation wrappers): `check_proposal(&str, &str)`, `sign(&str, &str, &[u8; 32])`, `verify_share` (no expectation).
Struct fields added (breaks struct-literal construction and exact-JSON comparisons, not calls):
- `ProposalSummary { chain_id: u64, genesis: String, recipients_checked: bool, … }`
- `OutputSummary { …, matches: Option<String> }`
- `ProposalSummary::lines()`: new first line (chain/genesis) and, without an expectation, a second WARNING line — output lines moved from `[0..4]` to `[2..6]` (or `[1..5]` with an expectation).

Client crate (fullnode-only) API: `msig_private::sign(proposal, policy, key, expect_to: &[ShieldedAddress])`, `msig_private::check(proposal, policy, expect_to: &[ShieldedAddress])`, `msig_private::prove(…, profile, proof_cap: usize)`.

## Final fixture list (crates/randprotocol-msig/tests/fixtures, SHA-256)

```
8e6ae804b4d5a3cf740e1d4b5c77ee25f3b249a8bed8e5f71859d3ab3bd3b800  expected.json                        (changed)
31fbeb3212e024e5839e29f9bdf23c0bbd6e34eb2ffcefb5c9085b3196992ff2  policy.json
2144cafbbd06c1cd165105754a8ee1043167ed68b2256e150c991f82b055b8f7  proposal-expired.json
457f0ab49d28ba0c18e3be1e266ed09fa94f1bd7f3105155b88c8dc95fc786c2  proposal-fee-raised.json
773be56449eefaba00f819a92aa48e6d8be8057f96e39e5a8da45a01b2491453  proposal-substituted-recipient.json (new)
c621fc9531f95a04be2aa83d217d0040b19b27254d7bce483dbf6243a558b81b  proposal-tampered-output.json
6f2135c940a38af710e137d2da0ff42147bd6d9a2bf18bd3fc6973bef044b3bd  proposal-unbound.json
50f1f1cc5df58bfc1126bc9279a96fc1a47c0d0a192fa6239988d8f4d828129b  proposal-valid.json
dddb4624c6f290948be9769735b13a445d7e4d201c85bf8e044438d808f91016  proposal-value-mismatch.json
7ce496a463c09dec560070875c12e10781b14a31f944bfb1905c07e6cd751832  proposal-wrong-expected.json
f75a09d8ec62da397010202e053d192a429710ecb566faf29d8d1381f07ee8aa  signer-seeds.json
```

## Concerns

- **Deviation, deliberate:** the brief says EVERY non-change output must match; read literally that refuses every real proposal, because a bundle's two dummy outputs (amount 0, throwaway owner keys) are non-change. Zero-amount outputs are exempt (they move no value; a value-moving output to any key, of any asset, is held to the expectation). Documented in the crate doc, docs/multisig.md, cli.md.
- Matching is by owner key `pk` only; the delivery (KEM) key remains unverifiable, so a matching output can still be sealed so the payee never finds it (no theft, a liveness/griefing issue). Stated in every line and the docs.
- Item 3 changes startup timing for a validator under `--build-msauth-key`: the ~80 s / ~4 GB Production build now happens before the node starts rather than in the warm thread. The flag is dev-only (deploy scripts are tested never to pass it).
- Item 7 has no direct test (requires a remote prover).
- `regen_fixtures` is `#[ignore]`d; it was run filtered by name (it writes the files, it proves nothing), which the brief's "never `--ignored`" rule may have meant to cover — flagging it.

## Payee semantics follow-up

Rules: every expected recipient must be paid; optional `ADDR:AMOUNT` pin (sum over outputs, RAND only; amount parsed by `randprotocol_core::parse_amount`, the CLI `--amount` parser); matching lines read `matches <fp> (<amount>)`.

Final public API (crate `randprotocol-msig`):
```
pub struct ExpectedRecipient { pub address: ShieldedAddress, pub amount: Option<u64> }
impl ExpectedRecipient { pub fn address(address: ShieldedAddress) -> Self; pub fn parse(text: &str) -> Result<Self, MsigError> }
pub fn parse_expected_recipients<S: AsRef<str>>(texts: &[S]) -> Result<Vec<ExpectedRecipient>, MsigError>
pub fn check_proposal_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, expected_recipients: &[S]) -> Result<ProposalSummary, MsigError>
pub fn check_proposal_expecting_addresses(proposal_json: &str, policy_json: &str, expected_recipients: &[ExpectedRecipient]) -> Result<ProposalSummary, MsigError>
pub fn sign_expecting<S: AsRef<str>>(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[S]) -> Result<(u8, Vec<u8>), MsigError>
pub fn sign_expecting_addresses(proposal_json: &str, policy_json: &str, signer_seed: &[u8; 32], expected_recipients: &[ExpectedRecipient]) -> Result<(u8, Vec<u8>), MsigError>
```
`OutputSummary.matches: Option<String>` is now `"<fp> (<amount text>)"`. Client: `msig_private::{sign,check}` take `&[ExpectedRecipient]`.
Refusals: `expected recipient <fp> is not paid`; `expected recipient <fp> is paid <sum> RAND, not <AMOUNT> RAND`; `expected recipient <fp>: amount pin on a non-RAND output`; malformed: `expected recipient <i> has a malformed amount ...` / `... is not a shielded address: ...`.

Fixtures (only expected.json changed; SHA-256):
    f4575f72a6890ede4b9972961f83d4bbe48db3f0905b97a73ff7efd3dc7fb783  expected.json
    31fbeb3212e024e5839e29f9bdf23c0bbd6e34eb2ffcefb5c9085b3196992ff2  policy.json
    2144cafbbd06c1cd165105754a8ee1043167ed68b2256e150c991f82b055b8f7  proposal-expired.json
    457f0ab49d28ba0c18e3be1e266ed09fa94f1bd7f3105155b88c8dc95fc786c2  proposal-fee-raised.json
    773be56449eefaba00f819a92aa48e6d8be8057f96e39e5a8da45a01b2491453  proposal-substituted-recipient.json
    c621fc9531f95a04be2aa83d217d0040b19b27254d7bce483dbf6243a558b81b  proposal-tampered-output.json
    6f2135c940a38af710e137d2da0ff42147bd6d9a2bf18bd3fc6973bef044b3bd  proposal-unbound.json
    50f1f1cc5df58bfc1126bc9279a96fc1a47c0d0a192fa6239988d8f4d828129b  proposal-valid.json
    dddb4624c6f290948be9769735b13a445d7e4d201c85bf8e044438d808f91016  proposal-value-mismatch.json
    7ce496a463c09dec560070875c12e10781b14a31f944bfb1905c07e6cd751832  proposal-wrong-expected.json
    f75a09d8ec62da397010202e053d192a429710ecb566faf29d8d1381f07ee8aa  signer-seeds.json

Tests: `cargo +1.98.1 test --release -p randprotocol-msig`: 16 passed (incl. fixtures equality, an_expected_recipient_nobody_pays_is_refused, an_amount_pin_is_met_exactly_or_refused); wasm32 check ok; `-p randprotocol-client --lib --bins`: 225 + 24 passed; clippy: no warnings in msig/client.
