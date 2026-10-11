# Private multisig: the M-of-N check inside the auth proof

> Status: **design, 2026-10-11.** Nothing here is built. The public multisig register
> (`docs/superpowers/specs/2026-10-08-multisig-design.md`, `docs/multisig.md`) is unchanged by
> this design and stays the treasury's home until phase 5.

## 1. Problem

The public multisig register gives M-of-N control by checking Dilithium2 signatures **natively in
the node**. Whatever the node checks, it must see, so the account id, its keys, the threshold, the
balance, every payout and the indices that signed are all public. That is fine for an auditable
treasury and wrong for everyone else: a user who wants a 2-of-3 cold wallet has to give up the
privacy every single-key note has.

Classical chains hide the policy with signature aggregation (MuSig2, FROST, BLS). Those rest on
discrete logs or pairings, and lattice threshold signatures are not standardised or deployed.
The post-quantum way to hide a threshold is to **verify the M signatures inside a zero-knowledge
proof**, so the chain verifies one proof and learns nothing about the policy.

## 2. Where the check goes: a second auth guest

Split authorisation (`docs/shielded.md` §2, `docs/prover.md` §8) already separates *who may spend*
from *what is spent*:

```
auth guest    private: sk, salt       nk = H(NK, sk);  c = H(AUTH, nk ‖ salt)     public segment: binding
bundle v3     private: nk, salt, …    pk_self = H(PK, nk); folds c into its digest
ledger        auth proof verifies against hc_auth and the transaction binding, and its c == auth_commit
```

The bundle guest never sees `sk`; it sees only `nk`. So **a different way of proving "I may act
for `nk`" needs a different auth guest and nothing else**. The multisig auth guest replaces
"I know `sk` with `H(NK, sk) = nk`" by "`nk` was derived from a policy, and M of that policy's
keys signed this transaction's binding":

```
multisig auth guest   private: msk, salt, threshold, M_MAX signature slots
                      nk = H(NK_MS, msk ‖ policy);  c = H(AUTH, nk ‖ salt)        public segment: binding
```

It publishes the **same** `c` as the single-key guest. Bundle guest v3, the transaction format,
`auth_commit`, the binding and the txid domain are all unchanged.

Rejected alternatives:

| alternative | why not |
|---|---|
| Threshold check inside bundle guest v4 | every spend pays for M Dilithium verifications, or the bundle guest forks into two programs anyway; a new `hc_bundle` is a hard fork for every wallet and prover |
| Each signer proves its own hash-key auth proof; the ledger verifies M of them | M × 1.37 MB on the wire (the 4 MiB block holds one 3-proof transaction), and M is visible |
| SLH-DSA (SPHINCS+) keys verified with the existing SHA-256 chip | about 2 200 compressions per verification (~140 k sha256 rows), not clearly cheaper than Dilithium2; new keys for every signer; 7 856-byte signatures; slow signing. Kept as the fallback if phase 3 fails |
| Lattice threshold signatures | not standardised, multi-round, no audited implementation |

## 3. The policy and the address

New Poseidon2 domain tags, node-local range (`HIDDEN_BUNDLE_DOMAIN = 64` and `AUTH_DOMAIN = 65`
are taken):

| tag | value | hashes |
|---|---|---|
| `MS_LEAF` | 66 | one signer's Dilithium2 public key: 1 312 bytes as 328 little-endian words |
| `MS_NODE` | 67 | a Merkle node: `left ‖ right` (16 words) |
| `MS_POLICY` | 68 | `threshold ‖ signer_root` (9 words) |
| `NK_MS` | 69 | `msk ‖ policy` (16 words) |

```
leaf_i       = H(MS_LEAF, pk_i)                  for i < n;   [0; 8] for n ≤ i < 16
signer_root  = depth-4 Merkle root over leaf_0 … leaf_15, node = H(MS_NODE, left ‖ right)
policy       = H(MS_POLICY, threshold ‖ signer_root)
nk           = H(NK_MS, msk ‖ policy)
pk, address, ovk, kem keys = exactly as for a single-key wallet, from nk
```

- `N_MAX = 16` (depth 4), so N is hidden. `1 ≤ threshold ≤ M_MAX`; `M_MAX` is fixed in phase 2 by
  measurement (target 3; see §6).
- `msk` is 8 random words that every signer holds. It is there so that someone who learns the
  signer keys (from the public register, for example) cannot compute `nk` and read the account.
  `msk` alone cannot spend: a spend also needs M signatures over its binding.
- Holding `nk` (or `msk` and the policy) is a **viewing** key for the account, exactly as `nk` is
  for a single-key wallet: every signer can scan, decrypt and see the history.
- Because `pk = H(PK, nk)`, a multisig address cannot be told apart from a single-key one, and its
  notes share the one shielded pool.
- The wallet refuses to create a policy with a repeated key, `threshold > M_MAX` or `n > 16`. The
  guest enforces distinct *indices*, not distinct keys: a duplicated key only weakens its own
  creator's policy.

## 4. The multisig auth guest

A compiled Rust guest (`circuits/guests-compiled/msauth`, built by `rand-guest`), because a
Dilithium verifier is far beyond hand-assembly. Its Dilithium2 verifier is a `no_std` port of
`crystals-dilithium` 2.0.0's **round-3 `dilithium2`** (the module the node's `crypto.rs` uses, not
`ml_dsa_44`), with SHAKE built on the `KECCAK` syscall.

Private input: a fixed `MSAUTH_WORDS = 17 + M_MAX × 967` words, always all present, so the input
height is pinned and does not reveal M:

| offset | words | field |
|---|---|---|
| 0 | 8 | `msk` |
| 8 | 8 | `salt` (fresh per transaction, as for the single-key guest) |
| 16 | 1 | `threshold` |
| 17 + 967·s | 1 | slot `s`: `active` (0 or 1) |
| +1 | 1 | `index` (0..16) |
| +2 | 328 | `pk` (1 312 bytes LE) |
| +330 | 605 | `sig` (2 420 bytes LE) |
| +935 | 32 | Merkle path, leaf to root, 4 siblings |

Public segment: the transaction binding (`TX_BINDING_WORDS = 8`), read with `read_public`.

The relation, every check folding into one `bad` flag:

1. `1 ≤ threshold ≤ M_MAX`; every `active ∈ {0, 1}`.
2. Active slots have strictly increasing `index < 16` (so they are distinct).
3. Each active slot: `leaf = H(MS_LEAF, pk)`, the path from `leaf` at `index` gives
   `signer_root`, and every active slot gives the **same** root.
4. Each active slot: `dilithium2::verify(pk, m, sig)` with
   `m = "rand-msauth-1" ‖ binding as 32 bytes LE`. The prefix keeps a shielded-multisig signature
   from ever being valid as a public `MultisigPay`/`MultisigRotate` signature (those sign a
   32-byte blake3 digest with no prefix), and the other way round.
5. The number of active slots is at least `threshold`.
6. `policy = H(MS_POLICY, threshold ‖ signer_root)`, `nk = H(NK_MS, msk ‖ policy)`,
   `c = H(AUTH, nk ‖ salt)`.

Output slots 0..8: `c` if `bad == 0`, otherwise the guest-sdk panic sentinel. A sentinel never
equals any `auth_commit`, so the ledger's existing `AuthMismatch` refuses it. No new error path.

**Shape pinning.** The guest's tier is pinned to its worst case (`M_MAX` active slots), as
`AUTH_TIER` pins the single-key guest, so the proof's tier and heights are the same for every
policy and every M. The chain learns "multisig-authorised", and nothing else.

## 5. What the chain sees

| visible | hidden |
|---|---|
| that the auth proof is the multisig shape (its declared heights) | the account, `msk`, `nk` |
| the bundle's public fields, as for any v3 bundle | N, M, the threshold, the signer keys |
| the transaction size | which signers signed |
| | inputs, outputs, amounts, recipients (shielded, as always) |

Rotation is an ordinary M-of-N spend of every note to the address of a new policy (new keys,
threshold or `msk`). Replay protection is the nullifier, so no nonce and no mempool slot are
needed. A proposal prepared before a rotation dies when its notes are spent.

A delegated prover for the multisig auth proof needs `msk`, the policy and the signatures. That
gives it the account's viewing power and nothing more: the signatures are bound to one binding.
This is the same trust a v3 viewing-key prover job already carries.

## 6. Cost: the number that decides the phases

Estimate before measurement (phase 1 replaces it). A Dilithium2 verification in software on
RV32IM:

| part | estimate |
|---|---|
| ExpandA (16 polynomials, SHAKE128 rejection sampling) | ~80 permutations through the chip; ~60 k cycles of byte parsing |
| NTTs (≈13 × 1 024 butterflies, Montgomery with `MUL`/`MULH`) | ~200 k cycles |
| pointwise products, unpacking `z`/`t1`, `UseHint`, packing `w1` | ~120 k cycles |
| hashing `tr`, `mu`, `c̃` | ~15 permutations |
| **total** | **~400 k cycles, ~100 Keccak-f permutations** |

Tier 20 holds 1 048 575 cycles, so software verification fits about **two signatures**, and a
tier-20 proof does not fit a 48 GB laptop. The target is **`M_MAX = 3` at tier ≤ 19**, so a strong
prover-pool machine can prove it. If phase 2 misses that, phase 3 adds a coprocessor.

Wire size: the multisig auth proof is one proof at its pinned tier (~1.6–2 MB at Production FRI,
measured in phase 2), replacing the 1.37 MB single-key auth proof. A transfer with it is about
3.1–3.5 MB, which fits the 4 MiB default with no `Call`. `Genesis::validate`'s
`3 · max_proof_bytes + 1 MiB` rule already covers it if `max_proof_bytes` does.

## 7. Phases

| # | repo | deliverable | gate to the next phase |
|---|---|---|---|
| 1 | circuits | `dilithium-core` (`no_std` round-3 Dilithium2 verify over a `Keccak` trait) and a `dilithium-verify` measurement guest | known-answer agreement with `crystals-dilithium` 2.0.0 on ≥ 200 seeded cases plus every malformed class; cycles and permutations per verification recorded in `research/docs/04-guests.md` |
| 2 | circuits | `research/src/msauth.rs` (host model, tags, witness layout) and the `msauth` guest; cheating suite; proofs at `M_MAX` ∈ {2, 3, 5} | the tier at `M_MAX = 3`. ≤ 19: skip phase 3. Otherwise phase 3 |
| 3 | circuits | a `MODQ`/NTT chip for `q = 8 380 417` (one cpu row per 256-coefficient NTT layer, or per butterfly row), syscall 7, optional per proof like keccak's | `M_MAX = 3` at tier ≤ 19, re-measured |
| 4 | fullnode | re-vendor; genesis `hc_auth_multisig` (requires `hc_auth`); admission dispatches on the auth proof's declared heights (single-key shape → `hc_auth`, multisig shape → `hc_auth_multisig`, otherwise `InvalidAuthProof`), so there is no wire or txid change; prover witness kind `MultisigAuth`; `rand multisig-private address / prepare / sign / prove / submit`; wallet scanning by `nk` | real-proof e2e: a 2-of-3 private address receives, spends with signers 0 and 2, rotates; a 1-signature attempt is refused |
| 5 | cut | `hc_auth_multisig` in a chain's genesis | the treasury may move into a private account with an ordinary `MultisigPay` |

Each phase gets its own implementation plan when the one before has passed its gate. Phase 1 and
phase 2's plan is `docs/superpowers/plans/2026-10-11-private-multisig-phase1-2.md`.

## 8. Open questions

1. `M_MAX`: 3 is the target (2-of-3 and 3-of-5 both need ≤ 3 signatures). 5 only if phase 3
   makes it cheap.
2. Should the public register's signers' keys be reusable as private-policy keys? They can be:
   the signing message prefix keeps the two signature domains apart. The wallet may warn that
   reuse links the two accounts for anyone who knows both policies.
3. Detection tags (the viewing-key gap list) matter more here: every signer's wallet scans.
