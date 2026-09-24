# Consensus: the rules added since the architecture write-up

`docs/architecture.md` §6 describes chained HotStuff as this node runs it — the leader schedule,
the vote rule and the lock, local QC assembly, the three-consecutive-view commit rule, the
timeouts and the bounds on speculative state. This page holds what the audit-v4 release (v0.5.4)
added on top, one section per rule, with the class of change each one is (spec
`docs/superpowers/specs/2026-09-24-audit-v4-v0.5.4-design.md` §2): node-only policy rolls one
node at a time; a wire-coordinated change gathers its evidence only once the fleet has rolled;
a genesis-gated rule activates at a chain cut.

## Sibling proposals (CON-3) — node-only

A leader used to be able to fill a replica's 512-block speculative tree with siblings: any
leader-signed block on a certified parent, for any view up to `MAX_VIEW_AHEAD` ahead, was
executed and inserted, and the tree was pruned only on commit — which needs a proposal the full
tree then refused (`TreeFull`). Three local acceptance rules close that
(`crates/randprotocol-core/src/consensus/hotstuff.rs`, `on_proposal`); a block refused by any of
them is still valid to a replica that judges it differently, so none is a validity rule:

- **One block per (view, leader).** The first block a leader is seen to sign for a view is the
  one the replica holds; a second, different block for the same view from the same leader is
  refused as `ConsensusError::Equivocation { view, first, second }` and both hashes are logged.
  The record follows the tree: entries at or under the committed head's view, and entries whose
  block was pruned or evicted, are dropped with it.
- **A proposal window.** A block whose view is more than `PROPOSAL_VIEW_WINDOW` = 8 views past
  the replica's current view is refused as `ConsensusError::ViewTooFarAhead` before its
  signature is checked, and is not kept as an orphan. Views move on QCs and NewViews; a replica
  that is far behind catches up through the QCs it assembles from gossiped votes and through
  block sync, never through a far-future proposal. (The pacemaker itself — one signed NewView
  still pulls a replica forward — is the open B3 item and is unchanged here.)
- **Eviction when full.** When the tree is at `max_tree_blocks`, blocks off the certified chain
  — anything not on the path from the committed head up to the high QC's block or the locked
  block — are evicted oldest view first until there is room, then whatever descended from an
  evicted block. Only then is `TreeFull` returned, so the proposal that extends the high QC
  always fits. An evicted block is uncertified speculation a peer can re-send.

Regression tests (`consensus/tests.rs`): `a_leaders_second_block_for_one_view_is_refused_as_equivocation`,
`a_proposal_past_the_view_window_is_refused_not_stored`,
`six_hundred_siblings_do_not_stop_the_honest_leaders_proposal` (fails on v0.5.3 with `TreeFull`).

## The lock (CON-4) — wire-coordinated; durable pending blocks (audit v5)

A validator's `locked_qc` is a promise to the rest of the set: it will not vote for a branch that
does not extend the locked block unless a newer QC releases it. Since v0.5.1 the lock survives a
restart (audit v3, CON-1b), but until v0.5.4 it was taken back on evidence anyone could
manufacture: once `MAX_FETCH_ATTEMPTS` = 8 fetches for the locked block had failed — each a
`Block(None)` or a timeout from a peer picked by an unsigned status — `fallback_high_qc` lowered
the lock to the committed head's QC. Eight sybils released any honest validator's lock. Two
changes close that, and v0.5.5 (audit v5) tightens both:

- **Every certified block is persisted** (v0.5.5; until then only the locked block was, beside
  the lock under `META_LOCKED_BLOCK`). Whenever the high QC rises to a block the replica holds —
  and whenever the block a high QC already named arrives — the replica emits
  `Action::PersistPending(Vec<Block>)`: the certified chain from the committed head's child up
  to the high QC's block (and the locked block's, when the lock is off that chain), in height
  order, a few blocks in steady state. The node writes the whole set under `META_PENDING_BLOCKS`
  (CF_META, one bincode `Vec<Block>`, fsynced like the safety state, replaced on every write,
  deleted when empty), *after* the `Commit` in the same batch — the replica emits the set after
  the commit's prune, so a crash between the two leaves a set that starts at the new head, which
  `resume` skips over. `HotStuff::resume` takes the set and re-executes each block on its parent
  in order: a block at or under the head is skipped, a block whose parent is not held is dropped
  silently (never inserted), and the high QC and the lock are then restored from the safety
  state exactly as before. So after a restart — a whole-fleet one included — the block the
  persisted high QC or lock names is one the replica holds: no fetch, no not-held round, no ghost
  QC. Those paths stay for the genuine cases (a set lost with the disk, a lock advanced past a
  block that never arrived). The v0.5.4 key is read once more by the first v0.5.5 startup on
  such a database, folded into the pending set, and retired (`Storage::clear_locked_block`).
- **Release only on a signed not-held quorum.** A validator asked `BlockByHash(h)` for a block it
  holds neither in its tree nor in its committed chain answers `SyncResponse::NotHeld` — a
  Dilithium2 signature over `rand-not-held-1 ‖ genesis_hash ‖ h`, bound to one chain and one
  block; an observer answers `Block(None)` as before, its word carrying no stake. The asker
  verifies the signer against its *current* validator set (a member of an earlier epoch's set
  counts nothing), records the signer's stake against the hash, and lowers the lock only once the
  signers hold **a quorum — strictly more than two thirds of the set's stake**
  (`ValidatorSet::has_quorum`, since v0.5.5; v0.5.4 released on more than a third, which is not
  sound: a third is exactly what the Byzantine validators may hold, so nobody honest need be
  among them). Timeouts and `Block(None)` still count as fetch attempts, bounding the fetch
  loop, but never as evidence. `high_qc` keeps the old fallback: it is liveness state, not a
  promise. Evidence is kept for the locked block alone and cleared when the block arrives, when
  the lock is released, and on commit.

Three more rules from watching chain 14 stall on the v0.5.4 build (2026-09-24), all node-only:

- **A persisted high QC on a block the pending set lacks is a ghost.** With every certified
  block persisted, every legitimately certified block above the head is in the set, so `resume`
  does not restore such a QC: `high_qc` falls to the highest QC certifying a block the replica
  holds (the lock is untouched). Every node of the fleet had exactly that state — a high QC on a
  block nobody held, restored at every restart and re-announced by every NewView.
- **The fallback lands on the highest certified block held.** `fallback_high_qc` (and the rule
  above) falls to `max` by view over the head's QC, the lock's when its block is held, and every
  certificate a tree entry remembers for its block (a child's `justify`, or a QC that was the
  high QC — `Entry::qc`), never blindly to the head's: a replica holding certified pending blocks
  248948..248952 above head 248947 fell back to the head's QC and proposed a sibling of 248948
  that nobody could vote for.
- **By-hash fetches expire.** `fetch_block` first drops an inflight request older than the wire's
  `sync_request_timeout` — the abandon rule `sync_from` applies to batch requests — so a request
  libp2p neither answers nor reports (node A: one `NotHeld`, one timeout, then no third attempt
  for thirty minutes) no longer blocks the hash for good; it was counted as an attempt when sent.

Regression tests: `a_persisted_high_qc_on_a_block_the_pending_set_lacks_is_dropped_at_resume`,
`a_fallback_lands_on_the_highest_certified_block_held` (both fail on v0.5.4: the head's view-0
QC), the node's `an_inflight_fetch_older_than_the_timeout_does_not_block_a_new_attempt`.

What this costs: with less than a quorum of the stake attesting — an old peer never answers
`NotHeld`, a partition, or genuinely fewer than that many validators missing the block — a lock
on an unobtainable block holds, and that validator withholds its vote until a newer QC forms
without it (spec D15: a rare stall is accepted; a lock is never released on unsigned evidence
again). With every certified block persisted, that position is reached only when the block was
never on this node's disk at all. **Roll note:** the rule gathers evidence only from peers running
v0.5.4 or later, so in a mixed fleet a lock on an unobtainable block holds until the fleet has
rolled whole — roll every validator, one at a time, before relying on it (`docs/deploy.md`).

Regression tests: `eight_unsigned_not_found_replies_no_longer_release_the_lock` (fails on
v0.5.3: the first fallback lowered the lock), `not_held_releases_the_lock_only_on_a_quorum`
(fails on v0.5.4: three of six released),
`a_not_held_from_outside_the_current_set_or_for_another_chain_counts_nothing`,
`a_restart_keeps_the_blocks_a_qc_certified` (fails on v0.5.4: the restart drops the block the
persisted high QC names), `a_stale_pending_set_is_dropped`,
`a_resumed_validator_finds_its_locked_block_without_a_fetch`; `leader_falls_back_when_high_qc_block_is_unobtainable`
keeps the high-QC half and resumes the chain on signed evidence; the node's
`a_validator_answers_an_unknown_hash_with_a_signed_not_held_and_an_observer_does_not` and
`a_v054_locked_block_is_read_once_then_superseded_by_the_pending_set`; the storage round trips
`pending_blocks_round_trip_and_an_empty_set_deletes_the_key` and
`the_v054_locked_block_is_read_once_then_cleared`.

## Signing domains (consensus domain v1) — genesis-gated

Until v0.5.4 no signed consensus message named the chain: a vote signed `rand-vote ‖ view ‖
hash`, a new-view `rand-newview ‖ view ‖ bincode(high_qc)`, and a proposer signed its block's
`rand-block` header hash. A validator key reused across chains — every chain since 8 ran on the
same keys until chain 14 — could have its signatures replayed from one chain to another wherever
views and hashes lined up. The genesis file's `consensus_domain` field switches every one of them
(`crates/randprotocol-core/src/types/block.rs`, `SigningDomain`):

| | version 0 (absent — chain 14) | version 1 (the next cut) |
|---|---|---|
| vote | `rand-vote ‖ view ‖ hash` | `rand-vote-2 ‖ genesis ‖ view ‖ hash` |
| new-view | `rand-newview ‖ view ‖ bincode(high_qc)` | `rand-newview-2 ‖ genesis ‖ view ‖ bincode(high_qc)` |
| proposal | the `rand-block` header hash | `rand-block-2 ‖ genesis ‖ bincode(header)` |

Every message is a 32-byte BLAKE3 digest under its tag, signed with Dilithium2. The not-held
attestation (above) is new and binds the genesis hash under every version. A block's *identity*
— `Block::hash`, the `rand-block` header hash, which is also what a QC certifies and what the
genesis hash itself is — is the same under both versions: the genesis hash is that hash of the
genesis block, so it cannot prefix itself.

The domain travels three ways, all from the genesis file: `ConsensusConfig.domain`
(`GenesisState::signing_domain()` — the version over the genesis hash) is what the replica signs
and verifies with; the `Ledger` carries the same domain as non-state data for its own proposer
signature check on replay and sync (`reload_ledger` restores it, like `epoch_blocks`); and the
storage integrity check and the sync path verify certificates under it. A replica that forgot it
would sign under v0 on a v1 chain and be refused by every peer — which is what the simulator's
`config_of` showed when it did.

Gated: the field is committed to the genesis binding only when present (`b"consensus_domain" ‖
version`), so chain 14's file, which has none, builds to the pinned hash and its validators sign
exactly what they always signed (`domain_v0_signs_exactly_what_it_signed_before`). A version this
build does not know is refused by `Genesis::validate` (`GenesisError::BadConsensusDomain`). The
next cut sets `"consensus_domain": 1` (`docs/deploy.md`).

Regression tests: `a_v1_vote_for_one_chain_does_not_verify_under_another`,
`a_v1_new_view_for_one_chain_does_not_verify_under_another`,
`domain_v0_signs_exactly_what_it_signed_before`,
`a_genesis_with_consensus_domain_1_commits_it_and_one_without_is_unchanged`, and
`the_consensus_suite_holds_under_signing_domain_v1`, which runs the simulator's commit, restart,
timeout, lock and epoch test bodies again under version 1 and refuses a v0 vote there.
