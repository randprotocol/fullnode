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

## The lock (CON-4) — wire-coordinated

A validator's `locked_qc` is a promise to the rest of the set: it will not vote for a branch that
does not extend the locked block unless a newer QC releases it. Since v0.5.1 the lock survives a
restart (audit v3, CON-1b), but until v0.5.4 it was taken back on evidence anyone could
manufacture: once `MAX_FETCH_ATTEMPTS` = 8 fetches for the locked block had failed — each a
`Block(None)` or a timeout from a peer picked by an unsigned status — `fallback_high_qc` lowered
the lock to the committed head's QC. Eight sybils released any honest validator's lock. Two
changes close that:

- **The locked block is persisted beside the lock.** `Action::PersistSafety(SafetyState,
  Option<Block>)` carries the block the new `locked_qc` certifies while the lock is above the
  head; the node writes it under `META_LOCKED_BLOCK` (CF_META, fsynced like the safety state,
  replaced when it changes, deleted when the lock is back at the head — an older build never
  reads the key). `HotStuff::resume` re-executes it on the head and puts it back in the tree, so
  a restarted validator checks the next proposal against its own promise without a fetch. That
  alone removes the whole-fleet-restart case the old fallback existed for. (A lock that advanced
  past a block not on the head — the lock can move without a commit — keeps the fetch path: the
  block's parent is not there to execute on.)
- **Release only on signed not-held.** A validator asked `BlockByHash(h)` for a block it holds
  neither in its tree nor in its committed chain answers `SyncResponse::NotHeld` — a Dilithium2
  signature over `rand-not-held-1 ‖ genesis_hash ‖ h`, bound to one chain and one block; an
  observer answers `Block(None)` as before, its word carrying no stake. The asker verifies the
  signer against its *current* validator set (a member of an earlier epoch's set counts nothing),
  records the signer's stake against the hash, and lowers the lock only once the signers hold
  **strictly more than a third of the set's stake** (`ValidatorSet::has_third`) — so at least one
  honest validator is among them and the block is genuinely unobtainable. Timeouts and
  `Block(None)` still count as fetch attempts, bounding the fetch loop, but never as evidence.
  `high_qc` keeps the old fallback: it is liveness state, not a promise. Evidence is kept for the
  locked block alone and cleared when the block arrives, when the lock is released, and on commit.

What this costs: with fewer than a third of the stake attesting — an old peer never answers
`NotHeld`, a partition, or genuinely fewer than that many validators missing the block — a lock
on an unobtainable block holds, and that validator withholds its vote until a newer QC forms
without it (spec D15: a rare stall is accepted; a lock is never released on unsigned evidence
again). **Roll note:** the rule gathers evidence only from peers running v0.5.4, so in a mixed
fleet a lock on an unobtainable block holds until the fleet has rolled whole — roll every
validator, one at a time, before relying on it (`docs/deploy.md`).

Regression tests: `eight_unsigned_not_found_replies_no_longer_release_the_lock` (fails on
v0.5.3: the first fallback lowered the lock),
`not_held_from_more_than_a_third_of_the_stake_releases_the_lock_and_less_does_not`,
`a_not_held_from_outside_the_current_set_or_for_another_chain_counts_nothing`,
`a_resumed_validator_finds_its_locked_block_without_a_fetch`; `leader_falls_back_when_high_qc_block_is_unobtainable`
keeps the high-QC half and resumes the chain on signed evidence; the node's
`a_validator_answers_an_unknown_hash_with_a_signed_not_held_and_an_observer_does_not` and the
storage round trip `locked_block_roundtrip_and_clear`.
