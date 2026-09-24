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
