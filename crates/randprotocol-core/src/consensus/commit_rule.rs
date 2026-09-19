//! The three-chain commit rule, in one place.
//!
//! Chained HotStuff finalises a block `b` when three QCs sit in consecutive views above it: `b`'s
//! own certificate, one for its child `b1`, and one for its grandchild `b2`. `HotStuff::
//! update_lock_and_commit` evaluates that rule on the live path, where the blocks arrive one at a
//! time. [`committed_prefix`] evaluates the same rule over a run of blocks that arrived together,
//! which is what the sync path receives — and which, before audit v3's CON-1a, it never evaluated
//! at all: it committed every block that carried a valid QC of its own.
//!
//! A QC only says a block was certified. Blocks are certified and then abandoned in the normal
//! course of a view change, so "certified" is not "committed", and a peer serving a certified
//! branch could make a syncing node finalise a fork the chain never committed.

/// How many blocks of a parent-linked, QC-verified run are committed by the three-chain rule.
///
/// `views` are the blocks' views, in height order, contiguous, each block the parent of the next,
/// and every block's own QC already verified by the caller. Because a block's justify certifies
/// its parent, the three QC views the rule compares are the views of `b`, `b1` and `b2`
/// themselves.
///
/// Returns the length of the committed prefix: `b[i]` commits when `b[i+1]` and `b[i+2]` follow it
/// in consecutive views, and everything below a committed block is committed with it, so the
/// answer is the highest such `i`, plus one.
///
/// The last two blocks of a run therefore never commit on their own evidence — the blocks that
/// would prove them are not in the run. A syncing node holds them as ordinary pending blocks and
/// commits them through the live path when the chain's next blocks arrive.
pub fn committed_prefix(views: &[u64]) -> usize {
    let mut prefix = 0;
    for i in 0..views.len().saturating_sub(2) {
        // Checked, not saturating: at the top of the view space `saturating_add` would make
        // `MAX` and `MAX` look consecutive and commit a block on a chain that never advanced.
        let consecutive = views[i].checked_add(1) == Some(views[i + 1])
            && views[i].checked_add(2) == Some(views[i + 2]);
        if consecutive {
            prefix = i + 1;
        }
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_consecutive_three_chain_commits() {
        // 1, 2, 3: block 1 is committed by its child and grandchild.
        assert_eq!(committed_prefix(&[1, 2, 3]), 1);
        // Certified but never committed: a view change sits between each pair.
        assert_eq!(committed_prefix(&[1, 3, 5]), 0);
        assert_eq!(committed_prefix(&[1, 2, 4]), 0);
        // The run commits as far as its last three-chain reaches; ancestors ride along.
        assert_eq!(committed_prefix(&[4, 5, 6, 7, 8]), 3);
        assert_eq!(committed_prefix(&[1, 2, 3, 5]), 1);
        assert_eq!(committed_prefix(&[1, 2, 3, 4, 9, 10]), 2);
        // Too short to prove anything.
        assert_eq!(committed_prefix(&[]), 0);
        assert_eq!(committed_prefix(&[7]), 0);
        assert_eq!(committed_prefix(&[7, 8]), 0);
    }

    #[test]
    fn the_rule_is_immune_to_view_arithmetic_overflow() {
        assert_eq!(committed_prefix(&[u64::MAX - 1, u64::MAX, u64::MAX]), 0);
        assert_eq!(committed_prefix(&[u64::MAX, u64::MAX, u64::MAX]), 0);
    }
}
