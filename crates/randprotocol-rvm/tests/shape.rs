//! `height_groups`: the one function the program and the tape both call to order a round's
//! matrices into height groups (Cut A), so the two cannot disagree.
use randprotocol_rvm::shape::height_groups;

#[test]
fn height_groups_are_tallest_first_and_stable_within_a_height() {
    // Heights by matrix index: 13, 15, 17, 16, 9, 9, 17, 11, 3 (the cs8 inner shape's degree bits).
    let groups = height_groups(&[13, 15, 17, 16, 9, 9, 17, 11, 3]);
    assert_eq!(groups, vec![vec![2, 6], vec![3], vec![1], vec![0], vec![7], vec![4, 5], vec![8]]);
}

#[test]
fn a_single_height_is_one_group_in_index_order() {
    assert_eq!(height_groups(&[5, 5, 5]), vec![vec![0, 1, 2]]);
}

#[test]
fn an_empty_round_has_no_groups() {
    assert!(height_groups(&[]).is_empty());
}

/// The arity schedule is invariant under the blowup: `compute_log_arity_for_round` reads only
/// height differences, and the blowup shifts every input height and the final height equally —
/// so the round heights all move by the same amount and the arities do not change.
#[test]
fn the_fri_schedule_is_invariant_under_the_blowup() {
    use randprotocol_rvm::shape::{fri_schedule_for_tests, INNER_LOG_BLOWUP};
    // The toy rVM shape's extended degree bits at tier 8 (cpu 9, reg 10, ram 10, poseidon2 9, public 9, range 9, program 9).
    let bits = [9usize, 9, 10, 10, 9, 9, 9];
    let at_three = fri_schedule_for_tests(&bits, INNER_LOG_BLOWUP).unwrap();
    let at_two = fri_schedule_for_tests(&bits, 2).unwrap();
    assert_eq!(at_three.iter().sum::<usize>() + INNER_LOG_BLOWUP, 10 + INNER_LOG_BLOWUP, "folds from the tallest input height to the final height");
    assert_eq!(at_two.iter().sum::<usize>() + 2, 10 + 2);
    assert!(at_two.iter().all(|&a| a >= 1 && a <= 3), "arities stay within max_log_arity: {at_two:?}");
    assert_eq!(at_two, at_three, "the schedule is blowup-invariant: every round height shifts by the same amount");
}
