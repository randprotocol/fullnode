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
