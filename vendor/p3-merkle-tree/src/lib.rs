#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

pub mod counter_rng;
mod hiding_mmcs;
mod merkle_tree;
mod mmcs;
mod pruning;

pub use counter_rng::CounterModeRng;
pub use hiding_mmcs::*;
pub use merkle_tree::MerkleTree;
pub use mmcs::{MerkleTreeError, MerkleTreeMmcs, PrunedBatchOpening, PrunedProofError};
pub use p3_symmetric::MerkleCap;
pub use pruning::{MerkleAuthPath, PrunedMerklePaths};
