//! A hiding program commitment and the admitted-programs tree — the **host side** of the design
//! for monorepo issue 61 (ZKVM-108), and only the host side.
//!
//! **Status: not enforced by any proof.** The current constraint set publishes `hc` itself
//! (`tables::cpu::pv::HC0..7`), unsalted, and nothing here changes that: no AIR, public value,
//! verifier key or digest is touched by this module, and `Machine::verify` does not call it.
//! What is here is the arithmetic the next constraint set's rows would prove, fixed and tested
//! so the circuit, the full node and the wallet have one definition to agree with.
//! `docs/03-privacy.md`, "A hiding program commitment (ZKVM-108)", has the design and the
//! constraint change; this comment is the definitions.
//!
//! ## The two functions
//!
//! Both are sponges over the crate's Poseidon2 permutation in its usual shape (width 8, rate 4,
//! overwrite mode, a domain header in the capacity lanes), and both absorb `hc` as its four
//! **field-element lanes** (`hc_lanes`), not as its eight published words — in the circuit `hc`
//! is the four rate lanes of the last program-digest row's output state, so absorbing the lanes
//! is a copy between rows with no limb decomposition.
//!
//! - [`salted`]`(hc, salt)`, the published commitment `hc'`: start from
//!   `[0, 0, 0, 0, HCC, 0, 0, 1]`; overwrite the rate with the four salt words and permute;
//!   overwrite the rate with `hc`'s four lanes and permute; the digest is lanes `0..4`. Two
//!   permutations. The salt goes in first, exactly as `hash::input_digest`'s salt block does.
//! - [`node`]`(left, right)`, one level of the admitted-programs tree: start from
//!   `[0, 0, 0, 0, ADMIT_NODE, 0, 0, 1]`; absorb `left`, permute; absorb `right`, permute.
//!   Two permutations.
//!
//! The `1` in capacity lane 7 keeps both apart from every sponge a guest can compute: the
//! `POSEIDON2` syscall starts from the zero state, `POSEIDON2_LEN` from `[0, 0, 0, 0, n, 0, 0,
//! 0]`, and the three in-circuit digests from `[.., tag, x, y, 0]` — lane 7 is zero in all of
//! them, so no message length or header a guest chooses reproduces these start states.
//!
//! A tree of depth `d` has `2^d` leaves; a leaf is a program's `hc` lanes and an empty leaf is
//! `[0; 4]` (reaching it would need a program whose digest is zero). Proving membership is `d`
//! [`node`] evaluations, so the whole statement — commitment plus membership — is
//! [`permutations`]`(d) = 2 + 2d` permutations on top of the program digest a proof already
//! computes.
use crate::hash::{permute_state, split_digest};
use crate::machine::Val;
use p3_field::{PrimeCharacteristicRing, PrimeField64};

/// Domain tags for this module's two sponges. Distinct from every tag in `notes::domain`
/// (1..=16, 0xff) and from each other; `tests/program_commitment.rs` checks both.
pub mod domain {
    /// The salted program commitment `hc' = H(HCC; salt, hc)`.
    pub const HCC: u32 = 17;
    /// A node of the admitted-programs tree.
    pub const ADMIT_NODE: u32 = 18;
}

/// The deepest tree [`AdmittedSet`] builds: 2^32 admitted programs.
pub const MAX_DEPTH: usize = 32;

/// `hc`'s four field-element lanes from its eight published words (`hash::split_digest`'s
/// inverse). `None` if a lane is not canonical (`lo + hi·2^32 >= p`), which no honest `hc` is.
pub fn hc_lanes(hc: &[u32; 8]) -> Option<[Val; 4]> {
    let mut out = [Val::ZERO; 4];
    for i in 0..4 {
        let v = hc[2 * i] as u64 | (hc[2 * i + 1] as u64) << 32;
        if v >= Val::ORDER_U64 {
            return None;
        }
        out[i] = Val::new(v);
    }
    Some(out)
}

fn absorb2(tag: u32, first: [Val; 4], second: [Val; 4]) -> [Val; 4] {
    let mut s = [Val::ZERO; 8];
    s[4] = Val::from_u32(tag);
    s[7] = Val::ONE;
    s[..4].copy_from_slice(&first);
    s = permute_state(s);
    s[..4].copy_from_slice(&second);
    s = permute_state(s);
    [s[0], s[1], s[2], s[3]]
}

/// The salted commitment's lanes: `H(HCC; salt, hc)`.
pub fn salted_lanes(hc: [Val; 4], salt: [u32; 4]) -> [Val; 4] {
    absorb2(domain::HCC, salt.map(Val::from_u32), hc)
}

/// The salted commitment as eight words, the way a digest is published. `None` if `hc` is not
/// a canonical digest.
pub fn salted(hc: &[u32; 8], salt: [u32; 4]) -> Option<[u32; 8]> {
    Some(split_digest(salted_lanes(hc_lanes(hc)?, salt)))
}

/// Whether `(hc, salt)` opens `commitment` — what a user hands an auditor to disclose which
/// program one proof ran, without disclosing any other proof's.
pub fn opens(commitment: &[u32; 8], hc: &[u32; 8], salt: [u32; 4]) -> bool {
    salted(hc, salt).is_some_and(|c| &c == commitment)
}

/// One tree level: `H(ADMIT_NODE; left, right)`.
pub fn node(left: [Val; 4], right: [Val; 4]) -> [Val; 4] {
    absorb2(domain::ADMIT_NODE, left, right)
}

/// Permutations the statement adds to a proof for a tree of depth `depth`: two for the salted
/// commitment and two per level.
pub const fn permutations(depth: usize) -> usize {
    2 + 2 * depth
}

/// A membership path: the leaf's index and the sibling at each level, leaf level first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPath {
    pub index: u64,
    pub siblings: Vec<[Val; 4]>,
}

/// The root a path leads to from `hc`. `None` if the index does not fit the path's depth.
pub fn root_from_path(hc: [Val; 4], path: &AdmissionPath) -> Option<[Val; 4]> {
    let depth = path.siblings.len();
    if depth > MAX_DEPTH || (depth < 64 && path.index >> depth != 0) {
        return None;
    }
    let mut cur = hc;
    for (level, sib) in path.siblings.iter().enumerate() {
        cur = if (path.index >> level) & 1 == 0 { node(cur, *sib) } else { node(*sib, cur) };
    }
    Some(cur)
}

/// Whether `hc` is the leaf at `path.index` of the depth-`depth` tree with root `root`. The
/// depth is the verifier's, not the path's: a path of another length is refused, so an inner
/// node cannot be passed off as a leaf.
pub fn is_admitted(root: &[Val; 4], depth: usize, hc: &[u32; 8], path: &AdmissionPath) -> bool {
    if path.siblings.len() != depth {
        return false;
    }
    let Some(lanes) = hc_lanes(hc) else { return false };
    root_from_path(lanes, path).is_some_and(|r| &r == root)
}

/// The admitted-programs tree, built in full on the host: fixed depth, leaves in admission
/// order, empty leaves zero. For a full node's state this is the reference; a node would keep
/// it incrementally.
#[derive(Clone, Debug)]
pub struct AdmittedSet {
    depth: usize,
    /// `levels[0]` is the leaves that exist; `levels[l]` the nodes above them. Positions past
    /// the end of a level are that level's empty subtree.
    levels: Vec<Vec<[Val; 4]>>,
    /// `empty[l]` is the root of an all-empty subtree of height `l`.
    empty: Vec<[Val; 4]>,
}

impl AdmittedSet {
    /// A tree of `depth` levels over `programs` (each an `hc`). `None` if the depth is out of
    /// range, there are more programs than leaves, an `hc` is not canonical, or one repeats.
    pub fn new(depth: usize, programs: &[[u32; 8]]) -> Option<Self> {
        if depth == 0 || depth > MAX_DEPTH || programs.len() as u128 > 1u128 << depth {
            return None;
        }
        let mut seen = std::collections::HashSet::new();
        let mut leaves = Vec::with_capacity(programs.len());
        for hc in programs {
            if !seen.insert(*hc) {
                return None;
            }
            leaves.push(hc_lanes(hc)?);
        }
        let mut empty = vec![[Val::ZERO; 4]];
        for l in 0..depth {
            empty.push(node(empty[l], empty[l]));
        }
        let mut levels = vec![leaves];
        for l in 0..depth {
            let below = &levels[l];
            let above: Vec<[Val; 4]> = below.chunks(2).map(|c| node(c[0], if c.len() == 2 { c[1] } else { empty[l] })).collect();
            levels.push(above);
        }
        Some(Self { depth, levels, empty })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// The root the chain would hold in state.
    pub fn root(&self) -> [Val; 4] {
        self.levels[self.depth].first().copied().unwrap_or(self.empty[self.depth])
    }

    /// The root as eight words.
    pub fn root_words(&self) -> [u32; 8] {
        split_digest(self.root())
    }

    /// The membership path of the `index`-th admitted program; `None` past the end.
    pub fn path(&self, index: usize) -> Option<AdmissionPath> {
        if index >= self.len() {
            return None;
        }
        let siblings = (0..self.depth).map(|l| self.levels[l].get((index >> l) ^ 1).copied().unwrap_or(self.empty[l])).collect();
        Some(AdmissionPath { index: index as u64, siblings })
    }

    /// The path of the program with digest `hc`, if it is admitted.
    pub fn path_of(&self, hc: &[u32; 8]) -> Option<AdmissionPath> {
        let lanes = hc_lanes(hc)?;
        self.path(self.levels[0].iter().position(|l| *l == lanes)?)
    }
}
