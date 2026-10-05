//! RandProtocol patch (2026-10-04): quotient layout.

/// How an instance's quotient chunks are committed in the quotient round.
///
/// Plonky3 0.7.0 commits one matrix per chunk: `Challenge::DIMENSION` data columns, plus whatever
/// a hiding PCS appends to every matrix (random codewords) and the hiding MMCS salts per row. For an
/// instance with sixteen chunks that is sixteen matrices of 2 + 4 columns at one height, 200 %
/// overhead on the data. `PerInstance` commits one matrix per instance — every chunk's data
/// columns side by side, the random codewords once — at the same height. The two-adic PCS reads
/// nothing of a matrix but its height and its rows, so the chunk polynomials, their ZK
/// randomisation and the verifier's recomposition are unchanged; only the commitment and the
/// opening rows are laid out differently. A proof made under one layout is refused under the
/// other by the PCS (a matrix-count or row-width mismatch), never silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotientLayout {
    /// One committed matrix per quotient chunk — upstream Plonky3 0.7.0's layout. The default
    /// every caller of `prove_batch` / `verify_batch` keeps.
    PerChunk,
    /// One committed matrix per instance: `chunks · DIMENSION` data columns, then the hiding
    /// PCS's random codewords once.
    PerInstance,
}
