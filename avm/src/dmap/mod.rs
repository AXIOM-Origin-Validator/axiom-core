//! DMAP — Deterministic Memory Attestation Protocol
//!
//! YPX-006: Probabilistic execution attestation via AVM memory checkpoints.
//! Replaces ZK proofs for standard transactions with a lightweight scheme
//! that samples memory at deterministic-but-unpredictable checkpoints.
//!
//! See docs/AXIOM_YPX-006_DMAP.md for full specification.

pub mod checkpoint;
pub mod challenge;
pub mod attestation;
pub mod verification;
pub mod merkle;
#[cfg(test)]
mod integration_tests;

pub use checkpoint::{DmapCheckpoint, DmapTrace};
pub use challenge::derive_challenges;
pub use attestation::DmapAttestation;
pub use verification::{verify_dmap_attestation, verify_with_reexecution, DmapResult, DMAP_MIN_CHECKPOINTS};
pub use merkle::{MerkleTree, compute_merkle_root, verify_merkle_proof};

/// Instructions between DMAP checkpoints (YPX-006 §9).
///
/// This is the *initial* interval. Collection is bounded (see
/// [`MAX_COLLECTED_CHECKPOINTS`]): once the collected set reaches the cap the
/// effective interval doubles and the set is decimated, so a huge run coarsens
/// its spacing rather than collecting unboundedly.
///
/// Set to 50k (was 10k) as a throughput lever: each checkpoint costs one
/// `memory_root()` (a page-Merkle build), so cost is linear in the checkpoint
/// count. This is **security-neutral** — detection `P = 1 − (1−f)^(vK)` (§2.3.1)
/// depends on the corrupted *fraction* `f` and the reveals `K`, not on the total
/// count `N`: a cheat that taints a fixed fraction of *execution* taints that
/// same fraction of checkpoints at any interval, and a propagating cheat taints
/// all downstream checkpoints regardless. A coarser interval only loses the
/// ability to pinpoint a sub-50k-instruction *non-propagating* divergence —
/// which by definition never reaches the output.
pub const DMAP_CHECKPOINT_INTERVAL: u64 = 50_000;

/// Upper bound on the number of interior checkpoints collected in a single run
/// (KI#39 performance fix).
///
/// Collecting one snapshot per fixed 10k-instruction interval means a ~608M-
/// instruction CL5 redeem would take ~60,800 snapshots — and each snapshot's
/// `memory_root()` hashes the (growing) allocated page set, so the cost is
/// roughly quadratic and collapses AVM throughput to ~10M instr/s (redeem hops
/// blow the SDK's 60s poll window). The security model only needs K
/// checkpoints *revealed* (see [`DMAP_NUM_CHALLENGES`]), not tens of thousands
/// *collected*. So the collector caps the set at this many: when the cap is
/// hit it doubles the interval and keeps every other checkpoint — an in-stream
/// power-of-two decimation that preserves a uniform sample spanning the whole
/// run while bounding total `memory_root` work to
/// O(MAX_COLLECTED · log(run/interval)). Detection is unaffected: reveals
/// sample K from the committed set and the verifier re-executes to each
/// revealed checkpoint's exact `instruction_count` (§2.3.1), independent of how
/// many were collected. 1024 keeps ≥42× headroom over K=24.
pub const MAX_COLLECTED_CHECKPOINTS: usize = 1024;

/// Number of challenged checkpoints per attestation (Fiat-Shamir).
///
/// K=24 — the size↔detection sweet spot; full derivation in
/// docs/AXIOM_YPX-006_DMAP.md §"Choosing K (challenge count)". Detection of a cheat
/// that taints fraction f of checkpoints across v=3 independent validators is
/// P = 1 − (1−f)^(vK); K=24 catches any cheat tainting ≥8% of checkpoints at 99.9%
/// per validator (≈1−10^-18 across the k=3 quorum), while keeping the attestation
/// ~14 KB. K=64 (S=192) was over-provisioned: it only extended coverage to f≥3.6%
/// at ~2.6× the attestation size, which bloated receipts past the delivery caps and
/// broke end-to-end redeem (KnownIssues KI#39). A cheat that taints <8% must diverge
/// in the final ~8% of execution, which the guaranteed final checkpoint (Improvement
/// F) catches directly — so high K buys almost nothing real.
pub const DMAP_NUM_CHALLENGES: u64 = 24;

/// BLAKE3 domain tag for challenge derivation (must be exactly 32 bytes)
pub const DMAP_CHALLENGE_DOMAIN: &[u8; 32] = b"AXIOM_DMAP_CHALLENGE_V1\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// BLAKE3 domain tag for checkpoint commitment
pub const DMAP_COMMIT_DOMAIN: &[u8] = b"AXIOM_DMAP_COMMIT";

/// Proof type discriminator for wire protocol
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofType {
    /// RISC Zero STARK proof (existing, heavyweight)
    #[default]
    Zkp = 0,
    /// DMAP attestation (new, lightweight)
    Dmap = 1,
}
