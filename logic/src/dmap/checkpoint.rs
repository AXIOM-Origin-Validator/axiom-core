//! DMAP Checkpoint Types
//!
//! A checkpoint is a snapshot of the AVM interpreter state at a specific
//! instruction count. Checkpoints are collected automatically during execution
//! at DMAP_CHECKPOINT_INTERVAL boundaries.

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

/// A single DMAP checkpoint — snapshot of CPU + memory + register state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmapCheckpoint {
    /// Instruction count when this snapshot was taken
    pub instruction_count: u64,

    /// Program counter (RV32IM PC value)
    pub pc: u32,

    /// Merkle root of all guest memory pages at this point
    pub memory_root: [u8; 32],

    /// BLAKE3 hash of all 32 RISC-V registers (Improvement A)
    /// Any instruction-level divergence changes register state, making
    /// checkpoint hash diverge at the next boundary.
    #[serde(default)]
    pub register_hash: [u8; 32],
}

/// A revealed checkpoint with its Merkle proof (for attestation verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedCheckpoint {
    /// Index in the checkpoint sequence (0-based)
    pub index: u64,

    /// The checkpoint snapshot
    pub checkpoint: DmapCheckpoint,

    /// Merkle proof from this checkpoint's hash to the checkpoint_commitment root
    pub merkle_proof: Vec<[u8; 32]>,
}

/// Complete DMAP trace collected during execution
///
/// Contains all checkpoints and the Merkle commitment over them.
/// Used to construct DmapAttestation proofs.
#[derive(Debug, Clone)]
pub struct DmapTrace {
    /// All checkpoints collected during execution
    pub checkpoints: Vec<DmapCheckpoint>,

    /// Merkle root over all checkpoint hashes (the commitment)
    pub commitment: [u8; 32],
}

impl DmapTrace {
    /// Build a trace from collected checkpoints
    pub fn from_checkpoints(checkpoints: Vec<DmapCheckpoint>) -> Self {
        let hashes: Vec<[u8; 32]> = checkpoints
            .iter()
            .map(checkpoint_hash)
            .collect();

        let commitment = super::merkle::compute_merkle_root(&hashes);

        DmapTrace {
            checkpoints,
            commitment,
        }
    }

    /// Get a revealed checkpoint with its Merkle proof
    pub fn reveal(&self, index: u64) -> Option<RevealedCheckpoint> {
        let idx = index as usize;
        if idx >= self.checkpoints.len() {
            return None;
        }

        let hashes: Vec<[u8; 32]> = self.checkpoints
            .iter()
            .map(checkpoint_hash)
            .collect();

        let proof = super::merkle::generate_merkle_proof(&hashes, idx);

        Some(RevealedCheckpoint {
            index,
            checkpoint: self.checkpoints[idx].clone(),
            merkle_proof: proof,
        })
    }

    /// Number of checkpoints
    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
}

/// Compute BLAKE3 hash of a checkpoint (for Merkle tree leaf)
pub fn checkpoint_hash(cp: &DmapCheckpoint) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(super::DMAP_COMMIT_DOMAIN);
    hasher.update(&cp.instruction_count.to_le_bytes());
    hasher.update(&cp.pc.to_le_bytes());
    hasher.update(&cp.memory_root);
    hasher.update(&cp.register_hash);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_hash_deterministic() {
        let cp = DmapCheckpoint {
            instruction_count: 10000,
            pc: 0x1234,
            memory_root: [0xAB; 32],
            register_hash: [0x11; 32],
        };
        let h1 = checkpoint_hash(&cp);
        let h2 = checkpoint_hash(&cp);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_checkpoint_hash_changes() {
        let cp1 = DmapCheckpoint {
            instruction_count: 10000,
            pc: 0x1234,
            memory_root: [0xAB; 32],
            register_hash: [0x11; 32],
        };
        let cp2 = DmapCheckpoint {
            instruction_count: 10000,
            pc: 0x1234,
            memory_root: [0xCD; 32], // different memory
            register_hash: [0x11; 32],
        };
        assert_ne!(checkpoint_hash(&cp1), checkpoint_hash(&cp2));
    }

    #[test]
    fn test_trace_reveal() {
        let checkpoints = vec![
            DmapCheckpoint { instruction_count: 10000, pc: 0x100, memory_root: [1; 32], register_hash: [0; 32] },
            DmapCheckpoint { instruction_count: 20000, pc: 0x200, memory_root: [2; 32], register_hash: [0; 32] },
            DmapCheckpoint { instruction_count: 30000, pc: 0x300, memory_root: [3; 32], register_hash: [0; 32] },
        ];
        let trace = DmapTrace::from_checkpoints(checkpoints);
        assert_eq!(trace.len(), 3);

        let revealed = trace.reveal(1).unwrap();
        assert_eq!(revealed.index, 1);
        assert_eq!(revealed.checkpoint.pc, 0x200);
        assert!(!revealed.merkle_proof.is_empty());
    }
}
