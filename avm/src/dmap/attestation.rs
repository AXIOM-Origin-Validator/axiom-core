//! DMAP Attestation Construction
//!
//! AttestationProof bundles the execution evidence: CoreID, input/output hashes,
//! checkpoint commitment, and the K revealed checkpoints with Merkle proofs.

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use super::checkpoint::{DmapTrace, RevealedCheckpoint};
use super::challenge::derive_challenges;
use super::DMAP_NUM_CHALLENGES;

/// A complete DMAP attestation proving correct Core execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmapAttestation {
    /// BLAKE3 hash of axiom-core.elf (identifies which code ran)
    pub core_id: [u8; 32],

    /// BLAKE3 of serialized PublicInputs
    pub input_hash: [u8; 32],

    /// BLAKE3 of serialized PublicOutputs
    pub output_hash: [u8; 32],

    /// Total checkpoints collected during execution
    pub total_checkpoints: u64,

    /// Merkle root of all checkpoint hashes
    pub checkpoint_commitment: [u8; 32],

    /// The K challenged checkpoints with Merkle proofs
    pub revealed_checkpoints: Vec<RevealedCheckpoint>,

    /// Dilithium signature over (core_id || input_hash || output_hash || checkpoint_commitment)
    /// For client attestations: Ed25519 signature instead
    pub signature: Vec<u8>,

    /// TARDIS tick at time of execution
    pub tick: u64,

    /// Validator public key used for challenge derivation (Improvement B)
    /// Each validator derives different challenges, giving k×K independent samples.
    #[serde(default)]
    pub validator_pk: [u8; 32],
}

impl DmapAttestation {
    /// Construct an attestation from a DMAP trace
    ///
    /// # Arguments
    /// * `core_id` — BLAKE3 hash of the Core ELF
    /// * `input_hash` — BLAKE3 of serialized PublicInputs
    /// * `output_hash` — BLAKE3 of serialized PublicOutputs
    /// * `trace` — the DMAP trace from execution
    /// * `tick` — current TARDIS tick
    /// * `validator_pk` — validator's public key (for per-validator independent challenges)
    pub fn from_trace(
        core_id: [u8; 32],
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        trace: &DmapTrace,
        tick: u64,
        validator_pk: [u8; 32],
    ) -> Self {
        let total_checkpoints = trace.len() as u64;

        // Derive challenges (per-validator independent — Improvement B)
        let challenge_indices = derive_challenges(
            &core_id,
            &input_hash,
            &output_hash,
            &validator_pk,
            total_checkpoints,
            DMAP_NUM_CHALLENGES,
        );

        // Reveal challenged checkpoints with Merkle proofs
        let mut revealed = Vec::with_capacity(challenge_indices.len());
        for &idx in &challenge_indices {
            if let Some(r) = trace.reveal(idx) {
                revealed.push(r);
            }
        }

        DmapAttestation {
            core_id,
            input_hash,
            output_hash,
            total_checkpoints,
            checkpoint_commitment: trace.commitment,
            revealed_checkpoints: revealed,
            signature: Vec::new(), // Caller must sign
            tick,
            validator_pk,
        }
    }

    /// Get the data that should be signed
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(&self.core_id);
        payload.extend_from_slice(&self.input_hash);
        payload.extend_from_slice(&self.output_hash);
        payload.extend_from_slice(&self.checkpoint_commitment);
        payload.extend_from_slice(&self.tick.to_le_bytes());
        payload
    }

    /// Set the signature (after external signing)
    pub fn set_signature(&mut self, sig: Vec<u8>) {
        self.signature = sig;
    }

    /// Serialized size estimate (for wire protocol budgeting)
    pub fn estimated_size(&self) -> usize {
        // Fixed fields: 32*4 + 8 + 8 = 144 bytes
        // Each revealed checkpoint: ~32 (hash) + 4 (pc) + 8 (count) + proof (~log2(N)*32)
        // ceil(log2(N)) = number of bits to index N leaves, computed as exact
        // integer math (no_std f64 has no inherent .log2()/.ceil()). For N>1,
        // ceil(log2(N)) == bit-width of (N-1) == BITS - leading_zeros(N-1).
        let proof_depth = if self.total_checkpoints > 1 {
            let n = self.total_checkpoints as usize;
            (usize::BITS - (n - 1).leading_zeros()) as usize
        } else {
            0
        };
        let per_revealed = 76 + proof_depth * 32; // 76 = 8 + 4 + 32 + 32 (with register_hash)
        let revealed_total = self.revealed_checkpoints.len() * per_revealed;
        144 + revealed_total + self.signature.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::checkpoint::DmapCheckpoint;

    #[test]
    fn test_attestation_from_trace() {
        let checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: (i as u32) * 4 + 0x1000,
                memory_root: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                register_hash: [i as u8; 32],
            })
            .collect();

        let trace = DmapTrace::from_checkpoints(checkpoints);
        let core_id = [0xAA; 32];
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let vpk = [0x01; 32];

        let attestation = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );

        assert_eq!(attestation.total_checkpoints, 50);
        assert!(attestation.revealed_checkpoints.len() <= DMAP_NUM_CHALLENGES as usize);
        assert_eq!(attestation.core_id, core_id);
        assert_eq!(attestation.validator_pk, vpk);
        assert!(attestation.signature.is_empty()); // Not yet signed
    }

    #[test]
    fn test_signing_payload_deterministic() {
        let att = DmapAttestation {
            core_id: [1; 32],
            input_hash: [2; 32],
            output_hash: [3; 32],
            total_checkpoints: 10,
            checkpoint_commitment: [4; 32],
            revealed_checkpoints: Vec::new(),
            signature: Vec::new(),
            tick: 12345,
            validator_pk: [0; 32],
        };

        let p1 = att.signing_payload();
        let p2 = att.signing_payload();
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 32 * 4 + 8); // 136 bytes
    }

    #[test]
    fn test_estimated_size_reasonable() {
        let checkpoints: Vec<DmapCheckpoint> = (0..100u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000,
                memory_root: [i as u8; 32],
                register_hash: [0; 32],
            })
            .collect();

        let trace = DmapTrace::from_checkpoints(checkpoints);
        let att = DmapAttestation::from_trace(
            [0; 32], [0; 32], [0; 32], &trace, 0, [0; 32],
        );

        let size = att.estimated_size();
        // Wire budget: at K=24 (DMAP_NUM_CHALLENGES) a full attestation is ~14KB even
        // with hundreds of interior checkpoints; cap at 20KB as a regression guard.
        assert!(size < 20_000, "Attestation too large: {} bytes", size);
    }
}
