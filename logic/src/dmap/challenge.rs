//! DMAP Challenge Derivation
//!
//! Derives which checkpoints to reveal using Fiat-Shamir transform.
//! The challenge depends on output_hash, which commits to execution results.
//! This makes the challenge unpredictable before execution completes
//! but deterministic and independently verifiable afterward.

use alloc::vec::Vec;

/// Derive K challenge indices from public transaction data
///
/// The challenge determines which checkpoints the prover must reveal.
/// Any party can re-derive the same challenges from the same public data.
///
/// # Arguments
/// * `core_id` — BLAKE3 hash of the Core ELF (identifies which code ran)
/// * `input_hash` — BLAKE3 hash of serialized PublicInputs
/// * `output_hash` — BLAKE3 hash of serialized PublicOutputs
/// * `validator_pk` — validator's public key (Improvement B: per-validator independence)
/// * `total_checkpoints` — how many checkpoints were collected
/// * `num_challenges` — K, how many to reveal (protocol constant)
///
/// # Returns
/// Vector of checkpoint indices to reveal (may contain duplicates if K > N)
pub fn derive_challenges(
    core_id: &[u8; 32],
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
    validator_pk: &[u8; 32],
    total_checkpoints: u64,
    num_challenges: u64,
) -> Vec<u64> {
    if total_checkpoints == 0 {
        return Vec::new();
    }

    let mut indices = Vec::with_capacity(num_challenges as usize);

    for i in 0..num_challenges {
        // Build challenge input: core_id || input_hash || output_hash || validator_pk || counter
        // Including validator_pk gives each validator different challenges (Improvement B)
        let mut challenge_input = Vec::with_capacity(32 + 32 + 32 + 32 + 8);
        challenge_input.extend_from_slice(core_id);
        challenge_input.extend_from_slice(input_hash);
        challenge_input.extend_from_slice(output_hash);
        challenge_input.extend_from_slice(validator_pk);
        challenge_input.extend_from_slice(&i.to_le_bytes());

        // Keyed BLAKE3 hash with domain separation
        let digest = blake3::keyed_hash(
            super::DMAP_CHALLENGE_DOMAIN,
            &challenge_input,
        );

        // Extract index from first 8 bytes
        let raw = u64::from_le_bytes(
            digest.as_bytes()[0..8].try_into().unwrap()
        );
        indices.push(raw % total_checkpoints);
    }

    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let core_id = [1u8; 32];
        let input_hash = [2u8; 32];
        let output_hash = [3u8; 32];

        let vpk = [0u8; 32];
        let c1 = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, 100, 20);
        let c2 = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, 100, 20);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_different_outputs_different_challenges() {
        let core_id = [1u8; 32];
        let input_hash = [2u8; 32];
        let output_hash_a = [3u8; 32];
        let output_hash_b = [4u8; 32];

        let vpk = [0u8; 32];
        let ca = derive_challenges(&core_id, &input_hash, &output_hash_a, &vpk, 100, 20);
        let cb = derive_challenges(&core_id, &input_hash, &output_hash_b, &vpk, 100, 20);
        assert_ne!(ca, cb);
    }

    #[test]
    fn test_indices_within_range() {
        let core_id = [0xAB; 32];
        let input_hash = [0xCD; 32];
        let output_hash = [0xEF; 32];

        let vpk = [0u8; 32];
        let challenges = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, 50, 20);
        assert_eq!(challenges.len(), 20);
        for &idx in &challenges {
            assert!(idx < 50, "Challenge index {} out of range", idx);
        }
    }

    #[test]
    fn test_empty_checkpoints() {
        let core_id = [0; 32];
        let input_hash = [0; 32];
        let output_hash = [0; 32];
        let vpk = [0u8; 32];
        let challenges = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, 0, 20);
        assert!(challenges.is_empty());
    }

    #[test]
    fn test_distribution() {
        // With 100 checkpoints and 1000 challenges, expect reasonable spread
        let core_id = [0x42; 32];
        let input_hash = [0x43; 32];
        let output_hash = [0x44; 32];

        let vpk = [0u8; 32];
        let challenges = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, 100, 1000);

        // Count hits per bucket
        let mut counts = [0u32; 100];
        for &idx in &challenges {
            counts[idx as usize] += 1;
        }

        // Each bucket should have ~10 hits. Allow 0-30 range for randomness.
        let non_zero = counts.iter().filter(|&&c| c > 0).count();
        assert!(non_zero > 80, "Too many empty buckets: {}", 100 - non_zero);
    }

    #[test]
    fn test_validator_independence() {
        // Different validator PKs must produce different challenges (Improvement B)
        let core_id = [1u8; 32];
        let input_hash = [2u8; 32];
        let output_hash = [3u8; 32];
        let vpk_a = [0xAA; 32];
        let vpk_b = [0xBB; 32];

        let ca = derive_challenges(&core_id, &input_hash, &output_hash, &vpk_a, 100, 64);
        let cb = derive_challenges(&core_id, &input_hash, &output_hash, &vpk_b, 100, 64);
        assert_ne!(ca, cb, "Different validators must get different challenges");

        // Measure overlap — should be much less than 100%
        let set_a: std::collections::HashSet<u64> = ca.iter().copied().collect();
        let set_b: std::collections::HashSet<u64> = cb.iter().copied().collect();
        let overlap = set_a.intersection(&set_b).count();
        // With 64 samples from 100, expected overlap ~ 64*64/100 = 41 (random)
        // But should NOT be 64 (identical)
        assert!(overlap < 60, "Too much overlap ({}/64) — independence broken", overlap);
    }
}
