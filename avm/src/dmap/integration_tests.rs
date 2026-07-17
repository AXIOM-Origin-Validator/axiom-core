//! DMAP End-to-End Integration Tests
//!
//! Tests the complete DMAP pipeline: checkpoint collection → trace → attestation →
//! verification, including tamper detection, multi-validator independence, and
//! serialization roundtrips.

#[cfg(test)]
mod tests {
    use crate::dmap::*;
    use crate::dmap::checkpoint::{DmapCheckpoint, DmapTrace, checkpoint_hash};
    use crate::dmap::attestation::DmapAttestation;
    use crate::dmap::verification::{verify_dmap_attestation, verify_with_reexecution, DmapResult};
    use crate::dmap::challenge::derive_challenges;
    use crate::dmap::merkle::verify_merkle_proof;
    use std::collections::HashSet;
    use ed25519_dalek::{SigningKey, Signer};

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /// Simulate a realistic execution producing N checkpoints
    fn simulate_execution(num_checkpoints: u64) -> Vec<DmapCheckpoint> {
        (0..num_checkpoints)
            .map(|i| {
                // Simulate evolving state across execution
                let mut memory_root = [0u8; 32];
                let hash = blake3::hash(&i.to_le_bytes());
                memory_root.copy_from_slice(hash.as_bytes());

                let mut register_hash = [0u8; 32];
                let rhash = blake3::hash(&(i + 1000).to_le_bytes());
                register_hash.copy_from_slice(rhash.as_bytes());

                DmapCheckpoint {
                    instruction_count: (i + 1) * DMAP_CHECKPOINT_INTERVAL,
                    pc: 0x80000000 + (i as u32) * 4,
                    memory_root,
                    register_hash,
                }
            })
            .collect()
    }

    /// Build a complete signed attestation from simulated execution.
    /// Uses a deterministic Ed25519 key derived from the validator_pk_seed byte.
    /// AUDIT-FIX v2.11.14: attestations are now signed with Ed25519.
    fn build_test_attestation(
        num_checkpoints: u64,
        core_id: [u8; 32],
        validator_pk_seed: [u8; 32],
    ) -> (DmapAttestation, Vec<DmapCheckpoint>, [u8; 32], [u8; 32]) {
        let checkpoints = simulate_execution(num_checkpoints);
        let input_hash = *blake3::hash(b"test-inputs").as_bytes();
        let output_hash = *blake3::hash(b"test-outputs").as_bytes();
        let sk = SigningKey::from_bytes(&validator_pk_seed);
        let vpk = sk.verifying_key().to_bytes();
        let trace = DmapTrace::from_checkpoints(checkpoints.clone());
        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());
        (att, checkpoints, input_hash, output_hash)
    }

    // ─── Pipeline Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_full_pipeline_100_checkpoints() {
        // 1. Simulate execution
        let checkpoints = simulate_execution(100);
        assert_eq!(checkpoints.len(), 100);

        // 2. Build trace with Merkle commitment
        let trace = DmapTrace::from_checkpoints(checkpoints.clone());
        assert_eq!(trace.len(), 100);
        assert_ne!(trace.commitment, [0u8; 32]);

        // 3. Verify every checkpoint can be revealed with valid Merkle proof
        for i in 0..trace.len() {
            let revealed = trace.reveal(i as u64).unwrap();
            assert_eq!(revealed.index, i as u64);
            let leaf = checkpoint_hash(&revealed.checkpoint);
            assert!(
                verify_merkle_proof(&leaf, &revealed.merkle_proof, i, &trace.commitment),
                "Merkle proof invalid for checkpoint {}",
                i
            );
        }

        // 4. Build attestation
        let core_id = [0xAA; 32];
        let input_hash = *blake3::hash(b"inputs").as_bytes();
        let output_hash = *blake3::hash(b"outputs").as_bytes();
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk = sk.verifying_key().to_bytes();

        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());

        assert_eq!(att.total_checkpoints, 100);
        assert_eq!(att.core_id, core_id);
        assert_eq!(att.validator_pk, vpk);
        assert!(att.revealed_checkpoints.len() <= DMAP_NUM_CHALLENGES as usize);

        // 5. Verify attestation
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid), "Verification failed: {:?}", result);

        // 6. Verify with matching re-execution
        let result = verify_with_reexecution(
            &att, &core_id, &input_hash, &output_hash, &vpk, &checkpoints,
        );
        assert!(matches!(result, DmapResult::Valid), "Re-execution check failed: {:?}", result);
    }

    #[test]
    fn test_full_pipeline_large_execution() {
        // 500 checkpoints = 5M instructions — realistic production execution
        let checkpoints = simulate_execution(500);
        let trace = DmapTrace::from_checkpoints(checkpoints.clone());
        let core_id = [0xBB; 32];
        let input_hash = *blake3::hash(b"large-inputs").as_bytes();
        let output_hash = *blake3::hash(b"large-outputs").as_bytes();
        let sk = SigningKey::from_bytes(&[0x02; 32]);
        let vpk = sk.verifying_key().to_bytes();

        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());

        // With 500 checkpoints and K=64, we get exactly 64 revealed
        assert_eq!(att.revealed_checkpoints.len(), DMAP_NUM_CHALLENGES as usize);

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid));

        // Size budget check — at K=24 a full attestation is ~14KB even with deep Merkle
        // proofs; cap at 20KB as a regression guard (well under nabla's 1MB wire cap).
        let size = att.estimated_size();
        assert!(size < 20_000, "Attestation too large: {} bytes (limit 20KB)", size);
    }

    // ─── Tamper Detection Tests ──────────────────────────────────────────────

    #[test]
    fn test_tamper_memory_root_detected() {
        let (att, mut checkpoints, input_hash, output_hash) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);

        // Tamper with a checkpoint's memory root
        for cp in checkpoints.iter_mut() {
            cp.memory_root = [0xFF; 32]; // all different
        }

        let result = verify_with_reexecution(
            &att, &att.core_id, &input_hash, &output_hash, &att.validator_pk, &checkpoints,
        );
        assert!(
            matches!(result, DmapResult::MemoryMismatch { .. }),
            "Tampered memory should be detected: {:?}",
            result
        );
    }

    #[test]
    fn test_register_hash_in_commitment() {
        // Register hash is included in checkpoint_hash (Improvement A).
        // Changing register state changes the Merkle leaf, so any attestation
        // built from tampered checkpoints will have a different commitment.
        let checkpoints = simulate_execution(50);
        let mut tampered = checkpoints.clone();
        tampered[10].register_hash = [0xDE; 32];

        let trace_good = DmapTrace::from_checkpoints(checkpoints);
        let trace_bad = DmapTrace::from_checkpoints(tampered);

        assert_ne!(
            trace_good.commitment, trace_bad.commitment,
            "Register hash change must alter checkpoint commitment"
        );

        // Also verify that checkpoint_hash itself changes
        let cp1 = DmapCheckpoint {
            instruction_count: 10000, pc: 0x1000,
            memory_root: [0xAB; 32], register_hash: [0x11; 32],
        };
        let cp2 = DmapCheckpoint {
            instruction_count: 10000, pc: 0x1000,
            memory_root: [0xAB; 32], register_hash: [0x22; 32], // only register_hash differs
        };
        assert_ne!(checkpoint_hash(&cp1), checkpoint_hash(&cp2));
    }

    #[test]
    fn test_tamper_wrong_core_id_rejected() {
        let (att, _, ih, oh) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);

        let result = verify_dmap_attestation(&att, &[0xFF; 32], &ih, &oh, &att.validator_pk);
        assert!(matches!(result, DmapResult::WrongCore));
    }

    #[test]
    fn test_tamper_wrong_input_hash_rejected() {
        let (att, _, _ih, output_hash) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);

        let result = verify_dmap_attestation(&att, &att.core_id, &[0xFF; 32], &output_hash, &att.validator_pk);
        assert!(matches!(result, DmapResult::InputHashMismatch));
    }

    #[test]
    fn test_tamper_wrong_output_hash_rejected() {
        let (att, _, input_hash, _) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);

        let result = verify_dmap_attestation(&att, &att.core_id, &input_hash, &[0xFF; 32], &att.validator_pk);
        assert!(matches!(result, DmapResult::OutputHashMismatch));
    }

    #[test]
    fn test_tamper_merkle_proof_detected() {
        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);
        let vpk = att.validator_pk;

        // Corrupt a Merkle proof
        if let Some(revealed) = att.revealed_checkpoints.first_mut() {
            if let Some(proof_node) = revealed.merkle_proof.first_mut() {
                *proof_node = [0xFF; 32]; // corrupt
            }
        }

        let result = verify_dmap_attestation(&att, &att.core_id, &input_hash, &output_hash, &vpk);
        assert!(
            matches!(result, DmapResult::MerkleProofInvalid(_)),
            "Corrupted Merkle proof should be detected: {:?}",
            result
        );
    }

    #[test]
    fn test_tamper_swapped_checkpoint_detected() {
        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);
        let vpk = att.validator_pk;

        // Swap checkpoint data between two revealed checkpoints
        if att.revealed_checkpoints.len() >= 2 {
            let cp0 = att.revealed_checkpoints[0].checkpoint.clone();
            att.revealed_checkpoints[0].checkpoint =
                att.revealed_checkpoints[1].checkpoint.clone();
            att.revealed_checkpoints[1].checkpoint = cp0;
        }

        let result = verify_dmap_attestation(&att, &att.core_id, &input_hash, &output_hash, &vpk);
        assert!(
            !matches!(result, DmapResult::Valid),
            "Swapped checkpoints should be detected"
        );
    }

    // ─── Multi-Validator Independence Tests ──────────────────────────────────

    #[test]
    fn test_three_validators_independent_challenges() {
        let core_id = [0xAA; 32];
        let input_hash = *blake3::hash(b"tx-inputs").as_bytes();
        let output_hash = *blake3::hash(b"tx-outputs").as_bytes();
        let checkpoints = simulate_execution(200);
        let trace = DmapTrace::from_checkpoints(checkpoints);

        // k=3 validators with different keys
        let sk_seeds = [[0x01; 32], [0x02; 32], [0x03; 32]];
        let mut all_attestations = Vec::new();
        let mut all_challenge_sets: Vec<HashSet<u64>> = Vec::new();

        for &seed in &sk_seeds {
            let sk = SigningKey::from_bytes(&seed);
            let vpk = sk.verifying_key().to_bytes();
            let mut att = DmapAttestation::from_trace(
                core_id, input_hash, output_hash, &trace, 1710000000, vpk,
            );
            let payload = att.signing_payload();
            let sig = sk.sign(&payload);
            att.set_signature(sig.to_bytes().to_vec());

            // Each attestation must independently verify
            let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
            assert!(matches!(result, DmapResult::Valid), "Validator {:02x} failed: {:?}", seed[0], result);

            // Collect challenged indices
            let indices: HashSet<u64> = att.revealed_checkpoints
                .iter()
                .map(|r| r.index)
                .collect();
            all_challenge_sets.push(indices);
            all_attestations.push(att);
        }

        // Verify pairwise independence
        for i in 0..3 {
            for j in (i + 1)..3 {
                let overlap = all_challenge_sets[i]
                    .intersection(&all_challenge_sets[j])
                    .count();
                let unique_i = all_challenge_sets[i].len();
                let unique_j = all_challenge_sets[j].len();

                // Overlap should be much less than total (random expectation: ~K²/N)
                assert!(
                    overlap < unique_i.min(unique_j),
                    "Validators {} and {} have too much overlap: {}/{} (independence broken)",
                    i, j, overlap, unique_i.min(unique_j)
                );
            }
        }

        // Combined coverage: union of all challenged indices
        let combined: HashSet<u64> = all_challenge_sets
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();

        // With K=24 per validator, 3 validators, 200 checkpoints:
        // Expected unique coverage ≈ 200 * (1 - (1 - 1/200)^(3*24=72)) ≈ 61 unique indices.
        // Threshold set well below expectation to tolerate sampling variance.
        assert!(
            combined.len() > 45,
            "Combined coverage too low: {} unique indices from 3 validators (K={})",
            combined.len(), DMAP_NUM_CHALLENGES
        );
    }

    #[test]
    fn test_validator_challenges_match_attestation() {
        // Verify that challenge re-derivation matches what's in the attestation
        let core_id = [0xCC; 32];
        let (att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x05; 32]);
        let vpk = att.validator_pk;

        let expected = derive_challenges(
            &core_id, &input_hash, &output_hash, &vpk,
            att.total_checkpoints, DMAP_NUM_CHALLENGES,
        );

        for (i, revealed) in att.revealed_checkpoints.iter().enumerate() {
            assert_eq!(
                revealed.index, expected[i],
                "Challenge mismatch at position {}: got {}, expected {}",
                i, revealed.index, expected[i]
            );
        }
    }

    // ─── Commitment Integrity Tests ──────────────────────────────────────────

    #[test]
    fn test_commitment_deterministic() {
        let checkpoints = simulate_execution(50);
        let trace1 = DmapTrace::from_checkpoints(checkpoints.clone());
        let trace2 = DmapTrace::from_checkpoints(checkpoints);
        assert_eq!(trace1.commitment, trace2.commitment);
    }

    #[test]
    fn test_commitment_changes_with_any_checkpoint() {
        let mut checkpoints = simulate_execution(50);
        let trace1 = DmapTrace::from_checkpoints(checkpoints.clone());

        // Change one checkpoint in the middle
        checkpoints[25].memory_root[0] ^= 0xFF;
        let trace2 = DmapTrace::from_checkpoints(checkpoints);

        assert_ne!(
            trace1.commitment, trace2.commitment,
            "Changing one checkpoint must change the commitment"
        );
    }

    #[test]
    fn test_signing_payload_covers_all_fields() {
        let (att1, _, _, _) = build_test_attestation(50, [0xAA; 32], [0x01; 32]);
        let (att2, _, _, _) = build_test_attestation(50, [0xBB; 32], [0x01; 32]); // different core_id

        assert_ne!(att1.signing_payload(), att2.signing_payload());

        // Payload must include: core_id + input_hash + output_hash + commitment + tick
        let payload = att1.signing_payload();
        assert_eq!(payload.len(), 32 * 4 + 8); // 136 bytes
    }

    // ─── Serialization Roundtrip Tests ───────────────────────────────────────

    #[test]
    fn test_attestation_cbor_roundtrip() {
        let (att, checkpoints, input_hash, output_hash) =
            build_test_attestation(100, [0xAA; 32], [0x01; 32]);

        // CBOR is the wire format (writer: lambda/src/core_client.rs).
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&att, &mut buf).expect("serialize");
        let att2: DmapAttestation = ciborium::de::from_reader(&buf[..]).expect("deserialize");

        // Verify the deserialized attestation still passes verification
        let vpk = att.validator_pk;
        let result = verify_dmap_attestation(&att2, &att.core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid), "Roundtrip broke verification: {:?}", result);

        // And re-execution verification
        let result = verify_with_reexecution(
            &att2, &att.core_id, &input_hash, &output_hash, &vpk, &checkpoints,
        );
        assert!(matches!(result, DmapResult::Valid), "Roundtrip broke re-execution: {:?}", result);

        // Field integrity
        assert_eq!(att.core_id, att2.core_id);
        assert_eq!(att.input_hash, att2.input_hash);
        assert_eq!(att.output_hash, att2.output_hash);
        assert_eq!(att.checkpoint_commitment, att2.checkpoint_commitment);
        assert_eq!(att.total_checkpoints, att2.total_checkpoints);
        assert_eq!(att.validator_pk, att2.validator_pk);
        assert_eq!(att.tick, att2.tick);
        assert_eq!(att.revealed_checkpoints.len(), att2.revealed_checkpoints.len());
    }

    #[test]
    fn test_checkpoint_bincode_roundtrip() {
        let cp = DmapCheckpoint {
            instruction_count: 50000,
            pc: 0x80001234,
            memory_root: [0xAB; 32],
            register_hash: [0xCD; 32],
        };

        let encoded = serde_json::to_vec(&cp).unwrap();
        let decoded: DmapCheckpoint = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(cp.instruction_count, decoded.instruction_count);
        assert_eq!(cp.pc, decoded.pc);
        assert_eq!(cp.memory_root, decoded.memory_root);
        assert_eq!(cp.register_hash, decoded.register_hash);
        assert_eq!(checkpoint_hash(&cp), checkpoint_hash(&decoded));
    }

    // ─── Edge Cases ──────────────────────────────────────────────────────────

    #[test]
    fn test_single_checkpoint_execution() {
        let checkpoints = simulate_execution(1);
        let trace = DmapTrace::from_checkpoints(checkpoints.clone());
        assert_eq!(trace.len(), 1);

        let core_id = [0xDD; 32];
        let input_hash = *blake3::hash(b"single").as_bytes();
        let output_hash = *blake3::hash(b"single-out").as_bytes();
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk = sk.verifying_key().to_bytes();

        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1, vpk,
        );
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());

        // With 1 checkpoint, all challenges point to index 0
        assert!(!att.revealed_checkpoints.is_empty());
        for r in &att.revealed_checkpoints {
            assert_eq!(r.index, 0);
        }

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid));
    }

    #[test]
    fn test_few_checkpoints_less_than_k() {
        // When N < K, some challenges will be duplicates (same index mod N)
        let checkpoints = simulate_execution(5);
        let trace = DmapTrace::from_checkpoints(checkpoints.clone());

        let core_id = [0xEE; 32];
        let input_hash = *blake3::hash(b"few").as_bytes();
        let output_hash = *blake3::hash(b"few-out").as_bytes();
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk = sk.verifying_key().to_bytes();

        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1, vpk,
        );
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());

        // Should still have K revealed (with duplicate indices)
        assert_eq!(att.revealed_checkpoints.len(), DMAP_NUM_CHALLENGES as usize);

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid));

        let result = verify_with_reexecution(
            &att, &core_id, &input_hash, &output_hash, &vpk, &checkpoints,
        );
        assert!(matches!(result, DmapResult::Valid));
    }

    #[test]
    fn test_checkpoint_interval_alignment() {
        // Verify instruction counts align with DMAP_CHECKPOINT_INTERVAL
        let checkpoints = simulate_execution(10);
        for (i, cp) in checkpoints.iter().enumerate() {
            assert_eq!(
                cp.instruction_count,
                (i as u64 + 1) * DMAP_CHECKPOINT_INTERVAL,
                "Checkpoint {} instruction count misaligned",
                i
            );
        }
    }

    // ─── Security Property Tests ─────────────────────────────────────────────

    #[test]
    fn test_challenge_unpredictability() {
        // Challenges should be uniformly distributed — no clustering
        let core_id = [0x42; 32];
        let input_hash = [0x43; 32];
        let output_hash = [0x44; 32];
        let vpk = [0x01; 32];
        let n = 1000u64;

        let challenges = derive_challenges(&core_id, &input_hash, &output_hash, &vpk, n, 64);

        // Chi-squared test: divide into 10 buckets of 100
        let mut buckets = [0u32; 10];
        for &idx in &challenges {
            buckets[(idx / 100) as usize] += 1;
        }

        // Expected: 6.4 per bucket. Allow 0-20 (very generous for 64 samples)
        let non_empty = buckets.iter().filter(|&&b| b > 0).count();
        assert!(
            non_empty >= 4,
            "Challenges clustered in too few buckets: {:?}",
            buckets
        );
    }

    #[test]
    fn test_grinding_resistance() {
        // Changing only the output hash should change challenges (Fiat-Shamir binding)
        let core_id = [0x42; 32];
        let input_hash = [0x43; 32];
        let vpk = [0x01; 32];
        let n = 100u64;

        let mut unique_challenge_sets = HashSet::new();

        for trial in 0..50u8 {
            let mut output_hash = [0u8; 32];
            output_hash[0] = trial;
            let challenges = derive_challenges(
                &core_id, &input_hash, &output_hash, &vpk, n, 64,
            );
            unique_challenge_sets.insert(challenges);
        }

        // All 50 trials should produce different challenge sets
        assert_eq!(
            unique_challenge_sets.len(), 50,
            "Some output hashes produced identical challenges (grinding vulnerability)"
        );
    }

    #[test]
    fn test_attestation_size_budget() {
        // Production size must stay within wire protocol budget
        for n in [50, 100, 200, 500, 1000] {
            let (att, _, _, _) = build_test_attestation(n, [0xAA; 32], [0x01; 32]);
            let size = att.estimated_size();
            // With K=24, proof depth grows with log2(N). At ~1000 checkpoints, depth
            // ~10 → ~14KB. Cap at 20KB (well under nabla's 1MB production wire limit).
            assert!(
                size < 20_000,
                "Attestation with {} checkpoints exceeds 20KB: {} bytes",
                n, size
            );
        }
    }

    #[test]
    fn test_final_checkpoint_coverage() {
        // Improvement D: the last checkpoint should be reachable by challenges
        let core_id = [0x42; 32];
        let input_hash = [0x43; 32];
        let output_hash = [0x44; 32];
        let n = 100u64;

        // Try many validator keys — at least one should challenge the last checkpoint
        let mut last_challenged = false;
        for v in 0..100u8 {
            let vpk = [v; 32];
            let challenges = derive_challenges(
                &core_id, &input_hash, &output_hash, &vpk, n, DMAP_NUM_CHALLENGES,
            );
            if challenges.contains(&(n - 1)) {
                last_challenged = true;
                break;
            }
        }
        assert!(
            last_challenged,
            "Last checkpoint never challenged across 100 validator keys"
        );
    }

    // ─── Adversarial Tests ──────────────────────────────────────────────────

    #[test]
    fn test_replay_proof_different_txid() {
        // Build a valid attestation for TX_A. Then present it as if it were
        // for TX_B (different input_hash). Verifier must reject with
        // InputHashMismatch — the attestation's embedded input_hash won't
        // match the expected one.
        let core_id = [0xAA; 32];

        let (att_a, _, input_hash_a, output_hash_a) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att_a.validator_pk;

        // Attestation was built for input_hash_a. Verify it passes normally.
        let result = verify_dmap_attestation(&att_a, &core_id, &input_hash_a, &output_hash_a, &vpk);
        assert!(matches!(result, DmapResult::Valid), "Baseline should pass");

        // Now verify against TX_B's input_hash — must reject.
        let input_hash_b = *blake3::hash(b"completely-different-tx-inputs").as_bytes();
        assert_ne!(input_hash_a, input_hash_b);

        let result = verify_dmap_attestation(&att_a, &core_id, &input_hash_b, &output_hash_a, &vpk);
        assert!(
            matches!(result, DmapResult::InputHashMismatch),
            "Replaying proof for different TX must be InputHashMismatch, got: {:?}",
            result
        );
    }

    #[test]
    fn test_replay_proof_same_input_different_output() {
        // Valid attestation, but verifier expects a different output_hash.
        // Two properties: (1) OutputHashMismatch rejection, and
        // (2) challenge indices change when output_hash changes (Fiat-Shamir binding).
        let core_id = [0xAA; 32];

        let (att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att.validator_pk;

        // Property 1: OutputHashMismatch when output differs
        let output_hash_b = *blake3::hash(b"different-output").as_bytes();
        assert_ne!(output_hash, output_hash_b);

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash_b, &vpk);
        assert!(
            matches!(result, DmapResult::OutputHashMismatch),
            "Different output must be OutputHashMismatch, got: {:?}",
            result
        );

        // Property 2: Fiat-Shamir binding — challenges differ when output differs
        let challenges_a = derive_challenges(
            &core_id, &input_hash, &output_hash, &vpk, 100, DMAP_NUM_CHALLENGES,
        );
        let challenges_b = derive_challenges(
            &core_id, &input_hash, &output_hash_b, &vpk, 100, DMAP_NUM_CHALLENGES,
        );
        assert_ne!(
            challenges_a, challenges_b,
            "Challenge indices must change when output_hash changes (Fiat-Shamir binding)"
        );
    }

    #[test]
    fn test_mutate_core_id_single_bit() {
        // Flip exactly one bit of core_id in the attestation. The verifier
        // compares attestation.core_id against expected_core_id, so even a
        // single-bit difference must trigger WrongCore.
        let core_id = [0xAA; 32];

        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);

        // Flip bit 0 of the first byte of the embedded core_id
        att.core_id[0] ^= 0x01;
        assert_ne!(att.core_id, core_id, "Single bit flip must change core_id");

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &att.validator_pk);
        assert!(
            matches!(result, DmapResult::WrongCore),
            "Single-bit core_id mutation must be WrongCore, got: {:?}",
            result
        );
    }

    #[test]
    fn test_truncated_checkpoints() {
        // Build valid attestation then remove the last revealed checkpoint,
        // giving K-1 instead of K. Verifier must reject with MissingCheckpoints.
        let core_id = [0xAA; 32];

        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att.validator_pk;

        let original_len = att.revealed_checkpoints.len();
        assert_eq!(original_len, DMAP_NUM_CHALLENGES as usize);

        // Remove last checkpoint
        att.revealed_checkpoints.pop();
        assert_eq!(att.revealed_checkpoints.len(), original_len - 1);

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(
            matches!(result, DmapResult::MissingCheckpoints(_)),
            "K-1 checkpoints must be MissingCheckpoints, got: {:?}",
            result
        );
    }

    #[test]
    fn test_duplicate_checkpoint_indices() {
        // Replace the last revealed checkpoint with a copy of the first
        // (same index, same checkpoint data, same proof). The verifier
        // re-derives challenges and checks that each position matches the
        // expected index — the duplicate will have the wrong index for its
        // position, triggering ChallengeMismatch.
        let core_id = [0xAA; 32];

        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att.validator_pk;

        assert!(att.revealed_checkpoints.len() >= 2);

        // Re-derive expected challenges to confirm last index differs from first
        let expected = derive_challenges(
            &core_id, &input_hash, &output_hash, &vpk,
            att.total_checkpoints, DMAP_NUM_CHALLENGES,
        );
        let last_pos = att.revealed_checkpoints.len() - 1;

        // Only run this test if the first and last expected indices differ
        // (with 100 checkpoints and K=64, overwhelmingly likely)
        if expected[0] != expected[last_pos] {
            // Replace last with copy of first
            att.revealed_checkpoints[last_pos] = att.revealed_checkpoints[0].clone();

            let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
            assert!(
                matches!(result, DmapResult::ChallengeMismatch(_)),
                "Duplicate checkpoint at wrong position must be ChallengeMismatch, got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_swapped_checkpoint_order() {
        // Swap two revealed checkpoints' positions (but keep their original
        // index fields). The verifier checks each position against the derived
        // challenge sequence — swapped positions will have wrong indices.
        let core_id = [0xAA; 32];

        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att.validator_pk;

        assert!(att.revealed_checkpoints.len() >= 2);

        // Find two positions with different expected indices
        let expected = derive_challenges(
            &core_id, &input_hash, &output_hash, &vpk,
            att.total_checkpoints, DMAP_NUM_CHALLENGES,
        );

        // Find a pair (i, j) where expected[i] != expected[j]
        let mut swap_pair = None;
        'outer: for i in 0..expected.len() {
            for j in (i + 1)..expected.len() {
                if expected[i] != expected[j] {
                    swap_pair = Some((i, j));
                    break 'outer;
                }
            }
        }

        if let Some((i, j)) = swap_pair {
            att.revealed_checkpoints.swap(i, j);

            let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
            assert!(
                matches!(result, DmapResult::ChallengeMismatch(_) | DmapResult::MerkleProofInvalid(_)),
                "Swapped checkpoint order must fail with ChallengeMismatch or MerkleProofInvalid, got: {:?}",
                result
            );
        } else {
            panic!("Could not find two positions with different challenge indices in 100 checkpoints");
        }
    }

    #[test]
    fn test_checkpoint_commitment_forgery() {
        // Replace checkpoint_commitment with random bytes. All Merkle proofs
        // should fail because they were built against the real commitment.
        let core_id = [0xAA; 32];

        let (mut att, _, input_hash, output_hash) =
            build_test_attestation(100, core_id, [0x01; 32]);
        let vpk = att.validator_pk;

        // Verify baseline passes
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid), "Baseline should pass");

        // Forge the commitment — this also invalidates the signature, but
        // the Merkle check happens before signature check, so we expect MerkleProofInvalid.
        att.checkpoint_commitment = *blake3::hash(b"forged-commitment").as_bytes();

        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(
            matches!(result, DmapResult::MerkleProofInvalid(_)),
            "Forged commitment must cause MerkleProofInvalid, got: {:?}",
            result
        );
    }

    #[test]
    fn test_zero_total_checkpoints() {
        // AUDIT-FIX v2.11.14: Zero-checkpoint attestations are now rejected early
        // with MissingCheckpoints — they prove nothing about execution.
        let core_id = [0xAA; 32];
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk = sk.verifying_key().to_bytes();
        let input_hash = *blake3::hash(b"zero-inputs").as_bytes();
        let output_hash = *blake3::hash(b"zero-outputs").as_bytes();

        // Manually construct an attestation with total_checkpoints=0
        let att = DmapAttestation {
            core_id,
            input_hash,
            output_hash,
            total_checkpoints: 0,
            checkpoint_commitment: [0u8; 32],
            revealed_checkpoints: Vec::new(),
            signature: Vec::new(),
            tick: 1710000000,
            validator_pk: vpk,
        };

        // Zero checkpoints must be rejected early with MissingCheckpoints.
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(
            matches!(result, DmapResult::MissingCheckpoints(_)),
            "Zero-checkpoint attestation must be rejected with MissingCheckpoints, got: {:?}",
            result
        );

        // Also test that a legitimate attestation with revealed checkpoints
        // but total_checkpoints=0 is rejected.
        let (real_att, _, _, _) = build_test_attestation(100, core_id, [0x01; 32]);
        let mut forged = real_att.clone();
        forged.total_checkpoints = 0;
        let result = verify_dmap_attestation(&forged, &core_id, &forged.input_hash, &forged.output_hash, &forged.validator_pk);
        assert!(
            matches!(result, DmapResult::MissingCheckpoints(_)),
            "total_checkpoints=0 with non-empty revealed must be MissingCheckpoints, got: {:?}",
            result
        );
    }

    #[test]
    fn test_binding_tuple_independence() {
        // Same core_id + input_hash but different output_hash must produce
        // different challenge sets. This proves output_hash is bound into
        // the Fiat-Shamir transcript and cannot be swapped post-hoc.
        let core_id = [0xAA; 32];
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk = sk.verifying_key().to_bytes();
        let input_hash = *blake3::hash(b"shared-input").as_bytes();
        let n = 200u64;

        let mut seen_challenge_sets: Vec<Vec<u64>> = Vec::new();

        for trial in 0..20u8 {
            let mut output_hash = [0u8; 32];
            output_hash[0] = trial;
            let output_hash = *blake3::hash(&output_hash).as_bytes();

            let challenges = derive_challenges(
                &core_id, &input_hash, &output_hash, &vpk, n, DMAP_NUM_CHALLENGES,
            );
            seen_challenge_sets.push(challenges);
        }

        // All 20 challenge sets must be distinct
        for i in 0..seen_challenge_sets.len() {
            for j in (i + 1)..seen_challenge_sets.len() {
                assert_ne!(
                    seen_challenge_sets[i], seen_challenge_sets[j],
                    "Challenge sets for output variants {} and {} must differ (output binding broken)",
                    i, j
                );
            }
        }

        // Additionally, build two full attestations and verify both are valid
        // independently — proving the binding doesn't break verification.
        let checkpoints = simulate_execution(200);
        let trace = DmapTrace::from_checkpoints(checkpoints);

        let output_a = *blake3::hash(b"output-alpha").as_bytes();
        let output_b = *blake3::hash(b"output-beta").as_bytes();

        let mut att_a = DmapAttestation::from_trace(
            core_id, input_hash, output_a, &trace, 1710000000, vpk,
        );
        let payload_a = att_a.signing_payload();
        let sig_a = sk.sign(&payload_a);
        att_a.set_signature(sig_a.to_bytes().to_vec());

        let mut att_b = DmapAttestation::from_trace(
            core_id, input_hash, output_b, &trace, 1710000000, vpk,
        );
        let payload_b = att_b.signing_payload();
        let sig_b = sk.sign(&payload_b);
        att_b.set_signature(sig_b.to_bytes().to_vec());

        // Both must verify against their own output_hash
        assert!(matches!(
            verify_dmap_attestation(&att_a, &core_id, &input_hash, &output_a, &vpk),
            DmapResult::Valid
        ));
        assert!(matches!(
            verify_dmap_attestation(&att_b, &core_id, &input_hash, &output_b, &vpk),
            DmapResult::Valid
        ));

        // Cross-verification must fail — att_a verified against output_b
        assert!(matches!(
            verify_dmap_attestation(&att_a, &core_id, &input_hash, &output_b, &vpk),
            DmapResult::OutputHashMismatch
        ));

        // The revealed checkpoint sets must differ (different challenges)
        let indices_a: Vec<u64> = att_a.revealed_checkpoints.iter().map(|r| r.index).collect();
        let indices_b: Vec<u64> = att_b.revealed_checkpoints.iter().map(|r| r.index).collect();
        assert_ne!(
            indices_a, indices_b,
            "Same input but different output must produce different revealed indices"
        );
    }
}
