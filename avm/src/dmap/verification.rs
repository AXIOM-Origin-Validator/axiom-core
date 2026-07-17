//! DMAP Attestation Verification
//!
//! Verifies that a DmapAttestation is consistent:
//! - CoreID matches canonical
//! - Challenge indices are correctly derived
//! - Merkle proofs are valid against checkpoint_commitment
//! - Memory roots match independent re-execution (when available)

use alloc::string::String;
use alloc::format;
use super::attestation::DmapAttestation;
use super::challenge::derive_challenges;
use super::checkpoint::{checkpoint_hash, DmapCheckpoint};
use super::merkle::verify_merkle_proof;
use super::DMAP_NUM_CHALLENGES;

/// Result of DMAP attestation verification
#[derive(Debug, PartialEq)]
pub enum DmapResult {
    /// Attestation is valid
    Valid,
    /// CoreID does not match expected canonical value
    WrongCore,
    /// Input hash mismatch
    InputHashMismatch,
    /// Output hash mismatch
    OutputHashMismatch,
    /// Challenge index at position `i` doesn't match derivation
    ChallengeMismatch(usize),
    /// Merkle proof at position `i` is invalid
    MerkleProofInvalid(usize),
    /// Memory root at checkpoint `index` doesn't match re-execution
    MemoryMismatch {
        index: u64,
        expected: [u8; 32],
        claimed: [u8; 32],
    },
    /// Register hash at checkpoint `index` doesn't match re-execution (Improvement E)
    RegisterMismatch {
        index: u64,
        expected: [u8; 32],
        claimed: [u8; 32],
    },
    /// Signature is invalid
    InvalidSignature,
    /// Missing revealed checkpoints
    MissingCheckpoints(String),
}

/// Minimum total checkpoints for a valid DMAP attestation.
/// AUDIT-FIX v2.11.14: Prevents zero-checkpoint attestations from passing as Valid.
/// Any real Core execution produces at least 1 checkpoint (10K+ instructions minimum).
pub const DMAP_MIN_CHECKPOINTS: u64 = 1;

/// Verify a DMAP attestation without re-execution
///
/// Checks structural validity: CoreID, challenge derivation, Merkle proofs,
/// signature authenticity, and minimum execution evidence.
///
/// # Arguments
/// * `expected_core_id` — BLAKE3 of the canonical Core ELF (from trusted config)
/// * `input_hash` — BLAKE3 of serialized PublicInputs (recomputed by verifier)
/// * `output_hash` — BLAKE3 of serialized PublicOutputs (from execution)
/// * `expected_validator_pk` — Validator's Ed25519 PK from trusted context (NOT from attestation)
///
/// AUDIT-FIX v2.11.14 (3 findings):
/// - Finding 1: Signature now verified (was unchecked)
/// - Finding 2: Zero-checkpoint attestations rejected (was accepted as Valid)
/// - Finding 3: Challenge derived from trusted expected_validator_pk (was from untrusted attestation)
pub fn verify_dmap_attestation(
    attestation: &DmapAttestation,
    expected_core_id: &[u8; 32],
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
    expected_validator_pk: &[u8; 32],
) -> DmapResult {
    // Step 0: AUDIT-FIX v2.11.14 — Reject zero-checkpoint attestations.
    // Any real Core execution produces checkpoints. Zero means no execution evidence.
    if attestation.total_checkpoints < DMAP_MIN_CHECKPOINTS {
        return DmapResult::MissingCheckpoints(format!(
            "total_checkpoints={} below minimum {} — no execution evidence",
            attestation.total_checkpoints, DMAP_MIN_CHECKPOINTS
        ));
    }

    // Step 1: Verify CoreID
    if attestation.core_id != *expected_core_id {
        return DmapResult::WrongCore;
    }

    // Step 2: Verify input/output hashes
    if attestation.input_hash != *input_hash {
        return DmapResult::InputHashMismatch;
    }
    if attestation.output_hash != *output_hash {
        return DmapResult::OutputHashMismatch;
    }

    // Step 2b: AUDIT-FIX v2.11.14 — Verify attestation.validator_pk matches expected.
    // Challenge indices depend on validator_pk. If we derive from an attacker-controlled
    // value, the attacker picks their own challenge seed. Use trusted expected_validator_pk
    // and verify it matches what the attestation claims.
    if attestation.validator_pk != *expected_validator_pk {
        return DmapResult::InvalidSignature; // validator_pk mismatch = identity forgery
    }

    // Step 3: Re-derive challenges using trusted expected_validator_pk
    let expected_indices = derive_challenges(
        expected_core_id,
        input_hash,
        output_hash,
        expected_validator_pk,
        attestation.total_checkpoints,
        DMAP_NUM_CHALLENGES,
    );

    if attestation.revealed_checkpoints.len() != expected_indices.len() {
        return DmapResult::MissingCheckpoints(format!(
            "Expected {} revealed, got {}",
            expected_indices.len(),
            attestation.revealed_checkpoints.len()
        ));
    }

    // Step 4: Verify each revealed checkpoint
    for (i, revealed) in attestation.revealed_checkpoints.iter().enumerate() {
        // 4a: Verify challenge index matches derivation
        if revealed.index != expected_indices[i] {
            return DmapResult::ChallengeMismatch(i);
        }

        // 4b: Verify Merkle proof
        let leaf = checkpoint_hash(&revealed.checkpoint);
        if !verify_merkle_proof(
            &leaf,
            &revealed.merkle_proof,
            revealed.index as usize,
            &attestation.checkpoint_commitment,
        ) {
            return DmapResult::MerkleProofInvalid(i);
        }
    }

    // Step 5: AUDIT-FIX v2.11.14 — Verify signature over binding tuple.
    // The signature binds (core_id, input_hash, output_hash, checkpoint_commitment, tick)
    // to the validator's identity. Without this check, attestations are unsigned structural
    // objects that any party can forge.
    if attestation.signature.is_empty() {
        return DmapResult::InvalidSignature;
    }
    let payload = attestation.signing_payload();
    if axiom_core_logic::verify::verify_ed25519(
        expected_validator_pk,
        &payload,
        &attestation.signature,
    ).is_err() {
        // Try Dilithium for validator-produced attestations (larger sig)
        if axiom_core_logic::verify::verify_dilithium(
            // Dilithium PK is not available here — Ed25519 is the expected path
            // for client/webclient attestations. For validator attestations,
            // the witness Ed25519 signature on commitment_hash already covers the proof.
            // This branch ensures at least Ed25519 is verified.
            expected_validator_pk,
            &payload,
            &attestation.signature,
        ).is_err() {
            return DmapResult::InvalidSignature;
        }
    }

    DmapResult::Valid
}

/// Verify a DMAP attestation WITH re-execution memory comparison
///
/// Takes checkpoints from an independent re-execution and compares
/// memory roots at challenged indices.
pub fn verify_with_reexecution(
    attestation: &DmapAttestation,
    expected_core_id: &[u8; 32],
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
    expected_validator_pk: &[u8; 32],
    reexecution_checkpoints: &[DmapCheckpoint],
) -> DmapResult {
    // First do structural verification
    let structural = verify_dmap_attestation(
        attestation,
        expected_core_id,
        input_hash,
        output_hash,
        expected_validator_pk,
    );

    if !matches!(structural, DmapResult::Valid) {
        return structural;
    }

    // Now compare memory roots AND register hashes at challenged checkpoints
    for revealed in &attestation.revealed_checkpoints {
        let idx = revealed.index as usize;
        if idx >= reexecution_checkpoints.len() {
            return DmapResult::MemoryMismatch {
                index: revealed.index,
                expected: [0; 32],
                claimed: revealed.checkpoint.memory_root,
            };
        }

        let own = &reexecution_checkpoints[idx];

        // Compare memory roots
        if own.memory_root != revealed.checkpoint.memory_root {
            return DmapResult::MemoryMismatch {
                index: revealed.index,
                expected: own.memory_root,
                claimed: revealed.checkpoint.memory_root,
            };
        }

        // Compare register hashes (Improvement E: catches computational
        // divergence that hasn't yet propagated to memory)
        if own.register_hash != revealed.checkpoint.register_hash {
            return DmapResult::RegisterMismatch {
                index: revealed.index,
                expected: own.register_hash,
                claimed: revealed.checkpoint.register_hash,
            };
        }
    }

    DmapResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::checkpoint::DmapTrace;
    use ed25519_dalek::{SigningKey, Signer};

    /// Build a signed test attestation. Returns (attestation, core_id, input_hash, output_hash, vpk).
    /// AUDIT-FIX v2.11.14: attestations are now signed with Ed25519.
    fn make_test_attestation() -> (DmapAttestation, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let core_id = [0xAA; 32];
        let input_hash = [0xBB; 32];
        let output_hash = [0xCC; 32];
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vpk: [u8; 32] = sk.verifying_key().to_bytes();

        let checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                register_hash: [i as u8; 32],
            })
            .collect();

        let trace = DmapTrace::from_checkpoints(checkpoints);
        let mut att = DmapAttestation::from_trace(
            core_id, input_hash, output_hash, &trace, 1710000000, vpk,
        );

        // Sign the attestation
        let payload = att.signing_payload();
        let sig = sk.sign(&payload);
        att.set_signature(sig.to_bytes().to_vec());

        (att, core_id, input_hash, output_hash, vpk)
    }

    #[test]
    fn test_valid_attestation() {
        let (att, core_id, input_hash, output_hash, vpk) = make_test_attestation();
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::Valid));
    }

    #[test]
    fn test_wrong_core_id() {
        let (att, _, input_hash, output_hash, vpk) = make_test_attestation();
        let wrong_core = [0xFF; 32];
        let result = verify_dmap_attestation(&att, &wrong_core, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::WrongCore));
    }

    // ── CoreID lineage accept-set composition (design §11) ──────────────────
    // Drives the accept-set through the SHARED resolver the Lambda/Nabla verify sites
    // call (version::resolve_dmap_verify_core_id_in — the injectable form of the exact
    // fn those sites use) against a REAL attestation, proving it composes with the
    // challenge-derivation binding: a blessed prior verifies, a non-blessed one is
    // WrongCore. Because the sites and this test share ONE resolver, a passing test
    // reflects the real site behavior, not a replica.
    #[test]
    fn accept_set_composes_with_dmap_verify() {
        use axiom_core_logic::version::resolve_dmap_verify_core_id_in;
        // Attestation minted under a PRIOR CoreID P; the node's CURRENT CoreID is Q ≠ P.
        let (att, prior_core_id, input_hash, output_hash, vpk) = make_test_attestation();
        let current = [0x11u8; 32];
        assert_ne!(att.core_id, current, "test setup: prior must differ from current");

        // Hex-encode P for the blessed list.
        let mut prior_hex = String::new();
        for b in &prior_core_id {
            prior_hex.push_str(&format!("{:02x}", b));
        }

        // (1) P NOT in the accept-set → resolver falls through to current Q → WrongCore.
        let vcid = resolve_dmap_verify_core_id_in(&att.core_id, &current, "");
        assert!(
            matches!(
                verify_dmap_attestation(&att, &vcid, &input_hash, &output_hash, &vpk),
                DmapResult::WrongCore
            ),
            "an outstanding cheque's prior CoreID must reject when it is NOT blessed"
        );

        // (2) P blessed → resolver picks P → challenges derive from P → Valid.
        let vcid = resolve_dmap_verify_core_id_in(&att.core_id, &current, &prior_hex);
        assert!(
            matches!(
                verify_dmap_attestation(&att, &vcid, &input_hash, &output_hash, &vpk),
                DmapResult::Valid
            ),
            "an outstanding cheque minted under a BLESSED prior CoreID must verify across the rotation"
        );

        // (3) revocation-by-omission: drop P from the set → back to WrongCore.
        let vcid = resolve_dmap_verify_core_id_in(&att.core_id, &current, "");
        assert!(
            matches!(
                verify_dmap_attestation(&att, &vcid, &input_hash, &output_hash, &vpk),
                DmapResult::WrongCore
            ),
            "revoking (omitting) the prior CoreID must make the same cheque unredeemable again"
        );
    }

    #[test]
    fn test_wrong_output_hash() {
        let (att, core_id, input_hash, _, vpk) = make_test_attestation();
        let wrong_output = [0xFF; 32];
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &wrong_output, &vpk);
        assert!(matches!(result, DmapResult::OutputHashMismatch));
    }

    #[test]
    fn test_unsigned_attestation_rejected() {
        let (mut att, core_id, input_hash, output_hash, vpk) = make_test_attestation();
        att.signature = Vec::new(); // Remove signature
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::InvalidSignature),
            "Unsigned attestation must be rejected");
    }

    #[test]
    fn test_wrong_validator_pk_rejected() {
        let (att, core_id, input_hash, output_hash, _vpk) = make_test_attestation();
        let wrong_pk = [0xFF; 32]; // different from attestation's validator_pk
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &wrong_pk);
        assert!(matches!(result, DmapResult::InvalidSignature),
            "Mismatched validator_pk must be rejected");
    }

    #[test]
    fn test_forged_signature_rejected() {
        let (mut att, core_id, input_hash, output_hash, vpk) = make_test_attestation();
        // Corrupt one byte of the signature
        if let Some(b) = att.signature.get_mut(0) {
            *b ^= 0xFF;
        }
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::InvalidSignature),
            "Corrupted signature must be rejected");
    }

    #[test]
    fn test_zero_checkpoints_rejected() {
        let (mut att, core_id, input_hash, output_hash, vpk) = make_test_attestation();
        att.total_checkpoints = 0;
        att.revealed_checkpoints.clear();
        let result = verify_dmap_attestation(&att, &core_id, &input_hash, &output_hash, &vpk);
        assert!(matches!(result, DmapResult::MissingCheckpoints(_)),
            "Zero-checkpoint attestation must be rejected, got {:?}", result);
    }

    #[test]
    fn test_memory_mismatch_detected() {
        let (att, core_id, input_hash, output_hash, vpk) = make_test_attestation();

        let bad_checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: [0xFF; 32],
                register_hash: [i as u8; 32],
            })
            .collect();

        let result = verify_with_reexecution(
            &att, &core_id, &input_hash, &output_hash, &vpk, &bad_checkpoints,
        );
        assert!(matches!(result, DmapResult::MemoryMismatch { .. }));
    }

    #[test]
    fn test_matching_reexecution_passes() {
        let (att, core_id, input_hash, output_hash, vpk) = make_test_attestation();

        let good_checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                register_hash: [i as u8; 32],
            })
            .collect();

        let result = verify_with_reexecution(
            &att, &core_id, &input_hash, &output_hash, &vpk, &good_checkpoints,
        );
        assert!(matches!(result, DmapResult::Valid));
    }

    #[test]
    fn test_register_mismatch_detected() {
        let (att, core_id, input_hash, output_hash, vpk) = make_test_attestation();

        let bad_reg_checkpoints: Vec<DmapCheckpoint> = (0..50u64)
            .map(|i| DmapCheckpoint {
                instruction_count: (i + 1) * 10000,
                pc: 0x1000 + (i as u32) * 4,
                memory_root: {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                },
                register_hash: [0xFF; 32],
            })
            .collect();

        let result = verify_with_reexecution(
            &att, &core_id, &input_hash, &output_hash, &vpk, &bad_reg_checkpoints,
        );
        assert!(
            matches!(result, DmapResult::RegisterMismatch { .. }),
            "Should detect register divergence even when memory matches"
        );
    }
}
