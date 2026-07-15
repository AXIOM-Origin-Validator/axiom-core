//! Meta-Validator Inheritance Binding (MVIB) — Yellow Paper §10
//!
//! When a validator joins the network, it publishes a signed binding to its
//! upstream admission set: the k=3 validators who signed its VBC. This binding
//! is what allows JFP voting responsibility to pass to meta-validators when a
//! validator disappears.
//!
//! MVIB commitment: BLAKE3("AXIOM_MVIB" || validator_id || admission_set || tick)
//! MVIB signature: Ed25519 over that commitment, using the validator's operational key.
//!
//! The admission chain can be walked upward: given a validator's MVIB, its
//! meta-validators are the admission_set members. Each of those validators
//! has its own MVIB with its own admission_set, forming a tree of inheritance
//! back to root validators.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use crate::errors::CoreResult;
use crate::types::{MvibBinding, ValidationError};

/// Domain separation tag for MVIB commitments.
const MVIB_DOMAIN_TAG: &[u8] = b"AXIOM_MVIB";

/// Required number of issuers in an MVIB admission set (k=3).
pub const MVIB_REQUIRED_ISSUERS: usize = 3;

/// Compute the MVIB commitment hash.
///
/// commitment = BLAKE3("AXIOM_MVIB" || validator_id || admission_set[0] || ... || admission_set[k-1] || tick)
///
/// This is the payload that gets signed by the validator's Ed25519 key.
pub fn compute_mvib_commitment(
    validator_id: &[u8; 32],
    admission_set: &[[u8; 32]],
    tick: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MVIB_DOMAIN_TAG);
    hasher.update(validator_id);
    for issuer_id in admission_set {
        hasher.update(issuer_id);
    }
    hasher.update(&tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify an MVIB binding: structure checks + Ed25519 signature over commitment.
///
/// Checks:
/// 1. Admission set has exactly 3 members (k=3)
/// 2. No duplicate validator IDs in admission set
/// 3. Binding tick is non-zero
/// 4. Ed25519 signature over BLAKE3 commitment is valid
///
/// `validator_ed25519_pk` is the validator's operational Ed25519 public key
/// (from VBC.subject_pubkey_ed25519). The caller must provide it because the
/// MvibBinding itself only contains the validator_id (BLAKE3 of SPHINCS+ PK),
/// and we need the Ed25519 key for signature verification.
pub fn verify_mvib_binding(
    binding: &MvibBinding,
    validator_ed25519_pk: &[u8],
) -> CoreResult<()> {
    // Step 1: Admission set must have exactly k=3 members
    if binding.admission_set.is_empty() {
        return Err(ValidationError::MvibEmptyAdmissionSet);
    }
    if binding.admission_set.len() != MVIB_REQUIRED_ISSUERS {
        return Err(ValidationError::MvibInvalidAdmissionSetSize);
    }

    // Step 2: No duplicate validator IDs in admission set
    {
        let mut seen = BTreeSet::new();
        for id in &binding.admission_set {
            if !seen.insert(id) {
                return Err(ValidationError::MvibDuplicateIssuer);
            }
        }
    }

    // Step 3: Binding tick must be non-zero
    if binding.binding_tick == 0 {
        return Err(ValidationError::MvibInvalidTick);
    }

    // Step 4: Verify Ed25519 signature over commitment
    let commitment = compute_mvib_commitment(
        &binding.validator_id,
        &binding.admission_set,
        binding.binding_tick,
    );

    crate::crypto::verify_ed25519(validator_ed25519_pk, &commitment, &binding.signature)
        .map_err(|_| ValidationError::MvibInvalidSignature)?;

    Ok(())
}

/// Select the meta-validator inheritance set for a given validator.
///
/// Given a validator's ID and a collection of all known MVIB bindings,
/// walks up the admission chain to find the full MV-set: the validators
/// who inherit JFP voting responsibility if this validator disappears.
///
/// The walk is:
/// 1. Start with the target validator's MVIB → get its admission_set (3 IDs)
/// 2. For each member of that admission_set, look up their MVIB → get their admission_set
/// 3. Continue until we reach validators with no MVIB (root validators) or max depth
///
/// Returns the flattened, deduplicated set of all meta-validators in the chain.
/// Root validators (those without an MVIB) are included if they appear in any admission set.
pub fn select_mv_set(
    validator_id: &[u8; 32],
    all_bindings: &[MvibBinding],
) -> Vec<[u8; 32]> {
    let mut result = BTreeSet::new();
    let mut queue: Vec<[u8; 32]> = Vec::new();
    let mut visited = BTreeSet::new();

    // Find the target validator's binding
    if let Some(binding) = all_bindings.iter().find(|b| b.validator_id == *validator_id) {
        for issuer_id in &binding.admission_set {
            if result.insert(*issuer_id) {
                queue.push(*issuer_id);
            }
        }
    }

    // Walk up the chain (BFS)
    // Max depth = 10 to match VBC chain depth limit
    let mut depth = 0;
    const MAX_WALK_DEPTH: usize = 10;

    while !queue.is_empty() && depth < MAX_WALK_DEPTH {
        let mut next_queue = Vec::new();
        for id in &queue {
            if !visited.insert(*id) {
                continue;
            }
            if let Some(binding) = all_bindings.iter().find(|b| b.validator_id == *id) {
                for issuer_id in &binding.admission_set {
                    if result.insert(*issuer_id) {
                        next_queue.push(*issuer_id);
                    }
                }
            }
            // No binding found = root validator, chain terminates here
        }
        queue = next_queue;
        depth += 1;
    }

    result.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};

    /// Helper: create a valid MVIB binding with a real Ed25519 signature.
    fn make_signed_binding(
        validator_id: [u8; 32],
        admission_set: Vec<[u8; 32]>,
        tick: u64,
        signing_key: &SigningKey,
    ) -> MvibBinding {
        let commitment = compute_mvib_commitment(&validator_id, &admission_set, tick);
        let signature = signing_key.sign(&commitment);
        MvibBinding {
            validator_id,
            admission_set,
            binding_tick: tick,
            signature: signature.to_bytes().to_vec(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 1: Valid MVIB binding creation and verification
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_valid_mvib_binding_verifies() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];
        let admission_set = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        let binding = make_signed_binding(validator_id, admission_set, 1000, &sk);
        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(result.is_ok(), "Valid MVIB binding should verify: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 2: Invalid signature rejected
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_invalid_signature_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let wrong_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let wrong_pk = wrong_sk.verifying_key();
        let validator_id = [0xAAu8; 32];
        let admission_set = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        // Sign with sk but verify with wrong_pk
        let binding = make_signed_binding(validator_id, admission_set, 1000, &sk);
        let result = verify_mvib_binding(&binding, wrong_pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibInvalidSignature)),
            "Wrong key should produce MvibInvalidSignature, got: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 3: MV-set selection follows admission chain
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_mv_set_follows_admission_chain() {
        // Build a chain: V3 admitted by [V0, V1, V2], V2 admitted by [R0, R1, R2]
        let sk3 = SigningKey::from_bytes(&[0x33u8; 32]);
        let sk2 = SigningKey::from_bytes(&[0x22u8; 32]);

        let v0 = [0x00u8; 32];
        let v1 = [0x01u8; 32];
        let v2 = [0x02u8; 32];
        let v3 = [0x03u8; 32];
        let r0 = [0xF0u8; 32];
        let r1 = [0xF1u8; 32];
        let r2 = [0xF2u8; 32];

        let binding_v3 = make_signed_binding(v3, vec![v0, v1, v2], 1000, &sk3);
        let binding_v2 = make_signed_binding(v2, vec![r0, r1, r2], 500, &sk2);

        let all_bindings = vec![binding_v3, binding_v2];
        let mv_set = select_mv_set(&v3, &all_bindings);

        // V3's direct admission set: V0, V1, V2
        assert!(mv_set.contains(&v0), "MV-set should contain V0");
        assert!(mv_set.contains(&v1), "MV-set should contain V1");
        assert!(mv_set.contains(&v2), "MV-set should contain V2");
        // V2's admission set: R0, R1, R2 (walked up)
        assert!(mv_set.contains(&r0), "MV-set should contain R0 (walked up from V2)");
        assert!(mv_set.contains(&r1), "MV-set should contain R1 (walked up from V2)");
        assert!(mv_set.contains(&r2), "MV-set should contain R2 (walked up from V2)");
        // V0 and V1 have no bindings (root validators), so no further expansion
        assert_eq!(mv_set.len(), 6);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 4: Empty admission set rejected
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_empty_admission_set_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];

        let binding = make_signed_binding(validator_id, vec![], 1000, &sk);
        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibEmptyAdmissionSet)),
            "Empty admission set should be rejected, got: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 5: Duplicate validator in admission set rejected
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_duplicate_in_admission_set_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];
        let dup = [0x01u8; 32];

        let binding = make_signed_binding(validator_id, vec![dup, dup, [0x03u8; 32]], 1000, &sk);
        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibDuplicateIssuer)),
            "Duplicate issuer should be rejected, got: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 6: Wrong admission set size rejected (not k=3)
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_wrong_admission_set_size_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];

        // Only 2 issuers
        let binding = make_signed_binding(validator_id, vec![[0x01u8; 32], [0x02u8; 32]], 1000, &sk);
        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibInvalidAdmissionSetSize)),
            "Wrong size admission set should be rejected, got: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 7: Zero tick rejected
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_zero_tick_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];
        let admission_set = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        let binding = make_signed_binding(validator_id, admission_set, 0, &sk);
        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibInvalidTick)),
            "Zero tick should be rejected, got: {:?}", result);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 8: Commitment is deterministic
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_commitment_deterministic() {
        let vid = [0xAAu8; 32];
        let set = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let c1 = compute_mvib_commitment(&vid, &set, 1000);
        let c2 = compute_mvib_commitment(&vid, &set, 1000);
        assert_eq!(c1, c2, "Same inputs must produce same commitment");

        // Different tick → different commitment
        let c3 = compute_mvib_commitment(&vid, &set, 1001);
        assert_ne!(c1, c3, "Different tick must produce different commitment");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 9: MV-set for unknown validator returns empty
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_mv_set_unknown_validator_empty() {
        let unknown = [0xFFu8; 32];
        let mv_set = select_mv_set(&unknown, &[]);
        assert!(mv_set.is_empty(), "Unknown validator should have empty MV-set");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Test 10: Tampered signature rejected
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_tampered_binding_data_rejected() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let validator_id = [0xAAu8; 32];
        let admission_set = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        let mut binding = make_signed_binding(validator_id, admission_set, 1000, &sk);
        // Tamper with the binding tick after signing
        binding.binding_tick = 9999;

        let result = verify_mvib_binding(&binding, pk.as_bytes());
        assert!(matches!(result, Err(ValidationError::MvibInvalidSignature)),
            "Tampered binding should fail signature verification, got: {:?}", result);
    }
}
