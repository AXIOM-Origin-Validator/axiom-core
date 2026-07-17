//! C1: Mirror Worldline Resolution — Canonical Reality Attestation
//!
//! When a fork is detected (two valid but incompatible VBC chains traced to genesis),
//! Root Authority key holders produce Reality Attestations. 2-of-3 attestations
//! constitute consensus on which genesis chain is canonical.
//!
//! Core verifies attestations against hardcoded ROOT_AUTHORITY_PKS.
//! Lambda broadcasts via CL10 Fan-Out (content type 0x0200).

use crate::types::RealityAttestation;
use crate::genesis::ROOT_AUTHORITY_PKS;
use crate::errors::ValidationError;

/// Compute the commitment for a Reality Attestation.
/// BLAKE3("AXIOM_CANONICAL" || canonical_genesis_hash || tick)
pub fn compute_reality_commitment(
    canonical_genesis_hash: &[u8; 32],
    tick: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CANONICAL");
    hasher.update(canonical_genesis_hash);
    hasher.update(&tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify a single Reality Attestation.
/// Checks:
/// 1. root_authority_index is 0, 1, or 2
/// 2. root_authority_pk matches ROOT_AUTHORITY_PKS[index]
/// 3. SPHINCS+ signature over commitment is valid
pub fn verify_reality_attestation(
    attestation: &RealityAttestation,
) -> Result<(), ValidationError> {
    // 1. Index valid
    if attestation.root_authority_index > 2 {
        return Err(ValidationError::InternalError);
    }

    // 2. PK matches hardcoded root authority
    let expected_pk = &ROOT_AUTHORITY_PKS[attestation.root_authority_index as usize];
    if attestation.root_authority_pk.len() != 32
        || &attestation.root_authority_pk[..] != expected_pk
    {
        return Err(ValidationError::InternalError);
    }

    // 3. Verify SPHINCS+ signature over commitment
    let commitment = compute_reality_commitment(
        &attestation.canonical_genesis_hash,
        attestation.tick,
    );
    crate::crypto::verify_signature(
        &attestation.root_authority_pk,
        &commitment,
        &attestation.signature,
    )?;

    Ok(())
}

/// Verify a set of Reality Attestations.
/// Returns Ok if at least 2-of-3 valid attestations agree on the same genesis hash.
pub fn verify_canonical_consensus(
    attestations: &[RealityAttestation],
) -> Result<[u8; 32], ValidationError> {
    if attestations.is_empty() {
        return Err(ValidationError::InternalError);
    }

    let mut valid_count = 0u8;
    let mut canonical_hash = [0u8; 32];

    // All attestations must agree on the same genesis hash
    let target_hash = &attestations[0].canonical_genesis_hash;

    for att in attestations {
        // Must all reference same canonical hash
        if &att.canonical_genesis_hash != target_hash {
            return Err(ValidationError::InternalError);
        }

        // Verify each attestation
        if verify_reality_attestation(att).is_ok() {
            valid_count += 1;
            canonical_hash = att.canonical_genesis_hash;
        }
    }

    // 2-of-3 required
    if valid_count >= 2 {
        Ok(canonical_hash)
    } else {
        Err(ValidationError::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn reality_commitment_deterministic() {
        let hash = [0xAA; 32];
        let c1 = compute_reality_commitment(&hash, 1000);
        let c2 = compute_reality_commitment(&hash, 1000);
        assert_eq!(c1, c2);
    }

    #[test]
    fn reality_commitment_differs_on_tick() {
        let hash = [0xAA; 32];
        let c1 = compute_reality_commitment(&hash, 1000);
        let c2 = compute_reality_commitment(&hash, 1001);
        assert_ne!(c1, c2);
    }

    #[test]
    fn reality_commitment_differs_on_hash() {
        let c1 = compute_reality_commitment(&[0xAA; 32], 1000);
        let c2 = compute_reality_commitment(&[0xBB; 32], 1000);
        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_rejects_bad_index() {
        let att = RealityAttestation {
            canonical_genesis_hash: [0xAA; 32],
            root_authority_index: 5, // invalid
            root_authority_pk: vec![0; 32],
            signature: vec![0; 64],
            tick: 1000,
        };
        assert!(verify_reality_attestation(&att).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pk() {
        let att = RealityAttestation {
            canonical_genesis_hash: [0xAA; 32],
            root_authority_index: 0,
            root_authority_pk: vec![0xFF; 32], // wrong PK
            signature: vec![0; 64],
            tick: 1000,
        };
        assert!(verify_reality_attestation(&att).is_err());
    }

    #[test]
    fn consensus_rejects_empty() {
        assert!(verify_canonical_consensus(&[]).is_err());
    }

    #[test]
    fn consensus_rejects_disagreeing_hashes() {
        let att1 = RealityAttestation {
            canonical_genesis_hash: [0xAA; 32],
            root_authority_index: 0,
            root_authority_pk: ROOT_AUTHORITY_PKS[0].to_vec(),
            signature: vec![0; 64],
            tick: 1000,
        };
        let att2 = RealityAttestation {
            canonical_genesis_hash: [0xBB; 32], // different hash
            root_authority_index: 1,
            root_authority_pk: ROOT_AUTHORITY_PKS[1].to_vec(),
            signature: vec![0; 64],
            tick: 1000,
        };
        assert!(verify_canonical_consensus(&[att1, att2]).is_err());
    }
}
