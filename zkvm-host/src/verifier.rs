//! zkVM Verifier
//!
//! Verifies ZK proofs of AVM execution (which runs core-logic validation).
//!
//! Requires the `verify` feature for real RISC Zero STARK verification.
//! No dev mode — all verification is cryptographic.

use axiom_dmap_vm::PublicOutputs;
use axiom_core_logic::ZkpCheckpointOutputs;
use crate::{ZkvmError, ZkvmReceipt, ZkvmConfig};

#[cfg(feature = "verify")]
use risc0_zkvm::Receipt;

/// zkVM Verifier — production only, no dev mode.
pub struct ZkvmVerifier {
    /// Expected program digest (IMAGE_ID)
    expected_digest: [u8; 32],
}

impl ZkvmVerifier {
    /// Create a production verifier. Fails if zkVM artifacts are not available.
    pub fn production() -> Result<Self, ZkvmError> {
        let mut config = ZkvmConfig::from_env();
        if !config.is_available() {
            return Err(ZkvmError::ExecutionFailed(format!(
                "zkVM artifacts not found. {}\n\
                 See ~/.axiom/zkvm/README.md for setup instructions.",
                config.status()
            )));
        }
        let expected_digest = config.load_image_id()?;
        Ok(Self {
            expected_digest,
        })
    }

    /// Create a production verifier with explicit config.
    pub fn production_with_config(mut config: ZkvmConfig) -> Result<Self, ZkvmError> {
        if !config.is_available() {
            return Err(ZkvmError::ExecutionFailed(format!(
                "zkVM artifacts not found. {}\n\
                 See ~/.axiom/zkvm/README.md for setup instructions.",
                config.status()
            )));
        }
        let expected_digest = config.load_image_id()?;
        Ok(Self {
            expected_digest,
        })
    }

    /// Create a verifier with a known digest (for cases where digest is already loaded).
    pub fn with_digest(expected_digest: [u8; 32]) -> Self {
        Self { expected_digest }
    }

    // DELETED 2026-09-02: `verify()` and its `verify_real()` helpers (both cfg
    // variants), the twin of the `ZkvmProver::prove()` deleted in cc3573ac.
    // They decoded the journal as `PublicOutputs`, which no guest has committed
    // since the checkpoint cutover — so proof_type==0 STARK verification could
    // not succeed for ANY valid proof.
    //
    // Unlike prove(), this one had LIVE consensus-path callers (Nabla's
    // registration witness check and Lambda's cheque redeem), so the ZKP tier
    // was not merely dead — it was a path that always failed. Both are rewired
    // to `verify_checkpoint()` below, which is byte-identical apart from the
    // decoded type: same digest check, same STARK verification, same
    // journal-integrity check.

    /// Verify a checkpoint receipt and extract ZkpCheckpointOutputs.
    pub fn verify_checkpoint(&self, receipt: &ZkvmReceipt) -> Result<ZkpCheckpointOutputs, ZkvmError> {
        if receipt.program_digest != self.expected_digest {
            return Err(ZkvmError::ProgramDigestMismatch);
        }
        self.verify_checkpoint_real(receipt)
    }

    #[cfg(feature = "verify")]
    fn verify_checkpoint_real(&self, receipt: &ZkvmReceipt) -> Result<ZkpCheckpointOutputs, ZkvmError> {
        let risc0_receipt: Receipt = bincode::deserialize(&receipt.seal)
            .map_err(|e| ZkvmError::InvalidReceipt(format!("Failed to deserialize receipt: {}", e)))?;

        risc0_receipt.verify(self.expected_digest)
            .map_err(|e| ZkvmError::VerificationFailed(format!("Proof verification failed: {}", e)))?;

        if receipt.journal != risc0_receipt.journal.bytes {
            return Err(ZkvmError::VerificationFailed(
                "Journal mismatch: receipt journal does not match proven journal".to_string()
            ));
        }

        let checkpoint: ZkpCheckpointOutputs = risc0_receipt.journal.decode()
            .map_err(|e| ZkvmError::InvalidReceipt(format!("Failed to decode checkpoint: {}", e)))?;

        Ok(checkpoint)
    }

    #[cfg(not(feature = "verify"))]
    fn verify_checkpoint_real(&self, _receipt: &ZkvmReceipt) -> Result<ZkpCheckpointOutputs, ZkvmError> {
        Err(ZkvmError::VerificationFailed(
            "Real verification requires the 'verify' feature.".to_string()
        ))
    }

    /// Get the expected program digest
    pub fn expected_digest(&self) -> [u8; 32] {
        self.expected_digest
    }
}

/// Verify that a receipt's program digest matches expected
pub fn verify_program_digest(
    receipt: &ZkvmReceipt,
    expected: &[u8; 32],
) -> Result<(), ZkvmError> {
    if receipt.program_digest == *expected {
        Ok(())
    } else {
        Err(ZkvmError::ProgramDigestMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_requires_artifacts() {
        let config = crate::ZkvmConfig::new("/nonexistent/path.elf", "/nonexistent/id.hex");
        let result = ZkvmVerifier::production_with_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_digest() {
        // Verifier with known digest rejects mismatched receipt
        let verifier = ZkvmVerifier::with_digest([0x42; 32]);
        let receipt = ZkvmReceipt {
            journal: b"{}".to_vec(),
            seal: b"fake".to_vec(),
            program_digest: [0xFF; 32], // Wrong digest
        };
        // Ported to verify_checkpoint 2026-09-02 with the deletion of verify().
        // The property is unchanged: the digest gate runs BEFORE any STARK work,
        // so a receipt claiming a foreign IMAGE_ID is refused outright — with a
        // deliberately unverifiable seal here, reaching any other error would
        // mean the digest check had been skipped.
        let result = verifier.verify_checkpoint(&receipt);
        assert!(matches!(result, Err(ZkvmError::ProgramDigestMismatch)));
    }

    #[test]
    fn test_verify_program_digest_helper() {
        let digest = [0x42; 32];
        let receipt = ZkvmReceipt {
            journal: vec![],
            seal: vec![],
            program_digest: digest,
        };
        assert!(verify_program_digest(&receipt, &digest).is_ok());
        assert!(verify_program_digest(&receipt, &[0xFF; 32]).is_err());
    }
}
