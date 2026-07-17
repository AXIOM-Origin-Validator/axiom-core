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

    /// Verify a receipt and extract outputs.
    ///
    /// Performs full RISC Zero STARK verification (requires `verify` feature).
    pub fn verify(&self, receipt: &ZkvmReceipt) -> Result<PublicOutputs, ZkvmError> {
        // First, check program digest matches
        if receipt.program_digest != self.expected_digest {
            return Err(ZkvmError::ProgramDigestMismatch);
        }

        self.verify_real(receipt)
    }

    /// Real verification using RISC Zero
    #[cfg(feature = "verify")]
    fn verify_real(&self, receipt: &ZkvmReceipt) -> Result<PublicOutputs, ZkvmError> {
        // Deserialize the RISC Zero receipt from the seal
        let risc0_receipt: Receipt = bincode::deserialize(&receipt.seal)
            .map_err(|e| ZkvmError::InvalidReceipt(format!("Failed to deserialize receipt: {}", e)))?;

        // Verify the cryptographic proof against expected IMAGE_ID
        risc0_receipt.verify(self.expected_digest)
            .map_err(|e| ZkvmError::VerificationFailed(format!("Proof verification failed: {}", e)))?;

        // Verify journal integrity: the wrapper's journal must match the proven journal
        if receipt.journal != risc0_receipt.journal.bytes {
            return Err(ZkvmError::VerificationFailed(
                "Journal mismatch: receipt journal does not match proven journal".to_string()
            ));
        }

        // Decode the outputs from the journal
        let outputs: PublicOutputs = risc0_receipt.journal.decode()
            .map_err(|e| ZkvmError::InvalidReceipt(format!("Failed to decode outputs: {}", e)))?;

        Ok(outputs)
    }

    /// Verification requires the `verify` feature.
    #[cfg(not(feature = "verify"))]
    fn verify_real(&self, _receipt: &ZkvmReceipt) -> Result<PublicOutputs, ZkvmError> {
        Err(ZkvmError::VerificationFailed(
            "Real verification requires the 'verify' feature. \
             Compile with --features verify".to_string()
        ))
    }

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
        let result = verifier.verify(&receipt);
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
