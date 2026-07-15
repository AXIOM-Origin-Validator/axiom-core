//! zkVM Prover
//!
//! Generates ZK proofs of AVM execution (which runs core-logic validation).
//!
//! Requires the `prove` feature and zkVM artifacts (ELF + IMAGE_ID).
//! No dev mode — all proofs are real RISC Zero STARK proofs.
//!
//! # Architecture
//!
//! ```text
//! zkVM Prover
//!     ↓
//! zkVM Guest (RISC-V ELF)
//!     ↓
//! AVM (validation executor)
//!     ↓
//! core-logic (validation rules)
//! ```

use axiom_dmap_vm::PublicInputs;
use axiom_dmap_vm::PublicOutputs;
use axiom_core_logic::ZkpCheckpointOutputs;
#[cfg(feature = "prove")]
use axiom_core_logic::FactCargo;
use crate::{ZkvmError, ZkvmReceipt, ZkvmConfig};

#[cfg(feature = "prove")]
use risc0_zkvm::{default_prover, ExecutorEnv};

/// Serialize a value to a CBOR byte frame for the guest.
///
/// The guest reads its inputs as self-describing CBOR (`env::read_frame()` +
/// `ciborium::de::from_reader`, matching the DMAP guest). We must NOT use
/// risc0's `ExecutorEnv::write` here: that codec is word-based and
/// non-self-describing, so a `#[serde(skip_serializing_if = "Option::is_none")]`
/// field (e.g. `WalletState.wallet_id`) is omitted on the host but still read
/// positionally by the guest — desyncing the stream (`DeserializeUnexpectedEnd`).
#[cfg(feature = "prove")]
fn to_cbor_frame<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ZkvmError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| ZkvmError::ProofGenerationFailed(format!("CBOR encode failed: {}", e)))?;
    Ok(buf)
}

/// zkVM Prover — production only, no dev mode.
#[derive(Debug)]
pub struct ZkvmProver {
    /// Configuration for loading ELF and IMAGE_ID
    config: ZkvmConfig,

    /// Program digest (IMAGE_ID) - loaded from artifacts
    program_digest: [u8; 32],
}

impl ZkvmProver {
    /// Create a production prover. Fails if zkVM artifacts are not available.
    pub fn production() -> Result<Self, ZkvmError> {
        let mut config = ZkvmConfig::from_env();
        if !config.is_available() {
            return Err(ZkvmError::ExecutionFailed(format!(
                "zkVM artifacts not found. {}\n\
                 See ~/.axiom/zkvm/README.md for setup instructions.",
                config.status()
            )));
        }
        let program_digest = config.load_image_id()?;
        Ok(Self {
            config,
            program_digest,
        })
    }

    /// Create a production prover with explicit config.
    pub fn production_with_config(mut config: ZkvmConfig) -> Result<Self, ZkvmError> {
        if !config.is_available() {
            return Err(ZkvmError::ExecutionFailed(format!(
                "zkVM artifacts not found. {}\n\
                 See ~/.axiom/zkvm/README.md for setup instructions.",
                config.status()
            )));
        }
        let program_digest = config.load_image_id()?;
        Ok(Self {
            config,
            program_digest,
        })
    }

    /// Execute core-logic (via AVM) inside zkVM and generate STARK proof.
    #[cfg(feature = "prove")]
    pub fn prove(&mut self, inputs: PublicInputs) -> Result<(PublicOutputs, ZkvmReceipt), ZkvmError> {
        // Load ELF from config
        let elf = self.config.load_elf()?;

        // CBOR-frame both inputs the guest reads (PublicInputs, then an
        // Option<FactCargo> — main.rs reads two frames). The basic prove path
        // carries no cargo, so the second frame is `None`. Each frame is a
        // `Vec<u8>` carried over risc0's stable word-serde; the guest decodes
        // the inner CBOR (see to_cbor_frame).
        let inputs_frame = to_cbor_frame(&inputs)?;
        let cargo_frame = to_cbor_frame(&None::<FactCargo>)?;

        // Build the executor environment with the CBOR frames
        let env = ExecutorEnv::builder()
            .write(&inputs_frame)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to write inputs frame: {}", e)))?
            .write(&cargo_frame)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to write cargo frame: {}", e)))?
            .build()
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to build env: {}", e)))?;

        // Get the default prover
        let prover = default_prover();

        // Prove the execution
        let prove_info = prover.prove(env, elf)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Proving failed: {}", e)))?;

        let receipt = prove_info.receipt;

        // Decode the outputs from the journal
        let outputs: PublicOutputs = receipt.journal.decode()
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to decode outputs: {}", e)))?;

        // Convert to our receipt format
        let journal = receipt.journal.bytes.clone();
        let seal = bincode::serialize(&receipt)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to serialize seal: {}", e)))?;

        let zkvm_receipt = ZkvmReceipt::new(journal, seal, self.program_digest);

        Ok((outputs, zkvm_receipt))
    }

    /// Proving requires the `prove` feature.
    #[cfg(not(feature = "prove"))]
    pub fn prove(&mut self, _inputs: PublicInputs) -> Result<(PublicOutputs, ZkvmReceipt), ZkvmError> {
        Err(ZkvmError::ProofGenerationFailed(
            "Real proving requires the 'prove' feature. \
             Compile with --features prove".to_string()
        ))
    }

    /// Prove with minimal ZK boundary (checkpoint mode).
    ///
    /// Flow:
    /// 1. Core runs natively on host → produces PublicOutputs (incl. FACT data)
    /// 2. Both PublicInputs and native PublicOutputs are sent to guest
    /// 3. Guest runs 14 cheap checks + commits FACT data as cargo
    /// 4. STARK proves: input integrity + essential checks + IMAGE_ID
    ///
    /// This is ~10× faster than full prove() because Dilithium signing,
    /// FACT chain verification, and witness validation run natively.
    #[cfg(feature = "prove")]
    pub fn prove_checkpoint(
        &mut self,
        inputs: PublicInputs,
        native_outputs: Option<PublicOutputs>,
    ) -> Result<(ZkpCheckpointOutputs, ZkvmReceipt), ZkvmError> {
        let elf = self.config.load_elf()?;

        // Strip fields the guest doesn't need — reduce serialization inside RISC-V.
        // The guest only runs 14 cheap checks; it doesn't need Dilithium keys,
        // FACT chain, VBC bundle, overlapped signatures, etc.
        let mut guest_inputs = inputs;
        guest_inputs.my_dilithium_sk = None;
        guest_inputs.my_dilithium_pk = None;
        guest_inputs.issuer_sphincs_sk = None;

        // Convert PublicOutputs → lightweight FactCargo (only txid, saves ~1M RISC-V cycles)
        // fact_signature (3,309 bytes) stays on host — attached to output post-proving.
        let fact_signature = native_outputs.as_ref().and_then(|out| out.fact_signature.clone());
        let fact_cargo: Option<FactCargo> = native_outputs.map(|out| FactCargo {
            txid: out.txid,
        });

        // Pass stripped inputs and lightweight FactCargo to the guest as CBOR
        // frames (self-describing — see to_cbor_frame).
        let inputs_frame = to_cbor_frame(&guest_inputs)?;
        let cargo_frame = to_cbor_frame(&fact_cargo)?;
        let env = ExecutorEnv::builder()
            .write(&inputs_frame)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to write inputs frame: {}", e)))?
            .write(&cargo_frame)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to write cargo frame: {}", e)))?
            .build()
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to build env: {}", e)))?;

        let prover = default_prover();

        let prove_info = prover.prove(env, elf)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Proving failed: {}", e)))?;

        // Log execution stats for benchmarking
        eprintln!("[prove_checkpoint] stats: {:?}", prove_info.stats);

        let receipt = prove_info.receipt;

        // Decode ZkpCheckpointOutputs from the journal
        let mut checkpoint: ZkpCheckpointOutputs = receipt.journal.decode()
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to decode checkpoint: {}", e)))?;

        // Attach fact_signature post-proving (not inside STARK — independently verifiable via Dilithium PK)
        checkpoint.fact_signature = fact_signature;

        let journal = receipt.journal.bytes.clone();
        let seal = bincode::serialize(&receipt)
            .map_err(|e| ZkvmError::ProofGenerationFailed(format!("Failed to serialize seal: {}", e)))?;

        let zkvm_receipt = ZkvmReceipt::new(journal, seal, self.program_digest);

        Ok((checkpoint, zkvm_receipt))
    }

    #[cfg(not(feature = "prove"))]
    pub fn prove_checkpoint(
        &mut self,
        _inputs: PublicInputs,
        _native_outputs: Option<PublicOutputs>,
    ) -> Result<(ZkpCheckpointOutputs, ZkvmReceipt), ZkvmError> {
        Err(ZkvmError::ProofGenerationFailed(
            "Real proving requires the 'prove' feature. \
             Compile with --features prove".to_string()
        ))
    }

    /// Get the program digest (IMAGE_ID)
    pub fn program_digest(&self) -> [u8; 32] {
        self.program_digest
    }

    /// Get the config status
    pub fn config_status(&self) -> String {
        self.config.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_requires_artifacts() {
        let config = crate::ZkvmConfig::new("/nonexistent/path.elf", "/nonexistent/id.hex");
        let result = ZkvmProver::production_with_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_production_from_env_requires_artifacts() {
        // Unless artifacts are installed, production() should fail
        // This test verifies the fail-stop behavior
        let result = ZkvmProver::production();
        // May succeed if artifacts are installed, that's fine
        if let Err(e) = &result {
            assert!(format!("{}", e).contains("artifacts not found") || format!("{}", e).contains("Failed to load"));
        }
    }
}
