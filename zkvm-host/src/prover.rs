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

    // DELETED 2026-09-02: `ZkvmProver::prove()` (both the `prove`-gated body
    // and its non-feature stub).
    //
    // It was the ORIGINAL zkVM design: run all of Core inside the guest and
    // return a fully STARK-proved `PublicOutputs` — Dilithium FACT signing,
    // FACT-chain verification and witness validation all inside the ZK
    // boundary. That design was abandoned for cost: the guest
    // (core/zkvm-guest/guest/src/main.rs:149) commits a `ZkpCheckpointOutputs`
    // and nothing else, so `prove()` decoded the journal as a type no guest
    // produces and always died with "expected variant index 0 <= i < 3".
    //
    // It was not repairable in place. A `PublicOutputs` journal needs a
    // full-Core guest, which is the thing the checkpoint design deliberately
    // walked away from — and it would also break the two-VM invariant, which
    // holds over the checkpoint SUBSET (`result`, `produced_state_id`,
    // `new_balance`, `new_wallet_seq`, `rejection_reason`), never over
    // `PublicOutputs`.
    //
    // `prove_checkpoint()` below is the live path and always was in practice:
    // prover-worker and Lambda call it. Do not reintroduce a full-outputs
    // prove without first changing what the guest commits.

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
        // KI#155 (2026-09-13): the guest deserialises this whole frame IN-CIRCUIT
        // and `execute_cl3_zkp_checkpoint` reads none of the fields below. The
        // KI#145 certificate set alone is ~165 KB of SPHINCS+ bundles on a FACT
        // send — MEASURED 58 segments / 60.8 M cycles vs 1 segment for a plain
        // vector, ~95 % of it decoding data the proof ignores. Same strips as
        // Lambda's ZKP path (`core_client.rs`), plus the certificates both
        // predated. The journal binds transaction fields + state, never this
        // frame, so the proof's meaning is unchanged — only its cost.
        guest_inputs.fact_certificates = Vec::new();
        guest_inputs.vbc_bundle = None;
        guest_inputs.fact_witness_sigs = Vec::new();
        guest_inputs.cl1_execution_proof = None;

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
