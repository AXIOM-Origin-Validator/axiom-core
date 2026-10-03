//! AXIOM zkVM Host
//!
//! Proof generation and verification using RISC Zero.
//!
//! This crate provides:
//! - ZKP proof generation (prover)
//! - ZKP proof verification (verifier)
//! - Receipt handling
//! - Configuration for loading ELF/IMAGE_ID from disk
//!
//! # Configuration
//!
//! The zkVM artifacts (ELF binary and IMAGE_ID) can be loaded from:
//!
//! 1. Environment variables:
//!    ```bash
//!    export AXIOM_ZKVM_ELF=/path/to/axiom-core.elf
//!    export AXIOM_ZKVM_IMAGE_ID=/path/to/image-id.hex
//!    ```
//!
//! 2. Default paths: `~/.axiom/zkvm/axiom-core.elf` and `~/.axiom/zkvm/image-id.hex`
//!
//! # Architecture
//!
//! ```text
//! Host (this crate)              Guest (zkvm-guest)
//! ┌─────────────────┐           ┌─────────────────┐
//! │  Prover         │──inputs──▶│  Core.bin       │
//! │                 │           │                 │
//! │  - Load ELF     │           │  - Validate tx  │
//! │  - Execute      │           │  - Compute hash │
//! │  - Generate     │◀─outputs──│  - Commit       │
//! │    proof        │           │                 │
//! └─────────────────┘           └─────────────────┘
//!         │
//!         ▼
//! ┌─────────────────┐
//! │  Receipt        │
//! │  - Journal      │
//! │  - Seal (proof) │
//! └─────────────────┘
//! ```

pub mod config;
pub mod prover;
pub mod subprocess_prover;
pub mod verifier;

pub use config::ZkvmConfig;
pub use prover::ZkvmProver;
pub use subprocess_prover::SubprocessProver;
pub use verifier::ZkvmVerifier;

/// zkVM Receipt
///
/// Contains the proof of execution and public outputs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkvmReceipt {
    /// The journal (public outputs)
    pub journal: Vec<u8>,
    
    /// The seal (cryptographic proof)
    pub seal: Vec<u8>,
    
    /// Program digest (identifies which program was run)
    pub program_digest: [u8; 32],
}

impl ZkvmReceipt {
    /// Create a new receipt
    pub fn new(journal: Vec<u8>, seal: Vec<u8>, program_digest: [u8; 32]) -> Self {
        Self {
            journal,
            seal,
            program_digest,
        }
    }
    
    /// Serialize the receipt
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Program digest (32 bytes)
        bytes.extend_from_slice(&self.program_digest);
        
        // Journal length (4 bytes) + journal
        bytes.extend_from_slice(&(self.journal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.journal);
        
        // Seal length (4 bytes) + seal
        bytes.extend_from_slice(&(self.seal.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.seal);
        
        bytes
    }
    
    /// Deserialize a receipt
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkvmError> {
        if bytes.len() < 40 {
            return Err(ZkvmError::InvalidReceipt("Too short".to_string()));
        }
        
        // Program digest
        let program_digest: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| ZkvmError::InvalidReceipt("Invalid program digest".to_string()))?;
        
        // Journal
        let journal_len = u32::from_le_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| ZkvmError::InvalidReceipt("Invalid journal length".to_string()))?
        ) as usize;
        
        if bytes.len() < 36 + journal_len + 4 {
            return Err(ZkvmError::InvalidReceipt("Journal truncated".to_string()));
        }
        
        let journal = bytes[36..36 + journal_len].to_vec();
        
        // Seal
        let seal_offset = 36 + journal_len;
        let seal_len = u32::from_le_bytes(
            bytes[seal_offset..seal_offset + 4]
                .try_into()
                .map_err(|_| ZkvmError::InvalidReceipt("Invalid seal length".to_string()))?
        ) as usize;
        
        if bytes.len() < seal_offset + 4 + seal_len {
            return Err(ZkvmError::InvalidReceipt("Seal truncated".to_string()));
        }
        
        let seal = bytes[seal_offset + 4..seal_offset + 4 + seal_len].to_vec();
        
        Ok(Self {
            journal,
            seal,
            program_digest,
        })
    }
}

/// zkVM errors
#[derive(Debug, thiserror::Error)]
pub enum ZkvmError {
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid receipt: {0}")]
    InvalidReceipt(String),
    
    #[error("Program digest mismatch")]
    ProgramDigestMismatch,
    
    #[error("Guest execution failed: {0}")]
    ExecutionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_receipt_roundtrip() {
        let receipt = ZkvmReceipt {
            journal: b"test journal".to_vec(),
            seal: b"test seal".to_vec(),
            program_digest: [0x42u8; 32],
        };

        let bytes = receipt.to_bytes();
        let parsed = ZkvmReceipt::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.journal, receipt.journal);
        assert_eq!(parsed.seal, receipt.seal);
        assert_eq!(parsed.program_digest, receipt.program_digest);
    }

    // DELETED 2026-09-01: `test_stark_baseline` and `test_stark_real_cl3`.
    //
    // Both drove `ZkvmProver::prove()`, which decodes the journal as
    // `PublicOutputs` and therefore ALWAYS fails on a real receipt
    // ("expected variant index 0 <= i < 3") — the defect CLAUDE.md and
    // AXIOM_GUIDE_ZKVM.md both record. They were `#[ignore]`d, so they had
    // never run; and their fixtures had gone stale (missing RECALL / OODS /
    // FOB inputs), so they no longer COMPILED either. An ignored test of a
    // function that cannot succeed is not coverage, it is a claim (RULE 3).
    //
    // They went with the `first-proof` / `zkp-demo` bins in the same commit.
    // The live path keeps its benchmark: `test_stark_checkpoint` below drives
    // `prove_checkpoint()` / `verify_checkpoint()`, which is what
    // `prover-worker` and Lambda actually call.


    /// Benchmark: Minimal ZK boundary (checkpoint mode)
    ///
    /// Full production flow:
    /// 1. Core runs natively → produces PublicOutputs (incl. Dilithium FACT sig)
    /// 2. Guest runs 14 cheap checks + commits FACT data as cargo
    /// 3. STARK proves input integrity + essential checks + IMAGE_ID
    ///
    /// Expected: near 19s baseline (minimal guest, Ed25519 precompile + SHA3 + BLAKE3)
    ///
    /// Run: cargo test --release -p axiom-zk-vm --features prove --lib -- --ignored test_stark_checkpoint
    #[test]
    #[ignore]
    fn test_stark_checkpoint() {
        use axiom_dmap_vm::{PublicInputs, CoreLogicMode};
        use axiom_test_utils::TestWallet;
        use axiom_core_logic::{ValidationResult, ZkpCheckpointOutputs};
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes;

        // Create real wallets with Ed25519 keypairs
        let sender = TestWallet::generate("sender@test.com", 1_000_000_000);
        let receiver = TestWallet::generate("receiver@test.com", 0);

        // Generate Dilithium keypair for FACT signing
        eprintln!("[checkpoint] Generating ML-DSA-65 keypair...");
        let (dil_pk, dil_sk) = ml_dsa_65::try_keygen()
            .expect("Dilithium keygen failed");
        let dil_sk_bytes = dil_sk.into_bytes().to_vec();
        let dil_pk_bytes = dil_pk.into_bytes().to_vec();

        // ZKP nonce
        let zkp_nonce: [u8; 32] = {
            let mut n = [0u8; 32];
            n[0] = 0xBE; n[1] = 0xEF;
            n
        };

        // Create and sign a real transaction
        let tx = sender.create_transaction(
            &receiver.address(),
            50_000,
            "checkpoint benchmark",
            1,
        );

        // Build full production inputs (with Dilithium key for FACT signing)
        let inputs = PublicInputs {
            zkq_request: None,
            fact_certificates: Vec::new(),
            // §5.2.2b/c — added after this test last compiled; a plain CL3
            // send is not a subsidy claim and holds no stake lock.
            claimant_vbc: None,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            receiver_current_wallet_format: None,
            mode: CoreLogicMode::CL3,
            transaction: tx.clone(),
            prev_receipts: vec![],
            current_state: Some(sender.wallet_state()),
            // Inputs added after this test last compiled; a plain CL3 send
            // exercises none of them.
            recall_attestation: None,
            oods_attestation: None,
            fob_claim_attestation: None,
            receiver_witness: None,
            receiver_signing_key: None,
            vbc_bundle: None,
            my_validator_pk: None,
            overlapped_signatures: vec![],
            cheque_bundle: None,
            receiver_pk: None,
            receiver_current_balance: None,
            receiver_wallet_seq: None,
            receiver_new_balance: None,
            receiver_new_state_id: None,
            receiver_current_hibernation: None,
            group_member_index: None,
            sender_fact_chain: None,
            receiver_fact_chain: None,
            my_dilithium_sk: Some(dil_sk_bytes),
            my_dilithium_pk: Some(dil_pk_bytes),
            my_validator_id: None,
            fact_witness_sigs: vec![],
            issuer_sphincs_sk: None,
            cl1_execution_proof: None,
            zkp_nonce: Some(zkp_nonce),
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
            nabla_stake_proof: None,
            frozen_wallets: None,
            console_current_cert: None,
            console_new_cert: None,
            console_selector_picks: None,
            console_nominations: None,
            txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
            max_fact_links: None,
        
        };

        // === Step 1: Run Core NATIVELY (full execution incl. Dilithium FACT signing) ===
        let native_start = std::time::Instant::now();
        let native_outputs = axiom_core_logic::execute_core(inputs.clone());
        let native_elapsed = native_start.elapsed();
        eprintln!("[checkpoint] Native Core execution: {:.2?}", native_elapsed);
        assert_eq!(native_outputs.result, ValidationResult::Accept,
            "Native execution must Accept. Rejection: {:?}", native_outputs.rejection_reason);
        assert!(native_outputs.fact_signature.is_some(),
            "Native execution must produce FACT signature");
        assert!(native_outputs.txid.is_some(),
            "Native execution must produce txid");
        eprintln!("[checkpoint] Native fact_sig: {} bytes, txid: {}",
            native_outputs.fact_signature.as_ref().unwrap().len(),
            native_outputs.txid.map(hex::encode).unwrap_or_default());

        // === Step 2: Verify checkpoint works natively (sanity check) ===
        {
            let checkpoint = axiom_core_logic::execute_cl3_zkp_checkpoint(
                &inputs,
                Some(&native_outputs),
            );
            assert_eq!(checkpoint.result, ValidationResult::Accept,
                "Checkpoint must Accept natively. Rejection: {:?}", checkpoint.rejection_reason);
            assert!(checkpoint.produced_state_id.is_some());
            assert!(checkpoint.new_balance.is_some());
            assert!(checkpoint.fact_signature.is_some(),
                "Checkpoint must carry FACT signature from native execution");
            // zkp_nonce_hash is computed by the caller (guest), not by the
            // checkpoint function itself (to avoid BLAKE3 cycles in RISC-V).
            // (No FACT commitment field exists any more — R35, 2026-09-28.)
            assert!(checkpoint.zkp_nonce_hash.is_none(),
                "Checkpoint function should NOT compute zkp_nonce_hash (caller does it)");
            eprintln!("[checkpoint] Native checkpoint sanity check passed");
        }

        // === Step 3: STARK prove (minimal ZK boundary) ===
        let mut prover = ZkvmProver::production()
            .expect("zkVM artifacts must be available");
        let verifier = ZkvmVerifier::production()
            .expect("zkVM verifier must be available");

        let start = std::time::Instant::now();
        eprintln!("[checkpoint] Starting STARK proof (minimal ZK boundary)...");
        let (checkpoint, receipt) = prover.prove_checkpoint(inputs, Some(native_outputs.clone()))
            .expect("STARK proof generation must succeed");
        let prove_elapsed = start.elapsed();
        eprintln!("[checkpoint] Proof generated in {:.2?}, seal={} bytes",
            prove_elapsed, receipt.seal.len());

        // === Step 4: Verify outputs ===
        assert_eq!(checkpoint.result, ValidationResult::Accept,
            "Checkpoint must Accept in STARK");
        assert!(checkpoint.produced_state_id.is_some(),
            "Must produce state_id");
        assert!(checkpoint.new_balance.is_some(),
            "Must produce new_balance");
        assert!(checkpoint.zkp_nonce_hash.is_some(),
            "Must produce zkp_nonce_hash");
        // FACT fields: txid from STARK, fact_signature attached post-proving.
        // No fact_commitment: the guest's unread hand-copied FACT hash and the
        // field were DELETED (Fork Settlement §9b R35, 2026-09-28) — nothing
        // consumed it (Lambda set None, differential_conformance excluded it)
        // and it had drifted from `compute_fact_commitment`.
        assert!(checkpoint.txid.is_some(), "Must carry txid");
        assert!(checkpoint.fact_signature.is_some(),
            "Must carry FACT signature (attached post-proving by host)");
        assert_ne!(checkpoint.input_hash, [0u8; 32],
            "input_hash must be non-zero");

        // Cross-check: produced_state_id and balance must match native execution
        assert_eq!(checkpoint.produced_state_id, native_outputs.produced_state_id,
            "Checkpoint produced_state_id must match native");
        assert_eq!(checkpoint.new_balance, native_outputs.new_balance,
            "Checkpoint new_balance must match native");

        // Cross-check: zkp_nonce_hash must match protocol computation (BLAKE3)
        // This is exactly what Lambda does at CL1 and CL5 verification.
        {
            let expected_nonce_hash = {
                let mut h = blake3::Hasher::new();
                h.update(b"AXIOM_ZKP_NONCE");
                h.update(&zkp_nonce);
                *h.finalize().as_bytes()
            };
            assert_eq!(checkpoint.zkp_nonce_hash.unwrap(), expected_nonce_hash,
                "Guest zkp_nonce_hash must match BLAKE3(AXIOM_ZKP_NONCE || nonce)");
        }

        eprintln!("[checkpoint] Protocol hash cross-check PASSED (zkp_nonce_hash)");

        // === Step 5: Verify the STARK ===
        let start = std::time::Instant::now();
        // Verify the receipt (STARK is valid + IMAGE_ID matches)
        let _verified: ZkpCheckpointOutputs = verifier.verify_checkpoint(&receipt)
            .expect("STARK verification must succeed");
        let verify_elapsed = start.elapsed();

        eprintln!("═══════════════════════════════════════════════════════");
        eprintln!("[checkpoint] STARK BENCHMARK — MINIMAL ZK BOUNDARY");
        eprintln!("  native:    {:.2?} (full Core incl. Dilithium FACT signing)", native_elapsed);
        eprintln!("  prove:     {:.2?} (minimal guest: Ed25519 + balance + state_id)", prove_elapsed);
        eprintln!("  verify:    {:.2?}", verify_elapsed);
        eprintln!("  seal:      {} bytes ({:.1} KB)", receipt.seal.len(), receipt.seal.len() as f64 / 1024.0);
        eprintln!("  result:    {:?}", checkpoint.result);
        eprintln!("  state_id:  {}", checkpoint.produced_state_id.map(hex::encode).unwrap_or_default());
        eprintln!("  balance:   {} → {}", sender.balance, checkpoint.new_balance.unwrap_or(0));
        eprintln!("  fact_sig:  {} bytes", checkpoint.fact_signature.as_ref().map(|s| s.len()).unwrap_or(0));
        eprintln!("  input_hash:{}", hex::encode(checkpoint.input_hash));
        eprintln!("═══════════════════════════════════════════════════════");
    }
}
