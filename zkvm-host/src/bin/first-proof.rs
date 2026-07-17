//! AXIOM First Real ZK Proof
//!
//! Generates a real RISC Zero STARK proof of Core.bin execution.
//!
//! Usage:
//!   cargo run -p axiom-zk-vm --features prove --bin first-proof --release

use axiom_zk_vm::{ZkvmProver, ZkvmVerifier};
use axiom_dmap_vm::{CoreLogicMode, PublicInputs, Transaction, TxKind, WalletState};
use std::time::Instant;

fn main() {
    println!("========================================");
    println!("  AXIOM — First Real ZK Proof");
    println!("========================================");
    println!();

    // 1. Create prover and switch to production mode
    let mut prover = ZkvmProver::production()
        .expect("Failed to create prover — are zkVM artifacts installed?");
    println!("[1/5] Prover ready:");
    println!("  IMAGE_ID: {}", hex::encode(prover.program_digest()));
    println!("  {}", prover.config_status().replace('\n', "\n  "));

    // 2. Build test inputs (CL1: client validates outgoing transaction)
    println!();
    println!("[3/5] Building CL1 test inputs...");
    let inputs = PublicInputs {
        oods_attestation: None,
        mode: CoreLogicMode::CL1,
        transaction: Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: "test@example.com/abc12345".into(),
            receiver_address: None,
            amount: 100_000,
            reference: "first-zkp".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            kind: TxKind::Normal,
            core_id: [0u8; 32],
        },
        prev_receipts: vec![],
        current_state: Some(WalletState {
            public_key: vec![0u8; 32],
            balance: 1_000_000,
            wallet_seq: 0,
            state_id: [0u8; 32],
            auth_hash: None,
            wallet_id: None,
            group_members: None,
            hibernation_until: 0,
        }),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
        receiver_current_hibernation: None,
        my_validator_pk: None,
        overlapped_signatures: vec![],
        group_member_index: None,
        sender_fact_chain: None,
        receiver_fact_chain: None,
        my_dilithium_sk: None,
        my_dilithium_pk: None,
        my_validator_id: None,
        fact_witness_sigs: vec![],
        issuer_sphincs_sk: None,
        cl1_execution_proof: None,
        zkp_nonce: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            wallet_secret: None,
            fanout_message: None,
            candidate_balance: None,
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
            withdrawal_inputs: None,
            max_fact_links: None,
    
    };
    println!("  Mode: CL1 (Client Core Out)");
    println!("  Amount: {} atoms", inputs.transaction.amount);
    println!("  Balance: {} atoms", inputs.current_state.as_ref().unwrap().balance);

    // 3. Generate the proof
    println!();
    println!("[4/5] Generating STARK proof (this may take a while)...");
    let start = Instant::now();
    let (outputs, receipt) = prover.prove(inputs).expect("Proof generation failed");
    let elapsed = start.elapsed();

    println!("  Proof generated in {:.2?}", elapsed);
    println!("  Result: {:?}", outputs.result);
    println!("  Journal size: {} bytes", receipt.journal.len());
    println!("  Seal size: {} bytes", receipt.seal.len());
    println!("  Program digest: {}", hex::encode(receipt.program_digest));

    // 4. Verify the proof
    println!();
    println!("[5/5] Verifying proof...");
    let verifier = ZkvmVerifier::production()
        .expect("Verifier production mode failed");

    let start = Instant::now();
    let verified_outputs = verifier.verify(&receipt).expect("Proof verification FAILED");
    let verify_elapsed = start.elapsed();

    println!("  Verification: PASSED in {:.2?}", verify_elapsed);
    println!("  Verified result: {:?}", verified_outputs.result);

    println!();
    println!("========================================");
    println!("  AXIOM FIRST ZK PROOF: SUCCESS");
    println!("========================================");
    println!();
    println!("  Proof time:    {:.2?}", elapsed);
    println!("  Verify time:   {:.2?}", verify_elapsed);
    println!("  Journal:       {} bytes", receipt.journal.len());
    println!("  Seal:          {} bytes", receipt.seal.len());
    println!("  IMAGE_ID:      {}", hex::encode(receipt.program_digest));
}
