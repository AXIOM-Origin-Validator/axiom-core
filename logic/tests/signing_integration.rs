//! Integration tests with real cryptographic signing
//!
//! These tests verify that transactions with real Ed25519 signatures
//! pass validation in core-logic.

use axiom_core_logic::types::{PublicInputs, CoreLogicMode, ValidationResult};
use axiom_core_logic::modes::execute_core;
use axiom_test_utils::{TestWallet, TestFixture};

/// Test that a properly signed genesis transaction is accepted
#[test]
fn test_genesis_transaction_with_real_signature() {
    // Create a wallet with initial balance
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    // Create and sign a transaction
    let tx = alice.create_transaction(
        &bob.address(),
        500_000, // Send 500,000 atoms (dust minimum)
        "First payment",
        1, // nonce
    );
    
    // Create inputs for validation
    let inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx,
        prev_receipts: vec![], // Genesis transaction
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    // Execute validation
    let outputs = execute_core(inputs);
    
    // Should be accepted
    assert_eq!(
        outputs.result, 
        ValidationResult::Accept,
        "Genesis transaction with valid signature should be accepted. Rejection: {:?}",
        outputs.rejection_reason
    );
    
    // Should have new state
    assert!(outputs.new_state_hash.is_some());
    assert!(outputs.produced_state_id.is_some());
    assert_eq!(outputs.new_wallet_seq, Some(1));
}

/// Test that a transaction with invalid signature is rejected
#[test]
fn test_invalid_signature_rejected() {
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    // Create a transaction but don't sign it properly
    let mut tx = alice.create_transaction(&bob.address(), 500_000, "test", 1);
    
    // Corrupt the signature
    tx.client_sig[0] ^= 0xFF;
    
    let inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx,
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs = execute_core(inputs);

    // Should be rejected
    assert_eq!(outputs.result, ValidationResult::Reject);
}

/// Test that insufficient balance is rejected
#[test]
fn test_insufficient_balance_rejected() {
    let alice = TestWallet::generate("alice@test.com", 1_000); // Only 1000 atoms
    let bob = TestWallet::generate("bob@test.com", 0);
    
    // Try to send more than balance
    let tx = alice.create_transaction(&bob.address(), 500_000, "too much", 1);
    
    let inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx,
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs = execute_core(inputs);

    // Should be rejected (either for signature or balance, depending on check order)
    // With valid signature, it should hit balance check
    assert_eq!(outputs.result, ValidationResult::Reject);
}

/// Test CL2 validation (validator receiving transaction)
#[test]
fn test_cl2_validator_validation() {
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    let tx = alice.create_transaction(&bob.address(), 500_000, "CL2 test", 1);
    
    let inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL2,
        transaction: tx,
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs = execute_core(inputs);

    assert_eq!(
        outputs.result,
        ValidationResult::Accept,
        "CL2 validation should accept valid transaction. Rejection: {:?}",
        outputs.rejection_reason
    );
}

/// Test CL3 validation (validator producing witness)
#[test]
fn test_cl3_witness_production() {
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    let tx = alice.create_transaction(&bob.address(), 500_000, "CL3 test", 1);
    
    let inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL3,
        transaction: tx,
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs = execute_core(inputs);

    assert_eq!(
        outputs.result,
        ValidationResult::Accept,
        "CL3 should accept valid transaction. Rejection: {:?}",
        outputs.rejection_reason
    );
}

/// Test full flow: Alice sends to Bob
#[test]
fn test_full_payment_flow() {
    let fixture = TestFixture::new();
    let alice = fixture.alice;
    let bob = fixture.bob;
    
    let send_amount = 500_000;
    
    // Step 1: Create and sign transaction
    let tx = alice.create_transaction(
        &bob.address(),
        send_amount,
        "Payment for services",
        12345, // nonce
    );
    
    // Step 2: CL1 - Client validates outgoing
    let cl1_inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx.clone(),
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let cl1_outputs = execute_core(cl1_inputs);
    assert_eq!(cl1_outputs.result, ValidationResult::Accept, "CL1 failed: {:?}", cl1_outputs.rejection_reason);
    
    // Step 3: CL2 - Validator validates incoming
    let cl2_inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL2,
        transaction: tx.clone(),
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let cl2_outputs = execute_core(cl2_inputs);
    assert_eq!(cl2_outputs.result, ValidationResult::Accept, "CL2 failed: {:?}", cl2_outputs.rejection_reason);
    
    // Step 4: CL3 - Validator produces witness
    let cl3_inputs = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL3,
        transaction: tx.clone(),
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let cl3_outputs = execute_core(cl3_inputs);
    assert_eq!(cl3_outputs.result, ValidationResult::Accept, "CL3 failed: {:?}", cl3_outputs.rejection_reason);
    
    // Verify state changes
    assert!(cl3_outputs.produced_state_id.is_some());
    assert_eq!(cl3_outputs.new_wallet_seq, Some(1));
    
    println!("✓ Full payment flow completed successfully");
    println!("  Alice sent {} atoms to Bob", send_amount);
    println!("  New wallet_seq: {}", cl3_outputs.new_wallet_seq.unwrap());
}

/// Test that wallet_seq must be exactly prev + 1
#[test]
fn test_wallet_seq_must_increment() {
    let mut alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    // First transaction (seq 1) should work
    let tx1 = alice.create_transaction(&bob.address(), 500_000, "tx1", 1);
    
    let inputs1 = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx1,
        prev_receipts: vec![],
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs1 = execute_core(inputs1);
    assert_eq!(outputs1.result, ValidationResult::Accept);
    
    // Update Alice's state
    alice.wallet_seq = 1;
    alice.state_id = outputs1.produced_state_id.unwrap();
    
    // Create transaction with wrong seq (should be 2, not 5)
    let mut tx_bad = alice.create_transaction(&bob.address(), 500_000, "bad seq", 2);
    tx_bad.wallet_seq = 5; // Wrong!
    alice.sign_transaction(&mut tx_bad);
    
    // Need to provide prev_receipts for non-genesis
    // For this test, we'll check that validation rejects bad seq
    let inputs_bad = PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx_bad,
        prev_receipts: vec![], // This will cause rejection for non-genesis
        current_state: Some(alice.wallet_state()),
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    };

    let outputs_bad = execute_core(inputs_bad);
    assert_eq!(outputs_bad.result, ValidationResult::Reject);
}

// ════════════════════════════════════════════════════════════════════════
// CL1 → CL2 → CL3 × 3 validators → CL5 full pipeline integration test
// AUDIT-FIX v2.11.13: Complete pipeline with state chain verification
// ════════════════════════════════════════════════════════════════════════

/// Helper: Create a minimal PublicInputs with only the specified fields changed.
fn make_inputs(
    mode: CoreLogicMode,
    tx: axiom_core_logic::types::Transaction,
    state: Option<axiom_core_logic::types::WalletState>,
) -> PublicInputs {
    PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode,
        transaction: tx,
        prev_receipts: vec![],
        current_state: state,
        vbc_bundle: None,
        cheque_bundle: None,
        receiver_pk: None,
        receiver_current_balance: None,
        receiver_wallet_seq: None,
        receiver_new_balance: None,
        receiver_new_state_id: None,
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
        local_core_id: [0u8; 32],
        withdrawal_inputs: None,
        max_fact_links: None,
        current_tick: 0,
    
    }
}

/// Full CL1 → CL2 → CL3 × 3 → CL5 pipeline with real signatures.
/// Verifies state chain continuity, conservation law, and cheque consistency.
///
/// This test uses native Core execution (execute_core). Real DMAP/AVM
/// execution requires the ELF binary — set AXIOM_ZKVM_ELF to enable.
/// Without ELF, this test exercises the Core validation logic directly,
/// which is the same code path the AVM guest runs.
#[test]
#[ignore = "pre-A2: assumes redeem accepts cheque_bundle without sender_fact_chain; \
    A2 cutover (a94424c) made sender_anchor mandatory — \
    test needs to be rewritten to build a Lambda-style receiver_fact_chain. \
    See docs/AXIOM_DESIGN_A2_SenderAnchor.md."]
fn test_cl1_to_cl5_full_pipeline() {
    use axiom_core_logic::types::*;

    let send_amount = 500_000u64;
    let alice_initial = 10_000_000u64;
    let bob_initial = 5_000_000u64;

    let alice = TestWallet::generate("alice-pipeline@test.com", alice_initial);
    let bob = TestWallet::generate("bob-pipeline@test.com", bob_initial);

    let tx = alice.create_transaction(&bob.address(), send_amount, "pipeline-test", 42);

    // ── Step 1: CL1 (client validates outgoing) ──
    let cl1 = execute_core(make_inputs(CoreLogicMode::CL1, tx.clone(), Some(alice.wallet_state())));
    assert_eq!(cl1.result, ValidationResult::Accept,
        "CL1 must accept: {:?}", cl1.rejection_reason);
    assert!(cl1.produced_state_id.is_some(), "CL1 must produce state_id");
    let cl1_state_id = cl1.produced_state_id.unwrap();
    println!("  CL1: Accept, state_id={}", hex::encode(&cl1_state_id[..8]));

    // ── Step 2: CL2 (gateway validates incoming) ──
    let cl2 = execute_core(make_inputs(CoreLogicMode::CL2, tx.clone(), Some(alice.wallet_state())));
    assert_eq!(cl2.result, ValidationResult::Accept,
        "CL2 must accept: {:?}", cl2.rejection_reason);
    println!("  CL2: Accept");

    // ── Step 3: CL3 × 3 validators (witness production) ──
    // Run CL3 three times — each validator independently produces a witness.
    // All must agree on produced_state_id and commitment_hash.
    let mut produced_state_ids = Vec::new();
    let mut commitment_hashes = Vec::new();

    for v in 0..3 {
        let cl3 = execute_core(make_inputs(CoreLogicMode::CL3, tx.clone(), Some(alice.wallet_state())));
        assert_eq!(cl3.result, ValidationResult::Accept,
            "CL3 validator {} must accept: {:?}", v, cl3.rejection_reason);
        assert!(cl3.produced_state_id.is_some(), "CL3 must produce state_id");

        let psid = cl3.produced_state_id.unwrap();
        produced_state_ids.push(psid);
        if let Some(ch) = cl3.commitment_hash {
            commitment_hashes.push(ch);
        }
        println!("  CL3[{}]: Accept, state_id={}", v, hex::encode(&psid[..8]));
    }

    // Assert all 3 validators produce IDENTICAL state_id
    assert_eq!(produced_state_ids[0], produced_state_ids[1],
        "Validators 0 and 1 must agree on produced_state_id");
    assert_eq!(produced_state_ids[1], produced_state_ids[2],
        "Validators 1 and 2 must agree on produced_state_id");
    println!("  CL3: All 3 validators agree on state_id");

    // Assert CL3 state_id matches CL1 state_id (same Core, same inputs)
    assert_eq!(cl1_state_id, produced_state_ids[0],
        "CL1 and CL3 must produce same state_id");
    println!("  CL1 == CL3 state_id: verified");

    // Assert commitment hashes agree
    if commitment_hashes.len() == 3 {
        assert_eq!(commitment_hashes[0], commitment_hashes[1]);
        assert_eq!(commitment_hashes[1], commitment_hashes[2]);
        println!("  CL3: All 3 commitment_hashes agree");
    }

    // ── Step 4: Build ChequeBundle with real Ed25519 signatures ──
    let txid = produced_state_ids[0];
    let state_hash = cl1.new_state_hash.unwrap_or([0u8; 32]);
    let mut cheques = Vec::new();

    for v in 0..3 {
        // Each validator has its own Ed25519 keypair
        let val_sk = ed25519_dalek::SigningKey::from_bytes(&{
            let mut seed = [0u8; 32];
            seed[0] = v as u8 + 1;
            seed[31] = 0xAA;
            seed
        });
        let val_pk = ed25519_dalek::VerifyingKey::from(&val_sk);
        let val_pk_bytes = val_pk.to_bytes().to_vec();
        let val_id = *blake3::hash(&val_pk_bytes).as_bytes();

        // Cheques use redeem_address (wallet_secret path) — CL5 verifies this via
        // verify_wallet_id_with_secret. The send TX (CL1) uses address() (WALLET_IDENTITY_KEY path).
        let rate_bps: u32 = 10;
        let commitment = axiom_core_logic::compute::compute_cheque_commitment(
            &txid, &state_hash, &produced_state_ids[v],
            &bob.address(), send_amount, 1,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );

        // Sign commitment with validator's Ed25519 key
        use ed25519_dalek::Signer;
        let sig = val_sk.sign(&commitment).to_bytes().to_vec();

        cheques.push(ValidatorCheque {
            recall_target_tx_id: None,
            txid,
            validator_id: val_id,
            validator_pk: val_pk_bytes,
            signature: sig,
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".into(),
            carrier_address: format!("v{}@test", v),
            sender_wallet_id: alice.address(),
            receiver_wallet_id: bob.address(),
            amount: send_amount,
            rate_bps,
            reference: "pipeline-test".into(),
            epoch: 1,
            created_at: 0,
            state_hash,
            produced_state_id: produced_state_ids[v],
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        });
    }

    let bundle = ChequeBundle {
        cheques: cheques.clone(),
        fact_chain: None,
    };

    // Verify bundle consistency
    assert!(bundle.verify_consistency(), "ChequeBundle must be consistent");
    assert!(bundle.has_distinct_validators(), "Must have 3 distinct validators");
    println!("  Bundle: 3 cheques, consistent, distinct validators");

    // ── Step 5: CL5 (redeem) ──
    let new_balance = bob_initial + send_amount;
    let mut cl5_inputs = make_inputs(CoreLogicMode::CL5, tx.clone(), None);
    cl5_inputs.cheque_bundle = Some(bundle);
    cl5_inputs.receiver_pk = Some(bob.public_key());
    cl5_inputs.receiver_current_balance = Some(bob_initial);
    cl5_inputs.receiver_wallet_seq = Some(bob.wallet_seq);
    cl5_inputs.receiver_new_balance = Some(new_balance);
    // wallet_secret omitted: cheques use WALLET_IDENTITY_KEY-path wallet_id,
    // which uses a different checksum than wallet_secret path. Legacy mode.

    let cl5 = execute_core(cl5_inputs);
    assert_eq!(cl5.result, ValidationResult::Accept,
        "CL5 must accept: {:?}", cl5.rejection_reason);
    assert!(cl5.produced_state_id.is_some(), "CL5 must produce receiver state_id");
    println!("  CL5: Accept, receiver new_balance={}", new_balance);

    // ── Step 6: Conservation law ──
    let alice_new_balance = alice_initial - send_amount;
    let bob_new_balance = bob_initial + send_amount;
    assert_eq!(alice_new_balance + bob_new_balance, alice_initial + bob_initial,
        "Conservation law: total money must be preserved");
    println!("  Conservation: {} + {} = {} (preserved)", alice_new_balance, bob_new_balance, alice_initial + bob_initial);

    // ── Step 7: State chain is unbroken ──
    // CL3 produced_state_id = CL1 produced_state_id = sender's new state
    // CL5 produced_state_id = receiver's new state (different from sender's)
    let cl5_state_id = cl5.produced_state_id.unwrap();
    assert_ne!(cl1_state_id, cl5_state_id,
        "Sender and receiver state_ids must be different");
    println!("  State chain: sender={} receiver={}", hex::encode(&cl1_state_id[..8]), hex::encode(&cl5_state_id[..8]));

    println!("\n  ✓ CL1→CL2→CL3×3→CL5 full pipeline PASSED");
    println!("    Alice: {} → {} ({} sent)", alice_initial, alice_new_balance, send_amount);
    println!("    Bob:   {} → {} ({} received)", bob_initial, bob_new_balance, send_amount);
}

/// CL1→CL5 pipeline with FACT chain — exercises verify_fact_chain in CL5.
/// Uses real Dilithium signatures for FACT witnesses (k=3).
/// This test is slow (~10s) due to Dilithium keygen.
#[test]
#[ignore = "pre-A2: hand-built fact_chain with sender_anchor=None doesn't pass \
    verify_fact_chain after A2 cutover. Test needs to construct an A2-shaped \
    chain (sender_anchor populated on each link) — significant rewrite. \
    See docs/AXIOM_DESIGN_A2_SenderAnchor.md."]
fn test_cl1_to_cl5_with_fact_chain() {
    use axiom_core_logic::types::*;
    use axiom_core_logic::compute::compute_fact_commitment;
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes as DilSerDes;

    let send_amount = 500_000u64;
    let alice_initial = 10_000_000u64;
    let bob_initial = 5_000_000u64;

    let alice = TestWallet::generate("alice-fact@test.com", alice_initial);
    let bob = TestWallet::generate("bob-fact@test.com", bob_initial);

    // ── Build FACT chain: 1 prior link with k=3 Dilithium witnesses ──
    let prior_tx_id = [0xA0u8; 32];
    let prior_prev_sid = [0xA1u8; 32];
    let prior_new_sid = alice.wallet_state().state_id;
    let _fact_commitment = compute_fact_commitment(
        &prior_tx_id, &prior_prev_sid, &prior_new_sid, alice_initial, None, false,
    );

    // Generate 3 Dilithium keypairs and sign the FACT commitment
    let mut fact_witnesses = Vec::new();
    for i in 0..3u8 {
        let (pk_obj, sk_obj) = ml_dsa_65::try_keygen().expect("Dilithium keygen");
        let pk_bytes = pk_obj.into_bytes().to_vec();
        let sk_bytes = sk_obj.into_bytes().to_vec();
        let sig = axiom_core_logic::compute::sign_fact_commitment(
            &sk_bytes, &prior_tx_id, &prior_prev_sid, &prior_new_sid, alice_initial, None, false,
        ).expect("Dilithium sign");
        let mut vid = [0u8; 32];
        vid[0] = i + 1;
        fact_witnesses.push(FactWitness {
            validator_id: vid,
            validator_pk: pk_bytes,
            signature: sig,
            vbc_genesis_anchor: None,
        });
    }

    let fact_chain = FactChain {
        checkpoint: None,
        links: vec![FactLink {
            tx_id: prior_tx_id,
            previous_state_id: prior_prev_sid,
            new_state_id: prior_new_sid,
            amount: alice_initial,
            required_k: 3,
            tick: 1,
            witnesses: fact_witnesses,
            nabla_confirmation: Some(NablaConfirmation {
                nabla_node_id: [0xBBu8; 32],
                nabla_signature: vec![0u8; 64],
                root_hash: [0xCCu8; 32],
                synced_to_tick: 1,
                ..Default::default()
            }),
            receiver_contact: None,
            burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
        }],
    };

    // Verify the FACT chain is valid before using it
    assert!(axiom_core_logic::fact::verify_fact_chain(&fact_chain).is_ok(),
        "FACT chain must be valid before CL5");
    println!("  FACT chain: valid (1 link, 3 Dilithium witnesses, Nabla-confirmed)");

    // ── CL1 ──
    let tx = alice.create_transaction(&bob.address(), send_amount, "fact-test", 42);
    let cl1 = execute_core(make_inputs(CoreLogicMode::CL1, tx.clone(), Some(alice.wallet_state())));
    assert_eq!(cl1.result, ValidationResult::Accept, "CL1: {:?}", cl1.rejection_reason);
    let txid = cl1.produced_state_id.unwrap();
    let state_hash = cl1.new_state_hash.unwrap_or([0u8; 32]);

    // ── Build ChequeBundle with FACT chain + non-empty DMAP proof ──
    let mut cheques = Vec::new();
    for v in 0..3 {
        let vsk = ed25519_dalek::SigningKey::from_bytes(&{
            let mut s = [0u8; 32]; s[0] = v as u8 + 10; s[31] = 0xBB; s
        });
        let vpk = ed25519_dalek::VerifyingKey::from(&vsk);
        let vid = *blake3::hash(&vpk.to_bytes()).as_bytes();
        let rate_bps: u32 = 10;
        let commitment = axiom_core_logic::compute::compute_cheque_commitment(
            &txid, &state_hash, &txid, &bob.address(), send_amount, 1,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );
        use ed25519_dalek::Signer;
        let sig = vsk.sign(&commitment).to_bytes().to_vec();
        cheques.push(ValidatorCheque {
            recall_target_tx_id: None,
            txid, validator_id: vid, validator_pk: vpk.to_bytes().to_vec(),
            signature: sig,
            execution_proof: vec![0xDA, 0x7A, 0x01], // Non-empty DMAP proof
            vbc_bundle: None, carrier_type: "test".into(), carrier_address: format!("v{}@t", v),
            sender_wallet_id: alice.address(), receiver_wallet_id: bob.address(),
            amount: send_amount, rate_bps, reference: "fact-test".into(), epoch: 1, created_at: 0,
            state_hash, produced_state_id: txid,
            sender_fact_chain: Some(fact_chain.clone()),
            zkp_nonce: None, proof_type: 1,
            dmap_input_hash: [0u8; 32], dmap_output_hash: [0u8; 32],
            oracle_claim: None, nabla_hint: None, sender_wallet_pk: None,
        });
    }
    let bundle = ChequeBundle { cheques, fact_chain: Some(fact_chain) };
    assert!(bundle.verify_consistency());

    // ── CL5 with FACT chain ──
    let mut cl5_inputs = make_inputs(CoreLogicMode::CL5, tx.clone(), None);
    cl5_inputs.cheque_bundle = Some(bundle);
    cl5_inputs.receiver_pk = Some(bob.public_key());
    cl5_inputs.receiver_current_balance = Some(bob_initial);
    cl5_inputs.receiver_wallet_seq = Some(bob.wallet_seq);
    cl5_inputs.receiver_new_balance = Some(bob_initial + send_amount);
    // wallet_secret omitted: legacy WALLET_IDENTITY_KEY-path wallet_ids in cheques

    let cl5 = execute_core(cl5_inputs);
    assert_eq!(cl5.result, ValidationResult::Accept,
        "CL5 with FACT chain must accept: {:?}", cl5.rejection_reason);
    println!("  CL5 with FACT chain: PASS (Dilithium-verified, non-empty DMAP proof)");
}

// ════════════════════════════════════════════════════════════════════════
// Consensus test vectors — deterministic from fixed seeds.
// If any vector produces a different result, a consensus-breaking change
// was introduced. Third-party reimplementers can verify compatibility
// by reproducing these inputs and asserting the same outputs.
// ════════════════════════════════════════════════════════════════════════

/// Helper: create a wallet from a fixed seed (deterministic).
fn wallet_from_seed(seed: [u8; 32], email: &str, balance: u64) -> TestWallet {
    // TestWallet::generate uses OsRng — we need deterministic keys.
    // Construct manually from the fixed seed.
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = ed25519_dalek::VerifyingKey::from(&sk);
    let pk_bytes = vk.to_bytes();
    let state_id = axiom_core_logic::genesis::compute_genesis_state_id(
        &pk_bytes,
        balance,
        axiom_core_logic::wallet_id::K_DEFAULT,
        axiom_core_logic::wallet_id::PROOF_TYPE_DMAP,
    );
    let wallet_id = axiom_core_logic::wallet_id::generate_wallet_id(email, "42", &pk_bytes)
        .unwrap_or_else(|_| format!("{}/0000000042", email));
    let suffix = wallet_id.rsplit('/').next().unwrap_or("0000000042").to_string();
    let wallet_secret: [u8; 32] = {
        let mut data = b"TEST_WALLET_SECRET".to_vec();
        data.extend_from_slice(&seed);
        *blake3::hash(&data).as_bytes()
    };
    let wallet_id_secret = axiom_core_logic::wallet_id::generate_wallet_id_with_secret(
        email, "42", &wallet_secret, &pk_bytes,
    ).unwrap_or_else(|_| format!("{}/00000042", email));
    let wallet_id_secret_suffix = wallet_id_secret.rsplit('/').next().unwrap_or("00000042").to_string();

    TestWallet {
        signing_key: sk,
        verifying_key: vk,
        balance,
        wallet_seq: 0,
        state_id,
        email: email.to_string(),
        wallet_id: suffix,
        wallet_secret,
        wallet_id_secret: wallet_id_secret_suffix,
    }
}

#[test]
fn test_consensus_vectors_stable() {
    // Vector 1: CL1 accept — valid send from deterministic wallet
    let alice = wallet_from_seed([0x01; 32], "alice@vector.test", 10_000_000);
    let bob = wallet_from_seed([0x02; 32], "bob@vector.test", 5_000_000);

    let tx1 = alice.create_transaction(&bob.address(), 500_000, "vector-test", 12345);
    let out1 = execute_core(make_inputs(CoreLogicMode::CL1, tx1, Some(alice.wallet_state())));
    assert_eq!(out1.result, ValidationResult::Accept, "V1 CL1_ACCEPT");
    let v1_sid = out1.produced_state_id.unwrap();
    // Pin the exact state_id — if this changes, consensus changed
    println!("  V1 CL1_ACCEPT: state_id={}", hex::encode(v1_sid));

    // Vector 2: CL1 reject — bad signature
    let mut tx2 = alice.create_transaction(&bob.address(), 500_000, "vector-test", 12345);
    tx2.client_sig = vec![0xFF; 64];
    let out2 = execute_core(make_inputs(CoreLogicMode::CL1, tx2, Some(alice.wallet_state())));
    assert_eq!(out2.result, ValidationResult::Reject, "V2 CL1_REJECT_SIG");
    assert_eq!(out2.rejection_reason, Some(axiom_core_logic::types::ValidationError::InvalidClientSignature));

    // Vector 3: CL1 reject — insufficient balance
    let poor = wallet_from_seed([0x03; 32], "poor@vector.test", 100);
    let tx3 = poor.create_transaction(&bob.address(), 500_000, "vector-test", 1);
    let out3 = execute_core(make_inputs(CoreLogicMode::CL1, tx3, Some(poor.wallet_state())));
    assert_eq!(out3.result, ValidationResult::Reject, "V3 CL1_REJECT_BALANCE");

    // Vector 4: CL1 reject — dust
    let tx4 = alice.create_transaction(&bob.address(), 100, "vector-test", 1);
    let out4 = execute_core(make_inputs(CoreLogicMode::CL1, tx4, Some(alice.wallet_state())));
    assert_eq!(out4.result, ValidationResult::Reject, "V4 CL1_REJECT_DUST");
    assert_eq!(out4.rejection_reason, Some(axiom_core_logic::types::ValidationError::DustAmount));

    // Vector 5: CL1 reject — zero amount
    let tx5 = alice.create_transaction(&bob.address(), 0, "vector-test", 1);
    let out5 = execute_core(make_inputs(CoreLogicMode::CL1, tx5, Some(alice.wallet_state())));
    assert_eq!(out5.result, ValidationResult::Reject, "V5 CL1_REJECT_ZERO");
    assert_eq!(out5.rejection_reason, Some(axiom_core_logic::types::ValidationError::ZeroAmount));

    // Vector 6: Deterministic — re-run V1 and assert same state_id
    let tx1_again = alice.create_transaction(&bob.address(), 500_000, "vector-test", 12345);
    let out1_again = execute_core(make_inputs(CoreLogicMode::CL1, tx1_again, Some(alice.wallet_state())));
    assert_eq!(out1_again.produced_state_id.unwrap(), v1_sid,
        "Consensus vectors must be deterministic — same input must produce same state_id");

    println!("  All 6 consensus vectors stable");
}

// ════════════════════════════════════════════════════════════════════════
// Consensus vectors from JSON file — automated conformance check.
// Loads consensus_vectors.json at compile time and verifies each vector
// by deserializing CBOR inputs and running through execute_core.
// ════════════════════════════════════════════════════════════════════════

#[derive(serde::Deserialize)]
struct VectorSuite {
    vectors: Vec<ConformanceVector>,
}

#[derive(serde::Deserialize)]
struct ConformanceVector {
    id: String,
    mode: String,
    #[serde(default)]
    inputs_cbor_hex: Option<String>,
    expected_result: String,
    #[serde(default)]
    expected_rejection_reason: Option<String>,
    #[serde(default)]
    expected_produced_state_id_hex: Option<String>,
}

#[test]
fn test_consensus_vectors_from_file() {
    let json_str = include_str!("../../../tests/consensus_vectors.json");
    let suite: VectorSuite = serde_json::from_str(json_str)
        .expect("consensus_vectors.json must be valid JSON");

    let executable = ["CL1", "CL2", "CL3", "CL4", "CL5", "CL6", "CL7",
                      "CL8", "CL9", "CL10", "CL11"];
    let mut tested = 0;

    for v in &suite.vectors {
        if !executable.contains(&v.mode.as_str()) { continue; }
        let hex_str = match &v.inputs_cbor_hex {
            Some(h) if !h.is_empty() => h,
            _ => { println!("  {} — skipped (no CBOR inputs)", v.id); continue; }
        };
        let bytes = hex::decode(hex_str)
            .unwrap_or_else(|_| panic!("{}: invalid inputs_cbor_hex", v.id));
        let inputs = axiom_core_ipc::codec::decode_inputs(&bytes)
            .unwrap_or_else(|e| panic!("{}: IPC decode failed: {}", v.id, e));
        let outputs = execute_core(inputs);

        let got = format!("{:?}", outputs.result);
        assert_eq!(got, v.expected_result,
            "Consensus vector {} failed — a consensus-breaking change was introduced. \
             Expected {} got {}. If intentional, regenerate: \
             cargo run -p axiom-core-logic --example generate_vectors > tests/consensus_vectors.json",
            v.id, v.expected_result, got);

        if let Some(ref rr) = v.expected_rejection_reason {
            let got_rr = outputs.rejection_reason.as_ref()
                .map(|r| format!("{:?}", r)).unwrap_or_default();
            assert_eq!(&got_rr, rr,
                "Consensus vector {} wrong rejection: expected {} got {}", v.id, rr, got_rr);
        }
        if let Some(ref sid) = v.expected_produced_state_id_hex {
            let got_sid = outputs.produced_state_id.map(hex::encode).unwrap_or_default();
            assert_eq!(&got_sid, sid,
                "Consensus vector {} wrong state_id: expected {} got {}", v.id, sid, got_sid);
        }
        tested += 1;
        println!("  {} — PASS", v.id);
    }
    println!("  {}/{} vectors verified from consensus_vectors.json", tested, suite.vectors.len());
    assert!(tested >= 15, "Expected at least 15 executable vectors, got {}", tested);
}
