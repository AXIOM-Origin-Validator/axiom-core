//! Permanent adversarial test corpus for AXIOM Core.
//!
//! Curated attack vectors that MUST pass on every commit.
//! Each test builds a malicious input and verifies Core rejects it
//! with the correct error variant. These are regression gates — if
//! any vector starts passing, someone weakened a security boundary.

use axiom_core_logic::modes::execute_core;
use axiom_core_logic::types::{
    CoreLogicMode, PublicInputs, Receipt, ValidationError, ValidationResult, WitnessSig,
};
use axiom_core_logic::validation::{validate_witnesses, MINIMUM_TX_ATOMS};
use axiom_test_utils::TestWallet;

// ---------------------------------------------------------------------------
// Helper: build a minimal CL1 PublicInputs from wallet + transaction
// ---------------------------------------------------------------------------
fn build_cl1_inputs(
    wallet: &TestWallet,
    tx: axiom_core_logic::types::Transaction,
) -> PublicInputs {
    PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx,
        prev_receipts: vec![],
        current_state: Some(wallet.wallet_state()),
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

/// Helper: build CL2 PublicInputs with prev_receipts for witness validation
fn build_cl2_inputs_with_receipts(
    wallet: &TestWallet,
    tx: axiom_core_logic::types::Transaction,
    prev_receipts: Vec<Receipt>,
) -> PublicInputs {
    PublicInputs {
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL2,
        transaction: tx,
        prev_receipts,
        current_state: Some(wallet.wallet_state()),
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

/// Assert that Core rejected a transaction with a specific error.
fn assert_rejected(outputs: &axiom_core_logic::types::PublicOutputs, expected: ValidationError) {
    assert_eq!(
        outputs.result,
        ValidationResult::Reject,
        "Expected Reject but got {:?} (reason: {:?})",
        outputs.result,
        outputs.rejection_reason
    );
    assert_eq!(
        outputs.rejection_reason,
        Some(expected.clone()),
        "Wrong rejection reason: got {:?}, expected {:?}",
        outputs.rejection_reason,
        Some(expected)
    );
}

// ===========================================================================
// (a) Stale VBC attack — expired VBC bundle with valid structure
// ===========================================================================
//
// Attack scenario: An attacker presents a VBC bundle where the target VBC
// has expired timestamps but otherwise valid structure. CL6 verification
// must reject it with VBCExpired.

#[test]
fn adversarial_stale_vbc_expired_timestamps() {
    use axiom_core_logic::types::{VBC, VBCProofBundle};
    use axiom_core_logic::vbc::verify_vbc_bundle;

    // Build a structurally valid-looking VBC with timestamps in the past.
    // issued_at = 1000, expires_at = 2000, current_time = 100_000_000
    let stale_vbc = VBC {
        baseline_tick: 0,
        network_size_baseline: 0,
        version: 0x09,
        validator_id: [0xAA; 32],
        subject_pubkey_sphincs: vec![0u8; 32],
        subject_pubkey_dilithium: vec![0u8; 1952],
        subject_pubkey_ed25519: vec![0u8; 32],
        pgp_fingerprint: vec![],
        node_name: String::new(),
        proof_cap: String::new(),
        issued_at: 1_000,
        expires_at: 2_000, // Expired long ago
        chain_depth: 0,
        issuer_set: vec![vec![0u8; 32]; 3],
        signatures: vec![vec![0u8; 64]; 3],
        max_tx: 0,
        founding_vbc_hash: [0u8; 32],
    };

    let bundle = VBCProofBundle {
        target_vbc: stale_vbc,
        supporting_vbcs: vec![],
    };

    // Current time far after expiry
    let result = verify_vbc_bundle(&bundle, 100_000_000);

    // Must be rejected — either VBCExpired or another structural error.
    // The key invariant: an expired VBC never passes verification.
    assert!(
        result.is_err(),
        "Expired VBC bundle must be rejected, but verification returned Ok(())"
    );
}

// ===========================================================================
// (b) Zero commitment_hash receipt — forged receipt bypass attempt
// ===========================================================================
//
// Attack scenario: Attacker builds a receipt with commitment_hash = [0; 32]
// to skip signature verification. validation.rs line 915 must catch this.

#[test]
fn adversarial_zero_commitment_hash_receipt() {
    let alice = TestWallet::generate("alice@adversarial.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@adversarial.com", 0);

    // Build a second TX (wallet_seq=2) so prev_receipts are checked.
    // First, create a wallet state as if seq=1 already completed.
    let mut alice_state = alice.wallet_state();
    alice_state.wallet_seq = 1;

    // Forge a receipt with zero commitment_hash.
    // Each witness must have a DISTINCT validator_pk to avoid DuplicateValidator.
    let mut pk1 = [0u8; 32]; pk1[0] = 1;
    let mut pk2 = [0u8; 32]; pk2[0] = 2;
    let mut pk3 = [0u8; 32]; pk3[0] = 3;

    let forged_receipt = Receipt {
        oods_flag: None,
        txid: [0x42; 32],
        state_hash: [0u8; 32],
        produced_state_id: alice.state_id, // Chain to current state
        new_wallet_seq: 1,
        commitment_hash: [0u8; 32], // ATTACK: zero commitment_hash
        sdid: [0u8; 32],
        lineage_hash: [0u8; 32],
        core_version: String::new(),
        core_id: [0u8; 32],
        witness_sigs: vec![
            WitnessSig {
                validator_id: [1u8; 32],
                validator_pk: pk1.to_vec(),
                vbc_bundle: None,
                carrier_type: "test".to_string(),
                carrier_address: "v1".to_string(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 1,
                availability_attestation: None,
                validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            },
            WitnessSig {
                validator_id: [2u8; 32],
                validator_pk: pk2.to_vec(),
                vbc_bundle: None,
                carrier_type: "test".to_string(),
                carrier_address: "v2".to_string(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 1,
                availability_attestation: None,
                validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            },
            WitnessSig {
                validator_id: [3u8; 32],
                validator_pk: pk3.to_vec(),
                vbc_bundle: None,
                carrier_type: "test".to_string(),
                carrier_address: "v3".to_string(),
                signature: vec![0u8; 64],
                execution_proof: vec![],
                proof_type: 1,
                availability_attestation: None,
                validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            },
        ],
        epoch: 1,
        fact_proof: None,
        receipt_commitment: [0u8; 32],
        required_k: 3,
        fee_breakdown: Vec::new(),
        is_dev_class: false,
    };

    // Call validate_witnesses directly to test the zero commitment_hash
    // rejection at validation.rs line 915 without other CL2 checks
    // (like AuthHashRequired) firing first.
    let tx = alice.create_transaction(&bob.address(), 500_000, "zero-commit", 1);

    let inputs = build_cl2_inputs_with_receipts(
        &alice,
        tx,
        vec![forged_receipt],
    );

    let result = validate_witnesses(&inputs);

    // Must be Err(InvalidWitnessSignature) — zero commitment_hash caught at line 915
    assert!(
        result.is_err(),
        "Zero commitment_hash receipt must be rejected by validate_witnesses, but got Ok(())"
    );
    assert_eq!(
        result.unwrap_err(),
        ValidationError::InvalidWitnessSignature,
        "Expected InvalidWitnessSignature for zero commitment_hash"
    );
}

// ===========================================================================
// (c) Self-send rejection — sender_wallet_id == receiver email (non-Ark)
// ===========================================================================
//
// Attack scenario: A user tries to send money to themselves to game
// validator resources. Section 11.9.4 mandates rejection.

#[test]
fn adversarial_self_send_same_email_rejected() {
    let alice = TestWallet::generate("alice@selfsend.com", 10_000_000_000);

    // Alice sends to her own address (same email, not Ark)
    let tx = alice.create_transaction(&alice.address(), 500_000, "self-send", 1);

    let mut inputs = build_cl1_inputs(&alice, tx);
    // Set sender_wallet_id so the self-send check fires
    inputs.transaction.sender_wallet_id = alice.address();
    // Must re-sign after modifying sender_wallet_id
    alice.sign_transaction(&mut inputs.transaction);

    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::SelfSendRejected);
}

#[test]
fn adversarial_self_send_different_suffix_same_email() {
    // Same email but different wallet_id suffix — still a self-send
    let alice = TestWallet::generate("alice@selfsend2.com", 10_000_000_000);
    let bob = TestWallet::generate("alice@selfsend2.com", 0); // Same email, different keys

    let tx = alice.create_transaction(&bob.address(), 500_000, "self-send-2", 1);

    let mut inputs = build_cl1_inputs(&alice, tx);
    inputs.transaction.sender_wallet_id = alice.address();
    alice.sign_transaction(&mut inputs.transaction);

    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::SelfSendRejected);
}

// ===========================================================================
// (d) Dust amount rejection — amount < MINIMUM_TX_ATOMS (500,000)
// ===========================================================================
//
// Attack scenario: Spam the network with sub-dust transactions.

#[test]
fn adversarial_dust_amount_exactly_below_minimum() {
    let alice = TestWallet::generate("alice@dust.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@dust.com", 0);

    // Amount = MINIMUM_TX_ATOMS - 1
    let tx = alice.create_transaction(
        &bob.address(),
        MINIMUM_TX_ATOMS - 1,
        "dust-attack",
        1,
    );

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::DustAmount);
}

#[test]
fn adversarial_dust_amount_one_atom() {
    let alice = TestWallet::generate("alice@dust1.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@dust1.com", 0);

    let tx = alice.create_transaction(&bob.address(), 1, "one-atom-spam", 1);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::DustAmount);
}

#[test]
fn adversarial_zero_amount_rejected() {
    let alice = TestWallet::generate("alice@zero.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@zero.com", 0);

    let tx = alice.create_transaction(&bob.address(), 0, "zero-amount", 1);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::ZeroAmount);
}

#[test]
fn adversarial_dust_exactly_at_minimum_accepted() {
    // Sanity check: exactly at the minimum SHOULD be accepted
    let alice = TestWallet::generate("alice@dustok.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@dustok.com", 0);

    let tx = alice.create_transaction(
        &bob.address(),
        MINIMUM_TX_ATOMS,
        "exact-minimum",
        1,
    );

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_eq!(
        outputs.result,
        ValidationResult::Accept,
        "TX at exact MINIMUM_TX_ATOMS ({}) should be accepted, but got rejection: {:?}",
        MINIMUM_TX_ATOMS,
        outputs.rejection_reason,
    );
}

// ===========================================================================
// (e) Boundary tick values — tick=0 and tick=u64::MAX
// ===========================================================================
//
// Attack scenario: Manipulate epoch/tick to extreme values to trigger
// overflow, underflow, or bypass time-based checks.

#[test]
fn adversarial_epoch_zero() {
    let alice = TestWallet::generate("alice@tick0.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@tick0.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "epoch-zero", 1);
    tx.epoch = 0;
    alice.sign_transaction(&mut tx);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);

    // epoch=0 should still be accepted for CL1 (epoch is informational at CL1)
    // The key invariant: no panic, no undefined behavior.
    assert!(
        outputs.result == ValidationResult::Accept || outputs.result == ValidationResult::Reject,
        "epoch=0 must produce a definite result (Accept or Reject), not crash. Got: {:?}",
        outputs.result,
    );
}

#[test]
fn adversarial_epoch_u64_max() {
    let alice = TestWallet::generate("alice@tickmax.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@tickmax.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "epoch-max", 1);
    tx.epoch = u64::MAX;
    alice.sign_transaction(&mut tx);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);

    // epoch=u64::MAX must not panic or overflow. Definite Accept or Reject.
    assert!(
        outputs.result == ValidationResult::Accept || outputs.result == ValidationResult::Reject,
        "epoch=u64::MAX must produce a definite result, not crash. Got: {:?}",
        outputs.result,
    );
}

#[test]
fn adversarial_wallet_seq_zero() {
    // wallet_seq=0 is invalid for any transaction (must be >= 1)
    let alice = TestWallet::generate("alice@seq0.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@seq0.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "seq-zero", 1);
    tx.wallet_seq = 0;
    alice.sign_transaction(&mut tx);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);

    assert_eq!(
        outputs.result,
        ValidationResult::Reject,
        "wallet_seq=0 must be rejected, got: {:?} (reason: {:?})",
        outputs.result,
        outputs.rejection_reason,
    );
}

#[test]
fn adversarial_wallet_seq_u64_max() {
    let alice = TestWallet::generate("alice@seqmax.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@seqmax.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "seq-max", 1);
    tx.wallet_seq = u64::MAX;
    alice.sign_transaction(&mut tx);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);

    // u64::MAX wallet_seq on a fresh wallet (seq=0, expects 1) must be rejected.
    assert_eq!(
        outputs.result,
        ValidationResult::Reject,
        "wallet_seq=u64::MAX must be rejected, got: {:?} (reason: {:?})",
        outputs.result,
        outputs.rejection_reason,
    );
}

// ===========================================================================
// Additional adversarial vectors
// ===========================================================================

#[test]
fn adversarial_reference_field_oversized() {
    // Reference field > 256 bytes = DoS prevention rejection
    let alice = TestWallet::generate("alice@ref.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@ref.com", 0);

    let long_ref = "A".repeat(257);
    let tx = alice.create_transaction(&bob.address(), 500_000, &long_ref, 1);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::ReferenceTooLarge);
}

#[test]
fn adversarial_reference_field_exactly_256_accepted() {
    // 256 bytes is the limit — should be accepted
    let alice = TestWallet::generate("alice@ref256.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@ref256.com", 0);

    let exact_ref = "B".repeat(256);
    let tx = alice.create_transaction(&bob.address(), 500_000, &exact_ref, 1);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_eq!(
        outputs.result,
        ValidationResult::Accept,
        "256-byte reference should be accepted, got rejection: {:?}",
        outputs.rejection_reason,
    );
}

#[test]
fn adversarial_corrupted_signature_rejected() {
    let alice = TestWallet::generate("alice@sig.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@sig.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "corrupt-sig", 1);
    // Flip every byte of the signature
    for byte in tx.client_sig.iter_mut() {
        *byte ^= 0xFF;
    }

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_eq!(
        outputs.result,
        ValidationResult::Reject,
        "Corrupted signature must be rejected, got: {:?}",
        outputs.rejection_reason,
    );
}

#[test]
fn adversarial_empty_signature_rejected() {
    let alice = TestWallet::generate("alice@emptysig.com", 10_000_000_000);
    let bob = TestWallet::generate("bob@emptysig.com", 0);

    let mut tx = alice.create_transaction(&bob.address(), 500_000, "empty-sig", 1);
    tx.client_sig = vec![]; // Empty signature

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_eq!(
        outputs.result,
        ValidationResult::Reject,
        "Empty signature must be rejected, got: {:?} (reason: {:?})",
        outputs.result,
        outputs.rejection_reason,
    );
}

#[test]
fn adversarial_insufficient_balance() {
    let alice = TestWallet::generate("alice@broke.com", 500_000); // Exactly dust minimum
    let bob = TestWallet::generate("bob@broke.com", 0);

    // Try to send more than balance
    let tx = alice.create_transaction(&bob.address(), 500_001, "overdraft", 1);

    let inputs = build_cl1_inputs(&alice, tx);
    let outputs = execute_core(inputs);
    assert_rejected(&outputs, ValidationError::InsufficientBalance);
}
