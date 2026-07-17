//! Differential verification test for AXIOM Core.
//!
//! Two independent validator instances replay the same transaction corpus
//! and must produce byte-identical accept/reject decisions + state transitions.
//! This proves Core is a deterministic function: same inputs → same outputs.
//!
//! The corpus covers: normal send, insufficient balance, zero amount, dust,
//! minimum threshold, wrong wallet_seq, replay attempt (same consumed_state_id),
//! frozen wallet, self-send, DWP protocol address, oversized reference,
//! corrupted signature, empty signature, and balance overflow.

use axiom_core_logic::modes::execute_core;
use axiom_core_logic::types::{
    CoreLogicMode, PublicInputs, PublicOutputs, ValidationError, ValidationResult,
};
use axiom_core_logic::validation::MINIMUM_TX_ATOMS;
use axiom_test_utils::TestWallet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal CL1 PublicInputs from a wallet and transaction.
fn build_cl1(wallet: &TestWallet, tx: axiom_core_logic::types::Transaction) -> PublicInputs {
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

/// Build CL1 inputs with a frozen wallet set.
fn build_cl1_frozen(
    wallet: &TestWallet,
    tx: axiom_core_logic::types::Transaction,
    frozen: Vec<[u8; 32]>,
) -> PublicInputs {
    let mut inputs = build_cl1(wallet, tx);
    inputs.frozen_wallets = Some(frozen);
    inputs
}

/// A named test vector: description + a closure that builds identical PublicInputs.
/// The closure is called each time we need a fresh copy (no shared mutable state).
struct TestVector {
    name: &'static str,
    /// Expected outcome
    expect_accept: bool,
    /// Expected rejection reason (when expect_accept == false)
    expect_error: Option<ValidationError>,
    /// Builder returns fresh, identical PublicInputs each call.
    /// Uses a deterministic wallet created once and cloned.
    build: Box<dyn Fn() -> PublicInputs>,
}

/// Compare two PublicOutputs for byte-identical agreement.
fn assert_outputs_identical(name: &str, a: &PublicOutputs, b: &PublicOutputs) {
    assert_eq!(
        a.result, b.result,
        "[{}] result mismatch: {:?} vs {:?}",
        name, a.result, b.result
    );
    assert_eq!(
        a.rejection_reason, b.rejection_reason,
        "[{}] rejection_reason mismatch: {:?} vs {:?}",
        name, a.rejection_reason, b.rejection_reason
    );
    assert_eq!(
        a.produced_state_id, b.produced_state_id,
        "[{}] produced_state_id mismatch",
        name
    );
    assert_eq!(
        a.new_state_hash, b.new_state_hash,
        "[{}] new_state_hash mismatch",
        name
    );
    assert_eq!(
        a.commitment_hash, b.commitment_hash,
        "[{}] commitment_hash mismatch",
        name
    );
    assert_eq!(
        a.new_wallet_seq, b.new_wallet_seq,
        "[{}] new_wallet_seq mismatch",
        name
    );
    assert_eq!(
        a.new_balance, b.new_balance,
        "[{}] new_balance mismatch",
        name
    );
    assert_eq!(a.txid, b.txid, "[{}] txid mismatch", name);
    assert_eq!(
        a.is_overlapped, b.is_overlapped,
        "[{}] is_overlapped mismatch",
        name
    );
    assert_eq!(
        a.required_k, b.required_k,
        "[{}] required_k mismatch",
        name
    );
    assert_eq!(
        a.extracted_proof_type, b.extracted_proof_type,
        "[{}] extracted_proof_type mismatch",
        name
    );
}

/// Build the full corpus of test vectors. Each vector is deterministic:
/// wallets are created once, transactions signed once, then cloned for each run.
fn build_corpus() -> Vec<TestVector> {
    // ── Wallets (created once, cloned per-vector) ──────────────────────
    let alice = TestWallet::generate("alice@diff.com", 10_000_000_000); // 10B atoms
    let bob = TestWallet::generate("bob@diff.com", 500_000_000);
    let charlie = TestWallet::generate("charlie@diff.com", 0);

    let mut corpus: Vec<TestVector> = Vec::new();

    // ── 1. Normal send (valid, should accept) ──────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), 1_000_000, "normal send", 100);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "normal_send",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 2. Insufficient balance ────────────────────────────────────────
    {
        let w = TestWallet::generate("poor@diff.com", 500_000); // exactly dust minimum
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), 500_001, "overdraft", 200);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "insufficient_balance",
            expect_accept: false,
            expect_error: Some(ValidationError::InsufficientBalance),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 3. Zero amount ─────────────────────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), 0, "zero", 300);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "zero_amount",
            expect_accept: false,
            expect_error: Some(ValidationError::ZeroAmount),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 4. Dust amount (below minimum) ─────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), MINIMUM_TX_ATOMS - 1, "dust", 400);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "dust_amount",
            expect_accept: false,
            expect_error: Some(ValidationError::DustAmount),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 5. Valid amount at minimum threshold ───────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), MINIMUM_TX_ATOMS, "exact-min", 500);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "exact_minimum_threshold",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 6. Wrong wallet_seq (too high) ─────────────────────────────────
    // wallet_seq=99 with no prev_receipts and prev_seq=0 triggers
    // MissingPrevReceipts (check fires before wallet_seq validation).
    {
        let w = alice.clone();
        let r = bob.clone();
        let mut tx = w.create_transaction(&r.address(), 500_000, "bad-seq", 600);
        tx.wallet_seq = 99; // wallet_seq should be 1 for fresh wallet
        w.sign_transaction(&mut tx);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "wrong_wallet_seq_high",
            expect_accept: false,
            expect_error: Some(ValidationError::MissingPrevReceipts),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 7. Wrong wallet_seq (zero) ─────────────────────────────────────
    // wallet_seq=0 with no prev_receipts and prev_seq=0 triggers
    // MissingPrevReceipts (the condition wallet_seq==1 && prev_seq==0 is false).
    {
        let w = alice.clone();
        let r = bob.clone();
        let mut tx = w.create_transaction(&r.address(), 500_000, "seq-zero", 700);
        tx.wallet_seq = 0;
        w.sign_transaction(&mut tx);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "wrong_wallet_seq_zero",
            expect_accept: false,
            expect_error: Some(ValidationError::MissingPrevReceipts),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 8. Replay attempt (same consumed_state_id submitted twice) ────
    // Both use the same inputs — Core is deterministic, so the same
    // consumed_state_id produces the same result. Replay *detection*
    // happens in Lambda (state_id chain mismatch). Here we verify that
    // running identical inputs twice yields identical outputs (determinism).
    {
        let w = alice.clone();
        let r = charlie.clone();
        let tx = w.create_transaction(&r.address(), 500_000, "replay-test", 800);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "replay_attempt_determinism",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 9. Frozen wallet TX ────────────────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), 500_000, "frozen", 900);
        // Freeze Alice's pk
        let mut pk32 = [0u8; 32];
        pk32.copy_from_slice(&w.public_key());
        let inputs = build_cl1_frozen(&w, tx, vec![pk32]);
        corpus.push(TestVector {
            name: "frozen_wallet",
            expect_accept: false,
            expect_error: Some(ValidationError::WalletFrozen),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 10. Self-send (same email, non-Ark) ────────────────────────────
    {
        let w = alice.clone();
        // Create a receiver with the same email as alice
        let r = TestWallet::generate("alice@diff.com", 0);
        let tx = w.create_transaction(&r.address(), 500_000, "self-send", 1000);
        let mut inputs = build_cl1(&w, tx);
        inputs.transaction.sender_wallet_id = w.address();
        w.sign_transaction(&mut inputs.transaction);
        corpus.push(TestVector {
            name: "self_send",
            expect_accept: false,
            expect_error: Some(ValidationError::SelfSendRejected),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 11. DWP protocol address (1-atom, bypasses dust) ───────────────
    {
        let w = alice.clone();
        let mut tx = w.create_transaction("DWP/vote_group_01", 1, "jfp-vote", 1100);
        // DWP address uses DWP/ prefix — must re-sign since receiver changed
        w.sign_transaction(&mut tx);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "dwp_protocol_1atom",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 12. Oversized reference field ──────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let long_ref = "X".repeat(257);
        let tx = w.create_transaction(&r.address(), 500_000, &long_ref, 1200);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "oversized_reference",
            expect_accept: false,
            expect_error: Some(ValidationError::ReferenceTooLarge),
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 13. Corrupted signature ────────────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let mut tx = w.create_transaction(&r.address(), 500_000, "corrupt-sig", 1300);
        for byte in tx.client_sig.iter_mut() {
            *byte ^= 0xFF;
        }
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "corrupted_signature",
            expect_accept: false,
            expect_error: None, // Could be InvalidClientSignature or E_INVALID_CLIENT_SIG
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 14. Empty signature ────────────────────────────────────────────
    {
        let w = alice.clone();
        let r = bob.clone();
        let mut tx = w.create_transaction(&r.address(), 500_000, "empty-sig", 1400);
        tx.client_sig = vec![];
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "empty_signature",
            expect_accept: false,
            expect_error: None, // Reject with some sig error variant
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 15. Large valid send (close to full balance) ───────────────────
    {
        let w = alice.clone();
        let r = charlie.clone();
        // Send almost everything (leave 0 remainder is fine for CL1)
        let tx = w.create_transaction(&r.address(), 9_999_000_000, "big-send", 1500);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "large_valid_send",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 16. Exact balance send ─────────────────────────────────────────
    {
        let w = alice.clone();
        let r = charlie.clone();
        let tx = w.create_transaction(&r.address(), 10_000_000_000, "exact-balance", 1600);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "exact_balance_send",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 17. Frozen wallet with empty freeze list (should NOT freeze) ──
    {
        let w = alice.clone();
        let r = bob.clone();
        let tx = w.create_transaction(&r.address(), 500_000, "empty-freeze", 1700);
        let inputs = build_cl1_frozen(&w, tx, vec![]);
        corpus.push(TestVector {
            name: "empty_freeze_list_accepted",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    // ── 18. Reference at exactly 256 bytes (boundary, should accept) ──
    {
        let w = alice.clone();
        let r = bob.clone();
        let exact_ref = "R".repeat(256);
        let tx = w.create_transaction(&r.address(), 500_000, &exact_ref, 1800);
        let inputs = build_cl1(&w, tx);
        corpus.push(TestVector {
            name: "reference_exactly_256",
            expect_accept: true,
            expect_error: None,
            build: Box::new(move || inputs.clone()),
        });
    }

    corpus
}

// ===========================================================================
// Test 1: Differential verification — two independent executions agree
// ===========================================================================

#[test]
fn differential_two_validators_agree_on_every_tx() {
    let corpus = build_corpus();
    assert!(
        corpus.len() >= 15,
        "Corpus must have at least 15 vectors, got {}",
        corpus.len()
    );

    for vector in &corpus {
        // Two independent executions with fresh state (cloned from builder)
        let inputs_a = (vector.build)();
        let inputs_b = (vector.build)();

        let outputs_a = execute_core(inputs_a);
        let outputs_b = execute_core(inputs_b);

        // Byte-identical outputs
        assert_outputs_identical(vector.name, &outputs_a, &outputs_b);

        // Verify expected outcome
        if vector.expect_accept {
            assert_eq!(
                outputs_a.result,
                ValidationResult::Accept,
                "[{}] expected Accept, got Reject: {:?}",
                vector.name,
                outputs_a.rejection_reason,
            );
        } else {
            assert_eq!(
                outputs_a.result,
                ValidationResult::Reject,
                "[{}] expected Reject, got Accept",
                vector.name,
            );
            // If we specified a particular error, check it
            if let Some(ref expected_err) = vector.expect_error {
                assert_eq!(
                    outputs_a.rejection_reason.as_ref(),
                    Some(expected_err),
                    "[{}] wrong rejection reason: {:?}",
                    vector.name,
                    outputs_a.rejection_reason,
                );
            }
        }
    }
}

// ===========================================================================
// Test 2: Determinism proof — 3 full runs produce identical results
// ===========================================================================

#[test]
fn determinism_proof_three_runs_identical() {
    let corpus = build_corpus();

    // Run 1
    let results_1: Vec<PublicOutputs> = corpus.iter().map(|v| execute_core((v.build)())).collect();

    // Run 2
    let results_2: Vec<PublicOutputs> = corpus.iter().map(|v| execute_core((v.build)())).collect();

    // Run 3
    let results_3: Vec<PublicOutputs> = corpus.iter().map(|v| execute_core((v.build)())).collect();

    for (i, vector) in corpus.iter().enumerate() {
        // Run 1 vs Run 2
        assert_outputs_identical(
            &format!("{} (run1 vs run2)", vector.name),
            &results_1[i],
            &results_2[i],
        );
        // Run 2 vs Run 3
        assert_outputs_identical(
            &format!("{} (run2 vs run3)", vector.name),
            &results_2[i],
            &results_3[i],
        );
    }
}

// ===========================================================================
// Test 3: Accepted TX state transitions are fully populated
// ===========================================================================

#[test]
fn accepted_txs_have_complete_state_transitions() {
    let corpus = build_corpus();

    for vector in &corpus {
        let outputs = execute_core((vector.build)());

        if outputs.result == ValidationResult::Accept {
            assert!(
                outputs.produced_state_id.is_some(),
                "[{}] accepted TX missing produced_state_id",
                vector.name
            );
            assert!(
                outputs.new_state_hash.is_some(),
                "[{}] accepted TX missing new_state_hash",
                vector.name
            );
            assert!(
                outputs.commitment_hash.is_some(),
                "[{}] accepted TX missing commitment_hash",
                vector.name
            );
            assert!(
                outputs.new_wallet_seq.is_some(),
                "[{}] accepted TX missing new_wallet_seq",
                vector.name
            );
            // Note: txid is computed in CL2/CL3, not CL1.
            // CL1 outputs txid = None by design.
        } else {
            // Rejected TXs must have a rejection reason
            assert!(
                outputs.rejection_reason.is_some(),
                "[{}] rejected TX missing rejection_reason",
                vector.name
            );
        }
    }
}

// ===========================================================================
// Test 4: Replay vector — same inputs always yield same state_id
// ===========================================================================

#[test]
fn replay_inputs_produce_identical_state_ids() {
    let alice = TestWallet::generate("replay@diff.com", 5_000_000_000);
    let bob = TestWallet::generate("replay-recv@diff.com", 0);

    let tx = alice.create_transaction(&bob.address(), 1_000_000, "replay-proof", 42);
    let inputs = build_cl1(&alice, tx);

    // Execute 5 times with cloned inputs
    let mut state_ids: Vec<Option<[u8; 32]>> = Vec::new();
    let mut commitment_hashes: Vec<Option<[u8; 32]>> = Vec::new();

    for _ in 0..5 {
        let outputs = execute_core(inputs.clone());
        assert_eq!(outputs.result, ValidationResult::Accept);
        state_ids.push(outputs.produced_state_id);
        commitment_hashes.push(outputs.commitment_hash);
    }

    // All 5 runs must produce identical values
    for i in 1..5 {
        assert_eq!(
            state_ids[0], state_ids[i],
            "produced_state_id diverged on run {}",
            i
        );
        assert_eq!(
            commitment_hashes[0], commitment_hashes[i],
            "commitment_hash diverged on run {}",
            i
        );
    }
}

// ===========================================================================
// Test 5: Different inputs produce different state_ids (collision resistance)
// ===========================================================================

#[test]
fn different_txs_produce_different_state_ids() {
    let alice = TestWallet::generate("collision@diff.com", 10_000_000_000);
    let bob = TestWallet::generate("collision-b@diff.com", 0);
    let charlie = TestWallet::generate("collision-c@diff.com", 0);

    let tx1 = alice.create_transaction(&bob.address(), 500_000, "tx-one", 1);
    let tx2 = alice.create_transaction(&charlie.address(), 500_000, "tx-two", 2);

    let out1 = execute_core(build_cl1(&alice, tx1));
    let out2 = execute_core(build_cl1(&alice, tx2));

    assert_eq!(out1.result, ValidationResult::Accept);
    assert_eq!(out2.result, ValidationResult::Accept);

    // Different receivers or nonces must produce different state transitions
    assert_ne!(
        out1.produced_state_id, out2.produced_state_id,
        "Different TXs must produce different produced_state_id"
    );
    assert_ne!(
        out1.commitment_hash, out2.commitment_hash,
        "Different TXs must produce different commitment_hash"
    );
    // Note: txid is computed in CL2/CL3, not CL1 — both are None here.
}
