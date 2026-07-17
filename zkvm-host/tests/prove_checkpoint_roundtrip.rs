//! End-to-end regression test for the production zkVM proving path.
//!
//! Guards the host↔guest serialization contract. The guest reads its
//! `PublicInputs` as a CBOR-bytes frame (self-describing) rather than via
//! risc0's word-serde, because the latter silently OMITS
//! `#[serde(skip_serializing_if = "Option::is_none")]` fields (e.g.
//! `WalletState.wallet_id`) on the host while the guest still reads them
//! positionally — desyncing the stream and tripping `DeserializeUnexpectedEnd`.
//!
//! This test feeds a `current_state` whose `wallet_id` is `None` (the exact
//! field that triggered the bug) through a REAL STARK prove + verify. Before the
//! CBOR-frame fix this panicked inside the guest; after it, the proof generates
//! and `verify_checkpoint` round-trips the journal.
//!
//! Requires the `prove` feature and installed zkVM artifacts
//! (`~/.axiom/zkvm/axiom-core.elf` + `image-id.hex`). Skips (passes) cleanly if
//! artifacts are absent, mirroring the prover's own production() fail-stop.

#![cfg(feature = "prove")]

use axiom_dmap_vm::{CoreLogicMode, PublicInputs, Transaction, TxKind, WalletState};
use axiom_zk_vm::{ZkvmProver, ZkvmVerifier};

fn cl1_inputs_with_none_wallet_id() -> PublicInputs {
    PublicInputs {
        mode: CoreLogicMode::CL1,
        transaction: Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: "test@example.com/abc12345".into(),
            receiver_address: None,
            amount: 100_000,
            reference: "checkpoint-roundtrip".into(),
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
            // The field under test: None → host word-serde would OMIT it.
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
    }
}

#[test]
fn prove_checkpoint_roundtrips_state_with_none_wallet_id() {
    let mut prover = match ZkvmProver::production() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: zkVM artifacts not installed ({e}) — install via core/build-zkvm.sh");
            return;
        }
    };

    let inputs = cl1_inputs_with_none_wallet_id();

    // The fix under test: this must NOT panic with DeserializeUnexpectedEnd
    // inside the guest. native_outputs = None → fact_cargo frame is `None`.
    let (checkpoint, receipt) = prover
        .prove_checkpoint(inputs, None)
        .expect("prove_checkpoint must generate a real STARK proof");

    // input_hash is a 32-byte SHA256 the guest computes over the decoded inputs.
    // A non-zero hash proves the guest actually decoded the PublicInputs frame.
    assert_ne!(
        checkpoint.input_hash, [0u8; 32],
        "guest produced a zero input_hash — inputs did not decode"
    );

    // The STARK must verify against the installed IMAGE_ID, and the verified
    // journal must round-trip to the same input_hash.
    let verifier = ZkvmVerifier::production().expect("verifier production");
    let verified = verifier
        .verify_checkpoint(&receipt)
        .expect("checkpoint receipt must verify");
    assert_eq!(
        verified.input_hash, checkpoint.input_hash,
        "verified journal input_hash differs from prover output"
    );

    eprintln!(
        "OK: prove+verify round-trip; result={:?} input_hash={}",
        verified.result,
        hex::encode(verified.input_hash)
    );
}
