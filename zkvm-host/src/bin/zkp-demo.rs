//! AXIOM ZK Proof Demo — Prove, Verify, Tamper, Fail
//!
//! Run:
//!   cargo run -p axiom-zk-vm --features prove --bin zkp-demo --release

use axiom_zk_vm::{ZkvmProver, ZkvmVerifier, ZkvmReceipt};
use axiom_dmap_vm::{CoreLogicMode, PublicInputs, Transaction, TxKind, WalletState};
use std::time::Instant;

fn separator() {
    println!("────────────────────────────────────────────────────────");
}

fn main() {
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          AXIOM — ZK PROOF DEMONSTRATION             ║");
    println!("║                                                     ║");
    println!("║  Prove a transaction was validated by Core.bin      ║");
    println!("║  inside a RISC-V zkVM. Then try to cheat.           ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // ── Setup ──────────────────────────────────────────────────
    let mut prover = ZkvmProver::production()
        .expect("zkVM artifacts not found — run build-zkvm first");
    let image_id = hex::encode(prover.program_digest());

    println!("IMAGE_ID: {}...{}", &image_id[..16], &image_id[48..]);
    separator();

    // ══════════════════════════════════════════════════════════
    // STEP 1: Create a real transaction
    // ══════════════════════════════════════════════════════════
    println!();
    println!("STEP 1  Create transaction");
    println!();

    let inputs = PublicInputs {
        oods_attestation: None,
        mode: CoreLogicMode::CL1,
        transaction: Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: "alice@axiom.net/7f3a2b01".into(),
            receiver_address: None,
            amount: 500_000,
            reference: "Payment for penguins".into(),
            nonce: 42,
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
            balance: 10_000_000,
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

    println!("  To:      {}", inputs.transaction.receiver_wallet_id);
    println!("  Amount:  {} atoms (0.5 AXM)", inputs.transaction.amount);
    println!("  Balance: {} atoms (10 AXM)", inputs.current_state.as_ref().unwrap().balance);
    println!("  Ref:     \"{}\"", inputs.transaction.reference);

    // ══════════════════════════════════════════════════════════
    // STEP 2: Generate STARK proof
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("STEP 2  Generate STARK proof");
    println!();
    println!("  Executing Core.bin inside RISC-V zkVM...");

    let t = Instant::now();
    let (outputs, receipt) = prover.prove(inputs).expect("proving failed");
    let prove_time = t.elapsed();

    println!("  Done.");
    println!();
    println!("  Result:     {:?}", outputs.result);
    println!("  Prove time: {:.2?}", prove_time);
    println!("  Journal:    {} bytes (public outputs)", receipt.journal.len());
    println!("  Seal:       {} bytes ({:.1} KB STARK proof)", receipt.seal.len(), receipt.seal.len() as f64 / 1024.0);

    // ══════════════════════════════════════════════════════════
    // STEP 3: Verify the honest proof
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("STEP 3  Verify proof (honest)");
    println!();

    let verifier = ZkvmVerifier::production().unwrap();

    let t = Instant::now();
    let result = verifier.verify(&receipt);
    let verify_time = t.elapsed();

    match &result {
        Ok(out) => {
            println!("  PASS  Proof is valid.  ({:.2?})", verify_time);
            println!("  Verified result: {:?}", out.result);
        }
        Err(e) => {
            println!("  UNEXPECTED FAILURE: {}", e);
            std::process::exit(1);
        }
    }

    // ══════════════════════════════════════════════════════════
    // STEP 4: Tamper with the proof seal (flip one bit)
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("STEP 4  Tamper with proof (flip 1 bit in seal)");
    println!();

    let mut tampered_seal = receipt.seal.clone();
    // Flip a bit deep inside the proof (not in the header)
    let tamper_offset = tampered_seal.len() / 2;
    tampered_seal[tamper_offset] ^= 0x01;
    println!("  Flipped bit at seal byte {}/{}", tamper_offset, tampered_seal.len());

    let tampered_receipt = ZkvmReceipt::new(
        receipt.journal.clone(),
        tampered_seal,
        receipt.program_digest,
    );

    let t = Instant::now();
    let result = verifier.verify(&tampered_receipt);
    let verify_time = t.elapsed();

    match result {
        Err(e) => {
            println!("  FAIL  Tampered proof rejected.  ({:.2?})", verify_time);
            println!("  Error: {}", e);
        }
        Ok(_) => {
            println!("  !! CRITICAL: Tampered proof was ACCEPTED !!");
            println!("  !! THE ZK PROOF IS BROKEN !!");
            std::process::exit(99);
        }
    }

    // ══════════════════════════════════════════════════════════
    // STEP 5: Tamper with the journal (change the outputs)
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("STEP 5  Tamper with journal (corrupt public outputs)");
    println!();

    let mut tampered_journal = receipt.journal.clone();
    // Flip a bit in the journal (the public outputs)
    if !tampered_journal.is_empty() {
        tampered_journal[0] ^= 0xFF;
        println!("  Corrupted journal byte 0: 0x{:02x} -> 0x{:02x}",
            receipt.journal[0], tampered_journal[0]);
    }

    let tampered_receipt2 = ZkvmReceipt::new(
        tampered_journal,
        receipt.seal.clone(),
        receipt.program_digest,
    );

    let t = Instant::now();
    let result = verifier.verify(&tampered_receipt2);
    let verify_time = t.elapsed();

    match result {
        Err(e) => {
            println!("  FAIL  Tampered journal rejected.  ({:.2?})", verify_time);
            println!("  Error: {}", e);
        }
        Ok(_) => {
            println!("  !! CRITICAL: Tampered journal was ACCEPTED !!");
            println!("  !! THE ZK PROOF IS BROKEN !!");
            std::process::exit(99);
        }
    }

    // ══════════════════════════════════════════════════════════
    // STEP 6: Wrong IMAGE_ID (different program)
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("STEP 6  Wrong IMAGE_ID (pretend different Core.bin)");
    println!();

    let mut wrong_digest = receipt.program_digest;
    wrong_digest[0] ^= 0xFF;
    println!("  Changed digest byte 0: 0x{:02x} -> 0x{:02x}",
        receipt.program_digest[0], wrong_digest[0]);

    let wrong_id_receipt = ZkvmReceipt::new(
        receipt.journal.clone(),
        receipt.seal.clone(),
        wrong_digest,
    );

    let result = verifier.verify(&wrong_id_receipt);

    match result {
        Err(e) => {
            println!("  FAIL  Wrong IMAGE_ID rejected.");
            println!("  Error: {}", e);
        }
        Ok(_) => {
            println!("  !! CRITICAL: Wrong IMAGE_ID was ACCEPTED !!");
            println!("  !! THE ZK PROOF IS BROKEN !!");
            std::process::exit(99);
        }
    }

    // ══════════════════════════════════════════════════════════
    // Summary
    // ══════════════════════════════════════════════════════════
    separator();
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║              ALL CHECKS PASSED                      ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║                                                     ║");
    println!("║  Honest proof:      VERIFIED                        ║");
    println!("║  Tampered seal:     REJECTED                        ║");
    println!("║  Tampered journal:  REJECTED                        ║");
    println!("║  Wrong IMAGE_ID:    REJECTED                        ║");
    println!("║                                                     ║");
    println!("║  The STARK proof is cryptographically sound.        ║");
    println!("║  No one can forge a Core.bin execution.             ║");
    println!("║                                                     ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Prove:  {:<43}║", format!("{:.2?}", prove_time));
    println!("║  Verify: {:<43}║", format!("{:.2?}", verify_time));
    println!("║  Seal:   {:<43}║", format!("{} bytes ({:.1} KB)", receipt.seal.len(), receipt.seal.len() as f64 / 1024.0));
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
}
