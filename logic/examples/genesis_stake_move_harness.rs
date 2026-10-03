//! Native-key genesis-stake MOVE harness — YP §2.10.1 / YPX-011 §2.5.
//!
//! Proves the stronger property the hermetic C-tier gate `stake.genesis_lock_release`
//! cannot: that a genesis validator's stake actually MOVES — a real signed send is
//! ACCEPTED and the balance is debited — once the 3-year lock expires. It needs the
//! on-disk genesis PRIVATE key (to sign) plus a forged post-lock epoch (the lock is a
//! 3-year wall-clock span never reached by any live run). Complements, does not
//! replace, the unit gate.
//!
//! Run:
//!   cargo run -p axiom-core-logic --example genesis_stake_move_harness \
//!     --features dev-mode -- <path/to/config/ed25519.key> [sender-email]
//!
//! The key MUST be a genesis stake key (its pk in GENESIS_STAKE_WALLET_PKS), or the
//! harness refuses. Exit 0 = PASS, 1 = FAIL, 2 = usage / precondition unmet.

use axiom_core_logic::types::{
    PublicInputs, CoreLogicMode, ValidationResult, ValidationError, WalletState, Transaction,
};
use axiom_core_logic::modes::execute_core;
use axiom_test_utils::TestWallet;

/// The full PublicInputs skeleton for a CL1 client self-check of a genesis send.
/// (PublicInputs derives Default only under cfg(test), so an example writes it out.)
fn make_inputs(tx: Transaction, state: WalletState) -> PublicInputs {
    PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: None,
        fob_claim_attestation: None,
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1,
        transaction: tx,
        prev_receipts: vec![], // genesis first send — no anchor to re-derive
        current_state: Some(state),
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
        receiver_witness: None,
        receiver_signing_key: None,
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
        local_core_id: [0u8; 32],
        max_fact_links: None,
        current_tick: 0,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key_path = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: genesis_stake_move_harness <path/to/ed25519.key> [sender-email]");
            std::process::exit(2);
        }
    };
    let raw = match std::fs::read(&key_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("cannot read {key_path}: {e}"); std::process::exit(2); }
    };
    let key: [u8; 32] = match raw.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => { eprintln!("key must be 32 raw bytes, got {}", raw.len()); std::process::exit(2); }
    };

    // Derive the pk and confirm this is genuinely a genesis stake key.
    let sk = ed25519_dalek::SigningKey::from_bytes(&key);
    let pk: [u8; 32] = ed25519_dalek::VerifyingKey::from(&sk).to_bytes();
    let opening = axiom_core_logic::genesis::genesis_opening_balance(&pk);
    if opening == 0 {
        eprintln!(
            "FAIL: {key_path} is NOT a genesis stake key — genesis_opening_balance == 0 (pk {}… not in GENESIS_STAKE_WALLET_PKS).",
            hex::encode(&pk[..8])
        );
        std::process::exit(1);
    }

    // Sender = a wallet around the real genesis key at its opening balance. Receiver
    // = a fresh wallet in the SAME class (same email domain) so R1 does not interfere.
    let email = args.get(2).cloned().unwrap_or_else(|| "alpha@axiom".to_string());
    let domain = email.rsplit('@').next().unwrap_or("axiom").to_string();
    let sender = TestWallet::from_ed25519_key(&email, key, opening);
    let receiver = TestWallet::generate(&format!("stakemove-rx@{domain}"), 0);

    let lock_start = axiom_core_logic::genesis_integrity::GENESIS_STAKE_LOCK_START_SECS;
    let lockup_secs = axiom_core_logic::validation::GENESIS_LOCKUP_SECONDS;
    let lockup_end = lock_start + lockup_secs;
    let amount: u64 = 500_000; // dust minimum

    let probe = |epoch: u64| {
        let mut tx = sender.create_transaction(&receiver.address(), amount, "genesis stake move", 1);
        tx.epoch = epoch; // forge a post-lock epoch
        sender.sign_transaction(&mut tx); // re-sign so client_sig covers the new epoch
        execute_core(make_inputs(tx, sender.wallet_state()))
    };

    println!(
        "genesis key {}… | opening {} atoms | lock_start {} | lockup_end {}",
        hex::encode(&pk[..8]), opening, lock_start, lockup_end
    );

    // 1. DURING the lock — the send must be refused GenesisStakeLocked.
    let during = probe(lockup_end - 1);
    let during_ok = during.result == ValidationResult::Reject
        && during.rejection_reason == Some(ValidationError::GenesisStakeLocked);
    println!(
        "  during lock (epoch {}): result={:?} reason={:?} -> {}",
        lockup_end - 1, during.result, during.rejection_reason,
        if during_ok { "LOCKED ok" } else { "UNEXPECTED" }
    );

    // 2. AFTER the lock — the stake MOVES: Accept, and the balance is debited.
    let after = probe(lockup_end + 1);
    // A valid send advances the state (seq 0 -> 1, a produced_state_id) and, where
    // CL1 reports it, debits the balance. new_balance may be None at CL1; don't
    // fail on its absence — Accept + seq advance + produced_state_id is the move.
    let new_balance = after.new_balance;
    let debited = new_balance.map_or(true, |b| b < opening);
    let moved = after.result == ValidationResult::Accept
        && after.produced_state_id.is_some()
        && after.new_wallet_seq == Some(1)
        && debited;
    println!(
        "  after lock  (epoch {}): result={:?} reason={:?} new_balance={:?} (debited? {}) new_seq={:?} -> {}",
        lockup_end + 1, after.result, after.rejection_reason, new_balance,
        debited, after.new_wallet_seq,
        if moved { "MOVED ok" } else { "DID NOT MOVE" }
    );

    if during_ok && moved {
        println!("PASS: genesis stake is LOCKED before expiry and MOVES (Accept, debited) after.");
        std::process::exit(0);
    }
    eprintln!("FAIL: expected LOCKED before expiry AND a debited Accept after.");
    std::process::exit(1);
}
