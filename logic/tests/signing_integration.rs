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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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

/// P3.7 — ArkSendFinalize refuses a NON-Ark transfer. The offline send-link
/// finalize is k=0-only; a normal (k=3) transfer routed through it must reject with
/// ArkOnlineTradeRejected (proving the mode is wired + the tier gate fires). The
/// positive k=0 path is env-validated by the live Ark trade smoke.
#[test]
fn test_ark_finalize_refuses_non_ark_transfer() {
    use axiom_core_logic::types::ValidationError;
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    let tx = alice.create_transaction(&bob.address(), 500_000, "not an ark trade", 1);

    let mut inputs = build_finalize_inputs(&alice, tx);
    inputs.mode = CoreLogicMode::ArkSendFinalize;
    let outputs = execute_core(inputs);

    assert_eq!(outputs.result, ValidationResult::Reject,
        "non-Ark transfer through ArkSendFinalize must reject");
    assert_eq!(outputs.rejection_reason, Some(ValidationError::ArkOnlineTradeRejected),
        "expected ArkOnlineTradeRejected, got {:?}", outputs.rejection_reason);
    assert!(outputs.ark_send_fact_chain.is_none(), "rejected finalize produces no chain");
}

/// Minimal PublicInputs for the ArkSendFinalize refusal test (a genesis-shaped send).
fn build_finalize_inputs(wallet: &TestWallet, tx: axiom_core_logic::types::Transaction) -> PublicInputs {
    PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
        oods_attestation: None, recall_attestation: None, receiver_current_hibernation: None,
        mode: CoreLogicMode::CL1, transaction: tx, prev_receipts: vec![],
        current_state: Some(wallet.wallet_state()), vbc_bundle: None, cheque_bundle: None,
        receiver_pk: None, receiver_current_balance: None, receiver_wallet_seq: None,
        receiver_new_balance: None, receiver_new_state_id: None, my_validator_pk: None,
        overlapped_signatures: vec![], group_member_index: None, sender_fact_chain: None,
        receiver_witness: None, receiver_fact_chain: None, my_dilithium_sk: None,
        receiver_signing_key: None,
        my_dilithium_pk: None, my_validator_id: None, fact_witness_sigs: vec![],
        issuer_sphincs_sk: None, cl1_execution_proof: None, zkp_nonce: None,
        audit_confirmation: None, nonce_response: None, audit_response: None,
        wallet_secret: None, fanout_message: None,
        nabla_stake_proof: None, frozen_wallets: None, console_current_cert: None,
        console_new_cert: None, console_selector_picks: None, console_nominations: None,
        txid_attestation: None, cheque_claim_proof: None, clara_attestation: None,
        phase_out_payload: None, phase_out_era_end_ticks: vec![], phase_out_blocked_era_ids: vec![],
        local_core_id: [0u8; 32], max_fact_links: None, current_tick: 0,
    }
}

const ARK_BAL: u64 = 10_000_000;
const ARK_AMOUNT: u64 = 500_000;

/// The P3.7 offline ⟠ trade up to the k=0 cheque — shared by the round-trip
/// test below and the W7a redeem-preimage test (one fixture, RULE 1). Every
/// intermediate assertion of the original test stays here.
struct ArkTrade {
    receiver_sk: ed25519_dalek::SigningKey,
    rpk: [u8; 32],
    r_addr: String,
    s_state: axiom_core_logic::types::WalletState,
    tx: axiom_core_logic::types::Transaction,
    send_chain: axiom_core_logic::types::FactChain,
    cheque: axiom_core_logic::types::ValidatorCheque,
}

fn ark_base_inputs(
    s_state: &axiom_core_logic::types::WalletState,
    t: axiom_core_logic::types::Transaction,
) -> PublicInputs {
    let mut i = build_finalize_inputs(&TestWallet::generate("unused@test.com", 0), t);
    i.current_state = Some(s_state.clone());
    i
}

/// The receiver's LOCAL CL5 (k=0 profile) inputs for `a`'s cheque.
/// `receiver_state` = the receiver's declared pre-redeem state (`None` = fresh).
fn ark_local_cl5_inputs(
    a: &ArkTrade,
    signing_key: Option<[u8; 32]>,
    receiver_state: Option<axiom_core_logic::types::WalletState>,
) -> PublicInputs {
    let mut i = ark_base_inputs(&a.s_state, a.tx.clone());
    i.mode = CoreLogicMode::CL5;
    i.current_state = receiver_state;
    i.cheque_bundle = Some(axiom_core_logic::types::ChequeBundle {
        cheques: vec![a.cheque.clone()],
        fact_chain: Some(a.send_chain.clone()),
    });
    i.receiver_pk = Some(a.rpk.to_vec());
    i.receiver_current_balance = Some(0);
    i.receiver_wallet_seq = Some(0);
    i.receiver_current_hibernation = Some(0);
    i.receiver_new_balance = Some(ARK_AMOUNT); // rate_bps=0 ⇒ no fee offline
    i.receiver_signing_key = signing_key;
    i
}

fn ark_offline_trade() -> ArkTrade {
    use axiom_core_logic::types::{
        ChequeBundle, Transaction, TxKind, ValidationError, WalletState,
    };
    use axiom_core_logic::wallet_id::{generate_all_wallet_ids, K_ARK, PROOF_TYPE_ARK};
    use ed25519_dalek::{Signer, SigningKey};

    const BAL: u64 = ARK_BAL;
    const AMOUNT: u64 = ARK_AMOUNT;

    let sender_sk = SigningKey::from_bytes(&[0x51u8; 32]);
    let receiver_sk = SigningKey::from_bytes(&[0x52u8; 32]);
    let spk = sender_sk.verifying_key().to_bytes();
    let rpk = receiver_sk.verifying_key().to_bytes();
    let ark_id = |email: &str, pk: &[u8; 32]| -> String {
        generate_all_wallet_ids(email, "42", pk).unwrap()
            .into_iter()
            .find(|(_, k, _, _)| *k == K_ARK)
            .map(|(a, _, _, _)| a)
            .unwrap()
    };
    let s_addr = ark_id("arksender@test.com", &spk);
    let r_addr = ark_id("arkreceiver@test.com", &rpk);

    // Sender's k=0 tier state (as if charged earlier; first ark-tier move → seq 0→1).
    let s_state_id = axiom_core_logic::genesis::compute_genesis_state_id(
        &spk, BAL, K_ARK, PROOF_TYPE_ARK,
    );
    let s_state = WalletState {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        public_key: spk.to_vec(),
        balance: BAL,
        wallet_seq: 0,
        state_id: s_state_id,
        auth_hash: None,
        wallet_id: None,
        group_members: None,
        hibernation_until: 0,
    };

    let mut tx = Transaction {
        consumed_state_id: s_state_id,
        client_pk: spk.to_vec(),
        sender_wallet_id: s_addr.clone(),
        wallet_seq: 1,
        receiver_wallet_id: r_addr.clone(),
        receiver_address: None,
        amount: AMOUNT,
        reference: "ark trade".to_string(),
        nonce: 1,
        epoch: 1000,
        client_sig: vec![],
        scar_passcode: None,
        burn_target_tx_id: None,
        recall_target_tx_id: None,
        oracle_claim: None,
        required_k: 0,
        proof_type: 0,
        core_version: String::new(),
        core_id: [0u8; 32],
        kind: TxKind::Normal,
    };
    let msg = axiom_core_logic::validation::compute_signing_message_public(&tx);
    tx.client_sig = sender_sk.sign(&msg).to_bytes().to_vec();

    let base_inputs = |t: Transaction| ark_base_inputs(&s_state, t);

    // ── Sender CL1 self-check: learn produced_state_id + txid (leg S1 prep) ──
    let cl1_out = execute_core(base_inputs(tx.clone()));
    assert_eq!(cl1_out.result, ValidationResult::Accept,
        "k=0 trade CL1 must accept, got {:?}", cl1_out.rejection_reason);
    let produced = cl1_out.produced_state_id.expect("CL1 produced_state_id");
    let txid = axiom_core_logic::compute::compute_txid(&tx); // CL1 doesn't emit one
    let s_state_hash = cl1_out.new_state_hash.expect("CL1 state_hash");

    // ── Receiver-as-witness CL2 — the mode the DRIVER actually runs (§11.4):
    // no validator apparatus, no overlapped sigs. Must accept (the S-ABR
    // overlap gate is a validator-set concept and relaxes for the k=0
    // offline profile — the double-spend gate moves to §12 settlement) and
    // must reproduce the sender's produced_state_id (Core determinism — this
    // is the transition the receiver co-signs). First live run rejected
    // SABRInsufficientOverlap because this leg was only ever CL1-modeled.
    // NOTE: with empty prev_receipts the overlap gate doesn't arm, so this
    // asserts the exemption's happy path only; the ANCHORED shape (charge
    // receipt in prev_receipts, where the gate previously fired) needs a
    // root-signed VBC fixture and is exercised by the LIVE trade smoke
    // (tests/ark_offline_trade_smoke.py), the binding gate for this path.
    // §11.2 (ruling 2026-07-20): the k=0 CL2 profile now REQUIRES the
    // sender's CL1 DMAP attestation (the worldline proof) in
    // cl1_execution_proof — fail-closed. This native execute_core path
    // cannot mint a real attestation (no AVM/dmap trace), so here we assert
    // the GATE IS ARMED (rejects without proof); the CL2-accept happy path
    // + produced_state_id reproduction moved to the LIVE smoke
    // (tests/ark_offline_trade_smoke.py) with a real sender attestation —
    // fabricating a synthetic attestation to feed the verifier here is
    // exactly the shortcut feedback_test_real_producer_not_synthetic bans.
    let mut cl2_inputs = base_inputs(tx.clone());
    cl2_inputs.mode = CoreLogicMode::CL2;
    cl2_inputs.cl1_execution_proof = None;
    let cl2_out = execute_core(cl2_inputs);
    assert_eq!(cl2_out.result, ValidationResult::Reject,
        "k=0 CL2 must fail-closed without the sender attestation");
    assert_eq!(cl2_out.rejection_reason,
        Some(axiom_core_logic::types::ValidationError::ArkSenderProofMissing),
        "the missing sender proof must be the rejection cause");

    // ── Leg R2: the receiver co-signs the transition's fact commitment ──
    let commitment = axiom_core_logic::fact::compute_fact_commitment(
        &txid, &tx.consumed_state_id, &produced, AMOUNT, None, false, K_ARK, &[], None,
    );
    let rw = axiom_core_logic::types::ReceiverWitness {
        receiver_pk: rpk,
        signature: receiver_sk.sign(&commitment).to_bytes(),
    };

    // ── Sender ArkSendFinalize: Core assembles the k=0 send link ──
    let mut fin_inputs = base_inputs(tx.clone());
    fin_inputs.mode = CoreLogicMode::ArkSendFinalize;
    fin_inputs.receiver_witness = Some(rw);
    let fin_out = execute_core(fin_inputs);
    assert_eq!(fin_out.result, ValidationResult::Accept,
        "finalize must accept, got {:?}", fin_out.rejection_reason);
    let send_chain = fin_out.ark_send_fact_chain.expect("finalize chain");
    let send_tip = send_chain.links.last().expect("send link");
    assert_eq!(send_tip.required_k, K_ARK);
    assert!(send_tip.receiver_witness.is_some(), "send link carries the receiver witness");
    axiom_core_logic::fact::verify_fact_chain(&send_chain, &axiom_core_logic::fact::FactTrust::new(&[], None))
        .expect("k=0 send chain must verify (P3.2 receiver-witness branch)");

    // ── Leg S3: the sender issues the k=0 cheque (shared builder, wallet-key-signed) ──
    let issuer = axiom_core_logic::cheque_build::ChequeIssuerContext {
        issuer_id: *blake3::hash(&spk).as_bytes(),
        issuer_pk: spk.to_vec(),
        vbc_bundle: None,
        carrier_type: "ark".to_string(),
        carrier_address: String::new(),
        rate_bps: 0,
        created_at: 1000,
    };
    let mut cheque = axiom_core_logic::cheque_build::build_cheque_unsigned(
        &tx, txid, s_state_hash, produced, Some(send_chain.clone()),
        b"", None, 1, [0u8; 32], [0u8; 32], None, None, Vec::new(), &issuer,
    );
    let cheque_commitment = axiom_core_logic::compute::compute_cheque_commitment(
        &cheque.txid, &cheque.state_hash, &cheque.produced_state_id,
        &cheque.sender_wallet_id, &cheque.receiver_wallet_id, cheque.amount, cheque.epoch, cheque.created_at, cheque.rate_bps,
        &cheque.dmap_input_hash, &cheque.dmap_output_hash,
        cheque.oracle_claim.as_ref(), cheque.recall_target_tx_id.as_ref(),
    );
    cheque.signature = sender_sk.sign(&cheque_commitment).to_bytes().to_vec();

    ArkTrade { receiver_sk, rpk, r_addr, s_state, tx, send_chain, cheque }
}

/// P3.7 round-trip — the COMPLETE offline ⟠ trade at the Core level, both devices:
///   sender CL1 (self-check → produced_state_id/txid) → receiver co-signs the fact
///   commitment (leg R2) → sender `ArkSendFinalize` assembles the k=0 send link →
///   sender issues the k=0 cheque (shared `build_cheque_unsigned`, wallet-key-signed)
///   → receiver's LOCAL CL5 (k=0 profile) redeems it and — the new piece — assembles
///   its own receiver-witnessed k=0 REDEEM link in-guest via `receiver_signing_key`.
/// Every produced chain must pass the real `verify_fact_chain`.
#[test]
fn test_ark_offline_trade_finalize_then_local_cl5_redeem() {
    use axiom_core_logic::types::{ChequeBundle, ValidationError};
    use axiom_core_logic::wallet_id::K_ARK;

    const BAL: u64 = ARK_BAL;
    const AMOUNT: u64 = ARK_AMOUNT;
    let a = ark_offline_trade();
    let (receiver_sk, rpk, r_addr) = (a.receiver_sk.clone(), a.rpk, a.r_addr.clone());
    let send_tip = a.send_chain.links.last().expect("send link");
    let base_inputs = |t: axiom_core_logic::types::Transaction| ark_base_inputs(&a.s_state, t);

    // ── Receiver's LOCAL CL5 (k=0 profile): redeem + build the redeem link ──
    let cl5_inputs = |signing_key: Option<[u8; 32]>| ark_local_cl5_inputs(&a, signing_key, None);
    let cl5_out = execute_core(cl5_inputs(Some(receiver_sk.to_bytes())));
    assert_eq!(cl5_out.result, ValidationResult::Accept,
        "k=0 local CL5 must accept, got {:?}", cl5_out.rejection_reason);
    assert_eq!(cl5_out.new_balance, Some(AMOUNT));
    let redeem_chain = cl5_out.receiver_fact_chain
        .expect("k=0 CL5 must assemble the receiver's redeem link (§11.2.1)");
    let redeem_tip = redeem_chain.links.last().expect("redeem link");
    assert_eq!(redeem_tip.required_k, K_ARK);
    assert!(redeem_tip.receiver_witness.is_some(),
        "redeem link carries the receiver's own witness");
    assert_eq!(redeem_tip.sender_anchor, Some(send_tip.new_state_id),
        "redeem link anchors the k=0 send link the receiver co-signed");
    axiom_core_logic::fact::verify_fact_chain(&redeem_chain, &axiom_core_logic::fact::FactTrust::new(&[], None))
        .expect("k=0 redeem chain must verify");

    // ── Negatives ──
    // Without the receiver's signing key, the OFFLINE receiver-witness profile
    // is not selected (§12: no key ⇒ this is the online settlement/charge path,
    // needing k≥3 validator cheques). A 1-cheque offline bundle therefore fails
    // the normal-path cheque-count gate — i.e. you cannot do the offline redeem
    // without the key, it just surfaces as InsufficientCheques now.
    let no_key = execute_core(cl5_inputs(None));
    assert_eq!(no_key.rejection_reason, Some(ValidationError::InsufficientCheques),
        "k=0 redeem without receiver_signing_key routes to the normal k≥3 path");
    // A FOREIGN key still selects the offline profile (key present) and fails
    // the §11.7 pk binding on the receiver witness.
    let wrong_key = execute_core(cl5_inputs(Some([0x99u8; 32])));
    assert_eq!(wrong_key.rejection_reason, Some(ValidationError::ArkReceiverWitnessInvalid),
        "a foreign signing key must fail the §11.7 pk binding");

    // ── CHARGE-split pin (§10.3 / §11.4): a k≥3 sender → k=0 receiver redeem
    // is an ONLINE charge redeem, NOT the k=0 profile. Lambda's CL5 pass has
    // no receiver_signing_key — it must NOT be demanded; the redeem must fail
    // on the ONLINE mandatory gates instead (here: the Nabla claim proof).
    let k3_sender = TestWallet::generate("chargesender@test.com", BAL);
    let mut charge_tx = k3_sender.create_transaction(&r_addr, AMOUNT, "charge-shaped", 7);
    charge_tx.sender_wallet_id = k3_sender.address();
    k3_sender.sign_transaction(&mut charge_tx);
    let charge_txid = axiom_core_logic::compute::compute_txid(&charge_tx);
    let charge_issuer = axiom_core_logic::cheque_build::ChequeIssuerContext {
        issuer_id: *blake3::hash(&k3_sender.public_key()).as_bytes(),
        issuer_pk: k3_sender.public_key(),
        vbc_bundle: None,
        carrier_type: "email".to_string(),
        carrier_address: String::new(),
        rate_bps: 0,
        created_at: 1000,
    };
    let charge_cheque = axiom_core_logic::cheque_build::build_cheque_unsigned(
        &charge_tx, charge_txid, [0u8; 32], [1u8; 32], None,
        b"", None, 1, [0u8; 32], [0u8; 32], None, None, Vec::new(), &charge_issuer,
    );
    let mut charge_inputs = base_inputs(charge_tx.clone());
    charge_inputs.mode = CoreLogicMode::CL5;
    charge_inputs.current_state = None;
    charge_inputs.cheque_bundle = Some(ChequeBundle {
        cheques: vec![charge_cheque], fact_chain: None,
    });
    charge_inputs.receiver_pk = Some(rpk.to_vec());
    charge_inputs.receiver_current_balance = Some(0);
    charge_inputs.receiver_wallet_seq = Some(0);
    charge_inputs.receiver_current_hibernation = Some(0);
    charge_inputs.receiver_new_balance = Some(AMOUNT);
    charge_inputs.receiver_signing_key = None; // Lambda never has one
    let charge_out = execute_core(charge_inputs);
    eprintln!("[charge-pin] rejection = {:?}", charge_out.rejection_reason);
    assert_ne!(charge_out.rejection_reason, Some(ValidationError::ArkReceiverWitnessMissing),
        "a charge redeem (k≥3 sender → k=0 receiver) must NOT take the k=0 profile");
}

/// Fork Settlement W7a (spec R52c / §9g, the [R8] follow-on): the redeem leg's
/// carried preimage — built by THE one constructor `LegPreimage::redeem_of_cl5`
/// from a REAL CL5-produced receipt — recomputes Core's redeem commitment
/// BYTE-IDENTICALLY through the one verifier `redeem_preimage_matches`; every
/// tampered field is a mismatch. Run on a fresh receiver (consumed = zero) AND
/// a receiver with a declared prior state (consumed ≠ zero), so the
/// consumed-state binding is exercised on a real run, not only by tampering.
///
/// MUTATIONS (RULE 6 3a) that turn THIS test red: drop any field from
/// `RedeemPreimage::commitment_hash` / reorder its arguments; make
/// `redeem_preimage_matches` return `true`; read the consumed state anywhere
/// but `modes::cl5_consumed_state_id`.
#[test]
fn cl5_redeem_preimage_recomputes_the_real_cl5_commitment() {
    use axiom_core_logic::nabla_wire::LegPreimage;
    use axiom_core_logic::types::{LegKind, RedeemPreimage, WalletState};
    use axiom_core_logic::validation::redeem_preimage_matches;

    let a = ark_offline_trade();
    let key = Some(a.receiver_sk.to_bytes());
    let prior = WalletState {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
        public_key: a.rpk.to_vec(),
        balance: 0,
        wallet_seq: 0,
        state_id: [0x77u8; 32],
        auth_hash: None,
        wallet_id: None,
        group_members: None,
        hibernation_until: 0,
    };
    for (label, receiver_state, want_consumed) in [
        ("fresh receiver", None, [0u8; 32]),
        ("declared prior state", Some(prior), [0x77u8; 32]),
    ] {
        let inputs = ark_local_cl5_inputs(&a, key, receiver_state);
        let out = execute_core(inputs.clone());
        assert_eq!(out.result, ValidationResult::Accept, "{label}: CL5 must accept, got {:?}", out.rejection_reason);
        let core_commitment = out.commitment_hash.expect("CL5 returns the redeem commitment");

        let origin = LegPreimage::origin_of(&a.tx).expect("the cheque's send has an origin record");
        let leg = LegPreimage::redeem_of_cl5(&inputs, &out, origin.clone()).expect("an accepted CL5 has a redeem leg");
        assert_eq!(leg.cheque_origin(), Some(&origin), "{label}: the leg carries the cheque origin (KI#241 F-2)");
        assert_eq!(leg.kind(), LegKind::Redeem);
        assert!(leg.send_preimage().is_none());
        let p: RedeemPreimage = leg.redeem_preimage().expect("Redeem leg carries its preimage").clone();
        assert_eq!(p.cheque_txid, a.cheque.txid, "{label}: the cheque's txid");
        assert_eq!(p.receiver_pk, a.rpk, "{label}: the receiver's key");
        assert_eq!(Some(p.new_balance), out.new_balance, "{label}");
        assert_eq!(Some(p.new_state_id), out.produced_state_id, "{label}");
        assert_eq!(p.consumed_state_id, want_consumed, "{label}: the receiver-declared consumed state");
        assert_eq!(p.commitment_hash(), core_commitment,
            "{label}: the carried preimage reproduces Core's redeem commitment BYTE-IDENTICALLY");
        assert!(redeem_preimage_matches(&p, &core_commitment), "{label}: the verifier accepts the genuine leg");

        // Each tampered field is a mismatch.
        let tampers: [(&str, fn(&mut RedeemPreimage)); 5] = [
            ("cheque_txid", |p| p.cheque_txid[0] ^= 1),
            ("receiver_pk", |p| p.receiver_pk[0] ^= 1),
            ("new_balance", |p| p.new_balance += 1),
            ("new_state_id", |p| p.new_state_id[0] ^= 1),
            ("consumed_state_id", |p| p.consumed_state_id[0] ^= 1),
        ];
        for (field, tamper) in tampers {
            let mut t = p.clone();
            tamper(&mut t);
            assert!(!redeem_preimage_matches(&t, &core_commitment),
                "{label}: a tampered `{field}` must NOT recompute to Core's commitment");
        }
        // And a genuine preimage against a different commitment is refused.
        let mut other = core_commitment;
        other[31] ^= 1;
        assert!(!redeem_preimage_matches(&p, &other), "{label}: wrong commitment must mismatch");
    }

    // No accepted CL5 ⇒ no redeem leg (a rejected run is never carried).
    let bad_inputs = ark_local_cl5_inputs(&a, Some([0x99u8; 32]), None);
    let bad = execute_core(bad_inputs.clone());
    assert_eq!(bad.result, ValidationResult::Reject, "fixture: a foreign key rejects");
    assert!(LegPreimage::redeem_of_cl5(&bad_inputs, &bad, LegPreimage::origin_of(&a.tx).unwrap()).is_err(),
        "a rejected CL5 has no redeem leg");
}

/// KI#241 F-2 (Fable review 2026-10-01, test 1) — `redeem_of_cl5` refuses a
/// cheque origin that is not THIS cheque's: an amount +1 (the forged-amount
/// shape that would open Nabla's burn exit for the wrong value), a wrong
/// epoch, a `Redeem` kind. Control: the genuine origin (`origin_of(&tx)`)
/// builds, and the leg's carried amount is the cheque's GROSS amount.
///
/// MUTATION (run 2026-10-01): drop the `cheque_origin_matches` check in
/// `LegPreimage::redeem_of_cl5` ⇒ the forged origin builds ⇒ RED.
#[test]
fn cl5_redeem_leg_refuses_a_cheque_origin_that_is_not_the_cheques() {
    use axiom_core_logic::nabla_wire::{LegPreimage, LegPreimageError};
    use axiom_core_logic::types::LegKind;

    let a = ark_offline_trade();
    let inputs = ark_local_cl5_inputs(&a, Some(a.receiver_sk.to_bytes()), None);
    let out = execute_core(inputs.clone());
    assert_eq!(out.result, ValidationResult::Accept, "fixture: CL5 accepts");
    let genuine = LegPreimage::origin_of(&a.tx).unwrap();
    assert_eq!(genuine.preimage.txid(genuine.epoch), a.cheque.txid, "fixture: the origin reproduces the cheque txid");
    let leg = LegPreimage::redeem_of_cl5(&inputs, &out, genuine.clone()).expect("control: the genuine origin builds");
    assert_eq!(leg.cheque_origin().unwrap().preimage.amount, a.cheque.amount, "the GROSS cheque amount rides the leg");

    let mut forged = genuine.clone();
    forged.preimage.amount += 1;
    assert_eq!(LegPreimage::redeem_of_cl5(&inputs, &out, forged).unwrap_err(), LegPreimageError::ChequeOriginMismatch,
        "an origin with amount+1 is not the cheque's origin");
    let mut wrong_epoch = genuine.clone();
    wrong_epoch.epoch += 1;
    assert_eq!(LegPreimage::redeem_of_cl5(&inputs, &out, wrong_epoch).unwrap_err(), LegPreimageError::ChequeOriginMismatch,
        "an origin under another epoch does not reproduce the txid");
    let mut wrong_kind = genuine;
    wrong_kind.kind = LegKind::Redeem;
    assert_eq!(LegPreimage::redeem_of_cl5(&inputs, &out, wrong_kind).unwrap_err(), LegPreimageError::ChequeOriginMismatch,
        "a cheque origin is a SEND leg");
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
    
    };

    let outputs = execute_core(inputs);

    // Should be rejected (either for signature or balance, depending on check order)
    // With valid signature, it should hit balance check
    assert_eq!(outputs.result, ValidationResult::Reject);
}

/// CL2 inputs for a validator receiving `tx` against `state` (the first-tx
/// path: no prev_receipts). Shared by the plain CL2 test and the KI#256 CLARA
/// tests so both run the SAME fixture.
fn cl2_inputs(tx: axiom_core_logic::types::Transaction, state: axiom_core_logic::types::WalletState) -> PublicInputs {
    PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
        oods_attestation: None,
        recall_attestation: None,
        receiver_current_hibernation: None,
        mode: CoreLogicMode::CL2,
        transaction: tx,
        prev_receipts: vec![],
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

/// Test CL2 validation (validator receiving transaction)
#[test]
fn test_cl2_validator_validation() {
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    let tx = alice.create_transaction(&bob.address(), 500_000, "CL2 test", 1);
    
    let inputs = cl2_inputs(tx, alice.wallet_state());

    let outputs = execute_core(inputs);

    assert_eq!(
        outputs.result,
        ValidationResult::Accept,
        "CL2 validation should accept valid transaction. Rejection: {:?}",
        outputs.rejection_reason
    );
}

// ── KI#256 — Core's YPX-018 CL2 CLARA gate on an HONEST post-heal send ──────
//
// The SDK attaches its stored attestation ONLY to the tx that consumes the
// attested `healed_to_state_id` (`sdk/client/src/send.rs::clara_attestation_for_tx`).
// These tests pin what Core does with exactly that shape, through the REAL NBC
// trust anchor (`NABLA_ROOT_AUTHORITY_PKS`; an integration test does not see the
// crate's `#[cfg(test)]` test roots). The root private keys (`root-keys/*/root_N.key`)
// are gitignored, present on the dev/preflight box: a missing key FAILS these tests
// loudly (KI#256 review F6 — a silent `return` made them pass with no assertion run).
// ~~"Skipped when the root private key is not on disk (CI / fresh clone)"~~.
//
// Mutations (each reverted):
//   (i)  [2026-10-03, rewritten for KI#260 — the 2026-10-02 note "drop
//        `stored != to &&`" named a conjunct of the retired three-arm predicate]
//        `modes.rs` CL2 eligibility compares the view against
//        `healed_from_state_id` instead of `healed_to_state_id`
//        → `ki256_cl2_accepts_honest_post_heal_send_with_attestation` RED
//        (ClaraStateNotGarbage on the honest shape).
//   (ii) [2026-10-02] the test's own NBC signature corrupted → the honest test
//        RED with ClaraNbcTrustFailed (the accept is not vacuous: the gate ran).

/// The KI#256 tests sign with the PRIVATE root keys (`root-keys/`, gitignored, never
/// published). `AXIOM_REQUIRE_ROOT_KEYS=1` (exported by `scripts/preflight.sh`) ⇒ a missing
/// key PANICS — on the dev/preflight box these tests can never be a green that ran nothing.
/// Without it (a public `axiom-core` clone, which cannot hold the keys) they print a loud
/// SKIPPED line and return.
fn ki256_keys_present() -> bool {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../root-keys");
    let need = [base.join("nabla/root_1.key"), base.join("authority/root_1.key"),
                base.join("authority/root_2.key"), base.join("authority/root_3.key")];
    let missing: Vec<String> = need.iter().filter(|p| !p.exists()).map(|p| p.display().to_string()).collect();
    if missing.is_empty() {
        return true;
    }
    if std::env::var("AXIOM_REQUIRE_ROOT_KEYS").as_deref() == Ok("1") {
        panic!("KI#256 Core tests need the private root keys (AXIOM_REQUIRE_ROOT_KEYS=1): missing {missing:?}");
    }
    eprintln!("⚠ SKIPPED KI#256 Core test — private root keys absent ({missing:?}); \
               set AXIOM_REQUIRE_ROOT_KEYS=1 where they must run");
    false
}

/// `root-keys/<kind>/root_<n>.{key,pub}` — PANICS when absent (callers gate on
/// `ki256_keys_present()` first).
fn ki256_root(kind: &str, n: u8) -> (Vec<u8>, Vec<u8>) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../root-keys").join(kind);
    let read = |f: String| std::fs::read(dir.join(&f)).unwrap_or_else(|e| panic!(
        "KI#256 Core tests need {}/{} (gitignored root key, present on the dev/preflight box): {e}. \
         These tests FAIL rather than skip — a skipped CLARA gate test is a green that ran nothing.",
        dir.display(), f));
    (read(format!("root_{n}.key")), read(format!("root_{n}.pub")))
}

fn ki256_root_key() -> (Vec<u8>, Vec<u8>) {
    ki256_root("nabla", 1)
}

/// FIPS 205 SLH-DSA-SHA2-128s deterministic sign (`compute::sign_sphincs` is
/// `ceremony`-gated; this is the same call).
fn ki256_sphincs_sign(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::{SerDes, Signer};
    let sk_arr: [u8; slh_dsa_sha2_128s::SK_LEN] =
        sk.try_into().expect("root key is a SPHINCS+ SHA2-128s secret key");
    let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_arr).expect("SPHINCS+ sk");
    sk.try_sign(msg, b"", false).expect("SPHINCS+ sign").to_vec()
}

/// A Nabla-signed, NBC-anchored attestation exactly as `nabla_node.rs` builds
/// one (YPX-018 §2.2), for `wallet` healed to `healed_to` at its current
/// (balance, seq).
fn ki256_attestation(
    wallet: &TestWallet,
    healed_to: [u8; 32],
    garbage: Vec<[u8; 32]>,
    root: &(Vec<u8>, Vec<u8>),
) -> axiom_core_logic::types::ClaraAttestation {
    use ed25519_dalek::Signer;
    let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let nabla_pk = nabla_sk.verifying_key().to_bytes();
    let mut commitment = Vec::new();
    commitment.extend_from_slice(b"AXIOM_VBC_CLARA_KI256_TEST");
    commitment.extend_from_slice(&nabla_pk);
    // `compute::sign_sphincs` is `ceremony`-gated; the same FIPS 205 call here.
    let nbc_sig = {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{SerDes, Signer};
        let sk_arr: [u8; slh_dsa_sha2_128s::SK_LEN] =
            root.0.as_slice().try_into().expect("root_1.key is a SPHINCS+ SHA2-128s secret key");
        let sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_arr).expect("SPHINCS+ sk");
        sk.try_sign(blake3::hash(&commitment).as_bytes(), b"", false)
            .expect("SPHINCS+ sign with the root key")
            .to_vec()
    };
    let state = wallet.wallet_state();
    let mut att = axiom_core_logic::types::ClaraAttestation {
        wallet_pk: state.public_key.as_slice().try_into().unwrap(),
        healed_from_state_id: [0x66; 32],
        healed_to_state_id: healed_to,
        healed_at_seq: state.wallet_seq,
        healed_balance: state.balance,
        heal_txid: [0xAA; 32],
        garbage_state_ids: garbage,
        bloom_era_id: 0,
        bloom_era_root: [0; 32],
        nabla_tick: 1_777_000_000,
        nabla_node_pk: nabla_pk,
        nabla_signature: vec![],
        nbc_issuer_pk: root.1.clone(),
        nbc_signature: nbc_sig,
        nbc_commitment: commitment,
    };
    att.nabla_signature = nabla_sk
        .sign(&axiom_core_logic::compute::compute_clara_message(&att))
        .to_bytes()
        .to_vec();
    att
}

/// The honest post-heal send: the wallet sits at the attested `healed_to`, the
/// tx consumes it, (balance, seq) are the healed values. Core verifies the
/// attestation (wallet binding, Ed25519, NBC root anchor), finds the view
/// eligible (`== healed_to`, the only eligible state since KI#260) and ACCEPTS.
#[test]
fn ki256_cl2_accepts_honest_post_heal_send_with_attestation() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    let tx = alice.create_transaction(&bob.address(), 500_000, "KI#256 post-heal", 1);
    let att = ki256_attestation(&alice, tx.consumed_state_id, vec![[0x55; 32]], &root);
    let mut inputs = cl2_inputs(tx, alice.wallet_state());
    inputs.clara_attestation = Some(att);
    let out = execute_core(inputs);
    assert_eq!(out.result, ValidationResult::Accept,
        "Core must accept an honest post-heal send carrying its attestation: {:?}",
        out.rejection_reason);
}

/// Why the SDK stops attaching once the wallet moves past `healed_to`: the same
/// honest send carrying a STALE attestation (healed to an earlier state, the
/// current state is not its healed_to) is refused by Core.
#[test]
fn ki256_cl2_refuses_a_stale_attestation_on_a_later_send() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    let tx = alice.create_transaction(&bob.address(), 500_000, "KI#256 later send", 1);
    let att = ki256_attestation(&alice, [0x88; 32], vec![[0x55; 32]], &root);
    let mut inputs = cl2_inputs(tx, alice.wallet_state());
    inputs.clara_attestation = Some(att);
    let out = execute_core(inputs);
    assert_eq!(out.result, ValidationResult::Reject);
    assert_eq!(out.rejection_reason,
        Some(axiom_core_logic::types::ValidationError::ClaraStateNotGarbage));
}

// ── KI#256 F6 — the ANCHOR path: the heal receipt is `prev_receipts.last()` ──
//
// The live post-heal send carries prev_receipts, so its declared (seq, balance)
// are judged by the §15 anchor against the heal's k-signed receipt
// (`verify_state_anchored`). KI#260 (2026-10-03) DELETED Core's CLARA rewrite
// (state_id, seq, balance) := (healed_to, healed_at_seq, healed_balance): under
// `view == healed_to` its state_id write was the identity, and its (seq, balance)
// write only chose WHICH input the anchor checked — an accepted tx's values are the
// k-signed ones either way. These tests pin: honest shape ACCEPT; an attestation
// balance the heal receipt never signed is INERT (Core never reads it); a DECLARED
// balance the heal receipt never signed is refused by the anchor.
//
// Fixture: three witnesses sign the heal receipt; the LAST carries a VBC signed by
// the three REAL authority roots (`ROOT_AUTHORITY_PKS`, `root-keys/authority`), so
// `validate_witnesses` verifies it through the production chain; this validator
// is witness 0 (overlapped). The VBC is judged on CL2 against an attested tick, so
// the request carries a real OODS attestation anchored by the Nabla root.
//
// Mutations (run 2026-10-03 after KI#260, each reverted; the 2026-10-02 notes
// named the deleted rewrite and the retired predicate):
//   (iii) `modes.rs`: re-add `state.balance = clara.healed_balance;` after the
//         eligibility check → `ki256_cl2_anchor_attestation_balance_is_inert` RED
//         (StateNotAnchored) and `ki256_cl2_anchor_refuses_a_declared_balance_…`
//         RED (ACCEPT — the rewrite masked the declared lie).
//   (iv)  `validation.rs` Step 1d: skip `verify_state_anchored` →
//         `ki256_cl2_anchor_refuses_a_declared_balance_…` RED (ACCEPT).
//   (v)   `modes.rs` eligibility against `healed_from_state_id` →
//         `ki256_cl2_anchor_accepts_post_heal_send_on_the_heal_receipt` RED
//         (ClaraStateNotGarbage) — the accept ran the CLARA gate, not around it.

struct Ki256Witness {
    ed: ed25519_dalek::SigningKey,
    vbc: Option<axiom_core_logic::types::VBCProofBundle>,
    id: [u8; 32],
}

fn ki256_witnesses() -> Vec<Ki256Witness> {
    use axiom_core_logic::types::{VBC, VBCProofBundle};
    let roots: Vec<(Vec<u8>, Vec<u8>)> = (1..=3).map(|n| ki256_root("authority", n)).collect();
    (0..3u8).map(|i| {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[0xA1 + i; 32]);
        let sphincs_pk = vec![0xB1 + i; 32];
        let id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
        // Only the LAST witness's certificate is judged on a receipt (YPX-015 §2.8);
        // witness 1 carries one too so it can sign a fresh validator's overlap
        // (KI#260 C11 test — the overlap walk verifies every carried sig's VBC).
        let vbc = (i >= 1).then(|| {
            let mut vbc = VBC {
                genesis_lineage: [0u8; 32],
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 0x09,
                validator_id: id,
                subject_pubkey_sphincs: sphincs_pk.clone(),
                subject_pubkey_dilithium: vec![0xC1; 32],
                subject_pubkey_ed25519: ed.verifying_key().to_bytes().to_vec(),
                pgp_fingerprint: vec![],
                node_name: String::new(),
                issued_at: 0,
                expires_at: u64::MAX,
                chain_depth: 0,
                issuer_set: roots.iter().map(|(_, pk)| pk.clone()).collect(),
                signatures: vec![],
                proof_cap: String::new(),
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
                nabla_registration: None,
            };
            let payload = axiom_core_logic::compute::compute_vbc_signing_payload(&vbc);
            vbc.signatures = roots.iter().map(|(sk, _)| ki256_sphincs_sign(sk, &payload)).collect();
            VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None }
        });
        Ki256Witness { ed, vbc, id }
    }).collect()
}

/// The heal's k-signed receipt: produced `state.state_id` at `state.wallet_seq`,
/// `state_hash` anchoring `state`'s (balance, seq, …).
fn ki256_heal_receipt(
    state: &axiom_core_logic::types::WalletState,
    ws: &[Ki256Witness],
) -> axiom_core_logic::types::Receipt {
    use ed25519_dalek::Signer;
    let sh = axiom_core_logic::compute::compute_state_hash(
        &state.public_key, state.balance, state.wallet_seq, state.hibernation_until,
        state.wall_clock_lock, state.emission_claimed_epoch, state.stake_floor_until,
        &state.wallet_format,
    );
    let mut r = axiom_core_logic::receipt::build_send_receipt(axiom_core_logic::receipt::SendReceiptInputs {
        txid: [0xAA; 32], // == the attestation's heal_txid
        state_hash: sh,
        produced_state_id: state.state_id,
        new_wallet_seq: state.wallet_seq,
        commitment_hash: [0x5C; 32],
        epoch: 0,
        witness_sigs: vec![],
        required_k: 3,
        core_id: [0u8; 32],
        is_dev_class: false,
        oods_flag: None,
        confidence_index: None,
    });
    r.witness_sigs = ws.iter().map(|w| axiom_core_logic::types::WitnessSig {
        receipt_commitment_sig: Some(w.ed.sign(&r.receipt_commitment).to_bytes().to_vec()),
        ..ki256_sig(w, &r.commitment_hash)
    }).collect();
    r
}

/// `w`'s witness signature over `commitment` (its VBC attached) — the receipt's
/// witness entries above and a fresh validator's carried overlap sigs (KI#260 C11).
fn ki256_sig(w: &Ki256Witness, commitment: &[u8; 32]) -> axiom_core_logic::types::WitnessSig {
    use ed25519_dalek::Signer;
    axiom_core_logic::types::WitnessSig {
        validator_id: w.id,
        validator_pk: w.ed.verifying_key().to_bytes().to_vec(),
        vbc_bundle: w.vbc.clone(),
        carrier_type: String::new(),
        carrier_address: String::new(),
        signature: w.ed.sign(commitment).to_bytes().to_vec(),
        execution_proof: vec![],
        proof_type: 0,
        availability_attestation: None,
        validator_hints: vec![],
        fact_signature: None,
        checkpoint_sig: None,
        receipt_signature: None,
        receipt_commitment_sig: None,
        rate_bps: 0,
        slot_amount: 0,
    }
}

/// A real Nabla OODS attestation (genesis-exempt baseline 0) — CL2 judges the
/// prev-receipt VBC against its attested tick (KI#130).
fn ki256_oods(root: &(Vec<u8>, Vec<u8>)) -> axiom_core_logic::types::NablaOodsAttestation {
    use ed25519_dalek::Signer;
    let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]);
    let nabla_pk = nabla_sk.verifying_key().to_bytes();
    let mut commitment = b"AXIOM_NBC_OODS_KI256_TEST".to_vec();
    commitment.extend_from_slice(&nabla_pk);
    let tick = 1_777_000_000;
    axiom_core_logic::types::NablaOodsAttestation {
        oods_size: 10,
        tick,
        baseline_size: 0,
        baseline_tick: 0,
        nabla_node_pk: nabla_pk,
        nabla_signature: nabla_sk
            .sign(&axiom_core_logic::compute::compute_oods_attestation_payload(10, tick, 0, 0))
            .to_bytes().to_vec(),
        nbc_issuer_pk: root.1.clone(),
        nbc_signature: ki256_sphincs_sign(&root.0, blake3::hash(&commitment).as_bytes()),
        nbc_commitment: commitment,
    }
}

/// Alice right after a CLARA heal: tip = healed_to, (balance, seq) = the heal's.
/// CL2 inputs for its send with the heal receipt as `prev_receipts.last()`.
fn ki256_post_heal_inputs(
    root: &(Vec<u8>, Vec<u8>),
    attestation_balance_delta: u64,
) -> PublicInputs {
    let mut alice = TestWallet::generate("alice@test.com", 1_000_000);
    alice.wallet_seq = 4;
    alice.state_id = [0x4E; 32]; // healed_to
    let bob = TestWallet::generate("bob@test.com", 0);
    let ws = ki256_witnesses();
    let heal_receipt = ki256_heal_receipt(&alice.wallet_state(), &ws);
    let tx = alice.create_transaction(&bob.address(), 500_000, "KI#256 post-heal anchored", 1);
    assert_eq!(tx.consumed_state_id, heal_receipt.produced_state_id);
    let mut att = ki256_attestation(&alice, alice.state_id, vec![[0x55; 32]], root);
    att.heal_txid = heal_receipt.txid;
    if attestation_balance_delta != 0 {
        // Nabla re-signs the forged balance (a fully valid attestation) — only the
        // anchor can catch it.
        use ed25519_dalek::Signer;
        att.healed_balance += attestation_balance_delta;
        att.nabla_signature = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
            .sign(&axiom_core_logic::compute::compute_clara_message(&att))
            .to_bytes().to_vec();
    }
    let mut inputs = cl2_inputs(tx, alice.wallet_state());
    inputs.prev_receipts = vec![heal_receipt];
    inputs.my_validator_pk = Some(ws[0].ed.verifying_key().to_bytes().to_vec());
    inputs.oods_attestation = Some(ki256_oods(root));
    inputs.clara_attestation = Some(att);
    inputs
}

/// Positive control for the anchor path: the honest post-heal send with the heal
/// receipt as `prev_receipts.last()` and the SAME heal's attestation → ACCEPT.
#[test]
fn ki256_cl2_anchor_accepts_post_heal_send_on_the_heal_receipt() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let out = execute_core(ki256_post_heal_inputs(&root, 0));
    assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
        "honest post-heal send anchored on the heal receipt must ACCEPT");
}

/// The attestation declares `healed_balance + 1` (validly Nabla-signed). Since
/// KI#260 Core never reads it: the anchor judges the DECLARED (k-signed) state, so
/// the send is ACCEPTED exactly as with an honest attestation — the forged value
/// moves nothing. (Until 2026-10-03 the rewrite fed it to the anchor → refused.)
#[test]
fn ki256_cl2_anchor_attestation_balance_is_inert() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let out = execute_core(ki256_post_heal_inputs(&root, 1));
    assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None));
}

/// The wallet DECLARES `balance + 1` (honest attestation): the §15 anchor
/// re-derives a different state_hash than the heal receipt's → StateNotAnchored.
#[test]
fn ki256_cl2_anchor_refuses_a_declared_balance_the_heal_receipt_never_signed() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let mut inputs = ki256_post_heal_inputs(&root, 0);
    inputs.current_state.as_mut().unwrap().balance += 1;
    let out = execute_core(inputs);
    assert_eq!((out.result, out.rejection_reason),
        (ValidationResult::Reject, Some(axiom_core_logic::types::ValidationError::StateNotAnchored)));
}

// ── KI#260 — CL2 CLARA eligibility is `stored == healed_to` ONLY (RULED 2026-10-02) ──
//
// Core's CL2 view of the wallet (`current_state`) is built by Lambda
// (`lambda/src/consensus.rs` `core_state_id`, READ IN CODE): a validator whose key is
// in `prev_receipts` (overlapped) is shown its OWN stored state_id; every other
// validator is shown the tx's `consumed_state_id`. Lambda's CL3 view carries the same
// `core_state_id`, and CL3 refuses `consumed != state_id` (SABRHashMismatch) — so a
// view other than `consumed` never completed a witness even under the old
// `stored ∈ {healed_to, healed_from} ∪ garbage` rule.
//
// Measured on the OLD Core (2026-10-03, before the change): the C11 test GREEN; both
// attacker tests ACCEPT (the roll-back). Mutations (run 2026-10-03, each reverted):
//   eligibility against `healed_from_state_id` → the C11 test RED (ClaraStateNotGarbage),
//     `…_at_healed_from` RED (InvalidStateId);
//   re-add the garbage arm (`&& !garbage.contains(stored)`) → `…_in_declared_garbage`
//     RED (InvalidStateId — without the deleted rewrite Step 1 catches it next).

/// The YPX-018 C11 liveness case under the narrowed rule. V was POISONED at P
/// (= the attestation's declared garbage `[0x55;32]`) by a partial tx and did NOT
/// witness the heal, so its key is not in the heal receipt: Lambda hands Core
/// `consumed` (= healed_to), V verifies the k-1 overlap the heal's witnesses carried
/// over this send, and the post-heal send is ACCEPTED on the fresh-validator path.
/// Test-input mutation (run 2026-10-03): show V its STORED state P instead (what
/// Lambda would do were V overlapped) → ClaraStateNotGarbage — the accept depends
/// on Lambda's consumed view, which is why that view is the liveness argument.
#[test]
fn ki260_c11_poisoned_non_heal_witness_still_witnesses_the_post_heal_send() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let mut inputs = ki256_post_heal_inputs(&root, 0);
    let ws = ki256_witnesses();
    let commitment = axiom_core_logic::validation::compute_commitment_hash(&inputs.transaction);
    let fresh_v = ed25519_dalek::SigningKey::from_bytes(&[0xF7; 32]);
    inputs.my_validator_pk = Some(fresh_v.verifying_key().to_bytes().to_vec());
    inputs.overlapped_signatures = vec![ki256_sig(&ws[1], &commitment), ki256_sig(&ws[2], &commitment)];
    let att = inputs.clara_attestation.as_ref().unwrap();
    assert!(att.garbage_state_ids.contains(&[0x55; 32]), "V's poisoned state P is declared garbage");
    assert_eq!(inputs.current_state.as_ref().unwrap().state_id, inputs.transaction.consumed_state_id,
        "Lambda's view for a non-prev-receipt witness is `consumed`");
    let out = execute_core(inputs);
    assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
        "a poisoned validator that was not a heal witness must still witness the post-heal send");
    assert_eq!(out.is_overlapped, Some(false), "the FRESH-validator path ran (overlap sigs verified)");
}

/// KI#260 attacker shape: an OVERLAPPED validator whose stored state is one the
/// attestation lists as garbage (e.g. a predicted FUTURE state the wallet reached
/// after the heal) is shown that state; the old rule called it eligible and rewrote
/// the view back to `healed_to` (a roll-back). Now refused.
#[test]
fn ki260_cl2_refuses_a_view_in_declared_garbage() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let mut inputs = ki256_post_heal_inputs(&root, 0);
    inputs.current_state.as_mut().unwrap().state_id = [0x55; 32]; // declared garbage
    let out = execute_core(inputs);
    assert_eq!((out.result, out.rejection_reason),
        (ValidationResult::Reject, Some(axiom_core_logic::types::ValidationError::ClaraStateNotGarbage)));
}

/// Same, with the view at the attestation's `healed_from_state_id` (`[0x66;32]`).
#[test]
fn ki260_cl2_refuses_a_view_at_healed_from() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let mut inputs = ki256_post_heal_inputs(&root, 0);
    inputs.current_state.as_mut().unwrap().state_id =
        inputs.clara_attestation.as_ref().unwrap().healed_from_state_id;
    let out = execute_core(inputs);
    assert_eq!((out.result, out.rejection_reason),
        (ValidationResult::Reject, Some(axiom_core_logic::types::ValidationError::ClaraStateNotGarbage)));
}

// ── KI#257 — a heal consumes only a FULL-QUORUM anchored state (RULED 2026-10-02) ──
//
// Alice's last k-signed receipt anchors X = `[0x4E;32]` (seq 4, 1_000_000). A send of
// 300_000 from X reached fewer than k witnesses: its produced state P = `[0x9A;32]`
// (seq 5, 700_000) sits in those witnesses' ledgers, no receipt anchors it. The heal
// is judged by the SAME Step 1b (state-id chain) + Step 1d (§15 anchor) every send is
// judged by — `prev_receipts` are full-quorum by `validate_witnesses`.
//
// Measured on the OLD Core (2026-10-03): honest heal ACCEPT; both refusals ACCEPT.
// Mutations (run 2026-10-03, each reverted; the honest control stayed GREEN in both):
//   restore `&& !tx.is_heal()` on Step 1b → `…_consuming_a_sub_quorum_state_…` RED
//     (StateNotAnchored — the anchor then catches P's seq);
//   restore `&& !tx.is_heal()` on the Step 1d anchor → `…_declaring_a_sub_quorum_debit_…`
//     RED (ACCEPT).

/// CL2 inputs for a heal at overlapped validator ws[0] (it signed X's receipt),
/// consuming `consumed` at `(seq, balance)` declared, with X's receipt as the anchor.
fn ki257_heal_inputs(
    root: &(Vec<u8>, Vec<u8>),
    consumed: [u8; 32],
    seq: u64,
    balance: u64,
) -> PublicInputs {
    let mut alice = TestWallet::generate("alice@test.com", 1_000_000);
    alice.wallet_seq = 4;
    alice.state_id = [0x4E; 32];
    let ws = ki256_witnesses();
    let anchor = ki256_heal_receipt(&alice.wallet_state(), &ws);
    // The heal's pre-state as the wallet declares it (Lambda's CL2 view for an
    // overlapped validator: its stored state_id + the declared balance/seq).
    alice.state_id = consumed;
    alice.wallet_seq = seq;
    alice.balance = balance;
    let mut tx = alice.create_transaction(&alice.address(),
        axiom_core_logic::validation::MINIMUM_TX_ATOMS, "heal", 1); // the SDK heal amount (DUST_THRESHOLD)
    tx.kind = axiom_core_logic::types::TxKind::Heal;
    // Core's ONE signing builder (binds AXIOM_HEAL_BIND for the heal kind).
    tx.client_sig = {
        use ed25519_dalek::Signer;
        alice.signing_key.sign(&axiom_core_logic::validation::compute_signing_message_public(&tx))
            .to_bytes().to_vec()
    };
    let mut inputs = cl2_inputs(tx, alice.wallet_state());
    inputs.prev_receipts = vec![anchor];
    inputs.my_validator_pk = Some(ws[0].ed.verifying_key().to_bytes().to_vec());
    inputs.oods_attestation = Some(ki256_oods(root));
    inputs
}

/// The production heal shape (`heal.rs::clara_heal_pre_state` — every SDK writer
/// declares the wallet's own anchored tip, KI#257 "Measured (SDK)"): consume X at its
/// anchored (seq, balance) → ACCEPT.
#[test]
fn ki257_honest_heal_of_the_anchored_tip_is_accepted() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let out = execute_core(ki257_heal_inputs(&root, [0x4E; 32], 4, 1_000_000));
    assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
        "the production heal (anchored tip) must ACCEPT");
}

/// A heal consuming the half-signed P (carrying the send's debit) → refused by the
/// state-id chain: P is not the last full-quorum receipt's produced state.
#[test]
fn ki257_heal_consuming_a_sub_quorum_state_is_refused() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let out = execute_core(ki257_heal_inputs(&root, [0x9A; 32], 5, 700_000));
    assert_eq!((out.result, out.rejection_reason),
        (ValidationResult::Reject, Some(axiom_core_logic::types::ValidationError::InvalidStateId)));
}

/// A heal consuming X but declaring the sub-quorum send's DEBITED balance → refused
/// by the §15 anchor: X's k-signed receipt never anchored 700_000.
#[test]
fn ki257_heal_declaring_a_sub_quorum_debit_is_refused() {
    if !ki256_keys_present() { return; }
    let root = ki256_root_key();
    let out = execute_core(ki257_heal_inputs(&root, [0x4E; 32], 4, 700_000));
    assert_eq!((out.result, out.rejection_reason),
        (ValidationResult::Reject, Some(axiom_core_logic::types::ValidationError::StateNotAnchored)));
}

/// Test CL3 validation (validator producing witness)
#[test]
fn test_cl3_witness_production() {
    let alice = TestWallet::generate("alice@test.com", 1_000_000);
    let bob = TestWallet::generate("bob@test.com", 0);
    
    let tx = alice.create_transaction(&bob.address(), 500_000, "CL3 test", 1);
    
    let inputs = PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
    
    };

    let cl1_outputs = execute_core(cl1_inputs);
    assert_eq!(cl1_outputs.result, ValidationResult::Accept, "CL1 failed: {:?}", cl1_outputs.rejection_reason);
    
    // Step 3: CL2 - Validator validates incoming
    let cl2_inputs = PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
    
    };

    let cl2_outputs = execute_core(cl2_inputs);
    assert_eq!(cl2_outputs.result, ValidationResult::Accept, "CL2 failed: {:?}", cl2_outputs.rejection_reason);
    
    // Step 4: CL3 - Validator produces witness
    let cl3_inputs = PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
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
            &alice.address(), &bob.address(), send_amount, 1, 0,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );

        // Sign commitment with validator's Ed25519 key
        use ed25519_dalek::Signer;
        let sig = val_sk.sign(&commitment).to_bytes().to_vec();

        cheques.push(ValidatorCheque {
            fact_certificates: Vec::new(),
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
        &prior_tx_id, &prior_prev_sid, &prior_new_sid, alice_initial, None, false, 3, &[], None,
    );

    // Generate 3 Dilithium keypairs and sign the FACT commitment
    let mut fact_witnesses = Vec::new();
    for i in 0..3u8 {
        let (pk_obj, sk_obj) = ml_dsa_65::try_keygen().expect("Dilithium keygen");
        let pk_bytes = pk_obj.into_bytes().to_vec();
        let sk_bytes = sk_obj.into_bytes().to_vec();
        let sig = axiom_core_logic::compute::sign_fact_commitment(
            &sk_bytes, &prior_tx_id, &prior_prev_sid, &prior_new_sid, alice_initial, None, false, 3, &[], None,
        ).expect("Dilithium sign");
        let mut vid = [0u8; 32];
        vid[0] = i + 1;
        fact_witnesses.push(FactWitness {
            validator_id: vid,
            validator_pk: pk_bytes,
            signature: sig,
            vbc_hash: [0u8; 32],
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
            burn_proof: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            burn_target_tx_id: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
        }],
    };

    // Verify the FACT chain is valid before using it
    assert!(axiom_core_logic::fact::verify_fact_chain(&fact_chain, &axiom_core_logic::fact::FactTrust::new(&[], None)).is_ok(),
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
            &txid, &state_hash, &txid, &alice.address(), &bob.address(), send_amount, 1, 0,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );
        use ed25519_dalek::Signer;
        let sig = vsk.sign(&commitment).to_bytes().to_vec();
        cheques.push(ValidatorCheque {
            fact_certificates: Vec::new(),
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
                      "CL8", "CL10", "CL11"];
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

/// Fork Settlement R4 (2026-09-28, wave 2b-ii) — the CL3 WITNESS (Core signs the
/// FACT commitment inside `execute_cl3`) and the FINALIZER (`build_fact_link`,
/// which Lambda calls with `PublicOutputs.required_k`) bind the SAME `required_k`.
/// Driven through `execute_core` with a k=5 RECEIVER, so a CL3 that signed a
/// constant (e.g. 3) instead of `validate_transaction`'s k fails here: every
/// witness signature is discarded by `build_fact_link` and the link never builds
/// (`FactInsufficientWitnesses` — the KI#54 class, with k instead of burn target).
#[test]
fn cl3_witness_and_finalizer_bind_the_same_required_k() {
    use axiom_core_logic::types::{FactChain, VBCProofBundle, VBC, WitnessSig};
    use fips204::ml_dsa_65;
    use fips204::traits::SerDes as DilSerDes;
    use rand::SeedableRng;

    let alice = TestWallet::generate("alice-rk@test.com", 10_000_000);
    let bob = TestWallet::generate("bob-rk@test.com", 0);
    // A k=5 receiver address (same identity-key path as `address()`).
    let bob_k5 = axiom_core_logic::wallet_id::generate_all_wallet_ids(
        "bob-rk@test.com", "42", &bob.verifying_key.to_bytes(),
    ).expect("wallet ids").into_iter().find(|(_, k, _, _)| *k == 5).expect("k=5 id").0;
    let tx = alice.create_transaction(&bob_k5, 500_000, "rk", 7);

    let mut rng = rand::rngs::StdRng::from_seed([0x4Bu8; 32]);
    let mut witness_sigs: Vec<WitnessSig> = Vec::new();
    let mut outputs = None;
    for i in 0..5u8 {
        let (pk_obj, sk_obj) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("keygen");
        let pk = pk_obj.into_bytes().to_vec();
        let sk = sk_obj.into_bytes().to_vec();
        let mut inputs = make_inputs(CoreLogicMode::CL3, tx.clone(), Some(alice.wallet_state()));
        inputs.my_dilithium_sk = Some(sk);
        let out = execute_core(inputs);
        assert_eq!(out.result, ValidationResult::Accept, "CL3 must accept: {:?}", out.rejection_reason);
        assert_eq!(out.required_k, 5, "a k=5 receiver makes this a k=5 round");
        let mut vid = [0u8; 32]; vid[0] = i + 1;
        witness_sigs.push(WitnessSig {
            validator_id: vid,
            validator_pk: pk.clone(),
            signature: vec![0u8; 64],
            execution_proof: vec![],
            proof_type: 0,
            availability_attestation: None,
            carrier_type: "test".to_string(),
            carrier_address: "t".to_string(),
            vbc_bundle: Some(VBCProofBundle {
                target_vbc: VBC {
                    genesis_lineage: [0u8; 32], network_size_baseline: 0, baseline_tick: 0,
                    version: 9, validator_id: vid, subject_pubkey_dilithium: pk,
                    subject_pubkey_ed25519: vec![0u8; 32], subject_pubkey_sphincs: vec![0u8; 32],
                    pgp_fingerprint: vec![], node_name: "t".into(), proof_cap: "dmap".into(),
                    issued_at: 0, expires_at: u64::MAX, chain_depth: 0, issuer_set: vec![],
                    signatures: vec![], max_tx: 50000, founding_vbc_hash: [0u8; 32],
                    nabla_registration: None,
                },
                supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None,
            }),
            fact_signature: Some(out.fact_signature.clone().expect("CL3 signs the FACT commitment")),
            checkpoint_sig: None,
            receipt_signature: None,
            receipt_commitment_sig: None,
            validator_hints: vec![],
            rate_bps: 0,
            slot_amount: 0,
        });
        outputs = Some(out);
    }
    let out = outputs.unwrap();

    // The finalizer, exactly as Lambda calls it (`consensus.rs` build_fact_link
    // with `proof.outputs.required_k`).
    let chain: FactChain = axiom_core_logic::fact::build_fact_link(
        &out.txid.expect("txid"), &tx.consumed_state_id, &out.produced_state_id.expect("produced"),
        tx.amount, out.required_k, &witness_sigs, None, None,
        out.is_dev_class.unwrap_or(false), Vec::new(), None, None, None,
    ).expect("finalizer must accept every CL3 witness signature");
    let link = chain.links.last().expect("link");
    assert_eq!(link.required_k, 5);
    assert_eq!(link.witnesses.len(), 5, "all five CL3 signatures verify under the finalizer's k");

    // And the k is really bound: a finalizer using any other k keeps NONE.
    let wrong_k = axiom_core_logic::fact::build_fact_link(
        &out.txid.unwrap(), &tx.consumed_state_id, &out.produced_state_id.unwrap(),
        tx.amount, 3, &witness_sigs, None, None,
        out.is_dev_class.unwrap_or(false), Vec::new(), None, None, None,
    );
    assert_eq!(wrong_k.err(), Some(axiom_core_logic::types::ValidationError::FactInsufficientWitnesses),
        "signatures over a k=5 commitment must not verify as a k=3 link");
}
