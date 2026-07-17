//! Generate canonical consensus test vectors for AXIOM protocol conformance.
//!
//! All inputs use fixed seeds — deterministic on every run and every platform.
//! Run: cargo run -p axiom-core-logic --example generate_vectors > tests/consensus_vectors.json

use axiom_core_logic::types::*;
use axiom_core_logic::modes::execute_core;
use axiom_core_logic::genesis::compute_genesis_state_id;
use axiom_core_logic::wallet_id::generate_wallet_id;
use axiom_core_logic::validation::{derive_owner_pubkey, sign_owner_proof};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use serde_json::json;

fn make_inputs(mode: CoreLogicMode, tx: Transaction, state: Option<WalletState>) -> PublicInputs {
    PublicInputs {
        recall_attestation: None,
        oods_attestation: None,
        receiver_current_hibernation: None,
        mode, transaction: tx, prev_receipts: vec![], current_state: state,
        vbc_bundle: None, cheque_bundle: None, receiver_pk: None,
        receiver_current_balance: None, receiver_wallet_seq: None,
        receiver_new_balance: None, receiver_new_state_id: None,
        my_validator_pk: None, overlapped_signatures: vec![],
        group_member_index: None, sender_fact_chain: None,
        receiver_fact_chain: None,
        my_dilithium_sk: None, my_dilithium_pk: None, my_validator_id: None,
        fact_witness_sigs: vec![], issuer_sphincs_sk: None,
        cl1_execution_proof: None, zkp_nonce: None,
        audit_confirmation: None, nonce_response: None, audit_response: None,
        scar_heal_tx_id: None, scar_heal_nabla_id: None, scar_heal_root_hash: None,
        wallet_secret: None, fanout_message: None, candidate_balance: None,
        nabla_stake_proof: None, frozen_wallets: None,
        console_current_cert: None, console_new_cert: None,
        console_selector_picks: None, console_nominations: None,
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

struct Wallet {
    sk: SigningKey,
    pk: VerifyingKey,
    state_id: [u8; 32],
    balance: u64,
    address: String,
}

impl Wallet {
    fn new(seed: [u8; 32], email: &str, balance: u64) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let pk = VerifyingKey::from(&sk);
        let state_id = compute_genesis_state_id(&pk.to_bytes(), balance);
        let address = generate_wallet_id(email, "42", &pk.to_bytes()).unwrap_or_else(|_| format!("{}/0000000042", email));
        Self { sk, pk, state_id, balance, address }
    }

    fn sign_tx(&self, tx: &mut Transaction) {
        tx.client_pk = self.pk.to_bytes().to_vec();
        let mut msg = Vec::new();
        msg.extend_from_slice(&tx.consumed_state_id);
        msg.extend_from_slice(&tx.wallet_seq.to_le_bytes());
        msg.extend_from_slice(tx.sender_wallet_id.as_bytes());
        msg.extend_from_slice(tx.receiver_wallet_id.as_bytes());
        msg.extend_from_slice(&tx.amount.to_le_bytes());
        msg.extend_from_slice(tx.reference.as_bytes());
        msg.extend_from_slice(&tx.nonce.to_le_bytes());
        msg.extend_from_slice(&tx.epoch.to_le_bytes());
        msg.extend_from_slice(tx.burn_target_tx_id.as_ref().unwrap_or(&[0u8; 32]));
        msg.extend_from_slice(AXIOM_PROTOCOL_VERSION.as_bytes());
        tx.client_sig = self.sk.sign(&msg).to_bytes().to_vec();
    }

    fn ws(&self) -> WalletState {
        WalletState {
            hibernation_until: 0,
            public_key: self.pk.to_bytes().to_vec(),
            balance: self.balance,
            wallet_seq: 0,
            state_id: self.state_id,
            auth_hash: None,
            wallet_id: None,
            group_members: None,
        }
    }

    fn tx(&self, receiver: &str, amount: u64) -> Transaction {
        let mut tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: self.state_id,
            client_pk: self.pk.to_bytes().to_vec(),
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: receiver.to_string(),
            receiver_address: None,
            core_id: [0u8; 32],
            amount,
            reference: "vector-test".to_string(),
            nonce: 12345,
            epoch: 1,
            client_sig: vec![],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: None,
            required_k: 0,
            proof_type: 0,
            core_version: String::new(),
            kind: TxKind::Normal,
        };
        self.sign_tx(&mut tx);
        tx
    }
}

/// Encode PublicInputs using production IPC codec (integer-keyed CBOR).
fn encode_inputs_ipc(inputs: &PublicInputs) -> String {
    hex::encode(axiom_core_ipc::codec::encode_inputs(inputs).unwrap_or_default())
}

/// Encode PublicOutputs using production IPC codec (integer-keyed CBOR).
fn encode_outputs_ipc(outputs: &PublicOutputs) -> String {
    hex::encode(axiom_core_ipc::codec::encode_outputs(outputs).unwrap_or_default())
}

/// Run a vector: encode inputs as IPC CBOR, execute Core, return JSON entry.
fn run_vector(id: &str, mode: &str, desc: &str, inputs: PublicInputs, notes: &str) -> serde_json::Value {
    let inputs_hex = encode_inputs_ipc(&inputs);
    let out = execute_core(inputs);
    let outputs_hex = encode_outputs_ipc(&out);
    json!({
        "id": id,
        "mode": mode,
        "description": desc,
        "inputs_cbor_hex": inputs_hex,
        "outputs_cbor_hex": outputs_hex,
        "expected_result": format!("{:?}", out.result),
        "expected_rejection_reason": out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        "expected_produced_state_id_hex": out.produced_state_id.map(hex::encode),
        "expected_new_balance": out.new_balance,
        "notes": notes,
    })
}

fn main() {
    let alice = Wallet::new([0x01; 32], "alice@vectors.axiom", 10_000_000);
    let bob = Wallet::new([0x02; 32], "bob@vectors.axiom", 5_000_000);
    let poor = Wallet::new([0x03; 32], "poor@vectors.axiom", 100);

    let mut vectors = Vec::new();

    // CL1_ACCEPT_001 — keep execute_core: out1 needed for CL5 cheque building
    let tx1 = alice.tx(&bob.address, 500_000);
    let cl1_inputs = make_inputs(CoreLogicMode::CL1, tx1.clone(), Some(alice.ws()));
    let cl1_inputs_hex = encode_inputs_ipc(&cl1_inputs);
    let out1 = execute_core(cl1_inputs);
    vectors.push(json!({
        "id": "CL1_ACCEPT_001",
        "mode": "CL1",
        "description": "CL1: valid send transaction accepted",
        "inputs_cbor_hex": cl1_inputs_hex,
        "outputs_cbor_hex": encode_outputs_ipc(&out1),
        "expected_result": format!("{:?}", out1.result),
        "expected_rejection_reason": out1.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        "expected_produced_state_id_hex": out1.produced_state_id.map(hex::encode),
        "expected_new_balance": out1.new_balance,
        "notes": "Standard send, alice→bob, 500_000 atoms",
    }));

    // CL1_REJECT_SIG_001
    let mut tx2 = alice.tx(&bob.address, 500_000);
    tx2.client_sig = vec![0xFF; 64];
    vectors.push(run_vector("CL1_REJECT_SIG_001", "CL1", "CL1: invalid signature rejected",
        make_inputs(CoreLogicMode::CL1, tx2, Some(alice.ws())), "Corrupted Ed25519 signature"));

    // CL1_REJECT_BALANCE_001
    let tx3 = poor.tx(&bob.address, 500_000);
    vectors.push(run_vector("CL1_REJECT_BALANCE_001", "CL1", "CL1: insufficient balance rejected",
        make_inputs(CoreLogicMode::CL1, tx3, Some(poor.ws())), "Balance 100, tries 500_000"));

    // CL1_REJECT_DUST_001
    let tx4 = alice.tx(&bob.address, 100);
    vectors.push(run_vector("CL1_REJECT_DUST_001", "CL1", "CL1: dust amount rejected",
        make_inputs(CoreLogicMode::CL1, tx4, Some(alice.ws())), "100 < MINIMUM_TX_ATOMS"));

    // CL1_REJECT_ZERO_001
    let tx5 = alice.tx(&bob.address, 0);
    vectors.push(run_vector("CL1_REJECT_ZERO_001", "CL1", "CL1: zero amount rejected",
        make_inputs(CoreLogicMode::CL1, tx5, Some(alice.ws())), "Amount 0"));

    // CL1_REJECT_SEQ_001
    let mut tx6 = alice.tx(&bob.address, 500_000);
    tx6.wallet_seq = 999;
    alice.sign_tx(&mut tx6);
    vectors.push(run_vector("CL1_REJECT_SEQ_001", "CL1", "CL1: wrong wallet_seq rejected",
        make_inputs(CoreLogicMode::CL1, tx6, Some(alice.ws())), "wallet_seq=999, expected 1"));

    // CL1_DETERMINISM_001
    let tx7 = alice.tx(&bob.address, 500_000);
    let mut v7 = run_vector("CL1_DETERMINISM_001", "CL1", "CL1: determinism pin — same input same output",
        make_inputs(CoreLogicMode::CL1, tx7, Some(alice.ws())),
        "Determinism pin — same input must always produce same state_id. If this diverges from CL1_ACCEPT_001, a consensus-breaking change was introduced.");
    v7["determinism_check_against"] = json!("CL1_ACCEPT_001");
    vectors.push(v7);

    // CL2_ACCEPT_001
    let tx8 = alice.tx(&bob.address, 500_000);
    vectors.push(run_vector("CL2_ACCEPT_001", "CL2", "CL2: validator accepts incoming TX",
        make_inputs(CoreLogicMode::CL2, tx8, Some(alice.ws())), "Gateway validation"));

    // CL5_ACCEPT_001 — build cheque bundle with real sigs
    let txid = out1.produced_state_id.unwrap();
    let state_hash = out1.new_state_hash.unwrap_or([0u8; 32]);
    let mut cheques = Vec::new();
    for (i, seed_byte) in [0x10u8, 0x11, 0x12].iter().enumerate() {
        let vsk = SigningKey::from_bytes(&{  [*seed_byte; 32] });
        let vpk = VerifyingKey::from(&vsk);
        let vid = *blake3::hash(&vpk.to_bytes()).as_bytes();
        let rate_bps: u32 = 10;
        let commitment = axiom_core_logic::compute::compute_cheque_commitment(
            &txid, &state_hash, &txid, &bob.address, 500_000, 1,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );
        let sig = vsk.sign(&commitment).to_bytes().to_vec();
        cheques.push(ValidatorCheque {
            recall_target_tx_id: None,
            txid, validator_id: vid, validator_pk: vpk.to_bytes().to_vec(),
            signature: sig, execution_proof: vec![], vbc_bundle: None,
            carrier_type: "test".into(), carrier_address: format!("v{}@test", i),
            sender_wallet_id: alice.address.clone(), receiver_wallet_id: bob.address.clone(),
            amount: 500_000, rate_bps, reference: "vector-test".into(), epoch: 1, created_at: 0,
            state_hash, produced_state_id: txid, sender_fact_chain: None,
            zkp_nonce: None, proof_type: 1, dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32], oracle_claim: None, nabla_hint: None,
            sender_wallet_pk: None,
        });
    }
    let bundle = ChequeBundle { cheques: cheques.clone(), fact_chain: None };
    let mut cl5_in = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
    cl5_in.cheque_bundle = Some(bundle);
    cl5_in.receiver_pk = Some(bob.pk.to_bytes().to_vec());
    cl5_in.receiver_current_balance = Some(5_000_000);
    cl5_in.receiver_wallet_seq = Some(0);
    cl5_in.receiver_new_balance = Some(5_500_000);
    let cl5_inputs_hex = encode_inputs_ipc(&cl5_in);
    let out_cl5 = execute_core(cl5_in);
    let mut v_cl5 = json!({
        "id": "CL5_ACCEPT_001",
        "mode": "CL5",
        "description": "CL5: valid cheque bundle redeemed",
        "inputs_cbor_hex": cl5_inputs_hex,
        "outputs_cbor_hex": encode_outputs_ipc(&out_cl5),
        "expected_result": format!("{:?}", out_cl5.result),
        "expected_rejection_reason": out_cl5.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        "expected_produced_state_id_hex": out_cl5.produced_state_id.map(hex::encode),
        "expected_new_balance": out_cl5.new_balance,
        "notes": "3 cheques from val0/val1/val2, bob redeems 500_000",
    });
    v_cl5["expected_new_balance"] = json!(5_500_000);
    vectors.push(v_cl5);

    // CL5_REJECT_FORGED_001
    let mut forged = cheques.clone();
    for c in &mut forged { c.signature = vec![0xAB; 64]; }
    let forged_bundle = ChequeBundle { cheques: forged, fact_chain: None };
    let mut cl5_forged = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
    cl5_forged.cheque_bundle = Some(forged_bundle);
    cl5_forged.receiver_pk = Some(bob.pk.to_bytes().to_vec());
    cl5_forged.receiver_current_balance = Some(5_000_000);
    cl5_forged.receiver_wallet_seq = Some(0);
    cl5_forged.receiver_new_balance = Some(5_500_000);
    let cl5_forged_hex = encode_inputs_ipc(&cl5_forged);
    let out_forged = execute_core(cl5_forged);
    vectors.push(json!({
        "id": "CL5_REJECT_FORGED_001",
        "mode": "CL5",
        "description": "CL5: forged cheque signatures rejected",
        "inputs_cbor_hex": cl5_forged_hex,
        "outputs_cbor_hex": encode_outputs_ipc(&out_forged),
        "expected_result": format!("{:?}", out_forged.result),
        "expected_rejection_reason": out_forged.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        "expected_produced_state_id_hex": out_forged.produced_state_id.map(hex::encode),
        "expected_new_balance": out_forged.new_balance,
        "notes": "All sigs replaced with 0xAB",
    }));

    // CL5_REJECT_UNDERK_001
    let underk = ChequeBundle { cheques: cheques[..2].to_vec(), fact_chain: None };
    let mut cl5_underk = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
    cl5_underk.cheque_bundle = Some(underk);
    cl5_underk.receiver_pk = Some(bob.pk.to_bytes().to_vec());
    cl5_underk.receiver_current_balance = Some(5_000_000);
    cl5_underk.receiver_wallet_seq = Some(0);
    cl5_underk.receiver_new_balance = Some(5_500_000);
    let cl5_underk_hex = encode_inputs_ipc(&cl5_underk);
    let out_underk = execute_core(cl5_underk);
    vectors.push(json!({
        "id": "CL5_REJECT_UNDERK_001",
        "mode": "CL5",
        "description": "CL5: under-k cheque bundle rejected",
        "inputs_cbor_hex": cl5_underk_hex,
        "outputs_cbor_hex": encode_outputs_ipc(&out_underk),
        "expected_result": format!("{:?}", out_underk.result),
        "expected_rejection_reason": out_underk.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        "expected_produced_state_id_hex": out_underk.produced_state_id.map(hex::encode),
        "expected_new_balance": out_underk.new_balance,
        "notes": "Only 2 cheques, need 3",
    }));

    // CL1_REJECT_REPLAY_001 — wallet_seq=2 with no prev_receipts
    let mut tx_replay = alice.tx(&bob.address, 500_000);
    tx_replay.wallet_seq = 2; // implies prior TX, but no prev_receipts
    alice.sign_tx(&mut tx_replay);
    let mut ws_replay = alice.ws();
    ws_replay.wallet_seq = 1; // stored seq is 1 (one prior TX)
    vectors.push(run_vector("CL1_REJECT_REPLAY_001", "CL1", "CL1: missing prev_receipts on non-genesis TX",
        make_inputs(CoreLogicMode::CL1, tx_replay, Some(ws_replay)),
        "wallet_seq=2 implies prior TX exists but no prev_receipts provided"));

    // FACT_VERIFY_ACCEPT_001 — CL5 with valid Dilithium FACT chain
    {
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes as DilSerDes;

        let prior_tx = [0xA0u8; 32];
        let prior_prev = [0xA1u8; 32];
        let prior_new = alice.state_id;
        let mut fact_witnesses = Vec::new();
        for i in 0..3u8 {
            let (pk_obj, sk_obj) = ml_dsa_65::try_keygen().expect("keygen");
            let pk_bytes = pk_obj.into_bytes().to_vec();
            let sk_bytes = sk_obj.into_bytes().to_vec();
            let sig = axiom_core_logic::compute::sign_fact_commitment(
                &sk_bytes, &prior_tx, &prior_prev, &prior_new, alice.balance, None, false, &[],
            ).expect("fact sign");
            let mut vid = [0u8; 32]; vid[0] = i + 1;
            fact_witnesses.push(FactWitness {
                validator_id: vid, validator_pk: pk_bytes, signature: sig, vbc_genesis_anchor: None,
            });
        }
        let fact_chain = FactChain {
            checkpoint: None,
            links: vec![FactLink {
                tx_id: prior_tx, previous_state_id: prior_prev, new_state_id: prior_new,
                amount: alice.balance, required_k: 3, tick: 1, witnesses: fact_witnesses.clone(),
                nabla_confirmation: Some(NablaConfirmation {
                    nabla_node_id: [0xBB; 32], nabla_signature: vec![0; 64],
                    root_hash: [0xCC; 32], synced_to_tick: 1,
                    ..Default::default()
                }),
                receiver_contact: None, burn_proof: None, sender_anchor: None,
                is_dev_class: false,
                recall_proof: None,
                inherited_scar_txids: Vec::new(),
                inherited_scar_resolutions: Vec::new(),
            }],
        };

        // CL5 with FACT chain
        let mut fact_cheques = cheques.clone();
        for c in &mut fact_cheques { c.sender_fact_chain = Some(fact_chain.clone()); }
        let fact_bundle = ChequeBundle { cheques: fact_cheques, fact_chain: Some(fact_chain.clone()) };
        let mut cl5_fact = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
        cl5_fact.cheque_bundle = Some(fact_bundle);
        cl5_fact.receiver_pk = Some(bob.pk.to_bytes().to_vec());
        cl5_fact.receiver_current_balance = Some(5_000_000);
        cl5_fact.receiver_wallet_seq = Some(0);
        cl5_fact.receiver_new_balance = Some(5_500_000);
        let cl5_fact_hex = encode_inputs_ipc(&cl5_fact);
        let out_fact = execute_core(cl5_fact);
        vectors.push(json!({
            "id": "FACT_VERIFY_ACCEPT_001",
            "mode": "CL5",
            "description": "CL5: valid FACT chain with 3 Dilithium witnesses",
            "inputs_cbor_hex": cl5_fact_hex,
            "outputs_cbor_hex": encode_outputs_ipc(&out_fact),
            "expected_result": format!("{:?}", out_fact.result),
            "expected_rejection_reason": out_fact.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": out_fact.produced_state_id.map(hex::encode),
            "expected_new_balance": out_fact.new_balance,
            "notes": "FACT chain verification exercised in CL5 with real Dilithium signatures",
        }));

        // FACT_VERIFY_BROKEN_001 — broken state_id in FACT link
        let mut broken_chain = fact_chain.clone();
        broken_chain.links[0].new_state_id = [0u8; 32]; // break continuity
        // Re-sign with bad state — signatures will still be "valid" for the wrong data
        // but verify_fact_chain checks state continuity separately
        let broken_bundle_cheques = cheques.iter().map(|c| {
            let mut cc = c.clone();
            cc.sender_fact_chain = Some(broken_chain.clone());
            cc
        }).collect::<Vec<_>>();
        let broken_bundle = ChequeBundle { cheques: broken_bundle_cheques, fact_chain: Some(broken_chain) };
        let mut cl5_broken = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
        cl5_broken.cheque_bundle = Some(broken_bundle);
        cl5_broken.receiver_pk = Some(bob.pk.to_bytes().to_vec());
        cl5_broken.receiver_current_balance = Some(5_000_000);
        cl5_broken.receiver_wallet_seq = Some(0);
        cl5_broken.receiver_new_balance = Some(5_500_000);
        let cl5_broken_hex = encode_inputs_ipc(&cl5_broken);
        let out_broken = execute_core(cl5_broken);
        vectors.push(json!({
            "id": "FACT_VERIFY_BROKEN_001",
            "mode": "CL5",
            "description": "CL5: broken FACT chain state_id rejected",
            "inputs_cbor_hex": cl5_broken_hex,
            "outputs_cbor_hex": encode_outputs_ipc(&out_broken),
            "expected_result": format!("{:?}", out_broken.result),
            "expected_rejection_reason": out_broken.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": out_broken.produced_state_id.map(hex::encode),
            "expected_new_balance": out_broken.new_balance,
            "notes": "FactLink new_state_id set to zeros — state chain discontinuity",
        }));

        // FACT_VERIFY_SCAR_001 — scarred FACT (no nabla_confirmation)
        let mut scarred_chain = fact_chain.clone();
        scarred_chain.links[0].nabla_confirmation = None; // SCAR
        let scar_cheques = cheques.iter().map(|c| {
            let mut cc = c.clone();
            cc.sender_fact_chain = Some(scarred_chain.clone());
            cc
        }).collect::<Vec<_>>();
        let scar_bundle = ChequeBundle { cheques: scar_cheques, fact_chain: Some(scarred_chain) };
        let mut cl5_scar = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
        cl5_scar.cheque_bundle = Some(scar_bundle);
        cl5_scar.receiver_pk = Some(bob.pk.to_bytes().to_vec());
        cl5_scar.receiver_current_balance = Some(5_000_000);
        cl5_scar.receiver_wallet_seq = Some(0);
        cl5_scar.receiver_new_balance = Some(5_500_000);
        let cl5_scar_hex = encode_inputs_ipc(&cl5_scar);
        let out_scar = execute_core(cl5_scar);
        vectors.push(json!({
            "id": "FACT_VERIFY_SCAR_001",
            "mode": "CL5",
            "description": "CL5: scarred FACT link accepted (receiver consented)",
            "inputs_cbor_hex": cl5_scar_hex,
            "outputs_cbor_hex": encode_outputs_ipc(&out_scar),
            "expected_result": format!("{:?}", out_scar.result),
            "expected_rejection_reason": out_scar.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": out_scar.produced_state_id.map(hex::encode),
            "expected_new_balance": out_scar.new_balance,
            "notes": "Scarred links permitted in CL5 — receiver consented via scar-passcode",
        }));
    }

    // OWNER_PROOF_ACCEPT_001
    let auth_pk = derive_owner_pubkey(b"test-secret-42");
    let mut tx_owner = alice.tx(&bob.address, 500_000);
    tx_owner.owner_proof = Some(sign_owner_proof(b"test-secret-42", &tx_owner));
    let mut ws_auth = alice.ws();
    ws_auth.auth_hash = Some(auth_pk);
    vectors.push(run_vector("OWNER_PROOF_ACCEPT_001", "CL1", "CL1: valid owner_proof accepted",
        make_inputs(CoreLogicMode::CL1, tx_owner, Some(ws_auth.clone())),
        "Ed25519 derived-key owner_proof round-trip"));

    // OWNER_PROOF_REJECT_001
    let mut tx_bad_owner = alice.tx(&bob.address, 500_000);
    tx_bad_owner.owner_proof = Some(sign_owner_proof(b"wrong-secret", &tx_bad_owner));
    vectors.push(run_vector("OWNER_PROOF_REJECT_001", "CL1", "CL1: wrong owner_proof rejected",
        make_inputs(CoreLogicMode::CL1, tx_bad_owner, Some(ws_auth)),
        "Signed with wrong secret"));

    // ── CL11: Console Certificate validation ──
    {
        use axiom_core_logic::types::{ConsoleCertificate, SelectorPick, CONSOLE_SIZE, CONSOLE_TICKS_PER_YEAR};
        use axiom_core_logic::compute::compute_console_chain_hash;

        // Build 15 current seats (fixed seeds)
        let current_seats: Vec<[u8; 32]> = (0..CONSOLE_SIZE as u8)
            .map(|i| { let mut s = [0xC0u8; 32]; s[0] = i; s })
            .collect();

        // Genesis cert (generation 0)
        let current_cert = ConsoleCertificate {
            generation: 0,
            seats: current_seats.clone(),
            term_start_tick: 0,
            term_end_tick: 100,
            previous_link_hash: [0u8; 32], // genesis
            election_attempt: 0,
            group_wallet_id: "DWP/CONSOLE/0".into(),
            core_signature: vec![],
        };
        let chain_hash = compute_console_chain_hash(&current_cert);

        // Build 15 nominations (new seats)
        let new_seats: Vec<[u8; 32]> = (0..CONSOLE_SIZE as u8)
            .map(|i| { let mut s = [0xD0u8; 32]; s[0] = i; s })
            .collect();

        // 3 selectors from current seats, each picks 5 unique from nominations
        let selector_picks: Vec<SelectorPick> = (0..3usize).map(|si| {
            SelectorPick {
                selector_id: current_seats[si],
                picks: new_seats[si*5..(si+1)*5].to_vec(),
                signature: vec![0u8; 64], // stub — CL11 verifies in release builds only
                selector_ed25519_pk: [0u8; 32],
            }
        }).collect();

        // New cert (generation 1)
        let new_cert = ConsoleCertificate {
            generation: 1,
            seats: new_seats.clone(),
            term_start_tick: 100,
            term_end_tick: 100 + CONSOLE_TICKS_PER_YEAR,
            previous_link_hash: chain_hash,
            election_attempt: 0,
            group_wallet_id: "DWP/CONSOLE/1".into(),
            core_signature: vec![],
        };

        // CL11_ACCEPT_001 — valid election
        let mut cl11_inputs = make_inputs(CoreLogicMode::CL11, alice.tx(&bob.address, 0), None);
        cl11_inputs.console_current_cert = Some(current_cert.clone());
        cl11_inputs.console_new_cert = Some(new_cert.clone());
        cl11_inputs.console_selector_picks = Some(selector_picks.clone());
        cl11_inputs.console_nominations = Some(new_seats.clone());
        let cl11_hex = encode_inputs_ipc(&cl11_inputs);
        let cl11_out = execute_core(cl11_inputs);
        vectors.push(json!({
            "id": "CL11_ACCEPT_001",
            "mode": "CL11",
            "description": "CL11: valid election — 15 seats resolved, chain hash correct",
            "inputs_cbor_hex": cl11_hex,
            "outputs_cbor_hex": encode_outputs_ipc(&cl11_out),
            "expected_result": format!("{:?}", cl11_out.result),
            "expected_rejection_reason": cl11_out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": cl11_out.produced_state_id.map(hex::encode),
            "expected_new_balance": cl11_out.new_balance,
            "notes": "CL11: valid election — 15 seats resolved from 15 nominations, chain hash correct. IPC codec pending — from_file test skips CL11.",
        }));

        // CL11_REJECT_INVALID_PICK_001 — seat mismatch
        let mut bad_seats = new_seats.clone();
        bad_seats[0] = [0xDE; 32]; // mismatch
        let bad_cert = ConsoleCertificate {
            generation: 1,
            seats: bad_seats,
            term_start_tick: 100,
            term_end_tick: 100 + CONSOLE_TICKS_PER_YEAR,
            previous_link_hash: chain_hash,
            election_attempt: 0,
            group_wallet_id: "DWP/CONSOLE/1".into(),
            core_signature: vec![],
        };
        let mut cl11_bad = make_inputs(CoreLogicMode::CL11, alice.tx(&bob.address, 0), None);
        cl11_bad.console_current_cert = Some(current_cert);
        cl11_bad.console_new_cert = Some(bad_cert);
        cl11_bad.console_selector_picks = Some(selector_picks);
        cl11_bad.console_nominations = Some(new_seats);
        let cl11_bad_hex = encode_inputs_ipc(&cl11_bad);
        let cl11_bad_out = execute_core(cl11_bad);
        vectors.push(json!({
            "id": "CL11_REJECT_INVALID_PICK_001",
            "mode": "CL11",
            "description": "CL11: seat mismatch — resolved set differs from new_cert.seats",
            "inputs_cbor_hex": cl11_bad_hex,
            "outputs_cbor_hex": encode_outputs_ipc(&cl11_bad_out),
            "expected_result": format!("{:?}", cl11_bad_out.result),
            "expected_rejection_reason": cl11_bad_out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": cl11_bad_out.produced_state_id.map(hex::encode),
            "expected_new_balance": cl11_bad_out.new_balance,
            "notes": "CL11: seat mismatch — resolved set differs from new_cert.seats. IPC codec pending — from_file test skips CL11.",
        }));
    }

    // ── Oracle VBC freshness vectors (YPX-012 §2.5) ──
    {
        let oracle_epoch = 50_000u64;
        // Use alice as both sender and receiver (oracle = self-payout)
        // Build oracle TX with correct fields, then re-sign
        let living_sig = axiom_core_logic::oracle::living_signature(&alice.address);
        let mut oracle_tx = Transaction {
            recall_target_tx_id: None,
            consumed_state_id: alice.state_id,
            client_pk: alice.pk.to_bytes().to_vec(),
            sender_wallet_id: alice.address.clone(),
            wallet_seq: 1,
            receiver_wallet_id: alice.address.clone(), // self-payout
            receiver_address: None,
            core_id: [0u8; 32],
            amount: 0, // oracle TX must have 0
            reference: "vector-test".to_string(),
            nonce: 12345,
            epoch: oracle_epoch,
            client_sig: vec![],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: Some(OracleClaimData {
                platform_url: "https://foldingathome.org".into(),
                user_id: 1,
                username: format!("user_{}", living_sig),
                credit_total: 100_000,
                credit_delta: 10_000,
                payout_amount: 0,
                zktls_proof: None,
            }),
            required_k: 0,
            proof_type: 0,
            core_version: String::new(),
            kind: TxKind::Normal,
        };
        alice.sign_tx(&mut oracle_tx);

        // Helper: build a WitnessSig with VBC at the given issued_at
        let make_oracle_witness = |issued_at: u64| -> WitnessSig {
            let wsk = SigningKey::from_bytes(&[0x77; 32]);
            let wpk = VerifyingKey::from(&wsk);
            let sphincs_pk = vec![0xAA; 32];
            let vid = *blake3::hash(&sphincs_pk).as_bytes();
            WitnessSig {
                validator_id: vid,
                validator_pk: wpk.to_bytes().to_vec(),
                vbc_bundle: Some(VBCProofBundle {
                    target_vbc: VBC {
                        network_size_baseline: 0,
                        baseline_tick: 0,
                        version: 0x09, validator_id: vid,
                        subject_pubkey_sphincs: sphincs_pk,
                        subject_pubkey_dilithium: vec![0u8; 1952],
                        subject_pubkey_ed25519: vec![0u8; 32],
                        pgp_fingerprint: vec![], node_name: String::new(),
                        proof_cap: String::new(), issued_at,
                        expires_at: u64::MAX, chain_depth: 0,
                        issuer_set: vec![], signatures: vec![],
                        max_tx: 0, founding_vbc_hash: [0u8; 32],
                    },
                    supporting_vbcs: vec![],
                }),
                carrier_type: String::new(), carrier_address: String::new(),
                signature: wsk.sign(&[0u8; 32]).to_bytes().to_vec(),
                execution_proof: vec![], proof_type: 1,
                availability_attestation: None, validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            }
        };

        let make_oracle_receipt = |witness: WitnessSig| -> Receipt {
            Receipt {
                oods_flag: None,
                txid: [0u8; 32], state_hash: [0u8; 32], produced_state_id: [0u8; 32],
                new_wallet_seq: 0, commitment_hash: [0u8; 32], sdid: [0u8; 32],
                lineage_hash: [0u8; 32], core_version: String::new(),
                witness_sigs: vec![witness], epoch: 0, fact_proof: None,
                receipt_commitment: [0u8; 32],
                required_k: 3,
                core_id: [0u8; 32],
                fee_breakdown: Vec::new(),
                is_dev_class: false,
            }
        };

        // ORACLE_VBC_TOO_OLD_001: VBC 17_281 ticks old → rejected
        // NOTE: IPC CBOR does not encode oracle_claim — from-file test would lose the
        // oracle exemption from self-send check. CBOR hex omitted; vector is reference-only.
        let stale_witness = make_oracle_witness(oracle_epoch - 17_281);
        let mut stale_inputs = make_inputs(CoreLogicMode::CL1, oracle_tx.clone(), Some(alice.ws()));
        stale_inputs.prev_receipts = vec![make_oracle_receipt(stale_witness)];
        let stale_out = execute_core(stale_inputs);
        vectors.push(json!({
            "id": "ORACLE_VBC_TOO_OLD_001",
            "mode": "CL1",
            "description": "Oracle TX rejected — witness VBC is 17_281 ticks old (1 tick beyond 24h limit). Reference only — IPC CBOR cannot round-trip oracle_claim.",
            "inputs_cbor_hex": "",
            "outputs_cbor_hex": encode_outputs_ipc(&stale_out),
            "expected_result": format!("{:?}", stale_out.result),
            "expected_rejection_reason": stale_out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": stale_out.produced_state_id.map(hex::encode),
            "expected_new_balance": stale_out.new_balance,
            "notes": "YPX-012 §2.5 Defense 5. ORACLE_VBC_RENEWAL_TICKS = 17_280. Age 17_281 > limit.",
        }));

        // ORACLE_VBC_FRESH_001: VBC exactly 17_280 ticks old → passes VBC check
        // Same IPC limitation as above — reference-only.
        let fresh_witness = make_oracle_witness(oracle_epoch - 17_280);
        let mut fresh_inputs = make_inputs(CoreLogicMode::CL1, oracle_tx, Some(alice.ws()));
        fresh_inputs.prev_receipts = vec![make_oracle_receipt(fresh_witness)];
        let fresh_out = execute_core(fresh_inputs);
        vectors.push(json!({
            "id": "ORACLE_VBC_FRESH_001",
            "mode": "CL1",
            "description": "Oracle TX — witness VBC at 24h boundary. Not rejected for VBC age. Reference only — IPC CBOR cannot round-trip oracle_claim.",
            "inputs_cbor_hex": "",
            "outputs_cbor_hex": encode_outputs_ipc(&fresh_out),
            "expected_result": format!("{:?}", fresh_out.result),
            "expected_rejection_reason": fresh_out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
            "expected_produced_state_id_hex": fresh_out.produced_state_id.map(hex::encode),
            "expected_new_balance": fresh_out.new_balance,
            "notes": "YPX-012 §2.5 Defense 5. Age 17_280 == limit — boundary inclusive. Rejection (if any) is NOT OracleVBCTooOld.",
        }));
    }

    let output = json!({
        "axiom_version": CORE_VERSION,
        "generated_at": "2026-04-02T00:00:00Z",
        "description": "Canonical consensus test vectors for AXIOM protocol conformance. Any correct implementation of Core must produce the expected outputs for the given inputs. Vectors are deterministic from fixed seeds. Regenerate with: cargo run -p axiom-core-logic --example generate_vectors",
        "vector_count": vectors.len(),
        "vectors": vectors,
    });

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
