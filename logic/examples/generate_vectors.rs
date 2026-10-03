//! Generate canonical consensus test vectors for AXIOM protocol conformance.
//!
//! All inputs use fixed seeds — deterministic on every run and every platform —
//! EXCEPT the subject keys of root-certified witnesses, which derive from the
//! three root secrets (KI#49 D1, `witness_subject_seed`): a root-signed
//! credential whose secret is public would be usable on the network.
//! Run: cargo run -p axiom-core-logic --example generate_vectors > tests/consensus_vectors.json

use axiom_core_logic::types::*;
use axiom_core_logic::modes::execute_core;
use axiom_core_logic::genesis::compute_genesis_state_id;
use axiom_core_logic::wallet_id::generate_wallet_id;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use serde_json::json;

fn make_inputs(mode: CoreLogicMode, tx: Transaction, state: Option<WalletState>) -> PublicInputs {
    PublicInputs {
        zkq_request: None,
        fact_certificates: Vec::new(),
        claimant_vbc: None,
        receiver_current_wall_clock_lock: None,
        receiver_current_emission_claimed_epoch: None,
        receiver_current_stake_floor_until: None,
        receiver_current_wallet_format: Some(axiom_core_logic::types::WalletFormat::CURRENT), // §6b.13 — CL5 refuses a missing block
        fob_claim_attestation: None,
        receiver_witness: None,
        receiver_signing_key: None,
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
        wallet_secret: None, fanout_message: None, nabla_stake_proof: None, frozen_wallets: None,
        console_current_cert: None, console_new_cert: None,
        console_selector_picks: None, console_nominations: None,
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
        // Standard tier (k=3, DMAP) — matches `generate_wallet_id`'s default below.
        let state_id = compute_genesis_state_id(
            &pk.to_bytes(),
            balance,
            axiom_core_logic::wallet_id::K_DEFAULT,
            axiom_core_logic::wallet_id::PROOF_TYPE_DMAP,
        );
        let address = generate_wallet_id(email, "42", &pk.to_bytes()).unwrap_or_else(|_| format!("{}/0000000042", email));
        Self { sk, pk, state_id, balance, address }
    }

    fn sign_tx(&self, tx: &mut Transaction) {
        tx.client_pk = self.pk.to_bytes().to_vec();
        // THE builder Core verifies the client signature against (Pattern 1,
        // KI#55 2026-10-02) — this example used to hand-assemble the preimage
        // and mirror only the two subsidy-claim binds.
        let msg = axiom_core_logic::validation::compute_signing_message_public(tx);
        tx.client_sig = self.sk.sign(&msg).to_bytes().to_vec();
    }

    fn ws(&self) -> WalletState {
        WalletState {
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: axiom_core_logic::types::WalletFormat::CURRENT,
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
    run_vector_out(id, mode, desc, inputs, notes).0
}

/// THE one vector builder (every executable vector goes through it, so every one
/// gets the round-trip guard). Returns the JSON entry and Core's outputs.
///
/// ROUND-TRIP GUARD (KI#49 (d), 2026-10-02). The corpus pins what Core returns
/// for `inputs` — but a conformance runner never sees `inputs`, it sees
/// `inputs_cbor_hex`, decoded by `core-bin` through the IPC codec. A field the
/// codec drops or defaults (it hardcodes several CL5 inputs to None) would make
/// the vector pin an outcome `core-bin` can never reproduce, or — worse — one it
/// reproduces for a DIFFERENT reason. So before a vector is emitted:
///   1. decode(inputs_hex) must re-encode to the SAME bytes (the codec is stable
///      on what it emits), and
///   2. Core re-run on the DECODED inputs must give the same result, rejection
///      reason, produced_state_id and new_balance as on the original inputs.
/// Any mismatch panics: the vector does not test what it says over the wire.
fn run_vector_out(id: &str, mode: &str, desc: &str, inputs: PublicInputs, notes: &str)
    -> (serde_json::Value, PublicOutputs)
{
    let inputs_hex = encode_inputs_ipc(&inputs);
    let out = execute_core(inputs);
    {
        let bytes = hex::decode(&inputs_hex).expect("hex");
        let decoded = axiom_core_ipc::codec::decode_inputs(&bytes)
            .unwrap_or_else(|e| panic!("{id}: its own inputs_cbor_hex does not decode: {e}"));
        let reencoded = axiom_core_ipc::codec::encode_inputs(&decoded).expect("re-encode");
        assert!(reencoded == bytes,
            "{id}: decode→encode of inputs_cbor_hex is not byte-identical — the codec is unstable on this vector");
        let rerun = execute_core(decoded);
        let pin = |o: &PublicOutputs| (format!("{:?}", o.result), format!("{:?}", o.rejection_reason),
            o.produced_state_id, o.new_balance);
        assert!(pin(&rerun) == pin(&out),
            "{id}: Core on the DECODED inputs gives {:?}, on the original {:?} — the IPC codec loses \
             something this vector depends on, so core-bin cannot reproduce it (KI#49 round-trip guard)",
            pin(&rerun), pin(&out));
    }
    let outputs_hex = encode_outputs_ipc(&out);
    let entry = json!({
        "id": id,
        "mode": mode,
        "description": desc,
        "inputs_cbor_hex": inputs_hex,
        "outputs_cbor_hex": outputs_hex,
        "expected_result": format!("{:?}", out.result),
        "expected_rejection_reason": out.rejection_reason.as_ref().map(|r| format!("{:?}", r)),
        // Numeric wire discriminant, straight from the codec's own mapping.
        // The NAME is for humans; this is what `run_conformance.py` compares,
        // because the name would require a parallel table in Python that drifts.
        // Until 2026-08-01 the runner compared neither — it read CBOR key 15
        // (which does not exist; the reason lives at PO_REJECT = 4) and then
        // discarded the value, so `result` was the ONLY thing ever asserted.
        "expected_rejection_code": out.rejection_reason.as_ref()
            .map(axiom_core_ipc::codec::ve_to_u64),
        "expected_produced_state_id_hex": out.produced_state_id.map(hex::encode),
        "expected_new_balance": out.new_balance,
        "notes": notes,
    });
    (entry, out)
}

fn main() {
    let alice = Wallet::new([0x01; 32], "alice@vectors.axiom", 10_000_000);
    let bob = Wallet::new([0x02; 32], "bob@vectors.axiom", 5_000_000);
    let poor = Wallet::new([0x03; 32], "poor@vectors.axiom", 100);

    let mut vectors = Vec::new();

    // CL1_ACCEPT_001 — out1 is needed for CL5 cheque building
    let tx1 = alice.tx(&bob.address, 500_000);
    let (v1, out1) = run_vector_out("CL1_ACCEPT_001", "CL1", "CL1: valid send transaction accepted",
        make_inputs(CoreLogicMode::CL1, tx1.clone(), Some(alice.ws())),
        "Standard send, alice→bob, 500_000 atoms");
    vectors.push(v1);

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

    // KI#152 (b) has NO corpus vector: the conformance IPC codec hardcodes
    // `kind: TxKind::Normal` (it does not round-trip discriminants), so a stake
    // claim cannot reach core-bin as a claim — the KI#49 corpus gap. The pin is
    // `validation::tests::stake_claim_to_a_non_standard_tier_is_refused`.

    // ══════════════════════════════════════════════════════════════════════
    // CL3 — the ONLY mode the zkVM guest can be differentially tested against
    // ══════════════════════════════════════════════════════════════════════
    //
    // Added 2026-07-31. The corpus previously had ZERO CL3 vectors, which made
    // the DMAP-VM/zk-VM equivalence UNVERIFIABLE rather than verified: the
    // guest runs `execute_cl3_zkp_checkpoint`, which implements CL3 semantics
    // and ignores `inputs.mode`, so feeding it CL1/CL2/CL5/CL11 vectors compares
    // two different functions and manufactures false divergences. (Observed:
    // CL1_ACCEPT_001 gave `new_balance dmap=None zk=Some(9500000)` — DMAP was
    // right, and this corpus agreed with it.)
    //
    // These vectors are consumed by
    // `core/zkvm-host/examples/differential_conformance.rs`.
    //
    // SCOPE RULE — read before adding more. The ZK checkpoint is a strict
    // SUBSET of full CL3: it runs 14 cheap checks and leaves FACT-chain
    // verification, witness validation, Dilithium signing and txid to native
    // host execution. So a CL3 vector belongs here ONLY if the rule it exercises
    // is one the checkpoint also implements:
    //   prev_receipts-required, dust/zero, burn consistency, scar cap,
    //   S-ABR consumed==state, state-id chain, wallet_seq, receiver-id format,
    //   Ed25519 client sig, owner proof, balance, VBC expiry.
    // A vector exercising a rule only full CL3 has (e.g. FACT-chain integrity)
    // would make the two disagree BY DESIGN and produce a permanently-red gate
    // that says nothing. Keep them aligned with the checkpoint's check list in
    // `core/logic/src/modes.rs::execute_cl3_zkp_checkpoint`.
    //
    // All use empty prev_receipts (first TX after genesis, wallet_seq 0 -> 1),
    // which is the one path where the §16 quorum gate is legitimately skipped —
    // there is no previous receipt to anchor to.

    // Accept: the balance/state-chain arithmetic both sides must agree on.
    let tx_cl3 = alice.tx(&bob.address, 500_000);
    vectors.push(run_vector("CL3_ACCEPT_001", "CL3",
        "CL3: validator re-validation accepts — produced_state_id + new_balance pinned",
        make_inputs(CoreLogicMode::CL3, tx_cl3, Some(alice.ws())),
        "Differential anchor for the zkVM checkpoint: both VMs must agree on \
         result, produced_state_id, new_balance and new_wallet_seq."));

    // Reject: Ed25519 client signature (checkpoint check 9).
    let mut tx_cl3_sig = alice.tx(&bob.address, 500_000);
    tx_cl3_sig.client_sig[0] ^= 0xFF;
    vectors.push(run_vector("CL3_REJECT_SIG_001", "CL3", "CL3: invalid client signature rejected",
        make_inputs(CoreLogicMode::CL3, tx_cl3_sig, Some(alice.ws())),
        "Corrupted Ed25519 signature — checkpoint check 9."));

    // Reject: balance (checkpoint check 11).
    let tx_cl3_bal = poor.tx(&bob.address, 500_000);
    vectors.push(run_vector("CL3_REJECT_BALANCE_001", "CL3", "CL3: insufficient balance rejected",
        make_inputs(CoreLogicMode::CL3, tx_cl3_bal, Some(poor.ws())),
        "Balance 100, tries 500_000 — checkpoint check 11."));

    // Reject: dust (checkpoint check 2).
    let tx_cl3_dust = alice.tx(&bob.address, 100);
    vectors.push(run_vector("CL3_REJECT_DUST_001", "CL3", "CL3: dust amount rejected",
        make_inputs(CoreLogicMode::CL3, tx_cl3_dust, Some(alice.ws())),
        "100 < MINIMUM_TX_ATOMS — checkpoint check 2."));

    // Reject: prev_receipts required once past the first TX.
    //
    // NAMED FOR WHAT IT ACTUALLY TESTS. The obvious way to write this — set
    // wallet_seq=999 and call it a wallet_seq vector — does NOT reach check 7:
    // with wallet_seq != 1 the tx is no longer "the first TX", so the
    // prev_receipts-required check fires FIRST and the observed rejection is
    // `MissingPrevReceipts`, not `InvalidWalletSeq`. Both VMs implement that
    // check, so this is still a valid differential vector; it just is not the
    // one the name would have promised.
    //
    // GAP, recorded rather than papered over: `InvalidWalletSeq` (check 7) has
    // no vector. Reaching it needs non-empty prev_receipts carrying a real
    // 3-witness quorum (§16), which this generator has no helper for yet.
    let mut tx_cl3_seq = alice.tx(&bob.address, 500_000);
    tx_cl3_seq.wallet_seq = 999;
    alice.sign_tx(&mut tx_cl3_seq);
    vectors.push(run_vector("CL3_REJECT_NO_PREV_RECEIPTS_001", "CL3",
        "CL3: non-first TX without prev_receipts rejected",
        make_inputs(CoreLogicMode::CL3, tx_cl3_seq, Some(alice.ws())),
        "wallet_seq=999 makes this a non-first TX, so prev_receipts become \
         mandatory and their absence rejects before the wallet_seq check."));

    // Reject: S-ABR binding (checkpoint check 5). The single most
    // consensus-critical of the set — it is what stops a validator computing on
    // a state the client never consumed.
    let mut tx_cl3_sabr = alice.tx(&bob.address, 500_000);
    tx_cl3_sabr.consumed_state_id = [0xAB; 32];
    alice.sign_tx(&mut tx_cl3_sabr);
    vectors.push(run_vector("CL3_REJECT_SABR_001", "CL3", "CL3: consumed_state_id != stored state rejected",
        make_inputs(CoreLogicMode::CL3, tx_cl3_sabr, Some(alice.ws())),
        "S-ABR hash mismatch — checkpoint check 5."));

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
            &txid, &state_hash, &txid, &alice.address, &bob.address, 500_000, 1, 0,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );
        let sig = vsk.sign(&commitment).to_bytes().to_vec();
        cheques.push(ValidatorCheque {
            fact_certificates: Vec::new(),
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
    let cl5_with = |b: ChequeBundle| -> PublicInputs {
        let mut i = make_inputs(CoreLogicMode::CL5, tx1.clone(), None);
        i.cheque_bundle = Some(b);
        i.receiver_pk = Some(bob.pk.to_bytes().to_vec());
        i.receiver_current_balance = Some(5_000_000);
        i.receiver_wallet_seq = Some(0);
        i.receiver_new_balance = Some(5_500_000);
        i
    };
    // KI#49 (d), 2026-10-02 — was `CL5_ACCEPT_001` ("valid cheque bundle
    // redeemed") with a HAND-SET `expected_new_balance = 5_500_000` written over
    // Core's output: a vector named ACCEPT that expects Reject, pinning a balance
    // no Reject produces. Named for what it asserts now; every field is Core's.
    // A real CL5 ACCEPT vector needs a claim proof whose secrets come from the
    // root-secret KDF (KI#49 D2-B) — still OPEN.
    vectors.push(run_vector("CL5_REJECT_NO_CLAIM_PROOF_001", "CL5",
        "CL5: a redeem without a cheque_claim_proof is refused before anything else (ChequeClaimProofMissing)",
        cl5_with(bundle),
        "3 genuinely-signed cheques from val0/val1/val2 to bob, no claim proof. CL5's claim gate fires first; \
         the IPC codec carries no cheque_claim_proof, so no CL5 vector can get past it over the wire (KI#49 D2-B)."));

    // CL5_REJECT_FORGED_001
    let mut forged = cheques.clone();
    for c in &mut forged { c.signature = vec![0xAB; 64]; }
    vectors.push(run_vector("CL5_REJECT_FORGED_001", "CL5", "CL5: forged cheque signatures rejected",
        cl5_with(ChequeBundle { cheques: forged, fact_chain: None }), "All sigs replaced with 0xAB"));

    // CL5_REJECT_UNDERK_001
    vectors.push(run_vector("CL5_REJECT_UNDERK_001", "CL5", "CL5: under-k cheque bundle rejected",
        cl5_with(ChequeBundle { cheques: cheques[..2].to_vec(), fact_chain: None }), "Only 2 cheques, need 3"));

    // CL1_REJECT_REPLAY_001 DELETED 2026-10-02 (KI#49 (d)). It was "wallet_seq=2
    // with no prev_receipts" and rejected MissingPrevReceipts exactly like
    // CL1_REJECT_SEQ_001 — one test under two names. A TRUE replay was tried
    // (CL1_ACCEPT_001's transaction against the state it produced, stored seq 1)
    // and MEASURED to reject MissingPrevReceipts (600) too: any non-first CL1
    // without prev_receipts stops at that gate, and reaching the replay rule needs
    // a k=3 prev_receipt quorum this generator has no helper for (the same gap as
    // `InvalidWalletSeq`, see CL3_REJECT_NO_PREV_RECEIPTS_001). Replay protection
    // stays uncovered by the corpus until that helper exists — stated, not faked.

    // ── FACT-chain vectors that actually REACH fact.rs (KI#49 item 3) ─────────
    //
    // The CL5 FACT vectors below never exercise FACT verification: CL5 bails at
    // the mandatory `cheque_claim_proof` gate (modes.rs) long before the chain is
    // looked at, so valid / broken / scarred all collapse onto
    // Reject/ChequeClaimProofMissing and the corpus cannot tell them apart. That
    // left `core/logic/src/fact.rs` — a CONSENSUS_CRITICAL file — with no
    // distinguishing coverage at all.
    //
    // The fix is NOT to forge a claim proof. Doing that needs a root-authority
    // SPHINCS+ signature, and the only reproducible way to ship one is to commit
    // a root-signed credential plus the fixed-seed Ed25519 secret it binds — into
    // a corpus we PUBLISH. That hands anyone a usable Nabla-writer credential for
    // the dev network, which is not a thing to publish to make a test pass.
    //
    // Instead, reach the same code by the front door.
    // `verify_fact_chain_inner_with_burn_skip` is called from
    // `validate_transaction` on `inputs.sender_fact_chain` with NO mode gate
    // (validation.rs), so CL3 exercises it directly — no cheque, no Nabla, no
    // credential, fully deterministic.
    {
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes as DilSerDes;
        use rand::SeedableRng;

        // DETERMINISTIC keygen. The existing FACT vectors call
        // `ml_dsa_65::try_keygen()`, which is UNSEEDED — that, not a signing
        // nonce, is the real reason those three vectors churn `inputs_cbor_hex`
        // on every regeneration. Seeded here so these vectors are byte-stable.
        // YP §26.17.6.5 (2026-09-11): a FACT witness binds only through a
        // certificate Core verifies to the compiled roots (B2), and the chain
        // must start at the wallet's derived opening state (B1). So the CL3
        // FACT vectors carry REAL depth-0 certificates signed by the three root
        // keys in `root-keys/authority/` (the keys `genesis.rs` carries in
        // public form; the G1 ceremony installs its fresh ones there before it
        // regenerates this corpus). SLH-DSA signing is deterministic
        // (`sign_sphincs` passes `randomize = false`) and the witness subject
        // keys (Dilithium + SPHINCS+) come from RNGs seeded by a KDF over the
        // three root SECRETS (`witness_subject_seed`, KI#49 D1 — never a public
        // seed), so the corpus is byte-stable for a given root set and nobody
        // without all three root keys can derive a certified witness secret.
        // Without the root keys the FACT vectors cannot be produced and the run
        // stops — a vector expecting Accept on an uncertified chain would be a lie.
        let root_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../root-keys/authority");
        let root_sks: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(root_dir.join(format!("root_{i}.key")))
                .unwrap_or_else(|e| panic!("root-keys/authority/root_{i}.key: {e} — the FACT vectors need the root keys (YP §26.17.6.5 B2)")))
            .collect();
        let root_pks: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(root_dir.join(format!("root_{i}.pub"))).expect("root pub"))
            .collect();
        for (i, pk) in root_pks.iter().enumerate() {
            assert!(axiom_core_logic::genesis::is_root_authority(pk),
                "root-keys/authority/root_{}.pub is not a compiled ROOT_AUTHORITY_PK — rebuild after the ceremony", i + 1);
        }
        // KI#49 D1 (2026-10-01): every witness SUBJECT key below is derived from
        // the three root SECRETS (`witness_subject_seed`), never from a public
        // seed. See that function for why — the short version: these certificates
        // are root-signed, so a subject secret anyone can regenerate is a usable
        // k=3 FACT-witness credential, and the corpus is PUBLISHED.
        assert_eq!(root_sks.len(), 3, "the FACT vectors need all three root keys");
        let certify = |seed: u8, i: u8, dilithium_pk: &[u8]| -> (VBCProofBundle, [u8; 32], [u8; 32]) {
            use fips205::slh_dsa_sha2_128s;
            use fips205::traits::SerDes as SphincsSerDes;
            let mut srng = rand::rngs::StdRng::from_seed(witness_subject_seed(&root_sks, "sphincs", seed, i));
            let (spk, _ssk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut srng).expect("sphincs keygen");
            let sphincs_pk = spk.into_bytes().to_vec();
            let validator_id = axiom_core_logic::compute::compute_validator_id(&sphincs_pk);
            let mut vbc = VBC {
                genesis_lineage: [0u8; 32], network_size_baseline: 0, baseline_tick: 0, version: 0x09,
                validator_id, subject_pubkey_sphincs: sphincs_pk,
                subject_pubkey_dilithium: dilithium_pk.to_vec(),
                subject_pubkey_ed25519: vec![0x11u8; 32], pgp_fingerprint: vec![],
                // `expires_at = u64::MAX` is NOT the exposure and a short expiry
                // would NOT be a fix: `fact::certify_presented` verifies with
                // `now = 0`, and a short window makes the certificate PROVISIONAL,
                // which certifies nothing (the vector would stop testing B2).
                // The protection is that nobody but the root holders can derive
                // the subject secret (KI#49 D1). Do not "harden" this field.
                node_name: String::new(), issued_at: 1_000, expires_at: u64::MAX, chain_depth: 0,
                issuer_set: root_pks.clone(), signatures: vec![], proof_cap: String::new(),
                max_tx: 0, founding_vbc_hash: [0u8; 32], nabla_registration: None,
            };
            let payload = axiom_core_logic::compute::compute_vbc_signing_payload(&vbc);
            // `crypto::sign_sphincs` is gated behind the `ceremony` feature; this is
            // the same call (FIPS 205 SLH-DSA-SHA2-128s, randomize = false).
            vbc.signatures = root_sks.iter().map(|sk| {
                use fips205::traits::Signer;
                let sk_arr: [u8; 64] = sk.as_slice().try_into().expect("root key is 64 bytes");
                slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&sk_arr).expect("root sk")
                    .try_sign(&payload, b"", false).expect("sphincs sign").to_vec()
            }).collect();
            let reference = axiom_core_logic::vbc::vbc_reference_hash(&vbc);
            (VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None }, validator_id, reference)
        };
        // B1 needs a derivable OWNER: `(client_pk, sender_wallet_id)`. The corpus
        // transactions carry an empty sender id (a fixture shortcut the rest of
        // validation tolerates); the FACT vectors carry alice's real address and
        // are re-signed over it, so Core can derive the opening state to compare.
        let fact_tx = |amount: u64| -> Transaction {
            let mut t = alice.tx(&bob.address, amount);
            t.sender_wallet_id = alice.address.clone();
            alice.sign_tx(&mut t);
            t
        };
        // B1 — the chain starts where Core derives alice's opening state.
        let alice_origin = axiom_core_logic::genesis::opening_state_id_for(
            &alice.pk.to_bytes(), axiom_core_logic::wallet_id::K_DEFAULT, axiom_core_logic::wallet_id::PROOF_TYPE_DMAP);
        let build_chain = |seed: u8, new_state: [u8; 32], k: u8, n_witnesses: usize| -> (FactChain, Vec<VBCProofBundle>) {
            let prior_tx = [0xC0u8 | seed; 32];
            let prior_prev = alice_origin;
            let mut ws = Vec::new();
            let mut certs = Vec::new();
            for i in 0..n_witnesses {
                // KI#49 D1: root-secret-derived, one RNG per witness. It was
                // `StdRng::from_seed([seed; 32])` — a PUBLIC seed, so the Dilithium
                // secret behind every root-certified witness was reproducible
                // from the published generator.
                let mut rng = rand::rngs::StdRng::from_seed(
                    witness_subject_seed(&root_sks, "dilithium", seed, i as u8));
                let (pk_obj, sk_obj) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("keygen");
                let pk_bytes = pk_obj.into_bytes().to_vec();
                let sk_bytes = sk_obj.into_bytes().to_vec();
                // Signed over the link's OWN `k` (Fork Settlement R4 / R36): the
                // commitment binds `required_k`, so every vector here must sign
                // with the k its link declares — otherwise CL3_FACT_UNDERK_001
                // (an UNDER-QUORUM vector: a k=3 link with 2 witnesses) could
                // drift into a signature-invalid one and silently change what it
                // tests.
                let sig = axiom_core_logic::compute::sign_fact_commitment(
                    &sk_bytes, &prior_tx, &prior_prev, &new_state, alice.balance,
                    None, false, k, &[], None,
                ).expect("fact sign");
                let (bundle, validator_id, vbc_hash) = certify(seed, i as u8, &pk_bytes);
                certs.push(bundle);
                ws.push(FactWitness { validator_id, validator_pk: pk_bytes, signature: sig, vbc_hash });
            }
            (FactChain {
                checkpoint: None,
                links: vec![FactLink {
                    tx_id: prior_tx, previous_state_id: prior_prev, new_state_id: new_state,
                    amount: alice.balance, required_k: k, tick: 1, witnesses: ws,
                    // No confirmation. A FORGED one (nabla_signature: [0;64], as the
                    // CL5 fixtures carry) fails Core's verify_nabla_confirmation and
                    // rejects the whole chain — the CL5 vectors get away with it only
                    // because they never reach verification. A link WITHOUT a
                    // confirmation is scarred but structurally valid: it blocks
                    // compression, it does not fail the chain.
                    nabla_confirmation: None,
                    burn_proof: None, burn_target_tx_id: None,
                    sender_anchor: None, is_dev_class: false, recall_proof: None,
                    out_of_order_confirmation: None,
                    inherited_scar_txids: Vec::new(),
                    inherited_scar_resolutions: Vec::new(),
                    receiver_witness: None,
                }],
            }, certs)
        };

        // (a) VALID — tip binds to consumed_state_id, k=3 real Dilithium sigs.
        // Distinct amount so this vector has its OWN state transition. If it
        // produced the same outputs as the chain-less CL3_ACCEPT_001, it would
        // prove nothing: an implementation that never verifies FACT chains would
        // pass both identically.
        let mut in_ok = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (chain, certs) = build_chain(0x11, alice.state_id, 3, 3);
        in_ok.sender_fact_chain = Some(chain);
        in_ok.fact_certificates = certs;
        vectors.push(run_vector("CL3_FACT_VALID_001", "CL3",
            "CL3: valid FACT chain (3 Dilithium witnesses) verified end-to-end",
            in_ok,
            "Reaches verify_fact_chain_inner_with_burn_skip — the CL5 FACT vectors \
             never do (they stop at the cheque_claim_proof gate)."));

        // (b) BROKEN CONTINUITY — tip no longer matches consumed_state_id.
        let mut in_broken = make_inputs(CoreLogicMode::CL3, fact_tx(500_000), Some(alice.ws()));
        let (chain, certs) = build_chain(0x22, [0u8; 32], 3, 3);
        in_broken.sender_fact_chain = Some(chain);
        in_broken.fact_certificates = certs; // certified, so the ONLY defect is the tip
        vectors.push(run_vector("CL3_FACT_BROKEN_001", "CL3",
            "CL3: FACT chain whose tip does not bind to consumed_state_id is rejected",
            in_broken,
            "Continuity/freshness break — MUST be distinguishable from the valid chain."));

        // (c) UNDER-K — a link claiming k=3 carrying only 2 witnesses.
        let mut in_underk = make_inputs(CoreLogicMode::CL3, fact_tx(500_000), Some(alice.ws()));
        let (chain, certs) = build_chain(0x33, alice.state_id, 3, 2);
        in_underk.sender_fact_chain = Some(chain);
        in_underk.fact_certificates = certs; // certified, so the ONLY defect is the quorum
        vectors.push(run_vector("CL3_FACT_UNDERK_001", "CL3",
            "CL3: FACT link with fewer witnesses than its required_k is rejected",
            in_underk,
            "Quorum gate on the chain itself — distinct failure from a continuity break."));

        // YP §26.17.6.5 B2 — the SAME valid chain with its certificates withheld
        // is refused: a witness that resolves to no presented certificate binds
        // nothing, and Core never looks one up.
        let mut in_uncert = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (chain, _certs) = build_chain(0x11, alice.state_id, 3, 3);
        in_uncert.sender_fact_chain = Some(chain);
        vectors.push(run_vector("CL3_FACT_UNCERTIFIED_001", "CL3",
            "CL3: a valid FACT chain whose witness certificates are NOT presented is refused (E_FACT_WITNESS_UNCERTIFIED)",
            in_uncert,
            "YP §26.17.6.5 B2. Same bytes as CL3_FACT_VALID_001 minus `fact_certificates` — the \
             verdict must flip on the certificate set alone."));

        // YP §26.17.6.5 B1 — a certified chain that does not start at alice's
        // derived opening state is refused before any witness is examined.
        let mut in_origin = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (mut chain, certs) = build_chain(0x11, alice.state_id, 3, 3);
        chain.links[0].previous_state_id = [0xC1u8; 32]; // an origin nobody derived (the pre-amendment fixture value)
        in_origin.sender_fact_chain = Some(chain);
        in_origin.fact_certificates = certs;
        vectors.push(run_vector("CL3_FACT_ORIGIN_001", "CL3",
            "CL3: FACT chain that does not start at the sender's derived opening state is refused (E_FACT_ORIGIN_INVALID)",
            in_origin,
            "YP §26.17.6.5 B1. The witnesses' signatures no longer match the link (previous_state_id is \
             in the commitment), but B1 is judged FIRST — the reason must be the origin, not the signature."));

        // KI#49 (a), 2026-10-01 — the SIGNATURE checks had no vector, so an
        // implementation that skipped Dilithium witness verification, the
        // certificate's root signatures, or the duplicate-witness rule passed
        // the whole corpus (ORIGIN's bad signatures are masked by B1, judged
        // first). Each of these is CL3_FACT_VALID_001 with exactly ONE change.

        // (d) BAD WITNESS SIGNATURE — certified witness, one signature byte flipped.
        let mut in_badsig = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (mut chain, certs) = build_chain(0x11, alice.state_id, 3, 3);
        chain.links[0].witnesses[0].signature[0] ^= 0xFF;
        in_badsig.sender_fact_chain = Some(chain);
        in_badsig.fact_certificates = certs;
        vectors.push(run_vector("CL3_FACT_BADSIG_001", "CL3",
            "CL3: a certified FACT witness whose Dilithium signature does not verify is rejected (FactInvalidSignature)",
            in_badsig,
            "VALID with witness[0].signature[0] ^= 0xFF. An implementation that does not verify witness \
             signatures accepts this."));

        // (e) BAD CERTIFICATE — a presented certificate whose root signature fails.
        let mut in_badcert = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (chain, mut certs) = build_chain(0x11, alice.state_id, 3, 3);
        certs[0].target_vbc.signatures[0][0] ^= 0xFF;
        in_badcert.sender_fact_chain = Some(chain);
        in_badcert.fact_certificates = certs;
        vectors.push(run_vector("CL3_FACT_BADCERT_001", "CL3",
            "CL3: a presented witness certificate that does not verify to the roots is rejected (FactCertificateInvalid)",
            in_badcert,
            "VALID with certificate[0]'s first root signature corrupted. An implementation that trusts a \
             presented certificate without checking its issuers' signatures accepts this."));

        // (f) DUPLICATE WITNESS — one certified witness counted twice toward k=3.
        let mut in_dup = make_inputs(CoreLogicMode::CL3, fact_tx(640_000), Some(alice.ws()));
        let (mut chain, certs) = build_chain(0x11, alice.state_id, 3, 3);
        chain.links[0].witnesses[2] = chain.links[0].witnesses[0].clone();
        in_dup.sender_fact_chain = Some(chain);
        in_dup.fact_certificates = certs;
        vectors.push(run_vector("CL3_FACT_DUPWITNESS_001", "CL3",
            "CL3: a FACT link that counts the same witness twice is rejected (FactDuplicateWitness)",
            in_dup,
            "VALID with witness[2] replaced by a copy of witness[0] — every signature is genuine, the \
             quorum is not. An implementation that counts signatures instead of distinct witnesses accepts this."));
    }

    // FACT_VERIFY_ACCEPT_001 — CL5 with valid Dilithium FACT chain
    {
        use fips204::ml_dsa_65;
        use fips204::traits::SerDes as DilSerDes;
        use rand::SeedableRng;

        let prior_tx = [0xA0u8; 32];
        let prior_prev = [0xA1u8; 32];
        let prior_new = alice.state_id;
        // SEEDED. This used unseeded `try_keygen()`, which is the actual reason
        // these three vectors churned `inputs_cbor_hex` on every regeneration —
        // long attributed to "an unseeded Dilithium signing nonce". It is the
        // KEY that was unseeded, not the signature. Seeding it makes the whole
        // corpus byte-stable, so a real diff is never lost in expected noise.
        let mut fact_keyrng = rand::rngs::StdRng::from_seed([0x5Au8; 32]);
        let mut fact_witnesses = Vec::new();
        for i in 0..3u8 {
            let (pk_obj, sk_obj) = ml_dsa_65::try_keygen_with_rng(&mut fact_keyrng).expect("keygen");
            let pk_bytes = pk_obj.into_bytes().to_vec();
            let sk_bytes = sk_obj.into_bytes().to_vec();
            let sig = axiom_core_logic::compute::sign_fact_commitment(
                &sk_bytes, &prior_tx, &prior_prev, &prior_new, alice.balance, None, false,
                3, // the link's `required_k` below (R4 binds it)
                &[], None,
            ).expect("fact sign");
            let mut vid = [0u8; 32]; vid[0] = i + 1;
            fact_witnesses.push(FactWitness {
                validator_id: vid, validator_pk: pk_bytes, signature: sig, vbc_hash: [0u8; 32],
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
                burn_proof: None, burn_target_tx_id: None,
                sender_anchor: None,
                is_dev_class: false,
                recall_proof: None,
                out_of_order_confirmation: None,
                inherited_scar_txids: Vec::new(),
                inherited_scar_resolutions: Vec::new(),
                receiver_witness: None,
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
        vectors.push(run_vector("FACT_VERIFY_ACCEPT_001", "CL5",
            "CL5: valid FACT chain with 3 Dilithium witnesses",
            cl5_fact,
            "FACT chain verification exercised in CL5 with real Dilithium signatures"));

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
        vectors.push(run_vector("FACT_VERIFY_BROKEN_001", "CL5",
            "CL5: broken FACT chain state_id rejected",
            cl5_broken,
            "FactLink new_state_id set to zeros — state chain discontinuity"));

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
        vectors.push(run_vector("FACT_VERIFY_SCAR_001", "CL5",
            "CL5: scarred FACT link accepted (receiver consented)",
            cl5_scar,
            "Scarred links permitted in CL5 — receiver consented via scar-passcode"));
    }

    // OWNER_PROOF_ACCEPT_001 / OWNER_PROOF_REJECT_001 DELETED 2026-09-25 with
    // `Transaction.owner_proof` (KI#108).

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
                // stub — Core verifies picks in EVERY build (the release-only gate was
                // removed 2026-10-02), so this rejects ConsoleInvalidPick. Do NOT
                // self-sign it to make CL11_ACCEPT_001 accept (KI#49 D3).
                signature: vec![0u8; 64],
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
        vectors.push(run_vector("CL11_ACCEPT_001", "CL11",
            "CL11: valid election — 15 seats resolved, chain hash correct",
            cl11_inputs,
            "CL11: valid election — 15 seats resolved from 15 nominations, chain hash correct. IPC codec pending — from_file test skips CL11."));

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
        vectors.push(run_vector("CL11_REJECT_INVALID_PICK_001", "CL11",
            "CL11: seat mismatch — resolved set differs from new_cert.seats",
            cl11_bad,
            "CL11: seat mismatch — resolved set differs from new_cert.seats. IPC codec pending — from_file test skips CL11."));
    }

    // ── Oracle-shaped CL1 vector (was "Oracle VBC freshness", YPX-012 §2.5 — never reached; see below) ──
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
                        // §5.3 — depth-0, so no adopted lineage is declared.
                        genesis_lineage: [0u8; 32],
                        nabla_registration: None,
                    },
                    supporting_vbcs: vec![],
                    candidacy_pulse: None, renewal_work_receipt: None,
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
                confidence_index: None,
                sender_state: None,
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

        // KI#49 (d), 2026-10-02 — the two ORACLE_VBC_* vectors carried NO inputs CBOR
        // ("IPC CBOR cannot round-trip oracle_claim" — stale: tx key 16 carries it).
        // Made executable, the round-trip guard passed, and the outcome was MEASURED:
        // BOTH reject `InvalidStateId` (101) — the fixture prev_receipt does not anchor
        // alice's declared state, a check that runs BEFORE the oracle VBC-age rule.
        // Neither ever tested YPX-012 §2.5 (TOO_OLD pinned 101 since before this
        // date). So: ORACLE_VBC_FRESH_001 DELETED (same outcome, nothing to pin), and
        // ORACLE_VBC_TOO_OLD_001 RENAMED to the rule it does reach. `OracleVBCTooOld`
        // has NO corpus vector — reaching it needs a quorum-anchored prev_receipt
        // (no helper yet; same gap as `InvalidWalletSeq`).
        let stale_witness = make_oracle_witness(oracle_epoch - 17_281);
        let mut stale_inputs = make_inputs(CoreLogicMode::CL1, oracle_tx, Some(alice.ws()));
        stale_inputs.prev_receipts = vec![make_oracle_receipt(stale_witness)];
        vectors.push(run_vector("CL1_REJECT_UNANCHORED_PREV_RECEIPT_001", "CL1",
            "CL1: a prev_receipt whose state_hash does not anchor the declared state is rejected (InvalidStateId)",
            stale_inputs,
            "Was ORACLE_VBC_TOO_OLD_001. An oracle TX (witness VBC 17_281 ticks old) — but the anchor check fires \
             first, so this pins state anchoring, NOT the YPX-012 §2.5 VBC-age rule."));
    }

    // KI#49 (e), 2026-10-01 — THE vector-count floor. ONE value: the generator
    // writes `executable_vector_count` into the corpus, and `run_conformance.py`
    // fails unless exactly that many vectors execute. The ceremony
    // (`g1-full-ceremony.sh` step 9) and the D-check (`dcheck.sh` leg 2) both
    // read it from the corpus — no script carries its own number any more (they
    // had drifted: the ceremony's `--min-vectors 30` against 28 executable would
    // have failed the production seal, which no rehearsal ever ran).
    // `MIN_EXECUTABLE_VECTORS` is the shrink-ratchet on the generator itself:
    // RAISE it in the commit that adds vectors; LOWER it only in the commit
    // that deletes vectors, saying which and why. Never lower it to pass.
    // Stays 31 on 2026-10-02: +1 ORACLE_VBC_TOO_OLD_001 made executable (renamed
    // CL1_REJECT_UNANCHORED_PREV_RECEIPT_001; it carried no inputs CBOR); −1
    // CL1_REJECT_REPLAY_001 deleted (≡ CL1_REJECT_SEQ_001, see its tombstone);
    // ORACLE_VBC_FRESH_001 deleted (was never executable); CL5_ACCEPT_001 RENAMED
    // (CL5_REJECT_NO_CLAIM_PROOF_001), not removed.
    const MIN_EXECUTABLE_VECTORS: usize = 31;
    let executable_vector_count = vectors.iter()
        .filter(|v| v.get("inputs_cbor_hex").and_then(|x| x.as_str()).map_or(false, |h| !h.is_empty()))
        .count();
    assert!(executable_vector_count >= MIN_EXECUTABLE_VECTORS,
        "the corpus shrank: {executable_vector_count} executable vectors < floor {MIN_EXECUTABLE_VECTORS} (KI#49 e)");

    let output = json!({
        "axiom_version": CORE_VERSION,
        "generated_at": "2026-04-02T00:00:00Z",
        "description": "Canonical consensus test vectors for AXIOM protocol conformance. Any correct implementation of Core must produce the expected outputs for the given inputs. Vectors are deterministic from fixed seeds. Regenerate with: cargo run -p axiom-core-logic --example generate_vectors",
        "vector_count": vectors.len(),
        "executable_vector_count": executable_vector_count,
        "vectors": vectors,
    });

    assert_no_collapsed_vectors(&vectors);

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Seed for one ROOT-CERTIFIED witness subject key in the CL3 FACT vectors.
///
/// KI#49 D1 (2026-10-01, pre-ceremony blocker). The CL3 FACT vectors carry
/// depth-0 VBCs signed by the three root keys, and Core accepts a FACT witness
/// that binds through such a certificate (`fact::certify_presented`). Until this
/// date the subject keys came from `StdRng::from_seed([seed; 32])` — PUBLIC
/// seeds in a PUBLISHED generator — so anyone could regenerate the Dilithium
/// secret and sign k=3 FACT witnesses that verify against the compiled roots:
/// forged sender provenance at CL3/CL5 on any network running those roots. The
/// ceremony as scripted would have minted the same credential under the REAL
/// roots and `publish-code.py` would have shipped it.
///
/// The seed is now a KDF over ALL THREE root secrets — never `root_1.key` alone:
/// with one key sufficing, ONE root holder would own a k=3 FACT-forgery
/// capability, weaker than the 3-of-3 quorum VBC issuance already requires.
/// Whoever holds all three can sign any VBC anyway, so the derived keys grant
/// nobody anything new. Expiry is no substitute (see the VBC literal).
///
/// The artifact-level check is `corpus_credential_gate` (run by the ceremony
/// after it regenerates this corpus, and by the D-check on the committed one).
fn witness_subject_seed(root_sks: &[Vec<u8>], purpose: &str, seed: u8, i: u8) -> [u8; 32] {
    assert_eq!(root_sks.len(), 3, "witness subject keys derive from all three root secrets");
    for (n, sk) in root_sks.iter().enumerate() {
        assert_eq!(sk.len(), 64, "root_{}.key is not a 64-byte SLH-DSA secret", n + 1);
        assert!(sk.iter().any(|b| *b != 0), "root_{}.key is all zero", n + 1);
    }
    assert!(root_sks[0] != root_sks[1] && root_sks[1] != root_sks[2] && root_sks[0] != root_sks[2],
        "the three root secrets must be distinct");
    let mut h = blake3::Hasher::new_derive_key("AXIOM conformance corpus root-certified witness subject key");
    for sk in root_sks {
        h.update(sk);
    }
    h.update(&(purpose.len() as u64).to_le_bytes());
    h.update(purpose.as_bytes());
    h.update(&[seed, i]);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::witness_subject_seed;

    fn keys(tag: u8) -> Vec<Vec<u8>> {
        (1..=3u8).map(|n| vec![tag ^ n; 64]).collect()
    }

    #[test]
    fn witness_subject_seed_depends_on_every_root_secret() {
        let base = keys(0x40);
        let s = witness_subject_seed(&base, "dilithium", 0x11, 0);
        assert_eq!(s, witness_subject_seed(&base, "dilithium", 0x11, 0), "deterministic");
        // Change each root secret in turn: the seed must change every time —
        // no single root key (and no two) determines the witness secret.
        for n in 0..3 {
            let mut k = base.clone();
            k[n][0] ^= 0xFF;
            assert_ne!(s, witness_subject_seed(&k, "dilithium", 0x11, 0), "root_{} ignored", n + 1);
        }
        assert_ne!(s, witness_subject_seed(&keys(0x41), "dilithium", 0x11, 0), "different secrets, same seed");
        assert_ne!(s, witness_subject_seed(&base, "sphincs", 0x11, 0), "purposes must separate");
        assert_ne!(s, witness_subject_seed(&base, "dilithium", 0x11, 1), "witness index must separate");
        assert_ne!(s, witness_subject_seed(&base, "dilithium", 0x22, 0), "chain seed must separate");
        // The pre-fix recipe's seed was public: it must never come back.
        assert_ne!(s, [0x11u8; 32]);
    }

    #[test]
    #[should_panic(expected = "all three root secrets")]
    fn witness_subject_seed_refuses_a_single_root_key() {
        witness_subject_seed(&keys(0x40)[..1], "dilithium", 0x11, 0);
    }
}

/// Refuse to emit a corpus in which two vectors are indistinguishable.
///
/// WHY (KI#49, 2026-08-01). Five vectors collapsed onto
/// `Reject/ChequeClaimProofMissing` because they all bail at the same early CL5
/// gate: `CL5_ACCEPT_001` ("valid cheque bundle redeemed") and
/// `FACT_VERIFY_ACCEPT_001` ("valid FACT chain") both EXPECT Reject, and valid /
/// broken / scarred FACT chains are indistinguishable. Since `run_conformance.py`
/// compared only `result`, all three "passed" identically — so an implementation
/// doing NO FACT verification passes the suite, while `core/logic/src/fact.rs` is
/// CONSENSUS_CRITICAL. Two vectors with the same (mode, result, rejection code)
/// are the same test wearing different names.
///
/// This gate is live for NEW vectors today. The known-collapsed ids below are
/// grandfathered with their KI#49 item so the gate can land before the corpus is
/// repaired — REMOVE each id as it is fixed, and never weaken the assert itself.
fn assert_no_collapsed_vectors(vectors: &[serde_json::Value]) {
    use std::collections::BTreeMap;

    // (id, why) — every entry must be justified and must shrink over time.
    const GRANDFATHERED: &[(&str, &str)] = &[
        // LEGITIMATE: exists precisely to pin determinism against CL1_ACCEPT_001.
        ("CL1_DETERMINISM_001", "determinism pin — intentional duplicate"),
        // KI#49 item 3: these bail at the cheque_claim_proof gate before the
        // logic they are named for runs. NOT fixed by forging a claim proof —
        // that needs a root-authority SPHINCS+ signature, and shipping one
        // reproducibly means committing a root-signed credential plus the
        // fixed-seed secret it binds, into a corpus we PUBLISH. Instead the
        // COVERAGE was added by the front door: CL3_FACT_{VALID,BROKEN,UNDERK}
        // reach `verify_fact_chain_inner_with_burn_skip` directly (it is called
        // from `validate_transaction` with no mode gate), so fact.rs now has
        // three distinguishable outcomes. These five stay grandfathered because
        // they are still indistinguishable AS CL5 VECTORS — that is a separate,
        // smaller gap: the CL5 redeem path itself is untested past the gate.
        ("CL5_REJECT_FORGED_001", "TODO(KI#49): blocked at cheque_claim_proof gate"),
        ("FACT_VERIFY_ACCEPT_001", "TODO(KI#49): blocked at cheque_claim_proof gate"),
        ("FACT_VERIFY_BROKEN_001", "TODO(KI#49): blocked at cheque_claim_proof gate"),
        ("FACT_VERIFY_SCAR_001", "TODO(KI#49): blocked at cheque_claim_proof gate"),
        // KI#49: distinct intent, identical outcome — need inputs that actually
        // reach the rule each is named for.
        ("CL11_REJECT_INVALID_PICK_001", "TODO(KI#49): collapses onto ConsoleInvalidPick"),
    ];

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut violations: Vec<String> = Vec::new();

    for v in vectors {
        let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("<no id>");
        if GRANDFATHERED.iter().any(|(g, _)| *g == id) {
            continue;
        }
        // A REJECT is identified by which rule fired; an ACCEPT has no rejection
        // code, so it is identified by the state transition it produces. Without
        // that split every Accept in a mode looks identical and the guard is
        // useless for them — and, more importantly, two Accepts with the SAME
        // transition really are indistinguishable: an implementation that skips
        // the rule one of them is named for still passes both.
        let result = v.get("expected_result").and_then(|x| x.as_str()).unwrap_or("?");
        let discriminator = if result == "Accept" {
            format!(
                "{}|{}",
                v.get("expected_produced_state_id_hex").and_then(|x| x.as_str()).unwrap_or("-"),
                v.get("expected_new_balance").and_then(|x| x.as_u64())
                    .map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            )
        } else {
            v.get("expected_rejection_code")
                .and_then(|x| x.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".into())
        };
        let key = format!(
            "{}|{}|{}",
            v.get("mode").and_then(|x| x.as_str()).unwrap_or("?"),
            result,
            discriminator,
        );
        if let Some(prev) = seen.get(&key) {
            violations.push(format!(
                "  {id} is indistinguishable from {prev}  ({key})"
            ));
        } else {
            seen.insert(key, id.to_string());
        }
    }

    if !violations.is_empty() {
        panic!(
            "COLLAPSED VECTORS — the corpus cannot tell these apart, so they are \
             one test with several names (KI#49):\n{}\n\n\
             Give each vector inputs that actually reach the rule it is named \
             for. Do NOT add it to GRANDFATHERED to make this pass — that is how \
             the corpus stopped checking FACT verification in the first place.",
            violations.join("\n")
        );
    }
}
