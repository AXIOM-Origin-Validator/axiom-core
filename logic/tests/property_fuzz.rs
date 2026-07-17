//! Property-based fuzz tests for FACT chain, CBOR codec, and crypto invariants.
//!
//! Uses proptest to verify structural invariants that must hold for ALL inputs,
//! not just hand-crafted test cases. These catch edge cases that unit tests miss.

use proptest::prelude::*;
use proptest::collection::vec as pvec;

use axiom_core_logic::types::{
    FactChain, FactLink, FactWitness, NablaConfirmation,
    Transaction, TxKind, PublicInputs,
};
use axiom_core_logic::fact::compress_fact_chain;
use axiom_core_logic::verify::ct_eq;
use axiom_core_logic::validation::compute_signing_message_public;

use fips204::ml_dsa_65;
use fips204::traits::SerDes;

// ============================================================================
// TEST KEY HELPERS
// ============================================================================

/// Dilithium keypair for FACT test signing.
struct DilithiumTestKey {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

fn test_keys() -> Vec<DilithiumTestKey> {
    (0..3)
        .map(|_| {
            let (pk_obj, sk_obj) = ml_dsa_65::try_keygen().expect("Dilithium keygen");
            DilithiumTestKey {
                pk: pk_obj.into_bytes().to_vec(),
                sk: sk_obj.into_bytes().to_vec(),
            }
        })
        .collect()
}

/// Build a properly-signed FactLink.
fn make_signed_link(
    tx_id: [u8; 32],
    prev_state: [u8; 32],
    new_state: [u8; 32],
    amount: u64,
    resolved: bool,
    keys: &[DilithiumTestKey],
) -> FactLink {
    let commitment = axiom_core_logic::compute::compute_fact_commitment(
        &tx_id, &prev_state, &new_state, amount, None, false,
    );
    let witnesses: Vec<FactWitness> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let sk_array: [u8; 4032] = key.sk.as_slice().try_into().expect("sk len");
            let sk_obj = ml_dsa_65::PrivateKey::try_from_bytes(sk_array)
                .expect("sk decode");
            use fips204::traits::Signer;
            let sig = sk_obj.try_sign(&commitment, &[]).expect("dilithium sign")
                .to_vec();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            FactWitness {
                validator_id: vid,
                validator_pk: key.pk.clone(),
                signature: sig,
                vbc_genesis_anchor: None,
            }
        })
        .collect();

    let nabla_confirmation = if resolved {
        Some(NablaConfirmation {
            nabla_node_id: [42u8; 32],
            nabla_signature: vec![0u8; 64],
            root_hash: [1u8; 32],
            synced_to_tick: 100,
            ..Default::default()
        })
    } else {
        None
    };

    FactLink {
        tx_id,
        previous_state_id: prev_state,
        new_state_id: new_state,
        amount,
        required_k: witnesses.len() as u8,
        tick: 0,
        witnesses,
        nabla_confirmation,
        receiver_contact: None,
        burn_proof: None,
        sender_anchor: None,
        is_dev_class: false,
        recall_proof: None,
    }
}

/// Build a valid, continuous FACT chain with the given scar pattern.
/// `resolved_flags[i]` = true means link i has Nabla confirmation.
fn build_valid_chain(
    state_ids: &[[u8; 32]],
    tx_ids: &[[u8; 32]],
    amounts: &[u64],
    resolved_flags: &[bool],
    keys: &[DilithiumTestKey],
) -> FactChain {
    assert!(state_ids.len() >= 2, "need at least 2 state_ids for 1 link");
    let link_count = state_ids.len() - 1;
    assert_eq!(tx_ids.len(), link_count);
    assert_eq!(amounts.len(), link_count);
    assert_eq!(resolved_flags.len(), link_count);

    let links: Vec<FactLink> = (0..link_count)
        .map(|i| {
            make_signed_link(
                tx_ids[i],
                state_ids[i],
                state_ids[i + 1],
                amounts[i],
                resolved_flags[i],
                keys,
            )
        })
        .collect();

    FactChain {
        checkpoint: None,
        links,
    }
}

// ============================================================================
// PROPTEST STRATEGIES
// ============================================================================

/// Generate a random [u8; 32].
fn arb_hash() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

/// Generate a minimal Transaction for signing-message tests.
fn arb_transaction() -> impl Strategy<Value = Transaction> {
    (
        arb_hash(),                              // consumed_state_id
        pvec(any::<u8>(), 32..=32),              // client_pk
        "[a-z]{3,8}@test\\.com/[0-9a-f]{8}",    // sender_wallet_id
        "[a-z]{3,8}@test\\.com/[0-9a-f]{8}",    // receiver_wallet_id
        500_000u64..10_000_000u64,               // amount (above dust)
        "[a-zA-Z0-9 ]{0,50}",                   // reference
        0u64..(i64::MAX as u64),                 // nonce (IPC codec uses i64 for CBOR)
        0u64..(i64::MAX as u64),                 // epoch
        1u64..1_000_000u64,                      // wallet_seq
    )
        .prop_map(
            |(consumed_state_id, client_pk, sender_wallet_id, receiver_wallet_id, amount, reference, nonce, epoch, wallet_seq)| {
                Transaction {
                    recall_target_tx_id: None,
                    consumed_state_id,
                    client_pk,
                    sender_wallet_id,
                    receiver_wallet_id,
                    receiver_address: None,
                    core_id: [0u8; 32],
                    amount,
                    reference,
                    nonce,
                    epoch,
                    wallet_seq,
                    client_sig: vec![0u8; 64],
                    owner_proof: None,
                    scar_passcode: None,
                    burn_target_tx_id: None,
                    oracle_claim: None,
                    required_k: 3,
                    proof_type: 1,
                    core_version: "Kyoto/2.11".to_string(),
                    kind: TxKind::Normal,
                }
            },
        )
}

// ============================================================================
// 1. FACT CHAIN PROPERTY TESTS
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))] // Dilithium keygen is slow

    /// Compression is idempotent: compress(compress(chain)) == compress(chain).
    /// Once a chain is compressed, compressing again should not change it.
    #[test]
    fn fact_compression_idempotent(
        link_count in 7usize..=12,
        amounts in pvec(1u64..1_000_000, 7..=12),
    ) {
        let keys = test_keys();
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut vid = [0u8; 32];
                vid[0] = i as u8;
                (vid, k.pk.as_slice(), k.sk.as_slice())
            })
            .collect();

        // Build a chain where ALL links are resolved (eligible for compression)
        let link_count = link_count.min(amounts.len());
        let mut state_ids = Vec::with_capacity(link_count + 1);
        for i in 0..=link_count {
            let mut s = [0u8; 32];
            s[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            state_ids.push(s);
        }
        let tx_ids: Vec<[u8; 32]> = (0..link_count)
            .map(|i| {
                let mut t = [0u8; 32];
                t[0..8].copy_from_slice(&((i + 100) as u64).to_le_bytes());
                t
            })
            .collect();
        let resolved_flags = vec![true; link_count];

        let chain = build_valid_chain(
            &state_ids,
            &tx_ids,
            &amounts[..link_count],
            &resolved_flags,
            &keys,
        );

        // First compression
        let compressed1 = compress_fact_chain(chain, &validators).unwrap();
        let depth1 = compressed1.links.len();
        let cp1_count = compressed1.checkpoint.as_ref().map(|c| c.compressed_count);

        // Second compression (should be no-op or at least stable)
        let compressed2 = compress_fact_chain(compressed1.clone(), &validators).unwrap();
        let depth2 = compressed2.links.len();
        let cp2_count = compressed2.checkpoint.as_ref().map(|c| c.compressed_count);

        prop_assert_eq!(depth1, depth2, "link count changed on re-compression");
        prop_assert_eq!(cp1_count, cp2_count, "checkpoint count changed on re-compression");
    }

    /// Scar count is monotonically non-increasing under compression.
    /// Compression can only remove resolved links, never create new scars.
    #[test]
    fn fact_scar_count_monotonic(
        link_count in 3usize..=8,
        scar_bits in pvec(any::<bool>(), 3..=8),
    ) {
        let keys = test_keys();
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut vid = [0u8; 32];
                vid[0] = i as u8;
                (vid, k.pk.as_slice(), k.sk.as_slice())
            })
            .collect();

        let link_count = link_count.min(scar_bits.len());
        let mut state_ids = Vec::with_capacity(link_count + 1);
        for i in 0..=link_count {
            let mut s = [0u8; 32];
            s[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            state_ids.push(s);
        }
        let tx_ids: Vec<[u8; 32]> = (0..link_count)
            .map(|i| {
                let mut t = [0u8; 32];
                t[0..8].copy_from_slice(&((i + 100) as u64).to_le_bytes());
                t
            })
            .collect();
        let amounts = vec![1_000_000u64; link_count];
        // resolved = !scar (true = resolved, false = scar)
        let resolved_flags: Vec<bool> = scar_bits[..link_count].iter().map(|&b| !b).collect();

        let chain = build_valid_chain(&state_ids, &tx_ids, &amounts, &resolved_flags, &keys);
        let scar_before = chain.scar_count();

        let compressed = compress_fact_chain(chain, &validators).unwrap();
        let scar_after = compressed.scar_count();

        prop_assert!(
            scar_after <= scar_before,
            "scars increased: {} -> {}",
            scar_before,
            scar_after
        );
    }

    /// Chain continuity invariant after compression: if a checkpoint exists,
    /// checkpoint.final_state_id == first_link.previous_state_id.
    #[test]
    fn fact_compression_preserves_continuity(
        link_count in 7usize..=12,
    ) {
        let keys = test_keys();
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut vid = [0u8; 32];
                vid[0] = i as u8;
                (vid, k.pk.as_slice(), k.sk.as_slice())
            })
            .collect();

        let mut state_ids = Vec::with_capacity(link_count + 1);
        for i in 0..=link_count {
            let mut s = [0u8; 32];
            s[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            state_ids.push(s);
        }
        let tx_ids: Vec<[u8; 32]> = (0..link_count)
            .map(|i| {
                let mut t = [0u8; 32];
                t[0..8].copy_from_slice(&((i + 100) as u64).to_le_bytes());
                t
            })
            .collect();
        let amounts = vec![500_000u64; link_count];
        let resolved_flags = vec![true; link_count]; // all resolved → compressible

        let chain = build_valid_chain(&state_ids, &tx_ids, &amounts, &resolved_flags, &keys);
        let compressed = compress_fact_chain(chain, &validators).unwrap();

        if let Some(ref cp) = compressed.checkpoint {
            if let Some(first_link) = compressed.links.first() {
                prop_assert!(
                    ct_eq(&cp.final_state_id, &first_link.previous_state_id),
                    "checkpoint.final_state_id != first_link.previous_state_id after compression"
                );
            }
        }
    }

    /// A valid chain that is compressed then re-verified has same or fewer scars.
    #[test]
    fn fact_compress_then_verify_scar_count(
        link_count in 7usize..=10,
        scar_positions in pvec(any::<bool>(), 7..=10),
    ) {
        let keys = test_keys();
        let validators: Vec<([u8; 32], &[u8], &[u8])> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut vid = [0u8; 32];
                vid[0] = i as u8;
                (vid, k.pk.as_slice(), k.sk.as_slice())
            })
            .collect();

        let link_count = link_count.min(scar_positions.len());
        let mut state_ids = Vec::with_capacity(link_count + 1);
        for i in 0..=link_count {
            let mut s = [0u8; 32];
            s[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            state_ids.push(s);
        }
        let tx_ids: Vec<[u8; 32]> = (0..link_count)
            .map(|i| {
                let mut t = [0u8; 32];
                t[0..8].copy_from_slice(&((i + 100) as u64).to_le_bytes());
                t
            })
            .collect();
        let amounts = vec![1_000_000u64; link_count];
        let resolved_flags: Vec<bool> = scar_positions[..link_count].iter().map(|&b| !b).collect();

        let chain = build_valid_chain(&state_ids, &tx_ids, &amounts, &resolved_flags, &keys);
        let scar_before = chain.scar_count();

        let compressed = compress_fact_chain(chain, &validators).unwrap();
        // Scars in uncompressed links only — compressed resolved links are gone
        let scar_after = compressed.scar_count();

        prop_assert!(
            scar_after <= scar_before,
            "scar count increased after compress+verify: {} -> {}",
            scar_before,
            scar_after
        );
    }
}

// ============================================================================
// 2. CBOR CODEC PROPERTY TESTS
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Any Transaction round-trips through serde_json without loss.
    #[test]
    fn transaction_json_roundtrip(tx in arb_transaction()) {
        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();

        prop_assert_eq!(tx.consumed_state_id, decoded.consumed_state_id);
        prop_assert_eq!(tx.client_pk, decoded.client_pk);
        prop_assert_eq!(tx.sender_wallet_id, decoded.sender_wallet_id);
        prop_assert_eq!(tx.receiver_wallet_id, decoded.receiver_wallet_id);
        prop_assert_eq!(tx.amount, decoded.amount);
        prop_assert_eq!(tx.reference, decoded.reference);
        prop_assert_eq!(tx.nonce, decoded.nonce);
        prop_assert_eq!(tx.epoch, decoded.epoch);
        prop_assert_eq!(tx.required_k, decoded.required_k);
        prop_assert_eq!(tx.proof_type, decoded.proof_type);
    }

    /// Any PublicInputs round-trips through IPC encode/decode without loss.
    /// Constructs minimal PublicInputs via serde_json to avoid enumerating all fields.
    #[test]
    fn public_inputs_cbor_roundtrip(tx in arb_transaction()) {
        let tx_json = serde_json::to_value(&tx).unwrap();
        let inputs_json = serde_json::json!({
            "mode": "CL1",
            "transaction": tx_json,
            "prev_receipts": [],
            "current_state": null,
            "vbc_bundle": null,
            "cheque_bundle": null,
            "receiver_pk": null,
            "receiver_current_balance": null,
            "receiver_wallet_seq": null,
            "receiver_new_balance": null,
            "receiver_new_state_id": null,
            "my_validator_pk": null,
            "overlapped_signatures": [],
            "group_member_index": null,
            "sender_fact_chain": null,
            "my_dilithium_sk": null,
            "my_dilithium_pk": null,
            "my_validator_id": null,
            "fact_witness_sigs": [],
            "issuer_sphincs_sk": null,
            "witness_sigs": [],
        });
        let inputs: PublicInputs = serde_json::from_value(inputs_json).unwrap();

        let encoded = axiom_core_ipc::codec::encode_inputs(&inputs).unwrap();
        let decoded = axiom_core_ipc::codec::decode_inputs(&encoded).unwrap();

        // Verify key fields survived the roundtrip
        prop_assert_eq!(
            inputs.transaction.consumed_state_id,
            decoded.transaction.consumed_state_id
        );
        prop_assert_eq!(inputs.transaction.amount, decoded.transaction.amount);
        prop_assert_eq!(
            inputs.transaction.sender_wallet_id,
            decoded.transaction.sender_wallet_id
        );
        prop_assert_eq!(
            inputs.transaction.receiver_wallet_id,
            decoded.transaction.receiver_wallet_id
        );
        prop_assert_eq!(inputs.transaction.nonce, decoded.transaction.nonce);
        prop_assert_eq!(inputs.transaction.epoch, decoded.transaction.epoch);
        prop_assert_eq!(
            inputs.transaction.reference,
            decoded.transaction.reference
        );
    }

    /// Random bytes never cause a panic in CBOR decode (fuzz the decoder).
    #[test]
    fn cbor_decode_random_no_panic(data in pvec(any::<u8>(), 0..2000)) {
        // Must not panic — errors are fine
        let _ = axiom_core_ipc::codec::decode_inputs(&data);
    }
}

// ============================================================================
// 3. CRYPTO PROPERTY TESTS
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// ct_eq(a, a) == true for any a (reflexivity).
    #[test]
    fn ct_eq_reflexive(a in pvec(any::<u8>(), 0..128)) {
        prop_assert!(ct_eq(&a, &a), "ct_eq(a, a) must be true");
    }

    /// ct_eq(a, b) == ct_eq(b, a) (symmetry).
    #[test]
    fn ct_eq_symmetric(
        a in pvec(any::<u8>(), 0..128),
        b in pvec(any::<u8>(), 0..128),
    ) {
        prop_assert_eq!(
            ct_eq(&a, &b),
            ct_eq(&b, &a),
            "ct_eq must be symmetric"
        );
    }

    /// If a and b differ at any byte position, ct_eq returns false.
    #[test]
    fn ct_eq_detects_difference(
        base in pvec(any::<u8>(), 1..128),
        flip_pos_raw in any::<usize>(),
        flip_val in 1u8..=255,
    ) {
        let flip_pos = flip_pos_raw % base.len();
        let mut modified = base.clone();
        modified[flip_pos] ^= flip_val; // guaranteed non-zero XOR

        // If the XOR actually changed the byte (it always does since flip_val > 0)
        if base[flip_pos] != modified[flip_pos] {
            prop_assert!(
                !ct_eq(&base, &modified),
                "ct_eq should return false when bytes differ"
            );
        }
    }

    /// ct_eq returns false for different-length slices.
    #[test]
    fn ct_eq_different_lengths(
        a in pvec(any::<u8>(), 1..64),
        extra in pvec(any::<u8>(), 1..32),
    ) {
        let mut b = a.clone();
        b.extend_from_slice(&extra);
        prop_assert!(
            !ct_eq(&a, &b),
            "ct_eq must return false for different-length slices"
        );
    }

    /// compute_signing_message is injective: different key fields produce
    /// different signing messages (collision resistance).
    #[test]
    fn signing_message_injective_amount(
        tx in arb_transaction(),
        delta in 1u64..1_000_000,
    ) {
        let msg1 = compute_signing_message_public(&tx);

        let mut tx2 = tx.clone();
        tx2.amount = tx2.amount.wrapping_add(delta);
        // Only test when the add actually changed the value
        if tx2.amount != tx.amount {
            let msg2 = compute_signing_message_public(&tx2);
            prop_assert_ne!(msg1, msg2, "different amounts must produce different signing messages");
        }
    }

    /// Different nonces produce different signing messages.
    #[test]
    fn signing_message_injective_nonce(
        tx in arb_transaction(),
        delta in 1u64..1_000_000,
    ) {
        let msg1 = compute_signing_message_public(&tx);

        let mut tx2 = tx.clone();
        tx2.nonce = tx2.nonce.wrapping_add(delta);
        if tx2.nonce != tx.nonce {
            let msg2 = compute_signing_message_public(&tx2);
            prop_assert_ne!(msg1, msg2, "different nonces must produce different signing messages");
        }
    }

    /// Different receiver_wallet_ids produce different signing messages.
    #[test]
    fn signing_message_injective_receiver(
        tx in arb_transaction(),
        suffix in "[a-z]{1,4}",
    ) {
        let msg1 = compute_signing_message_public(&tx);

        let mut tx2 = tx.clone();
        tx2.receiver_wallet_id.push_str(&suffix);
        let msg2 = compute_signing_message_public(&tx2);
        prop_assert_ne!(msg1, msg2, "different receivers must produce different signing messages");
    }

    /// Different sender_wallet_ids produce different signing messages.
    #[test]
    fn signing_message_injective_sender(
        tx in arb_transaction(),
        suffix in "[a-z]{1,4}",
    ) {
        let msg1 = compute_signing_message_public(&tx);

        let mut tx2 = tx.clone();
        tx2.sender_wallet_id.push_str(&suffix);
        let msg2 = compute_signing_message_public(&tx2);
        prop_assert_ne!(msg1, msg2, "different senders must produce different signing messages");
    }
}
