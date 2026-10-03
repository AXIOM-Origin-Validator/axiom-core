//! ForkSettlement wave 2a (AXIOM_DESIGN_ForkSettlement.md §2.2, §2.3 [R17]) —
//! the `LegPreimage` a registration carries, checked against what CORE itself
//! produced, and the §13 wire refusals.
//!
//! Why an integration test (not a unit test in `nabla_wire.rs`): it decodes the
//! committed consensus vectors with `axiom_core_ipc`, which depends on
//! `axiom_core_logic`; inside the crate's own unit tests that would be a second
//! instance of every type.

use axiom_core_logic::nabla_wire::{LegPreimage, Registration, WireMessage};

fn vector(id: &str) -> (axiom_core_logic::types::PublicInputs, axiom_core_logic::types::PublicOutputs) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/consensus_vectors.json");
    let raw = std::fs::read_to_string(path).expect("tests/consensus_vectors.json is committed");
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let v = json["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap_or_else(|| panic!("vector {id} present"));
    assert_eq!(v["expected_result"], "Accept", "{id} must be an ACCEPT vector");
    let hex_of = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    let inputs = axiom_core_ipc::codec::decode_inputs(&hex_of("inputs_cbor_hex")).unwrap();
    let outputs = axiom_core_ipc::codec::decode_outputs(&hex_of("outputs_cbor_hex")).unwrap();
    (inputs, outputs)
}

/// THE wallet_seq SEMANTICS, measured on Core's own output (not re-derived):
/// the preimage's `wallet_seq` is `Transaction.wallet_seq`, and Core stamps
/// exactly that value as the receipt's `new_wallet_seq` (`validation.rs`, CL
/// output `new_wallet_seq: Some(tx.wallet_seq)`). So the door's check
/// `preimage.wallet_seq == receipt.new_wallet_seq` and the commitment recompute
/// agree on the SAME seq — and `preimage.commitment_hash()` reproduces the
/// commitment Core put on the receipt, which is what the k witnesses sign.
///
/// If Core ever stamped the post-increment seq instead, the first assertion
/// goes red; if `send_of` copied the wrong field, the second does.
#[test]
fn leg_preimage_reproduces_cores_own_commitment_and_seq() {
    for id in ["CL1_ACCEPT_001", "CL3_ACCEPT_001"] {
        let (inputs, outputs) = vector(id);
        let tx = &inputs.transaction;
        let leg = LegPreimage::send_of(tx).expect("a 32-byte-key send has a leg");
        let p = leg.send_preimage().unwrap();
        assert_eq!(
            Some(p.wallet_seq),
            outputs.new_wallet_seq,
            "{id}: receipt.new_wallet_seq is the tx's wallet_seq (the seq the preimage binds)",
        );
        assert_eq!(
            Some(p.commitment_hash()),
            outputs.commitment_hash,
            "{id}: the carried preimage reproduces Core's commitment_hash",
        );
        if let Some(txid) = outputs.txid {
            assert_eq!(p.txid(tx.epoch), txid, "{id}: and Core's txid under tx.epoch");
        }
        assert_eq!(p.consumed_state_id, tx.consumed_state_id);
    }
}

/// A send whose key is not 32 bytes has no leg (the fork verdict checks the
/// client sig under a 32-byte Ed25519 key).
#[test]
fn a_non_32_byte_key_has_no_send_leg() {
    let (inputs, _) = vector("CL1_ACCEPT_001");
    let mut tx = inputs.transaction.clone();
    tx.client_pk = vec![7u8; 33];
    assert!(LegPreimage::send_of(&tx).is_err());
}

fn cbor<T: serde::Serialize>(v: &T) -> ciborium::Value {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    ciborium::from_reader(b.as_slice()).unwrap()
}

fn sample_registration() -> Registration {
    // Built through serde from a JSON document so this test pins the WIRE
    // shape, not a Rust struct literal that would silently gain fields.
    let a = |b: u8| vec![b; 32];
    let wire = serde_json::json!({
        "wallet_id": a(1), "old_state": a(2), "new_state": a(3),
        "tx_hash": a(4), "k_tier": 3, "client_pk": a(5), "client_sig": [],
        "declared_balance": 0, "declared_hibernation_until": 0,
        "declared_wall_clock_lock": 0, "declared_emission_claimed_epoch": 0,
        // ValidatorJoin §6b.13 — mandatory (no default): the floor + format block.
        "declared_stake_floor_until": 0,
        "declared_wallet_format": {
            "wallet_version": 1, "ext_bytes_1": vec![0u8; 32], "ext_bytes_2": vec![0u8; 32],
            "ext_bytes_3": vec![0u8; 32], "ext_u64_1": 0, "ext_u64_2": 0, "ext_u64_3": 0
        },
        "claimant_wallet_id": "", "is_dev_claim": false,
        "receipt": {
            "consumed_state_id": a(2), "produced_state_id": a(3), "amount": 9,
            "signatures": [], "state_hash": a(6), "new_wallet_seq": 4,
            "commitment_hash": a(7), "epoch": 8
        },
        "preimage": { "Redeem": {
            "redeem": {
                "cheque_txid": a(4), "receiver_pk": a(5), "new_balance": 9,
                "new_state_id": a(3), "consumed_state_id": a(2)
            },
            // KI#241 F-2 — the cheque origin rides the redeem leg (LAST, mandatory).
            "cheque": {
                "preimage": {
                    "consumed_state_id": a(9), "client_pk": a(10), "wallet_seq": 1,
                    "receiver_wallet_id": "r", "amount": 9, "nonce": 1
                },
                "epoch": 8, "kind": "Send"
            }
        } }
    });
    serde_json::from_value(wire).expect("the complete wave-2a + W7a shape decodes")
}

/// W7a (spec R52c, §13): the wave-2a UNIT `Redeem` leg — a redeem announced
/// with no preimage — no longer decodes. Every redeem register carries the five
/// redeem-commitment inputs; there is no default and no fallback.
/// MUTATION: make the payload optional (`Redeem(Option<RedeemPreimage>)` or a
/// `#[serde(default)]`) → red.
#[test]
fn a_unit_redeem_leg_no_longer_decodes() {
    let mut wire = serde_json::to_value(sample_registration()).unwrap();
    wire["preimage"] = serde_json::json!("Redeem");
    assert!(serde_json::from_value::<Registration>(wire.clone()).is_err(),
        "the preimage-less wave-2a Redeem leg must be refused");
    // CBOR too (the wire the SDK and Nabla speak).
    let mut v = cbor(&sample_registration());
    if let ciborium::Value::Map(m) = &mut v {
        let slot = m.iter_mut().find(|(k, _)| k.as_text() == Some("preimage")).unwrap();
        slot.1 = ciborium::Value::Text("Redeem".into());
    }
    assert!(!decodes(&v), "CBOR: a unit Redeem leg must not decode");
    // A redeem preimage missing one of its five fields is refused too.
    for field in ["cheque_txid", "receiver_pk", "new_balance", "new_state_id", "consumed_state_id"] {
        let mut v = cbor(&sample_registration());
        strip(&mut v, &["preimage", "Redeem", "redeem"], field);
        assert!(!decodes(&v), "a RedeemPreimage without `{field}` must not decode");
    }
    // KI#241 F-2: the pre-F-2 shape (a Redeem leg with NO cheque origin) and
    // the tuple form `Redeem(RedeemPreimage)` are refused — never a default.
    let mut v = cbor(&sample_registration());
    strip(&mut v, &["preimage", "Redeem"], "cheque");
    assert!(!decodes(&v), "a Redeem leg without its cheque origin must not decode");
    let mut wire = serde_json::to_value(sample_registration()).unwrap();
    let inner = wire["preimage"]["Redeem"]["redeem"].clone();
    wire["preimage"] = serde_json::json!({ "Redeem": inner });
    assert!(serde_json::from_value::<Registration>(wire).is_err(), "the pre-F-2 tuple Redeem leg must be refused");
    assert!(decodes(&cbor(&sample_registration())), "control: the full shape decodes");
}

fn strip(v: &mut ciborium::Value, path: &[&str], key: &str) {
    let mut cur = v;
    for p in path {
        cur = match cur {
            ciborium::Value::Map(m) => &mut m.iter_mut().find(|(k, _)| k.as_text() == Some(p)).unwrap().1,
            _ => panic!("map expected"),
        };
    }
    if let ciborium::Value::Map(m) = cur {
        let before = m.len();
        m.retain(|(k, _)| k.as_text() != Some(key));
        assert_eq!(m.len() + 1, before, "{key} was present");
    }
}

fn decodes(v: &ciborium::Value) -> bool {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    ciborium::from_reader::<Registration, _>(b.as_slice()).is_ok()
}

/// §13 / [R17]: a SKELETON receipt — one that omits the four commitment inputs
/// the legacy `canonical_receipt: None` path zeroed — no longer DECODES. It is
/// refused at the wire, not merely failed at a later verify.
/// MUTATION: restore `#[serde(default)]` on any of the four → its case goes red.
#[test]
fn a_skeleton_k3_receipt_fails_to_decode() {
    let full = cbor(&sample_registration());
    assert!(decodes(&full), "control: the complete register decodes");
    for field in ["state_hash", "new_wallet_seq", "commitment_hash", "epoch"] {
        let mut v = full.clone();
        strip(&mut v, &["receipt"], field);
        assert!(!decodes(&v), "a K3Receipt without `{field}` must not decode");
    }
}

/// §13: a register without its leg does not decode (every register states it).
#[test]
fn a_registration_without_its_leg_fails_to_decode() {
    let mut v = cbor(&sample_registration());
    strip(&mut v, &[], "preimage");
    assert!(!decodes(&v));
    // And it rides the SDK→Nabla envelope intact.
    let reg = sample_registration();
    let msg = WireMessage::Register(reg.clone(), axiom_core_logic::nabla_wire::DeedTransaction {
        sender_wallet_id: [0; 32], receiver_wallet_id: [0; 32], amount: 0, signature: vec![],
    });
    let mut b = Vec::new();
    ciborium::into_writer(&msg, &mut b).unwrap();
    match ciborium::from_reader::<WireMessage, _>(b.as_slice()).unwrap() {
        WireMessage::Register(r, _) => assert_eq!(r.preimage, reg.preimage),
        _ => panic!("Register expected"),
    }
}
