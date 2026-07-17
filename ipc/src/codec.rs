//! Canonical CBOR Codec for Core IPC (YP §5.10)
//!
//! Encodes PublicInputs/PublicOutputs as CBOR maps with integer keys.
//! Integer keys are canonical: sorted by value (shorter CBOR encoding first).
//!
//! # Wire Format
//!
//! PublicInputs as CBOR map:
//!   { 0: mode, 1: transaction, 2: prev_receipts, 3: current_state, ... }
//!
//! # Integer keys, not strings
//!
//! serde derives produce string-keyed CBOR maps (field names).
//! Yellow Paper requires integer keys for:
//!   1. Compact wire format (1 byte vs N bytes for strings)
//!   2. Deterministic encoding (integer sort is unambiguous)
//!   3. ZK-circuit compatibility (no string parsing)

// CONSENSUS_CRITICAL

use axiom_core_logic::{
    PublicInputs, PublicOutputs, CoreLogicMode, ValidationResult, ValidationError,
};
use axiom_core_logic::types::*;
use ciborium::value::Value;

// ============================================================================
// PUBLIC API
// ============================================================================

/// Encode PublicInputs to Canonical CBOR with integer keys.
pub fn encode_inputs(inputs: &PublicInputs) -> Result<Vec<u8>, String> {
    let val = inputs_to_value(inputs);
    let mut buf = Vec::new();
    ciborium::into_writer(&val, &mut buf)
        .map_err(|e| format!("CBOR encode PublicInputs: {}", e))?;
    Ok(buf)
}

/// Decode PublicInputs from Canonical CBOR.
pub fn decode_inputs(bytes: &[u8]) -> Result<PublicInputs, String> {
    let val: Value = ciborium::from_reader(bytes)
        .map_err(|e| format!("CBOR decode PublicInputs: {}", e))?;
    value_to_inputs(&val)
}

/// Encode PublicOutputs to Canonical CBOR with integer keys.
pub fn encode_outputs(outputs: &PublicOutputs) -> Result<Vec<u8>, String> {
    let val = outputs_to_value(outputs);
    let mut buf = Vec::new();
    ciborium::into_writer(&val, &mut buf)
        .map_err(|e| format!("CBOR encode PublicOutputs: {}", e))?;
    Ok(buf)
}

/// Decode PublicOutputs from Canonical CBOR.
pub fn decode_outputs(bytes: &[u8]) -> Result<PublicOutputs, String> {
    let val: Value = ciborium::from_reader(bytes)
        .map_err(|e| format!("CBOR decode PublicOutputs: {}", e))?;
    value_to_outputs(&val)
}

// ============================================================================
// HELPERS — CBOR Value construction (i64 keys, not i128)
// ============================================================================

/// Build a canonical CBOR map from (key, value) pairs. Keys sorted ascending.
fn cbor_map(pairs: Vec<(i64, Value)>) -> Value {
    let mut sorted = pairs;
    sorted.sort_by_key(|(k, _)| *k);
    Value::Map(
        sorted
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    )
}

fn cbor_bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn cbor_u64(n: u64) -> Value {
    Value::Integer((n as i64).into())
}

fn cbor_text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn cbor_bool(b: bool) -> Value {
    Value::Bool(b)
}

fn cbor_null() -> Value {
    Value::Null
}

fn cbor_array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn cbor_opt<T, F: Fn(&T) -> Value>(opt: &Option<T>, f: F) -> Value {
    match opt {
        Some(v) => f(v),
        None => cbor_null(),
    }
}

// ============================================================================
// VALUE EXTRACTION HELPERS
// ============================================================================

fn get_map_field(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key as i128))
        .map(|(_, v)| v)
}

fn require_field<'a>(map: &'a [(Value, Value)], key: i64, name: &str) -> Result<&'a Value, String> {
    get_map_field(map, key).ok_or_else(|| format!("missing {} (key {})", name, key))
}

fn val_bytes(v: &Value) -> Result<Vec<u8>, String> {
    match v { Value::Bytes(b) => Ok(b.clone()), _ => Err("expected bytes".into()) }
}

fn val_bytes32(v: &Value) -> Result<[u8; 32], String> {
    val_bytes(v)?.try_into().map_err(|_| "expected 32 bytes".into())
}

fn val_u64(v: &Value) -> Result<u64, String> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            if n >= 0 && n <= u64::MAX as i128 { Ok(n as u64) }
            else { Err(format!("out of u64 range: {}", n)) }
        }
        _ => Err("expected integer".into()),
    }
}

fn val_u16(v: &Value) -> Result<u16, String> {
    val_u64(v).and_then(|n| {
        if n <= u16::MAX as u64 { Ok(n as u16) } else { Err("out of u16 range".into()) }
    })
}

fn val_u32(v: &Value) -> Result<u32, String> {
    val_u64(v).and_then(|n| {
        if n <= u32::MAX as u64 { Ok(n as u32) } else { Err("out of u32 range".into()) }
    })
}

fn val_text(v: &Value) -> Result<String, String> {
    match v { Value::Text(s) => Ok(s.clone()), _ => Err("expected text".into()) }
}

fn val_bool(v: &Value) -> Result<bool, String> {
    match v { Value::Bool(b) => Ok(*b), _ => Err("expected bool".into()) }
}

fn val_is_null(v: &Value) -> bool { matches!(v, Value::Null) }

fn val_opt<T, F: Fn(&Value) -> Result<T, String>>(v: &Value, f: F) -> Result<Option<T>, String> {
    if val_is_null(v) { Ok(None) } else { f(v).map(Some) }
}

fn val_array(v: &Value) -> Result<&Vec<Value>, String> {
    match v { Value::Array(a) => Ok(a), _ => Err("expected array".into()) }
}

fn val_map(v: &Value) -> Result<&Vec<(Value, Value)>, String> {
    match v {
        Value::Map(m) => {
            reject_duplicate_keys(m)?;
            Ok(m)
        }
        _ => Err("expected map".into()),
    }
}

/// AUDIT-FIX v2.11.13 (finding 3.3): Reject CBOR maps with duplicate integer keys.
/// Per YP §16.8.5.2: "No duplicate map keys. Same logical data = same bytes = same hash."
/// Prevents ambiguity attacks where different values under the same key
/// cause inconsistent field resolution across implementations.
fn reject_duplicate_keys(map: &[(Value, Value)]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for (k, _) in map {
        if let Value::Integer(i) = k {
            let key = i128::from(*i);
            if !seen.insert(key) {
                return Err(format!("duplicate CBOR map key: {}", key));
            }
        }
    }
    Ok(())
}

// ============================================================================
// INTEGER KEY ASSIGNMENTS — IMMUTABLE ONCE DEPLOYED (YP §5.10.4)
// ============================================================================

// PublicInputs
const PI_MODE: i64 = 0;
const PI_TX: i64 = 1;
const PI_PREV_RECEIPTS: i64 = 2;
const PI_CURRENT_STATE: i64 = 3;
const PI_VBC_BUNDLE: i64 = 4;
const PI_CHEQUE_BUNDLE: i64 = 5;
const PI_RECEIVER_PK: i64 = 6;
const PI_RECEIVER_BAL: i64 = 7;
const PI_RECEIVER_SEQ: i64 = 8;
const PI_RECEIVER_NEW_BAL: i64 = 9;
const PI_RECEIVER_NEW_SID: i64 = 10;
const PI_MY_VAL_PK: i64 = 11;
const PI_OVERLAP_SIGS: i64 = 12;
const PI_GROUP_IDX: i64 = 13;
const PI_SENDER_FACT: i64 = 14;
const PI_DIL_SK: i64 = 15;
const PI_DIL_PK: i64 = 16;
const PI_MY_VAL_ID: i64 = 17;
const PI_FACT_WSIGS: i64 = 18;
const PI_ISSUER_SPHINCS_SK: i64 = 19;  // CL8: issuer SPHINCS+ SK
const PI_CL1_EXEC_PROOF: i64 = 20;    // CL1: client execution proof
const PI_ZKP_NONCE: i64 = 21;         // ZKP anti-replay nonce
// §23.14 fields (not previously in CBOR — were serde-only)
const PI_AUDIT_CONFIRM: i64 = 22;    // §23.14 audit confirmation
const PI_SCAR_HEAL_TX: i64 = 23;     // CL9 scar heal tx_id
const PI_SCAR_HEAL_NABLA: i64 = 24;  // CL9 scar heal nabla_id
const PI_SCAR_HEAL_ROOT: i64 = 25;   // CL9 scar heal root_hash
// YPX-009 Silicon Pulse fields
const PI_NONCE_RESPONSE: i64 = 26;   // YPX-009: nonce response from Lambda
const PI_AUDIT_RESPONSE: i64 = 27;   // YPX-009: audit response from Lambda
// CL11 Console fields
const PI_CONSOLE_CURRENT: i64 = 28;  // CL11: current ConsoleCertificate
const PI_CONSOLE_NEW: i64 = 29;      // CL11: new ConsoleCertificate
const PI_CONSOLE_PICKS: i64 = 30;    // CL11: selector picks
const PI_CONSOLE_NOMS: i64 = 31;     // CL11: nominations
const PI_MAX_FACT_LINKS: i64 = 32;   // Operator's max_fact_links (None = unlimited)

// PublicOutputs
const PO_RESULT: i64 = 0;
const PO_STATE_HASH: i64 = 1;
const PO_PROD_SID: i64 = 2;
const PO_NEW_SEQ: i64 = 3;
const PO_REJECT: i64 = 4;
const PO_OVERLAP: i64 = 5;
const PO_COMMIT: i64 = 6;
const PO_TXID: i64 = 7;
const PO_FACT_SIG: i64 = 8;
const PO_NEW_BAL: i64 = 9;
const PO_NBC_SIG: i64 = 10;            // CL8: NBC SPHINCS+ signature
const PO_ZKP_NONCE_HASH: i64 = 11;    // ZKP anti-replay nonce hash
const PO_REQUIRED_K: i64 = 12;         // YPX-007: required validators
const PO_EXTRACTED_PT: i64 = 13;       // YPX-007: extracted proof type
// §23.14 fields (not previously in CBOR — were serde-only)
const PO_AUDIT_DEMAND: i64 = 14;      // §23.14 audit demand
// YPX-009 Silicon Pulse fields
const PO_AUDIT_REQUEST: i64 = 15;     // YPX-009: audit request from AVM
const PO_NONCE_CHALLENGE: i64 = 16;   // YPX-009: nonce challenge from AVM
const PO_PULSE_PROOF: i64 = 17;       // YPX-009: pulse proof data
const PO_AUDIT_FAILED: i64 = 18;      // YPX-009: audit failure flag

// ============================================================================
// ENCODE/DECODE: PublicInputs
// ============================================================================

fn inputs_to_value(pi: &PublicInputs) -> Value {
    let pairs = vec![
        (PI_MODE, cbor_u64(mode_to_u64(&pi.mode))),
        (PI_TX, tx_to_value(&pi.transaction)),
        (PI_PREV_RECEIPTS, cbor_array(pi.prev_receipts.iter().map(receipt_to_value).collect())),
        (PI_CURRENT_STATE, cbor_opt(&pi.current_state, ws_to_value)),
        (PI_VBC_BUNDLE, cbor_opt(&pi.vbc_bundle, blob_encode)),
        (PI_CHEQUE_BUNDLE, cbor_opt(&pi.cheque_bundle, blob_encode)),
        (PI_RECEIVER_PK, cbor_opt(&pi.receiver_pk, |v| cbor_bytes(v))),
        (PI_RECEIVER_BAL, cbor_opt(&pi.receiver_current_balance, |v| cbor_u64(*v))),
        (PI_RECEIVER_SEQ, cbor_opt(&pi.receiver_wallet_seq, |v| cbor_u64(*v))),
        (PI_RECEIVER_NEW_BAL, cbor_opt(&pi.receiver_new_balance, |v| cbor_u64(*v))),
        (PI_RECEIVER_NEW_SID, cbor_opt(&pi.receiver_new_state_id, |v| cbor_bytes(v))),
        (PI_MY_VAL_PK, cbor_opt(&pi.my_validator_pk, |v| cbor_bytes(v))),
        (PI_OVERLAP_SIGS, cbor_array(pi.overlapped_signatures.iter().map(wsig_to_value).collect())),
        (PI_GROUP_IDX, cbor_opt(&pi.group_member_index, |v| cbor_u64(*v as u64))),
        (PI_SENDER_FACT, cbor_opt(&pi.sender_fact_chain, fact_chain_to_value)),
        (PI_MAX_FACT_LINKS, cbor_opt(&pi.max_fact_links, |v| cbor_u64(*v as u64))),
        (PI_DIL_SK, cbor_opt(&pi.my_dilithium_sk, |v| cbor_bytes(v))),
        (PI_DIL_PK, cbor_opt(&pi.my_dilithium_pk, |v| cbor_bytes(v))),
        (PI_MY_VAL_ID, cbor_opt(&pi.my_validator_id, |v| cbor_bytes(v))),
        (PI_FACT_WSIGS, cbor_array(pi.fact_witness_sigs.iter().map(wsig_to_value).collect())),
        (PI_ISSUER_SPHINCS_SK, cbor_opt(&pi.issuer_sphincs_sk, |v| cbor_bytes(v))),
        (PI_CL1_EXEC_PROOF, cbor_opt(&pi.cl1_execution_proof, |v| cbor_bytes(v))),
        (PI_ZKP_NONCE, cbor_opt(&pi.zkp_nonce, |v| cbor_bytes(v))),
        (PI_AUDIT_CONFIRM, cbor_opt(&pi.audit_confirmation, blob_encode)),
        (PI_SCAR_HEAL_TX, cbor_opt(&pi.scar_heal_tx_id, |v| cbor_bytes(v))),
        (PI_SCAR_HEAL_NABLA, cbor_opt(&pi.scar_heal_nabla_id, |v| cbor_bytes(v))),
        (PI_SCAR_HEAL_ROOT, cbor_opt(&pi.scar_heal_root_hash, |v| cbor_bytes(v))),
        (PI_NONCE_RESPONSE, cbor_opt(&pi.nonce_response, blob_encode)),
        (PI_AUDIT_RESPONSE, cbor_opt(&pi.audit_response, blob_encode)),
        // CL11 Console fields
        (PI_CONSOLE_CURRENT, cbor_opt(&pi.console_current_cert, blob_encode)),
        (PI_CONSOLE_NEW, cbor_opt(&pi.console_new_cert, blob_encode)),
        (PI_CONSOLE_PICKS, cbor_opt(&pi.console_selector_picks, blob_encode)),
        (PI_CONSOLE_NOMS, cbor_opt(&pi.console_nominations, blob_encode)),
        // txid_attestation not encoded via IPC (only used in direct AVM path)
    ];
    cbor_map(pairs)
}

fn value_to_inputs(val: &Value) -> Result<PublicInputs, String> {
    let m = val_map(val)?;
    Ok(PublicInputs {
        // oods_attestation not encoded via IPC (only used in the direct
        // AVM path — same treatment as txid_attestation).
        oods_attestation: None,
        recall_attestation: None,
        mode: u64_to_mode(val_u64(require_field(m, PI_MODE, "mode")?)?)?,
        transaction: value_to_tx(require_field(m, PI_TX, "tx")?)?,
        prev_receipts: val_array(require_field(m, PI_PREV_RECEIPTS, "prev_receipts")?)?
            .iter().map(value_to_receipt).collect::<Result<Vec<_>,_>>()?,
        current_state: val_opt(require_field(m, PI_CURRENT_STATE, "state")?, value_to_ws)?,
        vbc_bundle: val_opt(require_field(m, PI_VBC_BUNDLE, "vbc")?, blob_decode::<VBCProofBundle>)?,
        cheque_bundle: val_opt(require_field(m, PI_CHEQUE_BUNDLE, "cheque")?, blob_decode::<ChequeBundle>)?,
        receiver_pk: val_opt(require_field(m, PI_RECEIVER_PK, "rpk")?, val_bytes)?,
        receiver_current_balance: val_opt(require_field(m, PI_RECEIVER_BAL, "rbal")?, val_u64)?,
        receiver_wallet_seq: val_opt(require_field(m, PI_RECEIVER_SEQ, "rseq")?, val_u64)?,
        receiver_new_balance: val_opt(require_field(m, PI_RECEIVER_NEW_BAL, "rnbal")?, val_u64)?,
        receiver_new_state_id: val_opt(require_field(m, PI_RECEIVER_NEW_SID, "rnsid")?, val_bytes32)?,
        my_validator_pk: val_opt(require_field(m, PI_MY_VAL_PK, "mvpk")?, val_bytes)?,
        overlapped_signatures: val_array(require_field(m, PI_OVERLAP_SIGS, "osigs")?)?
            .iter().map(value_to_wsig).collect::<Result<Vec<_>,_>>()?,
        group_member_index: val_opt(require_field(m, PI_GROUP_IDX, "gidx")?, |v| val_u64(v).map(|n| n as u32))?,
        sender_fact_chain: val_opt(require_field(m, PI_SENDER_FACT, "sfc")?, value_to_fact_chain)?,
        max_fact_links: val_opt(require_field(m, PI_MAX_FACT_LINKS, "mfl")?, |v| val_u64(v).map(|n| n as u32))?,
        // IPC codec is conformance / multi-host only (CLAUDE.md). The
        // embedded-AVM path round-trips this field via serde directly;
        // IPC mode hasn't been wired for redeem yet, so leave None.
        receiver_fact_chain: None,
        my_dilithium_sk: val_opt(require_field(m, PI_DIL_SK, "dsk")?, val_bytes)?,
        my_dilithium_pk: val_opt(require_field(m, PI_DIL_PK, "dpk")?, val_bytes)?,
        my_validator_id: val_opt(require_field(m, PI_MY_VAL_ID, "vid")?, val_bytes32)?,
        fact_witness_sigs: val_array(require_field(m, PI_FACT_WSIGS, "fws")?)?
            .iter().map(value_to_wsig).collect::<Result<Vec<_>,_>>()?,
        issuer_sphincs_sk: match get_map_field(m, PI_ISSUER_SPHINCS_SK) {
            Some(v) => val_opt(v, val_bytes)?,
            None => None, // Backwards compatible: old encodings without this field
        },
        cl1_execution_proof: match get_map_field(m, PI_CL1_EXEC_PROOF) {
            Some(v) => val_opt(v, val_bytes)?,
            None => None, // Backwards compatible: old encodings without this field
        },
        zkp_nonce: match get_map_field(m, PI_ZKP_NONCE) {
            Some(v) => val_opt(v, val_bytes32)?,
            None => None,
        },
        audit_confirmation: match get_map_field(m, PI_AUDIT_CONFIRM) {
            Some(v) => val_opt(v, blob_decode::<AuditConfirmation>)?,
            None => None,
        },
        nonce_response: match get_map_field(m, PI_NONCE_RESPONSE) {
            Some(v) => val_opt(v, blob_decode::<NonceResponse>)?,
            None => None,
        },
        audit_response: match get_map_field(m, PI_AUDIT_RESPONSE) {
            Some(v) => val_opt(v, blob_decode::<PulseAuditResponse>)?,
            None => None,
        },
        scar_heal_tx_id: match get_map_field(m, PI_SCAR_HEAL_TX) {
            Some(v) => val_opt(v, val_bytes32)?,
            None => None,
        },
        scar_heal_nabla_id: match get_map_field(m, PI_SCAR_HEAL_NABLA) {
            Some(v) => val_opt(v, val_bytes32)?,
            None => None,
        },
        scar_heal_root_hash: match get_map_field(m, PI_SCAR_HEAL_ROOT) {
            Some(v) => val_opt(v, val_bytes32)?,
            None => None,
        },
        // Fields not carried over IPC CBOR — set defaults
        wallet_secret: None,
        fanout_message: None,
        candidate_balance: None,
        nabla_stake_proof: None,
        frozen_wallets: None,
        // CL11 Console fields
        console_current_cert: match get_map_field(m, PI_CONSOLE_CURRENT) {
            Some(v) => val_opt(v, blob_decode::<ConsoleCertificate>)?,
            None => None,
        },
        console_new_cert: match get_map_field(m, PI_CONSOLE_NEW) {
            Some(v) => val_opt(v, blob_decode::<ConsoleCertificate>)?,
            None => None,
        },
        console_selector_picks: match get_map_field(m, PI_CONSOLE_PICKS) {
            Some(v) => val_opt(v, blob_decode::<Vec<SelectorPick>>)?,
            None => None,
        },
        console_nominations: match get_map_field(m, PI_CONSOLE_NOMS) {
            Some(v) => val_opt(v, blob_decode::<Vec<[u8; 32]>>)?,
            None => None,
        },
        txid_attestation: None,
        cheque_claim_proof: None, // Not transmitted via IPC (direct AVM path only)
        clara_attestation: None, // Not transmitted via IPC (direct AVM path only)
        phase_out_payload: None, // Not transmitted via IPC (direct AVM path only)
        phase_out_era_end_ticks: Vec::new(),
        phase_out_blocked_era_ids: Vec::new(),
        current_tick: 0,
        // Not transmitted via IPC (direct AVM path only). All-zero
        // means "no core_id gate" — accepted for backward compat;
        // see validation.rs Step -1.5.
        local_core_id: [0u8; 32],

        withdrawal_inputs: None,
        // YPX-020 hibernation: not carried over IPC (conformance / multi-host
        // only). Redeem-side state-anchoring runs through the embedded-AVM
        // path which round-trips this via serde directly.
        receiver_current_hibernation: None,
    })
}

// ============================================================================
// ENCODE/DECODE: PublicOutputs
// ============================================================================

fn outputs_to_value(po: &PublicOutputs) -> Value {
    let pairs = vec![
        (PO_RESULT, cbor_u64(vr_to_u64(&po.result))),
        (PO_STATE_HASH, cbor_opt(&po.new_state_hash, |h| cbor_bytes(h))),
        (PO_PROD_SID, cbor_opt(&po.produced_state_id, |h| cbor_bytes(h))),
        (PO_NEW_SEQ, cbor_opt(&po.new_wallet_seq, |v| cbor_u64(*v))),
        (PO_REJECT, cbor_opt(&po.rejection_reason, |r| cbor_u64(ve_to_u64(r)))),
        (PO_OVERLAP, cbor_opt(&po.is_overlapped, |b| cbor_bool(*b))),
        (PO_COMMIT, cbor_opt(&po.commitment_hash, |h| cbor_bytes(h))),
        (PO_TXID, cbor_opt(&po.txid, |h| cbor_bytes(h))),
        (PO_FACT_SIG, cbor_opt(&po.fact_signature, |s| cbor_bytes(s))),
        (PO_NEW_BAL, cbor_opt(&po.new_balance, |v| cbor_u64(*v))),
        (PO_NBC_SIG, cbor_opt(&po.nbc_signature, |v| cbor_bytes(v))),
        (PO_ZKP_NONCE_HASH, cbor_opt(&po.zkp_nonce_hash, |v| cbor_bytes(v))),
        (PO_REQUIRED_K, cbor_u64(po.required_k as u64)),
        (PO_EXTRACTED_PT, cbor_u64(po.extracted_proof_type as u64)),
        (PO_AUDIT_DEMAND, cbor_opt(&po.audit_demand, blob_encode)),
        (PO_AUDIT_REQUEST, cbor_opt(&po.audit_request, blob_encode)),
        (PO_NONCE_CHALLENGE, cbor_opt(&po.nonce_challenge, blob_encode)),
        (PO_PULSE_PROOF, cbor_opt(&po.pulse_proof, blob_encode)),
        (PO_AUDIT_FAILED, cbor_bool(po.audit_failed)),
    ];
    cbor_map(pairs)
}

fn value_to_outputs(val: &Value) -> Result<PublicOutputs, String> {
    let m = val_map(val)?;
    Ok(PublicOutputs {
        // Same conformance-only treatment as is_dev_class (YPX-021 §8.2).
        oods_flag: None,
        result: u64_to_vr(val_u64(require_field(m, PO_RESULT, "result")?)?)?,
        new_state_hash: val_opt(require_field(m, PO_STATE_HASH, "sh")?, val_bytes32)?,
        produced_state_id: val_opt(require_field(m, PO_PROD_SID, "psid")?, val_bytes32)?,
        new_wallet_seq: val_opt(require_field(m, PO_NEW_SEQ, "nseq")?, val_u64)?,
        rejection_reason: val_opt(require_field(m, PO_REJECT, "rej")?, |v| val_u64(v).and_then(u64_to_ve))?,
        is_overlapped: val_opt(require_field(m, PO_OVERLAP, "ovlp")?, val_bool)?,
        commitment_hash: val_opt(require_field(m, PO_COMMIT, "cmit")?, val_bytes32)?,
        txid: val_opt(require_field(m, PO_TXID, "txid")?, val_bytes32)?,
        fact_signature: val_opt(require_field(m, PO_FACT_SIG, "fsig")?, val_bytes)?,
        new_balance: val_opt(require_field(m, PO_NEW_BAL, "nbal")?, val_u64)?,
        nbc_signature: match get_map_field(m, PO_NBC_SIG) {
            Some(v) => val_opt(v, val_bytes)?,
            None => None, // Backwards compatible
        },
        zkp_nonce_hash: match get_map_field(m, PO_ZKP_NONCE_HASH) {
            Some(v) => val_opt(v, val_bytes32)?,
            None => None, // Backwards compatible
        },
        required_k: match get_map_field(m, PO_REQUIRED_K) {
            Some(v) => val_u64(v)? as u8,
            None => 0, // Backwards compatible
        },
        extracted_proof_type: match get_map_field(m, PO_EXTRACTED_PT) {
            Some(v) => val_u64(v)? as u8,
            None => 0,
        },
        audit_demand: match get_map_field(m, PO_AUDIT_DEMAND) {
            Some(v) => val_opt(v, blob_decode::<AuditDemand>)?,
            None => None,
        },
        audit_request: match get_map_field(m, PO_AUDIT_REQUEST) {
            Some(v) => val_opt(v, blob_decode::<PulseAuditRequest>)?,
            None => None,
        },
        nonce_challenge: match get_map_field(m, PO_NONCE_CHALLENGE) {
            Some(v) => val_opt(v, blob_decode::<NonceChallenge>)?,
            None => None,
        },
        pulse_proof: match get_map_field(m, PO_PULSE_PROOF) {
            Some(v) => val_opt(v, blob_decode::<PulseProofData>)?,
            None => None,
        },
        audit_failed: match get_map_field(m, PO_AUDIT_FAILED) {
            Some(v) => val_bool(v)?,
            None => false,
        },
        // Not carried over IPC CBOR — set default
        fanout_new_ttl: None,
        console_chain_hash: None,
        compressed_fact_chain: None,
        // A2-redeem chain — embedded-AVM path round-trips this via serde;
        // IPC codec leaves it None until IPC mode is wired for redeem.
        receiver_fact_chain: None,
        receipt_commitment: None,

        validator_withdrawal_mint: None,
        // Not carried over IPC CBOR — IPC path is conformance-only and
        // never sees the dev-class flag. Defaults to None (Lambda
        // treats None as `false` at the Receipt-build site).
        is_dev_class: None,
        // YPX-020: same as is_dev_class — the IPC codec is the legacy
        // conformance/subprocess path and does not carry the newer trailing
        // fields (production reads PublicOutputs via serde, which DOES carry
        // hibernation_until). Defaults to 0.
        hibernation_until: 0,
    })
}

// ============================================================================
// ENUM MAPPINGS — Integer ↔ Enum (stable codes, never renumber)
// ============================================================================

fn mode_to_u64(m: &CoreLogicMode) -> u64 {
    match m {
        CoreLogicMode::CL1 => 1, CoreLogicMode::CL2 => 2,
        CoreLogicMode::CL3 => 3, CoreLogicMode::CL4 => 4,
        CoreLogicMode::CL5 => 5,
        // Code 6 retired (CL6 standalone VBC-verify removed as dead code 2026-07-05).
        CoreLogicMode::CL7 => 7, CoreLogicMode::CL8 => 8,
        CoreLogicMode::CL9 => 9, CoreLogicMode::CL10 => 10,
        CoreLogicMode::CL11 => 11,
        CoreLogicMode::CL2_PREFILTER => 12,
        // Code 13 retired (old CL12 / JFP_VERDICT removed — out-of-scope
        // Phase 3c rewrite). Slot stays reserved; do not reuse.
        CoreLogicMode::CL13 => 14,
        // CL12 reused for offline Send Proof verification (fresh code 15 — the
        // retired 13 is NOT reused).
        CoreLogicMode::CL12 => 15,
    }
}

fn u64_to_mode(n: u64) -> Result<CoreLogicMode, String> {
    match n {
        1 => Ok(CoreLogicMode::CL1), 2 => Ok(CoreLogicMode::CL2),
        3 => Ok(CoreLogicMode::CL3), 4 => Ok(CoreLogicMode::CL4),
        5 => Ok(CoreLogicMode::CL5),
        // Code 6 retired (CL6 removed 2026-07-05) — decodes to an error now.
        7 => Ok(CoreLogicMode::CL7), 8 => Ok(CoreLogicMode::CL8),
        9 => Ok(CoreLogicMode::CL9), 10 => Ok(CoreLogicMode::CL10),
        11 => Ok(CoreLogicMode::CL11),
        12 => Ok(CoreLogicMode::CL2_PREFILTER),
        // Code 13 retired (old CL12 / JFP_VERDICT removed).
        14 => Ok(CoreLogicMode::CL13),
        15 => Ok(CoreLogicMode::CL12),
        _ => Err(format!("unknown mode: {}", n)),
    }
}

fn vr_to_u64(r: &ValidationResult) -> u64 {
    match r { ValidationResult::Accept => 0, ValidationResult::Reject => 1, ValidationResult::Fatal => 2 }
}

fn u64_to_vr(n: u64) -> Result<ValidationResult, String> {
    match n {
        0 => Ok(ValidationResult::Accept), 1 => Ok(ValidationResult::Reject),
        2 => Ok(ValidationResult::Fatal), _ => Err(format!("unknown result: {}", n)),
    }
}

/// ValidationError → integer code. Stable — NEVER renumber.
fn ve_to_u64(e: &ValidationError) -> u64 {
    match e {
        // State
        ValidationError::StateIdAlreadyConsumed => 100,
        ValidationError::InvalidStateId => 101,
        // Wallet seq
        ValidationError::InvalidWalletSeq => 200,
        ValidationError::WalletSeqOverflow => 201,
        // Wallet ID
        ValidationError::InvalidWalletId => 210,
        ValidationError::MalformedAddress => 211,
        // Signature
        ValidationError::InvalidClientSignature => 300,
        ValidationError::InvalidWitnessSignature => 301,
        ValidationError::UnsupportedSignatureAlgorithm => 302,
        // Balance
        ValidationError::InsufficientBalance => 400,
        ValidationError::ConservationViolation => 401,
        ValidationError::ZeroAmount => 402,
        ValidationError::DustAmount => 403,
        // VBC
        ValidationError::InvalidVBC => 500,
        ValidationError::VBCExpired { .. } => 501,
        ValidationError::VBCNotYetValid { .. } => 502,
        ValidationError::VBCChainTooDeep => 503,
        ValidationError::VBCMissingIssuer => 504,
        ValidationError::VBCRootKeyMismatch => 505,
        ValidationError::DuplicateValidator => 506,
        ValidationError::InvalidVBCCount => 507,
        // Genesis
        ValidationError::MissingPrevReceipts => 600,
        ValidationError::InvalidGenesisTransaction => 601,
        // Proof
        ValidationError::InvalidExecutionProof => 700,
        ValidationError::ProgramDigestMismatch => 701,
        // JSON
        ValidationError::InvalidCanonicalJson => 710,
        // Cheque
        ValidationError::InsufficientCheques => 800,
        ValidationError::InconsistentChequeBundle => 801,
        ValidationError::InvalidChequeSignature => 802,
        ValidationError::ChequeAlreadyRedeemed => 803,
        // Redeem
        ValidationError::RedeemBalanceMismatch => 850,
        ValidationError::RedeemBalanceOverflow => 851,
        ValidationError::MissingRedeemInputs => 852,
        // Codes 860-864 retired with the v2.11.6 fee-cheque flow (Step 9A).
        // Carrier
        ValidationError::CarriersTooLarge => 900,
        // Hints
        ValidationError::InvalidHintCount => 910,
        ValidationError::SelfHintNotAllowed => 911,
        // S-ABR
        ValidationError::SABRInsufficientOverlap => 920,
        ValidationError::SABROverlapNotInPrev => 921,
        ValidationError::SABRMissingValidatorPK => 922,
        ValidationError::SABRHashMismatch => 923,
        // Auth
        ValidationError::AuthHashRequired => 950,
        ValidationError::InvalidAuthProof => 951,
        // Lineage
        ValidationError::ReceiptFromWrongWorldline => 960,
        ValidationError::ReceiptLineageMismatch => 961,
        // Group
        ValidationError::GroupTooManyMembers => 970,
        ValidationError::GroupShareBpsInvalid => 971,
        ValidationError::GroupNotMember => 972,
        ValidationError::GroupInsufficientAvailable => 973,
        ValidationError::GroupChecksumFailed => 974,
        ValidationError::GroupMembersImmutable => 975,
        ValidationError::GroupDistributionOverflow => 976,
        // FACT
        ValidationError::FactChainTooDeep => 1000,
        ValidationError::FactChainBreak => 1001,
        ValidationError::FactInsufficientWitnesses => 1002,
        ValidationError::FactInvalidSignature => 1003,
        ValidationError::FactDuplicateWitness => 1004,
        ValidationError::FactInvalidCheckpoint => 1005,
        // Burn
        ValidationError::BurnNoFactChain => 1020,
        ValidationError::BurnMissingTarget => 1021,
        ValidationError::BurnTargetNotFound => 1022,
        ValidationError::BurnTargetNotScarred => 1023,
        ValidationError::BurnTargetAlreadyBurned => 1024,
        ValidationError::BurnAmountMismatch => 1025,
        ValidationError::BurnProofInsufficientWitnesses => 1026,
        ValidationError::BurnProofDuplicateValidator => 1027,
        ValidationError::BurnTxIdNotInChain => 1028,
        // Scar cap
        ValidationError::TooManyUnresolvedScars => 1030,
        // Wallet state
        ValidationError::MissingWalletState => 1010,
        // Other
        ValidationError::MissingExecutionProof => 853,
        ValidationError::MissingVBC => 854,
        // YPX-007
        ValidationError::ZkpNotQualified => 930,
        ValidationError::ArkNotImplemented => 931,
        // YPX-012 Oracle
        ValidationError::OracleSenderMismatch => 1100,
        ValidationError::OracleInsufficientK => 1101,
        ValidationError::OraclePlatformInvalid => 1102,
        ValidationError::OracleLivingSignatureMissing => 1103,
        ValidationError::OracleZeroDelta => 1104,
        ValidationError::OracleNonZeroAmount => 1105,
        ValidationError::OracleMaturityNotReached => 1106,
        // Version
        ValidationError::VersionMismatch => 1040,
        // CL9
        ValidationError::MissingDilithiumKey => 1050,
        ValidationError::MissingField => 1051,
        // Wallet secret
        ValidationError::WalletSecretMismatch => 1060,
        // Fan-Out (CL10)
        ValidationError::FanOutMissingMessage => 1200,
        ValidationError::FanOutTtlExceeded => 1201,
        ValidationError::FanOutInvalidFanout => 1202,
        ValidationError::FanOutContentEmpty => 1203,
        ValidationError::FanOutContentTooLarge => 1204,
        ValidationError::FanOutTtlExpired => 1205,
        ValidationError::FanOutTtlInflated => 1206,
        ValidationError::FanOutUnknownContentType => 1207,
        ValidationError::FanOutTimestampFuture => 1208,
        ValidationError::FanOutTimestampExpired => 1209,
        ValidationError::FanOutDiffusionIdMismatch => 1210,
        ValidationError::FanOutInvalidOriginator => 1211,
        ValidationError::FanOutOriginatorPkMismatch => 1212,
        ValidationError::FanOutInvalidSignature => 1213,
        // Stake / Ark / Frozen
        ValidationError::InsufficientStake => 1300,
        ValidationError::WalletFrozen => 1301,
        ValidationError::ArkToNonArkRejected => 1302,
        ValidationError::ArkChargeNotOwner => 1303,
        ValidationError::ArkUnloadScarred => 1304,
        // Nabla stake
        ValidationError::NablaWriterDetected => 1310,
        ValidationError::StakeWalletMismatch => 1311,
        ValidationError::StakeNablaSignatureInvalid => 1312,
        ValidationError::StakeStateMismatch => 1313,
        ValidationError::StakeInsufficientReceipts => 1314,
        ValidationError::StakeProofExpired => 1315,
        // v2.11.13 additions
        ValidationError::ReferenceTooLarge => 1400,
        ValidationError::GroupMemberMismatch => 1401,
        ValidationError::MissingDilithiumPk => 1402,
        ValidationError::SelfSendRejected => 1403,
        ValidationError::ReceiverAddressRequired => 1404,
        ValidationError::InvalidReceiverAddress => 1405,
        // Console (CL11)
        ValidationError::ConsoleInvalidGeneration => 1500,
        ValidationError::ConsoleChainMismatch => 1501,
        ValidationError::ConsoleInvalidSeatCount => 1502,
        ValidationError::ConsoleDuplicateSeat => 1503,
        ValidationError::ConsoleTermMismatch => 1504,
        ValidationError::ConsoleInvalidTermLength => 1505,
        ValidationError::ConsoleInvalidSelector => 1506,
        ValidationError::ConsoleInvalidPick => 1507,
        ValidationError::ConsoleIncompleteSelection => 1508,
        ValidationError::ConsoleNotMember => 1509,
        // Genesis lockup
        ValidationError::GenesisStakeLocked => 1600,
        // Other
        ValidationError::InvalidMode => 9998,
        ValidationError::InternalError => 9999,
        // Catch-all for any remaining/future variants
        _ => 9900,
    }
}

fn u64_to_ve(n: u64) -> Result<ValidationError, String> {
    match n {
        100 => Ok(ValidationError::StateIdAlreadyConsumed),
        101 => Ok(ValidationError::InvalidStateId),
        200 => Ok(ValidationError::InvalidWalletSeq),
        201 => Ok(ValidationError::WalletSeqOverflow),
        210 => Ok(ValidationError::InvalidWalletId),
        211 => Ok(ValidationError::MalformedAddress),
        300 => Ok(ValidationError::InvalidClientSignature),
        301 => Ok(ValidationError::InvalidWitnessSignature),
        302 => Ok(ValidationError::UnsupportedSignatureAlgorithm),
        400 => Ok(ValidationError::InsufficientBalance),
        401 => Ok(ValidationError::ConservationViolation),
        402 => Ok(ValidationError::ZeroAmount),
        403 => Ok(ValidationError::DustAmount),
        500 => Ok(ValidationError::InvalidVBC),
        // IPC codec drops the (expires_at, current_tick) context for
        // wire compatibility — tick 0 is a sentinel "unknown" that
        // clients treat as "server didn't provide lifecycle data".
        501 => Ok(ValidationError::VBCExpired { expires_at: 0, current_tick: 0 }),
        502 => Ok(ValidationError::VBCNotYetValid { issued_at: 0, current_tick: 0 }),
        503 => Ok(ValidationError::VBCChainTooDeep),
        504 => Ok(ValidationError::VBCMissingIssuer),
        505 => Ok(ValidationError::VBCRootKeyMismatch),
        506 => Ok(ValidationError::DuplicateValidator),
        507 => Ok(ValidationError::InvalidVBCCount),
        600 => Ok(ValidationError::MissingPrevReceipts),
        601 => Ok(ValidationError::InvalidGenesisTransaction),
        700 => Ok(ValidationError::InvalidExecutionProof),
        701 => Ok(ValidationError::ProgramDigestMismatch),
        710 => Ok(ValidationError::InvalidCanonicalJson),
        800 => Ok(ValidationError::InsufficientCheques),
        801 => Ok(ValidationError::InconsistentChequeBundle),
        802 => Ok(ValidationError::InvalidChequeSignature),
        803 => Ok(ValidationError::ChequeAlreadyRedeemed),
        850 => Ok(ValidationError::RedeemBalanceMismatch),
        851 => Ok(ValidationError::RedeemBalanceOverflow),
        852 => Ok(ValidationError::MissingRedeemInputs),
        // Codes 860-864 retired with the v2.11.6 fee-cheque flow (Step 9A).
        900 => Ok(ValidationError::CarriersTooLarge),
        910 => Ok(ValidationError::InvalidHintCount),
        911 => Ok(ValidationError::SelfHintNotAllowed),
        920 => Ok(ValidationError::SABRInsufficientOverlap),
        921 => Ok(ValidationError::SABROverlapNotInPrev),
        922 => Ok(ValidationError::SABRMissingValidatorPK),
        923 => Ok(ValidationError::SABRHashMismatch),
        950 => Ok(ValidationError::AuthHashRequired),
        951 => Ok(ValidationError::InvalidAuthProof),
        960 => Ok(ValidationError::ReceiptFromWrongWorldline),
        961 => Ok(ValidationError::ReceiptLineageMismatch),
        970 => Ok(ValidationError::GroupTooManyMembers),
        971 => Ok(ValidationError::GroupShareBpsInvalid),
        972 => Ok(ValidationError::GroupNotMember),
        973 => Ok(ValidationError::GroupInsufficientAvailable),
        974 => Ok(ValidationError::GroupChecksumFailed),
        975 => Ok(ValidationError::GroupMembersImmutable),
        976 => Ok(ValidationError::GroupDistributionOverflow),
        1000 => Ok(ValidationError::FactChainTooDeep),
        1001 => Ok(ValidationError::FactChainBreak),
        1002 => Ok(ValidationError::FactInsufficientWitnesses),
        1003 => Ok(ValidationError::FactInvalidSignature),
        1004 => Ok(ValidationError::FactDuplicateWitness),
        1005 => Ok(ValidationError::FactInvalidCheckpoint),
        1020 => Ok(ValidationError::BurnNoFactChain),
        1021 => Ok(ValidationError::BurnMissingTarget),
        1022 => Ok(ValidationError::BurnTargetNotFound),
        1023 => Ok(ValidationError::BurnTargetNotScarred),
        1024 => Ok(ValidationError::BurnTargetAlreadyBurned),
        1025 => Ok(ValidationError::BurnAmountMismatch),
        1026 => Ok(ValidationError::BurnProofInsufficientWitnesses),
        1027 => Ok(ValidationError::BurnProofDuplicateValidator),
        1028 => Ok(ValidationError::BurnTxIdNotInChain),
        1030 => Ok(ValidationError::TooManyUnresolvedScars),
        1010 => Ok(ValidationError::MissingWalletState),
        853 => Ok(ValidationError::MissingExecutionProof),
        854 => Ok(ValidationError::MissingVBC),
        930 => Ok(ValidationError::ZkpNotQualified),
        931 => Ok(ValidationError::ArkNotImplemented),
        1040 => Ok(ValidationError::VersionMismatch),
        1050 => Ok(ValidationError::MissingDilithiumKey),
        1051 => Ok(ValidationError::MissingField),
        1060 => Ok(ValidationError::WalletSecretMismatch),
        1100 => Ok(ValidationError::OracleSenderMismatch),
        1101 => Ok(ValidationError::OracleInsufficientK),
        1102 => Ok(ValidationError::OraclePlatformInvalid),
        1103 => Ok(ValidationError::OracleLivingSignatureMissing),
        1104 => Ok(ValidationError::OracleZeroDelta),
        1105 => Ok(ValidationError::OracleNonZeroAmount),
        1106 => Ok(ValidationError::OracleMaturityNotReached),
        1200 => Ok(ValidationError::FanOutMissingMessage),
        1201 => Ok(ValidationError::FanOutTtlExceeded),
        1202 => Ok(ValidationError::FanOutInvalidFanout),
        1203 => Ok(ValidationError::FanOutContentEmpty),
        1204 => Ok(ValidationError::FanOutContentTooLarge),
        1205 => Ok(ValidationError::FanOutTtlExpired),
        1206 => Ok(ValidationError::FanOutTtlInflated),
        1207 => Ok(ValidationError::FanOutUnknownContentType),
        1208 => Ok(ValidationError::FanOutTimestampFuture),
        1209 => Ok(ValidationError::FanOutTimestampExpired),
        1210 => Ok(ValidationError::FanOutDiffusionIdMismatch),
        1211 => Ok(ValidationError::FanOutInvalidOriginator),
        1212 => Ok(ValidationError::FanOutOriginatorPkMismatch),
        1213 => Ok(ValidationError::FanOutInvalidSignature),
        1300 => Ok(ValidationError::InsufficientStake),
        1301 => Ok(ValidationError::WalletFrozen),
        1302 => Ok(ValidationError::ArkToNonArkRejected),
        1303 => Ok(ValidationError::ArkChargeNotOwner),
        1304 => Ok(ValidationError::ArkUnloadScarred),
        1310 => Ok(ValidationError::NablaWriterDetected),
        1311 => Ok(ValidationError::StakeWalletMismatch),
        1312 => Ok(ValidationError::StakeNablaSignatureInvalid),
        1313 => Ok(ValidationError::StakeStateMismatch),
        1314 => Ok(ValidationError::StakeInsufficientReceipts),
        1315 => Ok(ValidationError::StakeProofExpired),
        9998 => Ok(ValidationError::InvalidMode),
        9999 => Ok(ValidationError::InternalError),
        _ => Err(format!("unknown ValidationError code: {}", n)),
    }
}

// ============================================================================
// Transaction
// ============================================================================

fn tx_to_value(tx: &Transaction) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&tx.consumed_state_id)),
        (1, cbor_bytes(&tx.client_pk)),
        (2, cbor_u64(tx.wallet_seq)),
        (3, cbor_text(&tx.receiver_wallet_id)),
        (4, cbor_opt(&tx.receiver_address, |s| cbor_text(s))),
        (5, cbor_u64(tx.amount)),
        (6, cbor_text(&tx.reference)),
        (7, cbor_u64(tx.nonce)),
        (8, cbor_u64(tx.epoch)),
        (9, cbor_bytes(&tx.client_sig)),
        (10, cbor_opt(&tx.owner_proof, |z| cbor_bytes(z))),
        (11, cbor_opt(&tx.scar_passcode, |p| cbor_u64(*p as u64))),
        (12, cbor_opt(&tx.burn_target_tx_id, |b| cbor_bytes(b))),
        (13, cbor_u64(tx.required_k as u64)),
        (14, cbor_u64(tx.proof_type as u64)),
        (15, cbor_text(&tx.sender_wallet_id)),
        // GAP-O4: Oracle claim data — CBOR sub-map at key 16.
        (16, cbor_opt(&tx.oracle_claim, oracle_claim_to_value)),
        (17, cbor_opt(&tx.recall_target_tx_id, |b| cbor_bytes(b))),
    ];
    cbor_map(pairs)
}

/// Encode OracleClaimData as a CBOR sub-map with integer keys.
fn oracle_claim_to_value(oc: &OracleClaimData) -> Value {
    let pairs = vec![
        (0, cbor_text(&oc.platform_url)),
        (1, cbor_u64(oc.user_id)),
        (2, cbor_text(&oc.username)),
        (3, cbor_u64(oc.credit_total)),
        (4, cbor_u64(oc.credit_delta)),
        (5, cbor_u64(oc.payout_amount)),
        (6, cbor_opt(&oc.zktls_proof, |p| cbor_bytes(p))),
    ];
    cbor_map(pairs)
}

/// Decode OracleClaimData from a CBOR sub-map.
fn value_to_oracle_claim(val: &Value) -> Result<OracleClaimData, String> {
    let m = val_map(val)?;
    Ok(OracleClaimData {
        platform_url: val_text(require_field(m, 0, "oc_url")?)?,
        user_id: val_u64(require_field(m, 1, "oc_uid")?)?,
        username: val_text(require_field(m, 2, "oc_uname")?)?,
        credit_total: val_u64(require_field(m, 3, "oc_ctotal")?)?,
        credit_delta: val_u64(require_field(m, 4, "oc_cdelta")?)?,
        payout_amount: val_u64(require_field(m, 5, "oc_payout")?)?,
        zktls_proof: val_opt(require_field(m, 6, "oc_zktls")?, val_bytes)?,
    })
}

fn value_to_tx(val: &Value) -> Result<Transaction, String> {
    let m = val_map(val)?;
    Ok(Transaction {
        consumed_state_id: val_bytes32(require_field(m, 0, "csid")?)?,
        client_pk: val_bytes(require_field(m, 1, "cpk")?)?,
        wallet_seq: val_u64(require_field(m, 2, "wseq")?)?,
        receiver_wallet_id: val_text(require_field(m, 3, "rwid")?)?,
        receiver_address: val_opt(require_field(m, 4, "raddr")?, val_text)?,
        amount: val_u64(require_field(m, 5, "amt")?)?,
        reference: val_text(require_field(m, 6, "ref")?)?,
        nonce: val_u64(require_field(m, 7, "nonce")?)?,
        epoch: val_u64(require_field(m, 8, "epoch")?)?,
        client_sig: val_bytes(require_field(m, 9, "csig")?)?,
        owner_proof: val_opt(require_field(m, 10, "azkp")?, val_bytes)?,
        scar_passcode: val_opt(require_field(m, 11, "scar")?, val_u32)?,
        burn_target_tx_id: val_opt(require_field(m, 12, "burn_target")?, val_bytes32)?,
        recall_target_tx_id: val_opt(require_field(m, 17, "recall_target")?, val_bytes32)?,
        required_k: match get_map_field(m, 13) {
            Some(v) => val_u64(v)? as u8,
            None => 0, // Backwards compatible
        },
        proof_type: match get_map_field(m, 14) {
            Some(v) => val_u64(v)? as u8,
            None => 0, // Backwards compatible
        },
        sender_wallet_id: match get_map_field(m, 15) {
            Some(v) => val_text(v)?,
            None => String::new(), // Backwards compatible
        },
        // GAP-O4: Oracle claim — decoded from CBOR sub-map at key 16.
        oracle_claim: match get_map_field(m, 16) {
            Some(Value::Null) | None => None,
            Some(v) => Some(value_to_oracle_claim(v)?),
        },
        core_version: String::new(),
        // IPC codec doesn't carry core_id yet — direct AVM path uses
        // the full struct shape. All-zero is the backward-compat
        // sentinel; CL2 Step -1.5 skips the check.
        core_id: [0u8; 32],
        kind: TxKind::Normal,
    })
}

// ============================================================================
// Receipt
// ============================================================================

fn receipt_to_value(r: &Receipt) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&r.txid)),
        (1, cbor_bytes(&r.state_hash)),
        (2, cbor_bytes(&r.produced_state_id)),
        (3, cbor_u64(r.new_wallet_seq)),
        (4, cbor_bytes(&r.commitment_hash)),
        (5, cbor_bytes(&r.sdid)),
        (6, cbor_bytes(&r.lineage_hash)),
        (7, cbor_text(&r.core_version)),
        (8, cbor_array(r.witness_sigs.iter().map(wsig_to_value).collect())),
        (9, cbor_u64(r.epoch)),
        (10, cbor_opt(&r.fact_proof, fact_proof_to_value)),
        (11, cbor_u64(r.required_k as u64)),
        // Field-tag 12: receipt_commitment (BLAKE3 over the 7 receipt
        // input fields including fee_breakdown). Wire-encoded so IPC
        // peers can verify the commitment after deserialisation.
        (12, cbor_bytes(&r.receipt_commitment)),
        // Field-tag 13: fee_breakdown (Vec<FeeShare>). Bound into the
        // receipt_commitment hash; must round-trip exactly or CL2's
        // recompute will diverge from the stored commitment.
        (13, cbor_array(r.fee_breakdown.iter().map(fee_share_to_value).collect())),
    ];
    cbor_map(pairs)
}

fn fee_share_to_value(s: &axiom_core_logic::FeeShare) -> Value {
    cbor_map(vec![
        (0, cbor_bytes(&s.validator_id)),
        (1, cbor_u64(s.amount)),
    ])
}

fn value_to_fee_share(val: &Value) -> Result<axiom_core_logic::FeeShare, String> {
    let m = val_map(val)?;
    Ok(axiom_core_logic::FeeShare {
        validator_id: val_bytes32(require_field(m, 0, "vid")?)?,
        amount: val_u64(require_field(m, 1, "amt")?)?,
    })
}

fn value_to_receipt(val: &Value) -> Result<Receipt, String> {
    let m = val_map(val)?;
    Ok(Receipt {
        txid: val_bytes32(require_field(m, 0, "txid")?)?,
        state_hash: val_bytes32(require_field(m, 1, "sh")?)?,
        produced_state_id: val_bytes32(require_field(m, 2, "psid")?)?,
        new_wallet_seq: val_u64(require_field(m, 3, "nseq")?)?,
        commitment_hash: val_bytes32(require_field(m, 4, "cmit")?)?,
        sdid: val_bytes32(require_field(m, 5, "sdid")?)?,
        lineage_hash: val_bytes32(require_field(m, 6, "lh")?)?,
        core_version: val_text(require_field(m, 7, "cver")?)?,
        witness_sigs: val_array(require_field(m, 8, "wsigs")?)?
            .iter().map(value_to_wsig).collect::<Result<Vec<_>,_>>()?,
        epoch: val_u64(require_field(m, 9, "epoch")?)?,
        fact_proof: val_opt(require_field(m, 10, "fproof")?, value_to_fact_proof)?,
        required_k: m.iter()
            .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == 11))
            .map(|(_, v)| val_u64(v).unwrap_or(3) as u8)
            .unwrap_or(3),
        receipt_commitment: val_bytes32(require_field(m, 12, "rcmit")?)?,
        // IPC codec doesn't carry core_id yet; all-zero sentinel.
        core_id: [0u8; 32],
        fee_breakdown: val_array(require_field(m, 13, "fees")?)?
            .iter().map(value_to_fee_share).collect::<Result<Vec<_>,_>>()?,
        // IPC conformance-only codec; embedded-AVM path round-trips
        // is_dev_class via serde directly. Default to false here;
        // do NOT use the IPC path for production receipts.
        is_dev_class: false,
        // Same conformance-only treatment as is_dev_class (YPX-021 §8.2).
        oods_flag: None,
    })
}

// ============================================================================
// WitnessSig — actual fields from types.rs
// ============================================================================

fn wsig_to_value(ws: &WitnessSig) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&ws.validator_id)),
        (1, cbor_bytes(&ws.validator_pk)),
        (2, cbor_opt(&ws.vbc_bundle, blob_encode)),
        (3, cbor_text(&ws.carrier_type)),
        (4, cbor_text(&ws.carrier_address)),
        (5, cbor_bytes(&ws.signature)),
        (6, cbor_bytes(&ws.execution_proof)),
        (7, cbor_opt(&ws.availability_attestation, blob_encode)),
        (8, cbor_array(ws.validator_hints.iter().map(blob_encode).collect())),
        (9, cbor_opt(&ws.fact_signature, |s| cbor_bytes(s))),
        (10, cbor_u64(ws.proof_type as u64)),
        (11, cbor_opt(&ws.receipt_signature, |s| cbor_bytes(s))),
        // Field-tag 12: Ed25519 signature over receipt_commitment.
        // Required for Core CL2's strict receipt verification (Diff 6).
        (12, cbor_opt(&ws.receipt_commitment_sig, |s| cbor_bytes(s))),
        // Field-tag 13 (SEC-07): this validator's checkpoint endorsement
        // (a FactWitness — Dilithium sig over the deterministic FACT checkpoint
        // commitment). None on the Core conformance path; set by Lambda finalize.
        (13, cbor_opt(&ws.checkpoint_sig, blob_encode)),
    ];
    cbor_map(pairs)
}

fn value_to_wsig(val: &Value) -> Result<WitnessSig, String> {
    let m = val_map(val)?;
    Ok(WitnessSig {
        validator_id: val_bytes32(require_field(m, 0, "vid")?)?,
        validator_pk: val_bytes(require_field(m, 1, "vpk")?)?,
        vbc_bundle: val_opt(require_field(m, 2, "vbc")?, blob_decode::<VBCProofBundle>)?,
        carrier_type: val_text(require_field(m, 3, "ctype")?)?,
        carrier_address: val_text(require_field(m, 4, "caddr")?)?,
        signature: val_bytes(require_field(m, 5, "sig")?)?,
        execution_proof: val_bytes(require_field(m, 6, "eproof")?)?,
        proof_type: match get_map_field(m, 10) {
            Some(v) => val_u64(v)? as u8,
            None => 0, // Backwards compatible: default ZKP
        },
        availability_attestation: val_opt(
            require_field(m, 7, "aa")?,
            blob_decode::<AvailabilityAttestation>,
        )?,
        validator_hints: {
            let arr = val_array(require_field(m, 8, "hints")?)?;
            arr.iter().map(blob_decode::<ValidatorHint>).collect::<Result<Vec<_>,_>>()?
        },
        fact_signature: val_opt(require_field(m, 9, "fsig")?, val_bytes)?,
        receipt_signature: val_opt(require_field(m, 11, "rsig")?, val_bytes)?,
        receipt_commitment_sig: val_opt(require_field(m, 12, "rcsig")?, val_bytes)?,
        checkpoint_sig: val_opt(require_field(m, 13, "cpsig")?, blob_decode::<FactWitness>)?,
        rate_bps: 0,
        slot_amount: 0,
    })
}

// ============================================================================
// WalletState
// ============================================================================

fn ws_to_value(ws: &WalletState) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&ws.public_key)),
        (1, cbor_u64(ws.balance)),
        (2, cbor_u64(ws.wallet_seq)),
        (3, cbor_bytes(&ws.state_id)),
        (4, cbor_opt(&ws.auth_hash, |h| cbor_bytes(h))),
        (5, cbor_opt(&ws.group_members, |gm| {
            cbor_array(gm.iter().map(group_member_to_value).collect())
        })),
        (6, cbor_opt(&ws.wallet_id, |wid| Value::Text(wid.clone()))),
        (7, cbor_u64(ws.hibernation_until)), // YPX-020 — thread both ways or it drifts over IPC
    ];
    cbor_map(pairs)
}

fn value_to_ws(val: &Value) -> Result<WalletState, String> {
    let m = val_map(val)?;
    Ok(WalletState {
        public_key: val_bytes(require_field(m, 0, "pk")?)?,
        balance: val_u64(require_field(m, 1, "bal")?)?,
        wallet_seq: val_u64(require_field(m, 2, "seq")?)?,
        state_id: val_bytes32(require_field(m, 3, "sid")?)?,
        auth_hash: val_opt(require_field(m, 4, "auth")?, val_bytes32)?,
        wallet_id: get_map_field(m, 6).and_then(|v| {
            if let Value::Text(s) = v { Some(s.clone()) } else { None }
        }),
        group_members: val_opt(require_field(m, 5, "gm")?, |v| {
            val_array(v)?.iter().map(value_to_group_member).collect::<Result<Vec<_>,_>>()
        })?,
        // YPX-020 — default 0 if absent (pre-hibernation peers); encoder always writes it.
        hibernation_until: get_map_field(m, 7).map(val_u64).transpose()?.unwrap_or(0),
    })
}

// ============================================================================
// GroupMember — actual fields: member_pk, share_bps (u16), available (u64)
// ============================================================================

fn group_member_to_value(gm: &GroupMember) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&gm.member_pk)),
        (1, cbor_u64(gm.share_bps as u64)),
        (2, cbor_u64(gm.available)),
    ];
    cbor_map(pairs)
}

fn value_to_group_member(val: &Value) -> Result<GroupMember, String> {
    let m = val_map(val)?;
    Ok(GroupMember {
        member_pk: val_bytes(require_field(m, 0, "mpk")?)?,
        share_bps: val_u16(require_field(m, 1, "bps")?)?,
        available: val_u64(require_field(m, 2, "avail")?)?,
    })
}

// ============================================================================
// FACT Chain
// ============================================================================

fn fact_chain_to_value(fc: &FactChain) -> Value {
    let pairs = vec![
        (0, cbor_array(fc.links.iter().map(fact_link_to_value).collect())),
        (1, cbor_opt(&fc.checkpoint, fact_checkpoint_to_value)),
    ];
    cbor_map(pairs)
}

fn value_to_fact_chain(val: &Value) -> Result<FactChain, String> {
    let m = val_map(val)?;
    Ok(FactChain {
        links: val_array(require_field(m, 0, "links")?)?
            .iter().map(value_to_fact_link).collect::<Result<Vec<_>,_>>()?,
        checkpoint: val_opt(require_field(m, 1, "cp")?, value_to_fact_checkpoint)?,
    })
}

fn fact_link_to_value(fl: &FactLink) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&fl.tx_id)),
        (1, cbor_bytes(&fl.previous_state_id)),
        (2, cbor_bytes(&fl.new_state_id)),
        (3, cbor_u64(fl.amount)),
        (4, cbor_u64(fl.tick)),
        (5, cbor_array(fl.witnesses.iter().map(fact_witness_to_value).collect())),
        (6, cbor_opt(&fl.nabla_confirmation, blob_encode)),
        (7, cbor_opt(&fl.receiver_contact, receiver_contact_to_value)),
        (8, cbor_opt(&fl.burn_proof, blob_encode)),
        (9, cbor_u64(fl.required_k as u64)),
        (10, cbor_opt(&fl.sender_anchor, |b: &[u8; 32]| cbor_bytes(b))),
        (11, cbor_opt(&fl.recall_proof, blob_encode)),  // YPX-022 recall scar-resolution
        // YPX-001 §1.5.1a scar inheritance (2026-07-12)
        (12, cbor_array(fl.inherited_scar_txids.iter().map(|t| cbor_bytes(t)).collect())),
        (13, cbor_array(fl.inherited_scar_resolutions.iter().map(blob_encode).collect())),
        // YPX-001 §1.5.4 burn-target binding (2026-07-17)
        (14, cbor_opt(&fl.burn_target_tx_id, |b: &[u8; 32]| cbor_bytes(b))),
    ];
    cbor_map(pairs)
}

fn value_to_fact_link(val: &Value) -> Result<FactLink, String> {
    let m = val_map(val)?;
    Ok(FactLink {
        tx_id: val_bytes32(require_field(m, 0, "txid")?)?,
        previous_state_id: val_bytes32(require_field(m, 1, "psid")?)?,
        new_state_id: val_bytes32(require_field(m, 2, "nsid")?)?,
        amount: val_u64(require_field(m, 3, "amt")?)?,
        required_k: require_field(m, 9, "rk").ok().and_then(|v| val_u64(v).ok()).unwrap_or(3) as u8,
        tick: val_u64(require_field(m, 4, "tick")?)?,
        witnesses: val_array(require_field(m, 5, "w")?)?
            .iter().map(value_to_fact_witness).collect::<Result<Vec<_>,_>>()?,
        nabla_confirmation: val_opt(require_field(m, 6, "nabla")?, blob_decode::<NablaConfirmation>)?,
        receiver_contact: val_opt(require_field(m, 7, "rc")?, value_to_receiver_contact)?,
        burn_proof: val_opt(require_field(m, 8, "bp")?, blob_decode::<BurnProof>)?,
        sender_anchor: val_opt(require_field(m, 10, "sa")?, val_bytes32)?,
        // YPX-022: round-trip the recall scar-resolution proof (graceful if absent).
        recall_proof: require_field(m, 11, "rp").ok()
            .and_then(|v| val_opt(v, blob_decode::<axiom_core_logic::types::RecallAttestation>).ok())
            .flatten(),
        // IPC codec is conformance-only; embedded-AVM path serializes
        // is_dev_class via serde. Default to false here; do NOT use
        // the IPC path for production FactLinks.
        is_dev_class: false,
        // YPX-001 §1.5.1a scar inheritance (2026-07-12). Same
        // conformance-only caveat as is_dev_class for older vectors:
        // absent fields decode to empty (no taint).
        inherited_scar_txids: require_field(m, 12, "ist").ok()
            .and_then(|v| val_array(v).ok())
            .map(|arr| arr.iter().filter_map(|x| val_bytes32(x).ok()).collect())
            .unwrap_or_default(),
        inherited_scar_resolutions: require_field(m, 13, "isr").ok()
            .and_then(|v| val_array(v).ok())
            .map(|arr| arr.iter()
                .filter_map(|x| blob_decode::<axiom_core_logic::types::NablaTxidAttestation>(x).ok())
                .collect())
            .unwrap_or_default(),
        // YPX-001 §1.5.4 burn-target binding (2026-07-17). Absent → None.
        burn_target_tx_id: require_field(m, 14, "btt").ok()
            .and_then(|v| val_opt(v, val_bytes32).ok())
            .flatten(),
    })
}

fn fact_witness_to_value(fw: &FactWitness) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&fw.validator_id)),
        (1, cbor_bytes(&fw.validator_pk)),
        (2, cbor_bytes(&fw.signature)),
    ];
    cbor_map(pairs)
}

fn value_to_fact_witness(val: &Value) -> Result<FactWitness, String> {
    let m = val_map(val)?;
    Ok(FactWitness {
        validator_id: val_bytes32(require_field(m, 0, "vid")?)?,
        validator_pk: val_bytes(require_field(m, 1, "vpk")?)?,
        signature: val_bytes(require_field(m, 2, "sig")?)?,
        vbc_genesis_anchor: None, // L5: IPC codec doesn't carry anchor yet
    })
}

// ============================================================================
// FactCheckpoint — actual fields: root_hash, compressed_count (u64),
//   final_state_id, genesis_state_id, total_amount, validator_sigs
// ============================================================================

fn fact_checkpoint_to_value(cp: &FactCheckpoint) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&cp.root_hash)),
        (1, cbor_u64(cp.compressed_count)),
        (2, cbor_bytes(&cp.final_state_id)),
        (3, cbor_bytes(&cp.genesis_state_id)),
        (4, cbor_u64(cp.total_amount)),
        (5, cbor_array(cp.validator_sigs.iter().map(fact_witness_to_value).collect())),
    ];
    cbor_map(pairs)
}

fn value_to_fact_checkpoint(val: &Value) -> Result<FactCheckpoint, String> {
    let m = val_map(val)?;
    Ok(FactCheckpoint {
        root_hash: val_bytes32(require_field(m, 0, "rh")?)?,
        compressed_count: val_u64(require_field(m, 1, "cc")?)?,
        final_state_id: val_bytes32(require_field(m, 2, "fsid")?)?,
        genesis_state_id: val_bytes32(require_field(m, 3, "gsid")?)?,
        total_amount: val_u64(require_field(m, 4, "tamt")?)?,
        validator_sigs: val_array(require_field(m, 5, "vsigs")?)?
            .iter().map(value_to_fact_witness).collect::<Result<Vec<_>,_>>()?,
        // Not carried over IPC CBOR — set default
        genesis_fact_hash: [0u8; 32],
        // SEC-07: provisional retain-count. Conformance-only IPC path carries
        // finalized checkpoints; default 0 (same precedent as genesis_fact_hash).
        pending_links: 0,
    })
}

// ============================================================================
// FactProof
// ============================================================================

fn fact_proof_to_value(fp: &FactProof) -> Value {
    let pairs = vec![
        (0, cbor_bytes(&fp.zkvm_receipt)),
        (1, cbor_bytes(&fp.core_digest)),
        (2, cbor_bytes(&fp.public_inputs_hash)),
        (3, cbor_bytes(&fp.public_outputs_hash)),
    ];
    cbor_map(pairs)
}

fn value_to_fact_proof(val: &Value) -> Result<FactProof, String> {
    let m = val_map(val)?;
    Ok(FactProof {
        zkvm_receipt: val_bytes(require_field(m, 0, "zr")?)?,
        core_digest: val_bytes32(require_field(m, 1, "cd")?)?,
        public_inputs_hash: val_bytes32(require_field(m, 2, "pih")?)?,
        public_outputs_hash: val_bytes32(require_field(m, 3, "poh")?)?,
    })
}

// ============================================================================
// ReceiverContact
// ============================================================================

fn receiver_contact_to_value(rc: &ReceiverContact) -> Value {
    let pairs = vec![
        (0, cbor_text(&rc.wallet_id)),
        (1, cbor_text(&rc.email)),
    ];
    cbor_map(pairs)
}

fn value_to_receiver_contact(val: &Value) -> Result<ReceiverContact, String> {
    let m = val_map(val)?;
    Ok(ReceiverContact {
        wallet_id: val_text(require_field(m, 0, "wid")?)?,
        email: val_text(require_field(m, 1, "email")?)?,
    })
}

// ============================================================================
// OPAQUE BLOB — for complex nested types (VBC, Cheque, Attestation, Hint, Nabla)
// Encode with ciborium serde → CBOR bytes. Core parses internally.
// ============================================================================

fn blob_encode<T: serde::Serialize>(val: &T) -> Value {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).unwrap_or_default();
    cbor_bytes(&buf)
}

fn blob_decode<T: serde::de::DeserializeOwned>(val: &Value) -> Result<T, String> {
    let bytes = val_bytes(val)?;
    ciborium::from_reader(&bytes[..])
        .map_err(|e| format!("blob decode: {}", e))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core_logic::{
        PublicInputs, PublicOutputs, CoreLogicMode, ValidationResult, ValidationError,
    };
    use axiom_core_logic::types::{
        Transaction, Receipt, WitnessSig, WalletState, GroupMember,
        FactChain, FactCheckpoint, FactLink, FactWitness, ReceiverContact,
    };

    // ----- helpers to build minimal real types -----

    fn make_tx() -> Transaction {
        Transaction {
            consumed_state_id: [1u8; 32],
            client_pk: vec![2u8; 32],
            sender_wallet_id: "alice@example.com/aabb1122".into(),
            wallet_seq: 7,
            receiver_wallet_id: "bob@example.com/ccdd3344".into(),
            receiver_address: Some("bob@example.com".into()),
            amount: 500_000,
            reference: "Test payment".into(),
            nonce: 42,
            epoch: 1,
            client_sig: vec![3u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            oracle_claim: None,
            required_k: 3,
            proof_type: 1,
            core_version: String::new(),
            kind: TxKind::Normal,
            core_id: [0u8; 32],
            recall_target_tx_id: None,
        }
    }

    fn make_wsig() -> WitnessSig {
        WitnessSig {
            validator_id: [10u8; 32],
            validator_pk: vec![11u8; 48],
            vbc_bundle: None,
            carrier_type: "email".into(),
            carrier_address: "val@axiom.local".into(),
            signature: vec![12u8; 64],
            execution_proof: vec![13u8; 128],
            proof_type: 1,
            availability_attestation: None,
            validator_hints: vec![],
            fact_signature: Some(vec![14u8; 64]),
            checkpoint_sig: None,
            receipt_signature: None,
            receipt_commitment_sig: None,
            rate_bps: 0,
            slot_amount: 0,
        }
    }

    fn make_receipt() -> Receipt {
        Receipt {
            txid: [20u8; 32],
            state_hash: [21u8; 32],
            produced_state_id: [22u8; 32],
            new_wallet_seq: 8,
            commitment_hash: [23u8; 32],
            sdid: [24u8; 32],
            lineage_hash: [25u8; 32],
            core_version: "2.11.10".into(),
            witness_sigs: vec![make_wsig()],
            epoch: 1,
            fact_proof: None,
            required_k: 3,
            receipt_commitment: [0u8; 32],
            core_id: [0u8; 32],
            fee_breakdown: Vec::new(),
            is_dev_class: false,
            oods_flag: None,
        }
    }

    fn make_wallet_state() -> WalletState {
        WalletState {
            public_key: vec![30u8; 32],
            balance: 1_000_000,
            wallet_seq: 7,
            state_id: [31u8; 32],
            auth_hash: Some([32u8; 32]),
            wallet_id: None,
            group_members: None,
            hibernation_until: 0,
        }
    }

    fn make_minimal_inputs() -> PublicInputs {
        PublicInputs {
            mode: CoreLogicMode::CL1,
            transaction: make_tx(),
            prev_receipts: vec![],
            current_state: None,
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
            max_fact_links: None,
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
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],
        
            withdrawal_inputs: None,
            oods_attestation: None,
            recall_attestation: None,
            receiver_current_hibernation: None,
        }
    }

    fn make_minimal_outputs() -> PublicOutputs {
        PublicOutputs {
            result: ValidationResult::Accept,
            new_state_hash: None,
            produced_state_id: None,
            new_wallet_seq: None,
            rejection_reason: None,
            is_overlapped: None,
            commitment_hash: None,
            txid: None,
            fact_signature: None,
            new_balance: None,
            nbc_signature: None,
            zkp_nonce_hash: None,
            required_k: 0,
            receipt_commitment: None,
            validator_withdrawal_mint: None,
            extracted_proof_type: 0,
            audit_demand: None,
            audit_request: None,
            nonce_challenge: None,
            pulse_proof: None,
            audit_failed: false,
            fanout_new_ttl: None,
            console_chain_hash: None,
            compressed_fact_chain: None,
            receiver_fact_chain: None,
            is_dev_class: None,
            hibernation_until: 0,
            oods_flag: None,
        }
    }

    // ================================================================
    // 1. Roundtrip encode/decode for PublicInputs (minimal)
    // ================================================================
    #[test]
    fn roundtrip_inputs_minimal() {
        let inputs = make_minimal_inputs();
        let encoded = encode_inputs(&inputs).expect("encode");
        let decoded = decode_inputs(&encoded).expect("decode");

        assert_eq!(decoded.mode, CoreLogicMode::CL1);
        assert_eq!(decoded.transaction.amount, 500_000);
        assert_eq!(decoded.transaction.sender_wallet_id, "alice@example.com/aabb1122");
        assert!(decoded.prev_receipts.is_empty());
        assert!(decoded.current_state.is_none());
        assert!(decoded.vbc_bundle.is_none());
    }

    // ================================================================
    // 2. Roundtrip encode/decode for PublicOutputs (minimal)
    // ================================================================
    #[test]
    fn roundtrip_outputs_minimal() {
        let outputs = make_minimal_outputs();
        let encoded = encode_outputs(&outputs).expect("encode");
        let decoded = decode_outputs(&encoded).expect("decode");

        assert_eq!(decoded.result, ValidationResult::Accept);
        assert!(decoded.new_state_hash.is_none());
        assert!(decoded.rejection_reason.is_none());
        assert_eq!(decoded.required_k, 0);
        assert!(!decoded.audit_failed);
    }

    // ================================================================
    // 3. Roundtrip PublicInputs with populated optional fields
    // ================================================================
    #[test]
    fn roundtrip_inputs_full() {
        let mut inputs = make_minimal_inputs();
        inputs.mode = CoreLogicMode::CL3;
        inputs.prev_receipts = vec![make_receipt()];
        inputs.current_state = Some(make_wallet_state());
        inputs.receiver_pk = Some(vec![40u8; 32]);
        inputs.receiver_current_balance = Some(999);
        inputs.receiver_wallet_seq = Some(5);
        inputs.receiver_new_balance = Some(1499);
        inputs.receiver_new_state_id = Some([41u8; 32]);
        inputs.my_validator_pk = Some(vec![42u8; 48]);
        inputs.overlapped_signatures = vec![make_wsig()];
        inputs.group_member_index = Some(2);
        inputs.my_dilithium_sk = Some(vec![43u8; 64]);
        inputs.my_dilithium_pk = Some(vec![44u8; 48]);
        inputs.my_validator_id = Some([45u8; 32]);
        inputs.fact_witness_sigs = vec![make_wsig()];
        inputs.zkp_nonce = Some([46u8; 32]);
        inputs.scar_heal_tx_id = Some([47u8; 32]);
        inputs.scar_heal_nabla_id = Some([48u8; 32]);
        inputs.scar_heal_root_hash = Some([49u8; 32]);

        let encoded = encode_inputs(&inputs).expect("encode");
        let decoded = decode_inputs(&encoded).expect("decode");

        assert_eq!(decoded.mode, CoreLogicMode::CL3);
        assert_eq!(decoded.prev_receipts.len(), 1);
        assert_eq!(decoded.prev_receipts[0].txid, [20u8; 32]);
        assert_eq!(decoded.prev_receipts[0].witness_sigs.len(), 1);
        let ws = decoded.current_state.as_ref().unwrap();
        assert_eq!(ws.balance, 1_000_000);
        assert_eq!(ws.auth_hash, Some([32u8; 32]));
        assert_eq!(decoded.receiver_current_balance, Some(999));
        assert_eq!(decoded.receiver_new_balance, Some(1499));
        assert_eq!(decoded.receiver_new_state_id, Some([41u8; 32]));
        assert_eq!(decoded.overlapped_signatures.len(), 1);
        assert_eq!(decoded.group_member_index, Some(2));
        assert_eq!(decoded.zkp_nonce, Some([46u8; 32]));
        assert_eq!(decoded.scar_heal_tx_id, Some([47u8; 32]));
        assert_eq!(decoded.scar_heal_nabla_id, Some([48u8; 32]));
        assert_eq!(decoded.scar_heal_root_hash, Some([49u8; 32]));
    }

    // ================================================================
    // 4. Roundtrip PublicOutputs with populated fields + rejection
    // ================================================================
    #[test]
    fn roundtrip_outputs_rejected() {
        let mut outputs = make_minimal_outputs();
        outputs.result = ValidationResult::Reject;
        outputs.new_state_hash = Some([50u8; 32]);
        outputs.produced_state_id = Some([51u8; 32]);
        outputs.new_wallet_seq = Some(8);
        outputs.rejection_reason = Some(ValidationError::InsufficientBalance);
        outputs.is_overlapped = Some(true);
        outputs.commitment_hash = Some([52u8; 32]);
        outputs.txid = Some([53u8; 32]);
        outputs.fact_signature = Some(vec![54u8; 128]);
        outputs.new_balance = Some(750_000);
        outputs.nbc_signature = Some(vec![55u8; 256]);
        outputs.zkp_nonce_hash = Some([56u8; 32]);
        outputs.required_k = 3;
        outputs.extracted_proof_type = 1;
        outputs.audit_failed = true;

        let encoded = encode_outputs(&outputs).expect("encode");
        let decoded = decode_outputs(&encoded).expect("decode");

        assert_eq!(decoded.result, ValidationResult::Reject);
        assert_eq!(decoded.new_state_hash, Some([50u8; 32]));
        assert_eq!(decoded.produced_state_id, Some([51u8; 32]));
        assert_eq!(decoded.new_wallet_seq, Some(8));
        assert_eq!(decoded.rejection_reason, Some(ValidationError::InsufficientBalance));
        assert_eq!(decoded.is_overlapped, Some(true));
        assert_eq!(decoded.commitment_hash, Some([52u8; 32]));
        assert_eq!(decoded.txid, Some([53u8; 32]));
        assert_eq!(decoded.fact_signature.as_ref().map(|v| v.len()), Some(128));
        assert_eq!(decoded.new_balance, Some(750_000));
        assert_eq!(decoded.nbc_signature.as_ref().map(|v| v.len()), Some(256));
        assert_eq!(decoded.zkp_nonce_hash, Some([56u8; 32]));
        assert_eq!(decoded.required_k, 3);
        assert_eq!(decoded.extracted_proof_type, 1);
        assert!(decoded.audit_failed);
    }

    // ================================================================
    // 5. Malformed input: truncated CBOR
    // ================================================================
    #[test]
    fn decode_inputs_truncated_cbor() {
        let inputs = make_minimal_inputs();
        let encoded = encode_inputs(&inputs).expect("encode");
        // Truncate to half
        let truncated = &encoded[..encoded.len() / 2];
        let result = decode_inputs(truncated);
        assert!(result.is_err(), "truncated CBOR should fail");
    }

    #[test]
    fn decode_outputs_truncated_cbor() {
        let outputs = make_minimal_outputs();
        let encoded = encode_outputs(&outputs).expect("encode");
        let truncated = &encoded[..encoded.len() / 2];
        let result = decode_outputs(truncated);
        assert!(result.is_err(), "truncated CBOR should fail");
    }

    // ================================================================
    // 6. Malformed input: wrong type (text instead of map)
    // ================================================================
    #[test]
    fn decode_inputs_wrong_type() {
        let val = Value::Text("not a map".into());
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        let result = decode_inputs(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected map"));
    }

    #[test]
    fn decode_outputs_wrong_type() {
        let val = Value::Integer(42.into());
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        let result = decode_outputs(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected map"));
    }

    // ================================================================
    // 7. Empty bytes → decode fails
    // ================================================================
    #[test]
    fn decode_inputs_empty_bytes() {
        let result = decode_inputs(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_outputs_empty_bytes() {
        let result = decode_outputs(&[]);
        assert!(result.is_err());
    }

    // ================================================================
    // 8. Field-level: Transaction fields survive roundtrip exactly
    // ================================================================
    #[test]
    fn field_level_transaction_roundtrip() {
        let mut inputs = make_minimal_inputs();
        inputs.transaction.consumed_state_id = [0xAA; 32];
        inputs.transaction.client_pk = vec![0xBB; 48];
        inputs.transaction.wallet_seq = i64::MAX as u64;
        inputs.transaction.receiver_wallet_id = "charlie@test.org/11223344".into();
        inputs.transaction.receiver_address = Some("charlie@test.org".into());
        inputs.transaction.amount = 123_456_789;
        inputs.transaction.reference = "Invoice #42 — special chars: <>\"'&".into();
        inputs.transaction.nonce = 99;
        inputs.transaction.epoch = 100;
        inputs.transaction.client_sig = vec![0xCC; 96];
        inputs.transaction.owner_proof = Some(vec![0xDD; 256]);
        inputs.transaction.scar_passcode = Some(123456);
        inputs.transaction.burn_target_tx_id = Some([0xEE; 32]);
        inputs.transaction.required_k = 5;
        inputs.transaction.proof_type = 2;

        let encoded = encode_inputs(&inputs).expect("encode");
        let decoded = decode_inputs(&encoded).expect("decode");
        let tx = &decoded.transaction;

        assert_eq!(tx.consumed_state_id, [0xAA; 32]);
        assert_eq!(tx.client_pk, vec![0xBB; 48]);
        assert_eq!(tx.wallet_seq, i64::MAX as u64);
        assert_eq!(tx.receiver_wallet_id, "charlie@test.org/11223344");
        assert_eq!(tx.receiver_address, Some("charlie@test.org".into()));
        assert_eq!(tx.amount, 123_456_789);
        assert_eq!(tx.reference, "Invoice #42 — special chars: <>\"'&");
        assert_eq!(tx.nonce, 99);
        assert_eq!(tx.epoch, 100);
        assert_eq!(tx.client_sig, vec![0xCC; 96]);
        assert_eq!(tx.owner_proof, Some(vec![0xDD; 256]));
        assert_eq!(tx.scar_passcode, Some(123456));
        assert_eq!(tx.burn_target_tx_id, Some([0xEE; 32]));
        assert_eq!(tx.required_k, 5);
        assert_eq!(tx.proof_type, 2);
    }

    // ================================================================
    // 9. Large payload: many receipts + large keys
    // ================================================================
    #[test]
    fn large_payload_roundtrip() {
        let mut inputs = make_minimal_inputs();
        // 50 receipts, each with a witness sig
        inputs.prev_receipts = (0..50).map(|i| {
            let mut r = make_receipt();
            r.txid[0] = i as u8;
            r.new_wallet_seq = i as u64;
            r
        }).collect();
        // Large keys (simulating Dilithium)
        inputs.my_dilithium_sk = Some(vec![0x77; 4032]);
        inputs.my_dilithium_pk = Some(vec![0x88; 1952]);
        inputs.issuer_sphincs_sk = Some(vec![0x99; 1281]);

        let encoded = encode_inputs(&inputs).expect("encode");
        assert!(encoded.len() > 10_000, "large payload should be sizable");

        let decoded = decode_inputs(&encoded).expect("decode");
        assert_eq!(decoded.prev_receipts.len(), 50);
        assert_eq!(decoded.prev_receipts[0].txid[0], 0);
        assert_eq!(decoded.prev_receipts[49].txid[0], 49);
        assert_eq!(decoded.prev_receipts[49].new_wallet_seq, 49);
        assert_eq!(decoded.my_dilithium_sk.as_ref().unwrap().len(), 4032);
        assert_eq!(decoded.my_dilithium_pk.as_ref().unwrap().len(), 1952);
        assert_eq!(decoded.issuer_sphincs_sk.as_ref().unwrap().len(), 1281);
    }

    // ================================================================
    // 10. All CoreLogicMode variants roundtrip
    // ================================================================
    #[test]
    fn all_modes_roundtrip() {
        let modes = [
            CoreLogicMode::CL1, CoreLogicMode::CL2, CoreLogicMode::CL3,
            CoreLogicMode::CL4, CoreLogicMode::CL5,
            CoreLogicMode::CL7, CoreLogicMode::CL8,
        ];
        for mode in &modes {
            let mut inputs = make_minimal_inputs();
            inputs.mode = *mode;
            let encoded = encode_inputs(&inputs).expect("encode");
            let decoded = decode_inputs(&encoded).expect("decode");
            assert_eq!(decoded.mode, *mode, "mode {:?} did not roundtrip", mode);
        }
    }

    // ================================================================
    // 11. All ValidationResult + ValidationError roundtrip through outputs
    // ================================================================
    #[test]
    fn validation_result_variants_roundtrip() {
        let cases: Vec<(ValidationResult, Option<ValidationError>)> = vec![
            (ValidationResult::Accept, None),
            (ValidationResult::Reject, Some(ValidationError::InsufficientBalance)),
            (ValidationResult::Reject, Some(ValidationError::ZeroAmount)),
            (ValidationResult::Reject, Some(ValidationError::InvalidClientSignature)),
            (ValidationResult::Reject, Some(ValidationError::FactChainBreak)),
            (ValidationResult::Reject, Some(ValidationError::BurnAmountMismatch)),
            (ValidationResult::Fatal, None),
        ];
        for (result, reason) in &cases {
            let mut outputs = make_minimal_outputs();
            outputs.result = *result;
            outputs.rejection_reason = reason.clone();
            let encoded = encode_outputs(&outputs).expect("encode");
            let decoded = decode_outputs(&encoded).expect("decode");
            assert_eq!(decoded.result, *result);
            assert_eq!(decoded.rejection_reason, *reason);
        }
    }

    // ================================================================
    // 12. FACT chain with links + checkpoint survives roundtrip
    // ================================================================
    #[test]
    fn fact_chain_roundtrip() {
        let mut inputs = make_minimal_inputs();
        inputs.sender_fact_chain = Some(FactChain {
            checkpoint: Some(FactCheckpoint {
                root_hash: [60u8; 32],
                compressed_count: 15,
                final_state_id: [61u8; 32],
                genesis_state_id: [62u8; 32],
                total_amount: 5_000_000,
                genesis_fact_hash: [0u8; 32], // not in CBOR codec
                validator_sigs: vec![FactWitness {
                    validator_id: [63u8; 32],
                    validator_pk: vec![64u8; 48],
                    signature: vec![65u8; 64],
                    vbc_genesis_anchor: None,
                }],
                pending_links: 0,
            }),
            links: vec![FactLink {
                tx_id: [70u8; 32],
                previous_state_id: [71u8; 32],
                new_state_id: [72u8; 32],
                amount: 100_000,
                tick: 42,
                required_k: 3,
                witnesses: vec![FactWitness {
                    validator_id: [73u8; 32],
                    validator_pk: vec![74u8; 48],
                    signature: vec![75u8; 64],
                    vbc_genesis_anchor: None,
                }],
                nabla_confirmation: None,
                receiver_contact: Some(ReceiverContact {
                    wallet_id: "bob@example.com/ccdd3344".into(),
                    email: "bob@example.com".into(),
                }),
                burn_proof: None,
                burn_target_tx_id: None,
                sender_anchor: None,
                is_dev_class: false,
                inherited_scar_txids: Vec::new(),
                inherited_scar_resolutions: Vec::new(),
                recall_proof: None,
            }],
        });

        let encoded = encode_inputs(&inputs).expect("encode");
        let decoded = decode_inputs(&encoded).expect("decode");

        let fc = decoded.sender_fact_chain.as_ref().unwrap();
        let cp = fc.checkpoint.as_ref().unwrap();
        assert_eq!(cp.root_hash, [60u8; 32]);
        assert_eq!(cp.compressed_count, 15);
        assert_eq!(cp.total_amount, 5_000_000);
        assert_eq!(cp.validator_sigs.len(), 1);

        assert_eq!(fc.links.len(), 1);
        let link = &fc.links[0];
        assert_eq!(link.tx_id, [70u8; 32]);
        assert_eq!(link.amount, 100_000);
        assert_eq!(link.tick, 42);
        assert_eq!(link.witnesses.len(), 1);
        assert_eq!(link.witnesses[0].validator_id, [73u8; 32]);
        let rc = link.receiver_contact.as_ref().unwrap();
        assert_eq!(rc.wallet_id, "bob@example.com/ccdd3344");
        assert_eq!(rc.email, "bob@example.com");
    }

    // ================================================================
    // 13. WalletState with group members roundtrip
    // ================================================================
    #[test]
    fn wallet_state_group_members_roundtrip() {
        let mut inputs = make_minimal_inputs();
        inputs.current_state = Some(WalletState {
            public_key: vec![80u8; 32],
            balance: 2_000_000,
            wallet_seq: 10,
            state_id: [81u8; 32],
            auth_hash: None,
            wallet_id: None,
            group_members: Some(vec![
                GroupMember { member_pk: vec![82u8; 32], share_bps: 5000, available: 1_000_000 },
                GroupMember { member_pk: vec![83u8; 32], share_bps: 3000, available: 600_000 },
                GroupMember { member_pk: vec![84u8; 32], share_bps: 2000, available: 400_000 },
            ]),
            hibernation_until: 0,
        });

        let encoded = encode_inputs(&inputs).expect("encode");
        let decoded = decode_inputs(&encoded).expect("decode");

        let ws = decoded.current_state.as_ref().unwrap();
        assert_eq!(ws.balance, 2_000_000);
        assert!(ws.auth_hash.is_none());
        let gm = ws.group_members.as_ref().unwrap();
        assert_eq!(gm.len(), 3);
        assert_eq!(gm[0].share_bps, 5000);
        assert_eq!(gm[0].available, 1_000_000);
        assert_eq!(gm[1].share_bps, 3000);
        assert_eq!(gm[2].member_pk, vec![84u8; 32]);
    }

    // ================================================================
    // 14. Determinism: encoding same input twice yields identical bytes
    // ================================================================
    #[test]
    fn encoding_is_deterministic() {
        let inputs = make_minimal_inputs();
        let a = encode_inputs(&inputs).expect("encode 1");
        let b = encode_inputs(&inputs).expect("encode 2");
        assert_eq!(a, b, "canonical CBOR must be deterministic");

        let outputs = make_minimal_outputs();
        let c = encode_outputs(&outputs).expect("encode 1");
        let d = encode_outputs(&outputs).expect("encode 2");
        assert_eq!(c, d, "canonical CBOR must be deterministic");
    }

    // ================================================================
    // CBOR duplicate key rejection (YP §16.8.5.2)
    // ================================================================

    #[test]
    fn reject_duplicate_keys_in_cbor_map() {
        // Build a CBOR map with duplicate key 0
        let dup_map = Value::Map(vec![
            (Value::Integer(0.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(0.into()), Value::Integer(99.into())),  // duplicate key 0
        ]);
        let err = val_map(&dup_map);
        assert!(err.is_err(), "duplicate CBOR keys must be rejected");
        assert!(err.unwrap_err().contains("duplicate CBOR map key"));
    }

    #[test]
    fn accept_unique_keys_in_cbor_map() {
        let ok_map = Value::Map(vec![
            (Value::Integer(0.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(2.into()), Value::Integer(3.into())),
        ]);
        assert!(val_map(&ok_map).is_ok(), "unique keys must be accepted");
    }

    #[test]
    fn duplicate_key_in_inputs_cbor_rejected() {
        // Encode valid inputs, then corrupt the CBOR by manually inserting a duplicate key
        let inputs = make_minimal_inputs();
        let encoded = encode_inputs(&inputs).expect("encode");

        // Parse to Value, inject duplicate key, re-encode
        let mut val: Value = ciborium::from_reader(&encoded[..]).expect("parse");
        if let Value::Map(ref mut m) = val {
            // Duplicate key 0 (mode)
            m.push((Value::Integer(0.into()), Value::Integer(42.into())));
        }
        let mut corrupted = Vec::new();
        ciborium::into_writer(&val, &mut corrupted).expect("re-encode");

        let result = decode_inputs(&corrupted);
        assert!(result.is_err(), "duplicate key in inputs CBOR must be rejected");
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("duplicate CBOR map key"),
            "error should mention duplicate key, got: {}", err_msg);
    }
}
