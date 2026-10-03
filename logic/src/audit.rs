//! §23.14 Peer Audit Demand — The Ping Defense
//!
//! Core randomly demands that Lambda (the operator) audit a peer validator.
//! The demand is deterministic (derived from txid), so DMAP re-execution
//! produces the same demand — making it tamper-evident.
//!
//! If Lambda ignores the demand, the AVM interpreter self-terminates
//! after AUDIT_COUNTDOWN_TXS invocations, forcing a restart with
//! VBC re-verification and ZK benchmark penalties.
//!
//! # Design
//!
//! - Core is stateless: each invocation is independent.
//! - Audit trigger: deterministic from txid (BLAKE3 hash, low 7 bits < threshold).
//! - Target selection: the current tx's co-witnesses at the finalizing CL3
//!   (`overlapped_signatures`) — `audit_target_candidates` (KI#213).
//! - Countdown enforcement: lives in AVM interpreter (host), not guest.
//! - Tamper protection: if operator modifies AVM to skip countdown,
//!   DMAP attestation diverges from honest re-executors → rejected.

use alloc::vec::Vec;
use crate::types::{AuditDemand, AUDIT_TRIGGER_RATE, PeerAuditRequest, PeerAuditResponse, PeerAuditNotHeld};

/// §23.14.2 — the validators a peer-audit demand may target for THIS execution:
/// the CO-WITNESSES of the current transaction, and only at the finalizing CL3,
/// where `inputs.overlapped_signatures` carries the other witnesses' signatures
/// over THIS tx (V1, V2 at V3 — Core verifies each against the commitment).
/// Any other mode yields no candidates (no demand).
///
/// ⚠ NOT `fact_witness_sigs`: at the finalizing CL3 execution Lambda hands Core
/// `fact_witness_sigs: vec![]` (the k signatures go to the separate FACT-link
/// build call), so a selector on that field arms NOTHING — measured 2026-09-24
/// on the first roll of this rule: zero demands across a whole tier B.
///
/// ONE rule, two compilations: the guest volume trigger (`modes.rs`) and the
/// host time-bond (`interpreter.rs::time_bond_demand`) both call this, so they
/// cannot disagree about who is auditable.
///
/// ⚠ WRONG READING, live until 2026-09-24 (KI#213, the owner ruled the fix): both
/// callers drew the target from `inputs.prev_receipts[].witness_sigs` — the
/// PREVIOUS transaction's witnesses — while `trigger_txid` is the CURRENT tx.
/// A previous witness outside the current set never executed that tx; on the
/// first request that ever reached a target it answered "unknown txid" and was
/// banned NonResponds. A co-witness of the current tx executed it at CL2 and
/// (since the same day) persists its digest (`witness_digests`), so it can
/// answer. Self is appended from `inputs.my_validator_pk` (it is never in
/// `overlapped_signatures`, which are the OTHER witnesses' signatures), so a
/// demand names its own validator ~1/k of the time — the §23.14.6 self-audit.
pub fn audit_target_candidates(inputs: &crate::types::PublicInputs) -> Vec<Vec<u8>> {
    if !matches!(inputs.mode, crate::CoreLogicMode::CL3) {
        return Vec::new();
    }
    let mut c: Vec<Vec<u8>> = inputs.overlapped_signatures.iter().map(|s| s.validator_pk.clone()).collect();
    // SELF is a candidate too (the owner 2026-09-24: "we should get the self audit fixed"):
    // the finalizer executed this tx as well, and a demand naming it is the
    // §23.14.6 SELF-audit — Core auditing Lambda's own DB. `my_validator_pk` is
    // what Lambda passes for this validator at CL2/CL3; absent (a client-side
    // CL1, tests) ⇒ no self candidate. Appended LAST and once, so the
    // txid-derived index is stable over the co-witnesses.
    if let Some(me) = inputs.my_validator_pk.as_ref() {
        if !c.iter().any(|pk| pk == me) {
            c.push(me.clone());
        }
    }
    c
}

/// Domain tag for audit challenge nonce derivation
const AUDIT_CHALLENGE_DOMAIN: &[u8] = b"AXIOM_AUDIT_CHALLENGE";

/// Check if this transaction should trigger an audit demand.
///
/// Deterministic: same txid always produces the same decision.
/// Probability: ~1 in AUDIT_TRIGGER_RATE (1 in 50 since 2026-09-26; was 100).
pub fn should_trigger_audit(txid: &[u8; 32]) -> bool {
    // Use first 8 bytes of txid as u64, mod AUDIT_TRIGGER_RATE
    let sample = u64::from_le_bytes([
        txid[0], txid[1], txid[2], txid[3],
        txid[4], txid[5], txid[6], txid[7],
    ]);
    sample.is_multiple_of(AUDIT_TRIGGER_RATE)
}

/// Generate an audit demand for a transaction.
///
/// Selects a target validator from `witness_pks` — the current tx's co-witnesses
/// (`audit_target_candidates`; was prev_receipts' witnesses until KI#213).
/// The challenge nonce is derived deterministically from the txid.
///
/// Returns None if there are no witness PKs to audit (genesis TX).
pub fn generate_audit_demand(
    txid: &[u8; 32],
    witness_pks: &[Vec<u8>],
) -> Option<AuditDemand> {
    if witness_pks.is_empty() {
        return None;
    }

    // Derive challenge nonce: BLAKE3("AXIOM_AUDIT_CHALLENGE" || txid)
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_CHALLENGE_DOMAIN);
    hasher.update(txid);
    let challenge_nonce: [u8; 32] = *hasher.finalize().as_bytes();

    // Select target validator: use bytes 8-15 of txid as index
    let target_idx = u64::from_le_bytes([
        txid[8], txid[9], txid[10], txid[11],
        txid[12], txid[13], txid[14], txid[15],
    ]) as usize % witness_pks.len();

    Some(AuditDemand {
        challenge_nonce,
        target_validator_pk: witness_pks[target_idx].clone(),
        trigger_txid: *txid,
    })
}

/// Verify an audit confirmation's nonce and target match the demand.
/// This is the first check — nonce binding prevents replay.
/// Content verification (raw data vs audit buffer) is done by AVM
/// in `enforce_audit_pre()`.
pub fn verify_audit_nonce(
    demand: &AuditDemand,
    confirmation: &crate::types::AuditConfirmation,
) -> bool {
    crate::crypto::ct_eq(&confirmation.challenge_nonce, &demand.challenge_nonce)
        && crate::crypto::ct_eq(&confirmation.target_validator_pk, &demand.target_validator_pk)
}

/// Verify audit confirmation content: hash the raw DB data Lambda sent back
/// and compare against the stored TxDigest in the audit buffer.
///
/// Lambda sends raw fields (tx_number, sender_balance, receiver_balance,
/// state_id, amount). Core reconstructs a TxDigest, hashes it with BLAKE3,
/// and compares against the stored entry's hash. Lambda does zero crypto.
///
/// Returns true if the stored data matches what Lambda reported.
pub fn verify_audit_content(
    confirmation: &crate::types::AuditConfirmation,
    stored_digest: &crate::types::TxDigest,
) -> bool {
    // Reconstruct TxDigest from confirmation's raw fields + stored tx_number
    // (tx_number is AVM-internal — Lambda doesn't know it)
    let reported = crate::types::TxDigest::from_confirmation(
        confirmation, stored_digest.tx_number,
    );
    // Compare via canonical byte representation (BLAKE3 hash)
    let reported_hash = blake3::hash(&reported.to_bytes());
    let stored_hash = blake3::hash(&stored_digest.to_bytes());
    *reported_hash.as_bytes() == *stored_hash.as_bytes()
}

// === §23.14.6: Peer Audit Protocol ===

/// Domain tag for peer audit hash computation
const PEER_AUDIT_HASH_DOMAIN: &[u8] = b"AXIOM_PEER_AUDIT_V1";

/// Compute the peer audit hash for a TxDigest.
///
/// BLAKE3("AXIOM_PEER_AUDIT_V1" || txid || sender_balance || receiver_balance || state_id || amount)
///
/// Both local and remote Core compute this independently from their respective
/// data sources (audit buffer vs Lambda DB). If the hashes match, both sides
/// stored the transaction honestly.
///
/// Core is the sole cryptographic authority — Lambda never calls this.
pub fn compute_peer_audit_hash(
    txid: &[u8; 32],
    sender_balance: u64,
    receiver_balance: u64,
    state_id: &[u8; 32],
    amount: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PEER_AUDIT_HASH_DOMAIN);
    hasher.update(txid);
    hasher.update(&sender_balance.to_le_bytes());
    hasher.update(&receiver_balance.to_le_bytes());
    hasher.update(state_id);
    hasher.update(&amount.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Domain tags for the KI#175 operational-wallet signatures. Distinct from
/// PEER_AUDIT_HASH_DOMAIN (the content hash) so a signature can never be
/// mistaken for, or replayed as, a content hash.
pub const PEER_AUDIT_REQ_SIGN_DOMAIN: &[u8] = b"AXIOM_PEER_AUDIT_REQ_V1";
pub const PEER_AUDIT_RESP_SIGN_DOMAIN: &[u8] = b"AXIOM_PEER_AUDIT_RESP_V1";

/// Canonical bytes A's operational wallet signs for a peer-audit REQUEST (KI#175).
/// Built identically by the signer (Lambda) and the verifier (B's Core).
pub fn peer_audit_request_signing_payload(
    txid: &[u8; 32],
    challenge_nonce: &[u8; 32],
    requester_pk: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(PEER_AUDIT_REQ_SIGN_DOMAIN.len() + 64 + requester_pk.len());
    m.extend_from_slice(PEER_AUDIT_REQ_SIGN_DOMAIN);
    m.extend_from_slice(txid);
    m.extend_from_slice(challenge_nonce);
    m.extend_from_slice(requester_pk);
    m
}

/// Canonical bytes B's operational wallet signs for a peer-audit RESPONSE (KI#175).
/// Binds the raw DB fields so a signed response cannot be re-fielded in flight.
#[allow(clippy::too_many_arguments)]
pub fn peer_audit_response_signing_payload(
    txid: &[u8; 32],
    challenge_nonce: &[u8; 32],
    sender_balance: u64,
    receiver_balance: u64,
    state_id: &[u8; 32],
    amount: u64,
    responder_pk: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(PEER_AUDIT_RESP_SIGN_DOMAIN.len() + 88 + responder_pk.len());
    m.extend_from_slice(PEER_AUDIT_RESP_SIGN_DOMAIN);
    m.extend_from_slice(txid);
    m.extend_from_slice(challenge_nonce);
    m.extend_from_slice(&sender_balance.to_le_bytes());
    m.extend_from_slice(&receiver_balance.to_le_bytes());
    m.extend_from_slice(state_id);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(responder_pk);
    m
}

/// KI#175: verify a peer-audit REQUEST's operational-wallet signature.
/// B calls this before answering — an unsigned/forged request is dropped.
pub fn verify_peer_audit_request_sig(request: &PeerAuditRequest) -> bool {
    let payload = peer_audit_request_signing_payload(
        &request.txid, &request.challenge_nonce, &request.requester_pk,
    );
    crate::crypto::verify_ed25519(&request.requester_pk, &payload, &request.requester_sig).is_ok()
}

/// KI#175: verify a peer-audit RESPONSE's operational-wallet signature.
/// A calls this (together with the responder_pk == target_validator_pk check in
/// the caller) BEFORE any ban, so a forged response cannot get B banned.
pub fn verify_peer_audit_response_sig(response: &PeerAuditResponse) -> bool {
    let payload = peer_audit_response_signing_payload(
        &response.txid, &response.challenge_nonce,
        response.sender_balance, response.receiver_balance,
        &response.state_id, response.amount, &response.responder_pk,
    );
    crate::crypto::verify_ed25519(&response.responder_pk, &payload, &response.responder_sig).is_ok()
}

/// Generate the UNSIGNED peer-audit request skeleton (KI#207 raw-fields: no
/// expected hash is sent). Lambda fills `requester_sig` with the operational
/// wallet signature at send time (Core holds no keys). The requester keeps its
/// own expected value locally (PendingAudit.peer_expected_hash) to judge the
/// reply — it is never put on the wire.
pub fn generate_peer_audit_request(
    txid: &[u8; 32],
    challenge_nonce: &[u8; 32],
    our_pk: &[u8],
) -> PeerAuditRequest {
    PeerAuditRequest {
        txid: *txid,
        challenge_nonce: *challenge_nonce,
        requester_pk: our_pk.to_vec(),
        requester_sig: Vec::new(), // filled by Lambda before send
    }
}

/// Judge a peer-audit response (A side, KI#207 raw-fields).
///
/// A hashes B's REPORTED raw fields and compares to A's own expected hash
/// (computed from A's audit buffer when the demand was armed). B never received
/// A's expected value, so it cannot echo — honest fields match, tampered fields
/// diverge. This is the CONTENT check only; the caller MUST first verify
/// `verify_peer_audit_response_sig` and `responder_pk == target_validator_pk`
/// (KI#175) before acting on the verdict.
///
/// Returns true if B's fields reproduce A's expected hash (peer honest).
pub fn verify_peer_audit_response(
    expected_hash: &[u8; 32],
    response: &PeerAuditResponse,
) -> bool {
    let computed = compute_peer_audit_hash(
        &response.txid,
        response.sender_balance,
        response.receiver_balance,
        &response.state_id,
        response.amount,
    );
    &computed == expected_hash
}

/// §23.14.6 (KI#213, ruled 2026-09-24): B's SIGNED statement that it holds no
/// record for `txid`. Its own domain, so it can never be confused with a
/// raw-fields response signature.
pub const PEER_AUDIT_NOTHELD_SIGN_DOMAIN: &[u8] = b"AXIOM_PEER_AUDIT_NOTHELD_V1";

pub fn peer_audit_not_held_signing_payload(
    txid: &[u8; 32],
    challenge_nonce: &[u8; 32],
    responder_pk: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(PEER_AUDIT_NOTHELD_SIGN_DOMAIN.len() + 64 + responder_pk.len());
    m.extend_from_slice(PEER_AUDIT_NOTHELD_SIGN_DOMAIN);
    m.extend_from_slice(txid);
    m.extend_from_slice(challenge_nonce);
    m.extend_from_slice(responder_pk);
    m
}

pub fn verify_peer_audit_not_held_sig(nh: &PeerAuditNotHeld) -> bool {
    let payload = peer_audit_not_held_signing_payload(&nh.txid, &nh.challenge_nonce, &nh.responder_pk);
    crate::crypto::verify_ed25519(&nh.responder_pk, &payload, &nh.responder_sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// §23.14.2 (KI#213): the target set is the CURRENT tx's co-witnesses at the
    /// finalizing CL3 — never the previous receipt's witnesses, never at CL2.
    /// Red on the pre-fix selection (prev_receipts at CL2|CL3).
    #[test]
    fn audit_targets_are_the_current_cowitnesses_at_cl3_only() {
        use crate::types::{PublicInputs, Receipt, WitnessSig};
        fn sig(pk: u8) -> WitnessSig {
            WitnessSig {
                validator_id: [0u8; 32], validator_pk: vec![pk; 32], vbc_bundle: None,
                carrier_type: "email".into(), carrier_address: "x@axiom".into(),
                signature: vec![], execution_proof: vec![], proof_type: 1,
                availability_attestation: None, validator_hints: vec![], fact_signature: None,
                checkpoint_sig: None, receipt_signature: None, receipt_commitment_sig: None,
                rate_bps: 0, slot_amount: 0,
            }
        }
        let mut inputs = PublicInputs::default();
        let prev = Receipt {
            oods_flag: None, confidence_index: None, sender_state: None,
            txid: [1u8; 32], state_hash: [2u8; 32], produced_state_id: [3u8; 32], new_wallet_seq: 1,
            commitment_hash: [0u8; 32], sdid: [0u8; 32], lineage_hash: [0u8; 32],
            core_version: alloc::string::String::new(), epoch: 0, fact_proof: None, required_k: 3,
            receipt_commitment: [0u8; 32], fee_breakdown: Vec::new(), is_dev_class: false,
            core_id: [0u8; 32],
            witness_sigs: vec![sig(0xAA)],                  // previous tx's witness
        };
        inputs.prev_receipts = vec![prev];
        inputs.overlapped_signatures = vec![sig(0xBB), sig(0xCC)]; // current co-witnesses (V1, V2 at V3)
        inputs.fact_witness_sigs = vec![sig(0xDD)];                // EMPTY at a real finalize — never the source
        inputs.mode = crate::CoreLogicMode::CL3;
        let c = audit_target_candidates(&inputs);
        assert_eq!(c, vec![vec![0xBBu8; 32], vec![0xCCu8; 32]], "co-witnesses of THIS tx, in order (no self pk given)");
        inputs.my_validator_pk = Some(vec![0xEEu8; 32]);
        let c = audit_target_candidates(&inputs);
        assert_eq!(c, vec![vec![0xBBu8; 32], vec![0xCCu8; 32], vec![0xEEu8; 32]],
                   "SELF is a candidate too, appended last — the §23.14.6 self-audit stays reachable");
        inputs.my_validator_pk = Some(vec![0xBBu8; 32]);
        assert_eq!(audit_target_candidates(&inputs).len(), 2, "never duplicated");
        inputs.my_validator_pk = Some(vec![0xEEu8; 32]);
        assert!(!c.contains(&vec![0xAAu8; 32]), "a previous witness is not a candidate");
        assert!(!c.contains(&vec![0xDDu8; 32]), "fact_witness_sigs is not the source (empty at a real finalize)");
        inputs.mode = crate::CoreLogicMode::CL2;
        assert!(audit_target_candidates(&inputs).is_empty(), "a CL2 hop has no current witness set — no demand");
    }

    #[test]
    fn test_should_trigger_deterministic() {
        let txid = [42u8; 32];
        let result1 = should_trigger_audit(&txid);
        let result2 = should_trigger_audit(&txid);
        assert_eq!(result1, result2, "Same txid must produce same decision");
    }

    #[test]
    fn test_trigger_rate_approximate() {
        // Generate 10000 random-ish txids and count triggers
        let mut triggers = 0u32;
        for i in 0u32..10000 {
            let mut txid = [0u8; 32];
            txid[0..4].copy_from_slice(&i.to_le_bytes());
            // Mix with blake3 for uniform distribution
            let hash = blake3::hash(&txid);
            let txid: [u8; 32] = *hash.as_bytes();
            if should_trigger_audit(&txid) {
                triggers += 1;
            }
        }
        // Expect 10000 / AUDIT_TRIGGER_RATE (1 in 50 → ~200); allow ±50 %.
        let expected = 10_000 / AUDIT_TRIGGER_RATE as u32;
        assert!(
            (expected / 2..=expected * 3 / 2).contains(&triggers),
            "Expected ~{} triggers in 10000 TXs (1 in {}), got {}", expected, AUDIT_TRIGGER_RATE, triggers
        );
    }

    #[test]
    fn test_generate_audit_demand() {
        let txid = [7u8; 32];
        let pks = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];

        let demand = generate_audit_demand(&txid, &pks).unwrap();

        // Challenge nonce is deterministic
        let demand2 = generate_audit_demand(&txid, &pks).unwrap();
        assert_eq!(demand.challenge_nonce, demand2.challenge_nonce);
        assert_eq!(demand.target_validator_pk, demand2.target_validator_pk);
        assert_eq!(demand.trigger_txid, txid);

        // Target is one of the PKs
        assert!(pks.contains(&demand.target_validator_pk));
    }

    #[test]
    fn test_generate_audit_demand_empty_pks() {
        let txid = [0u8; 32];
        assert!(generate_audit_demand(&txid, &[]).is_none());
    }

    fn make_test_confirmation(nonce: [u8; 32], target: Vec<u8>) -> crate::types::AuditConfirmation {
        crate::types::AuditConfirmation {
            challenge_nonce: nonce,
            target_validator_pk: target,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
        }
    }

    #[test]
    fn test_verify_nonce_valid() {
        let demand = AuditDemand {
            challenge_nonce: [1u8; 32],
            target_validator_pk: vec![2u8; 32],
            trigger_txid: [3u8; 32],
        };
        let confirmation = make_test_confirmation([1u8; 32], vec![2u8; 32]);
        assert!(verify_audit_nonce(&demand, &confirmation));
    }

    #[test]
    fn test_verify_nonce_wrong_nonce() {
        let demand = AuditDemand {
            challenge_nonce: [1u8; 32],
            target_validator_pk: vec![2u8; 32],
            trigger_txid: [3u8; 32],
        };
        let confirmation = make_test_confirmation([99u8; 32], vec![2u8; 32]);
        assert!(!verify_audit_nonce(&demand, &confirmation));
    }

    #[test]
    fn test_verify_nonce_wrong_target() {
        let demand = AuditDemand {
            challenge_nonce: [1u8; 32],
            target_validator_pk: vec![2u8; 32],
            trigger_txid: [3u8; 32],
        };
        let confirmation = make_test_confirmation([1u8; 32], vec![99u8; 32]);
        assert!(!verify_audit_nonce(&demand, &confirmation));
    }

    #[test]
    fn test_verify_content_match() {
        let digest = crate::types::TxDigest {
            tx_number: 42,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
        };
        let confirmation = make_test_confirmation([1u8; 32], vec![2u8; 32]);
        assert!(verify_audit_content(&confirmation, &digest));
    }

    #[test]
    fn test_verify_content_mismatch_balance() {
        let digest = crate::types::TxDigest {
            tx_number: 42,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
        };
        // Lambda reports inflated balance
        let mut confirmation = make_test_confirmation([1u8; 32], vec![2u8; 32]);
        confirmation.sender_balance = 9999;
        assert!(!verify_audit_content(&confirmation, &digest));
    }

    #[test]
    fn test_verify_content_mismatch_state_id() {
        let digest = crate::types::TxDigest {
            tx_number: 42,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
        };
        // Lambda reports tampered state_id
        let mut confirmation = make_test_confirmation([1u8; 32], vec![2u8; 32]);
        confirmation.state_id = [0u8; 32];
        assert!(!verify_audit_content(&confirmation, &digest));
    }

    #[test]
    fn test_target_selection_varies_with_txid() {
        let pks = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let mut targets = std::collections::HashSet::new();

        // Different txids should eventually select different targets
        for i in 0u32..100 {
            let mut txid = [0u8; 32];
            txid[8..12].copy_from_slice(&i.to_le_bytes());
            if let Some(demand) = generate_audit_demand(&txid, &pks) {
                targets.insert(demand.target_validator_pk.clone());
            }
        }
        // Should have selected at least 2 different targets
        assert!(targets.len() >= 2, "Target selection should vary");
    }

    // === Peer-audit tests ===

    #[test]
    fn test_compute_peer_audit_hash_deterministic() {
        let txid = [42u8; 32];
        let h1 = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let h2 = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        assert_eq!(h1, h2, "Same inputs must produce same hash");
    }

    #[test]
    fn test_compute_peer_audit_hash_differs_on_balance() {
        let txid = [42u8; 32];
        let h1 = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let h2 = compute_peer_audit_hash(&txid, 9999, 500, &[7u8; 32], 200);
        assert_ne!(h1, h2, "Different balance must produce different hash");
    }

    #[test]
    fn test_compute_peer_audit_hash_differs_on_state_id() {
        let txid = [42u8; 32];
        let h1 = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let h2 = compute_peer_audit_hash(&txid, 1000, 500, &[0u8; 32], 200);
        assert_ne!(h1, h2, "Different state_id must produce different hash");
    }

    #[test]
    fn test_generate_peer_audit_request_carries_no_expected_hash() {
        // KI#207: the request must NOT carry an answer for B to echo. This test
        // also acts as the mutation guard — generate_peer_audit_request takes
        // (txid, nonce, pk) only; re-adding an expected_hash field/arg breaks it.
        let txid = [7u8; 32];
        let nonce = [1u8; 32];
        let our_pk = vec![2u8; 32];

        let req = generate_peer_audit_request(&txid, &nonce, &our_pk);
        assert_eq!(req.txid, txid);
        assert_eq!(req.challenge_nonce, nonce);
        assert_eq!(req.requester_pk, our_pk);
        assert!(req.requester_sig.is_empty(), "Core builds unsigned; Lambda signs");
    }

    // --- KI#207 raw-fields: A judges B's reported fields against A's expected ---

    fn honest_response(txid: [u8; 32], nonce: [u8; 32], pk: Vec<u8>) -> PeerAuditResponse {
        PeerAuditResponse {
            txid,
            challenge_nonce: nonce,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
            responder_pk: pk,
            responder_sig: Vec::new(),
        }
    }

    #[test]
    fn test_verify_peer_audit_response_honest_fields_match() {
        let txid = [7u8; 32];
        // A's expected hash, computed from A's own audit buffer digest.
        let expected = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let resp = honest_response(txid, [1u8; 32], vec![3u8; 32]);
        assert!(verify_peer_audit_response(&expected, &resp), "honest B's fields reproduce A's expected");
    }

    #[test]
    fn test_verify_peer_audit_response_tampered_fields_mismatch() {
        let txid = [7u8; 32];
        let expected = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let mut resp = honest_response(txid, [1u8; 32], vec![3u8; 32]);
        resp.sender_balance = 9999; // B tampered its DB
        assert!(!verify_peer_audit_response(&expected, &resp), "tampered fields must diverge → ban");
    }

    #[test]
    fn test_echo_attack_impossible() {
        // KI#207: there is no expected_hash on the wire, so a peer that returns
        // ZERO/garbage fields (never held the tx) cannot reproduce A's expected.
        let txid = [7u8; 32];
        let expected = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let mut resp = honest_response(txid, [1u8; 32], vec![3u8; 32]);
        resp.sender_balance = 0;
        resp.receiver_balance = 0;
        resp.state_id = [0u8; 32];
        resp.amount = 0;
        assert!(!verify_peer_audit_response(&expected, &resp), "a peer with no data cannot pass");
    }

    // --- KI#175 operational-wallet signatures ---

    fn sk(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    fn sign_request(req: &mut PeerAuditRequest, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        req.requester_pk = key.verifying_key().to_bytes().to_vec();
        let payload = peer_audit_request_signing_payload(&req.txid, &req.challenge_nonce, &req.requester_pk);
        req.requester_sig = key.sign(&payload).to_bytes().to_vec();
    }

    fn sign_response(resp: &mut PeerAuditResponse, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        resp.responder_pk = key.verifying_key().to_bytes().to_vec();
        let payload = peer_audit_response_signing_payload(
            &resp.txid, &resp.challenge_nonce, resp.sender_balance,
            resp.receiver_balance, &resp.state_id, resp.amount, &resp.responder_pk,
        );
        resp.responder_sig = key.sign(&payload).to_bytes().to_vec();
    }

    #[test]
    fn test_request_sig_roundtrip_and_forgery() {
        let a = sk(0x0A);
        let mut req = generate_peer_audit_request(&[7u8; 32], &[1u8; 32], &[]);
        sign_request(&mut req, &a);
        assert!(verify_peer_audit_request_sig(&req), "A's real signature verifies → B answers");

        // Forged: tamper the txid after signing → B refuses.
        let mut forged = req.clone();
        forged.txid = [9u8; 32];
        assert!(!verify_peer_audit_request_sig(&forged), "forged request must be dropped");
    }

    #[test]
    fn test_response_sig_roundtrip_and_forgery() {
        let b = sk(0x0B);
        let mut resp = honest_response([7u8; 32], [1u8; 32], vec![]);
        sign_response(&mut resp, &b);
        assert!(verify_peer_audit_response_sig(&resp), "B's real signature verifies");

        // KI#175 crux: an attacker forges a WRONG-fields response as B, signing
        // with its OWN key. The sig verifies under the attacker's key, but the
        // attacker's pk != B's target pk, so the caller's target check rejects it.
        let attacker = sk(0xEE);
        let mut forged = honest_response([7u8; 32], [1u8; 32], vec![]);
        forged.sender_balance = 9999; // frame B
        sign_response(&mut forged, &attacker);
        assert!(verify_peer_audit_response_sig(&forged), "forged resp is self-consistently signed...");
        assert_ne!(forged.responder_pk, resp.responder_pk,
                   "...but signed by the attacker's key, not B's target pk → caller rejects, B not banned");
    }

    #[test]
    fn test_full_honest_round() {
        // A demands, B reports honest fields + signs, A verifies sig + judges content.
        let txid = [7u8; 32];
        let nonce = [1u8; 32];
        let a = sk(0x0A);
        let b = sk(0x0B);
        let target_pk = b.verifying_key().to_bytes().to_vec();

        let mut req = generate_peer_audit_request(&txid, &nonce, &[]);
        sign_request(&mut req, &a);
        assert!(verify_peer_audit_request_sig(&req));

        let mut resp = honest_response(txid, nonce, vec![]);
        sign_response(&mut resp, &b);

        // A's checks, in order (as handle_peer_audit_response does):
        assert!(verify_peer_audit_response_sig(&resp));           // 1: authentic
        assert_eq!(resp.responder_pk, target_pk);                 // 2: it's the peer A demanded
        let expected = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        assert!(verify_peer_audit_response(&expected, &resp));    // 3: content honest
    }
}
