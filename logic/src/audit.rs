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
//! - Target selection: pick from prev_receipts witness PKs.
//! - Countdown enforcement: lives in AVM interpreter (host), not guest.
//! - Tamper protection: if operator modifies AVM to skip countdown,
//!   DMAP attestation diverges from honest re-executors → rejected.

use alloc::vec::Vec;
use crate::types::{AuditDemand, AUDIT_TRIGGER_RATE, PeerAuditRequest, PeerAuditResponse};

/// Domain tag for audit challenge nonce derivation
const AUDIT_CHALLENGE_DOMAIN: &[u8] = b"AXIOM_AUDIT_CHALLENGE";

/// Check if this transaction should trigger an audit demand.
///
/// Deterministic: same txid always produces the same decision.
/// Probability: ~1 in AUDIT_TRIGGER_RATE (default 1 in 100).
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
/// Selects a target validator from the witness PKs in prev_receipts.
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

/// Generate a peer audit request from a TxDigest in the audit buffer.
///
/// Core computes the expected hash and packages it with the txid.
/// Lambda carries this to the remote validator via ANTIE email.
pub fn generate_peer_audit_request(
    txid: &[u8; 32],
    digest: &crate::types::TxDigest,
    challenge_nonce: &[u8; 32],
    our_pk: &[u8],
) -> PeerAuditRequest {
    let expected_hash = compute_peer_audit_hash(
        txid,
        digest.sender_balance,
        digest.receiver_balance,
        &digest.state_id,
        digest.amount,
    );
    PeerAuditRequest {
        txid: *txid,
        expected_hash,
        challenge_nonce: *challenge_nonce,
        requester_pk: our_pk.to_vec(),
    }
}

/// Verify an inbound peer audit request against local Lambda's DB data.
///
/// Called by remote Core when receiving a peer audit ping. Remote Lambda
/// provides raw DB fields, remote Core computes hash and compares against
/// the expected_hash sent by the requester.
///
/// Returns (computed_hash, matches). If !matches, remote Core should
/// initiate a 3-minute crash delay (its own Lambda's DB is corrupted).
pub fn verify_inbound_peer_audit(
    request: &PeerAuditRequest,
    sender_balance: u64,
    receiver_balance: u64,
    state_id: &[u8; 32],
    amount: u64,
) -> ([u8; 32], bool) {
    let computed_hash = compute_peer_audit_hash(
        &request.txid,
        sender_balance,
        receiver_balance,
        state_id,
        amount,
    );
    let matches = computed_hash == request.expected_hash;
    (computed_hash, matches)
}

/// Verify a peer audit response received from remote validator.
///
/// Called by local Core when the response arrives via ANTIE email.
/// Compares the remote's computed_hash against our expected_hash.
///
/// Returns true if hashes match (peer is honest). False = ban for 24h.
pub fn verify_peer_audit_response(
    expected_hash: &[u8; 32],
    response: &PeerAuditResponse,
) -> bool {
    response.computed_hash == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
        // Expect ~100 triggers (1%), allow 50-200 range
        assert!(
            (50..=200).contains(&triggers),
            "Expected ~100 triggers in 10000 TXs, got {}", triggers
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
    fn test_generate_peer_audit_request() {
        let txid = [7u8; 32];
        let digest = crate::types::TxDigest {
            tx_number: 42,
            sender_balance: 1000,
            receiver_balance: 500,
            state_id: [7u8; 32],
            amount: 200,
        };
        let nonce = [1u8; 32];
        let our_pk = vec![2u8; 32];

        let req = generate_peer_audit_request(&txid, &digest, &nonce, &our_pk);
        assert_eq!(req.txid, txid);
        assert_eq!(req.challenge_nonce, nonce);
        assert_eq!(req.requester_pk, our_pk);

        // expected_hash should match manual computation
        let expected = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        assert_eq!(req.expected_hash, expected);
    }

    #[test]
    fn test_verify_inbound_peer_audit_match() {
        let txid = [7u8; 32];
        let expected_hash = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let req = PeerAuditRequest {
            txid,
            expected_hash,
            challenge_nonce: [1u8; 32],
            requester_pk: vec![2u8; 32],
        };
        // Remote has same data — should match
        let (computed, matches) = verify_inbound_peer_audit(&req, 1000, 500, &[7u8; 32], 200);
        assert!(matches, "Honest DB should match");
        assert_eq!(computed, expected_hash);
    }

    #[test]
    fn test_verify_inbound_peer_audit_mismatch_tampered_balance() {
        let txid = [7u8; 32];
        let expected_hash = compute_peer_audit_hash(&txid, 1000, 500, &[7u8; 32], 200);
        let req = PeerAuditRequest {
            txid,
            expected_hash,
            challenge_nonce: [1u8; 32],
            requester_pk: vec![2u8; 32],
        };
        // Remote Lambda tampered: inflated balance
        let (_, matches) = verify_inbound_peer_audit(&req, 9999, 500, &[7u8; 32], 200);
        assert!(!matches, "Tampered balance must be detected");
    }

    #[test]
    fn test_verify_peer_audit_response_match() {
        let hash = [42u8; 32];
        let response = PeerAuditResponse {
            txid: [7u8; 32],
            computed_hash: hash,
            challenge_nonce: [1u8; 32],
            responder_pk: vec![3u8; 32],
        };
        assert!(verify_peer_audit_response(&hash, &response));
    }

    #[test]
    fn test_verify_peer_audit_response_mismatch() {
        let expected = [42u8; 32];
        let response = PeerAuditResponse {
            txid: [7u8; 32],
            computed_hash: [99u8; 32], // wrong hash
            challenge_nonce: [1u8; 32],
            responder_pk: vec![3u8; 32],
        };
        assert!(!verify_peer_audit_response(&expected, &response));
    }
}
