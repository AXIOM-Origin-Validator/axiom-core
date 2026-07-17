//! Canonical receipt builder — single source of truth for Receipt construction.
//!
//! # Why this module exists
//!
//! Pre-this-module, three places independently constructed Receipts (or
//! receipt-shaped CBOR maps):
//! - `lambda::consensus::ConsensusEngine::finalize_transaction` (full Receipt struct
//!   for storage + WitnessResponse)
//! - `sdk::send::build_receipt_cbor` (manual CBOR Map for wallet.cbor)
//! - `lambda::consensus::ConsensusEngine` redeem paths (variants of the above)
//!
//! Each call site independently chose values for `state_hash`, `epoch`, `txid`,
//! and `commitment_hash` from differently-shaped inputs. When one call site
//! disagreed with another, the receipt's stored `receipt_commitment` no longer
//! matched what `Core CL2::validate_witnesses` recomputed on the next TX,
//! producing `E_RECEIPT_COMMITMENT_MISMATCH` on every prev_receipt verify.
//!
//! Today's bugs caught and fixed by inlining this rule into a shared builder:
//! - `fund_genesis` hardcoded `&[0u8; 32]` for commitment_hash → [`build_send_receipt`]
//!   now requires the real value
//! - `redeem.rs` used `SystemTime::now()` for epoch but Lambda CL5 hashed with
//!   `epoch=0` → [`build_redeem_receipt`] forces `epoch=0`
//! - `redeem.rs` used `state_hash` from response but Lambda CL5 hashed with
//!   `state_hash=[0;32]` → [`build_redeem_receipt`] forces `state_hash=[0;32]`
//! - `redeem.rs` extracted `txid` from `bundle.txid` (hex text), but the
//!   string-vs-bytes encoding of that field produced unrecognized bytes →
//!   [`build_redeem_receipt`] takes a `cheque_txid: [u8; 32]` and the caller
//!   reads it from `cheque.txid` (the typed inner field)
//!
//! # Contract
//!
//! Both Lambda's `WitnessResponse.receipt` field and the SDK's
//! `wallet.last_receipt` byte blob are byte-identical when both sides go
//! through this builder. `Core CL2::validate_witnesses` then recomputes
//! `receipt_commitment` from the same field values and the verify always
//! matches.
//!
//! # Receipt kinds
//!
//! The four protocol modes that produce a Receipt have slightly different
//! input rules. Encoding the rules as variants of [`ReceiptInputs`] makes them
//! impossible to forget at a call site (the type system carries the mode).

use crate::crypto::compute_receipt_commitment;
use crate::types::{
    genesis_lineage_hash, genesis_sdid, FeeShare, Receipt, WitnessSig, CORE_VERSION,
};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Inputs for [`build_send_receipt`] — used by CL3 send/finalize and the
/// genesis-claim send path. Every field is the value Core's CL3 actually
/// produced; the builder applies no further transformation.
pub struct SendReceiptInputs {
    pub txid: [u8; 32],
    pub state_hash: [u8; 32],
    pub produced_state_id: [u8; 32],
    pub new_wallet_seq: u64,
    pub commitment_hash: [u8; 32],
    pub epoch: u64,
    pub witness_sigs: Vec<WitnessSig>,
    pub required_k: u8,
    /// BLAKE3 of the Core ELF that produced this receipt. Stamped onto
    /// `Receipt.core_id`; covered by `receipt_commitment`. See
    /// `Receipt::core_id` doc + CL2 Step −1.5 in validation.rs.
    /// Pass `[0u8; 32]` when not yet wired (backward compat — Receipt's
    /// `core_id` is `#[serde(default)]` so the check is skipped).
    pub core_id: [u8; 32],
    /// Dev-class flag — `true` iff this TX's sender was an
    /// `@axiom.internal` wallet (per `is_dev_wallet`). Routed by
    /// Nabla `/register` into the dev DEED pool + dev validator
    /// NET ledger so dev-AXC fees cannot leak into the public
    /// economy. Caller (modes.rs CL3) MUST set this from
    /// `is_dev_wallet(tx.sender_wallet_id)`.
    pub is_dev_class: bool,
    /// YPX-021 §8.2 — the OODS health flag Core derived from the verified
    /// `NablaOodsAttestation`. Callers MUST pass `PublicOutputs.oods_flag`
    /// verbatim — the same value Core bound into `receipt_commitment`.
    pub oods_flag: Option<crate::types::OodsFlag>,
}

/// Inputs for [`build_redeem_receipt`] — used by CL5 redeem and the
/// genesis-claim self-redeem. `epoch` is *forced* to `0` inside the builder
/// to match what `modes::execute_cl5` hashes into `receipt_commitment`
/// (see `core/logic/src/modes.rs:2071-2078`).
///
/// §15 (2026-06-05): `state_hash` is no longer forced to `[0u8; 32]`.
/// Pre-§15 the convention was "CL5 doesn't compute one (receiver-side)"
/// but that left every redeem receipt unanchored — the receiver's next
/// CL1 had no `state_hash` to anchor against. Now CL5 computes
/// `compute_state_hash(receiver_pk, new_balance, new_wallet_seq)` and
/// passes it in here; receipts have a uniform meaning regardless of
/// which Core mode produced them.
///
/// Callers MUST pass `cheque_txid` from `cheque.txid` (the typed `[u8; 32]`
/// field on the inner cheque), NOT from any hex-string encoding of the
/// bundle's top-level `txid` field. The bundle's `txid` is denormalized for
/// Python-side ergonomics; CL5 hashes the cheque's typed bytes.
pub struct RedeemReceiptInputs {
    pub cheque_txid: [u8; 32],
    pub produced_state_id: [u8; 32],
    pub new_wallet_seq: u64,
    pub commitment_hash: [u8; 32],
    pub witness_sigs: Vec<WitnessSig>,
    pub required_k: u8,
    /// BLAKE3 of the Core ELF that produced this receipt. See SendReceiptInputs.
    pub core_id: [u8; 32],
    /// Receiver-pays-only fee allocation. Bound into `receipt_commitment`.
    pub fee_breakdown: Vec<FeeShare>,
    /// §15: receiver's post-redeem `compute_state_hash(pk, new_balance,
    /// new_wallet_seq)`. Bound into `receipt_commitment` AND stored on
    /// the receipt's `state_hash` field so the receiver's next CL1
    /// anchor check can verify against it. Pre-§15 this was forced to
    /// `[0u8; 32]`.
    pub state_hash: [u8; 32],
    /// Dev-class flag — Core CL5 derives this from
    /// `is_dev_wallet(cheque.sender_wallet_id)` after asserting every
    /// cheque in the bundle agrees. Carried into Nabla `/register` via
    /// `Receipt.is_dev_class` for dev-pool routing.
    pub is_dev_class: bool,
    /// YPX-021 §8.2 — see `SendReceiptInputs::oods_flag`. Pass
    /// `PublicOutputs.oods_flag` verbatim from the CL5 run.
    pub oods_flag: Option<crate::types::OodsFlag>,
}

/// Inputs for [`build_heal_receipt`] — used by the heal-burn CL3 path.
/// Heal goes through CL3 like send (with `is_heal=true` on the Transaction)
/// so the same fields apply.
pub type HealReceiptInputs = SendReceiptInputs;

/// Build a Receipt for the CL3 send/finalize/genesis-claim/heal path.
///
/// Every field comes through unchanged. The builder only injects the
/// invariant fields (sdid, lineage_hash, core_version) and computes the
/// `receipt_commitment` deterministically from the inputs.
pub fn build_send_receipt(inputs: SendReceiptInputs) -> Receipt {
    // YP §20.8: send-path receipts have no fee_breakdown. Receiver-pays
    // model means fees live on the redeem path only.
    let empty_fees: Vec<FeeShare> = Vec::new();
    let receipt_commitment = compute_receipt_commitment(
        &inputs.txid,
        &inputs.state_hash,
        inputs.new_wallet_seq,
        &inputs.commitment_hash,
        inputs.epoch,
        inputs.is_dev_class,
        inputs.oods_flag.as_ref(),
    );
    Receipt {
        txid: inputs.txid,
        state_hash: inputs.state_hash,
        produced_state_id: inputs.produced_state_id,
        new_wallet_seq: inputs.new_wallet_seq,
        commitment_hash: inputs.commitment_hash,
        sdid: genesis_sdid(),
        lineage_hash: genesis_lineage_hash(),
        core_version: CORE_VERSION.to_string(),
        core_id: inputs.core_id,
        witness_sigs: inputs.witness_sigs,
        epoch: inputs.epoch,
        fact_proof: None,
        required_k: inputs.required_k,
        receipt_commitment,
        fee_breakdown: empty_fees,
        is_dev_class: inputs.is_dev_class,
        oods_flag: inputs.oods_flag,
    }
}

/// Build a Receipt for the CL5 redeem path.
///
/// Forces `state_hash = [0u8; 32]` and `epoch = 0` to match what
/// `modes::execute_cl5` hashes into `receipt_commitment`. Callers cannot
/// override these — that would break the CL2 prev_receipt verify on the
/// receiver's next send.
pub fn build_redeem_receipt(inputs: RedeemReceiptInputs) -> Receipt {
    const REDEEM_EPOCH: u64 = 0;

    let receipt_commitment = compute_receipt_commitment(
        &inputs.cheque_txid,
        &inputs.state_hash,
        inputs.new_wallet_seq,
        &inputs.commitment_hash,
        REDEEM_EPOCH,
        inputs.is_dev_class,
        inputs.oods_flag.as_ref(),
    );
    Receipt {
        txid: inputs.cheque_txid,
        state_hash: inputs.state_hash,
        produced_state_id: inputs.produced_state_id,
        new_wallet_seq: inputs.new_wallet_seq,
        commitment_hash: inputs.commitment_hash,
        sdid: genesis_sdid(),
        lineage_hash: genesis_lineage_hash(),
        core_version: CORE_VERSION.to_string(),
        core_id: inputs.core_id,
        witness_sigs: inputs.witness_sigs,
        epoch: REDEEM_EPOCH,
        fact_proof: None,
        required_k: inputs.required_k,
        receipt_commitment,
        fee_breakdown: inputs.fee_breakdown,
        is_dev_class: inputs.is_dev_class,
        oods_flag: inputs.oods_flag,
    }
}

/// Heal-burn shares the send receipt rule (CL3 path).
pub fn build_heal_receipt(inputs: HealReceiptInputs) -> Receipt {
    build_send_receipt(inputs)
}

/// Verify that a stored Receipt's `receipt_commitment` matches what would
/// be computed from its fields. Used by `Core CL2::validate_witnesses` and
/// available to clients for sanity-checking received receipts before
/// shipping them as prev_receipts.
///
/// Returns `true` iff the stored commitment is consistent with the field
/// values; a `false` return means the receipt was tampered with, was built
/// with a stale codec, or was hashed under different rules than this build
/// of the codebase enforces.
pub fn verify_receipt_commitment(receipt: &Receipt) -> bool {
    let expected = compute_receipt_commitment(
        &receipt.txid,
        &receipt.state_hash,
        receipt.new_wallet_seq,
        &receipt.commitment_hash,
        receipt.epoch,
        receipt.is_dev_class,
        receipt.oods_flag.as_ref(),
    );
    receipt.receipt_commitment == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_witness_sigs() -> Vec<WitnessSig> {
        Vec::new()
    }

    /// A send receipt built from the same inputs has the same
    /// `receipt_commitment` regardless of which side calls the builder
    /// (Lambda or SDK).
    #[test]
    fn send_receipt_is_deterministic() {
        let inputs1 = SendReceiptInputs {
            oods_flag: None,
            txid: [0xaa; 32],
            state_hash: [0xbb; 32],
            produced_state_id: [0xcc; 32],
            new_wallet_seq: 7,
            commitment_hash: [0xdd; 32],
            epoch: 1700000000,
            witness_sigs: dummy_witness_sigs(),
            required_k: 3,
            core_id: [0u8; 32],
            is_dev_class: false,
        };
        let inputs2 = SendReceiptInputs {
            oods_flag: None,
            txid: [0xaa; 32],
            state_hash: [0xbb; 32],
            produced_state_id: [0xcc; 32],
            new_wallet_seq: 7,
            commitment_hash: [0xdd; 32],
            epoch: 1700000000,
            witness_sigs: dummy_witness_sigs(),
            required_k: 3,
            core_id: [0u8; 32],
            is_dev_class: false,
        };
        let r1 = build_send_receipt(inputs1);
        let r2 = build_send_receipt(inputs2);
        assert_eq!(r1.receipt_commitment, r2.receipt_commitment);
        assert!(verify_receipt_commitment(&r1));
    }

    /// §15 (2026-06-05): redeem receipts now carry a state_hash bound
    /// to the receiver's NET state (`compute_state_hash(receiver_pk,
    /// new_balance, new_wallet_seq)`); the builder passes the caller-
    /// supplied value through. `epoch` is still forced to `0` — that
    /// stays a builder-enforced rule.
    #[test]
    fn redeem_receipt_carries_caller_state_hash_and_forces_zero_epoch() {
        let supplied_state_hash = [0xAB; 32];
        let inputs = RedeemReceiptInputs {
            oods_flag: None,
            cheque_txid: [0x11; 32],
            produced_state_id: [0x22; 32],
            new_wallet_seq: 5,
            commitment_hash: [0x33; 32],
            witness_sigs: dummy_witness_sigs(),
            required_k: 3,
            core_id: [0u8; 32],
            fee_breakdown: Vec::new(),
            state_hash: supplied_state_hash,
            is_dev_class: false,
        };
        let r = build_redeem_receipt(inputs);
        assert_eq!(r.state_hash, supplied_state_hash,
            "§15: redeem receipts carry the caller-supplied state_hash");
        assert_eq!(r.epoch, 0, "redeem receipts MUST use epoch=0");
        assert!(verify_receipt_commitment(&r));
    }

    /// Receipt commitment is exactly what `Core CL2::validate_witnesses`
    /// recomputes from the receipt's stored field values.
    #[test]
    fn receipt_commitment_matches_cl2_recompute() {
        let inputs = SendReceiptInputs {
            oods_flag: None,
            txid: [0xee; 32],
            state_hash: [0u8; 32],
            produced_state_id: [0xff; 32],
            new_wallet_seq: 1,
            commitment_hash: [0x77; 32],
            epoch: 1700000001,
            witness_sigs: dummy_witness_sigs(),
            required_k: 3,
            core_id: [0u8; 32],
            is_dev_class: false,
        };
        let r = build_send_receipt(inputs);
        // CL2's recompute IS verify_receipt_commitment.
        assert!(verify_receipt_commitment(&r));
    }

    /// A receipt with a tampered field fails verification.
    #[test]
    fn tampered_receipt_fails_verify() {
        let inputs = SendReceiptInputs {
            oods_flag: None,
            txid: [0x01; 32],
            state_hash: [0x02; 32],
            produced_state_id: [0x03; 32],
            new_wallet_seq: 2,
            commitment_hash: [0x04; 32],
            epoch: 1700000002,
            witness_sigs: dummy_witness_sigs(),
            required_k: 3,
            core_id: [0u8; 32],
            is_dev_class: false,
        };
        let mut r = build_send_receipt(inputs);
        // Mutate state_hash. The stored receipt_commitment was computed
        // over the original state_hash, so verify must fail.
        r.state_hash = [0x99; 32];
        assert!(
            !verify_receipt_commitment(&r),
            "tampered receipt must fail commitment verification"
        );
    }
}
