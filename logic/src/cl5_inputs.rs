//! CL5 attestation-input builder — single source of truth.
//!
//! The CL5 DMAP attestation flow has THREE call sites that must agree
//! byte-for-byte on the `PublicInputs` CBOR serialization or the
//! `input_hash` check fails:
//!
//!   1. SDK `run_cl5` (sdk/client/src/cl5.rs) — produces the attestation by
//!      running Core CL5 locally. The `input_hash` is BLAKE3 of the
//!      `ciborium::into_writer(&inputs, …)` output. CBOR, not JSON —
//!      JSON's HashMap ordering / escaping / float representation
//!      make it non-deterministic enough to produce false-positive
//!      `InputHashMismatch` between SDK and Lambda even when both
//!      build identical typed values. See
//!      `feedback_no_json_in_protocol_path` (#1 recurring bug class).
//!   2. Lambda's attestation verification (lambda/src/consensus.rs,
//!      around line 5498) — recomputes `expected_input_hash` over the
//!      same PublicInputs and compares against `attestation.input_hash`.
//!   3. Lambda's actual CL5 execution (lambda/src/core_client.rs:613) —
//!      runs Core CL5 with Lambda-side additional fields populated
//!      (validator keys, sender_fact_chain, etc). NOT byte-equivalent
//!      to (1)/(2), but must accept the same redeem.
//!
//! Pre-consolidation (2026-06-04 PM-3), (1) and (2) lived as parallel
//! struct literals. (2) was *stripped* — it set `cheque_claim_proof:
//! None` and `txid_attestation: None`, both of which Core CL5 requires
//! to accept the redeem. Result: every SDK CL5 run rejected locally
//! with `ChequeClaimProofMissing`, no proof was produced, Lambda
//! rejected with `E_LAMBDA_CL5_PROOF_MISSING`. The smoke caught it.
//!
//! This is the 6th instance of the mirror-struct pattern catalogued
//! in CLAUDE.md §12. The fix is mechanical: lift the literal into
//! ONE function that both (1) and (2) call.
//!
//! Lambda's actual CL5 execution at (3) is intentionally NOT routed
//! through this builder — it has additional Lambda-derived fields
//! (`my_dilithium_sk`, `sender_fact_chain`, `receiver_fact_chain`,
//! `vbc_bundle`) that the attestation context doesn't include. Those
//! fields don't affect the attestation hash because they live outside
//! the canonical attestation-input subset returned here.

extern crate alloc;
use alloc::{vec, vec::Vec};
use alloc::string::{String, ToString};

use crate::types::{
    ChequeBundle, ChequeClaimProof, CoreLogicMode, FeeShare, NablaTxidAttestation,
    PublicInputs, Receipt, Transaction, TxKind,
};

/// Build the canonical CL5 attestation-context `PublicInputs`.
///
/// Both the SDK's local CL5 execution (produces the DMAP attestation)
/// AND Lambda's attestation-verification recompute (computes
/// `expected_input_hash`) MUST call this function. Any field added,
/// removed, or reordered here changes the JSON serialization and
/// breaks the `input_hash` match on the next redeem.
///
/// `current_balance`, `wallet_seq`, and `state_id` are the receiver's
/// pre-redeem wallet state, supplied by the client via
/// `RedeemRequestEnvelope.current_state`. A first-time receiver supplies
/// its OPENING state (seq 0, opening balance, its opening id — what the
/// SDK's fresh wallet holds — or the zero label; `WalletState::
/// is_opening_state`) and NO `prev_receipts`; `None` is not a valid
/// encoding (CLAUDE.md §15).
///
/// `cheque_claim_proof` is the Nabla-writer-signed §4.6 verify
/// receipt; Core CL5 rejects with `ChequeClaimProofMissing` if
/// absent. `txid_attestation` is the YPX-014 global-double-redeem
/// gate; Core CL5 reads it but doesn't currently require it to be
/// `Some` (see modes.rs:1682). Both are passed through here so the
/// attestation input_hash binds them.
///
/// `local_core_id` is the validator's expected CoreID (Lambda's
/// `self.expected_core_id`) on the verification side, or the SDK's
/// loaded ELF CoreID on the production side. They must match for
/// the attestation to verify; passing it through the inputs makes
/// that binding explicit.
///
/// `max_fact_links` is deliberately NOT a parameter. It's only used
/// by `validation.rs:765` when `sender_fact_chain.is_some()`, but
/// the attestation context always sets `sender_fact_chain: None`,
/// so the field is functionally dead here. Forcing `None` removes
/// a divergence vector that previously had SDK (`None`) and Lambda
/// (`Some(self.max_fact_links)`) disagree, producing
/// `InputHashMismatch` even with identical builders. Lambda still
/// enforces its operator-configured cap in the real CL5 execution
/// at `core_client.rs:660`.
pub fn build_cl5_attestation_inputs(
    receiver_pk: &[u8],
    bundle: &ChequeBundle,
    current_balance: u64,
    wallet_seq: u64,
    current_hibernation: u64, // YPX-020 — receiver's current hibernation_until (carried, not zeroed)
    // §5.2.2c — the receiver's current stake lock. CL5's gate keys on this to
    // refuse a redeem by a stake-locked wallet (KI#133), so it must be
    // populated, not `None`.
    //
    // ⚠ WRONG READING, corrected 2026-10-01 (Fable review F-1(b); RULE 0 §4).
    // This said "both sides pass the CLIENT-declared value [here]; the
    // authoritative copy is the one Lambda passes to the REAL CL5 execution
    // from its own storage" — a client-declared / Lambda-authoritative split.
    // Lambda's row is NOT authoritative: a validator that never served the
    // wallet holds no row (it fed `0`), and one that served it before the lock
    // / floor was set holds a stale one. The authority is the receiver's LAST
    // K-SIGNED RECEIPT (`prev_receipts` below): CL5 re-derives these DECLARED
    // values to its `state_hash` (`modes::cl5_anchor_receiver_state`). So every
    // caller — the SDK's run, Lambda's recompute AND Lambda's real execution —
    // passes the DECLARED values; Lambda's row is a pre-check only.
    current_wall_clock_lock: u64,
    // §4.2a — the receiver's current `emission_claimed_epoch` (declared,
    // anchored like the lock above).
    current_emission_claimed_epoch: u64,
    // ValidatorJoin §6b.13 — the receiver's current stake floor (CARRIED by the
    // redeem) and wallet-format block (CL5 refuses a non-current one). Declared,
    // anchored like the two above.
    current_stake_floor_until: u64,
    current_wallet_format: crate::types::WalletFormat,
    state_id: [u8; 32],
    // Fable review 2026-10-01 F-1(b) — the receiver's last k-signed receipt
    // (`RedeemRequestEnvelope::prev_receipts`): EXACTLY ONE for a returning
    // receiver, NONE for a first-time (zero) one. Bound into the attestation
    // input hash, so a validator is never handed a different receipt than the
    // one the client attested with.
    prev_receipts: Vec<Receipt>,
    cheque_claim_proof: Option<ChequeClaimProof>,
    txid_attestation: Option<NablaTxidAttestation>,
    // YPX-021 §8.2 — the client-fetched Nabla OODS reading. BOTH call
    // sites (Lambda expected-input recompute + SDK local CL5 run) MUST
    // pass the same request-carried value or the input hashes diverge —
    // exactly the drift class this shared builder exists to prevent
    // (CLAUDE.md §12 instance 5).
    oods_attestation: Option<crate::types::NablaOodsAttestation>,
    local_core_id: [u8; 32],
) -> PublicInputs {
    let cl5_amount = bundle.amount().unwrap_or(0);
    // total_fee derives from the Dilithium-signed cheques themselves —
    // each `ValidatorCheque.rate_bps` is bound into the cheque commitment
    // signature, so the SDK and every Lambda derive identical totals
    // from identical inputs. Closes the
    // `E_RECEIPT_COMMITMENT_MISMATCH` class (2026-06-05 PM).
    let cl5_total_fee: u64 = bundle.cheques.iter()
        .map(|c| crate::validation::expected_fee_slot_amount(c.amount, c.rate_bps))
        .sum();
    let cl5_new_balance = current_balance
        .saturating_add(cl5_amount)
        .saturating_sub(cl5_total_fee);
    let cl5_receiver_wid = bundle.receiver_wallet_id()
        .unwrap_or_default()
        .to_string();

    // Core version stamp on the synthetic CL5 Transaction — matches the
    // canonical "<TAG>/DMAP" suffix Lambda has been using since
    // v2.11.14. Hardcoded by both call sites pre-consolidation; lifted
    // here so the literal doesn't drift.
    let core_version = {
        let mut s = String::from(crate::version::CORE_VERSION_TAG);
        s.push_str("/DMAP");
        s
    };

    let cl5_tx = Transaction {
        consumed_state_id: state_id,
        receiver_wallet_id: cl5_receiver_wid,
        amount: cl5_amount,
        client_pk: receiver_pk.to_vec(),
        sender_wallet_id: String::new(),
        client_sig: Vec::new(),
        epoch: 0,
        wallet_seq,
        oracle_claim: None,
        core_version,
        core_id: [0u8; 32],
        kind: TxKind::Normal,
        nonce: 0,
        reference: String::new(),
        receiver_address: None,
        scar_passcode: None,
        burn_target_tx_id: None,
        recall_target_tx_id: None,
        required_k: 0,
        proof_type: 0,
    };

    PublicInputs {
        zkq_request: None,
        fact_certificates: alloc::vec::Vec::new(),
        mode: CoreLogicMode::CL5,
        local_core_id,
        transaction: cl5_tx,
        current_state: None,
        prev_receipts,
        vbc_bundle: None,
        cheque_bundle: Some(bundle.clone()),
        receiver_pk: Some(receiver_pk.to_vec()),
        receiver_current_balance: Some(current_balance),
        receiver_wallet_seq: Some(wallet_seq),
        receiver_current_hibernation: Some(current_hibernation),
        receiver_current_wall_clock_lock: Some(current_wall_clock_lock),
        receiver_current_emission_claimed_epoch: Some(current_emission_claimed_epoch),
        receiver_current_stake_floor_until: Some(current_stake_floor_until),
        receiver_current_wallet_format: Some(current_wallet_format),
        receiver_new_balance: Some(cl5_new_balance),
        receiver_new_state_id: None,
        my_validator_pk: None,
        overlapped_signatures: vec![],
        group_member_index: None,
        sender_fact_chain: None,
        receiver_witness: None,
        receiver_signing_key: None,
        // §15-attestation: always None. See parameter-list comment above.
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
        wallet_secret: None,
        fanout_message: None,
        nabla_stake_proof: None,
        frozen_wallets: None,
        console_current_cert: None,
        console_new_cert: None,
        console_selector_picks: None,
        console_nominations: None,
        txid_attestation,
        cheque_claim_proof,
        oods_attestation,
        recall_attestation: None,
        fob_claim_attestation: None,
        claimant_vbc: None, // CL5 is redeem; RECALL is a CL2 self-send
        clara_attestation: None,
        phase_out_payload: None,
        phase_out_era_end_ticks: vec![],
        phase_out_blocked_era_ids: vec![],
        current_tick: 0,
    }
}
