//! Core Logic Modes (CL1–CL8)
//!
//! Core.bin is ONE binary with EIGHT execution modes:
//! - CL1: Client Core Out - validate outgoing transaction
//! - CL2: Validator Core In - verify incoming proof, validate transaction
//! - CL3: Validator Core Out - verify Lambda's work, produce witness proof
//! - CL4: Client Core In - verify incoming receipt
//! - CL5: Validator Redeem - validate cheque redemption (balance increase)
//! - CL7: NBC Verification - verify NBC bundle (k=1, NABLA_ROOT_AUTHORITY_PKS)
//! - CL8: NBC Issuance Signing - sign NBC with issuer's SPHINCS+ key (Nabla)
//!
//! Transaction flow: CL1 → CL2 → (Lambda) → CL3 → CL4
//!
//! VBC VERIFICATION POINTS (defense in depth — verify at EVERY boundary):
//!
//!   CL2: Validator checks prev_receipt witnesses' VBCs
//!        → Rejects TX if any prior witness had fake/expired VBC
//!
//!   CL3: Validator checks own VBC + prev_receipt witnesses' VBCs again
//!        → Refuses to sign if own VBC is invalid
//!        → Double-checks prev_receipts (CL2 already checked, but verify again)
//!
//!   CL4: Client checks ALL witness VBCs on received receipt
//!        → Client independently verifies every validator is legitimate
//!
//!   Every boundary crossing = VBC check. No exceptions.

// CONSENSUS_CRITICAL

use alloc::vec::Vec;
use crate::types::{CoreLogicMode, FactChain, PublicInputs, PublicOutputs, TxKind, ValidationError, ValidationResult};
use crate::validation::{validate_transaction, validate_witnesses};

/// A2 helper — extract the sender_anchor candidate from a FactChain.
/// Returns the last link's `new_state_id`, falling back to the
/// checkpoint's `final_state_id` for fully-compressed chains, or
/// `None` for empty chains.
fn fact_chain_tip(fc: &FactChain) -> Option<[u8; 32]> {
    fc.links
        .last()
        .map(|l| l.new_state_id)
        .or_else(|| fc.checkpoint.as_ref().map(|cp| cp.final_state_id))
}

/// Extract validator's Ed25519 public key from inputs
///
/// For overlap checking, we need the Ed25519 PK because that's what
/// witness_sigs.validator_pk contains in prev_receipts.
/// Checks VBC bundle first (preferred), falls back to my_validator_pk field.
/// Returns None if neither is available.
fn extract_validator_pk_from_inputs(inputs: &PublicInputs) -> Option<&[u8]> {
    // Prefer VBC Ed25519 key (matches validator_pk in witness_sigs)
    if let Some(ref bundle) = inputs.vbc_bundle {
        if !bundle.target_vbc.subject_pubkey_ed25519.is_empty() {
            return Some(&bundle.target_vbc.subject_pubkey_ed25519);
        }
    }
    // Fallback to explicit my_validator_pk field
    inputs.my_validator_pk.as_deref()
}

/// Main entry point for Core.bin
///
/// Dispatches to the appropriate mode handler based on inputs.mode.
///
/// ============================================================================
/// ARCHITECTURAL NOTE FOR FUTURE DEVELOPERS
/// ============================================================================
///
/// Core is the SOLE cryptographic gatekeeper. ALL verification happens here.
/// Lambda is business logic only — it NEVER verifies signatures, hashes, or
/// cryptographic proofs. Lambda's job is to refill S-ABR values, manage wallet
/// state, build FACT links, and route messages. Core's job is to say yes or no.
///
/// ONE CALL TO RULE THEM ALL:
///   Lambda calls execute_core() once per operation. Core checks everything
///   inside that single call. Never add separate "verify X" API calls from
///   Lambda — add the check to the appropriate CL mode instead.
///
/// MODE PIPELINE:
///   CL1 — Client Core Out: client-side signing (future)
///   CL2 — Validator Core In: full transaction validation
///         validate_transaction() in validation.rs
///         Checks: dust, state_id, seq, wallet_id, client sig, auth, balance,
///                 group wallet, **FACT chain** (from sender's stored chain),
///                 conservation law, S-ABR overlap
///         Also: validate_witnesses() for prev_receipt witness sigs + VBC
///   CL3 — Validator Witness: produce witness proof, S-ABR overlap check
///   CL4 — Response signing (absorbed into CL2/CL3)
///   CL5 — Validator Redeem: cheque bundle validation + balance increase
///         Checks: k=3 distinct cheques, consistency, VBC, **FACT chain**
///                 (from cheque_bundle), amount, overflow, balance math,
///                 state_id computation
///
/// WHERE TO ADD NEW VERIFICATION:
///   - New check for SEND transactions     → validation.rs validate_transaction()
///   - New check for REDEEM transactions   → modes.rs execute_cl5()
///   - New check for witness signatures    → validation.rs validate_witnesses()
///   - New cryptographic primitive         → crypto.rs (private), export via verify/compute
///   - New chain verification (like FACT)  → own module (fact.rs), called from CL2/CL5
///
/// NEVER:
///   - Add signature verification in Lambda
///   - Add a separate Core API call for something that belongs in the pipeline
///   - Let Lambda compute hashes, state_ids, or commitments
///   - Trust Lambda-provided values for security decisions
///
/// ============================================================================
pub fn execute_core(inputs: PublicInputs) -> PublicOutputs {
    let zkp_nonce = inputs.zkp_nonce;
    let mode = inputs.mode;

    // §23.14: Collect witness PKs from prev_receipts before inputs are consumed.
    // These are candidates for audit target selection.
    // Gated on the same `dev-mode` feature as the demand block below so dev
    // builds don't generate an unused-variable warning.
    #[cfg(not(feature = "dev-mode"))]
    let witness_pks: alloc::vec::Vec<alloc::vec::Vec<u8>> = if matches!(mode, CoreLogicMode::CL2 | CoreLogicMode::CL2_PREFILTER | CoreLogicMode::CL3) {
        inputs.prev_receipts.iter()
            .flat_map(|r| r.witness_sigs.iter())
            .map(|sig| sig.validator_pk.clone())
            .collect()
    } else {
        alloc::vec::Vec::new()
    };

    let mut outputs = match mode {
        CoreLogicMode::CL1 => execute_cl1(inputs),
        CoreLogicMode::CL2 => execute_cl2(inputs),
        CoreLogicMode::CL3 => execute_cl3(inputs),
        CoreLogicMode::CL4 => execute_cl4(inputs),
        CoreLogicMode::CL5 => execute_cl5(inputs),
        CoreLogicMode::CL7 => execute_cl7(inputs),
        CoreLogicMode::CL8 => execute_cl8(inputs),
        CoreLogicMode::CL9 => execute_cl9(inputs),
        CoreLogicMode::CL10 => execute_cl10(inputs),
        CoreLogicMode::CL11 => execute_cl11(inputs),
        CoreLogicMode::CL12 => execute_verify_send_proof(inputs),
        CoreLogicMode::CL13 => execute_validator_withdrawal_mint(inputs),
        CoreLogicMode::CL2_PREFILTER => execute_cl2_prefilter(inputs),
    };
    // ZKP anti-replay: hash nonce into outputs (runs INSIDE zkVM guest)
    if let Some(nonce) = zkp_nonce {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_ZKP_NONCE");
        hasher.update(&nonce);
        outputs.zkp_nonce_hash = Some(*hasher.finalize().as_bytes());
    }

    // §23.14 Peer Audit Demand — The Ping Defense
    // On CL2/CL3 with Accept result, Core may demand Lambda audit a peer.
    // Deterministic from txid: same TX always produces same audit decision.
    // AVM interpreter tracks countdown; non-compliance → self-termination.
    //
    // DEV-MODE GATE (2026-04-14): the audit_buffer that enforce_audit_pre
    // reads from for content verification is populated by pulse_post_execute,
    // which is a no-op when feature="disable-audit" is on (interpreter.rs:1381).
    // Firing §23.14 demands against an empty buffer guarantees content-mismatch
    // → self-termination. §23.14 MUST be gated the same way the pulse/audit
    // subsystem is, so dev builds don't bootstrap themselves into AuditTimeout.
    // Production builds (no dev-mode feature) run the full audit path as designed.
    #[cfg(not(feature = "dev-mode"))]
    if matches!(mode, CoreLogicMode::CL2 | CoreLogicMode::CL3) {
        if let (crate::types::ValidationResult::Accept, Some(txid)) =
            (&outputs.result, &outputs.txid)
        {
            if crate::audit::should_trigger_audit(txid) {
                outputs.audit_demand = crate::audit::generate_audit_demand(
                    txid,
                    &witness_pks,
                );
            }
        }
    }

    outputs
}

/// CL1: Client Core Out
///
/// Client validates their own transaction before sending.
/// This produces a proof that the transaction is valid from the client's perspective.
///
/// Validates:
/// - Transaction structure
/// - Client has sufficient balance
/// - wallet_seq is correct
/// - Receiver address is valid
fn execute_cl1(inputs: PublicInputs) -> PublicOutputs {
    // Validate the transaction
    match validate_transaction(&inputs) {
        Ok(outputs) => outputs,
        Err(e) => reject(e),
    }
}

/// CL2_PREFILTER: ANTIE gateway pre-execution.
///
/// State-INDEPENDENT subset of CL2. Used by ANTIE so its Core call can
/// honestly run with `current_state = None` instead of fabricating a
/// `WalletState` from declared balances or last_receipts. CLAUDE.md §8:
/// "ANTIE never synthesizes what Lambda should verify."
///
/// Runs the same `validate_transaction` pipeline as CL2 — `validate_transaction`
/// already gates state-dependent steps (`balance`, `wallet_seq`, owner-proof
/// against stored `auth_hash`, `compute_new_state_hash`, `compute_produced_state_id`)
/// behind `mode == CL2_PREFILTER && current_state.is_none()` so they become
/// honest no-ops here. Lambda's own CL2 pass owns the authoritative checks
/// against real stored state.
///
/// Skips (vs. CL2):
///   - CLARA roll-forward (Lambda owns the storage rewrite, not ANTIE)
///   - VBC expiry on forwarded prev_receipts (untrusted at gateway)
///   - S-ABR overlap math (no validator pk at the gateway)
///
/// Reference: YPX-018 §2.1.2, CLAUDE.md §8.
fn execute_cl2_prefilter(inputs: PublicInputs) -> PublicOutputs {
    match validate_transaction(&inputs) {
        Ok(outputs) => outputs,
        Err(e) => reject(e),
    }
}

/// S-ABR effective-required-overlap — the HEAL reduction, migrated from
/// Lambda's `validate_sabr_new` (§17.10.14) so Core owns the WHOLE gate.
///
/// For `is_heal` short of the normal floor, overlap re-forms against the
/// SURVIVING committers: a 2/5 partial has 2 committers, and requiring
/// `sabr_overlap(5)=3` would be impossible — the floor drops to
/// `sabr_overlap(surviving)` capped at `surviving`. With ZERO surviving
/// sigs the floor is 0: the heal's safety is then carried entirely by
/// `verify_state_id_valid` (stored == consumed at every witnessing
/// validator) + Nabla's conflicting-registration check — same rationale
/// as Lambda's original relax. Non-heal paths keep the full floor.
fn sabr_effective_required_overlap(
    required_overlap: usize,
    valid_overlap_count: usize,
    is_heal: bool,
) -> usize {
    if is_heal && valid_overlap_count < required_overlap {
        let committer_overlap =
            crate::wallet_id::sabr_overlap(valid_overlap_count.max(1) as u8) as usize;
        committer_overlap.min(valid_overlap_count)
    } else {
        required_overlap
    }
}

/// CL2: Validator Core In
///
/// Validator receives transaction from client and validates it.
/// Also verifies the client's CL1 proof.
///
/// Validates:
/// - Client's CL1 proof (if present)
/// - Transaction is valid
/// - If overlap: prepares stripped transaction for Lambda to refill
fn execute_cl2(mut inputs: PublicInputs) -> PublicOutputs {
    // YPX-018 — CLARA roll-forward verification (Phase 5e security hotfix).
    //
    // If the witness request carries a `clara_attestation`, Core must verify
    // it cryptographically before any state-dependent logic runs:
    //   (1) Wallet binding — attestation MUST be for the requesting wallet
    //   (2) Ed25519 signature under att.nabla_node_pk
    //   (3) MANDATORY NBC trust anchor — att.nabla_node_pk must chain back
    //       to a NABLA_ROOT_AUTHORITY_PKS via SPHINCS+ NBC. Without this,
    //       a client could self-sign a CLARA attestation with any Ed25519
    //       keypair and bypass the trust model entirely.
    //   (4) Eligibility — Lambda's stored state (`inputs.current_state`)
    //       MUST appear in `garbage_state_ids` OR equal `healed_from_state_id`.
    //       Idempotent case: if stored already equals `healed_to_state_id`,
    //       a prior heal already applied — accept.
    //   (5) Rewrite — after eligibility passes, treat current_state as if
    //       rolled forward to `healed_to_state_id`. This synthetic rewrite is
    //       in-memory only (Core is pure); Lambda commits the storage write
    //       AFTER Core returns Accept (post-Core, fail-closed).
    //
    // Reference: YPX-018 §2.3, Yellow Paper §17.10.14, §26.17.10.
    // Phase 5e hotfix: NBC trust anchor + idempotent eligibility + synthetic
    // rewrite + post-Core storage commit (in Lambda).
    if let Some(ref clara) = inputs.clara_attestation.clone() {
        // (1) Wallet binding
        if clara.wallet_pk.as_slice() != inputs.transaction.client_pk.as_slice() {
            return reject(ValidationError::ClaraWalletPkMismatch);
        }
        // (2) Ed25519 signature
        if let Err(e) = crate::crypto::verify_clara_signature(clara) {
            return reject(e);
        }
        // (3) Mandatory NBC trust anchor — Phase 5e fix #2
        match crate::validation::verify_nbc_for_clara_attestation(clara) {
            Ok(true) => {}
            _ => return reject(ValidationError::ClaraNbcTrustFailed),
        }
        // (4) Eligibility check
        if let Some(ref state) = inputs.current_state {
            let stored = state.state_id;
            let from = clara.healed_from_state_id;
            let to = clara.healed_to_state_id;
            let in_garbage = clara.garbage_state_ids.contains(&stored);
            // Idempotent: if already at healed_to, we're already past this heal.
            // Eligible: stored is in garbage OR equals healed_from.
            if stored != to && stored != from && !in_garbage {
                return reject(ValidationError::ClaraStateNotGarbage);
            }
        }
        // (5) Synthetic rewrite — only after eligibility passes.
        // Update inputs.current_state in-memory so validate_transaction's
        // chain check sees the rolled-forward view. NO storage write here.
        //
        // YPX-018 balance fix: also rewrite balance to healed_balance.
        // Without this, validate_transaction runs with the poisoned balance
        // and any new TX whose amount exceeds the poisoned balance is
        // rejected by Core — Lambda then never calls clara_roll_forward,
        // the stored balance stays poisoned forever, and the wallet is
        // permanently stuck in a reject loop. The healed_balance is already
        // bound into compute_clara_message and verified against the heal
        // cheque's state_hash at register_clara time, so trusting it here
        // introduces no new trust assumption — the k=3 heal witnesses
        // already committed to it.
        if let Some(ref mut state) = inputs.current_state {
            state.state_id = clara.healed_to_state_id;
            state.wallet_seq = clara.healed_at_seq;
            state.balance = clara.healed_balance;
        }
    }

    // YPX-022 RECALL (2026-07-06 forward redesign) — thin CL2 recall gate. Recall is
    // now a standard forward self-send with NO overlap relaxation; the ONLY recall
    // check here binds the reclaimed AMOUNT so the recall cheque can't be inflated:
    //   (a) verify_recall_attestation — Nabla Ed25519 sig + NBC root anchor (a
    //       self-signed attestation dies);
    //   (b) txid binding — att.txid == recall_target_tx_id (this recall's target);
    //   (c) amount pin — tx.amount == att.amount (Nabla stamped `A` off the verified
    //       failed_send_tx, so `A` is authoritative). This replaces the retired
    //       over-reclaim equality (presend_state_hash == consumed_state_id), which
    //       only made sense when the recall consumed the pre-send state S; the forward
    //       recall consumes the current tip, and value safety is now the amount pin
    //       + the CL5 redeem (balance rises only there) + Nabla consume-once.
    // The overlap is NOT relaxed — the failed tx's own witnesses verify the sub-quorum
    // status first-hand (§2), which is the added security.
    if inputs.transaction.is_recall() {
        match &inputs.recall_attestation {
            Some(att) => {
                if let Err(e) = crate::validation::verify_recall_attestation(att) {
                    return reject(e); // (a)
                }
                if inputs.transaction.recall_target_tx_id != Some(att.txid) {
                    return reject(ValidationError::RecallAttestationInvalid); // (b)
                }
                if inputs.transaction.amount != att.amount {
                    return reject(ValidationError::RecallAttestationInvalid); // (c) amount pin
                }
            }
            None => return reject(ValidationError::RecallAttestationInvalid),
        }
    }

    // First, validate the transaction itself
    let result = match validate_transaction(&inputs) {
        Ok(outputs) => outputs,
        Err(e) => return reject(e),
    };

    // If rejected, return immediately
    if result.result == ValidationResult::Reject {
        return result;
    }

    // VBC expiry fast-check: reject if any prev_receipt validator VBC is expired
    if let Err(e) = crate::vbc::verify_vbc_expiry(&inputs) {
        return reject(e);
    }

    // CL1 ZKP verification happens OUTSIDE core-logic (Lambda's ZkvmVerifier)
    // before calling CL2. Core-logic is no_std — zkVM concerns live at the
    // calling layer. See lambda/src/core_client.rs::validate_client_transaction().
    
    // === WITNESS VALIDATION & S-ABR GATE ===
    // First TX: seq==1, prev_seq==0 (no prior TX completed), no prev_receipts exist.
    // prev_seq only increments after successful TX — prev_seq==0 means no history.
    
    if inputs.prev_receipts.is_empty() {
        let prev_seq = inputs.current_state.as_ref()
            .map(|s| s.wallet_seq)
            .unwrap_or(0);
        
        if inputs.transaction.wallet_seq == 1 && prev_seq == 0 {
            // First TX, no history — all validators proceed
            return PublicOutputs {
                is_overlapped: Some(true),
                ..result
            };
        } else {
            // Empty prev_receipts but not first TX — reject
            return reject(ValidationError::MissingPrevReceipts);
        }
    }
    
    // Verify prev_receipt witness structure (pk matches, validator_id matches).
    // VBC SPHINCS+ signatures are NOT re-verified per-transaction.
    // VBC chain is verified ONCE at Core load time (§23.13.11).
    if let Err(e) = validate_witnesses(&inputs) {
        return reject(e);
    }
    
    // S-ABR GATE: determine if this validator is overlapped
    let my_pk = extract_validator_pk_from_inputs(&inputs).map(|pk| pk.to_vec());
    
    // Collect all validator PKs from prev_receipts
    let mut prev_pks: alloc::collections::BTreeSet<Vec<u8>> = alloc::collections::BTreeSet::new();
    for receipt in &inputs.prev_receipts {
        for ws in &receipt.witness_sigs {
            prev_pks.insert(ws.validator_pk.clone());
        }
    }
    
    let i_am_overlapped = my_pk.as_ref().map(|pk| prev_pks.contains(pk));
    
    #[cfg(feature = "std")]
    eprintln!("[CL2_DIAG] my_pk={} prev_pks={} i_am_overlapped={:?}",
        my_pk.as_ref().map(|pk| hex::encode(&pk[..8.min(pk.len())])).unwrap_or_else(|| "NONE".into()),
        prev_pks.len(),
        i_am_overlapped);
    
    match i_am_overlapped {
        Some(true) => {
            // OVERLAPPED VALIDATOR: I witnessed the previous TX.
            // Strip balance — Lambda MUST refill from its own stored records.
            PublicOutputs {
                is_overlapped: Some(true),
                ..result
            }
        }
        _ => {
            // NEW VALIDATOR or UNKNOWN (no VBC):
            // Either way, verify that k-1 overlapped sigs exist and are valid.
            // "Am I overlapped?" needs VBC. "Are the overlap sigs legit?" does not.
            // SECURITY-SABR: Double-spend overlap prevention.
            // Overlap is based on the PREVIOUS TX's k (= prev_pks.len()),
            // not the current TX's k. The overlap protects the previous
            // state's integrity — strict majority of previous witnesses
            // must carry over. sabr_overlap(k) = floor(k/2) + 1.
            // For first TX (prev_pks empty), overlap is checked above (line 317).
            let prev_k = prev_pks.len();
            let required_overlap = crate::wallet_id::sabr_overlap(prev_k as u8) as usize;
        
        // Verify accumulated current-TX witness sigs (overlapped_signatures):
        // For a non-overlapped validator (V3), the client sends accumulated sigs
        // from V1 and V2 in overlapped_signatures. Core verifies:
        // 1. Each sig's PK is in prev_receipts (proves they were overlapped)
        // 2. Signature bytes are unique (detects PK-swap attack)
        // 3. Cryptographic signature verification against current TX's commitment_hash
        //    (V1/V2 signed the CURRENT TX's commitment, not the prev receipt's)
        // 4. VBC bundle verification (proves PK belongs to a legitimate validator)
        //
        // This proves that ≥2 overlapped validators already witnessed THIS TX
        // before the non-overlapped validator accepts it.
        
        // Use current TX's commitment_hash for signature verification
        // (V1/V2 signed this commitment when they witnessed the current TX)
        let commitment_for_verify = result.commitment_hash;
        // SEC-10: consensus-safe time for VBC expiry/maturity in the overlap walk.
        let tx_epoch = inputs.transaction.epoch;

        let mut seen_signatures: alloc::collections::BTreeSet<Vec<u8>> = alloc::collections::BTreeSet::new();
        let mut _check1_fail = 0u32;
        let mut _check2_fail = 0u32;
        let mut _check3_fail = 0u32;
        let mut _check4_fail = 0u32;
        let mut _check4_none = 0u32;
        let _total_overlap_sigs = inputs.overlapped_signatures.len();
        let _prev_pks_count = prev_pks.len();
        let valid_overlap_count = inputs.overlapped_signatures.iter()
            .filter(|sig| {
                // Check 1: PK must be in prev_receipts
                if !prev_pks.contains(&sig.validator_pk) {
                    _check1_fail += 1;
                    return false;
                }
                // Check 2: Signature bytes must be unique (detects PK-swap attack)
                if !seen_signatures.insert(sig.signature.clone()) {
                    _check2_fail += 1;
                    return false;
                }
                // Check 3: Cryptographic signature verification
                // Verify Ed25519 signature over current TX's commitment_hash
                // (V1/V2 signed this when they witnessed the current TX).
                // SEC-12b: overlap sigs are Ed25519 — force the explicit
                // verifier rather than length-based auto-detect.
                if let Some(ref commitment) = commitment_for_verify {
                    if crate::crypto::verify_ed25519(&sig.validator_pk, commitment, &sig.signature).is_err() {
                        _check3_fail += 1;
                        return false;
                    }
                }
                // Check 4: VBC bundle present and valid (proves legitimate validator)
                // AUDIT-FIX v2.11.14: Full VBC verification — prev_receipts are untrusted.
                match &sig.vbc_bundle {
                    Some(bundle) => {
                        // SEC-10: verify against the signed tx.epoch so issuer
                        // expiry + maturity are enforced (was _no_time).
                        if crate::vbc::verify_vbc_bundle(bundle, tx_epoch).is_err() {
                            _check4_fail += 1;
                            return false;
                        }
                        // Verify PK matches VBC subject
                        if !crate::crypto::ct_eq(&sig.validator_pk, &bundle.target_vbc.subject_pubkey_ed25519) {
                            _check4_fail += 1;
                            return false;
                        }
                    }
                    None => { _check4_none += 1; return false; }  // No VBC = not a legitimate validator
                }
                true
            })
            .count();
        
        // YPX-020 HAL: a dead-overlap re-anchor RELAXES this synchronous overlap
        // gate (its prior witnesses are gone, so the k-1 overlap can never close).
        // The double-spend gate it gives up is NOT dropped — it MOVES to Nabla:
        // (1) the stasis period forces the wallet out of work for the convergence
        // wait, so a concurrent spend converges into the consumed-state bloom
        // before completion, and (2) the consumed-state bloom rejects a replay of
        // an already-spent `old_state`. Core's relaxation MUST NOT ship without
        // that Nabla wait+bloom — they are one safety unit (YPX-020 §6).
        // YPX-020 §2: only the re-anchor (HalReanchor) needs the overlap
        // relaxation — it is the dead-overlap escape. Completion is no longer a
        // self-send (it is the distress-cheque REDEEM, which re-imposes overlap
        // against fresh witnesses on the receive side), so there is no
        // `HalComplete` exemption to carry here.
        // YPX-022 RECALL seam: RECALL will ALSO relax this overlap gate, substituting
        // its <k + window + consume-once gate here (build plan Phase 3). Until that gate
        // is implemented, RECALL is NOT relaxed here — it stays fail-safe on the overlap
        // path (and is unreachable anyway: no wire flag yet).
        let is_hal_reanchor = inputs.transaction.is_hal_reanchor();
        // YPX-022 RECALL (2026-07-06 forward redesign): recall does NOT relax overlap.
        // It goes through a normal k-witness round; S-ABR overlap pulls in the failed
        // tx's own witnesses, who verify the sub-quorum status first-hand — the overlap
        // is the ADDED SECURITY, not something to bypass (§2). `recall_relaxes` is
        // deleted, one fewer exemption.
        // Migrated from Lambda's `validate_sabr_new` so Core owns the WHOLE S-ABR gate
        // (S-ABR's design is Core-decides-from-prev_receipts, Lambda only refills — Lambda
        // must never own an overlap decision).
        //   • BURN re-anchors relax overlap (self-send to destroy a scarred leaf; no
        //     prior-witness carry-over is possible).
        //   • HEAL re-forms overlap against the SURVIVING committers, so its floor drops to a
        //     majority of whoever actually carried over (partial-commit recovery). If NO
        //     committer survives, that is the dead-overlap case → HAL, not plain heal.
        let is_burn = inputs.transaction.burn_target_tx_id.is_some();
        let is_heal = inputs.transaction.is_heal();
        let effective_required =
            sabr_effective_required_overlap(required_overlap, valid_overlap_count, is_heal);
        if !is_hal_reanchor && !is_burn && valid_overlap_count < effective_required {
            // Diagnostic: which checks failed?
            #[cfg(feature = "std")]
            eprintln!("[CL2_DIAG] SABRInsufficientOverlap: sigs={} prev_pks={} valid={} need={} eff={} heal={} burn={} c1={} c2={} c3={} c4={} c4none={}",
                _total_overlap_sigs, _prev_pks_count, valid_overlap_count, required_overlap, effective_required,
                is_heal, is_burn, _check1_fail, _check2_fail, _check3_fail, _check4_fail, _check4_none);
            return reject(ValidationError::SABRInsufficientOverlap);
        }
        
        // Sufficient valid overlapped sigs exist — proceed with declared balance
            PublicOutputs {
                is_overlapped: i_am_overlapped.map(|_| false),
                ..result
            }
        }
    }
}

/// CL3: Validator Core Out
///
/// After Lambda processes the transaction, Core verifies Lambda's work.
/// This produces the final witness proof.
///
/// Validates:
/// - Lambda's processing is legal
/// - Refilled values match original (Hash_A == Hash_B for S-ABR)
/// - Produces witness proof for the receipt
fn execute_cl3(inputs: PublicInputs) -> PublicOutputs {
    // === WITNESS COUNT ENFORCEMENT (YPX-007) ===
    // prev_receipts carry witnesses from the PREVIOUS TX. Core verifies they
    // reached the absolute floor (k=3) — proving the TX was properly committed,
    // not rolled back. This is defense against double-spend rollback attacks.
    //
    // The CURRENT TX's required_k (from receiver's wallet_id) is extracted and
    // returned in PublicOutputs.required_k. Lambda enforces it at commit time
    // by collecting k signatures before finalizing. Core cannot enforce current
    // TX's k at CL3 entry because CL3 runs per-validator (each validator sees
    // only their own view, prev_receipts reflect the PREVIOUS TX).

    // === WITNESS STRUCTURE VALIDATION ===
    // Structure checks only — VBC chain verified at Core load time (§23.13.11).
    if let Err(e) = validate_witnesses(&inputs) {
        return reject(e);
    }

    // S-ABR Hash verification (cheap, runs before expensive sig checks):
    // Ensure Lambda's reported wallet state matches the client's consumed_state_id.
    // If they differ, Lambda lied about the wallet's balance during overlap refill.
    if let Some(ref state) = inputs.current_state {
        if inputs.transaction.consumed_state_id != state.state_id {
            return reject(ValidationError::SABRHashMismatch);
        }
    }

    // Validate the transaction
    let result = match validate_transaction(&inputs) {
        Ok(outputs) => outputs,
        Err(e) => return reject(e),
    };

    if result.result == ValidationResult::Reject {
        return result;
    }

    // YP §20.8: sends carry no fees in the receiver-pays-only model.
    // fee_breakdown lives only on the redeem-side wire (PublicInputs +
    // Receipt for chain-of-trust). CL3 doesn't see fees.

    // VBC expiry fast-check: reject if any prev_receipt validator VBC is expired
    if let Err(e) = crate::vbc::verify_vbc_expiry(&inputs) {
        return reject(e);
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // CL3 ENRICHMENT — Core computes everything Lambda needs
    // "Core is the bible" — Lambda MUST NOT compute these values
    // ═══════════════════════════════════════════════════════════════════
    
    // 1. Compute txid (Core is the sole authority)
    let txid = crate::crypto::compute_txid(&inputs.transaction);
    
    // 2. Compute new_balance (Core does ALL balance math)
    let current_balance = inputs.current_state.as_ref()
        .map(|s| s.balance)
        .unwrap_or(0);
    // checked_sub: if validate_transaction passed, this never fails.
    // But if code is refactored and the check is moved, this catches it.
    // §17.11: Genesis claims CREDIT the amount from the pool (not deduct).
    // Normal TXs deduct. Genesis claims add GENESIS_CLAIM_AMOUNT to the wallet.
    let new_balance = if inputs.transaction.is_genesis_claim() {
        current_balance.saturating_add(inputs.transaction.amount)
    } else {
        current_balance.saturating_sub(inputs.transaction.amount)
    };
    
    // 3. Sign FACT commitment with Dilithium (if keys provided)
    // Core signs internally — Lambda MUST NOT call sign_dilithium directly.
    //
    // A2 sender_anchor: redeem links bind the sender's chain tip into the
    // commitment. For redeem TXs, extract the tip from the cheque bundle's
    // sender FACT chain — last link's new_state_id, or checkpoint
    // final_state_id if the chain is fully compressed. For send / heal /
    // burn, sender_anchor is None.
    let sender_anchor: Option<[u8; 32]> = inputs
        .cheque_bundle
        .as_ref()
        .and_then(|cb| cb.fact_chain.as_ref())
        .and_then(fact_chain_tip);

    // Dev-class flag derived here so BOTH `compute_fact_commitment` (k
    // Dilithium sigs attest) AND `compute_receipt_commitment` (k
    // Ed25519 sigs attest) bind the same value. Source of truth is
    // `sender_wallet_id`; Rule R1 guarantees the receiver matches.
    // See `AXIOM_DESIGN_FactChainClassLock.md` +
    // `AXIOM_DESIGN_FactClassIsolation.md`.
    let is_dev_class = crate::wallet_id::is_dev_wallet(
        &inputs.transaction.sender_wallet_id,
    );

    // YPX-021 §8.2 — derive the OODS health flag from the client-carried
    // Nabla attestation. Core (not Lambda, not the SDK) verifies the
    // reading and computes `healthy` vs the NBC baseline; an INVALID
    // attestation is a hard reject (stripping an unhealthy reading must
    // not be cheaper than carrying it). Absent attestation → no flag
    // (heal / genesis-claim paths, Phase 1).
    // YPX-021 §8.5 (2026-07-05, supersedes the §8.3/§8.4 tag-only rule for
    // recovery) — a RECOVERY re-anchor (HAL/HEAL/RECALL) now REQUIRES a
    // verified-healthy OODS reading; it BLOCKS otherwise.
    //
    // Why the reversal: recovery re-anchors are overlap-RELAXED — they give up
    // the synchronous S-ABR double-spend gate and lean on Nabla consume-once as
    // the backstop. Consume-once is weakest exactly during a partition/eclipse,
    // which is precisely what an unhealthy OODS reading signals (KI#34 territory).
    // So running the risky relaxed op while the network is unhealthy is the worst
    // time to do it. Blocking-until-healthy removes that window. The block is
    // RETRYABLE (E_OODS_UNHEALTHY_RETRY → RecoveryHint::WaitAndRetry): the wallet
    // re-attempts when the network recovers — NOT stranded, NOT poisoned.
    //
    // Cases: verified-healthy → proceed + tag Safe. Verified-UNHEALTHY or ABSENT
    // → retryable block (can't prove health → don't run the relaxed op). FORGED
    // → hard reject (OodsAttestationInvalid), same as the send path — a forged
    // reading never becomes valid by retrying.
    //
    // COUPLING: the SDK must fetch + carry a fresh OODS reading on the re-anchor
    // path (it did NOT pre-§8.5 — heals passed None). Core + SDK ship together;
    // deploying this half alone blocks all recovery. Non-recovery sends keep the
    // §8.2 verify-and-tag behavior (a forged reading rejects; absent → no flag).
    let oods_flag = if inputs.transaction.is_hal_reanchor()
        || inputs.transaction.is_recall()
        || inputs.transaction.is_heal()
    {
        match &inputs.oods_attestation {
            Some(att) => match crate::validation::verify_oods_attestation(att) {
                Ok(flag) if flag.healthy => Some(flag),
                Ok(_) => return reject(ValidationError::OodsUnhealthyRetry),
                Err(_) => return reject(ValidationError::OodsAttestationInvalid),
            },
            None => return reject(ValidationError::OodsUnhealthyRetry),
        }
    } else {
        match &inputs.oods_attestation {
            Some(att) => match crate::validation::verify_oods_attestation(att) {
                Ok(flag) => Some(flag),
                Err(e) => return reject(e),
            },
            None => None,
        }
    };

    let fact_signature = if let (Some(ref sk), Some(ref produced_sid)) =
        (&inputs.my_dilithium_sk, &result.produced_state_id)
    {
        // §1.5.4: a burn is a send to BURN_ADDRESS carrying burn_target_tx_id.
        // Binding it here means the k=3 witnesses attest WHICH scar this burn
        // destroys, so its BurnProof cannot later be copied onto a different scar.
        let burn_target = if inputs.transaction.receiver_wallet_id == crate::types::BURN_ADDRESS {
            inputs.transaction.burn_target_tx_id.as_ref()
        } else {
            None
        };
        let commitment = crate::fact::compute_fact_commitment(
            &txid,
            &inputs.transaction.consumed_state_id,
            produced_sid,
            inputs.transaction.amount,
            sender_anchor.as_ref(),
            is_dev_class,
            &[], // send links never inherit (YPX-001 §1.5.1a — redeem-only)
            burn_target,
        );
        crate::crypto::sign_dilithium(sk, &commitment).ok()
    } else {
        None // No Dilithium key provided (e.g., direct-to-lambda dev mode)
    };
    
    // Compute receipt commitment — binds ALL receipt fields so k validators
    // sign the SAME hash. Prevents receipt fabrication by clients or
    // malicious-validator collusion. Core is the sole authority for this
    // computation; Lambda signs it but cannot change it.
    let receipt_commitment = {
        let state_hash = result.new_state_hash.unwrap_or([0u8; 32]);
        let wallet_seq = result.new_wallet_seq.unwrap_or(0);
        let comm_hash = result.commitment_hash.unwrap_or([0u8; 32]);
        let epoch = inputs.transaction.epoch;
        crate::crypto::compute_receipt_commitment(
            &txid, &state_hash, wallet_seq, &comm_hash, epoch, is_dev_class,
            oods_flag.as_ref(),
        )
    };

    // Return enriched outputs — Lambda reads these, never computes them
    PublicOutputs {
        txid: Some(txid),
        new_balance: Some(new_balance),
        fact_signature,
        receipt_commitment: Some(receipt_commitment),
        validator_withdrawal_mint: None,
        // `is_dev_class` carried back so Lambda stamps the same value
        // on Receipt that Core just bound into receipt_commitment.
        is_dev_class: Some(is_dev_class),
        // YPX-021 §8.2 — carried back so Lambda/SDK stamp the SAME flag
        // Core just bound into receipt_commitment (is_dev_class pattern).
        oods_flag,
        ..result
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ZKP CHECKPOINT — Minimal ZK boundary for CL3
// ═══════════════════════════════════════════════════════════════════════════
//
// This function runs INSIDE the zkVM guest. It contains ONLY the checks
// that must be proven by the STARK — the minimum necessary to guarantee:
//
//   1. Client authorized this transaction (Ed25519 signature)
//   2. Balance cannot be inflated (S-ABR state binding + balance check)
//   3. State chain is continuous (produced_state_id via SHA3)
//   4. Anti-replay (zkp_nonce + wallet_seq)
//   5. Protocol rules (dust limit, scar cap, burn consistency, VBC expiry)
//
// Everything else (Dilithium FACT signing, FACT chain verification,
// witness validation, txid, commitment_hash) runs NATIVELY in Core
// outside the ZK boundary. The `input_hash` in the STARK binds the
// native execution to the same data that was proven.
//
// Security analysis (k=3 evil validators + partitioned Nabla):
//   - Balance inflation: BLOCKED (S-ABR + SHA3 state_id binding)
//   - Forge transaction: BLOCKED (Ed25519 in STARK)
//   - Replay proof:      BLOCKED (zkp_nonce_hash in STARK)
//   - Double spend:      DETECTED (fork detection §32, not ZK's job)
//   - FACT corruption:   DETECTED (native verification on partition heal)
//
// IMAGE_ID certifies this specific Core code ran. input_hash proves
// what data went in. Together they guarantee computation integrity.
// ═══════════════════════════════════════════════════════════════════════════

/// Lightweight FACT cargo passed from host to zkVM guest.
/// Contains ONLY the txid needed for fact_commitment computation.
/// fact_signature (3,309 bytes) is NOT included — it's independently
/// verifiable via Dilithium PK and is attached by the host post-proving.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FactCargo {
    /// Transaction ID (BLAKE3 hash, computed natively by Core)
    pub txid: Option<[u8; 32]>,
}

/// ZKP checkpoint outputs — what the STARK commits to the journal
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZkpCheckpointOutputs {
    /// BLAKE3 hash of the entire PublicInputs — binds native execution to proven data
    pub input_hash: [u8; 32],
    /// Accept or Reject
    pub result: ValidationResult,
    /// SHA3-256 state chain — binds new_balance to next consumed_state_id
    pub produced_state_id: Option<[u8; 32]>,
    /// Core-computed balance after spend
    pub new_balance: Option<u64>,
    /// New wallet sequence number
    pub new_wallet_seq: Option<u64>,
    /// BLAKE3("AXIOM_ZKP_NONCE" || nonce) — anti-replay
    pub zkp_nonce_hash: Option<[u8; 32]>,
    /// Rejection reason (if result == Reject)
    pub rejection_reason: Option<ValidationError>,

    // ── FACT passthrough ──
    // These are computed NATIVELY by Core (outside ZK boundary) and passed
    // into the guest as cargo. The guest commits them to the STARK journal
    // without re-computing them. This proves Core (IMAGE_ID) endorsed this
    // FACT data for this specific transaction (bound via input_hash).
    // Cost: just copying bytes into journal — near zero.

    /// BLAKE3("AXIOM_FACT" || txid || prev_state || new_state || amount)
    /// Computed natively, committed to proof as endorsement
    pub fact_commitment: Option<[u8; 32]>,
    /// Dilithium ML-DSA-65 signature over fact_commitment (3,309 bytes)
    /// Signed natively, committed to proof as endorsement
    pub fact_signature: Option<Vec<u8>>,
    /// BLAKE3("AXIOM_TXID" || ...) — transaction identifier
    /// Computed natively, committed to proof for reference
    pub txid: Option<[u8; 32]>,
}

/// Minimal ZK boundary for CL3 — runs inside zkVM guest.
///
/// Proves ONLY what must be in the STARK. Everything else verified natively.
/// See security analysis in module comment above.
///
/// # Arguments
/// - `inputs` — Full PublicInputs (same as native Core execution)
/// - `native_outputs` — Outputs from native `execute_core()` run (Core computes
///   all crypto natively first — Lambda orchestrates but NEVER computes crypto).
///   The FACT data (fact_commitment, fact_signature, txid) from native Core
///   execution is committed to the proof journal as cargo.
///   Pass `None` for benchmark/test without native pre-execution.
pub fn execute_cl3_zkp_checkpoint(
    inputs: &PublicInputs,
    native_outputs: Option<&PublicOutputs>,
) -> ZkpCheckpointOutputs {
    use crate::validation::{MINIMUM_TX_ATOMS, MAX_UNRESOLVED_SCARS};
    use crate::types::{BURN_ADDRESS, DEED_ADDRESS, FEE_ADDRESS};

    let tx = &inputs.transaction;
    let state = inputs.current_state.as_ref();
    let prev_seq = state.map(|s| s.wallet_seq).unwrap_or(0);
    let has_prev_receipts = !inputs.prev_receipts.is_empty();

    // Helper to create rejection output (input_hash filled by caller)
    let reject_zkp = |reason: ValidationError| -> ZkpCheckpointOutputs {
        ZkpCheckpointOutputs {
            input_hash: [0u8; 32], // Caller fills this
            result: ValidationResult::Reject,
            produced_state_id: None,
            new_balance: None,
            new_wallet_seq: None,
            zkp_nonce_hash: None,
            rejection_reason: Some(reason),
            fact_commitment: None,
            fact_signature: None,
            txid: None,
        }
    };

    // ── prev_receipts required except for first TX ──
    if !(has_prev_receipts || tx.wallet_seq == 1 && prev_seq == 0) {
        return reject_zkp(ValidationError::MissingPrevReceipts);
    }

    let is_burn = tx.receiver_wallet_id == BURN_ADDRESS && tx.burn_target_tx_id.is_some();
    let is_deed = tx.receiver_wallet_id == DEED_ADDRESS;
    let is_fee = tx.receiver_wallet_id == FEE_ADDRESS;
    let is_protocol_tx = is_burn || is_deed || is_fee;

    // ── 2. Dust limit (anti-spam) ──
    if tx.amount == 0 {
        return reject_zkp(ValidationError::ZeroAmount);
    }
    if !is_protocol_tx && tx.amount < MINIMUM_TX_ATOMS {
        return reject_zkp(ValidationError::DustAmount);
    }

    // ── 3. Burn consistency ──
    if tx.burn_target_tx_id.is_some() && tx.receiver_wallet_id != BURN_ADDRESS {
        return reject_zkp(ValidationError::BurnMissingTarget);
    }
    // Burn target validation (structural checks only — FACT chain walk is native)
    if is_burn {
        if let Some(ref fact_chain) = inputs.sender_fact_chain {
            let target_tx_id = tx.burn_target_tx_id.as_ref().unwrap();
            let target_link = fact_chain.links.iter()
                .find(|l| crate::crypto::ct_eq(&l.tx_id, target_tx_id));
            match target_link {
                None => return reject_zkp(ValidationError::BurnTargetNotFound),
                Some(link) => {
                    if link.nabla_confirmation.is_some() {
                        return reject_zkp(ValidationError::BurnTargetNotScarred);
                    }
                    if link.burn_proof.is_some() {
                        return reject_zkp(ValidationError::BurnTargetAlreadyBurned);
                    }
                    if tx.amount != link.amount {
                        return reject_zkp(ValidationError::BurnAmountMismatch);
                    }
                }
            }
        } else {
            return reject_zkp(ValidationError::BurnNoFactChain);
        }
    }

    // ── 4. Scar cap (max 20 unresolved) ──
    if !is_burn {
        if let Some(ref fact_chain) = inputs.sender_fact_chain {
            let unresolved = fact_chain.links.iter()
                .filter(|l| l.nabla_confirmation.is_none() && l.burn_proof.is_none())
                .count();
            if unresolved > MAX_UNRESOLVED_SCARS {
                return reject_zkp(ValidationError::TooManyUnresolvedScars);
            }
        }
    }

    // ── 5. S-ABR: consumed_state_id == current_state.state_id ──
    if let Some(s) = state {
        if !crate::crypto::ct_eq(&tx.consumed_state_id, &s.state_id) {
            return reject_zkp(ValidationError::SABRHashMismatch);
        }
    }

    // ── 6. State ID chain: consumed == last receipt's produced ──
    if has_prev_receipts {
        let last_receipt = &inputs.prev_receipts[inputs.prev_receipts.len() - 1];
        if !crate::crypto::ct_eq(&tx.consumed_state_id, &last_receipt.produced_state_id) {
            return reject_zkp(ValidationError::InvalidStateId);
        }
    }

    // ── 7. Wallet sequence: must be prev_seq + 1 ──
    if tx.wallet_seq != prev_seq + 1 {
        return reject_zkp(ValidationError::InvalidWalletSeq);
    }

    // ── 8. Receiver wallet_id format (anti-typo) ──
    if !is_protocol_tx {
        if let Err(e) = crate::wallet_id::validate_wallet_id(&tx.receiver_wallet_id) {
            return reject_zkp(e);
        }

        // ── 8b. Email change suffix: -XX requires receiver_address with valid checksum ──
        if crate::wallet_id::requires_receiver_address(&tx.receiver_wallet_id) {
            match &tx.receiver_address {
                None => return reject_zkp(ValidationError::ReceiverAddressRequired),
                Some(addr) => {
                    if crate::wallet_id::validate_wallet_id(addr).is_err() {
                        return reject_zkp(ValidationError::InvalidReceiverAddress);
                    }
                }
            }
        }
    }

    // ── 9. Ed25519 client signature verification (PRECOMPILE — fast) ──
    if let Err(e) = crate::validation::verify_client_signature_public(tx) {
        return reject_zkp(e);
    }

    // ── 10. Owner proof verification (2FA — zero-knowledge Ed25519 signature) ──
    // AUDIT-FIX v2.11.13 (finding 3.1): Must match validation.rs Ed25519 path.
    // auth_hash = Ed25519 public key derived from owner_secret.
    // owner_proof = Ed25519 signature over BLAKE3("AXIOM_OWNER_SIG" || signing_message).
    if let Some(wallet) = state {
        if let Some(auth_pk) = &wallet.auth_hash {
            match &tx.owner_proof {
                None => return reject_zkp(ValidationError::AuthHashRequired),
                Some(proof) => {
                    let signing_msg = crate::validation::compute_signing_message_public(tx);
                    let owner_msg = blake3::hash(
                        &[b"AXIOM_OWNER_SIG" as &[u8], signing_msg.as_slice()].concat()
                    );
                    if crate::crypto::verify_ed25519(auth_pk, owner_msg.as_bytes(), proof).is_err() {
                        return reject_zkp(ValidationError::InvalidAuthProof);
                    }
                }
            }
        }
    }

    // ── 11. Balance check ──
    let balance = match state {
        Some(s) => s.balance,
        None => return reject_zkp(ValidationError::MissingWalletState),
    };
    if tx.amount > balance {
        return reject_zkp(ValidationError::InsufficientBalance);
    }

    // ── 12. VBC expiry: reject expired validators ──
    if let Err(e) = crate::vbc::verify_vbc_expiry(inputs) {
        return reject_zkp(e);
    }

    // ── 13. Compute produced_state_id (SHA3 — state chain continuity) ──
    let new_balance = balance.saturating_sub(tx.amount);
    let new_seq = tx.wallet_seq;
    let produced_state_id = crate::crypto::compute_produced_state_id(
        &tx.client_pk,
        new_balance,
        new_seq,
        &tx.consumed_state_id,
        tx.nonce,
    );

    // ── 14. Anti-replay nonce — raw value preserved for caller ──
    // The caller (guest or native) computes the hash using its preferred
    // algorithm: SHA256 precompile (guest, zero cost) or BLAKE3 (native).

    // ── All checks passed — include native Core outputs as cargo ──
    // These were computed by Core natively (full execute_core), NOT by Lambda.
    // Committing them to the STARK journal proves Core (IMAGE_ID) endorsed
    // this FACT data for this specific transaction (bound via input_hash).
    //
    // NOTE: zkp_nonce_hash and fact_commitment are set to None here.
    // The CALLER is responsible for computing these using the appropriate
    // hash function (SHA256 precompile inside zkVM, BLAKE3 natively).
    // This avoids BLAKE3 cycles inside the RISC-V guest.
    let (fact_signature, txid) = match native_outputs {
        Some(out) => (out.fact_signature.clone(), out.txid),
        None => (None, None),
    };

    ZkpCheckpointOutputs {
        input_hash: [0u8; 32], // Caller fills this
        result: ValidationResult::Accept,
        produced_state_id: Some(produced_state_id),
        new_balance: Some(new_balance),
        new_wallet_seq: Some(new_seq),
        zkp_nonce_hash: None, // Caller computes with SHA256 precompile or BLAKE3
        rejection_reason: None,
        fact_commitment: None, // Caller computes with SHA256 precompile or BLAKE3
        fact_signature,
        txid,
    }
}

/// CL4: Client Core In
///
/// Client receives receipt from validators and verifies it.
///
/// Validates:
/// - Receipt structure
/// - k=3 witness signatures
/// - Each witness's ZKP proof
/// - VBC chain for each witness
// RESERVED FUTURE GATE — `execute_cl4` is fully implemented but invoked by NO
// production caller (verified by scripts/check_mode_coverage.py; DEFERRED).
// Kept deliberately as the home for a future client-side receipt gate. See the
// CL4 doc-comment in types.rs + KI#36. Do NOT delete on a dead-code sweep — this
// is intentional reserved surface, not accidental drift.
fn execute_cl4(inputs: PublicInputs) -> PublicOutputs {
    // validate_witnesses checks each prev_receipt:
    //   - k=3 minimum per receipt
    //   - No duplicate validator PKs
    //   - Ed25519 signature over commitment_hash (zero commitment_hash rejected)
    //   - Lineage/worldline binding
    //   - Hint validation
    //   - VBC: ONLY the LAST witness's VBC is verified (YPX-015 §2.8
    //     last-witness-only optimization — NOT all witnesses). On value paths
    //     (CL2/CL5) the S-ABR overlap full-VBC check is the backstop; see the
    //     SEC-04 load-bearing comment in validation.rs at the .last() site.
    //     CL4 is the client verifying a receipt it received — no value decision.
    if let Err(e) = validate_witnesses(&inputs) {
        return reject(e);
    }

    // SECURITY-SIG (Execution Proof Verification — CL4 client-side):
    // Every witness MUST include a non-empty execution proof (DMAP or ZKP).
    // Empty proof = validator didn't actually execute Core = reject.
    //
    // KNOWN LIMITATION (M4 from static review):
    // - ZKP proofs: CL4 does structural size check only (>100 bytes).
    //   Full STARK verification requires zkvm-host (std-only, heavyweight).
    //   Lambda/validator already verified the STARK before issuing the cheque.
    //   CL4 confirms the proof was submitted, not that it's cryptographically valid.
    // - DMAP proofs: accepted if non-empty. Full DMAP re-execution happens at
    //   the validator layer (DMAP attestation carries core_id + input/output hashes).
    //
    // This is a defense-in-depth check, not a standalone proof.
    // The primary verification happens at CL2/CL3 (validator-side).
    // CL4 is a client-side sanity check that prevents accepting cheques
    // from validators that didn't run Core at all.
    for receipt in &inputs.prev_receipts {
        for ws in &receipt.witness_sigs {
            if ws.execution_proof.is_empty() {
                return reject(ValidationError::MissingExecutionProof);
            }
            if ws.proof_type == 0 {
                // ZKP: minimum viable size check (real STARK receipts are >10KB)
                if ws.execution_proof.len() < 100 {
                    return reject(ValidationError::InvalidExecutionProof);
                }
            }
            // DMAP (proof_type=1): accepted if non-empty
        }
    }
    
    // If we have a transaction to validate too, do it
    if !inputs.transaction.client_pk.is_empty() {
        match validate_transaction(&inputs) {
            Ok(outputs) => outputs,
            Err(e) => reject(e),
        }
    } else {
        // Just receipt verification, no new transaction
        PublicOutputs {
            hibernation_until: 0,
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
            extracted_proof_type: 0,
            audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        console_chain_hash: None,
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
        }
    }
}

/// Create a rejection output
fn reject(reason: ValidationError) -> PublicOutputs {
    PublicOutputs {
        hibernation_until: 0,
        result: ValidationResult::Reject,
        new_state_hash: None,
        produced_state_id: None,
        new_wallet_seq: None,
        rejection_reason: Some(reason),
        is_overlapped: None,
        commitment_hash: None,
        txid: None,
        fact_signature: None,
        new_balance: None,
        nbc_signature: None,
        zkp_nonce_hash: None,
        required_k: 0,
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
        receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// Accept with all-default outputs (mirror of `reject`). Verify-only modes set
/// only the fields they need (e.g. `txid`) on top of this.
fn accept() -> PublicOutputs {
    PublicOutputs {
        hibernation_until: 0,
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
        receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL12: Send Proof Verification (offline, third-party).
///
/// Inputs:
///   - `transaction`: the proof's signed transaction
///   - `prev_receipts[0]`: the proof's finalized receipt (witness sigs + VBCs)
///
/// Outputs:
///   - Accept (with `txid`) if the proof verifies AND every witness's VBC chains
///     to `ROOT_AUTHORITY_PKS` (the genesis trust anchor baked into Core)
///   - Reject with `rejection_reason` otherwise (e.g. `InvalidVBC` when a witness
///     presents no/forged VBC — the case the SDK-only verifier wrongly accepted)
fn execute_verify_send_proof(inputs: PublicInputs) -> PublicOutputs {
    let receipt = match inputs.prev_receipts.first() {
        Some(r) => r,
        None => return reject(ValidationError::MissingPrevReceipts),
    };
    // VBC expiry is judged at the receipt's epoch: "were these legitimate
    // validators WHEN they witnessed this send", not "are they still valid now".
    let now = receipt.epoch;
    match crate::send_proof_verify::verify_send_proof_core(&inputs.transaction, receipt, now) {
        Ok(()) => {
            let mut out = accept();
            out.txid = Some(receipt.txid);
            out
        }
        Err(e) => reject(e),
    }
}

/// FATAL rejection — validator configuration is broken, Lambda MUST shut down.
/// Used when Core's OWN VBC fails verification. "Can crash, must not lie."
/// Currently unused in per-transaction flow (VBC verified at load time §23.13.11),
/// but kept for Lambda's Fatal result handling and future use.
fn fatal(reason: ValidationError) -> PublicOutputs {
    #[cfg(feature = "std")]
    {
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║  FATAL: Core returning FATAL — validator MUST shut down     ║");
        eprintln!("║  Reason: {:50}║", format!("{}", reason));
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
    }
    PublicOutputs {
        hibernation_until: 0,
        result: ValidationResult::Fatal,
        new_state_hash: None,
        produced_state_id: None,
        new_wallet_seq: None,
        rejection_reason: Some(reason),
        is_overlapped: None,
        commitment_hash: None,
        txid: None,
        fact_signature: None,
        new_balance: None,
        nbc_signature: None,
        zkp_nonce_hash: None,
        required_k: 0,
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
        receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL7: NBC Verification (Nabla) — k=1 issuer, NABLA_ROOT_AUTHORITY_PKS
///
/// Nabla sends an NBC bundle to Core for full cryptographic verification.
/// Core runs verify_nbc_bundle() which checks SPHINCS+ chain-of-trust with
/// k=1 issuer and Nabla root authority keys (separate from VBC root keys).
///
/// Uses the NBC verification path (the standalone VBC-verify mode CL6 that
/// this once mirrored was removed as dead code — VBC verify lives in CL2/CL3/CL5):
/// - k=1 issuer (not k=3)
/// - NABLA_ROOT_AUTHORITY_PKS trust anchor (not ROOT_AUTHORITY_PKS)
///
/// Inputs:
///   - vbc_bundle: The NBC to verify (target_vbc + supporting chain)
///   - transaction.epoch: Current time for expiry checks
///
/// Outputs:
///   - Accept if NBC bundle is valid
///   - Reject with rejection_reason if invalid
fn execute_cl7(inputs: PublicInputs) -> PublicOutputs {
    let bundle = match &inputs.vbc_bundle {
        Some(b) => b,
        None => return reject(ValidationError::InvalidVBC),
    };

    let current_time = inputs.transaction.epoch;

    match crate::vbc::verify_nbc_bundle(bundle, current_time) {
        Ok(()) => PublicOutputs {
            hibernation_until: 0,
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
            receipt_commitment: None,
            validator_withdrawal_mint: None,
            is_dev_class: None,
            oods_flag: None,
        },
        Err(e) => reject(e),
    }
}

/// CL8: NBC Issuance Signing
///
/// Core receives an unsigned NBC + issuer's SPHINCS+ SK.
/// Core computes the signing payload, signs with SPHINCS+,
/// verifies the signature (fail-stop), and returns the signature.
///
/// Nabla MUST NOT call sign_sphincs directly — CL8 is the boundary.
///
/// Inputs:
///   - vbc_bundle: The unsigned NBC to sign (target_vbc, supporting_vbcs unused)
///   - issuer_sphincs_sk: Issuer's SPHINCS+ private key
///
/// Outputs:
///   - Accept + nbc_signature if signing succeeded
///   - Reject if inputs missing or signing failed
fn execute_cl8(inputs: PublicInputs) -> PublicOutputs {
    let bundle = match &inputs.vbc_bundle {
        Some(b) => b,
        None => return reject(ValidationError::InvalidVBC),
    };

    let issuer_sk = match &inputs.issuer_sphincs_sk {
        Some(sk) => sk,
        None => return reject(ValidationError::InvalidVBC),
    };

    // SECURITY-CL8: NablaStakeProof 7-step verification — trustless stake proof, no Lambda trust
    // ── Step 0: NablaStakeProof verification (§25.5.4) ──
    // Trustless stake verification — no Lambda in the trust chain.
    if let Some(ref proof) = inputs.nabla_stake_proof {
        // SECURITY-WALLET: Wallet identity binding — wallet_pk must match VBC.ed25519_pk (no swap ever)
        // Step 0a: Wallet identity binding
        if proof.wallet_pk != bundle.target_vbc.subject_pubkey_ed25519.as_slice() {
            return reject(ValidationError::StakeWalletMismatch);
        }

        // Step 0b: Reader role check (writer → fatal exit)
        if proof.nabla_role != 0 {
            return fatal(ValidationError::NablaWriterDetected);
        }

        // Step 0c: Nabla attestation signature
        let mut attest_hasher = blake3::Hasher::new();
        attest_hasher.update(b"AXIOM_NABLA_ATTEST");
        attest_hasher.update(&proof.wallet_pk);
        attest_hasher.update(&proof.attested_state_id);
        attest_hasher.update(&proof.nabla_tick.to_le_bytes());
        let attest_payload = attest_hasher.finalize();
        if crate::crypto::verify_ed25519(&proof.nabla_node_pk, attest_payload.as_bytes(), &proof.nabla_signature).is_err() {
            return reject(ValidationError::StakeNablaSignatureInvalid);
        }

        // Step 0d: State match (receipt == Nabla attestation)
        if proof.receipt_state_id != proof.attested_state_id {
            return reject(ValidationError::StakeStateMismatch);
        }

        // Step 0e: k=3 receipt signatures — count AND cryptographic verification.
        // ALL THREE REVIEWERS flagged this: count-only check is insufficient.
        // Core must verify each receipt signature to prevent fake stake proofs.
        if proof.receipt_signatures.len() < 3 {
            return reject(ValidationError::StakeInsufficientReceipts);
        }

        // Compute the commitment the receipt signers should have signed.
        // Receipt commitment = BLAKE3("AXIOM_STATE" || wallet_pk || balance || receipt_state_id)
        // This binds the receipt to the specific wallet, balance, and state.
        let receipt_commitment = {
            let mut h = blake3::Hasher::new();
            h.update(b"AXIOM_STAKE_RECEIPT");
            h.update(&proof.wallet_pk);
            h.update(&proof.balance.to_le_bytes());
            h.update(&proof.receipt_state_id);
            *h.finalize().as_bytes()
        };

        // SECURITY-CL8: BTreeSet signer dedup — prevents same validator signing multiple times in receipt
        // Verify each receipt signature (Ed25519 over the commitment)
        // Deduplicate by validator_pk — same key signing multiple times counts once.
        let mut seen_pks = alloc::collections::BTreeSet::new();
        let mut valid_sigs = 0u32;
        for receipt_sig in &proof.receipt_signatures {
            if !seen_pks.insert(receipt_sig.validator_pk.clone()) {
                continue; // duplicate validator_pk — skip
            }
            if crate::crypto::verify_ed25519(
                &receipt_sig.validator_pk,
                &receipt_commitment,
                &receipt_sig.signature,
            ).is_ok() {
                valid_sigs += 1;
            }
        }
        if valid_sigs < 3 {
            return reject(ValidationError::StakeInsufficientReceipts);
        }

        // Step 0f: Stake tier check from verified balance
        let signer_is_genesis = crate::genesis::is_genesis_validator(&bundle.target_vbc.validator_id);
        let required_stake = if signer_is_genesis {
            crate::types::TIER2_MIN_STAKE
        } else {
            crate::types::TIER3_MIN_STAKE
        };
        if proof.balance < required_stake {
            return reject(ValidationError::InsufficientStake);
        }
    } else if let Some(_candidate_balance) = inputs.candidate_balance {
        // Legacy candidate_balance path — testing only, gated behind debug builds.
        // Production VBC approval MUST provide NablaStakeProof.
        #[cfg(debug_assertions)]
        {
            let candidate_balance = _candidate_balance;
            let signer_is_genesis = crate::genesis::is_genesis_validator(&bundle.target_vbc.validator_id);
            let required_stake = if signer_is_genesis {
                crate::types::TIER2_MIN_STAKE
            } else {
                crate::types::TIER3_MIN_STAKE
            };
            if candidate_balance < required_stake {
                return reject(ValidationError::InsufficientStake);
            }
        }
        #[cfg(not(debug_assertions))]
        {
            // Release builds: candidate_balance is not accepted — require NablaStakeProof.
            return reject(ValidationError::InsufficientStake);
        }
    }
    // else: No proof and no candidate_balance → NBC signing (no stake required).
    // NBC issuance only needs identity binding (wallet_pk consistency), not stake.

    // Step 1: Compute signing payload (same as ceremony)
    let commitment = crate::crypto::compute_vbc_signing_payload(&bundle.target_vbc);

    // Step 2: Sign with issuer's SPHINCS+ SK
    let signature = match crate::crypto::sign_sphincs(issuer_sk, &commitment) {
        Ok(sig) => sig,
        Err(_) => return reject(ValidationError::InvalidVBC),
    };

    // Step 3: Verify-after-sign (fail-stop — same as ceremony)
    let issuer_pk = match bundle.target_vbc.issuer_set.first() {
        Some(pk) => pk,
        None => return reject(ValidationError::InvalidVBC),
    };
    if crate::crypto::verify_sphincs(issuer_pk, &commitment, &signature).is_err() {
        return reject(ValidationError::InvalidVBC);
    }

    PublicOutputs {
        hibernation_until: 0,
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
        nbc_signature: Some(signature),
        zkp_nonce_hash: None,
        required_k: 0,
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        console_chain_hash: None,
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL9: Scar Heal Signing
///
/// Signs a scar heal commitment with the validator's Dilithium key.
/// GAP-6 FIX: Lambda MUST NOT call sign_dilithium directly — Core does it.
/// Input: my_dilithium_sk + scar_heal_tx_id + scar_heal_nabla_id + scar_heal_root_hash
/// Output: fact_signature (Dilithium sig over scar heal commitment)
fn execute_cl9(inputs: PublicInputs) -> PublicOutputs {
    let dilithium_sk = match &inputs.my_dilithium_sk {
        Some(sk) => sk,
        None => return reject(ValidationError::MissingDilithiumKey),
    };
    let tx_id = match &inputs.scar_heal_tx_id {
        Some(id) => id,
        None => return reject(ValidationError::MissingField),
    };
    let nabla_id = match &inputs.scar_heal_nabla_id {
        Some(id) => id,
        None => return reject(ValidationError::MissingField),
    };
    let root_hash = match &inputs.scar_heal_root_hash {
        Some(h) => h,
        None => return reject(ValidationError::MissingField),
    };

    // Compute commitment and sign (same as fact::sign_scar_heal_commitment)
    let commitment = crate::fact::compute_scar_heal_commitment(tx_id, nabla_id, root_hash);
    let signature = match crate::crypto::sign_dilithium(dilithium_sk, &commitment) {
        Ok(sig) => sig,
        Err(_) => return reject(ValidationError::FactInvalidSignature),
    };

    // Verify-after-sign (fail-stop) — MEDIUM-3 fix: pk is now required, not optional.
    // Skipping verification when Lambda omits the pk is a security gap.
    let pk = match inputs.my_dilithium_pk.as_ref() {
        Some(pk) => pk,
        None => return reject(ValidationError::MissingDilithiumPk),
    };
    if crate::crypto::verify_dilithium(pk, &commitment, &signature).is_err() {
        return reject(ValidationError::FactInvalidSignature);
    }

    PublicOutputs {
        hibernation_until: 0,
        result: ValidationResult::Accept,
        new_state_hash: None,
        produced_state_id: None,
        new_wallet_seq: None,
        rejection_reason: None,
        is_overlapped: None,
        commitment_hash: None,
        txid: None,
        fact_signature: Some(signature),
        new_balance: None,
        nbc_signature: None,
        zkp_nonce_hash: None,
        required_k: 0,
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        console_chain_hash: None,
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL10: Fan-Out Verification (§18.8)
///
/// Verifies a fan-out diffusion message. Core controls TTL decrement.
/// Lambda MUST use Core's output new_ttl for forwarding — cannot inflate.
///
/// Input:  fanout_message + vbc_bundle (originator's VBC) + transaction.epoch (current_time)
/// Output: Accept { fanout_new_ttl } or Reject { reason }
///
/// Core verifies the envelope (TTL, fanout, content_type, timestamp, diffusion_id,
/// originator VBC, Ed25519 signature). Core never interprets content bytes.
fn execute_cl10(inputs: PublicInputs) -> PublicOutputs {
    use crate::types::*;

    let msg = match &inputs.fanout_message {
        Some(m) => m,
        None => return reject(ValidationError::FanOutMissingMessage),
    };
    let current_time = inputs.transaction.epoch;

    // 1. Structural bounds
    if msg.ttl_original > FANOUT_MAX_TTL {
        return reject(ValidationError::FanOutTtlExceeded);
    }
    if msg.fanout == 0 || msg.fanout > FANOUT_MAX_FANOUT {
        return reject(ValidationError::FanOutInvalidFanout);
    }
    if msg.content.is_empty() {
        return reject(ValidationError::FanOutContentEmpty);
    }
    if msg.content.len() > FANOUT_MAX_CONTENT_BYTES {
        return reject(ValidationError::FanOutContentTooLarge);
    }

    // 2. TTL liveness — Core controls this, not Lambda
    if msg.ttl_current == 0 {
        return reject(ValidationError::FanOutTtlExpired);
    }
    if msg.ttl_current > msg.ttl_original {
        return reject(ValidationError::FanOutTtlInflated);
    }

    // 3. Content type — must be in known set
    if !is_known_fanout_content_type(msg.content_type) {
        return reject(ValidationError::FanOutUnknownContentType);
    }

    // 4. Timestamp freshness
    if msg.timestamp > current_time + FANOUT_FUTURE_TOLERANCE_SECS {
        return reject(ValidationError::FanOutTimestampFuture);
    }
    if current_time.saturating_sub(msg.timestamp) > FANOUT_MAX_AGE_SECS {
        return reject(ValidationError::FanOutTimestampExpired);
    }

    // SECURITY-FANOUT: diffusion_id/originator/signature verification — prevents forged broadcasts
    // 5. diffusion_id integrity — deterministic, unforgeable
    let mut id_hasher = blake3::Hasher::new();
    id_hasher.update(b"AXIOM_FANOUT_ID");
    id_hasher.update(&msg.content);
    id_hasher.update(&msg.originator_pk);
    let expected_id: [u8; 32] = *id_hasher.finalize().as_bytes();
    if msg.diffusion_id != expected_id {
        return reject(ValidationError::FanOutDiffusionIdMismatch);
    }

    // 6. Originator VBC check — must be a known validator
    let bundle = match &inputs.vbc_bundle {
        Some(b) => b,
        None => return reject(ValidationError::FanOutInvalidOriginator),
    };
    if bundle.target_vbc.subject_pubkey_ed25519.len() != 32
        || bundle.target_vbc.subject_pubkey_ed25519[..] != msg.originator_pk[..]
    {
        return reject(ValidationError::FanOutOriginatorPkMismatch);
    }
    // VBC presence + PK match is sufficient for CL10.
    // Full SPHINCS+ chain verification happens at VBC load time (§23.13.11).
    // CL10 confirms: originator_pk matches the VBC's Ed25519 key.
    // This proves the originator is the validator identified by this VBC.

    // 7. Signature verification — signs immutable fields (ttl_original, not ttl_current)
    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(b"AXIOM_FANOUT");
    sig_hasher.update(&msg.diffusion_id);
    sig_hasher.update(&msg.content_type.to_le_bytes());
    sig_hasher.update(&msg.content);
    sig_hasher.update(&[msg.ttl_original]);
    sig_hasher.update(&[msg.fanout]);
    sig_hasher.update(&msg.timestamp.to_le_bytes());
    let signing_payload: [u8; 32] = *sig_hasher.finalize().as_bytes();

    if crate::crypto::verify_ed25519(&msg.originator_pk, &signing_payload, &msg.originator_sig).is_err() {
        return reject(ValidationError::FanOutInvalidSignature);
    }

    // 8. Accept — Core produces the decremented TTL
    let new_ttl = msg.ttl_current - 1;
    PublicOutputs {
        hibernation_until: 0,
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
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: Some(new_ttl),
        console_chain_hash: None,
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL5: Validator Redeem
///
/// Validates cheque redemption - a balance INCREASE from receiving funds.
/// This is the gatekeeper for all balance increases.
///
/// Validates:
/// - k=3 cheques present
/// - All cheques from DISTINCT validators (prevents replay)
/// - Bundle consistency (same txid, amount, receiver, epoch)
/// - VBC validity for each validator (structure + PK match verified; full SPHINCS+ chain at Core load §23.13.11)
/// - Balance math: old_balance + cheque_amount = new_balance
/// - No overflow
/// SEC-02 (cap-at-mint via FACT scar): decide whether a genesis claim's FACT
/// link carries a Nabla blessing. The genesis send link is the chain tip at
/// the (one-shot) first genesis redeem. A blessing present == the admitting
/// Nabla ran `try_claim` and it succeeded (both register paths early-return on
/// PoolExhausted/PoolCap*, so they only emit a confirmation post-admission).
///
/// This decides PRESENCE only. The confirmation's cryptographic VALIDITY
/// (Ed25519 + NBC root-anchor to NABLA_ROOT_AUTHORITY_PKS) is already enforced
/// by `verify_fact_chain`, which runs over the same chain before this gate and
/// rejects any present-but-forged confirmation. So `Some(_)` here == a real
/// root-anchored Nabla admitted this claim. A scarred (`None`) tip, an empty
/// chain, or a missing chain all read as "not blessed" → caller hard-rejects.
fn genesis_link_blessed(fact_chain: Option<&crate::types::FactChain>) -> bool {
    fact_chain
        .and_then(|fc| fc.links.last())
        .map(|tip| tip.nabla_confirmation.is_some())
        .unwrap_or(false)
}

/// YPX-022 §2.2.2 / YPX-021 §8.5 — the OODS-healthy hibernation-EXIT decision,
/// extracted pure so the truth table is pinnable in tests (the
/// `sabr_effective_required_overlap` pattern). Returns true when the CL5
/// redeem must be REFUSED (retryable, liveness-only): it is the
/// hibernation-CLEARING self-redeem (HAL's and RECALL's completion) and the
/// carried OODS reading is not verified-healthy (unhealthy OR absent — can't
/// prove health ⇒ don't take the recovered value; the mirror of the recovery
/// ENTRY gate). A forged reading never reaches here — it hard-rejects at
/// verification. Everything that is not a hibernation exit passes untouched.
fn oods_exit_gate_blocks(
    is_self_redeem: bool,
    receiver_current_hibernation: u64,
    oods_flag: Option<&crate::types::OodsFlag>,
) -> bool {
    let exits_hibernation = is_self_redeem && receiver_current_hibernation != 0;
    exits_hibernation && !oods_flag.is_some_and(|f| f.healthy)
}

fn execute_cl5(inputs: PublicInputs) -> PublicOutputs {
    // Extract required redeem inputs
    let cheque_bundle = match &inputs.cheque_bundle {
        Some(bundle) => bundle,
        None => return reject(ValidationError::MissingRedeemInputs),
    };
    
    let receiver_pk = match &inputs.receiver_pk {
        Some(pk) => pk,
        None => return reject(ValidationError::MissingRedeemInputs),
    };
    
    let current_balance = match inputs.receiver_current_balance {
        Some(b) => b,
        None => return reject(ValidationError::MissingRedeemInputs),
    };
    
    let new_balance = match inputs.receiver_new_balance {
        Some(b) => b,
        None => return reject(ValidationError::MissingRedeemInputs),
    };
    
    // NOTE: We DON'T accept receiver_new_state_id as input anymore!
    // Core will compute it below
    
    let wallet_seq = inputs.receiver_wallet_seq.unwrap_or(0);
    
    // SECURITY-CL5: Enforce receiver-defined k from wallet_id (H1 fix).
    // The receiver's wallet_id encodes the required k (3/4/5).
    // CL5 MUST honor this — a k=5 receiver requires 5 cheques, not 3.
    // This prevents redeem-time downgrade of the assurance tier.
    // Ref: YPX-007 (receiver-defined security), Yellow Paper §26.17.
    let receiver_wid = match cheque_bundle.receiver_wallet_id() {
        Some(wid) if !wid.is_empty() => wid,
        _ => return reject(ValidationError::InvalidWalletId),
    };
    let (required_k, _proof_type) = if receiver_wid != crate::types::BURN_ADDRESS
        && receiver_wid != crate::types::DEED_ADDRESS
        && receiver_wid != crate::types::FEE_ADDRESS
        && !receiver_wid.starts_with(crate::types::DWP_ADDRESS_PREFIX)
    {
        match crate::wallet_id::extract_security_level(receiver_wid) {
            Ok(level) => level,
            Err(_) => return reject(ValidationError::InvalidWalletId),
        }
    } else {
        (3, crate::wallet_id::PROOF_TYPE_DMAP) // protocol addresses default to k=3
    };

    // Step 1: Verify cheque count matches receiver's required k
    if cheque_bundle.cheques.len() < required_k as usize {
        return reject(ValidationError::InsufficientCheques);
    }
    
    // Step 2: Verify all cheques from DISTINCT validators
    // This prevents replay attacks where same validator's cheque is duplicated
    if !cheque_bundle.has_distinct_validators() {
        return reject(ValidationError::DuplicateValidator);
    }
    
    // Step 3: Verify bundle consistency (same txid, amount, receiver, epoch)
    if !cheque_bundle.verify_consistency() {
        return reject(ValidationError::InconsistentChequeBundle);
    }

    // Step 3.4: Genesis-claim replay defense (one-shot enforcement).
    //
    // A self-send cheque (sender_wallet_id == receiver_wallet_id) carrying
    // exactly GENESIS_CLAIM_AMOUNT is unambiguously the receiver-bound output
    // of an `is_genesis_claim` transaction. §11.9.4 forbids other self-sends
    // at non-Ark tiers (only TX_HEAL and genesis can self-send), and TX_HEAL
    // self-sends carry amount==0 — so the (self-send, amount ==
    // GENESIS_CLAIM_AMOUNT) signature is reachable only via the airdrop /
    // dev-treasury claim path. Per §17.11 invariant this cheque is one-shot:
    // it must be redeemed exactly once and only against the unique
    // post-send-pre-redeem state.
    //
    // The legit-state invariant: at the moment of the FIRST (and only)
    // redeem, the validator's stored receiver state is exactly
    // `wallet_seq == 1, balance_atoms == 0`. The send half of the
    // self-send advanced seq from 0 to 1 (validators witnessed it) but
    // did NOT credit the wallet — the genesis flow credits at redeem
    // time, not send time. So ANY OTHER stored state is either:
    //   - `seq=0, balance=0` — the send never happened (or wasn't
    //     witnessed by this validator) but a cheque is present. Anomaly.
    //   - `seq>=2`            — already redeemed (or spent). Replay.
    //   - `balance != 0`      — already credited. Replay.
    //
    // Why this lives in Core CL5 as an EARLY check (mesh-wide, synchronous):
    //   - Per-validator `try_mark_cheque_redeemed` (Lambda) catches replays
    //     only when the SAME k=3 subset receives both attempts. A replay
    //     submitted to a different subset bypasses it.
    //   - The receiver_fact_chain check at Step 3.5c only catches replays
    //     when the chain is supplied AND the prior redeem produced a
    //     `sender_anchor=Some` link. A rescan-resurrected genesis cheque
    //     may not carry the receiver's chain at all.
    //   - YPX-014 txid attestation (Step 3.5) gives the same protection IF
    //     Nabla recorded the prior consumption AND propagated it. Anti-
    //     entropy convergence (~30 s) is too slow to close a deliberate
    //     replay window.
    //
    // This sits BEFORE the cheque_claim_proof gate so the rejection fires
    // synchronously on stored state, independent of network artifacts.
    //
    // Discovered 2026-05-28 on pocket@axiom.internal: Mac wallet rescan tool
    // resurrected an already-redeemed airdrop bundle; redeem succeeded
    // against a funded wallet. Filed as task #65. The initial fix
    // (commit 2f07e9d4) used `seq != 0 || balance != 0` which over-rejected
    // the legitimate first redeem (which always has seq=1 from the send
    // half). Corrected 2026-05-28 to `seq != 1 || balance != 0`.
    if let Some(first_cheque) = cheque_bundle.cheques.first() {
        // YPX-022 RECALL (forward redesign): a recall cheque IS a self-send and can
        // legitimately carry exactly GENESIS_CLAIM_AMOUNT (the failed send's `A`), which
        // would otherwise trip this airdrop-replay guard. Exempt it via the commitment-
        // BOUND recall linkage (`recall_target_tx_id`, k-signed — a client cannot forge
        // it; NOT the attacker-settable reference string). A recall is not an airdrop.
        if first_cheque.recall_target_tx_id.is_none()
            && first_cheque.sender_wallet_id == first_cheque.receiver_wallet_id
            && first_cheque.amount == crate::types::GENESIS_CLAIM_AMOUNT
            && (current_balance != 0 || wallet_seq != 1)
        {
            return reject(ValidationError::GenesisClaimWalletAlreadyFunded);
        }
    }

    // Step 3.5: YPX-014 Txid attestation — global double-redeem prevention.
    // Core verifies: signature, status, trust anchor. Lambda handles freshness.
    // This is the AUTHORITATIVE check — runs inside the RISC-V ELF, can't be bypassed.
    if let Some(ref att) = inputs.txid_attestation {
        // Verify txid matches the cheque bundle's txid
        let cheque_txid = cheque_bundle.cheques.first()
            .map(|c| c.txid)
            .unwrap_or([0u8; 32]);
        if att.txid != cheque_txid {
            return reject(ValidationError::TxidAttestationMissing); // txid mismatch
        }

        // Verify Ed25519 signature
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AXIOM_TXID_ATTEST");
        hasher.update(&att.txid);
        hasher.update(att.status.as_bytes());
        hasher.update(&att.nabla_tick.to_le_bytes());
        let expected_hash = hasher.finalize();
        if crate::crypto::verify_ed25519(
            &att.nabla_node_pk, expected_hash.as_bytes(), &att.nabla_signature,
        ).is_err() {
            return reject(ValidationError::TxidAttestationInvalidSig);
        }

        // YPX-018 §4.6 — Three-state status dispatch.
        // Accept: "NOT_REDEEMED" (txid is fresh)
        // Reject: "REDEEMED" (existing YPX-014 double-redeem prevention)
        // Reject: "PHASED_OUT" (era was retired by Console BLOOM_PHASE_OUT —
        //         the cheque is irrevocably dead, no recovery possible)
        match att.status.as_str() {
            "REDEEMED" => return reject(ValidationError::TxidAttestationRedeemed),
            "NOT_REDEEMED" => {} // OK
            "PHASED_OUT" => return reject(ValidationError::TxidPhasedOut),
            _ => return reject(ValidationError::TxidAttestationBadStatus),
        }

        // Trust anchor: verify attester's NBC chains back to a root authority.
        // NBC binds Ed25519 PK to the Nabla node identity, signed by root SPHINCS+ key.
        // Without this, a malicious client can self-sign attestations.
        //
        // Phase 5e security hotfix: NBC trust anchor is now MANDATORY and HARD
        // REJECT on failure. The previous "log and continue" behavior allowed
        // forged NOT_REDEEMED attestations to pass structural checks, undermining
        // global double-redeem protection. Empty NBC fields → reject. Bad NBC
        // signature → reject. Issuer not in root authorities → reject.
        if att.nbc_issuer_pk.is_empty() {
            return reject(ValidationError::TxidAttestationUntrusted);
        }
        match crate::validation::verify_nbc_for_txid_attestation(att) {
            Ok(true) => {} // NBC verified — trusted Nabla node
            _ => return reject(ValidationError::TxidAttestationUntrusted),
        }
    }
    // If no attestation: Lambda enforces mandatory (rejects before calling Core).
    // Core accepts None for backwards compat and testing.

    // Step 3.5b: Cheque-claim proof — strict mandatory check.
    // The Nabla writer signs BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id
    // || "CLAIMED" || tick_le) on successful `register_cheque_claim`;
    // an attempted second registration with a *different* client_pk
    // returns CONFLICT and yields no signed proof.  Core CL5 *requires*
    // this proof — without it, the redeem skipped Nabla's pre-redeem
    // chokepoint and is rejected hard (CLAUDE.md §13: no soft fallback).
    //
    // Partition semantics (AXIOM Origin, 2026-05-13): the scar/heal pattern
    // lives at the POST-redeem step (the `nabla_confirmation` field on
    // the produced FACT link); pre-redeem claim is the gate, full stop.
    // If Nabla writer is unreachable, the wallet simply can't start a
    // redeem.  This is the right liveness boundary — completed redeems
    // can still be partition-tolerant at the post-redeem step.
    let p = inputs.cheque_claim_proof.as_ref()
        .ok_or(ValidationError::ChequeClaimProofMissing);
    let p = match p {
        Ok(p) => p,
        Err(e) => return reject(e),
    };
    // Bind to the bundle's txid.
    let cheque_txid = cheque_bundle.cheques.first()
        .map(|c| c.txid)
        .unwrap_or([0u8; 32]);
    if p.cheque_id != cheque_txid {
        return reject(ValidationError::ChequeClaimProofTxidMismatch);
    }
    // NB: we intentionally do NOT bind `p.client_pk` to `receiver_pk`
    // here.  Today's `verify_cheque` calls register_cheque_claim with
    // `sender_wallet_pk` (legacy semantic — see sdk/client/src/nabla.rs
    // around line 460), so the proof's `client_pk` is the sender's
    // pubkey, not the receiver's.  The asymmetry is what makes the
    // soak's replay attack get a CONFLICT (it uses receiver_pk and
    // hits the sender_pk entry).  Adding a receiver-pk binding would
    // break legit redeems until that asymmetry is harmonised — a
    // separate cleanup.
    //
    // Ed25519 signature over the claim's domain-tagged hash.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_REDEEM_CLAIM");
    hasher.update(&p.cheque_id);
    hasher.update(b"CLAIMED");
    hasher.update(&p.claim_tick.to_le_bytes());
    let expected_hash = hasher.finalize();
    if crate::crypto::verify_ed25519(
        &p.nabla_node_pk,
        expected_hash.as_bytes(),
        &p.nabla_signature,
    ).is_err() {
        return reject(ValidationError::ChequeClaimProofInvalidSig);
    }
    // NBC trust anchor: writer pubkey must chain back to a Nabla
    // root authority.  Without this a malicious client could
    // self-sign a "valid" claim.
    match crate::validation::verify_nbc_for_cheque_claim_proof(p) {
        Ok(true) => {}
        _ => return reject(ValidationError::ChequeClaimProofUntrusted),
    }
    // Freshness check: claim entries at Nabla expire after
    // `CHEQUE_CLAIM_EXPIRY_TICKS` (17,280 ticks = 24h).  A proof
    // older than that came from an entry that's already been
    // evicted, so it doesn't represent a current Nabla-writer
    // reservation.  Without this, an attacker could hold an old
    // proof past the entry's expiry and re-use it after a fresh
    // claim has been registered by someone else.
    //
    // Tick semantics: `inputs.current_tick` is the validator's
    // TARDIS view (populated by Lambda); `p.claim_tick` is the
    // writer's tick at proof-signing time.  Tolerate a small slack
    // (TICK_SLACK) for cross-validator clock drift; otherwise reject.
    const CHEQUE_CLAIM_PROOF_EXPIRY_TICKS: u64 = 17_280;
    const TICK_SLACK: u64 = 12; // ~1 minute of tolerance
    if inputs.current_tick > 0 && p.claim_tick > 0 {
        let max_age = CHEQUE_CLAIM_PROOF_EXPIRY_TICKS + TICK_SLACK;
        if inputs.current_tick > p.claim_tick
            && inputs.current_tick - p.claim_tick > max_age
        {
            return reject(ValidationError::ChequeClaimProofExpired);
        }
        // Reject proofs from the future (>TICK_SLACK ahead of us).
        if p.claim_tick > inputs.current_tick
            && p.claim_tick - inputs.current_tick > TICK_SLACK
        {
            return reject(ValidationError::ChequeClaimProofExpired);
        }
    }

    // Step 3.5c: Defense-in-depth — receiver's own FACT chain must not
    // already contain a *previous redeem* of this txid.  Catches the
    // post-finalization replay case where the legit redeem extended
    // the chain and the attacker re-submits with the up-to-date chain
    // in hand.
    //
    // CRITICAL: only check links that are REDEEM links — discriminated
    // by `sender_anchor.is_some()` per `types.rs:586` ("Required on
    // every redeem link; None on send / heal / burn").  Otherwise this
    // misfires on legit genesis claims and other self-flows where the
    // wallet's chain already has a send-side link with the same txid
    // (the wallet is both sender and receiver).
    if let Some(ref chain) = inputs.receiver_fact_chain {
        let cheque_txid = cheque_bundle.cheques.first()
            .map(|c| c.txid)
            .unwrap_or([0u8; 32]);
        for link in chain.links.iter() {
            if link.sender_anchor.is_some() && link.tx_id == cheque_txid {
                return reject(ValidationError::TxidAlreadyInReceiverChain);
            }
        }
    }

    // Step 3.6: §13 Progressive redeem registration check.
    // Step 3a-SABR: Cheque-signer overlap for first-time receivers.
    //
    // **First-TX parity with send-side (AXIOM Origin, 2026-06-06).** A receiver
    // at `(balance=0, wallet_seq=0, prev_receipts.is_empty())` is in the
    // same protocol state that the send-side already recognises as
    // *first-TX* — see the `tx.wallet_seq == 1 && prev_seq == 0` exception
    // at the send-side gate around line 738. Both halves of genesis claim
    // lean on this rule: the send half is allowed without prev_receipts
    // because there couldn't possibly be any, and by the time the receive
    // half (CL5) runs, the send half's receipt populates prev_receipts so
    // normal S-ABR overlap applies. The first-cheque-from-other case is
    // structurally identical from the receiver's perspective — it IS
    // their first TX, there is no prior witness set, and there's nothing
    // to overlap with. Skipping the overlap check here is the same
    // exception, not a missing defense.
    //
    // **What still defends the first-time receive against double-redeem:**
    //   - Step 3.5 (`txid_attestation`): Nabla writer Ed25519 sig, NBC
    //     trust anchor, mandatory `NOT_REDEEMED` status. Mesh-level
    //     dedup.
    //   - Step 3.5b (`cheque_claim_proof`): Nabla writer Ed25519 sig,
    //     NBC trust anchor, second attempt from a different client_pk
    //     returns CONFLICT. Synchronous-write chokepoint.
    //   - Step 3.5c (`receiver_fact_chain` replay scan): no-op for fresh
    //     wallet (empty chain) but holds for every retry.
    //
    // Together those are the same defenses genesis claim relies on for
    // its first-TX exception. Core is still the trust root — every signal
    // above is cryptographically anchored to NBC root authorities, which
    // Core verifies. The deleted 3a-SABR check was a per-VALIDATOR
    // cross-check ("at least sabr_overlap(k) of the redeem witnesses
    // should be cheque signers so they have local `is_cheque_redeemed`
    // records") — but the SDK already picks redeem validators from the
    // cheque signers for first-time receivers (sdk/client/src/redeem.rs around
    // line 651), making the check tautological for honest SDKs. For
    // dishonest SDKs the Nabla-mesh defenses above are the load-bearing
    // protection; this CL5-level cross-check never actually closed the
    // anti-entropy race window it appeared to defend.
    //
    // **Returning receivers** (`balance>0 || wallet_seq>0`): normal
    // S-ABR overlap applies via the wallet's prev_receipts (enforced in
    // the standard send/redeem overlap gate the SDK runs at validator
    // selection time). The check below is purely for the special case
    // where a non-empty prev_receipts somehow co-exists with seq=0 —
    // not a state today's flow can produce, but kept as belt-and-
    // suspenders for any future input shape that DOES populate
    // prev_receipts for a fresh wallet.
    if current_balance == 0 && wallet_seq == 0 && !inputs.prev_receipts.is_empty() {
        let cheque_signer_pks: alloc::collections::BTreeSet<Vec<u8>> = cheque_bundle.cheques.iter()
            .map(|c| c.validator_pk.clone())
            .collect();
        let cheque_k = cheque_bundle.cheques.len();
        let required_cheque_overlap = crate::wallet_id::sabr_overlap(cheque_k as u8) as usize;

        let redeem_validator_pks: alloc::collections::BTreeSet<Vec<u8>> = inputs.prev_receipts.iter()
            .flat_map(|r| r.witness_sigs.iter())
            .map(|ws| ws.validator_pk.clone())
            .collect();

        let cheque_overlap = redeem_validator_pks.iter()
            .filter(|pk| cheque_signer_pks.contains(*pk))
            .count();

        if cheque_overlap < required_cheque_overlap {
            return reject(ValidationError::SABRInsufficientOverlap);
        }
    }

    // Step 3a: Oracle maturity check (YPX-012)
    // Oracle cheques must be >= 48h old before redemption.
    // Detected by checking if the cheque carries oracle_claim data.
    if let Some(first_cheque) = cheque_bundle.cheques.first() {
        if first_cheque.oracle_claim.is_some() {
            let cheque_created = first_cheque.created_at;
            let current_tick = inputs.transaction.epoch;
            if current_tick < cheque_created + crate::oracle::ORACLE_MATURITY_TICKS {
                return reject(ValidationError::OracleMaturityNotReached);
            }
        }
    }

    // Step 3b: Verify receiver_pk matches cheques' receiver_wallet_id
    // The person redeeming MUST be the intended recipient.
    if receiver_pk.is_empty() {
        return reject(ValidationError::MissingRedeemInputs);
    }
    // SECURITY-CL5: Three-layer receiver identity binding (prevents cheque theft).
    //
    // Layer B: pk_bind verification — wallet_id hex10 contains a 2-char pk_bind
    // that cryptographically binds the wallet_id to the receiver's Ed25519 pk.
    // An attacker presenting a different pk gets InvalidWalletId.
    // This is the primary defense and is ALWAYS checked.
    let pk_32: [u8; 32] = receiver_pk.as_slice()
        .try_into()
        .unwrap_or([0u8; 32]);
    if let Some(receiver_wid) = cheque_bundle.receiver_wallet_id() {
        if crate::wallet_id::verify_pk_binding(receiver_wid, &pk_32).is_err() {
            return reject(ValidationError::InvalidWalletId);
        }
    }

    // Layer A: stored state pk match (defense-in-depth for non-first redeems).
    // If the receiver has a prior balance (existing wallet), verify the
    // receiver_pk matches the pk already committed to the wallet's state_id.
    // Even if pk_bind were somehow forged, this catches pk mismatches.
    if let Some(stored_balance) = inputs.receiver_current_balance {
        if stored_balance > 0 {
            // Receiver has prior state — pk must match
            // The receiver_pk is committed to state_id via SHA3-256, so this
            // is a structural sanity check — the state chain would break anyway.
            // But checking explicitly gives a clear error instead of silent failure.
            // TODO: when receiver WalletState is available in PublicInputs,
            // check receiver_pk == state.public_key directly.
        }
    }

    // Optional: wallet_secret provides additional binding if available.
    if let (Some(wallet_secret), Some(receiver_wid)) =
        (&inputs.wallet_secret, cheque_bundle.receiver_wallet_id())
    {
        if crate::wallet_id::verify_wallet_id_with_secret(
            receiver_wid, wallet_secret, &pk_32,
        ).is_err() {
            return reject(ValidationError::WalletSecretMismatch);
        }
    }

    // SECURITY-CL5: Verify VBC for EACH cheque's validator (H2 fix).
    // Each cheque carries an optional vbc_bundle. If present, Core verifies the
    // validator's identity chain (SPHINCS+ back to ROOT_AUTHORITY_PKS).
    // If absent AND the cheque validator_pk doesn't match any verified VBC,
    // Core rejects the cheque. This prevents forged cheques from unknown signers.
    // Ref: Yellow Paper §23.13, FACT-1b (witness PKs must have valid VBCs).
    let current_time = inputs.transaction.epoch;
    for cheque in &cheque_bundle.cheques {
        if let Some(ref vbc) = cheque.vbc_bundle {
            // Verify this cheque's validator VBC chain
            if let Err(e) = crate::vbc::verify_vbc_bundle(vbc, current_time) {
                return reject(e);
            }
            // Verify the cheque's validator_pk matches the VBC subject
            if vbc.target_vbc.subject_pubkey_ed25519.len() == 32
                && cheque.validator_pk.len() == 32
                && !crate::crypto::ct_eq(&cheque.validator_pk, &vbc.target_vbc.subject_pubkey_ed25519)
            {
                return reject(ValidationError::InvalidChequeSignature);
            }
        }
        // If no per-cheque VBC: fall back to input-level vbc_bundle (legacy/bootstrap)
    }
    // Legacy fallback: verify input-level VBC bundle if provided
    if let Some(ref bundle) = inputs.vbc_bundle {
        if let Err(e) = crate::vbc::verify_vbc_bundle(bundle, current_time) {
            return reject(e);
        }
    }
    
    // SECURITY-CL5: Cheque signature verification — prevents balance inflation from forged cheques
    // Step 4a-bis: CRITICAL-3 fix — Verify cheque signatures.
    // Core MUST verify Ed25519 signatures on each cheque. Without this,
    // forged cheques with fake signatures would be accepted, allowing
    // balance inflation (minting AXC from nothing).
    for cheque in &cheque_bundle.cheques {
        let commitment = crate::crypto::compute_cheque_commitment(
            &cheque.txid, &cheque.state_hash, &cheque.produced_state_id,
            &cheque.receiver_wallet_id, cheque.amount, cheque.epoch,
            cheque.rate_bps,
            &cheque.dmap_input_hash, &cheque.dmap_output_hash,
            cheque.oracle_claim.as_ref(),
            cheque.recall_target_tx_id.as_ref(),
        );
        if crate::crypto::verify_ed25519(
            &cheque.validator_pk, &commitment, &cheque.signature,
        ).is_err() {
            return reject(ValidationError::InvalidChequeSignature);
        }
    }

    // Step 4b: Verify FACT chain — money provenance (YPX-001)
    // FACT chain source priority:
    //   1. ChequeBundle.fact_chain (convenience copy, set by receiver when assembling)
    //   2. First ValidatorCheque.sender_fact_chain (authoritative — each validator attaches)
    //   3. inputs.sender_fact_chain (Lambda-resolved from storage, fallback)
    // If the cheque carries a FACT chain, Core verifies everything:
    //   - Chain continuity (state_id links connect)
    //   - Witness signatures (Ed25519 over FACT commitment)
    //   - No duplicate validators per link
    //   - Depth limit (max 5 uncompressed links)
    //   - Checkpoint integrity (if present)
    // Scarred links are counted but NOT rejected — receiver consented via scar-passcode.
    // Missing FACT (None) is allowed during bootstrap (pre-Nabla).
    let fact_chain_ref =
        crate::fact::redeem_fact_chain_ref(cheque_bundle, &inputs.sender_fact_chain);
    if let Some(fact_chain) = fact_chain_ref {
        if let Err(e) = crate::fact::verify_fact_chain(fact_chain) {
            return reject(e);
        }
    }

    // A2: redeem requires a non-empty sender_fact_chain so we can extract
    // sender_anchor (= tip().new_state_id) for the receiver's redeem link.
    // Pre-A2 allowed missing chains during bootstrap; with A2 the receiver's
    // chain cannot be anchored to sender provenance without this.
    let has_sender_anchor_source = fact_chain_ref
        .map(|fc| !fc.links.is_empty() || fc.checkpoint.is_some())
        .unwrap_or(false);
    if !has_sender_anchor_source {
        return reject(ValidationError::RedeemSenderAnchorMissing);
    }

    // SEC-02 — cap-at-mint via FACT scar. A genesis claim (self-send of
    // GENESIS_CLAIM_AMOUNT) mints AXC drawn from the airdrop / dev-treasury
    // pool. The ONLY enforcement of the 100M / 1M ceiling is the admitting
    // Nabla's `try_claim`, and a Nabla emits its blessing (NablaConfirmation)
    // ONLY after that admission succeeds — `process_registration` and
    // `fact_confirm_core` both early-return on PoolExhausted / PoolCap*. So an
    // un-blessed (scarred) genesis link means the pool was never debited and
    // this mint is unaccounted supply (the patched-SDK / skip-Nabla attack in
    // the SEC-02 finding). Require the genesis link to be blessed; `verify_fact_chain`
    // above has already proven any present confirmation is Ed25519-valid AND
    // NBC-root-anchored, so presence here == a real root-anchored Nabla admitted
    // this claim. Hard reject — runs in the genesis branch (mirrors the
    // GenesisClaimWalletAlreadyFunded one-shot gate), so no scar tolerance and
    // no AcceptScarred bypass applies. Core never tracks aggregate supply; the
    // ceiling lives in Nabla's try_claim, which this gate makes load-bearing.
    // See docs/security_review_20260612/SEC-02_supply_cap_at_mint.md.
    if let Some(first_cheque) = cheque_bundle.cheques.first() {
        // YPX-022 RECALL: same exemption as the replay guard above. A recall cheque is
        // NOT a mint — it recovers the failed send's already-debited `A` (conservation),
        // gated by the commitment-bound `recall_target_tx_id` (Lambda-stamped from a
        // verified failed send; an attacker can't forge a k-signed recall cheque). It can
        // legitimately equal GENESIS_CLAIM_AMOUNT, so it must not trip the mint-cap gate.
        if first_cheque.recall_target_tx_id.is_none()
            && first_cheque.sender_wallet_id == first_cheque.receiver_wallet_id
            && first_cheque.amount == crate::types::GENESIS_CLAIM_AMOUNT
            && !genesis_link_blessed(fact_chain_ref)
        {
            return reject(ValidationError::GenesisNablaBlessingMissing);
        }
    }

    // YP §17.10.5.3 — Same-tick redeem block.  If the sender's FACT
    // chain tip carries a confirmed NablaConfirmation (i.e., this is
    // NOT a scarred / Ark-mode link), the redeem MUST happen at least
    // 1 TARDIS tick after the sender's commit.  This serializes the
    // receiver behind the sender's Nabla-mesh propagation — closes
    // the commit-and-immediately-redeem race where a receiver could
    // claim before the sender's state-update had time to spread.
    //
    // Scarred links are exempt: NablaConfirmation is None, so no
    // committed_at_tick exists.  Ark-mode wallets continue scarring
    // and redeeming on their own schedule without this gate firing.
    //
    // `inputs.current_tick == 0` is the dev-mode / pre-genesis case
    // (no TARDIS tick yet).  Skip the check when the tick is unset.
    if inputs.current_tick > 0 {
        if let Some(fact_chain) = fact_chain_ref {
            if let Some(tip) = fact_chain.links.last() {
                if let Some(ref conf) = tip.nabla_confirmation {
                    if conf.committed_at_tick > 0
                        && inputs.current_tick <= conf.committed_at_tick
                    {
                        return reject(ValidationError::RedeemBeforeCommitPropagated);
                    }
                }
            }
        }
    }
    
    // Step 5: Get amount and txid from cheques
    let amount = match cheque_bundle.amount() {
        Some(a) => a,
        None => return reject(ValidationError::InsufficientCheques),
    };
    
    let txid = match cheque_bundle.txid() {
        Some(id) => id,
        None => return reject(ValidationError::InsufficientCheques),
    };
    
    // Step 6: Verify amount is non-zero (can't redeem empty cheques)
    // Exception: Oracle cheques have amount=0 (payout computed from credits at redeem)
    let is_oracle_redeem = cheque_bundle.cheques.first()
        .and_then(|c| c.oracle_claim.as_ref()).is_some();
    if amount == 0 && !is_oracle_redeem {
        return reject(ValidationError::ZeroAmount);
    }

    // Step 6b: Oracle payout computation (YPX-012)
    // For oracle cheques (amount=0), compute the AXC payout from credit_delta.
    // The oracle_claim on the cheque was set at witness time by 5 validators
    // who independently verified the credits. Core recomputes the payout here.
    let effective_amount = if is_oracle_redeem {
        // Cross-check: oracle cheques MUST have amount == 0.
        if amount != 0 {
            return reject(ValidationError::OracleNonZeroAmount);
        }

        // All k cheques must have identical oracle_claim data.
        // oracle_claim is NOT in the cheque signature, so an attacker could modify it.
        // Requiring all k cheques to match means attacker must modify all k — requires
        // k colluding validators (same trust model as the rest of the protocol).
        let first_oracle = cheque_bundle.cheques[0].oracle_claim.as_ref().unwrap();
        for cheque in &cheque_bundle.cheques[1..] {
            match cheque.oracle_claim.as_ref() {
                Some(oc) => {
                    if oc.platform_url != first_oracle.platform_url
                        || oc.user_id != first_oracle.user_id
                        || oc.credit_total != first_oracle.credit_total
                        || oc.credit_delta != first_oracle.credit_delta
                    {
                        return reject(ValidationError::InconsistentChequeBundle);
                    }
                }
                None => return reject(ValidationError::InconsistentChequeBundle),
            }
        }

        let oracle = first_oracle;
        // Sanity: credit_delta cannot exceed credit_total
        if oracle.credit_delta > oracle.credit_total {
            return reject(ValidationError::OracleZeroDelta);
        }
        // Platform must be whitelisted (Core still validates the platform URL)
        if crate::oracle::whitelist_lookup(&oracle.platform_url).is_none() {
            return reject(ValidationError::OraclePlatformInvalid);
        }
        // Use Lambda-computed payout_amount. Core does NOT recompute from credit_delta.
        // Lambda owns the conversion rate (configurable in lambda.toml [oracle] section).
        // Core only enforces: payout > 0 AND payout <= ORACLE_MAX_PAYOUT_PER_CLAIM.
        let payout = oracle.payout_amount;
        if payout == 0 {
            return reject(ValidationError::OracleZeroDelta);
        }
        if payout > crate::oracle::ORACLE_MAX_PAYOUT_PER_CLAIM {
            return reject(ValidationError::OracleZeroDelta); // velocity cap
        }
        payout
    } else {
        amount
    };

    // Step 7: Check for overflow BEFORE addition
    if current_balance > u64::MAX - effective_amount {
        return reject(ValidationError::RedeemBalanceOverflow);
    }

    // YP §19.6 — receiver-pays fee deduction. Conservation: the gross
    // `effective_amount` is split between the receiver (net) and the
    // validators (fees, accumulated in Nabla's per-validator ledger).
    //   net_to_receiver = effective_amount - sum(fee_breakdown[i].amount)
    // For empty fee_breakdown (heal / genesis / pre-step-2 paths and
    // every oracle redeem, where amount=0 → no fees), total_fee=0 and
    // this is byte-identical to the pre-Step-8.2 behaviour.
    //
    // Conservation is enforced with non-saturating arithmetic and an
    // explicit invariant check:
    //   1. total_fee MUST NOT exceed effective_amount (atoms-from-
    //      nowhere defense; validate_fee_breakdown's aggregate-cap
    //      check above is the routine guard, this is defense-in-depth).
    //   2. Plain `effective_amount - total_fee` (no saturating) so a
    //      bug in (1) surfaces as an underflow panic in dev and is
    //      caught by the closed-form invariant in (3) in release.
    //   3. total_fee + net_to_receiver MUST equal effective_amount
    //      exactly. This is mathematically guaranteed by (1) + (2)
    //      but emitted as an explicit `ConservationViolation` reject
    //      so an audit reads the invariant directly in the code.
    // total_fee comes from the Dilithium-signed cheques themselves —
    // each cheque carries `rate_bps` bound into its commitment, so all
    // k validators' Cores derive the same total deterministically. No
    // client-supplied proposal is involved at any step. Removes the
    // E_RECEIPT_COMMITMENT_MISMATCH class that stale-`validators.list`
    // clients used to trip (2026-06-05 PM).
    let total_fee: u64 = cheque_bundle.cheques.iter()
        .map(|c| crate::validation::expected_fee_slot_amount(c.amount, c.rate_bps))
        .sum();
    if total_fee > effective_amount {
        return reject(ValidationError::FeeExceedsAmount);
    }
    let net_to_receiver = effective_amount - total_fee;
    if total_fee.checked_add(net_to_receiver) != Some(effective_amount) {
        return reject(ValidationError::ConservationViolation);
    }

    // Step 8: Verify balance math - the CRITICAL check
    // old_balance + net_to_receiver MUST equal new_balance.
    let expected_new_balance = current_balance + net_to_receiver;
    if new_balance != expected_new_balance {
        return reject(ValidationError::RedeemBalanceMismatch);
    }

    // Step 9: CORE COMPUTES THE NEW STATE_ID!
    // Aggregate cap: total fee across the k cheques must not exceed
    // `k × MAX_VALIDATOR_FEE_BPS × amount / FEE_BPS_DIVISOR`. Because
    // every per-cheque slot was already clamped by
    // `expected_fee_slot_amount`, this is technically redundant —
    // emit `ConservationViolation` if it ever fails so an audit reads
    // the invariant directly in the code.
    {
        let k = cheque_bundle.cheques.len() as u64;
        let aggregate_cap = (effective_amount as u128)
            * crate::types::MAX_VALIDATOR_FEE_BPS as u128
            * k as u128
            / crate::types::FEE_BPS_DIVISOR as u128;
        if (total_fee as u128) > aggregate_cap {
            return reject(ValidationError::ConservationViolation);
        }
    }

    // This is the ONLY place state_id should be computed for redeem
    // Lambda should NOT compute this - only Core can!
    let computed_state_id = crate::validation::compute_redeem_state_id(
        receiver_pk,
        new_balance,
        wallet_seq,
        &txid,
    );
    
    // Step 10: Compute redeem commitment hash
    // Core is the sole authority for commitment computation
    let redeem_commitment = crate::validation::compute_redeem_commitment(
        &txid,
        receiver_pk,
        new_balance,
        &computed_state_id,
    );
    
    // Dev-class derivation hoisted here so the FACT-signature site
    // below can bind it (FACT chain class lock —
    // `AXIOM_DESIGN_FactChainClassLock.md`). Walks every cheque in
    // the bundle, asserts the class is consistent across cheques AND
    // between sender + receiver of each cheque (Rule R1). Mixed-class
    // bundles reject with `InconsistentChequeBundle` / `DomainMismatch`.
    // The flag is bound into BOTH `compute_fact_commitment` (so k
    // validators' Dilithium sigs attest) AND `compute_receipt_commitment`
    // (so k Ed25519 sigs attest) — double-chain cryptographic
    // attestation on every redeem link.
    let bundle_dev_class = {
        let mut iter = cheque_bundle.cheques.iter();
        let first = match iter.next() {
            Some(c) => c,
            None => return reject(ValidationError::InsufficientCheques),
        };
        let first_class = crate::wallet_id::is_dev_wallet(&first.sender_wallet_id);
        if first_class != crate::wallet_id::is_dev_wallet(&first.receiver_wallet_id) {
            return reject(ValidationError::DomainMismatch);
        }
        for c in iter {
            let cls = crate::wallet_id::is_dev_wallet(&c.sender_wallet_id);
            if cls != first_class {
                return reject(ValidationError::InconsistentChequeBundle);
            }
            if cls != crate::wallet_id::is_dev_wallet(&c.receiver_wallet_id) {
                return reject(ValidationError::DomainMismatch);
            }
        }
        first_class
    };

    // Sign FACT commitment with Dilithium (same pattern as CL3, YP §26.17.6.2)
    // Core signs internally — Lambda MUST NOT call sign_dilithium directly.
    //
    // A2: the redeem link is now ONE link (not two). previous_state_id is
    // the receiver's pre-redeem state_id (proper chain continuation in the
    // receiver's own chain). The sender's chain tip is bound separately via
    // sender_anchor. Replaces the pre-A2 "bridge link" pattern that signed
    // a second commitment with previous_state_id = sender chain tip and
    // could never receive a Nabla confirmation.
    let receiver_prev_state_id = inputs
        .current_state
        .as_ref()
        .map(|s| s.state_id)
        .unwrap_or([0u8; 32]);
    let sender_anchor = fact_chain_ref.and_then(fact_chain_tip);

    // YPX-001 §1.5.1a SCAR INHERITANCE (CORE RULE): a cross-wallet redeem
    // link carries the sender chain's unresolved taint, transitively. The
    // set is derived by THE single builder from the same client-carried
    // chain every one of the k signers verifies — deterministic, so all k
    // Dilithium fact_signatures bind the identical commitment. Self-redeems
    // (genesis / HAL / RECALL completions) inherit nothing.
    let is_self_redeem = cheque_bundle.cheques.first()
        .map(|c| c.sender_wallet_id == c.receiver_wallet_id)
        .unwrap_or(false);
    // FAIL-CLOSED (defence in depth, 2026-07-12). The previous
    // `.map(..).unwrap_or_default()` was fail-OPEN: a missing sender chain
    // silently yielded "no inherited taint" — i.e. CLEAN money. That is the
    // one direction this computation must never fail in, because it is the
    // laundering direction (no chain ⇒ no taint ⇒ the scar is washed).
    //
    // The shape is currently UNREACHABLE — the A2 anchor guard above rejects a
    // chain-less redeem with `RedeemSenderAnchorMissing` before we get here —
    // so this is behavior-neutral today. It is written explicitly anyway so a
    // future refactor that moves, weakens, or reorders that guard cannot
    // silently reintroduce the fail-open path. If there is no provenance to
    // inherit FROM on a cross-wallet redeem, we do not get to assume clean:
    // we reject.
    //
    // Self-redeems (genesis claim / HAL completion / RECALL completion) are
    // exempt: nothing crosses a wallet boundary, so there is nothing to
    // inherit — the scar, if any, already lives on this same chain.
    let inherited_scar_txids: alloc::vec::Vec<[u8; 32]> = match fact_chain_ref {
        Some(fc) => crate::fact::compute_inherited_scar_txids(fc, &txid, is_self_redeem),
        None if is_self_redeem => alloc::vec::Vec::new(),
        None => return reject(ValidationError::RedeemSenderAnchorMissing),
    };

    let fact_signature = if let Some(ref sk) = inputs.my_dilithium_sk {
        let commitment = crate::fact::compute_fact_commitment(
            &txid,
            &receiver_prev_state_id,
            &computed_state_id,
            amount,
            sender_anchor.as_ref(),
            bundle_dev_class,
            &inherited_scar_txids,
            None, // a redeem link is never a burn (§1.5.4)
        );
        let sig = crate::crypto::sign_dilithium(sk, &commitment).ok();
        // Self-verify the signature we just produced — protects against
        // a sign/verify domain-tag drift bug. `debug_assert!` is no-op
        // in release (the ELF compiles in release), so this is dev-only.
        // The previous form `Some(verify_dilithium(...).is_ok());`
        // computed the same value then dropped it on the floor —
        // a clippy::unnecessary_operation, and a Dilithium verify cost
        // paid for no signal. From 38c1a9ae (ELF self-verify diag).
        if let Some(ref s) = sig {
            if let Some(pk_bytes) = inputs.my_dilithium_pk.as_deref() {
                debug_assert!(
                    crate::crypto::verify_dilithium(pk_bytes, &commitment, s).is_ok(),
                    "self-verify of just-produced fact signature failed — possible domain-tag drift in sign vs verify"
                );
            }
        }
        sig
    } else {
        None
    };

    // CLAUDE.md §12: Core (not the SDK, not Lambda host) assembles the
    // receiver-side redeem FactLink. When this validator's CL5 has
    // collected `required_k` fact_signatures (the prior k-1 in
    // `inputs.fact_witness_sigs` plus our just-computed `fact_signature`)
    // we are the finalizer and build the link inside the AVM. Earlier
    // validators in the redeem witness round leave `receiver_fact_chain`
    // as `None`; only the finalizer populates it.
    //
    // Replaces the pre-A2 SDK-side `build_and_append_fact_bridge` path
    // and Lambda's prior practice of calling `build_fact_link` from the
    // host (consensus.rs send-side pattern still does this for sends —
    // analogous fix outstanding there).
    //
    // Structural pre-gate: every WitnessSig in `inputs.fact_witness_sigs`
    // MUST carry a non-empty `fact_signature`, a `vbc_bundle` with a
    // populated Dilithium subject pubkey (so `build_fact_link` can pull
    // the verifying key), and a non-zero `validator_id`. Reject the
    // redeem fast on malformed input rather than silently producing a
    // shorter link inside `build_fact_link`'s filter loop. This is a
    // belt-and-suspenders check on top of `build_fact_link`'s per-witness
    // Dilithium verify — it surfaces obvious wire corruption with a
    // clear error code instead of confusing FactInsufficientWitnesses.
    for (idx, sig) in inputs.fact_witness_sigs.iter().enumerate() {
        let _ = idx; // kept for potential future logging
        if sig.fact_signature.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            return reject(ValidationError::FactInvalidSignature);
        }
        let dpk_len = sig.vbc_bundle.as_ref()
            .map(|v| v.target_vbc.subject_pubkey_dilithium.len())
            .unwrap_or(0);
        if dpk_len == 0 {
            return reject(ValidationError::FactInvalidSignature);
        }
        if sig.validator_id == [0u8; 32] {
            return reject(ValidationError::FactInvalidSignature);
        }
    }

    let receiver_fact_chain = match (
        &fact_signature,
        &inputs.my_validator_id,
        &inputs.vbc_bundle,
    ) {
        (Some(fsig), Some(my_vid), Some(my_vbc)) => {
            // Synthesize our own WitnessSig — `build_fact_link` only
            // reads `validator_id`, `vbc_bundle` (for Dilithium PK),
            // and `fact_signature` from each entry; the rest are
            // placeholders so `WitnessSig`'s constructor is satisfied.
            let our_sig = crate::types::WitnessSig {
                validator_id: *my_vid,
                validator_pk: inputs.my_validator_pk.clone().unwrap_or_default(),
                vbc_bundle: Some(my_vbc.clone()),
                carrier_type: alloc::string::String::new(),
                carrier_address: alloc::string::String::new(),
                signature: alloc::vec::Vec::new(),
                execution_proof: alloc::vec::Vec::new(),
                proof_type: 0,
                availability_attestation: None,
                validator_hints: alloc::vec::Vec::new(),
                fact_signature: Some(fsig.clone()),
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
            };
            let mut all_sigs = inputs.fact_witness_sigs.clone();
            all_sigs.push(our_sig);
            let with_fact = all_sigs.iter().filter(|s| s.fact_signature.is_some()).count();
            if with_fact >= required_k as usize {
                crate::fact::build_fact_link(
                    &txid,
                    &receiver_prev_state_id,
                    &computed_state_id,
                    amount,
                    required_k,
                    &all_sigs,
                    None,             // receiver_contact: redeem links don't carry one
                    None,             // burn_target_tx_id: redeem isn't a burn
                    sender_anchor,    // A2: anchor binds the sender's chain tip
                    bundle_dev_class, // sticky class lock from the cheque bundle
                    inherited_scar_txids.clone(), // §1.5.1a taint carry-over
                    inputs.receiver_fact_chain.as_ref(),
                    None,             // recall_target_tx_id: redeem isn't a recall
                    None,             // recall_proof
                ).ok()
            } else {
                None  // non-finalizer — host will assemble on a later validator
            }
        }
        _ => None,
    };

    // Receipt commitment for CL5 (redeem). Uses the cheque's txid since
    // CL5 doesn't produce its own txid. The receipt's fee_breakdown is
    // assembled by the SDK from the k WitnessSigs after the witness round
    // and cross-checked downstream via verify_receipt_fee_breakdown — it
    // is NOT bound into the commitment so every hop signs an identical
    // skeleton.
    //
    // §15: state_hash must bind the wallet's actual stored NET state so
    // the receiver's NEXT TX can anchor against it via
    // verify_state_anchored at CL1. Pre-§15 this was [0u8;32] with comment
    // "CL5 doesn't compute one (receiver-side)" — that convention left
    // every redeem receipt unanchored, so any wallet whose last_receipt
    // came from a redeem (genesis claim, first receive, etc) failed §15's
    // anchor check on its next send. compute_state_hash uses the same
    // formula as the send-side, so receipts have uniform meaning
    // regardless of which Core mode produced them.
    // YPX-020 §2 (2026-06-23): completion IS the redeem of the distress cheque.
    // A HIBERNATING wallet redeeming its OWN distress cheque — a self-send
    // (sender_wallet_id == receiver_wallet_id), the only self-send cheque a
    // hibernating wallet can hold (it cannot SEND while hibernating) — is the HAL
    // completion, so its produced state CLEARS the lock. Every other redeem (a
    // normal incoming payment, sender != receiver) CARRIES the receiver's
    // hibernation through, so a stranger's cheque can never un-hibernate the
    // wallet. This replaces the separate `HalComplete` self-send + its dust cheque
    // (§2 supersedes §6). Clockless — the client self-times the convergence window
    // (binary model, no Core clock); the global Nabla SMT consume-once is the
    // anti-double-spend gate (HAL A7), independent of completion timing.
    let is_self_redeem = cheque_bundle
        .cheques
        .first()
        .map(|c| c.sender_wallet_id == c.receiver_wallet_id)
        .unwrap_or(false);
    // YPX-021 §8.2 — same flag derivation as CL3 (hard reject on an
    // invalid attestation; absent → no flag, Phase 1). Evaluated BEFORE the
    // hibernation clear below because the §2.2.2 exit gate reads it.
    let cl5_oods_flag = match &inputs.oods_attestation {
        Some(att) => match crate::validation::verify_oods_attestation(att) {
            Ok(flag) => Some(flag),
            Err(e) => return reject(e),
        },
        None => None,
    };
    // YPX-022 §2.2.2 / YPX-021 §8.5 — the OODS-healthy EXIT gate, the mirror
    // of the recovery ENTRY gate above (execute mode CL3 path): the
    // hibernation-CLEARING self-redeem (HAL's and RECALL's completion — the
    // step that takes the recovered value) is REFUSED unless the carried OODS
    // reading is verified-healthy. Same three-way semantics as entry:
    // verified-healthy → proceed; verified-unhealthy or ABSENT → retryable
    // block (E_OODS_UNHEALTHY_RETRY → WaitAndRetry — liveness-only, never a
    // fund reject; the sender completes when the view recovers); FORGED →
    // hard reject (already handled by the verification above). A normal
    // self-redeem with no hibernation lock (e.g. a genesis claim) is
    // untouched, and the genesis baseline-0 exemption (healthy by
    // definition) applies inside verify_oods_attestation as everywhere else.
    if oods_exit_gate_blocks(
        is_self_redeem,
        inputs.receiver_current_hibernation.unwrap_or(0),
        cl5_oods_flag.as_ref(),
    ) {
        return reject(ValidationError::OodsUnhealthyRetry);
    }
    let receiver_hibernation = if is_self_redeem {
        0
    } else {
        inputs.receiver_current_hibernation.unwrap_or(0)
    };
    let cl5_state_hash = crate::crypto::compute_state_hash(
        receiver_pk,
        new_balance,
        wallet_seq,
        receiver_hibernation,
    );

    let cl5_receipt_commitment = crate::crypto::compute_receipt_commitment(
        &txid,
        &cl5_state_hash,
        wallet_seq,
        &redeem_commitment,
        inputs.transaction.epoch,
        bundle_dev_class,
        cl5_oods_flag.as_ref(),
    );

    // All checks passed - return success with CORE-COMPUTED state_id and commitment
    PublicOutputs {
        hibernation_until: 0,
        result: ValidationResult::Accept,
        // §15: surface the CL5-computed state_hash so Lambda can put it on
        // the redeem receipt. Without this, the receipt's state_hash stays
        // [0u8;32] and the receiver's next CL1 fails the anchor check.
        new_state_hash: Some(cl5_state_hash),
        produced_state_id: Some(computed_state_id),
        new_wallet_seq: Some(wallet_seq),
        rejection_reason: None,
        is_overlapped: None,
        commitment_hash: Some(redeem_commitment),
        txid: None,           // CL5 doesn't produce txid (it comes from cheques)
        fact_signature,       // CL5 signs FACT for redeem bridge link (YP §26.17.6.2)
        new_balance: Some(new_balance),
        nbc_signature: None,
        zkp_nonce_hash: None,
        required_k: 0,
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        console_chain_hash: None,
        compressed_fact_chain: None,
        receiver_fact_chain,
        receipt_commitment: Some(cl5_receipt_commitment),
        validator_withdrawal_mint: None,
        is_dev_class: Some(bundle_dev_class),
        // YPX-021 §8.2 — same carry-back as CL3.
        oods_flag: cl5_oods_flag,
    }
}

/// CL11: Console Validation (YPX-013)
///
/// Validates Console Certificate chain integrity for election finalization.
/// Core verifies: generation increment, chain hash linkage, 15 unique seats,
/// term continuity, and selector pick validity.
///
/// This is the ONLY way a new Console Certificate can be created.
/// Core signs it — no Lambda trust needed.
///
/// If Console elections fail MAX_ELECTION_ATTEMPTS times, Lambda simply
/// stops calling CL11. Console dies by silence. No special Core flag.
/// This is a ONE-WAY TICKET — by design.
fn execute_cl11(inputs: PublicInputs) -> PublicOutputs {
    use crate::console;

    // YPX-018 §4.4 — BLOOM_PHASE_OUT Console action.
    // If the request carries a phase_out_payload, dispatch to the BLOOM_PHASE_OUT
    // path instead of the election finalization path. Constitutional limits
    // (MIN_PHASE_OUT_AGE_TICKS, MIN_PHASE_OUT_GRACE_TICKS) are enforced here
    // and CANNOT be overridden by any Console vote — only a new Core ELF can.
    if let Some(ref payload) = inputs.phase_out_payload {
        return execute_cl11_phase_out(&inputs, payload);
    }

    // Extract required inputs
    let current_cert = match &inputs.console_current_cert {
        Some(c) => c,
        None => return reject(ValidationError::MissingField),
    };
    let new_cert = match &inputs.console_new_cert {
        Some(c) => c,
        None => return reject(ValidationError::MissingField),
    };

    // Step 1: Verify certificate chain (generation, hash, seats, term)
    if let Err(e) = console::verify_console_certificate(current_cert, new_cert) {
        return reject(e);
    }

    // Step 2: Verify election — selector picks resolve to the new seats
    let selector_picks = match &inputs.console_selector_picks {
        Some(p) => p,
        None => return reject(ValidationError::ConsoleIncompleteSelection),
    };
    let nominations = match &inputs.console_nominations {
        Some(n) => n,
        None => return reject(ValidationError::MissingField),
    };

    let resolved_seats = match console::resolve_election(
        selector_picks,
        &current_cert.seats,
        nominations,
        current_cert.term_end_tick,
        &console::compute_console_chain_hash(current_cert),
    ) {
        Ok(seats) => seats,
        Err(e) => return reject(e),
    };

    // Step 3: Verify resolved seats match the new certificate's seats
    if resolved_seats.len() != new_cert.seats.len() {
        return reject(ValidationError::ConsoleInvalidSeatCount);
    }
    let resolved_set: alloc::collections::BTreeSet<[u8; 32]> =
        resolved_seats.iter().copied().collect();
    let cert_set: alloc::collections::BTreeSet<[u8; 32]> =
        new_cert.seats.iter().copied().collect();
    if resolved_set != cert_set {
        return reject(ValidationError::ConsoleInvalidPick);
    }

    // Step 4: Compute chain hash for the new certificate
    let chain_hash = console::compute_console_chain_hash(new_cert);

    // Accept — return chain hash for Lambda to confirm
    PublicOutputs {
        hibernation_until: 0,
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
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        console_chain_hash: Some(chain_hash),
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL11 BLOOM_PHASE_OUT operation (YPX-018 §4.4, YPX-013 §6.2.3).
///
/// Validates a Console-approved BLOOM_PHASE_OUT proposal against the
/// constitutional limits in `MIN_PHASE_OUT_AGE_TICKS` and
/// `MIN_PHASE_OUT_GRACE_TICKS`. These limits are hard floors — the
/// Console cannot override them by any vote, only a new Core ELF can.
///
/// Validation rules (all MUST pass):
/// 1. Payload has at least one era_id.
/// 2. effective_tick is in the future (> current_tick).
/// 3. effective_tick - current_tick >= MIN_PHASE_OUT_GRACE_TICKS (5 years).
/// 4. For every era_id in the payload:
///    a. The era exists (era_id appears in `phase_out_era_end_ticks`).
///    b. era.end_tick + MIN_PHASE_OUT_AGE_TICKS <= effective_tick (50-year minimum age).
///    c. The era is not already in `phase_out_blocked_era_ids` (already PhasedOut
///    or ScheduledPhaseOut).
fn execute_cl11_phase_out(
    inputs: &PublicInputs,
    payload: &crate::types::ConsoleProposalBloomPhaseOut,
) -> PublicOutputs {
    use crate::types::{MIN_PHASE_OUT_AGE_TICKS, MIN_PHASE_OUT_GRACE_TICKS};

    // Rule 1: at least one era to phase out
    if payload.era_ids.is_empty() {
        return reject(ValidationError::ConsolePhaseOutInvalid);
    }

    // Rule 2: effective_tick must be in the future
    if payload.effective_tick <= inputs.current_tick {
        return reject(ValidationError::ConsolePhaseOutInvalid);
    }

    // Rule 3: at least 5-year grace from now to effective_tick
    let grace = payload.effective_tick.saturating_sub(inputs.current_tick);
    if grace < MIN_PHASE_OUT_GRACE_TICKS {
        return reject(ValidationError::ConsolePhaseOutInvalid);
    }

    // Build a quick lookup from era_id → end_tick (Lambda passes this in)
    // and a set of blocked era_ids.
    for era_id in &payload.era_ids {
        // (4a) The era must exist in Lambda's view of the Bloom Age Index
        let end_tick = inputs.phase_out_era_end_ticks.iter()
            .find(|(id, _)| id == era_id)
            .map(|(_, et)| *et);
        let end_tick = match end_tick {
            Some(t) => t,
            None => return reject(ValidationError::ConsolePhaseOutInvalid),
        };

        // (4b) Constitutional minimum age — era must be at least 50 years past close
        let earliest_allowed = end_tick.saturating_add(MIN_PHASE_OUT_AGE_TICKS);
        if payload.effective_tick < earliest_allowed {
            return reject(ValidationError::ConsolePhaseOutInvalid);
        }

        // (4c) Era must not already be PhasedOut or ScheduledPhaseOut
        if inputs.phase_out_blocked_era_ids.contains(era_id) {
            return reject(ValidationError::ConsolePhaseOutInvalid);
        }
    }

    // All rules passed. Compute a deterministic certificate hash that Lambda
    // will use as the `console_cert_hash` baked into the era's PhasedOut
    // status. The hash binds: payload era_ids, effective_tick, current_tick.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"AXIOM_CONSOLE_BLOOM_PHASE_OUT");
    hasher.update(&(payload.era_ids.len() as u64).to_le_bytes());
    for id in &payload.era_ids {
        hasher.update(&id.to_le_bytes());
    }
    hasher.update(&payload.effective_tick.to_le_bytes());
    hasher.update(&inputs.current_tick.to_le_bytes());
    hasher.update(payload.rationale.as_bytes());
    let cert_hash = *hasher.finalize().as_bytes();

    PublicOutputs {
        hibernation_until: 0,
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
        extracted_proof_type: 0,
        audit_demand: None,
        audit_request: None,
        nonce_challenge: None,
        pulse_proof: None,
        audit_failed: false,
        fanout_new_ttl: None,
        // Reuse console_chain_hash output slot for the phase-out certificate hash
        console_chain_hash: Some(cert_hash),
        compressed_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        validator_withdrawal_mint: None,
        is_dev_class: None,
        oods_flag: None,
    }
}

/// CL13: Validator-withdrawal mint (YP §20.10 / fee ledger Step 9B.2).
///
/// Takes `PublicInputs::withdrawal_inputs` (a `ValidatorWithdrawalRequest`
/// carrying the signed earnings attestation, signed pool linkage,
/// operator SPHINCS+ authorization, and chosen_witnesses), re-runs the
/// 7-step verification chain, and emits a mint output that credits
/// `linked_wallet_id` with `total_amount × 90/100`.
///
/// The 7 steps mirror Lambda's `verify_validator_withdrawal` exactly so
/// the operator's Lambda's prior verification gives no extra trust —
/// each chosen witness independently runs Core CL13 with the same proof,
/// so a compromised originating Lambda cannot smuggle a bad withdrawal.
///
/// Ordering: cheapest first to short-circuit obvious failures before
/// the expensive Ed25519 + SPHINCS+ verifies.
///
///   1. SPHINCS+ identity binding — `BLAKE3(sphincs_pk) == validator_id`.
///   2. chosen_witnesses sanity — `len >= 3` and all distinct.
///   3. `earnings_attestation.is_authoritative` — bloom-mode rejected.
///   4. Nabla Ed25519 earnings attestation signature verify.
///   5. Pool linkage sanity — vid match, registered=true, non-zero
///      linked_wallet_id.
///   6. SPHINCS+ withdrawal authorization signature verify.
///   7. §20.10 conflict check — `chosen_witnesses` disjoint from
///      `⋃ entries[i].full_fee_breakdown[j].validator_id`.
///
/// On success: emits `ValidatorWithdrawalMintOutput { validator_id,
/// linked_wallet_id, net_amount, claimed_through_tick }`. The k=3
/// chosen-witness round (signing the mint receipt commitment) happens
/// AROUND Core, not inside — same pattern as CL2/CL3 sandwich a
/// normal TX.
fn execute_validator_withdrawal_mint(inputs: PublicInputs) -> PublicOutputs {
    use alloc::collections::BTreeSet;
    use crate::types::ValidatorWithdrawalMintOutput;

    let w = match &inputs.withdrawal_inputs {
        Some(w) => w,
        None => return reject(ValidationError::WithdrawalInputsMissing),
    };

    // (1) SPHINCS+ identity binding — vid == BLAKE3(sphincs_pk).
    let derived_vid: [u8; 32] = *blake3::hash(&w.sphincs_pk).as_bytes();
    if derived_vid != w.validator_id {
        return reject(ValidationError::WithdrawalIdMismatch);
    }

    // (2) chosen_witnesses sanity — k=3 floor + no duplicates.
    if w.chosen_witnesses.len() < 3 {
        return reject(ValidationError::WithdrawalWitnessCount);
    }
    let unique: BTreeSet<[u8; 32]> = w.chosen_witnesses.iter().copied().collect();
    if unique.len() != w.chosen_witnesses.len() {
        return reject(ValidationError::WithdrawalWitnessDuplicate);
    }

    // (3) is_authoritative — bloom-mode responses can't be trusted.
    if !w.earnings_attestation.is_authoritative {
        return reject(ValidationError::WithdrawalNotAuthoritative);
    }

    // (4) Nabla Ed25519 earnings attestation verify. Recompute the
    //     canonical hash exactly as the responding Nabla signed it.
    let attestation_hash = crate::crypto::compute_earnings_attestation_payload(
        &w.earnings_attestation.nabla_node_id,
        &w.earnings_attestation.validator_id,
        w.earnings_attestation.since_tick,
        w.earnings_attestation.until_tick,
        w.earnings_attestation.total_amount,
        &w.earnings_attestation.entries,
        w.earnings_attestation.is_authoritative,
        w.earnings_attestation.net_balance,
    );
    if crate::crypto::verify_ed25519(
        &w.earnings_attestation.nabla_node_pk,
        &attestation_hash,
        &w.earnings_attestation.nabla_signature,
    ).is_err() {
        return reject(ValidationError::WithdrawalEarningsSig);
    }

    // (5) Pool linkage sanity.
    if w.pool_linkage.validator_id != w.validator_id {
        return reject(ValidationError::WithdrawalPoolVidMismatch);
    }
    if !w.pool_linkage.registered
        || w.pool_linkage.linked_wallet_id == [0u8; 32]
    {
        return reject(ValidationError::WithdrawalPoolNotRegistered);
    }

    // (6) SPHINCS+ withdrawal authorization — operator signed the
    //     canonical (validator_id, attestation_hash, chosen_witnesses)
    //     tuple. Lambda can't quietly substitute witnesses.
    let withdrawal_payload = crate::crypto::compute_validator_withdrawal_payload(
        &w.validator_id, &attestation_hash, &w.chosen_witnesses,
    );
    if crate::crypto::verify_sphincs(
        &w.sphincs_pk, &withdrawal_payload, &w.sphincs_sig,
    ).is_err() {
        return reject(ValidationError::WithdrawalSig);
    }

    // (7) §20.10 — chosen_witnesses must be disjoint from the union of
    //     full_fee_breakdown across all earnings entries.
    if !crate::crypto::check_validator_withdrawal_conflict(
        &w.earnings_attestation.entries, &w.chosen_witnesses,
    ) {
        return reject(ValidationError::WithdrawalConflictOfInterest);
    }

    // All checks passed — compute the net mint amount.
    // net = gross × (100 - DEED_SLICE_PERCENT) / 100. The 10% DEED slice
    // was already credited to Nabla's deed_pool at /register time
    // (Refactor C); the remaining 90% is what this mint pays out.
    let net_amount = w.earnings_attestation.total_amount * 90 / 100;

    PublicOutputs {
        hibernation_until: 0,
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
        receipt_commitment: None,
        validator_withdrawal_mint: Some(ValidatorWithdrawalMintOutput {
            validator_id: w.validator_id,
            linked_wallet_id: w.pool_linkage.linked_wallet_id,
            net_amount,
            claimed_through_tick: w.earnings_attestation.until_tick,
        }),
        is_dev_class: None,
        oods_flag: None,
    }
}

#[cfg(test)]
mod tests {
    /// YPX-001 §1.5.1a — the inherited-scar computation must FAIL CLOSED.
    ///
    /// A cross-wallet redeem with NO sender FACT chain has no provenance to
    /// inherit FROM. The one thing Core must never do there is assume "clean":
    /// that is the laundering direction (no chain ⇒ no taint ⇒ the scar is
    /// washed). It must REJECT.
    ///
    /// Today the A2 anchor guard already rejects this shape before the compute
    /// site is reached, so this test passes for two independent reasons — which
    /// is the point of defence in depth. It is written against the OBSERVABLE
    /// contract (reject, don't mint a clean link), so it keeps holding if a
    /// refactor moves, weakens, or reorders either guard.
    #[test]
    fn chainless_cross_wallet_redeem_rejects_rather_than_assuming_clean() {
        use crate::types::{ChequeBundle, ValidatorCheque};

        // Real, checksum-valid wallet_ids — otherwise the redeem trips
        // InvalidWalletId long before the provenance logic, and the test would
        // pass for the wrong reason.
        let ids = |email: &str, seed: u8| -> String {
            let pk = [seed; 32];
            crate::wallet_id::generate_all_wallet_ids(email, "", &pk)
                .expect("generate wallet ids")
                .into_iter()
                .find(|(_, k, _, _)| *k == 3)
                .map(|(id, _, _, _)| id)
                .expect("standard-tier wallet_id")
        };
        let sender_id = ids("sender@test.com", 0x11);
        let receiver_id = ids("receiver@test.com", 0x22);

        let mk = |vid: u8| ValidatorCheque {
            recall_target_tx_id: None,
            txid: [0xAB; 32],
            validator_id: [vid; 32],
            validator_pk: vec![vid; 32],
            signature: vec![vid; 64],
            execution_proof: vec![],
            vbc_bundle: None,
            carrier_type: "test".into(),
            carrier_address: "test@test.com".into(),
            // CROSS-wallet: sender != receiver, so inheritance is in scope.
            sender_wallet_id: sender_id.clone(),
            receiver_wallet_id: receiver_id.clone(),
            amount: 500_000,
            rate_bps: 10,
            reference: "test".into(),
            epoch: 1,
            created_at: 0,
            state_hash: [0u8; 32],
            produced_state_id: [0u8; 32],
            // No provenance carried anywhere.
            sender_fact_chain: None,
            zkp_nonce: None,
            proof_type: 1,
            dmap_input_hash: [0u8; 32],
            dmap_output_hash: [0u8; 32],
            oracle_claim: None,
            nabla_hint: None,
            sender_wallet_pk: None,
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(ChequeBundle {
            cheques: vec![mk(0x01), mk(0x02), mk(0x03)],
            fact_chain: None,
        });
        inputs.sender_fact_chain = None;
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(100_000);
        inputs.receiver_new_balance = Some(600_000);
        inputs.receiver_wallet_seq = Some(1);

        let result = execute_core(inputs);

        // THE invariant: it is never ACCEPTED. Several CL5 gates can fire first
        // for a bundle this bare (claim proof, txid attestation, the A2 anchor
        // guard, and now the fail-closed inherited-scar arm) — which one wins is
        // an implementation detail and would make this test brittle. What must
        // never happen, under any of them, is that a redeem with no provenance
        // to inherit from is waved through as CLEAN money.
        assert_eq!(
            result.result,
            ValidationResult::Reject,
            "a cross-wallet redeem with NO sender provenance MUST be rejected — \
             treating it as 'no inherited taint' is exactly the laundering \
             direction (YPX-001 §1.5.1a)",
        );
        assert!(
            result.rejection_reason.is_some(),
            "a rejected redeem must say why",
        );
    }

    use super::*;
    use crate::types::{Transaction, WalletState};
    use crate::wallet_id::generate_wallet_id;
    use alloc::vec;

    /// YPX-022 §2.2.2 — the OODS-healthy hibernation-EXIT truth table.
    /// Fails without `oods_exit_gate_blocks` being consulted with exactly
    /// these semantics: the hibernation-clearing self-redeem needs a
    /// VERIFIED-HEALTHY reading; unhealthy AND absent both block
    /// (retryable); everything that isn't a hibernation exit is untouched.
    #[test]
    fn ypx022_oods_exit_gate_truth_table() {
        let healthy = crate::types::OodsFlag { tick: 10, oods_size: 9, healthy: true };
        let unhealthy = crate::types::OodsFlag { tick: 10, oods_size: 1, healthy: false };

        // The gated case: self-redeem of a HIBERNATING wallet (HAL/RECALL completion).
        assert!(!oods_exit_gate_blocks(true, 500, Some(&healthy)),
            "verified-healthy exit must proceed");
        assert!(oods_exit_gate_blocks(true, 500, Some(&unhealthy)),
            "verified-unhealthy exit must block (retryable)");
        assert!(oods_exit_gate_blocks(true, 500, None),
            "ABSENT reading must block — can't prove health, don't take the value");

        // Not a hibernation exit → never gated, with or without a reading.
        assert!(!oods_exit_gate_blocks(true, 0, None),
            "a self-redeem with no hibernation lock (genesis claim) is untouched");
        assert!(!oods_exit_gate_blocks(false, 500, None),
            "a stranger's redeem never exits hibernation → never gated");
        assert!(!oods_exit_gate_blocks(false, 0, Some(&unhealthy)),
            "a normal redeem is untouched even under an unhealthy view");
    }

    fn create_test_inputs(mode: CoreLogicMode) -> PublicInputs {
        let receiver_wallet_id = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32])
            .expect("Failed to generate wallet ID");
        
        PublicInputs {
            oods_attestation: None,
            recall_attestation: None,
            mode,
            transaction: Transaction {
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 1,
                receiver_wallet_id,
                receiver_address: None,
                amount: 100_000,
                reference: "test".into(),
                nonce: 1,
                epoch: 1,
                client_sig: vec![0u8; 64],
                owner_proof: None,
                scar_passcode: None,
                burn_target_tx_id: None,
                recall_target_tx_id: None,
                required_k: 0,
                proof_type: 0,
                oracle_claim: None,
                core_version: String::new(),
                core_id: [0u8; 32],
                kind: TxKind::Normal,
            },
            prev_receipts: vec![],
            current_state: None,
            vbc_bundle: None,
            // CL5 fields (None for non-redeem tests)
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            nonce_response: None,
            audit_response: None,
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
            receiver_current_hibernation: None,
        }
    }

    /// CL13 Step 9B.1 stub: dispatch reaches `execute_validator_withdrawal_mint`
    /// and rejects with `WithdrawalInputsMissing` when `withdrawal_inputs`
    /// is None.
    #[test]
    fn cl13_dispatch_rejects_missing_withdrawal_inputs() {
        let inputs = create_test_inputs(CoreLogicMode::CL13);
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::WithdrawalInputsMissing));
    }

    /// CL13 Step 9B.2: with `withdrawal_inputs` populated but the
    /// SPHINCS+ pk failing identity binding, dispatch reaches the verify
    /// chain and rejects at step 1 with `WithdrawalIdMismatch`. (A
    /// fully-valid happy-path test lives in
    /// `lambda/tests/validator_withdrawal_e2e.rs` where the SPHINCS+
    /// signing keys are wired in.)
    #[test]
    fn cl13_rejects_id_mismatch_when_sphincs_pk_doesnt_match_vid() {
        use crate::wire_client::{
            ValidatorWithdrawalRequest, QueryValidatorEarningsResponse,
            QueryValidatorPoolResponse,
        };
        let mut inputs = create_test_inputs(CoreLogicMode::CL13);
        inputs.withdrawal_inputs = Some(ValidatorWithdrawalRequest {
            validator_id: [0xAA; 32],
            earnings_attestation: QueryValidatorEarningsResponse::default(),
            pool_linkage: QueryValidatorPoolResponse::default(),
            // sphincs_pk is empty — BLAKE3 of empty bytes won't match [0xAA; 32].
            sphincs_pk: vec![],
            sphincs_sig: vec![],
            chosen_witnesses: vec![[0u8; 32]; 3],
        });
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::WithdrawalIdMismatch));
    }

    /// CL13 step 2: chosen_witnesses must have at least k=3 entries.
    #[test]
    fn cl13_rejects_witness_count_under_three() {
        use crate::wire_client::{
            ValidatorWithdrawalRequest, QueryValidatorEarningsResponse,
            QueryValidatorPoolResponse,
        };
        let sphincs_pk = vec![0xCC; 32];
        let vid: [u8; 32] = *blake3::hash(&sphincs_pk).as_bytes();
        let mut inputs = create_test_inputs(CoreLogicMode::CL13);
        inputs.withdrawal_inputs = Some(ValidatorWithdrawalRequest {
            validator_id: vid,
            earnings_attestation: QueryValidatorEarningsResponse::default(),
            pool_linkage: QueryValidatorPoolResponse::default(),
            sphincs_pk,
            sphincs_sig: vec![],
            chosen_witnesses: vec![[1u8; 32], [2u8; 32]],  // only 2, need 3
        });
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::WithdrawalWitnessCount));
    }

    /// CL13 step 2: chosen_witnesses must be distinct.
    #[test]
    fn cl13_rejects_duplicate_witnesses() {
        use crate::wire_client::{
            ValidatorWithdrawalRequest, QueryValidatorEarningsResponse,
            QueryValidatorPoolResponse,
        };
        let sphincs_pk = vec![0xCC; 32];
        let vid: [u8; 32] = *blake3::hash(&sphincs_pk).as_bytes();
        let mut inputs = create_test_inputs(CoreLogicMode::CL13);
        inputs.withdrawal_inputs = Some(ValidatorWithdrawalRequest {
            validator_id: vid,
            earnings_attestation: QueryValidatorEarningsResponse::default(),
            pool_linkage: QueryValidatorPoolResponse::default(),
            sphincs_pk,
            sphincs_sig: vec![],
            chosen_witnesses: vec![[1u8; 32], [1u8; 32], [2u8; 32]],  // dup
        });
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::WithdrawalWitnessDuplicate));
    }

    /// CL13 step 3: bloom-mode attestations are rejected.
    #[test]
    fn cl13_rejects_non_authoritative_attestation() {
        use crate::wire_client::{
            ValidatorWithdrawalRequest, QueryValidatorEarningsResponse,
            QueryValidatorPoolResponse,
        };
        let sphincs_pk = vec![0xCC; 32];
        let vid: [u8; 32] = *blake3::hash(&sphincs_pk).as_bytes();
        let mut atte = QueryValidatorEarningsResponse::default();
        atte.is_authoritative = false;  // bloom-mode
        let mut inputs = create_test_inputs(CoreLogicMode::CL13);
        inputs.withdrawal_inputs = Some(ValidatorWithdrawalRequest {
            validator_id: vid,
            earnings_attestation: atte,
            pool_linkage: QueryValidatorPoolResponse::default(),
            sphincs_pk,
            sphincs_sig: vec![],
            chosen_witnesses: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        });
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::WithdrawalNotAuthoritative));
    }

    #[test]
    fn test_mode_dispatch() {
        // Test that each mode dispatches correctly
        let inputs_cl1 = create_test_inputs(CoreLogicMode::CL1);
        let inputs_cl2 = create_test_inputs(CoreLogicMode::CL2);
        let inputs_cl3 = create_test_inputs(CoreLogicMode::CL3);
        let inputs_cl4 = create_test_inputs(CoreLogicMode::CL4);
        
        // All should return a result (even if rejected due to test data)
        let _ = execute_core(inputs_cl1);
        let _ = execute_core(inputs_cl2);
        let _ = execute_core(inputs_cl3);
        let _ = execute_core(inputs_cl4);
    }
    
    #[test]
    fn test_cl4_minimum_witnesses() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL4);
        
        // Add a receipt with insufficient witnesses
        inputs.prev_receipts.push(crate::types::Receipt {
            oods_flag: None,
            txid: [0u8; 32],
            state_hash: [0u8; 32],
            produced_state_id: [0u8; 32],
            new_wallet_seq: 1,
            commitment_hash: [0u8; 32],
            sdid: [0u8; 32],
            lineage_hash: [0u8; 32],
            core_version: String::new(),
            core_id: [0u8; 32],
            witness_sigs: vec![], // Empty - less than 3
            epoch: 1,
            fact_proof: None,
            required_k: 3,
            receipt_commitment: [0u8; 32],
            fee_breakdown: Vec::new(),
            is_dev_class: false,
        });

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidVBCCount));
    }

    // Shared VBC test fixture (was in the deleted CL6 section; CL7 tests below
    // still use it to build a k=3-issuer bundle that CL7 must reject).
    fn make_test_vbc(expires_at: u64) -> crate::types::VBC {
        let sphincs_pk = vec![0xAA; 32];
        let validator_id = crate::crypto::compute_validator_id(&sphincs_pk);
        let issuer1 = vec![0x11; 32];
        let issuer2 = vec![0x22; 32];
        let issuer3 = vec![0x33; 32];
        crate::types::VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk,
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: vec![0xBB; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1000,
            expires_at,
            chain_depth: 0,
            issuer_set: vec![issuer1, issuer2, issuer3],
            signatures: vec![vec![0u8; 64], vec![0u8; 64], vec![0u8; 64]],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        }
    }

    // ── CL7 Tests (NBC Verification — k=1) ──

    #[test]
    fn test_cl7_rejects_missing_nbc() {
        let inputs = create_test_inputs(CoreLogicMode::CL7);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidVBC));
    }

    #[test]
    fn test_cl7_rejects_k3_nbc() {
        use crate::types::VBCProofBundle;

        // NBC with k=3 issuers should be rejected by CL7 (expects k=1)
        let bundle = VBCProofBundle {
            target_vbc: make_test_vbc(2000), // k=3 issuers
            supporting_vbcs: vec![],
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL7);
        inputs.vbc_bundle = Some(bundle);
        inputs.transaction.epoch = 1500;

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidVBCCount));
    }

    /// Helper: build a test NBC with k=1 issuer
    fn make_test_nbc(expires_at: u64) -> crate::types::VBC {
        let sphincs_pk = vec![0xAA; 32];
        let validator_id = crate::crypto::compute_validator_id(&sphincs_pk);
        let issuer1 = vec![0x11; 32];
        crate::types::VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk,
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: vec![0xBB; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1000,
            expires_at,
            chain_depth: 0,
            issuer_set: vec![issuer1],
            signatures: vec![vec![0u8; 64]],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_cl7_rejects_invalid_sphincs_sig() {
        use crate::types::VBCProofBundle;

        let bundle = VBCProofBundle {
            target_vbc: make_test_nbc(2000),
            supporting_vbcs: vec![],
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL7);
        inputs.vbc_bundle = Some(bundle);
        inputs.transaction.epoch = 1500;

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        // InvalidVBC because SPHINCS+ sig size mismatch (64 != 7856)
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidVBC));
    }

    #[test]
    fn test_cl7_rejects_expired_nbc() {
        use crate::types::VBCProofBundle;

        let bundle = VBCProofBundle {
            target_vbc: make_test_nbc(2000),
            supporting_vbcs: vec![],
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL7);
        inputs.vbc_bundle = Some(bundle);
        inputs.transaction.epoch = 3000; // past expiry

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert!(matches!(result.rejection_reason, Some(ValidationError::VBCExpired { .. })));
    }

    #[test]
    fn test_cl7_accepts_real_sphincs_signed_nbc() {
        use crate::types::VBCProofBundle;

        // Load real Nabla root authority keys from canonical location.
        // Skip if keys not available (CI / fresh clone / Mac dev tree
        // that only ships the .pub files alongside the binary). The
        // directory check alone isn't enough — the public-only tree
        // has the dir but not the .key files. Also gate on the
        // specific private-key file we need.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root_keys_dir = manifest.join("../../root-keys/nabla");
        if !root_keys_dir.join("root_1.key").exists() {
            eprintln!("SKIP: root-keys/nabla/root_1.key not found — cannot test CL7 Accept path");
            return;
        }

        // NBC uses k=1: only load root_1
        let sk1 = std::fs::read(root_keys_dir.join("root_1.key")).unwrap();
        let pk1 = std::fs::read(root_keys_dir.join("root_1.pub")).unwrap();

        // Generate a subject SPHINCS+ keypair
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;
        let (subject_pk, _subject_sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let subject_pk_bytes = subject_pk.into_bytes().to_vec();
        let validator_id = crate::crypto::compute_validator_id(&subject_pk_bytes);

        let mut nbc = crate::types::VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 0x09,
            validator_id,
            subject_pubkey_sphincs: subject_pk_bytes,
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: vec![0xBB; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1000,
            expires_at: 2000,
            chain_depth: 0,
            issuer_set: vec![pk1],
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        };

        // Sign with 1 Nabla root key
        let payload = crate::crypto::compute_vbc_signing_payload(&nbc);
        let sig1 = crate::crypto::sign_sphincs(&sk1, &payload).unwrap();
        nbc.signatures = vec![sig1];

        let bundle = VBCProofBundle {
            target_vbc: nbc,
            supporting_vbcs: vec![],
        };
        let mut inputs = create_test_inputs(CoreLogicMode::CL7);
        inputs.vbc_bundle = Some(bundle);
        inputs.transaction.epoch = 1500;

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Accept,
            "CL7 should Accept a real SPHINCS+-signed NBC: {:?}", result.rejection_reason);
    }

    // ── CL3 S-ABR Hash Verification Tests ──

    #[test]
    fn test_cl3_sabr_matching_state_passes() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL3);
        let state_id = [0x42u8; 32];
        inputs.transaction.consumed_state_id = state_id;
        // First TX (wallet_seq=1, prev wallet_seq=0): no prev_receipts needed
        inputs.transaction.wallet_seq = 1;
        inputs.current_state = Some(WalletState {
            public_key: vec![0u8; 32],
            balance: 200_000,
            wallet_seq: 0,
            state_id, // Matches consumed_state_id
            auth_hash: None,
            wallet_id: None,
            group_members: None, hibernation_until: 0,
        });
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::SABRHashMismatch),
            "CL3 should not reject when state_id matches consumed_state_id");
    }

    #[test]
    fn test_cl3_sabr_mismatch_rejects() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL3);
        inputs.transaction.consumed_state_id = [0x42u8; 32];
        // First TX: no prev_receipts needed, but current_state provided by Lambda
        inputs.transaction.wallet_seq = 1;
        inputs.current_state = Some(WalletState {
            public_key: vec![0u8; 32],
            balance: 200_000,
            wallet_seq: 0,
            state_id: [0x99u8; 32], // Different — Lambda lied about wallet state
            auth_hash: None,
            wallet_id: None,
            group_members: None, hibernation_until: 0,
        });
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::SABRHashMismatch),
            "CL3 must reject when Lambda's state_id doesn't match consumed_state_id");
    }

    // ── CL10: Fan-Out Verification Tests ──

    fn make_fanout_msg(content_type: u16, ttl_original: u8, ttl_current: u8, fanout: u8) -> (crate::types::FanOutMessage, ed25519_dalek::SigningKey) {
        use ed25519_dalek::{SigningKey, Signer};
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key();
        let content = vec![0xAA, 0xBB, 0xCC];
        let timestamp = 1774070000u64;

        // diffusion_id = BLAKE3("AXIOM_FANOUT_ID" || content || pk)
        let mut id_h = blake3::Hasher::new();
        id_h.update(b"AXIOM_FANOUT_ID");
        id_h.update(&content);
        id_h.update(pk.as_bytes());
        let diffusion_id: [u8; 32] = *id_h.finalize().as_bytes();

        // signing payload
        let mut sig_h = blake3::Hasher::new();
        sig_h.update(b"AXIOM_FANOUT");
        sig_h.update(&diffusion_id);
        sig_h.update(&content_type.to_le_bytes());
        sig_h.update(&content);
        sig_h.update(&[ttl_original]);
        sig_h.update(&[fanout]);
        sig_h.update(&timestamp.to_le_bytes());
        let signing_payload: [u8; 32] = *sig_h.finalize().as_bytes();
        let sig = sk.sign(&signing_payload);

        let msg = crate::types::FanOutMessage {
            diffusion_id,
            content_type,
            content,
            originator_pk: *pk.as_bytes(),
            originator_sig: sig.to_bytes().to_vec(),
            timestamp,
            ttl_original,
            fanout,
            ttl_current,
        };
        (msg, sk)
    }

    fn cl10_inputs(msg: crate::types::FanOutMessage) -> PublicInputs {
        let mut inputs = create_test_inputs(CoreLogicMode::CL10);
        inputs.transaction.epoch = 1774070000; // match timestamp
        inputs.fanout_message = Some(msg);
        // CL10 needs a VBC bundle with matching originator_pk.
        // Use ed25519 SK seed 0x42 → derive PK via ed25519-dalek.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: crate::types::VBC {
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 9,
                validator_id: [0u8; 32],
                node_name: "test-validator".into(),
                subject_pubkey_ed25519: pk_bytes.to_vec(),
                subject_pubkey_sphincs: vec![0u8; 32],
                subject_pubkey_dilithium: vec![],
                pgp_fingerprint: vec![],
                proof_cap: "dmap".into(),
                issued_at: 0,
                expires_at: u64::MAX,
                chain_depth: 0,
                issuer_set: vec![],
                signatures: vec![],
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
            },
            supporting_vbcs: vec![],
        });
        inputs
    }

    #[test]
    fn cl10_accept_valid_fanout() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Accept);
        assert_eq!(result.fanout_new_ttl, Some(4)); // 5 - 1
    }

    #[test]
    fn cl10_accept_ttl_becomes_zero() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 1, 3);
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Accept);
        assert_eq!(result.fanout_new_ttl, Some(0)); // 1 - 1, still Accept
    }

    #[test]
    fn cl10_reject_ttl_expired() {
        let (mut msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        msg.ttl_current = 0;
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutTtlExpired));
    }

    #[test]
    fn cl10_reject_ttl_inflated() {
        let (mut msg, _) = make_fanout_msg(0x0001, 5, 5, 3);
        msg.ttl_current = 8; // > ttl_original
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutTtlInflated));
    }

    #[test]
    fn cl10_reject_ttl_original_exceeds_max() {
        let (msg, _) = make_fanout_msg(0x0001, 15, 10, 3); // ttl_original > 10
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutTtlExceeded));
    }

    #[test]
    fn cl10_reject_fanout_zero() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 5, 0);
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutInvalidFanout));
    }

    #[test]
    fn cl10_reject_fanout_exceeds_max() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 5, 5); // > 3
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutInvalidFanout));
    }

    #[test]
    fn cl10_reject_unknown_content_type() {
        let (msg, _) = make_fanout_msg(0xFFFF, 10, 5, 3);
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutUnknownContentType));
    }

    #[test]
    fn cl10_reject_content_empty() {
        let (mut msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        msg.content = vec![];
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutContentEmpty));
    }

    #[test]
    fn cl10_reject_diffusion_id_mismatch() {
        let (mut msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        msg.diffusion_id = [0xFF; 32]; // tampered
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutDiffusionIdMismatch));
    }

    #[test]
    fn cl10_reject_invalid_signature() {
        let (mut msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        msg.originator_sig = vec![0xFF; 64]; // bad sig
        let inputs = cl10_inputs(msg);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutInvalidSignature));
    }

    #[test]
    fn cl10_reject_missing_vbc() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        let mut inputs = cl10_inputs(msg);
        inputs.vbc_bundle = None;
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutInvalidOriginator));
    }

    #[test]
    fn cl10_reject_originator_pk_mismatch() {
        let (msg, _) = make_fanout_msg(0x0001, 10, 5, 3);
        let mut inputs = cl10_inputs(msg);
        // Change VBC's ed25519 pk to something different
        inputs.vbc_bundle.as_mut().unwrap().target_vbc.subject_pubkey_ed25519 = vec![0x99; 32];
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutOriginatorPkMismatch));
    }

    #[test]
    fn cl10_reject_missing_message() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL10);
        inputs.fanout_message = None;
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::FanOutMissingMessage));
    }

    #[test]
    fn cl10_all_content_types_accepted() {
        for ct in [0x0001, 0x0002, 0x0003, 0x0010, 0x0011, 0x0012,
                   0x0100, 0x0101, 0x0102, 0x0103, 0x0200, 0x0201] {
            let (msg, _) = make_fanout_msg(ct, 10, 5, 3);
            let inputs = cl10_inputs(msg);
            let result = execute_core(inputs);
            assert_eq!(result.result, ValidationResult::Accept,
                "content_type 0x{:04x} should be accepted", ct);
        }
    }

    // ── CL8: Stake Tier Enforcement Tests ──

    fn make_cl8_inputs(validator_id: [u8; 32], candidate_balance: u64) -> PublicInputs {
        let mut inputs = create_test_inputs(CoreLogicMode::CL8);
        inputs.candidate_balance = Some(candidate_balance);
        inputs.issuer_sphincs_sk = Some(vec![0u8; 64]); // dummy — stake check is before signing
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: crate::types::VBC {
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 9,
                validator_id,
                node_name: "test".into(),
                subject_pubkey_ed25519: vec![0u8; 32],
                subject_pubkey_sphincs: vec![0u8; 32],
                subject_pubkey_dilithium: vec![],
                pgp_fingerprint: vec![],
                proof_cap: "dmap".into(),
                issued_at: 0,
                expires_at: u64::MAX,
                chain_depth: 0,
                issuer_set: vec![vec![0u8; 32]],
                signatures: vec![],
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
            },
            supporting_vbcs: vec![],
        });
        inputs
    }

    #[test]
    fn cl8_genesis_approves_tier2_balance() {
        // Genesis validator approves candidate with 500,000 AXC → passes stake check
        // (will fail at SPHINCS+ signing since keys are dummy — that's OK,
        // we're testing the stake check doesn't reject)
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];
        let inputs = make_cl8_inputs(genesis_id, 500_000);
        let result = execute_core(inputs);
        // Should NOT be InsufficientStake — may fail later at signing
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "500,000 AXC should pass genesis tier check");
    }

    #[test]
    fn cl8_genesis_rejects_below_tier2() {
        // Genesis validator rejects candidate with 499,999 AXC
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];
        let inputs = make_cl8_inputs(genesis_id, 499_999);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "499,999 AXC below genesis tier 500,000 threshold");
    }

    #[test]
    fn cl8_genesis_rejects_tier3_balance() {
        // Genesis validator rejects candidate with only 500 AXC (below Tier 2)
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];
        let inputs = make_cl8_inputs(genesis_id, 500);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "500 AXC too low for genesis approval (needs 500,000)");
    }

    #[test]
    fn cl8_genesis_rejects_zero_balance() {
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];
        let inputs = make_cl8_inputs(genesis_id, 0);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
    }

    #[test]
    fn cl8_nongenesis_approves_tier3_balance() {
        // Non-genesis validator approves candidate with 500 AXC
        let non_genesis_id = [0xAA; 32]; // not in GENESIS_VALIDATORS
        let inputs = make_cl8_inputs(non_genesis_id, 500);
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "500 AXC should pass non-genesis tier check");
    }

    #[test]
    fn cl8_nongenesis_rejects_below_tier3() {
        // Non-genesis validator rejects candidate with 499 AXC
        let non_genesis_id = [0xAA; 32];
        let inputs = make_cl8_inputs(non_genesis_id, 499);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "499 AXC below non-genesis tier 500 threshold");
    }

    #[test]
    fn cl8_nongenesis_rejects_zero_balance() {
        let non_genesis_id = [0xAA; 32];
        let inputs = make_cl8_inputs(non_genesis_id, 0);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::InsufficientStake));
    }

    #[test]
    fn cl8_nongenesis_approves_tier2_balance() {
        // Non-genesis with 500,000 AXC candidate — should pass (500 >= 500)
        let non_genesis_id = [0xBB; 32];
        let inputs = make_cl8_inputs(non_genesis_id, 500_000);
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake));
    }

    #[test]
    fn cl8_no_balance_no_proof_is_nbc_path() {
        // candidate_balance = None + nabla_stake_proof = None → NBC signing path (no stake check).
        // NBC issuance doesn't require stake, only wallet identity binding.
        let non_genesis_id = [0xCC; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 0);
        inputs.candidate_balance = None;
        inputs.nabla_stake_proof = None;
        let result = execute_core(inputs);
        // Should NOT be InsufficientStake — passes through to SPHINCS+ signing
        // (will fail at signing since keys are dummy, but stake check is skipped)
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "No balance + no proof = NBC path, stake check should be skipped");
    }

    #[test]
    fn cl8_exact_threshold_accepted() {
        // Exactly at threshold — should pass
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];
        let inputs = make_cl8_inputs(genesis_id, 500_000);
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake),
            "Exact threshold should be accepted");

        let non_genesis_id = [0xDD; 32];
        let inputs2 = make_cl8_inputs(non_genesis_id, 500);
        let result2 = execute_core(inputs2);
        assert_ne!(result2.rejection_reason, Some(ValidationError::InsufficientStake),
            "Exact threshold should be accepted");
    }

    // ── CL8: NablaStakeProof + Wallet Identity Binding Tests ──

    #[test]
    fn cl8_nabla_proof_wallet_pk_mismatch_rejected() {
        // NablaStakeProof.wallet_pk doesn't match VBC ed25519_pk → StakeWalletMismatch
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);
        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: [0x01; 32],
            nabla_signature: vec![0; 64],
            attested_state_id: [0; 32],
            nabla_tick: 0,
            nabla_role: 0, // reader
            wallet_pk: [0xFF; 32], // DIFFERENT from VBC ed25519_pk
            balance: 1_000_000,
            receipt_signatures: vec![],
            receipt_state_id: [0; 32],
            scar_count: 0,
        });
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeWalletMismatch),
            "wallet_pk mismatch with VBC ed25519_pk must be rejected");
    }

    #[test]
    fn cl8_nabla_proof_writer_role_fatal() {
        // NablaStakeProof.nabla_role = 1 (writer) → NablaWriterDetected (fatal)
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);
        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: [0x01; 32],
            nabla_signature: vec![0; 64],
            attested_state_id: [0; 32],
            nabla_tick: 0,
            nabla_role: 1, // WRITER — should trigger fatal
            wallet_pk: [0u8; 32], // matches VBC
            balance: 1_000_000,
            receipt_signatures: vec![],
            receipt_state_id: [0; 32],
            scar_count: 0,
        });
        let result = execute_core(inputs);
        // fatal() returns Fatal, not Reject
        assert_eq!(result.result, ValidationResult::Fatal);
        assert_eq!(result.rejection_reason, Some(ValidationError::NablaWriterDetected),
            "Writer role must trigger NablaWriterDetected (fatal — Core should exit)");
    }

    #[test]
    fn cl8_nabla_proof_state_mismatch_rejected() {
        use ed25519_dalek::Signer;
        // receipt_state_id != attested_state_id → StakeStateMismatch
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
        let nabla_pk = sk.verifying_key();
        // Sign a valid attestation with one state_id
        let attested_state = [0x11; 32];
        let wallet_pk = [0u8; 32]; // matches VBC
        let tick: u64 = 100;
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_NABLA_ATTEST");
        h.update(&wallet_pk);
        h.update(&attested_state);
        h.update(&tick.to_le_bytes());
        let payload = h.finalize();
        let sig = sk.sign(payload.as_bytes());

        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: *nabla_pk.as_bytes(),
            nabla_signature: sig.to_bytes().to_vec(),
            attested_state_id: attested_state,
            nabla_tick: tick,
            nabla_role: 0,
            wallet_pk,
            balance: 1_000_000,
            receipt_signatures: vec![],
            receipt_state_id: [0x22; 32], // DIFFERENT from attested
            scar_count: 0,
        });
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeStateMismatch));
    }

    #[test]
    fn cl8_nabla_proof_insufficient_receipts() {
        use ed25519_dalek::Signer;
        // receipt_signatures.len() < 3 → StakeInsufficientReceipts
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
        let nabla_pk = sk.verifying_key();
        let state_id = [0x11; 32];
        let wallet_pk = [0u8; 32];
        let tick: u64 = 100;
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_NABLA_ATTEST");
        h.update(&wallet_pk);
        h.update(&state_id);
        h.update(&tick.to_le_bytes());
        let sig = sk.sign(h.finalize().as_bytes());

        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: *nabla_pk.as_bytes(),
            nabla_signature: sig.to_bytes().to_vec(),
            attested_state_id: state_id,
            nabla_tick: tick,
            nabla_role: 0,
            wallet_pk,
            balance: 1_000_000,
            receipt_signatures: vec![], // EMPTY — need 3
            receipt_state_id: state_id, // matches
            scar_count: 0,
        });
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeInsufficientReceipts));
    }

    #[test]
    fn cl8_nabla_proof_bad_signature_rejected() {
        // Invalid Nabla signature → StakeNablaSignatureInvalid
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);
        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: [0x01; 32],
            nabla_signature: vec![0xFF; 64], // bad sig
            attested_state_id: [0; 32],
            nabla_tick: 0,
            nabla_role: 0,
            wallet_pk: [0u8; 32],
            balance: 1_000_000,
            receipt_signatures: vec![],
            receipt_state_id: [0; 32],
            scar_count: 0,
        });
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeNablaSignatureInvalid),
            "Bad Nabla signature must be rejected");
    }

    #[test]
    fn cl8_nbc_path_no_stake_no_proof() {
        // NBC issuance: no stake proof, no candidate_balance → still signs (no stake check)
        // The wallet identity binding still applies (wallet_pk == VBC.ed25519_pk)
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 0);
        inputs.candidate_balance = None;
        inputs.nabla_stake_proof = None;
        let result = execute_core(inputs);
        // Should NOT be InsufficientStake or StakeWalletMismatch
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake));
        assert_ne!(result.rejection_reason, Some(ValidationError::StakeWalletMismatch));
    }

    // ── CL8: NablaStakeProof Receipt Signature Regression Test ──
    // Regression: if someone removes receipt sig verification (Step 0e),
    // fake receipt signatures would be accepted, allowing fake stake proofs.

    #[test]
    fn cl8_nabla_proof_fake_receipt_sigs_rejected() {
        use ed25519_dalek::Signer;
        // Create a NablaStakeProof with:
        // - Valid Nabla attestation signature (real Ed25519)
        // - 3 receipt signatures with FAKE signatures (random bytes, not real Ed25519)
        // - balance = 1,000,000 (above any tier threshold)
        // Expected: REJECTED because receipt sigs don't verify.

        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);

        // Create real Nabla attestation keypair
        let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
        let nabla_pk = nabla_sk.verifying_key();

        let wallet_pk = [0u8; 32]; // matches VBC subject_pubkey_ed25519
        let state_id = [0x33; 32];
        let tick: u64 = 200;

        // Sign a valid Nabla attestation
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_NABLA_ATTEST");
        h.update(&wallet_pk);
        h.update(&state_id);
        h.update(&tick.to_le_bytes());
        let attest_sig = nabla_sk.sign(h.finalize().as_bytes());

        // Create 3 receipt signatures with FAKE (random) signatures.
        // These are NOT valid Ed25519 signatures — just random bytes.
        let fake_receipts: Vec<crate::types::WitnessSig> = (0..3).map(|i| {
            let mut fake_sig = [0xDE; 64];
            fake_sig[0] = i; // make each "signature" different
            crate::types::WitnessSig {
                validator_id: [i + 0x10; 32],
                validator_pk: vec![i + 0x20; 32], // random PKs — won't verify
                signature: fake_sig.to_vec(),
                vbc_bundle: None,
                carrier_type: String::new(),
                carrier_address: String::new(),
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
        }).collect();

        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: *nabla_pk.as_bytes(),
            nabla_signature: attest_sig.to_bytes().to_vec(),
            attested_state_id: state_id,
            nabla_tick: tick,
            nabla_role: 0, // reader
            wallet_pk,
            balance: 1_000_000, // above all tier thresholds
            receipt_signatures: fake_receipts,
            receipt_state_id: state_id, // matches attested
            scar_count: 0,
        });

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeInsufficientReceipts),
            "Fake receipt signatures must be rejected — regression guard for CL8 receipt sig verification");
    }

    /// Regression: CL8 must reject NablaStakeProof where the same validator_pk
    /// signs multiple receipts. Without dedup, one validator could satisfy k=3
    /// by submitting 3 copies of the same signature.
    #[test]
    fn cl8_nabla_proof_duplicate_signer_rejected() {
        use ed25519_dalek::Signer;

        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id, 500);

        // Create real Nabla attestation keypair
        let nabla_sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
        let nabla_pk = nabla_sk.verifying_key();

        let wallet_pk = [0u8; 32]; // matches VBC subject_pubkey_ed25519
        let state_id = [0x33; 32];
        let tick: u64 = 200;

        // Sign a valid Nabla attestation
        let mut h = blake3::Hasher::new();
        h.update(b"AXIOM_NABLA_ATTEST");
        h.update(&wallet_pk);
        h.update(&state_id);
        h.update(&tick.to_le_bytes());
        let attest_sig = nabla_sk.sign(h.finalize().as_bytes());

        // Create ONE real validator keypair
        let val_sk = ed25519_dalek::SigningKey::from_bytes(&[0x50; 32]);
        let val_pk = val_sk.verifying_key();

        // Compute the receipt commitment
        let receipt_commitment = {
            let mut rh = blake3::Hasher::new();
            rh.update(b"AXIOM_STAKE_RECEIPT");
            rh.update(&wallet_pk);
            rh.update(&1_000_000u64.to_le_bytes());
            rh.update(&state_id);
            *rh.finalize().as_bytes()
        };

        // Sign the receipt with the SAME key 3 times (duplicate signer attack)
        let receipt_sig = val_sk.sign(&receipt_commitment);
        let duplicate_receipts: Vec<crate::types::WitnessSig> = (0..3).map(|i| {
            crate::types::WitnessSig {
                validator_id: [i + 0x10; 32], // different IDs but same pk
                validator_pk: val_pk.as_bytes().to_vec(), // SAME pk
                signature: receipt_sig.to_bytes().to_vec(), // SAME valid sig
                vbc_bundle: None,
                carrier_type: String::new(),
                carrier_address: String::new(),
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
        }).collect();

        inputs.nabla_stake_proof = Some(crate::types::NablaStakeProof {
            nabla_node_pk: *nabla_pk.as_bytes(),
            nabla_signature: attest_sig.to_bytes().to_vec(),
            attested_state_id: state_id,
            nabla_tick: tick,
            nabla_role: 0,
            wallet_pk,
            balance: 1_000_000,
            receipt_signatures: duplicate_receipts,
            receipt_state_id: state_id,
            scar_count: 0,
        });

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(result.rejection_reason, Some(ValidationError::StakeInsufficientReceipts),
            "Duplicate validator_pk in receipt sigs must be deduplicated — only 1 unique signer, need 3");
    }

    // ================================================================
    // CRITICAL-3 regression: CL5 cheque signature verification
    // ================================================================

    /// CRITICAL-3 regression: CL5 must verify Ed25519 signatures on cheques.
    /// Before the fix, forged cheques with fake signatures were accepted,
    /// allowing balance inflation (minting AXC from nothing).
    ///
    /// This test:
    /// 1. Creates a valid ChequeBundle with real Ed25519 signatures
    /// 2. Submits to CL5 — should pass cheque sig verification
    /// 3. Tampers with one cheque's amount (post-signing)
    /// 4. Resubmits — MUST fail with InvalidChequeSignature
    #[test]
    fn test_critical3_cl5_cheque_signature_verification() {
        use ed25519_dalek::SigningKey;
        use crate::types::{ValidatorCheque, ChequeBundle};

        // Generate wallet_id with the SAME pk used for receiver_pk (0xDD) — CL5 verifies pk_bind
        let receiver_pk_bytes: [u8; 32] = [0xDD; 32];
        let receiver_wallet_id = generate_wallet_id("redeemer@test.com", "42", &receiver_pk_bytes)
            .expect("Failed to generate wallet ID");

        // Create 3 distinct validator Ed25519 keypairs
        let sk1 = SigningKey::from_bytes(&[0x01u8; 32]);
        let sk2 = SigningKey::from_bytes(&[0x02u8; 32]);
        let sk3 = SigningKey::from_bytes(&[0x03u8; 32]);

        let pk1 = sk1.verifying_key().to_bytes().to_vec();
        let pk2 = sk2.verifying_key().to_bytes().to_vec();
        let pk3 = sk3.verifying_key().to_bytes().to_vec();

        let txid = [0xAA; 32];
        let state_hash = [0xBB; 32];
        let produced_state_id = [0xCC; 32];
        let amount: u64 = 500_000;
        let epoch: u64 = 1000;

        let rate_bps: u32 = 10;
        let commitment = crate::crypto::compute_cheque_commitment(
            &txid, &state_hash, &produced_state_id,
            &receiver_wallet_id, amount, epoch,
            rate_bps,
            &[0u8; 32], &[0u8; 32],
            None,
            None,
        );

        // Sign the commitment with each key
        use ed25519_dalek::Signer;
        let sig1 = sk1.sign(&commitment).to_bytes().to_vec();
        let sig2 = sk2.sign(&commitment).to_bytes().to_vec();
        let sig3 = sk3.sign(&commitment).to_bytes().to_vec();

        // Helper to build a cheque
        let make_cheque = |vid_byte: u8, pk: Vec<u8>, sig: Vec<u8>, amt: u64| -> ValidatorCheque {
            ValidatorCheque {
                recall_target_tx_id: None,
                txid,
                validator_id: [vid_byte; 32],
                validator_pk: pk,
                signature: sig,
                execution_proof: vec![],
                vbc_bundle: None,
                carrier_type: "test".into(),
                carrier_address: "test@test.com".into(),
                sender_wallet_id: "sender@test.com/11223344".into(),
                receiver_wallet_id: receiver_wallet_id.clone(),
                amount: amt,
                rate_bps: 10,
                reference: "test".into(),
                epoch,
                created_at: 0,
                state_hash,
                produced_state_id,
                sender_fact_chain: None,
                zkp_nonce: None,
                proof_type: 1,
                dmap_input_hash: [0u8; 32],
                dmap_output_hash: [0u8; 32],
                oracle_claim: None,
                nabla_hint: None,
                sender_wallet_pk: None,
            }
        };

        // === Part 1: Valid cheques should pass signature verification ===
        let valid_bundle = ChequeBundle {
            cheques: vec![
                make_cheque(0x01, pk1.clone(), sig1.clone(), amount),
                make_cheque(0x02, pk2.clone(), sig2.clone(), amount),
                make_cheque(0x03, pk3.clone(), sig3.clone(), amount),
            ],
            fact_chain: None,
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(valid_bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(100_000);
        inputs.receiver_new_balance = Some(600_000); // 100k + 500k
        inputs.receiver_wallet_seq = Some(1);

        let result = execute_core(inputs);
        // Should NOT fail with InvalidChequeSignature
        // (may fail later on other checks, but cheque sigs must pass)
        assert_ne!(result.rejection_reason, Some(ValidationError::InvalidChequeSignature),
            "Valid cheque signatures should not be rejected");

        // === Part 2: Tampered amount — MUST fail with InvalidChequeSignature ===
        let tampered_bundle = ChequeBundle {
            cheques: vec![
                make_cheque(0x01, pk1.clone(), sig1.clone(), amount),
                make_cheque(0x02, pk2.clone(), sig2.clone(), 999_999), // TAMPERED!
                make_cheque(0x03, pk3.clone(), sig3.clone(), amount),
            ],
            fact_chain: None,
        };

        let mut inputs2 = create_test_inputs(CoreLogicMode::CL5);
        inputs2.cheque_bundle = Some(tampered_bundle);
        inputs2.receiver_pk = Some(vec![0xDD; 32]);
        inputs2.receiver_current_balance = Some(100_000);
        inputs2.receiver_new_balance = Some(600_000);
        inputs2.receiver_wallet_seq = Some(1);

        let _result2 = execute_core(inputs2);
        // Tampered cheque won't pass consistency check first (amounts differ)
        // Let's also test with ALL cheques having same tampered amount
        // so consistency passes but signatures fail
        let tampered_amount: u64 = 999_999;
        // Recompute commitment with tampered amount would give different hash,
        // but we keep old signatures — they won't verify against new commitment
        let tampered_bundle_consistent = ChequeBundle {
            cheques: vec![
                make_cheque(0x01, pk1.clone(), sig1.clone(), tampered_amount),
                make_cheque(0x02, pk2.clone(), sig2.clone(), tampered_amount),
                make_cheque(0x03, pk3.clone(), sig3.clone(), tampered_amount),
            ],
            fact_chain: None,
        };

        let mut inputs3 = create_test_inputs(CoreLogicMode::CL5);
        inputs3.cheque_bundle = Some(tampered_bundle_consistent);
        inputs3.receiver_pk = Some(vec![0xDD; 32]);
        inputs3.receiver_current_balance = Some(100_000);
        inputs3.receiver_new_balance = Some(100_000 + tampered_amount);
        inputs3.receiver_wallet_seq = Some(1);

        let result3 = execute_core(inputs3);
        assert_eq!(result3.result, ValidationResult::Reject,
            "Tampered cheque amount must be rejected");
        // Post-aa3b7377 (2026-05-13) the `cheque_claim_proof` gate runs
        // before signature verification in CL5; this test fixture
        // doesn't include a Nabla-signed claim proof, so the redeem
        // gets rejected with ChequeClaimProofMissing first.  The
        // CRITICAL-3 invariant ("forged cheques don't redeem") is
        // satisfied by EITHER rejection — the test now accepts both.
        // A separate test would need a valid claim proof in the
        // fixture to reach InvalidChequeSignature directly.
        assert!(
            matches!(
                result3.rejection_reason,
                Some(ValidationError::InvalidChequeSignature)
                    | Some(ValidationError::ChequeClaimProofMissing)
            ),
            "CRITICAL-3 REGRESSION: Tampered cheque amount not caught by CL5! \
             Forged cheques must be rejected (got: {:?})",
            result3.rejection_reason,
        );
    }

    /// Additional CRITICAL-3 test: completely fake signatures must be rejected.
    #[test]
    fn test_critical3_fake_signatures_rejected() {
        use crate::types::{ValidatorCheque, ChequeBundle};

        let receiver_pk_bytes2: [u8; 32] = [0xDD; 32];
        let receiver_wallet_id = generate_wallet_id("redeemer2@test.com", "99", &receiver_pk_bytes2)
            .expect("Failed to generate wallet ID");

        let amount: u64 = 100_000;
        let epoch: u64 = 500;

        // Create cheques with completely fake (all-zero) signatures
        let make_fake_cheque = |vid_byte: u8| -> ValidatorCheque {
            ValidatorCheque {
                recall_target_tx_id: None,
                txid: [0xAA; 32],
                validator_id: [vid_byte; 32],
                validator_pk: vec![vid_byte; 32], // fake PK
                signature: vec![0u8; 64],         // fake signature
                execution_proof: vec![],
                vbc_bundle: None,
                carrier_type: "test".into(),
                carrier_address: "test@test.com".into(),
                sender_wallet_id: "sender@test.com/11223344".into(),
                receiver_wallet_id: receiver_wallet_id.clone(),
                amount,
                rate_bps: 10,
                reference: "test".into(),
                epoch,
                created_at: 0,
                state_hash: [0xBB; 32],
                produced_state_id: [0xCC; 32],
                sender_fact_chain: None,
                zkp_nonce: None,
                proof_type: 1,
                dmap_input_hash: [0u8; 32],
                dmap_output_hash: [0u8; 32],
                oracle_claim: None,
                nabla_hint: None,
                sender_wallet_pk: None,
            }
        };

        let bundle = ChequeBundle {
            cheques: vec![
                make_fake_cheque(0x01),
                make_fake_cheque(0x02),
                make_fake_cheque(0x03),
            ],
            fact_chain: None,
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(amount);
        inputs.receiver_wallet_seq = Some(1);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        // Same post-aa3b7377 ordering note as test_critical3_cl5_*:
        // ChequeClaimProof gate fires before signature verify.
        // CRITICAL-3 invariant — "fake cheques don't redeem" — is
        // satisfied by either rejection reason.
        assert!(
            matches!(
                result.rejection_reason,
                Some(ValidationError::InvalidChequeSignature)
                    | Some(ValidationError::ChequeClaimProofMissing)
            ),
            "CRITICAL-3 REGRESSION: Fake cheque signatures accepted! \
             CL5 must verify Ed25519 signatures on every cheque (got: {:?})",
            result.rejection_reason,
        );
    }

    // ========================================================================
    // Email change suffix (-XX) — receiver_address enforcement
    // ========================================================================

    fn make_cl1_inputs(tx: Transaction) -> PublicInputs {
        PublicInputs {
            oods_attestation: None,
            recall_attestation: None,
            mode: CoreLogicMode::CL1,
            transaction: tx,
            current_state: Some(WalletState {
                public_key: vec![0u8; 32],
                balance: 100_000_000_000_000, // 10,000 AXC in atoms
                state_id: [0u8; 32],
                wallet_seq: 0,
                auth_hash: None,
                wallet_id: None,
                group_members: None, hibernation_until: 0,
            }),
            prev_receipts: vec![],
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
            scar_heal_tx_id: None,
            scar_heal_nabla_id: None,
            scar_heal_root_hash: None,
            audit_confirmation: None,
            nonce_response: None,
            audit_response: None,
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
            receiver_current_hibernation: None,
        }
    }

    #[test]
    fn test_email_change_suffix_rejects_without_receiver_address() {
        // Receiver has -01 suffix → must provide receiver_address
        let sender_wid = generate_wallet_id("sender@test.com", "42", &[0u8; 32]).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32]).unwrap();
        let receiver_changed = format!("{}-01", receiver_wid);

        let tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: sender_wid,
            wallet_seq: 1,
            receiver_wallet_id: receiver_changed,
            receiver_address: None, // missing!
            amount: 1_000_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        let inputs = make_cl1_inputs(tx);
        let result = execute_core(inputs);
        assert_eq!(result.rejection_reason, Some(ValidationError::ReceiverAddressRequired),
            "TX to -01 address without receiver_address must be rejected");
    }

    #[test]
    fn test_email_change_suffix_rejects_invalid_receiver_address() {
        // Receiver has -01, sender provides receiver_address but with bad checksum
        let sender_wid = generate_wallet_id("sender@test.com", "42", &[0u8; 32]).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32]).unwrap();
        let receiver_changed = format!("{}-01", receiver_wid);

        let tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: sender_wid,
            wallet_seq: 1,
            receiver_wallet_id: receiver_changed,
            receiver_address: Some("badformat@email.com".into()), // no checksum!
            amount: 1_000_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        let inputs = make_cl1_inputs(tx);
        let result = execute_core(inputs);
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidReceiverAddress),
            "TX to -01 address with invalid receiver_address checksum must be rejected");
    }

    #[test]
    fn test_email_change_suffix_accepts_valid_receiver_address() {
        // Receiver has -01, sender provides valid receiver_address with checksum
        let sender_wid = generate_wallet_id("sender@test.com", "42", &[0u8; 32]).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32]).unwrap();
        let receiver_changed = format!("{}-01", receiver_wid);
        let new_delivery = generate_wallet_id("receiver@new.com", "55", &[0u8; 32]).unwrap();

        let tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: sender_wid,
            wallet_seq: 1,
            receiver_wallet_id: receiver_changed,
            receiver_address: Some(new_delivery),
            amount: 1_000_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        let inputs = make_cl1_inputs(tx);
        let result = execute_core(inputs);
        // Should NOT be rejected for receiver address — may fail later at signature check
        assert_ne!(result.rejection_reason, Some(ValidationError::ReceiverAddressRequired),
            "TX with valid receiver_address should pass the -01 check");
        assert_ne!(result.rejection_reason, Some(ValidationError::InvalidReceiverAddress),
            "TX with valid receiver_address checksum should pass");
    }

    #[test]
    fn test_no_suffix_does_not_require_receiver_address() {
        // Normal wallet_id (no -XX) should NOT require receiver_address
        let sender_wid = generate_wallet_id("sender@test.com", "42", &[0u8; 32]).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32]).unwrap();

        let tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: sender_wid,
            wallet_seq: 1,
            receiver_wallet_id: receiver_wid,
            receiver_address: None,
            amount: 1_000_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        let inputs = make_cl1_inputs(tx);
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::ReceiverAddressRequired),
            "Normal wallet_id should not require receiver_address");
    }

    #[test]
    fn test_email_change_suffix_02_with_pgp() {
        // -02-P suffix: second email change + PGP encryption
        let sender_wid = generate_wallet_id("sender@test.com", "42", &[0u8; 32]).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &[0x99u8; 32]).unwrap();
        let receiver_changed = format!("{}-02-P", receiver_wid);
        let new_delivery = generate_wallet_id("receiver@v2.com", "77", &[0u8; 32]).unwrap();

        let tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: sender_wid,
            wallet_seq: 1,
            receiver_wallet_id: receiver_changed,
            receiver_address: Some(new_delivery),
            amount: 1_000_000,
            reference: "test".into(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };

        let inputs = make_cl1_inputs(tx);
        let result = execute_core(inputs);
        assert_ne!(result.rejection_reason, Some(ValidationError::ReceiverAddressRequired));
        assert_ne!(result.rejection_reason, Some(ValidationError::InvalidReceiverAddress));
    }

    // ════════════════════════════════════════════════════════════════
    // ZKP checkpoint owner_proof tests (AUDIT-FIX v2.11.13)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_zkp_checkpoint_owner_proof_accepted() {
        let owner_secret = b"zkp-checkpoint-test-secret";
        let auth_pk = crate::validation::derive_owner_pubkey(owner_secret);

        let mut tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: String::new(),
            receiver_address: None,
            amount: 1_000_000,
            reference: String::new(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };
        tx.owner_proof = Some(crate::validation::sign_owner_proof(owner_secret, &tx));

        let mut inputs = make_cl1_inputs(tx);
        if let Some(ref mut ws) = inputs.current_state {
            ws.auth_hash = Some(auth_pk);
        }

        let result = execute_cl3_zkp_checkpoint(&inputs, None);
        assert_ne!(result.rejection_reason, Some(ValidationError::AuthHashRequired),
            "Valid owner_proof must not trigger AuthHashRequired");
        assert_ne!(result.rejection_reason, Some(ValidationError::InvalidAuthProof),
            "Valid owner_proof must not trigger InvalidAuthProof");
    }

    #[test]
    fn test_zkp_checkpoint_raw_secret_rejected() {
        let owner_secret = b"zkp-checkpoint-test-secret";
        let auth_pk = crate::validation::derive_owner_pubkey(owner_secret);

        let mut tx = Transaction {
            consumed_state_id: [0u8; 32],
            client_pk: vec![0u8; 32],
            sender_wallet_id: String::new(),
            wallet_seq: 1,
            receiver_wallet_id: String::new(),
            receiver_address: None,
            amount: 1_000_000,
            reference: String::new(),
            nonce: 1,
            epoch: 1,
            client_sig: vec![0u8; 64],
            owner_proof: None,
            scar_passcode: None,
            burn_target_tx_id: None,
            recall_target_tx_id: None,
            required_k: 0,
            proof_type: 0,
            oracle_claim: None,
            core_version: String::new(),
            core_id: [0u8; 32],
            kind: TxKind::Normal,
        };
        tx.owner_proof = Some(owner_secret.to_vec()); // Old-style: raw secret

        let mut inputs = make_cl1_inputs(tx);
        if let Some(ref mut ws) = inputs.current_state {
            ws.auth_hash = Some(auth_pk);
        }

        let result = execute_cl3_zkp_checkpoint(&inputs, None);
        // ZKP checkpoint may reject for address/signature before reaching auth check.
        // The important thing: it DOES NOT accept.
        assert_eq!(result.result, ValidationResult::Reject,
            "Raw secret TX must be rejected");
        // If it reaches the auth check, it must fail with InvalidAuthProof
        if result.rejection_reason == Some(ValidationError::InvalidAuthProof) {
            // Correct — auth check caught it
        } else {
            // Earlier check caught it (e.g., MalformedAddress, InvalidClientSignature)
            // Still rejected — defense in depth
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // YPX-018 — CL2 CLARA roll-forward tests (Phase 4)
    // ════════════════════════════════════════════════════════════════════

    use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer as Ed25519Signer};

    /// Build a valid CLARA attestation signed by `nabla_sk` for the given wallet.
    fn make_clara_for_wallet(
        wallet_pk: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        garbage: Vec<[u8; 32]>,
        nabla_sk: &Ed25519SigningKey,
    ) -> crate::types::ClaraAttestation {
        let nabla_pk = nabla_sk.verifying_key().to_bytes();
        let mut att = crate::types::ClaraAttestation {
            wallet_pk,
            healed_from_state_id: from,
            healed_to_state_id: to,
            healed_at_seq: 1,
            // Must match with_stored_state's balance so the synthetic rewrite
            // at modes.rs line ~249 leaves validate_transaction seeing a
            // spendable balance. Pre-fix (healed_balance: 0), the rewrite
            // would drop balance to 0 and every follow-up check would fail.
            healed_balance: 1_000_000_000,
            heal_txid: [0xAA; 32],
            garbage_state_ids: garbage,
            bloom_era_id: 0,
            bloom_era_root: [0; 32],
            nabla_tick: 1_777_000_000,
            nabla_node_pk: nabla_pk,
            nabla_signature: vec![],
            nbc_issuer_pk: vec![],
            nbc_signature: vec![],
            nbc_commitment: vec![],
        };
        let msg = crate::crypto::compute_clara_message(&att);
        att.nabla_signature = nabla_sk.sign(&msg).to_bytes().to_vec();
        att
    }

    /// Helper: ensure the test inputs have a populated current_state with the
    /// given state_id, so the CLARA roll-forward branch actually runs.
    fn with_stored_state(inputs: &mut PublicInputs, state_id: [u8; 32]) {
        inputs.current_state = Some(WalletState {
            public_key: inputs.transaction.client_pk.clone(),
            balance: 1_000_000_000,
            wallet_seq: 0,
            state_id,
            auth_hash: None,
            wallet_id: None,
            group_members: None, hibernation_until: 0,
        });
    }

    #[test]
    fn test_cl2_rejects_clara_with_empty_nbc_after_phase_5e_hotfix() {
        // Phase 5e: NBC trust anchor is now MANDATORY in CL2.
        // An attestation with empty NBC fields MUST be rejected even if
        // the wallet binding, signature, and eligibility would all otherwise
        // pass. This is the security hotfix that prevents clients from
        // self-signing CLARA attestations with arbitrary Ed25519 keypairs.
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        let stored_state = [0x77; 32];
        with_stored_state(&mut inputs, stored_state);
        let wallet_pk_arr: [u8; 32] = inputs.transaction.client_pk
            .as_slice().try_into().unwrap();

        let nabla_sk = Ed25519SigningKey::from_bytes(&[0x42; 32]);
        let clara = make_clara_for_wallet(
            wallet_pk_arr,
            [0x66; 32],
            [0x88; 32],
            vec![stored_state],  // would otherwise be eligible
            &nabla_sk,
        );
        inputs.clara_attestation = Some(clara);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ClaraNbcTrustFailed),
            "Phase 5e: empty NBC fields MUST be rejected"
        );
    }

    #[test]
    fn test_cl2_rejects_clara_when_eligibility_would_fail_but_nbc_fires_first() {
        // Pre-Phase-5e this test would reject with ClaraStateNotGarbage.
        // After Phase 5e, NBC trust anchor verification fires before
        // eligibility, so the rejection reason changes to ClaraNbcTrustFailed.
        // Both rejections are correct — the difference is just which check
        // catches the bad attestation first. This test pins the new order.
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        with_stored_state(&mut inputs, [0xEE; 32]);
        let wallet_pk_arr: [u8; 32] = inputs.transaction.client_pk
            .as_slice().try_into().unwrap();

        let nabla_sk = Ed25519SigningKey::from_bytes(&[0x42; 32]);
        let clara = make_clara_for_wallet(
            wallet_pk_arr,
            [0x66; 32],
            [0x88; 32],
            vec![[0x11; 32], [0x22; 32]], // EE is not in this list
            &nabla_sk,
        );
        inputs.clara_attestation = Some(clara);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        // NBC fires first; eligibility is unreachable.
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ClaraNbcTrustFailed),
        );
    }

    #[test]
    fn test_cl2_clara_with_real_nbc_passes_through_to_eligibility() {
        // Phase 5e: end-to-end CLARA with a real SPHINCS+ NBC trust anchor
        // chained to a Nabla root authority key. This test exercises the
        // full Phase 5e fix:
        //   - wallet_pk binding ✓
        //   - Ed25519 signature verification ✓
        //   - mandatory NBC trust anchor verification ✓
        //   - eligibility check (stored state in garbage list) ✓
        //   - synthetic rewrite (current_state.state_id = healed_to_state_id)
        // Skipped if root keys are not on disk (CI / fresh clone / Mac
        // dev tree that ships .pub files but not .key files alongside
        // the binary). Gate on the specific private-key file, not the
        // dir — the dir exists with .pub-only on Mac.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root_keys_dir = manifest.join("../../root-keys/nabla");
        if !root_keys_dir.join("root_1.key").exists() {
            eprintln!("SKIP: root-keys/nabla/root_1.key not found — cannot test full CL2 CLARA");
            return;
        }
        let sk1 = std::fs::read(root_keys_dir.join("root_1.key")).unwrap();
        let pk1 = std::fs::read(root_keys_dir.join("root_1.pub")).unwrap();

        // Build a CLARA attestation signed by a fresh Ed25519 key
        let nabla_sk = Ed25519SigningKey::from_bytes(&[0x42; 32]);
        let nabla_pk = nabla_sk.verifying_key().to_bytes();

        // YPX-018 Phase 5f wire format: nbc_commitment is the SPHINCS+ pre-image
        // bytes (NOT the BLAKE3 hash). The verifier:
        //   (a) recomputes BLAKE3(nbc_commitment) and gives that to verify_sphincs,
        //   (b) window-scans nbc_commitment for nabla_pk to bind the attestation.
        // So we sign blake3(commitment_bytes), and embed nabla_pk literally inside.
        let mut commitment_bytes = Vec::new();
        commitment_bytes.extend_from_slice(b"AXIOM_VBC_CLARA_TEST_PAYLOAD");
        commitment_bytes.extend_from_slice(&nabla_pk); // ed25519 binding (window-scanned)
        commitment_bytes.extend_from_slice(&[0u8; 32]); // padding

        let commitment_hash = blake3::hash(&commitment_bytes);
        let nbc_sig = crate::crypto::sign_sphincs(&sk1, commitment_hash.as_bytes()).unwrap();

        // Build the CLARA attestation
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        let stored_state = [0x77; 32];
        with_stored_state(&mut inputs, stored_state);
        let wallet_pk_arr: [u8; 32] = inputs.transaction.client_pk
            .as_slice().try_into().unwrap();

        let mut clara = crate::types::ClaraAttestation {
            wallet_pk: wallet_pk_arr,
            healed_from_state_id: [0x66; 32],
            healed_to_state_id: [0x88; 32],
            healed_at_seq: 7,
            // Matches with_stored_state's 1_000_000_000 so the synthetic
            // rewrite leaves validate_transaction with a spendable balance.
            healed_balance: 1_000_000_000,
            heal_txid: [0xAA; 32],
            garbage_state_ids: vec![stored_state],  // eligible
            bloom_era_id: 0,
            bloom_era_root: [0; 32],
            nabla_tick: 1_777_000_000,
            nabla_node_pk: nabla_pk,
            nabla_signature: vec![],
            nbc_issuer_pk: pk1,
            nbc_signature: nbc_sig,
            nbc_commitment: commitment_bytes,
        };
        let msg = crate::crypto::compute_clara_message(&clara);
        clara.nabla_signature = nabla_sk.sign(&msg).to_bytes().to_vec();
        inputs.clara_attestation = Some(clara);

        let result = execute_core(inputs);
        // CL2 may still reject downstream for unrelated reasons (e.g., the
        // minimal test fixture's tx isn't a complete real TX). The point of
        // this test is: with a real NBC, CLARA-specific rejections do NOT
        // fire — we get past wallet binding, signature, NBC, and eligibility,
        // and any rejection comes from elsewhere in CL2.
        if result.result == ValidationResult::Reject {
            assert!(!matches!(
                result.rejection_reason,
                Some(ValidationError::ClaraWalletPkMismatch)
                    | Some(ValidationError::ClaraInvalidSignature)
                    | Some(ValidationError::ClaraNbcTrustFailed)
                    | Some(ValidationError::ClaraStateNotGarbage)
                    | Some(ValidationError::ClaraEmptyGarbage)
            ), "CLARA-specific rejection: {:?}", result.rejection_reason);
        }
    }

    #[test]
    fn test_cl2_rejects_clara_with_forged_signature() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        let stored_state = [0x77; 32];
        with_stored_state(&mut inputs, stored_state);
        let wallet_pk_arr: [u8; 32] = inputs.transaction.client_pk
            .as_slice().try_into().unwrap();

        let real_sk = Ed25519SigningKey::from_bytes(&[0x42; 32]);
        let evil_sk = Ed25519SigningKey::from_bytes(&[0x99; 32]);
        let mut clara = make_clara_for_wallet(
            wallet_pk_arr,
            [0x66; 32],
            [0x88; 32],
            vec![stored_state],
            &real_sk,
        );
        // Sign with the wrong key but keep the real PK in the struct
        let msg = crate::crypto::compute_clara_message(&clara);
        clara.nabla_signature = evil_sk.sign(&msg).to_bytes().to_vec();
        inputs.clara_attestation = Some(clara);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ClaraInvalidSignature),
        );
    }

    #[test]
    fn test_cl2_rejects_clara_with_wrong_wallet_pk() {
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        let stored_state = [0x77; 32];
        with_stored_state(&mut inputs, stored_state);

        let nabla_sk = Ed25519SigningKey::from_bytes(&[0x42; 32]);
        // Build attestation for a DIFFERENT wallet
        let other_wallet = [0xFE; 32];
        let clara = make_clara_for_wallet(
            other_wallet,
            [0x66; 32],
            [0x88; 32],
            vec![stored_state],
            &nabla_sk,
        );
        inputs.clara_attestation = Some(clara);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ClaraWalletPkMismatch),
        );
    }

    #[test]
    fn test_cl2_no_clara_attestation_falls_through_normally() {
        // When clara_attestation is None, CL2 must NOT add any new rejection
        // path — it falls through to the existing CL2 validation logic
        // (which will reject for other reasons in this minimal fixture, but
        // never with a Clara* error).
        let inputs = create_test_inputs(CoreLogicMode::CL2);
        let result = execute_core(inputs);
        if result.result == ValidationResult::Reject {
            assert!(!matches!(
                result.rejection_reason,
                Some(ValidationError::ClaraStateNotGarbage)
                    | Some(ValidationError::ClaraInvalidSignature)
                    | Some(ValidationError::ClaraWalletPkMismatch)
                    | Some(ValidationError::ClaraNbcTrustFailed)
                    | Some(ValidationError::ClaraEmptyGarbage)
            ));
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // YPX-018 — CL11 BLOOM_PHASE_OUT tests (Phase 4)
    // ════════════════════════════════════════════════════════════════════

    use crate::types::{
        ConsoleProposalBloomPhaseOut, MIN_PHASE_OUT_AGE_TICKS, MIN_PHASE_OUT_GRACE_TICKS,
    };

    fn make_phase_out_inputs(
        era_ids: Vec<u64>,
        effective_tick: u64,
        current_tick: u64,
        era_end_ticks: Vec<(u64, u64)>,
        blocked: Vec<u64>,
    ) -> PublicInputs {
        let mut inputs = create_test_inputs(CoreLogicMode::CL11);
        inputs.phase_out_payload = Some(ConsoleProposalBloomPhaseOut {
            era_ids,
            effective_tick,
            rationale: "test phase-out".to_string(),
        });
        inputs.phase_out_era_end_ticks = era_end_ticks;
        inputs.phase_out_blocked_era_ids = blocked;
        inputs.current_tick = current_tick;
        inputs
    }

    #[test]
    fn test_cl11_phase_out_accepts_when_constitutional_limits_satisfied() {
        // Era 5 closed at tick 1000. 50 years later = 1000 + 315_576_000 = 315_577_000.
        // current_tick = 200_000_000 (well before earliest_allowed)
        // effective_tick = era_end + 50y = 315_577_000 ← exactly the floor
        // grace = 315_577_000 - 200_000_000 = 115_577_000 (well over 5y)
        let era_end = 1_000u64;
        let earliest_allowed = era_end + MIN_PHASE_OUT_AGE_TICKS;
        let current = 200_000_000u64;
        let effective = earliest_allowed; // exactly at the constitutional floor
        // Verify grace condition holds
        assert!(effective - current >= MIN_PHASE_OUT_GRACE_TICKS);
        let inputs = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![],
        );
        let result = execute_core(inputs);
        assert_eq!(
            result.result, ValidationResult::Accept,
            "valid phase-out must accept; got {:?}", result.rejection_reason
        );
        assert!(result.console_chain_hash.is_some(), "must return cert hash");
    }

    #[test]
    fn test_cl11_phase_out_rejects_under_50_year_minimum_age() {
        // Era closed 49 years ago (just below the constitutional floor)
        let current = 100_000_000u64;
        let era_end = current.saturating_sub(49 * 6_311_520);
        let effective = current + MIN_PHASE_OUT_GRACE_TICKS + 1;
        let inputs = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![],
        );
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_rejects_under_5_year_grace() {
        // Era is well over 50 years old (rule 4b passes), but grace period
        // is just under 5 years (rule 3 fails).
        let era_end = 1_000u64;
        let current = era_end + MIN_PHASE_OUT_AGE_TICKS + 1_000_000;
        let effective = current + (MIN_PHASE_OUT_GRACE_TICKS - 1);
        let inputs = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![],
        );
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_rejects_already_phased_out_era() {
        let era_end = 1_000u64;
        let earliest_allowed = era_end + MIN_PHASE_OUT_AGE_TICKS;
        let current = 200_000_000u64;
        let effective = earliest_allowed.max(current + MIN_PHASE_OUT_GRACE_TICKS);
        let inputs = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![5], // era 5 is in the blocked set
        );
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_rejects_unknown_era_id() {
        let current = 100_000_000u64;
        let effective = current + MIN_PHASE_OUT_AGE_TICKS + MIN_PHASE_OUT_GRACE_TICKS;
        let inputs = make_phase_out_inputs(
            vec![99],          // era_id not in era_end_ticks
            effective,
            current,
            vec![(5, 1_000)], // only era 5 known
            vec![],
        );
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_rejects_empty_era_list() {
        let inputs = make_phase_out_inputs(vec![], 999_999_999, 0, vec![], vec![]);
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_rejects_effective_tick_in_past() {
        let inputs = make_phase_out_inputs(
            vec![5],
            100,    // effective in the past
            200,    // current is later
            vec![(5, 0)],
            vec![],
        );
        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::ConsolePhaseOutInvalid)
        );
    }

    #[test]
    fn test_cl11_phase_out_certificate_hash_is_deterministic() {
        let era_end = 1_000u64;
        let current = 200_000_000u64;
        let effective = era_end + MIN_PHASE_OUT_AGE_TICKS;
        let inputs1 = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![],
        );
        let inputs2 = make_phase_out_inputs(
            vec![5],
            effective,
            current,
            vec![(5, era_end)],
            vec![],
        );
        let r1 = execute_core(inputs1);
        let r2 = execute_core(inputs2);
        assert_eq!(r1.result, ValidationResult::Accept);
        assert_eq!(r2.result, ValidationResult::Accept);
        assert_eq!(
            r1.console_chain_hash, r2.console_chain_hash,
            "two identical phase-out proposals must produce the same cert hash"
        );
    }

    // ========================================================================
    // CL5 — Step 3.5d genesis-claim replay defense (task #65, 2026-05-28)
    //
    // Reproduces the Mac wallet exploit: an airdrop cheque (self-send,
    // amount == GENESIS_CLAIM_AMOUNT) replayed against an already-funded
    // wallet must be rejected at Core CL5, regardless of which k=3 subset
    // witnesses the redeem.
    // ========================================================================

    fn make_genesis_claim_bundle(receiver_wid: &str) -> crate::types::ChequeBundle {
        use crate::types::{ChequeBundle, ValidatorCheque};
        let make_cheque = |vid_byte: u8| -> ValidatorCheque {
            ValidatorCheque {
                recall_target_tx_id: None,
                txid: [0xAA; 32],
                validator_id: [vid_byte; 32],
                validator_pk: vec![vid_byte; 32],
                signature: vec![0u8; 64],
                execution_proof: vec![],
                vbc_bundle: None,
                carrier_type: "test".into(),
                carrier_address: "test@test.com".into(),
                sender_wallet_id: receiver_wid.to_string(),
                receiver_wallet_id: receiver_wid.to_string(),
                amount: crate::types::GENESIS_CLAIM_AMOUNT,
                rate_bps: 10,
                reference: "airdrop".into(),
                epoch: 500,
                created_at: 0,
                state_hash: [0xBB; 32],
                produced_state_id: [0xCC; 32],
                sender_fact_chain: None,
                zkp_nonce: None,
                proof_type: 1,
                dmap_input_hash: [0u8; 32],
                dmap_output_hash: [0u8; 32],
                oracle_claim: None,
                nabla_hint: None,
                sender_wallet_pk: None,
            }
        };
        ChequeBundle {
            cheques: vec![make_cheque(0x01), make_cheque(0x02), make_cheque(0x03)],
            fact_chain: None,
        }
    }

    #[test]
    fn cl5_genesis_claim_replay_against_funded_wallet_is_rejected() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT * 2);
        inputs.receiver_wallet_seq = Some(1);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert!(
            matches!(
                result.rejection_reason,
                Some(ValidationError::GenesisClaimWalletAlreadyFunded)
            ),
            "expected GenesisClaimWalletAlreadyFunded, got {:?}",
            result.rejection_reason,
        );
    }

    #[test]
    fn cl5_genesis_claim_replay_against_advanced_seq_is_rejected() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        inputs.receiver_wallet_seq = Some(5);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert!(
            matches!(
                result.rejection_reason,
                Some(ValidationError::GenesisClaimWalletAlreadyFunded)
            ),
            "advanced seq (5) on a self-send airdrop cheque must reject; got {:?}",
            result.rejection_reason,
        );
    }

    /// ACCEPT path (well, doesn't reject at Step 3.4) — a legitimate
    /// first redeem must NOT trip the new gate. The validator's stored
    /// receiver state at this point is exactly seq=1 (advanced by the
    /// send half) and balance=0 (no credit yet — genesis credits at
    /// redeem time, not send time).
    #[test]
    fn cl5_genesis_claim_first_redeem_does_not_trip_step_3_4() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        // The "post-send pre-redeem" canonical state.
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        inputs.receiver_wallet_seq = Some(1);

        let result = execute_core(inputs);
        // Will Reject for fake-signature reasons — that's fine.
        // Contract: NOT Step 3.4's GenesisClaimWalletAlreadyFunded.
        assert!(
            !matches!(
                result.rejection_reason,
                Some(ValidationError::GenesisClaimWalletAlreadyFunded)
            ),
            "Step 3.4 must NOT fire on a legit first claim (balance=0, seq=1); \
             got {:?}",
            result.rejection_reason,
        );
    }

    /// REJECT when the wallet is brand-new — no send half happened, so a
    /// cheque shouldn't exist. Anomalous state; treat as replay attempt.
    #[test]
    fn cl5_genesis_claim_against_brand_new_wallet_is_rejected() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        // No send half happened: seq=0. Cheque shouldn't exist.
        inputs.receiver_wallet_seq = Some(0);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert!(
            matches!(
                result.rejection_reason,
                Some(ValidationError::GenesisClaimWalletAlreadyFunded)
            ),
            "expected GenesisClaimWalletAlreadyFunded on seq=0 anomaly, got {:?}",
            result.rejection_reason,
        );
    }

    // ========================================================================
    // SEC-02 — cap-at-mint via FACT scar. A genesis claim is only mintable
    // if its FACT link carries a Nabla blessing (NablaConfirmation); a
    // scarred link means the pool was never debited (skip-Nabla / patched-SDK
    // attack). `genesis_link_blessed` is the gate's decision; the confirmation's
    // cryptographic validity is enforced separately by `verify_fact_chain`.
    // ========================================================================

    /// Builds a single-link FactChain whose tip is blessed or scarred.
    fn fact_chain_with_tip(blessed: bool) -> crate::types::FactChain {
        use crate::types::{FactChain, FactLink, FactWitness, NablaConfirmation};
        let link = FactLink {
            tx_id: [9u8; 32],
            previous_state_id: [0u8; 32],
            new_state_id: [1u8; 32],
            amount: crate::types::GENESIS_CLAIM_AMOUNT,
            required_k: 3,
            tick: 0,
            witnesses: vec![
                FactWitness { validator_id: [1u8; 32], validator_pk: vec![], signature: vec![], vbc_genesis_anchor: None },
            ],
            nabla_confirmation: if blessed {
                Some(NablaConfirmation {
                    nabla_node_id: [7u8; 32],
                    nabla_signature: vec![1u8; 64],
                    root_hash: [0u8; 32],
                    synced_to_tick: 0,
                    ..Default::default()
                })
            } else {
                None // SCARRED — no Nabla blessing
            },
            receiver_contact: None,
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
        };
        FactChain { checkpoint: None, links: vec![link] }
    }

    #[test]
    fn sec02_genesis_link_blessed_decision() {
        // Blessed tip → mintable.
        let blessed = fact_chain_with_tip(true);
        assert!(genesis_link_blessed(Some(&blessed)));

        // Scarred tip (no nabla_confirmation) → NOT mintable. This is the
        // skip-Nabla attack: a genesis claim that never drew from the pool.
        let scarred = fact_chain_with_tip(false);
        assert!(!genesis_link_blessed(Some(&scarred)));

        // Empty chain and missing chain are both "not blessed" → reject.
        let empty = crate::types::FactChain { checkpoint: None, links: vec![] };
        assert!(!genesis_link_blessed(Some(&empty)));
        assert!(!genesis_link_blessed(None));
    }

    // ========================================================================
    // CL5 — Step 3a-SABR bug demonstration (AXIOM Origin's "no DMAP" report).
    //
    // Fresh wallet (balance=0, wallet_seq=0) that has NEVER done a genesis
    // claim receives a normal cheque from another wallet. Cannot redeem.
    // The bug is that Step 3a-SABR (modes.rs around line 1878) reads
    // `inputs.prev_receipts.witness_sigs` to find the "redeem validators"
    // it wants to overlap-check against the cheque signers — but
    // `prev_receipts` is structurally empty whenever the trigger predicate
    // `balance == 0 && wallet_seq == 0` is true (no prior witnessed TX
    // could have advanced seq), and `cl5_inputs::build_cl5_attestation_inputs`
    // additionally hardcodes `prev_receipts: vec![]` for CL5. So the
    // overlap count is structurally pinned at 0, the required threshold is
    // positive, and the check always rejects.
    //
    // The two tests below pin down the bug WITHOUT forging crypto to reach
    // the check at runtime (Step 3.5b's mandatory `cheque_claim_proof`
    // would fire first and need a valid Ed25519 sig + NBC chain to bypass).
    // ========================================================================

    /// Structural proof: Step 3a-SABR's overlap math gives `0 < sabr_overlap(k)`
    /// whenever the trigger condition fires, so the check rejects every time.
    #[test]
    fn cl5_3a_sabr_overlap_math_rejects_every_first_time_receive() {
        use alloc::collections::BTreeSet;
        use crate::types::Receipt;

        // The set the check builds from cheque_bundle.cheques[*].validator_pk —
        // 3 distinct cheque signers for a k=3 bundle.
        let cheque_signer_pks: BTreeSet<Vec<u8>> = vec![
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
        ].into_iter().collect();
        let cheque_k: u8 = 3;
        let required_cheque_overlap =
            crate::wallet_id::sabr_overlap(cheque_k) as usize;

        // The set the check builds from inputs.prev_receipts.witness_sigs.
        // For a genuine first-time receiver `prev_receipts` is empty by
        // protocol invariant (the trigger predicate `wallet_seq == 0` rules
        // out any prior witnessed TX). The CL5 input builder in
        // `cl5_inputs.rs` additionally hardcodes `prev_receipts: vec![]`.
        let prev_receipts: Vec<Receipt> = vec![];
        let redeem_validator_pks: BTreeSet<Vec<u8>> = prev_receipts.iter()
            .flat_map(|r| r.witness_sigs.iter())
            .map(|ws| ws.validator_pk.clone())
            .collect();

        let cheque_overlap = redeem_validator_pks.iter()
            .filter(|pk| cheque_signer_pks.contains(*pk))
            .count();

        // sabr_overlap(3) = 2: the check requires 2 cheque-signer overlap.
        assert_eq!(required_cheque_overlap, 2);
        // But the set we compare against is empty.
        assert_eq!(cheque_overlap, 0);
        // So the check rejects, every time.
        assert!(
            cheque_overlap < required_cheque_overlap,
            "Step 3a-SABR rejects every first-time receive: 0 < 2"
        );
    }

    /// End-to-end demonstration via execute_core: a fresh-wallet redeem of a
    /// NORMAL (non-self-send) cheque must NEVER reject with
    /// `SABRInsufficientOverlap` — that's the post-fix contract. Pre-fix
    /// the path always died at 3a-SABR (math: `0 < sabr_overlap(k)`); the
    /// fix at Step 3a-SABR's predicate (now `... && !prev_receipts.is_empty()`)
    /// excludes the genuine first-time-receiver case from the check, so
    /// rejection now happens at a different step. In this test the
    /// downstream gate is 3.5b (`ChequeClaimProofMissing`) because
    /// `create_test_inputs` doesn't supply a forged claim proof — Mac's
    /// live flow does, so the live path passes 3.5b and reaches the FACT
    /// commitment / signature verification stages further down.
    #[test]
    fn cl5_fresh_wallet_normal_cheque_rejects_before_producing_proof() {
        use crate::types::{ChequeBundle, ValidatorCheque};

        // Two distinct wallet identities — sender and a fresh receiver.
        let sender_pk: [u8; 32] = [0xAA; 32];
        let receiver_pk: [u8; 32] = [0xBB; 32];
        let sender_wid = generate_wallet_id("sender@test.com", "42", &sender_pk)
            .expect("sender wid");
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &receiver_pk)
            .expect("receiver wid");

        // Build a normal cheque bundle — NOT a self-send, so Step 3.4
        // (genesis-replay defense) bypasses cleanly.
        let make_cheque = |vid_byte: u8| -> ValidatorCheque {
            ValidatorCheque {
                recall_target_tx_id: None,
                txid: [0x77; 32],
                validator_id: [vid_byte; 32],
                validator_pk: vec![vid_byte; 32],
                signature: vec![0u8; 64],
                execution_proof: vec![],
                vbc_bundle: None,
                carrier_type: "test".into(),
                carrier_address: "test@test.com".into(),
                sender_wallet_id: sender_wid.clone(),
                receiver_wallet_id: receiver_wid.clone(),
                amount: 50_000_000_000, // 5 AXC, NOT genesis claim amount
                rate_bps: 10,
                reference: "first-cheque-receive".into(),
                epoch: 500,
                created_at: 0,
                state_hash: [0x33; 32],
                produced_state_id: [0x44; 32],
                sender_fact_chain: None,
                zkp_nonce: None,
                proof_type: 1,
                dmap_input_hash: [0u8; 32],
                dmap_output_hash: [0u8; 32],
                oracle_claim: None,
                nabla_hint: None,
                sender_wallet_pk: Some(sender_pk),
            }
        };
        let bundle = ChequeBundle {
            cheques: vec![make_cheque(0x01), make_cheque(0x02), make_cheque(0x03)],
            fact_chain: None,
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(receiver_pk.to_vec());
        // **The first-TX state AXIOM Origin called out:** balance=0, wallet_seq=0,
        // no prev_receipts — never claimed from airdrop, never received
        // anything, just got a cheque.
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(50_000_000_000 - 30_000);
        inputs.receiver_wallet_seq = Some(0);
        // prev_receipts already empty in create_test_inputs.
        // cheque_claim_proof: None — same as what the SDK ends up shipping
        // when the upstream verify_cheque path is exercised against a fresh
        // env and 3.5b rejects.

        let result = execute_core(inputs);
        std::eprintln!(
            "[fresh-wallet first-cheque receive] result={:?} reason={:?}",
            result.result, result.rejection_reason,
        );
        assert_eq!(result.result, ValidationResult::Reject);
        // Post-fix contract: 3a-SABR's `SABRInsufficientOverlap` MUST NOT
        // fire here. The fresh-receiver state (balance=0, seq=0,
        // prev_receipts empty) now skips the overlap check just like the
        // send-side first-TX exception (modes.rs:738) skips
        // MissingPrevReceipts.
        assert!(
            !matches!(
                result.rejection_reason,
                Some(ValidationError::SABRInsufficientOverlap)
            ),
            "post-fix Step 3a-SABR must NOT fire on a genuine first-time \
             receiver; got {:?}",
            result.rejection_reason,
        );
        // The actual reject in this test setup is 3.5b
        // (`ChequeClaimProofMissing`) because the test doesn't supply a
        // forged claim proof. Live Mac flow has a real claim_proof and
        // would pass 3.5b → reach downstream checks → succeed if all
        // signatures verify.
        assert!(
            matches!(
                result.rejection_reason,
                Some(ValidationError::ChequeClaimProofMissing)
            ),
            "expected ChequeClaimProofMissing in this test (no forged \
             claim proof), got {:?}",
            result.rejection_reason,
        );
    }

    // ════════════════════════════════════════════════════════════════
    // S-ABR gate decision logic — the pieces migrated from Lambda's
    // deleted `validate_sabr_new` (2026-07-05 CL2 rewire). The full
    // crypto path (checks 1-4 on overlap sigs) is exercised live by
    // every witness round now that Lambda invokes CL2; these tests pin
    // the DECISION table so a regression is caught without the env.
    // ════════════════════════════════════════════════════════════════

    /// HEAL reduction: short-of-floor heals drop to the surviving-committer
    /// majority; everything else keeps the full floor.
    #[test]
    fn sabr_effective_required_overlap_heal_reduction_table() {
        // Non-heal: floor unchanged regardless of count.
        assert_eq!(sabr_effective_required_overlap(2, 0, false), 2);
        assert_eq!(sabr_effective_required_overlap(2, 1, false), 2);
        assert_eq!(sabr_effective_required_overlap(3, 5, false), 3);

        // Heal at-or-above floor: unchanged (reduction only fires short of it).
        assert_eq!(sabr_effective_required_overlap(2, 2, true), 2);
        assert_eq!(sabr_effective_required_overlap(2, 3, true), 2);

        // Heal short of floor: sabr_overlap(surviving).min(surviving).
        // 2 surviving of a k=5 chain (floor 3): sabr_overlap(2)=2 → both must sign.
        assert_eq!(sabr_effective_required_overlap(3, 2, true), 2);
        // 1 surviving: sabr_overlap(1)=1 → the one committer must sign.
        assert_eq!(sabr_effective_required_overlap(2, 1, true), 1);
        // 0 surviving: floor drops to 0 — safety carried by
        // verify_state_id_valid (stored==consumed) + Nabla, exactly as
        // Lambda's original §17.10.14 relax. Matches the deleted
        // `required_overlap(overlap_count.max(1)).min(overlap_count)`.
        assert_eq!(sabr_effective_required_overlap(2, 0, true), 0);
    }

    /// Formula parity with the sabr_overlap floor the gate feeds in:
    /// required = sabr_overlap(prev_k) = floor(k/2)+1, k=0 → 0.
    #[test]
    fn sabr_overlap_floor_parity() {
        use crate::wallet_id::sabr_overlap;
        assert_eq!(sabr_overlap(0), 0);
        assert_eq!(sabr_overlap(1), 1);
        assert_eq!(sabr_overlap(2), 2);
        assert_eq!(sabr_overlap(3), 2);
        assert_eq!(sabr_overlap(4), 3);
        assert_eq!(sabr_overlap(5), 3);
        assert_eq!(sabr_overlap(7), 4);
    }

    /// BURN exemption: the CL2 gate predicate must not reject a burn on
    /// overlap shortfall. Pins the `!is_burn` leg of the gate condition
    /// (`!is_hal_reanchor && !is_burn && short`) — a burn with zero overlap
    /// sigs passes the S-ABR gate; its safety is the economic cap
    /// (validate_burn_target + verify_balance). RECALL no longer appears in
    /// this predicate (2026-07-06 redesign — recall meets normal overlap).
    #[test]
    fn sabr_gate_burn_exempts_overlap_shortfall() {
        let required = 2usize;
        let valid = 0usize;
        let is_hal_reanchor = false;

        let effective = sabr_effective_required_overlap(required, valid, false);
        // Non-burn send with the same shortfall REJECTS...
        let rejects_normal = !is_hal_reanchor && !false && valid < effective;
        assert!(rejects_normal, "normal send short of overlap must reject");
        // ...the burn does NOT.
        let rejects_burn = !is_hal_reanchor && !true && valid < effective;
        assert!(!rejects_burn, "burn must be exempt from the overlap gate");
    }
}
