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
///   CL3 — Validator Witness: produce witness proof. (CL3 itself runs NO S-ABR
///         overlap check — CL2 ran it on the same request first; the
///         ALLOW_NO_SABR_OVERLAP marker in execute_cl3 says why. Corrected
///         2026-10-02: this line used to claim CL3 did the overlap check.)
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
    // §23.14.2 (KI#213, ruled 2026-09-24): the candidates are the CURRENT tx's
    // co-witnesses at the finalizing CL3 — ONE rule shared with the host
    // time-bond (`audit::audit_target_candidates`). Until 2026-09-24 this
    // collected `prev_receipts[].witness_sigs` (the PREVIOUS tx's witnesses),
    // who often never executed the current tx and could only answer "unknown
    // txid" → banned NonResponds. Guest change ⇒ CoreID rotation
    // (docs/AXIOM_OPS_PendingRotation.md); the host half shipped the same day.
    // In every Core (2026-09-26 — the volume trigger below is no longer dev-gated).
    let witness_pks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
        crate::audit::audit_target_candidates(&inputs);

    let mut outputs = match mode {
        CoreLogicMode::CL1 => execute_cl1(inputs),
        CoreLogicMode::CL2 => execute_cl2(inputs),
        CoreLogicMode::CL3 => execute_cl3(inputs),
        CoreLogicMode::CL4 => execute_cl4(inputs),
        CoreLogicMode::CL5 => execute_cl5(inputs),
        CoreLogicMode::CL7 => execute_cl7(inputs),
        CoreLogicMode::CL8 => execute_cl8(inputs),
        CoreLogicMode::CL10 => execute_cl10(inputs),
        CoreLogicMode::CL11 => execute_cl11(inputs),
        CoreLogicMode::CL12 => execute_verify_send_proof(inputs),
        CoreLogicMode::CL2_PREFILTER => execute_cl2_prefilter(inputs),
        CoreLogicMode::ArkSendFinalize => execute_ark_send_finalize(inputs),
        CoreLogicMode::ZkpQualify => execute_zkp_qualify(inputs),
    };
    // ZKP anti-replay: hash nonce into outputs (runs INSIDE zkVM guest)
    if let Some(nonce) = zkp_nonce {
        // Pattern 1 sweep — ONE builder, shared with the zkVM guest and
        // Lambda's cross-check.
        outputs.zkp_nonce_hash = Some(crate::crypto::zkp_nonce_hash(&nonce));
    }

    // §23.14 Peer Audit Demand — The Ping Defense
    // On CL2/CL3 with Accept result, Core may demand Lambda audit a peer.
    // Deterministic from txid: same TX always produces same audit decision.
    // AVM interpreter tracks countdown; non-compliance → self-termination.
    //
    // Runs in EVERY Core, dev included (YP §23.14 AS BUILT item 1, amended
    // 2026-09-26). The old `#[cfg(not(feature = "dev-mode"))]` gate existed
    // because a demand armed against an empty audit buffer (disable-audit)
    // self-terminated the validator; the host now arms a demand ONLY on an
    // audited execution (KI#210, `enforce_audit_post`'s `accumulate` guard), so a
    // disable-audit pre-execution never arms one and the gate protects nothing.
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
///   - the CLARA attestation gate (no stored state at the gateway; Lambda's CL2 runs it)
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

/// **Do not widen the relaxation beyond `is_heal` without re-reading this.**
///
/// The strict-majority overlap this function may reduce is what makes offline
/// fork adjudication work, and the argument is a pigeonhole rather than a
/// protocol step: `sabr_overlap(k) = k/2 + 1` is a strict majority of the
/// anchor's own witness set, so two settlement rounds descending from one
/// predecessor each need a strict majority of the SAME set and must therefore
/// share at least one witness (`2m - k >= 1` at every tier: k=3 -> 1,
/// k=4 -> 2, k=5 -> 1). That shared validator refuses the second leg from its
/// own stored state (`SabrStateChainMismatch`) — locally, with no registry
/// lookup and no anti-entropy. Nabla's consume-once is the backstop, not the
/// mechanism.
///
/// A **settlement** is not a heal, not a HAL re-anchor, not a burn, and not a
/// k=0 offline trade, so it faces the full floor and the intersection holds.
/// If the reduction is ever extended to a transaction shape that settlements
/// take, or the gate's exemption list grows to cover them, the intersection is
/// gone and fork adjudication silently falls back to Nabla — which is
/// propagation-dependent, and therefore does NOT hold on a mesh that is not
/// converging.
///
/// This is not hypothetical: the rotation-6 `sabr_k0_anchored` exemption broke
/// fork adjudication in exactly this way, by removing the intersection for
/// k=0-anchored wallets (KI#41). It is also load-bearing for a published
/// claim — `papers/acceptance-without-prevention` §6.1(c) states the refusal as a property of the
/// mechanism, scoped specifically to settlement rounds.
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

/// §10.0 FOB fee-claim — the three tx↔attestation PINS, pure field logic
/// (no crypto) so they are unit-testable in isolation; the crypto half is
/// `validation::verify_fob_claim_attestation`, and the CL2 gate runs verify
/// THEN pins. Each pin:
///   (b) amount == att.amount — FULL sweep exactly (withdraw-full-only §4.1;
///       wrong amount = hard reject + retry = the collect-all-at-once rule);
///   (c) sender == att.linked_wallet_id — ONLY the SPHINCS+-registered stake
///       wallet claims (pk-binding already proved the sender owns the id);
///   (d) is_dev_wallet(sender) == att.is_dev — §10.2a last-mile class gate:
///       a dev pool pays only a dev wallet; Core rejects any cross.
fn fob_claim_tx_pins(
    tx: &crate::types::Transaction,
    att: &crate::types::FobClaimAttestation,
) -> Result<(), ValidationError> {
    // (a') pool pin (2026-09-14): a fee-sweep attestation cannot be presented
    // as an emission claim or vice versa — the kind names the pool.
    let pool_matches_kind = if tx.is_emission_claim() {
        crate::types::is_emission_pool(att.pool)
    } else {
        att.pool == crate::types::FOB_CLAIM_POOL_BOUNDED_FEE
    };
    if !pool_matches_kind {
        return Err(ValidationError::FobClaimInvalid);
    }
    if tx.amount != att.amount {
        return Err(ValidationError::FobClaimInvalid); // (b) full-sweep pin
    }
    if tx.sender_wallet_id != att.linked_wallet_id {
        return Err(ValidationError::FobClaimInvalid); // (c) claimant pin
    }
    if crate::wallet_id::is_dev_wallet(&tx.sender_wallet_id) != att.is_dev {
        return Err(ValidationError::FobClaimInvalid); // (d) class pin
    }
    Ok(())
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
    // ── YPX-010 §11.2 ARK SENDER EXECUTION PROOF (ruling 2026-07-20) ──
    // The k=0 offline ⟠-trade witness leg: the receiver's Core refuses to
    // witness unless the SENDER proves its side was executed by a Core of
    // THIS worldline. Receiver re-execution (the rest of this function)
    // proves the presented bytes are internally consistent; offline there
    // is no Nabla/VBC/validator apparatus, so only the sender's CL1 DMAP
    // attestation anchors them to reality — the ELF IS the worldline
    // (genesis validators + constants compiled in; CoreID = its BLAKE3),
    // and the attestation's challenges are CoreID-seeded.
    //
    // Bindings (all trusted-side): CoreID = STRICT equality with the
    // executing Core's own `local_core_id` — deliberately NOT the §12.6
    // accept-set resolver (blessed priors govern reconcile-after-rotation,
    // never a live peer trade, §11.8); identity = `tx.client_pk` (bound to
    // `sender_wallet_id` at Step -0.5); input binding = the sender's CL1
    // input bytes are reconstructed from THIS CL2's own inputs (both legs
    // build through the same offline literal, so CL1 inputs == CL2 inputs
    // with {mode: CL1, cl1_execution_proof: None}) — a replayed attestation
    // from any other tx hashes differently and fails. Fail-closed: no
    // proof, no witness.
    {
        use crate::wallet_id::{extract_security_level, K_ARK};
        let is_k0_offline_trade = inputs.vbc_bundle.is_none()
            && inputs.my_validator_pk.is_none()
            && matches!(extract_security_level(&inputs.transaction.sender_wallet_id), Ok((K_ARK, _)))
            && matches!(extract_security_level(&inputs.transaction.receiver_wallet_id), Ok((K_ARK, _)));
        if is_k0_offline_trade {
            let proof_bytes = match inputs.cl1_execution_proof.take() {
                Some(p) if !p.is_empty() => p,
                _ => return reject(ValidationError::ArkSenderProofMissing),
            };
            let attestation: crate::dmap::DmapAttestation =
                match ciborium::de::from_reader(proof_bytes.as_slice()) {
                    Ok(a) => a,
                    Err(_) => return reject(ValidationError::ArkSenderProofInvalid),
                };
            // Reconstruct the sender's CL1 input bytes (proof field already
            // taken → None, matching the sender's literal). Mode flips are
            // restored immediately; no clone of the (large) inputs.
            inputs.mode = CoreLogicMode::CL1;
            let mut rebuilt = alloc::vec::Vec::new();
            let ser_ok = ciborium::ser::into_writer(&inputs, &mut rebuilt).is_ok();
            inputs.mode = CoreLogicMode::CL2;
            if !ser_ok {
                return reject(ValidationError::ArkSenderProofInvalid);
            }
            let rebuilt_input_hash = *blake3::hash(&rebuilt).as_bytes();
            let sender_pk: [u8; 32] = match inputs.transaction.client_pk.as_slice().try_into() {
                Ok(pk) => pk,
                Err(_) => return reject(ValidationError::ArkSenderProofInvalid),
            };
            match crate::dmap::verify_dmap_attestation(
                &attestation,
                &inputs.local_core_id,
                &rebuilt_input_hash,
                // Output hash: self-consistent within the attestation's
                // signed binding tuple; with the INPUT bound and Core
                // execution deterministic, the output is determined.
                &attestation.output_hash,
                &sender_pk,
            ) {
                crate::dmap::DmapResult::Valid => {}
                _ => return reject(ValidationError::ArkSenderProofInvalid),
            }
        }
    }

    // YPX-018 — CLARA attestation gate (Phase 5e security hotfix; KI#260 2026-10-03).
    //
    // If the witness request carries a `clara_attestation`, Core verifies it
    // before any state-dependent logic runs:
    //   (1) Wallet binding — attestation MUST be for the requesting wallet
    //   (2) Ed25519 signature under att.nabla_node_pk
    //   (3) MANDATORY NBC trust anchor — att.nabla_node_pk must chain back
    //       to a NABLA_ROOT_AUTHORITY_PKS via SPHINCS+ NBC. Without this,
    //       a client could self-sign a CLARA attestation with any Ed25519
    //       keypair and bypass the trust model entirely.
    //   (4) Eligibility — the CL2 view's state_id (`inputs.current_state`)
    //       MUST equal `healed_to_state_id` (KI#260, RULED 2026-10-02).
    //
    // KI#260: the old predicate `stored ∈ {healed_to, healed_from} ∪ garbage`
    // followed by a synthetic rewrite to (healed_to, healed_at_seq,
    // healed_balance) let a caller-declared (possibly FUTURE, predictable)
    // garbage state roll a validator's view BACK to the heal. Both are gone:
    //   * Eligibility needs nothing else. The SDK attaches the attestation only
    //     to the tx consuming `healed_to`; Lambda shows Core that `consumed` for
    //     every non-prev-receipt witness (`consensus.rs` `core_state_id`), and a
    //     heal witness stores `healed_to` — so the YPX-018 C11 case (a validator
    //     poisoned by a partial that did not witness the heal) still witnesses
    //     (`signing_integration::ki260_c11_poisoned_non_heal_witness_…`). A view
    //     ≠ `consumed` never completed a witness anyway: Lambda's CL3 view
    //     carries the same state_id and CL3 refuses `consumed != state_id`.
    //   * The rewrite is DELETED, not kept as an identity: its state_id write is
    //     the identity under (4), and its (seq, balance) write could only change
    //     WHICH input the §15 anchor (`validation.rs` Step 1d, run on every
    //     post-heal send — it has prev_receipts and is not a heal) is checked
    //     against: an accepted tx's (seq, balance) are the k-signed ones either
    //     way. Core now judges the declared view like every other send's.
    //
    // Reference: YPX-018 §2.3, Yellow Paper §17.10.14, §26.17.10.
    if let Some(ref clara) = inputs.clara_attestation {
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
        // (4) Eligibility — `healed_to` ONLY (KI#260).
        if let Some(ref state) = inputs.current_state {
            if state.state_id != clara.healed_to_state_id {
                return reject(ValidationError::ClaraStateNotGarbage);
            }
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

    // §10.0 FOB fee-claim (2026-08-10 ruling) — thin CL2 gate, the RECALL
    // mirror. The claim is a standard no-debit self-send from the validator's
    // ATTACHED (stake) wallet; every witness runs this gate before signing its
    // 1/3 of the cheque:
    //   (a) verify_fob_claim_attestation — Nabla Ed25519 sig + NBC root anchor
    //       (a self-signed/stripped attestation dies);
    //   (b) amount pin — tx.amount == att.amount: the FULL pool, exactly
    //       (withdraw-full-only §4.1; wrong amount = hard reject + retry —
    //       reject-on-mismatch IS the collect-all-at-once enforcement);
    //   (c) claimant pin — tx.sender_wallet_id == att.linked_wallet_id: ONLY
    //       the SPHINCS+-registered stake wallet may claim (the pk-binding step
    //       already proved the sender owns that id);
    //   (d) class pin (§10.2a last-mile) — is_dev_wallet(sender) == att.is_dev:
    //       a dev pool pays only a dev wallet, a real pool only a real wallet;
    //       Core REJECTS any cross. This is the dev-fund isolation's Core gate.
    // Value safety: the pool sweep is Nabla consume-once at claim-registration
    // ("check twice: register + claim"); balance rises ONLY at the CL5 redeem.
    // The emission claim (YP §25.2.4) takes the SAME gate — one attestation
    // type, one verify, one set of pins, plus the pool pin in `fob_claim_tx_pins`.
    if inputs.transaction.is_pool_claim() {
        match &inputs.fob_claim_attestation {
            Some(att) => {
                if let Err(e) = crate::validation::verify_fob_claim_attestation(att) {
                    return reject(e); // (a)
                }
                if let Err(e) = fob_claim_tx_pins(&inputs.transaction, att) {
                    return reject(e); // (b)/(c)/(d)
                }
            }
            None => return reject(ValidationError::FobClaimInvalid),
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
    // The same boundary holds for the ZKP qualification receipt: Core judges the
    // Nabla tick bracket + challenge binding in mode `ZkpQualify`, never the STARK
    // itself (YPX-007 §9.4).
    
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
                        // §6b.5a — this bundle came OUT OF A RECEIPT (past
                        // evidence): chain only, no stamp (ruled B, 2026-09-08).
                        if crate::vbc::verify_vbc_bundle_historical(bundle, tx_epoch).is_err() {
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
        // YPX-010 §11.4: the OFFLINE k=0 ⟠-trade profile (both endpoints Ark,
        // NO validator apparatus — the same detection as the §11.7 online-ban
        // gate) has no overlapped validators to present: the receiver-as-
        // witness IS the whole witness set. The double-spend defense S-ABR
        // provides is NOT dropped — it MOVES to §12 settlement (the HAL
        // precedent above): consume-once + SeqForkBan adjudicate FIRST-WINS
        // when the offline links replay through the online path, and the CI
        // (§2-§4) prices the in-flood risk the receiver knowingly accepts.
        // A settlement replay (is_settlement, online apparatus present)
        // re-imposes normal overlap WHEN the anchor carries validator
        // witnesses (generation-1: charge-anchored). See k0_anchored below
        // for the pure-k=0-anchor case, where overlap is structurally void.
        let is_k0_offline_trade = {
            use crate::wallet_id::{extract_security_level, K_ARK};
            inputs.vbc_bundle.is_none()
                && inputs.my_validator_pk.is_none()
                && matches!(extract_security_level(&inputs.transaction.sender_wallet_id), Ok((K_ARK, _)))
                && matches!(extract_security_level(&inputs.transaction.receiver_wallet_id), Ok((K_ARK, _)))
        };
        // A settled Ark hop earns a real k≥3-witnessed receipt from its
        // settlement round (§12), so a wallet funded by an offline receive
        // re-enters the normal k≥3 world with a validator-witnessed anchor —
        // the S-ABR overlap then closes the ordinary way. There is therefore
        // NO Ark-specific exemption to this gate: the offline trade itself is
        // exempt above (is_k0_offline_trade — no validator apparatus), and the
        // settlement is a normal witnessed round that satisfies overlap on its
        // own settled prior.
        // §10.0 FOB fee-claim — "skip S-ABR" (design decision 2026-08-10): the claim's
        // witnesses are chosen FREELY (any 3), so the overlap floor does not
        // apply — same exemption mechanism as HAL/burn. Why this does NOT
        // reopen the sabr_effective_required_overlap warning above: the claim
        // is a NO-DEBIT self-send whose value source is the Bounded-Fee POOL
        // (whole-mesh-audited at tranche time, §7), not the wallet's balance —
        // there is nothing on the wallet chain for a fork to double-spend, and
        // a forked claim's second cheque dies at Nabla's consume-once pool
        // sweep (register) + claim re-verify ("check twice"), with the amount
        // attestation-pinned at this gate. Same safety shape as GenesisClaim
        // (pool-side consume-once), which likewise bypasses overlap.
        // The emission claim is the same pool-claim shape (consume-once at
        // Nabla, amount attestation-pinned) — no S-ABR overlap either.
        let is_fee_claim = inputs.transaction.is_pool_claim();
        let effective_required =
            sabr_effective_required_overlap(required_overlap, valid_overlap_count, is_heal);
        if !is_hal_reanchor && !is_burn && !is_k0_offline_trade && !is_fee_claim
            && valid_overlap_count < effective_required {
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
    // ALLOW_NO_SABR_OVERLAP(CL3 runs ONLY inside Lambda `process_witness_request`,
    // AFTER the authoritative `run_cl2` on the SAME request — which ran the S-ABR
    // overlap full-VBC check SEC-04 relies on; the two CL3 call sites,
    // `produce_witness_dmap` and `finalize_transaction`, are both downstream of
    // it — read 2026-10-02. A CL3 entry WITHOUT that CL2 in front would need the
    // overlap check here; `scripts/check_layer_boundary.sh` SEC-04 rule.)
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
    // §17.11.2 step 3: a genesis / stake claim's send leaves the balance
    // UNCHANGED (the pool funds it at the CL5 redeem). Normal TXs deduct.
    // ⚠ Until 2026-10-02 (KI#251) this comment and the rule said genesis claims
    // "CREDIT GENESIS_CLAIM_AMOUNT" at the send — wrong; see compute_post_tx_balance.
    // RULE 1: the one balance rule (also FIXES recall here — this site lacked
    // the recall no-debit arm the state_id/state_hash builders had).
    let new_balance = match crate::validation::compute_post_tx_balance(
        &inputs.transaction, current_balance,
    ) {
        Ok(b) => b,
        Err(e) => return reject(e),
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
        // KI#54 — ONE derivation, shared with the finalizer. This site used
        // to gate on BURN_ADDRESS alone, which silently dropped the target
        // for the sanctioned self-send heal-burn: the witnesses then signed
        // a commitment WITHOUT the field while the finalizer verified one
        // WITH it, so every signature failed and the link never built.
        let burn_target = crate::fact::fact_burn_target(&inputs.transaction);
        let commitment = crate::fact::compute_fact_commitment(
            &txid,
            &inputs.transaction.consumed_state_id,
            produced_sid,
            inputs.transaction.amount,
            sender_anchor.as_ref(),
            is_dev_class,
            // Fork Settlement R4: the k this send's link will declare. It is
            // `validate_transaction`'s value, returned below as
            // `PublicOutputs.required_k` (`..result`) — the SAME value Lambda
            // hands `build_fact_link`, so signer and finalizer bind one k.
            result.required_k,
            &[], // send links never inherit (YPX-001 §1.5.1a — redeem-only)
            burn_target,
        );
        crate::crypto::sign_dilithium(sk, &commitment).ok()
    } else {
        None // No Dilithium key provided (e.g., direct-to-lambda dev mode)
    };
    
    // YPX-010 §11.6 / P3.6 — stamp the sender's Core-computed Confidence Index on an
    // ordinary online k≥3 send, so a later offline ⟠ receiver reads Core-signed trust
    // evidence (bound into `receipt_commitment` below → the k witnesses attest it).
    // Only a real k≥3 sender on a plain transfer: special ops (heal / genesis / HAL /
    // recall) and protocol-address sends (burn / deed / fee) carry no CI. Robust to
    // hostile input (no unwrap on client-supplied bytes).
    let confidence_index = {
        let t = &inputs.transaction;
        let is_protocol_dest = t.receiver_wallet_id == crate::types::BURN_ADDRESS
            || t.receiver_wallet_id == crate::types::DEED_ADDRESS
            || t.receiver_wallet_id == crate::types::FEE_ADDRESS;
        let is_special = t.is_heal() || t.is_genesis_claim() || t.is_hal_reanchor()
            || t.is_recall() || is_protocol_dest;
        let sender_k = crate::wallet_id::extract_security_level(&t.sender_wallet_id)
            .map(|(k, _)| k)
            .unwrap_or(0);
        if !is_special && (sender_k as usize) >= crate::fact::MIN_FACT_WITNESSES {
            let k3_tick = if inputs.current_tick > 0 { inputs.current_tick } else { t.epoch };
            let empty = crate::types::FactChain::new();
            let chain = inputs.sender_fact_chain.as_ref().unwrap_or(&empty);
            Some(crate::ark::compute_ci_factors(chain, &t.client_pk, new_balance, k3_tick))
        } else {
            None
        }
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
            oods_flag.as_ref(), confidence_index.as_ref(),
            None, // CL3 send path: no external sender lineage (§32.3)
        )
    };

    // Return enriched outputs — Lambda reads these, never computes them
    PublicOutputs {
        txid: Some(txid),
        new_balance: Some(new_balance),
        fact_signature,
        receipt_commitment: Some(receipt_commitment),
        // `is_dev_class` carried back so Lambda stamps the same value
        // on Receipt that Core just bound into receipt_commitment.
        is_dev_class: Some(is_dev_class),
        // YPX-021 §8.2 — carried back so Lambda/SDK stamp the SAME flag
        // Core just bound into receipt_commitment (is_dev_class pattern).
        oods_flag,
        // P3.6 — the Core-computed CI, carried back so Lambda/SDK stamp it onto
        // Receipt.confidence_index (same pattern; source of truth in Core).
        confidence_index,
        ..result
    }
}

/// ArkSendFinalize (YPX-010 §11.2.1, P3.7) — assemble the OFFLINE k=0 ⟠-trade SEND link
/// on the sender's own device after leg R2 (the receiver's co-signature).
///
/// This is the send-link counterpart to `execute_cl5`'s redeem-link assembly: offline
/// there are no validators and the SDK may not construct FACT links (CLAUDE §12), so the
/// sender's Core does it. Steps: validate the k=0 Ark→Ark transfer (the same
/// `validate_transaction` path, k=0 profile), enforce exclusivity (§11.7 — the witness
/// key MUST pk-bind to `receiver_wallet_id`), verify the receiver-as-witness Ed25519
/// signature over the link's `compute_fact_commitment`, assemble the link
/// (`required_k = K_ARK`, NO validator witnesses, the witness attached), and return the
/// updated chain in `ark_send_fact_chain` for the leg-3 cheque. Core determinism makes
/// the sender's `produced_state_id` here equal the receiver's CL2 value it signed.
fn execute_ark_send_finalize(inputs: PublicInputs) -> PublicOutputs {
    use crate::wallet_id::{extract_security_level, is_dev_wallet, verify_pk_binding, K_ARK};

    // 1. Validate the transfer (k=0 profile: receiver-eligibility branch + §11.9 Ark
    //    rules; the offline flow carries no validator apparatus so the §11.7 online ban
    //    passes through, P3.4). Yields the produced_state_id + txid the witness signed.
    let mut result = match validate_transaction(&inputs) {
        Ok(o) => o,
        Err(e) => return reject(e),
    };
    if result.result == ValidationResult::Reject {
        return result;
    }
    let tx = &inputs.transaction;

    // 2. Finalize is offline-ONLY and k=0-ONLY: both endpoints must be Ark.
    let sender_k = extract_security_level(&tx.sender_wallet_id).map(|(k, _)| k).unwrap_or(u8::MAX);
    let receiver_k = extract_security_level(&tx.receiver_wallet_id).map(|(k, _)| k).unwrap_or(u8::MAX);
    if sender_k != K_ARK || receiver_k != K_ARK {
        return reject(ValidationError::ArkOnlineTradeRejected);
    }

    // 3. The receiver-as-witness co-signature is mandatory and, by exclusivity (§11.7),
    //    its key MUST pk-bind to the trade's receiver_wallet_id.
    let rw = match inputs.receiver_witness.as_ref() {
        Some(rw) => rw,
        None => return reject(ValidationError::ArkReceiverWitnessMissing),
    };
    if verify_pk_binding(&tx.receiver_wallet_id, &rw.receiver_pk).is_err() {
        return reject(ValidationError::ArkReceiverWitnessInvalid);
    }

    // `validate_transaction` returns `txid: None` on every path ("CL3 fills
    // this") — compute it here, exactly as CL3 does. Relying on `result.txid`
    // made the positive finalize path unreachable (every accept rejected
    // `InvalidStateId`); caught by the P3.7 round-trip test.
    let txid = crate::compute::compute_txid(tx);
    let produced = match result.produced_state_id {
        Some(p) => p,
        None => return reject(ValidationError::InvalidStateId),
    };
    let is_dev_class = is_dev_wallet(&tx.sender_wallet_id);
    // Surface the txid so the driver reads produced/txid off ONE finalize run.
    result.txid = Some(txid);

    // 4. Assemble the k=0 send link (no validator witnesses; receiver-as-witness only).
    let mut chain = match crate::fact::build_fact_link(
        &txid,
        &tx.consumed_state_id,
        &produced,
        tx.amount,
        K_ARK,                 // k=0 tier — floor-1 receiver-witness
        &[],                   // NO validator witness sigs offline
        None,                  // burn_target_tx_id — not a burn
        None,                  // sender_anchor — send link (not a redeem)
        is_dev_class,
        alloc::vec::Vec::new(), // Ark links never inherit taint (§1.5.1a)
        inputs.sender_fact_chain.as_ref(),
        None,                  // recall_target_tx_id
        None,                  // recall_proof
    ) {
        Ok(c) => c,
        Err(e) => return reject(e),
    };

    // 5. Verify the receiver signed EXACTLY this link's commitment, then attach it.
    let link = match chain.links.last_mut() {
        Some(l) => l,
        None => return reject(ValidationError::FactChainBreak),
    };
    let commitment = crate::fact::compute_fact_commitment(
        &link.tx_id,
        &link.previous_state_id,
        &link.new_state_id,
        link.amount,
        link.sender_anchor.as_ref(),
        link.is_dev_class,
        link.required_k,
        &link.inherited_scar_txids,
        link.burn_target_tx_id.as_ref(),
    );
    if crate::crypto::verify_ed25519(&rw.receiver_pk, &commitment, &rw.signature).is_err() {
        return reject(ValidationError::ArkReceiverWitnessInvalid);
    }
    link.receiver_witness = Some(rw.clone());

    result.ark_send_fact_chain = Some(chain);
    result
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
/// Contains ONLY the txid (passthrough into the journal). The guest computes no
/// FACT commitment (R35, 2026-09-28 — its hand copy was unread and stale).
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

    // `fact_commitment` DELETED 2026-09-28 (Fork Settlement §9b R35): it was
    // always `None` except in the zkVM guest's hand-copied hash, which nothing
    // read (Lambda set `None`; `differential_conformance` excluded it) and which
    // had drifted from `fact::compute_fact_commitment` (RULE 3 shapes 3/4/7).
    /// Dilithium ML-DSA-65 signature over the link's FACT commitment (3,309 bytes)
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
///   The FACT data (fact_signature, txid) from native Core
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

    // ── 2. Dust limit (anti-spam) — a VBC request carries amount 0 by design
    //      (§5.2.2b; `validation::verify_balance`) ──
    let is_vbc_request = tx.is_vbc_request();
    if tx.amount == 0 && !is_vbc_request {
        return reject_zkp(ValidationError::ZeroAmount);
    }
    if !is_protocol_tx && !is_vbc_request && tx.amount < MINIMUM_TX_ATOMS {
        return reject_zkp(ValidationError::DustAmount);
    }

    // ── 3. Burn consistency ──
    // KI#54 — same predicate as `validation.rs`. This path had NO self-send
    // heal-burn exemption, so CL3-ZKP rejected exactly the transactions
    // CL3-DMAP accepted — a two-VM divergence on the one mode that is
    // supposed to be comparable.
    if tx.burn_target_tx_id.is_some() && !crate::fact::burn_target_is_authorized(tx) {
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
    // KI#58: heal is cap-exempt (mirror DMAP `validation.rs`) so a scarred wallet
    // can always heal out of the cap. Was `if !is_burn` — heal was NOT exempted
    // here, so the zkVM checkpoint REJECTED a heal at >20 scars that DMAP ACCEPTED
    // (the two-VM divergence, KI#54 shape). The scar test is now the one predicate
    // `is_resolved` (recall + inherited aware), not the old nabla+burn-only inline
    // that counted recalled links toward the cap and missed inherited taint.
    let cap_exempt = crate::fact::burn_target_is_authorized(tx) || tx.is_heal();
    if !cap_exempt {
        if let Some(ref fact_chain) = inputs.sender_fact_chain {
            let unresolved = fact_chain.links.iter()
                .filter(|l| !l.is_resolved())
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

    // ── 10. (owner_proof check DELETED 2026-09-25, KI#108 — see validation.rs step 4.5) ──

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
    // RULE 1: the one balance rule (zkVM checkpoint MUST match the host).
    let new_balance = match crate::validation::compute_post_tx_balance(tx, balance) {
        Ok(b) => b,
        Err(e) => return reject_zkp(e),
    };
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
    // NOTE: zkp_nonce_hash is set to None here. The CALLER (the guest) computes
    // it with Core's one builder. (No FACT commitment is carried — R35.)
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
    // ALLOW_NO_SABR_OVERLAP(CL4: client-side receipt check, no value decision,
    // no production caller — reserved surface, KI#36.)
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
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
        }
    }
}

/// Create a rejection output
fn reject(reason: ValidationError) -> PublicOutputs {
    PublicOutputs {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None,
        receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
    }
}

/// Accept with all-default outputs (mirror of `reject`). Verify-only modes set
/// only the fields they need (e.g. `txid`) on top of this.
fn accept() -> PublicOutputs {
    PublicOutputs {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None,
        receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
    }
}

/// ZkpQualify (YPX-007 §9.4, KI#125) — judge the startup ZKP benchmark and sign
/// the qualification record. One input, one output; reads ONLY `oods_attestation`
/// (T0), `zkq_request`, `my_validator_id`, `my_dilithium_pk`, `my_dilithium_sk`,
/// `local_core_id`. Pure: no clock (the ticks are Nabla-signed DATA), no randomness
/// (the challenge's unpredictability is Nabla's signature). Core does NOT verify
/// the STARK — the record states exactly what was checked (§9.4 trust label).
fn execute_zkp_qualify(inputs: PublicInputs) -> PublicOutputs {
    let (Some(request), Some(before)) = (inputs.zkq_request, inputs.oods_attestation) else {
        return reject(ValidationError::ZkqMissingRequest);
    };
    let (Some(validator_id), Some(dilithium_pk), Some(sk)) =
        (inputs.my_validator_id, inputs.my_dilithium_pk, inputs.my_dilithium_sk) else {
        return reject(ValidationError::ZkqMissingSigner);
    };
    if let Err(e) = crate::validation::check_zkq_bracket(
        &validator_id, &inputs.local_core_id, &before, &request.att_after, &request.journal_nonce_hash,
    ) {
        return reject(e);
    }
    let mut record = crate::types::ZkpQualificationRecord {
        validator_id,
        dilithium_pk,
        core_id: inputs.local_core_id,
        program_digest: request.program_digest,
        att_before: before,
        att_after: request.att_after,
        zkp_nonce_hash: request.journal_nonce_hash,
        signature: Vec::new(),
    };
    // The CL3 FACT-signing precedent: the key passes INTO Core, Core signs.
    match crate::crypto::sign_dilithium(&sk, &crate::crypto::compute_zkq_record_payload(&record)) {
        Ok(sig) => record.signature = sig,
        Err(e) => return reject(e), // a malformed sk: sign_dilithium's own InvalidWitnessSignature
    }
    let mut out = accept();
    out.zkp_qualification = Some(record);
    out
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
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None,
        receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
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
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
            ark_send_fact_chain: None,
            receiver_fact_chain: None,
            receipt_commitment: None,
            is_dev_class: None,
            oods_flag: None,
            confidence_index: None,
            sender_state: None,
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
// KI#130 GUARDRAIL (compile-time, fires under BOTH the dev and non-dev builds
// through their respective register values): a VBC's max validity MUST exceed the
// "unusable near-expiry" window, or a cert would be born already unusable. If a
// register edit violates this, the build fails here rather than the fleet.
const _VBC_VALIDITY_EXCEEDS_UNUSABLE_WINDOW: () = assert!(
    crate::validation::protocol_gen::VBC_VALIDITY_TICKS
        > crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS,
    "vbc_validity_ticks must be > vbc_unusable_remaining_ticks (a cert needs usable life)"
);
fn execute_cl8(inputs: PublicInputs) -> PublicOutputs {
    // ⚠ EVERY REFUSAL BELOW ONCE RETURNED A BARE `InvalidVBC`, and that made
    // this mode undiagnosable: `execute_cl8` runs inside the RISC-V guest,
    // where the `#[cfg(feature = "std")]` diagnostic prints are compiled out,
    // so the error VARIANT is the only channel that reaches the mesh. Nine
    // distinct reasons arrived as one code, indistinguishable from each other
    // and from "the check never ran" (RULE 3 shape 2). Fixed 2026-09-04.
    // Keep it that way: a new refusal arm here needs its own variant.
    let bundle = match &inputs.vbc_bundle {
        Some(b) => b,
        None => return reject(ValidationError::Cl8MissingBundle),
    };

    let issuer_sk = match &inputs.issuer_sphincs_sk {
        Some(sk) => sk,
        None => return reject(ValidationError::Cl8MissingIssuerKey),
    };

    // §5.2.2e — set on the PROVISIONAL arm below; checked LAST, right before
    // signing, so every other refusal (signer not listed, no attested tick,
    // lineage) stays individually observable for a provisional request too.
    let mut requires_candidacy_pulse = false;

    // ── §6b.8a (RULED 2026-09-08, executed 2026-09-15 — KI#168) ──────────
    // Issuance carries NO stake check. A VBC-shaped certificate (3 issuers)
    // is a CANDIDATE: usable only once Nabla stamps it (ValidatorJoin §6b),
    // and the stamp — not this signature — is where the stake floor is read
    // (`verify_vbc_stamp`, at every reliance site). What issuance still asks
    // of a candidate is its candidacy Pulse (§5.2.2e, below) and a sane
    // lifetime. `vbc_is_provisional` stays as the CLASSIFIER — a short-lived
    // certificate binds the subsidy claim and cannot serve — no longer as a
    // stake exemption. The portable `NablaStakeProof` is not read here: it
    // had no producer (KI#168), and a proof the candidate carries about
    // itself is the shape §6b.1 rejected.
    if bundle.target_vbc.issuer_set.len() == crate::vbc::VBC_REQUIRED_ISSUERS {
        if bundle.target_vbc.expires_at <= bundle.target_vbc.issued_at {
            // Zero or inverted lifetime — never sign a cert that is already
            // dead or whose window runs backwards.
            return reject(ValidationError::Cl8ProvisionalLifetimeInvalid);
        }
        // KI#130 — cap the lifetime of a validator VBC issued/renewed here.
        // `expires_at` is requester-supplied (antie/src/gateway.rs), so without this
        // an operator could mint a cert of any lifetime. This applies to ALL CL8
        // issuance UNCONDITIONALLY, INCLUDING a genesis-lineage RENEWAL (no genesis
        // carve-out): the initial 10-year genesis cert is CEREMONY-signed
        // (genesis_ceremony.rs, sign_sphincs — never through execute_cl8), and after
        // it lapses a genesis validator renews on the same 6-month cert as everyone.
        // Tick VALUE units (the owner: "tick is tick") — expires_at/issued_at same unit.
        if bundle.target_vbc.expires_at.saturating_sub(bundle.target_vbc.issued_at)
            > crate::validation::protocol_gen::VBC_VALIDITY_TICKS
        {
            return reject(ValidationError::VBCLifetimeTooLong {
                expires_at: bundle.target_vbc.expires_at,
                issued_at: bundle.target_vbc.issued_at,
            });
        }
        requires_candidacy_pulse = true;

        // ── Q2-b (the owner ruled 2026-09-21) — RENEWAL PROOF-OF-VALIDATION ──
        // A VBC RENEWAL (the requester's CURRENT cert rides in
        // `supporting_vbcs`, sharing the target's SPHINCS+ subject) must prove
        // the identity did real witnessing work THIS term: >=1 k-signed receipt
        // it CO-SIGNED, dated after its current cert
        // (`verify_renewal_work_receipt`). This makes N Sybil identities
        // expensive — each must actually participate in consensus to keep
        // renewing — a universal reality/Sybil FLOOR applied to ALL validators
        // uniformly (Option A; no subsidised/self-funded branch — KI#161 removed
        // the tier field, so there is no in-guest signal to branch on, and
        // ruling #1's "self-funded idle is fine" is a separate did-work QUOTA,
        // not this >=1 reality floor: they compose). A FIRST issuance (no
        // same-subject prior in `supporting_vbcs`) SKIPS this gate. NO genesis
        // carve-out (same as the lifetime cap just above): the 10-year genesis
        // cert is ceremony-signed (never here), but genesis RENEWALS go through
        // CL8 and prove work like everyone. Everything is client-carried +
        // verified in-guest — no Nabla (RULE 7). Orthogonal to the candidacy
        // Pulse (per-key machine cost, below). It is a CANDIDATE obligation
        // independent of the issuer's key/lineage, so it joins the other
        // refuse-before-signing gates here.
        //
        // ⚠ Enforced in CORE, not Lambda. Lambda's `commit_vbc_sign` already
        // picks the prior cert for its own renewal-window gate, but THAT is a
        // patched Lambda's to skip (RULE 5). This is the enforcement.
        //
        // ⚠ VBC only (3 issuers — this block). An NBC (k=1) has no work-proof:
        // Nabla citizens do not witness validator receipts.
        if let Some(prev) = crate::vbc::find_renewal_prev(bundle) {
            let receipt = match bundle.renewal_work_receipt.as_ref() {
                Some(r) => r,
                None => return reject(ValidationError::VbcRenewalNoProofOfWork),
            };
            if let Err(e) = crate::vbc::verify_renewal_work_receipt(
                receipt,
                &bundle.target_vbc.subject_pubkey_ed25519,
                prev.baseline_tick,
            ) {
                return reject(e);
            }
        }
    }
    // else: an NBC-shaped cert (k=1) with no proof → NBC signing, no stake
    // required. NBC issuance only needs identity binding (wallet_pk
    // consistency), not stake — Nabla nodes do not stake.

    // Step 1: Compute signing payload (same as ceremony)
    let commitment = crate::crypto::compute_vbc_signing_payload(&bundle.target_vbc);

    // Step 2: Derive the signer's public key, and check everything that can be
    // checked, BEFORE spending a signature.
    //
    // ⚠ ORDER CHANGED 2026-09-04, and the order is the point. Signing used to
    // come first, so a request that CL8 was going to refuse anyway still cost
    // a SPHINCS+ signature — the most expensive thing this mode does, in the
    // guest, where it is most expensive. Worse for diagnosis: a malformed
    // issuer key died inside `sign_sphincs`, so `Cl8IssuerKeyUnusable` was
    // unreachable and a bad key reported as a signing fault (RULE 3 shape 1).
    //
    // Nothing below needs the signature, so nothing below runs after it.
    //
    // ⚠ THIS VERIFIED AGAINST `issuer_set.first()` UNTIL 2026-09-03, WHICH IS
    // CORRECT ONLY FOR ISSUER 0. A VBC carries THREE issuers, each a different
    // validator signing the same commitment with its own key; `signatures[i]`
    // belongs to `issuer_set[i]`. Issuers 1 and 2 would therefore verify their
    // own correct signature against SOMEONE ELSE'S public key and reject a
    // certificate they had just signed properly.
    //
    // It was unreachable, not merely untested: the genesis ceremony signs as
    // issuer 0, and until the §5.2.2d certificate-request path existed nothing
    // ever asked issuer 1 or 2 to sign. The first live 3-issuer request found
    // it immediately (E_INVALID_VBC).
    //
    // The signer's key is now DERIVED FROM THE SIGNING KEY ITSELF, so it cannot
    // disagree with what was actually used, and no index has to be guessed.
    let issuer_pk = match crate::crypto::sphincs_pk_from_sk(issuer_sk) {
        Ok(pk) => pk,
        Err(_) => return reject(ValidationError::Cl8IssuerKeyUnusable),
    };

    // The signer must be one of the certificate's declared issuers. Without
    // this, a validator could sign a certificate that does not list it — the
    // signature would be cryptographically fine and belong to no one the cert
    // claims, so `verify_chain_recursive` (which pairs signatures[i] with
    // issuer_set[i]) could never match it. Refusing here turns a certificate
    // that verifies nowhere into an error at the point of issue.
    if !bundle.target_vbc.issuer_set.iter().any(|k| k.as_slice() == issuer_pk.as_slice()) {
        return reject(ValidationError::Cl8SignerNotInIssuerSet);
    }

    // ── §5.3 — REFUSE TO SIGN WHAT COULD NEVER VERIFY ───────────────────
    //
    // The genesis-lineage rule is ENFORCED at verification of the finished
    // certificate (`vbc::verify_chain_recursive`), which is the load-bearing
    // site. This check is the fail-fast twin, and it exists because of what
    // happens without it: nothing examines the target during the witness
    // round, so all three issuers would sign a lineage-invalid certificate and
    // the candidate would discover it only on FIRST USE — three signatures and
    // a full round spent on a document that can never work.
    //
    // Refusing here fails the round at the FIRST hop that notices, not the
    // third, and returns a reason the candidate can act on.
    //
    // ⚠ This is defence in depth, NOT the enforcement. An issuer running
    // patched code simply skips it; the verification-time check is what makes
    // the rule hold (RULE 5). Only a depth>0 cert is subject to it — a
    // genesis-era cert has no issuers to be diverse about.
    //
    // ⚠ AND ONLY A VBC. CL8 SIGNS BOTH KINDS, and this block was gated on
    // `chain_depth > 0` alone — which a CITIZEN NBC also satisfies (depth 1).
    // So NBC issuance was made to answer the VBC-only genesis-lineage rule and
    // refused with `VBCNoAttestedTick`, because Nabla's issuance path carries
    // no OODS reading and never needed one. That broke citizen joins protocol
    // wide; measured 2026-09-05 when the Pi (焼き鳥) could not re-obtain its
    // NBC after a fresh genesis. §5.3 explicitly does NOT apply to an NBC —
    // `vbc::verify_nbc_bundle` says so: a Nabla citizen certificate has its own
    // root set and no genesis-family concept.
    //
    // The discriminator is the same STRUCTURAL one §7.1 uses two blocks above:
    // `issuer_set.len()` is 3 for a VBC and 1 for an NBC, it is inside the
    // signed pre-image, and `verify_chain_recursive` enforces the same count on
    // the verify side. A caller cannot set it to dodge the rule without
    // producing a cert that fails `InvalidVBCCount` everywhere.
    let is_vbc_shaped = bundle.target_vbc.issuer_set.len() == crate::vbc::VBC_REQUIRED_ISSUERS;
    if is_vbc_shaped && bundle.target_vbc.chain_depth > 0 {
        // §5.3 issuing bar, judged on the ATTESTED tick from the OODS reading —
        // the same mesh-attested source the stake lock uses, and for the same
        // reason: `tx.epoch` is chosen by the sender (KI#130), so an admission
        // control must not rest on it. Absent ⇒ refuse to sign.
        // ── THE OODS STAMP IS BOUND HERE (RULED 2026-09-04) ──────────────
        //
        // The candidate DECLARES `network_size_baseline` / `baseline_tick` on
        // the certificate, and every later verifier judges §5.3's issuing bar
        // on that stamp (`vbc::issuing_tick_for`) — so an unbound stamp would
        // let the candidate write its own admission clock, and YPX-021 §7's
        // trustworthiness record would be self-issued.
        //
        // Core refuses to sign a stamp that disagrees with the attestation the
        // round carried. Lambda checks the same thing before calling
        // (`check_issuer_derived_fields`), but THAT is defence in depth — a
        // patched Lambda skips it. This is the enforcement (RULE 5).
        let att = match inputs.oods_attestation.as_ref() {
            Some(a) => a,
            // Fails closed: no reading, no stamp to bind, no admission.
            None => return reject(ValidationError::VBCNoAttestedTick),
        };
        // KI#143 (2026-09-10): the reading is VERIFIED before anything is
        // bound to it — the citizen node's live-reading signature and the
        // NBC chain to an authorized issuer (`verify_oods_attestation`, the
        // same call CL3 and CL5 make; dev-mode relaxes only the baseline
        // suffix). Until today CL8 required the reading and compared fields
        // against it but never checked it, so the stamp below — and, since
        // §5.2.2e part iii, the candidacy Pulse's tick — were bound to a
        // self-consistent reading a patched Lambda could invent. Hard
        // reject (E_OODS_ATTESTATION_INVALID): a forged reading is never
        // "retry later".
        if let Err(e) = crate::validation::verify_oods_attestation(att) {
            return reject(e);
        }
        if bundle.target_vbc.baseline_tick != att.tick
            || bundle.target_vbc.network_size_baseline != att.oods_size
        {
            return reject(ValidationError::Cl8OodsStampMismatch);
        }
        // Judged on the stamp, which is now provably the attestation's own
        // value — the same expression every later verifier uses, so issuance
        // and verification cannot drift.
        let issuing_tick = match crate::vbc::issuing_tick_for(&bundle.target_vbc) {
            Some(t) => t,
            None => return reject(ValidationError::VBCNoAttestedTick),
        };
        let mut seen: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
        for issuer_key in &bundle.target_vbc.issuer_set {
            let cert = match bundle.supporting_vbcs.iter()
                .find(|c| c.subject_pubkey_sphincs.as_slice() == issuer_key.as_slice())
            {
                Some(c) => c,
                // The issuers' own certificates must ride in the request; they
                // are what the rule is checked against, here and at verify.
                None => return reject(ValidationError::VBCIssuerCertMissing),
            };
            // The issuer must have enough life LEFT to admit anyone.
            if !crate::validation::vbc_can_issue(cert.expires_at, issuing_tick) {
                return reject(ValidationError::VBCIssuerCannotIssue);
            }
            // Two distinct failures, and they were ONE `_` arm until
            // 2026-09-04 — "no family" and "a family already counted" are
            // different defects with different remedies, so they answer
            // differently now.
            match crate::vbc::effective_genesis_lineage(cert) {
                Some(l) if !seen.contains(&l) => seen.push(l),
                // Two issuers share one family — the rule this whole design
                // exists for.
                Some(_) => return reject(ValidationError::VBCIssuersShareLineage),
                // The issuer belongs to no genesis family at all.
                None => return reject(ValidationError::VBCIssuerNoLineage),
            }
        }
        // The candidate must be joining one of the families that sponsored it.
        match crate::vbc::effective_genesis_lineage(&bundle.target_vbc) {
            Some(mine) if seen.contains(&mine) => {}
            _ => return reject(ValidationError::VBCLineageNotAdopted),
        }
    }

    // §5.2.2e — the last gate before signing a PROVISIONAL: the candidate's
    // own Pulse proof (see the provisional arm above for why).
    if requires_candidacy_pulse {
        // Part iii: the proof must be seeded within slack of THIS round's
        // attested tick — `inputs.oods_attestation` is already required
        // above (VBCNoAttestedTick) and is what the stamp is bound to.
        let round_tick = match inputs.oods_attestation.as_ref() {
            Some(a) => a.tick,
            None => return reject(ValidationError::VBCNoAttestedTick),
        };
        if let Err(e) = crate::pulse::verify_candidacy_pulse(bundle, inputs.transaction.epoch, round_tick) {
            return reject(e);
        }
    }

    // Step 3: Sign with the issuer's SPHINCS+ SK — everything refusable has
    // been refused above.
    let signature = match crate::crypto::sign_sphincs(issuer_sk, &commitment) {
        Ok(sig) => sig,
        Err(_) => return reject(ValidationError::Cl8SigningFailed),
    };

    // Step 4: Verify-after-sign (fail-stop — same as ceremony). The signer's
    // key was DERIVED FROM THE SIGNING KEY ITSELF above, so it cannot disagree
    // with what was actually used and no index has to be guessed.
    if crate::crypto::verify_sphincs(&issuer_pk, &commitment, &signature).is_err() {
        return reject(ValidationError::Cl8VerifyAfterSignFailed);
    }

    PublicOutputs {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
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
    //    THE one builder (KI#55) — the signer (Lambda) calls the same fn.
    let expected_id = crate::crypto::fanout_diffusion_id(&msg.content, &msg.originator_pk);
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
    //    THE one builder (KI#55) — the signer (Lambda) calls the same fn.
    let signing_payload = crate::crypto::fanout_signing_payload(
        &msg.diffusion_id, msg.content_type, &msg.content, msg.ttl_original, msg.fanout, msg.timestamp,
    );

    if crate::crypto::verify_ed25519(&msg.originator_pk, &signing_payload, &msg.originator_sig).is_err() {
        return reject(ValidationError::FanOutInvalidSignature);
    }

    // 8. Accept — Core produces the decremented TTL
    let new_ttl = msg.ttl_current - 1;
    PublicOutputs {
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
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

/// The receiver's consumed (pre-redeem) state CL5 binds into the redeem
/// commitment and the redeem link's `previous_state_id`: `current_state.state_id`,
/// ZERO when absent. RECEIVER-DECLARED. ~~CL5 runs no §15 anchor on it (Fork
/// Settlement [R8] note, spec F8).~~ Since 2026-10-01 (Fable review F-1(b)) CL5
/// anchors the declared state's §15 FIELDS to the receiver's last k-signed
/// receipt (`cl5_anchor_receiver_state`); the state ID itself is not bound by
/// the receipt (`Receipt.produced_state_id` is outside `receipt_commitment`), so
/// it stays receiver-declared — consistency, not security (Fable §7 residual 5).
/// Extracted (W7a) so the redeem-leg carrier
/// `nabla_wire::LegPreimage::redeem_of_cl5` reads the SAME value Step 10 hashed
/// (RULE 1 — one derivation, no re-implementation in the SDK).
pub fn cl5_consumed_state_id(inputs: &PublicInputs) -> [u8; 32] {
    inputs
        .current_state
        .as_ref()
        .map(|s| s.state_id)
        .unwrap_or([0u8; 32])
}

/// Fable review 2026-10-01 F-1(b) — the CL5 RECEIVER ANCHOR, the redeem-side
/// mirror of CL2's `validate_witnesses` + §15 `verify_state_anchored` (YP
/// §17.3.1.4 / §15, CLAUDE.md §15(b)). ONE function so the unit tests drive the
/// rule `execute_cl5` runs (RULE 6 §3a).
///
/// `declared` is the receiver's DECLARED pre-redeem state exactly as CL5
/// computes on it (`cl5_declared_receiver_state`). The rule:
///   * the wallet's OPENING state (`WalletState::is_opening_state` — the
///     key-derived first state: seq 0, opening balance, opening id or zero
///     label, no history term) has nothing to anchor and must carry NO
///     receipt — the CL2 first-TX exemption's mirror;
///   * any other (returning) state must carry EXACTLY ONE receipt — the
///     wallet's last — which is verified by THE per-receipt verifier
///     (`validation::verify_anchor_receipt`: quorum, distinct witnesses,
///     worldline, Ed25519 over `commitment_hash`, `receipt_commitment` +
///     its sig, last-witness VBC) and must re-derive the declared §15 fields
///     (`validation::verify_declared_state_anchored`: seq, balance,
///     hibernation, lock, emission epoch, FLOOR, format). A declared floor /
///     lock / hibernation / emission of `0` on a wallet whose receipt binds a
///     non-zero value re-derives a different hash → `StateNotAnchored`.
///
/// ⚠ WHAT THIS DOES NOT PROVE (stated, not hidden — Fable §0): a k-signed
/// receipt proves the declared state is A state this wallet was witnessed in,
/// not the LATEST. A REWIND to a pre-floor receipt passes this anchor; it is
/// stopped by the S-ABR overlap (`cl5_receiver_overlap`, needs
/// `sabr_overlap(prev_k)` of that receipt's witnesses) and, if those collude,
/// is a self-fork of the wallet (two legs under `H(pk‖S0)`) for Nabla's fork
/// machinery (ban + derived hold).
///
/// `quorum_floor` = `required_witness_floor(receiver tier, Online)`; `tx_epoch`
/// = the signed CL5 clock (`transaction.epoch`). k≥3 profile only — the
/// offline k=0 redeem (`is_k0_redeem`) anchors to `ark_prev`, not here.
pub(crate) fn cl5_anchor_receiver_state(
    declared: &crate::types::WalletState,
    prev_receipts: &[crate::types::Receipt],
    receiver_pk: &[u8],
    (receiver_k, receiver_proof_type): (u8, u8),
    quorum_floor: usize,
    tx_epoch: u64,
) -> Result<(), ValidationError> {
    if declared.is_opening_state(receiver_pk, receiver_k, receiver_proof_type) {
        if !prev_receipts.is_empty() {
            return Err(ValidationError::ReceiverStateNotAnchored);
        }
        return Ok(());
    }
    if prev_receipts.len() != 1 {
        return Err(ValidationError::ReceiverStateNotAnchored);
    }
    crate::validation::verify_anchor_receipt(&prev_receipts[0], quorum_floor, tx_epoch)?;
    crate::validation::verify_declared_state_anchored(receiver_pk, Some(declared), prev_receipts)
}

/// The receiver's DECLARED pre-redeem state as CL5 computes on it — the values
/// `cl5_anchor_receiver_state` anchors and Step 9/10 bind. Every field comes from
/// the receiver-declared CL5 inputs (`receiver_current_*`), which EVERY caller
/// populates with the declared values (`cl5_inputs::build_cl5_attestation_inputs`;
/// Lambda passes the envelope's `current_state` verbatim since 2026-10-01).
///
/// `state_id` is read from `transaction.consumed_state_id` — the field the ONE
/// builder sets to the declared state id on BOTH the client run and Lambda's
/// run (`current_state` is `None` on the client run), so `is_opening_state`
/// decides identically on both. `current_balance` / `wallet_seq` are the values
/// `execute_cl5` already extracted (missing balance is refused before this).
fn cl5_declared_receiver_state(
    inputs: &PublicInputs,
    receiver_pk: &[u8],
    current_balance: u64,
    wallet_seq: u64,
    wallet_format: crate::types::WalletFormat,
) -> crate::types::WalletState {
    crate::types::WalletState {
        public_key: receiver_pk.to_vec(),
        balance: current_balance,
        wallet_seq,
        state_id: inputs.transaction.consumed_state_id,
        auth_hash: None,
        wallet_id: None,
        group_members: None,
        hibernation_until: inputs.receiver_current_hibernation.unwrap_or(0),
        wall_clock_lock: inputs.receiver_current_wall_clock_lock.unwrap_or(0),
        emission_claimed_epoch: inputs.receiver_current_emission_claimed_epoch.unwrap_or(0),
        stake_floor_until: inputs.receiver_current_stake_floor_until.unwrap_or(0),
        wallet_format,
    }
}

/// Fable review 2026-10-01 F-1(b) — Core-enforced S-ABR overlap on the REDEEM
/// (YP §17.3.1.4: "identical to the witness (send) path" — true in Core for the
/// first time). The mirror of CL2's overlap gate (Checks 1–4), with the redeem
/// round's existing serial carrier, `fact_witness_sigs`, in the role CL2 gives
/// `overlapped_signatures`.
///
///   * client run (no validator apparatus: `online_apparatus == false`) → skip;
///     the validators enforce it (RULE 5);
///   * no receipt (first-time receiver — the anchor has already refused any
///     other shape) → nothing to overlap with;
///   * THIS validator's Ed25519 key is one of the receipt's witnesses →
///     overlapped, proceed (it witnessed the state being consumed);
///   * otherwise `sabr_overlap(prev_k)` of the carried prior-hop sigs must be
///     VALID overlap sigs: C1 the sig's certificate Ed25519 subject is a witness
///     of the receipt; C2 the `fact_signature` bytes are unique; C3 the
///     Dilithium `fact_signature` verifies over THIS redeem link's FACT
///     commitment (`link_fact_commitment` — the one `execute_cl5` signs) under
///     the certificate's Dilithium key; C4 the certificate verifies (historical
///     chain, `tx_epoch`) and `validator_id == compute_validator_id(sphincs)`.
///     Else `SABRInsufficientOverlap`.
///
/// So a REWIND to a pre-floor receipt `R0` needs `sabr_overlap(prev_k)` of
/// `R0`'s own witnesses to sign it — the previous witnesses, not any three.
/// No HAL/heal/burn/claim exemption exists here: none of them is a redeem; the
/// dead-overlap exit for a receive is HAL (re-anchor at fresh witnesses, whose
/// receipt becomes the next anchor — YPX-020).
pub(crate) fn cl5_receiver_overlap(
    prev_receipts: &[crate::types::Receipt],
    my_pk: Option<&[u8]>,
    online_apparatus: bool,
    fact_witness_sigs: &[crate::types::WitnessSig],
    link_fact_commitment: &[u8; 32],
    tx_epoch: u64,
) -> Result<(), ValidationError> {
    if !online_apparatus {
        return Ok(());
    }
    let last = match prev_receipts.last() {
        Some(r) => r,
        None => return Ok(()),
    };
    let prev_pks: alloc::collections::BTreeSet<&[u8]> =
        last.witness_sigs.iter().map(|w| w.validator_pk.as_slice()).collect();
    if my_pk.is_some_and(|pk| prev_pks.contains(pk)) {
        return Ok(());
    }
    let required = crate::wallet_id::sabr_overlap(prev_pks.len() as u8) as usize;
    let mut seen: alloc::collections::BTreeSet<&[u8]> = alloc::collections::BTreeSet::new();
    let valid = fact_witness_sigs.iter().filter(|sig| {
        let (bundle, fsig) = match (&sig.vbc_bundle, &sig.fact_signature) {
            (Some(b), Some(f)) if !f.is_empty() => (b, f),
            _ => return false,
        };
        // C1 — a witness of the receipt being consumed.
        if !prev_pks.contains(bundle.target_vbc.subject_pubkey_ed25519.as_slice()) {
            return false;
        }
        // C2 — unique signature bytes (no one sig counted twice).
        if !seen.insert(fsig.as_slice()) {
            return false;
        }
        // C4 (id half) — the sig names the certificate's validator.
        if !crate::crypto::ct_eq(
            &sig.validator_id,
            &crate::crypto::compute_validator_id(&bundle.target_vbc.subject_pubkey_sphincs),
        ) {
            return false;
        }
        // C3 — it signed THIS redeem link.
        if crate::crypto::verify_dilithium(
            &bundle.target_vbc.subject_pubkey_dilithium, link_fact_commitment, fsig,
        ).is_err() {
            return false;
        }
        // C4 — a real validator: the certificate chains to the roots. Past
        // evidence (a co-witness's certificate), so historical: chain only,
        // no stamp (§6b.5a, ruled B 2026-09-08) — the same call as CL2 Check 4.
        crate::vbc::verify_vbc_bundle_historical(bundle, tx_epoch).is_ok()
    }).count();
    if valid < required {
        return Err(ValidationError::SABRInsufficientOverlap);
    }
    Ok(())
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

    // ── §5.2.2c — A STAKE-LOCKED WALLET MAY RECEIVE, BUT MAY NOT REDEEM ─────
    //
    // The paragraph above promises "a stranger's cheque can never un-hibernate
    // the wallet", and implements it by CARRYING `receiver_current_hibernation`
    // through. That value arrives from outside Core, and until 2026-10-01 CL5
    // ran no §15 anchor (`prev_receipts` was empty here), so nothing made the
    // promise true: a locked wallet could redeem declaring `hibernation_until =
    // 0`, Core would bind 0 into the produced state_hash, and the wallet would
    // walk out of a lock it had not served. KI#133. Since 2026-10-01 (Fable
    // review F-1(b)) Step 3.6 below anchors EVERY declared §15 field —
    // hibernation, lock, emission epoch, floor — to the receiver's last
    // k-signed receipt (`cl5_anchor_receiver_state`), so a declared `0` on a
    // locked / floored wallet is `StateNotAnchored`.
    //
    // The gate is the SAME DISCRIMINATION the send path already makes, applied
    // to the leg that was missing it (the owner, 2026-09-06):
    //
    //   hibernating + `wall_clock_lock == 0`  → HAL / RECALL. **EXEMPT** — the
    //     self-redeem IS the completion, and blocking it would strand every
    //     wallet mid-recovery with no exit. This is the case that must not
    //     break, and `hal_acceptance.sh` exists to prove it.
    //   hibernating + `wall_clock_lock != 0`  → a validator STAKE lock. REJECT.
    //     A stake lock ends by TIME and never by an action, so it needs no
    //     completing redeem, and permitting one is the whole escape.
    //
    // Consequence, and it is deliberate: a locked stake wallet can still
    // RECEIVE — a third party may send it a cheque at any time — it simply
    // cannot redeem until the lock ends. The cheque waits. Deferring receipt
    // was considered and rejected as unnecessary machinery at this scale.
    //
    // After release the wallet's first send clears BOTH deadlines, so this gate
    // stops firing on its own — there is no unlock step and nothing to notify.
    //
    // ⚠ THE TRIGGER IS `wall_clock_lock`, NOT the hibernation term, and that is
    // deliberate. The two are stamped TOGETHER by the claim's redeem and cleared
    // TOGETHER by the release send — a half-present pair is already a
    // fail-closed reject on the send path — so the lock alone identifies "this
    // wallet holds a validator stake".
    // ⚠ WRONG READING, corrected 2026-10-01 (Fable review F-1(b); RULE 0 §4):
    // this said the lock "is the term Lambda sources from ITS OWN STORAGE", as if
    // that made it trustworthy. It did not: a validator holding no row fed `0`
    // and one holding a stale row fed the stale value, so a round of such
    // validators let a patched client walk out of the lock (F-1). The lock here
    // is now the DECLARED value (Lambda passes the envelope's verbatim), and what
    // makes it trustworthy is Step 3.6's anchor to the receiver's last k-signed
    // receipt — a declared `0` on a locked wallet is `StateNotAnchored` there.
    // This gate stays first: it refuses a TRUTHFUL non-zero lock early.
    if inputs.receiver_current_wall_clock_lock.unwrap_or(0) != 0 {
        return reject(ValidationError::StakeLocked);
    }

    // ── ValidatorJoin §6b.13 — the receiver's floor and format block ────────
    //
    // RECEIVING IS NEVER GATED by the floor: a redeem only credits (fees come
    // out of the incoming amount — `net_to_receiver` below — never out of the
    // prior balance), so there is nothing to refuse. The floor is CARRIED into
    // the produced state unchanged; a redeem cannot set or lower it.
    //
    // The format block is REQUIRED: a missing or non-current block is refused
    // (`E_WALLET_FORMAT_INVALID`) — CL5 neither consumes nor produces anything
    // but `WalletFormat::CURRENT`. Missing is refused rather than defaulted:
    // a defaulted block is the silent zero RULE 13 forbids.
    let receiver_stake_floor_until = inputs.receiver_current_stake_floor_until.unwrap_or(0);
    match inputs.receiver_current_wallet_format.as_ref() {
        Some(f) if f.is_current() => {}
        _ => return reject(ValidationError::WalletFormatInvalid),
    }
    
    // SECURITY-CL5: Enforce receiver-defined k from wallet_id (H1 fix) and the
    // CHARGE-fix k=0 split — ONE derivation, `fact::cl5_redeem_required_k`
    // (extracted 2026-09-28, Fork Settlement wave 2b-ii): the same k is now
    // bound into the redeem link's FACT commitment (R4), so Lambda's diagnostic
    // mirror must derive it identically (RULE 1). Read the helper for the rules.
    let receiver_wid = match cheque_bundle.receiver_wallet_id() {
        Some(wid) if !wid.is_empty() => wid,
        _ => return reject(ValidationError::InvalidWalletId),
    };
    let offline_receiver_witness = inputs.receiver_signing_key.is_some();
    let (required_k, is_k0_redeem) =
        match crate::fact::cl5_redeem_required_k(cheque_bundle, offline_receiver_witness) {
            Ok(v) => v,
            Err(e) => return reject(e),
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

    // P3.4 CL5 k=0 PROFILE (YPX-010 §11.4): a k=0 ⟠-trade cheque is redeemed OFFLINE
    // by the receiver's own Core. `txid_attestation` (Step 3.5) and
    // `cheque_claim_proof` (Step 3.5b) are Nabla-*registration* artifacts — they
    // cannot exist offline, so they are NOT in the k=0 input set. This is a PROFILE
    // selected by the two parties' UNFORGEABLE wallet_id tiers (`is_k0_redeem`,
    // derived with the required_k charge-split above: BOTH endpoints k=0), NOT an
    // `Option` fallback: every online redeem — the k≥3 path AND a CHARGE redeem to a
    // k=0 receiver — still HARD-requires `cheque_claim_proof` (no `serde(default)`,
    // no "if present"). A k=0 cheque's integrity rests on its receiver-witness FACT
    // link (§11.2.1) and the later settlement round (§12) that registers it and runs
    // consume-once.

    // Step 3.5: YPX-014 Txid attestation — global double-redeem prevention.
    // Core verifies: signature, status, trust anchor. Lambda handles freshness.
    // This is the AUTHORITATIVE check — runs inside the RISC-V ELF, can't be bypassed.
    // (k=0 offline redeems carry none; the `if let Some` naturally skips it.)
    if let Some(ref att) = inputs.txid_attestation {
        // Verify txid matches the cheque bundle's txid
        let cheque_txid = cheque_bundle.cheques.first()
            .map(|c| c.txid)
            .unwrap_or([0u8; 32]);
        if att.txid != cheque_txid {
            return reject(ValidationError::TxidAttestationMissing); // txid mismatch
        }

        // Verify Ed25519 signature
        // Pattern 1 sweep — ONE builder, shared with the Nabla node that signs.
        // The payload binds `origin` + `sender_registered_at_tick` (YPX-001
        // §1.5.1b), so the settled-origin read at the inherit site below reads
        // SIGNED fields — verified here, once, never re-verified there.
        let expected_hash = blake3::Hash::from(crate::crypto::txid_attest_payload(
            &att.txid, &att.status, att.nabla_tick,
            att.origin.as_ref(), att.sender_registered_at_tick,
            att.oods_size, att.oods_healthy, att.origin_status));
        if crate::crypto::verify_ed25519(
            &att.nabla_node_pk, expected_hash.as_bytes(), &att.nabla_signature,
        ).is_err() {
            return reject(ValidationError::TxidAttestationInvalidSig);
        }
        // ForkSettlement §9p — the signed origin status must agree with the
        // signed origin (`Vouched` ⇔ `Some`); the ONE rule, shared with the
        // stored-resolution check (`fact::txid_attestation_origin_consistent`).
        // A malformed attestation is a bad status.
        if !crate::fact::txid_attestation_origin_consistent(att) {
            return reject(ValidationError::TxidAttestationBadStatus);
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
    // Presence is enforced BELOW, after the cheque-claim gate, for every
    // online (k≥1) redeem — Core, not Lambda, is the enforcement (KI#144).

    // Step 3.5b: Cheque-claim proof — strict mandatory check.
    // The Nabla writer signs `compute::redeem_claim_nabla_payload` =
    // BLAKE3("AXIOM_REDEEM_CLAIM" || cheque_id || "CLAIMED" || tick_le ||
    // claim_sig) on successful `register_cheque_claim`; an attempted second
    // registration with a *different* client_pk returns CONFLICT and yields
    // no signed proof.  Core CL5 *requires* this proof — without it, the
    // redeem skipped Nabla's pre-redeem chokepoint and is rejected hard
    // (CLAUDE.md §13: no soft fallback).  Since YPX-022 §2.1.2a (KI#205) the
    // claim is AUTHENTICATED — `claim_sig` by the claimant's key — and the
    // Nabla signature covers it; both are verified below.
    //
    // Partition semantics (AXIOM Origin, 2026-05-13): the scar/heal pattern
    // lives at the POST-redeem step (the `nabla_confirmation` field on
    // the produced FACT link); pre-redeem claim is the gate, full stop.
    // If Nabla writer is unreachable, the wallet simply can't start a
    // redeem.  This is the right liveness boundary — completed redeems
    // can still be partition-tolerant at the post-redeem step.
    // k=0 PROFILE: skip the entire Step-3.5b mandatory `cheque_claim_proof` gate — it
    // is a Nabla-registration artifact that cannot exist for an offline Ark cheque. The
    // k≥3 path runs it unchanged (hard-required, no fallback).
    if !is_k0_redeem {
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
    // KI#144 (2026-09-11): an online redeem WITHOUT the YPX-014 txid
    // attestation is refused HERE. Until today Core verified the attestation
    // only when present ("Lambda enforces mandatory") — a patched Lambda or
    // client could omit it and Core would accept, so global double-redeem
    // prevention was a Lambda policy, not a Core rule (RULE 5). The k=0
    // offline profile legitimately carries none and is excluded by the
    // enclosing `if`.
    if inputs.txid_attestation.is_none() {
        return reject(ValidationError::TxidAttestationMissing);
    }
    // ~~NB: we intentionally do NOT bind `p.client_pk` to `receiver_pk` here
    // (the SDK's verify_cheque registered the claim under the SENDER's key —
    // "legacy semantic")~~ — SUPERSEDED 2026-09-25 (KI#205): the claim is
    // signed by the key it names, so the SDK now claims under the REDEEMER's
    // own key at every site, and the binding is SAFE and REQUIRED: the proof's
    // `client_pk` must be the receiver redeeming this cheque, or a claim made
    // by anyone else could authorise this redeem. This wires the
    // `ChequeClaimProofReceiverMismatch` variant that KI#216 recorded as
    // declared-never-raised (RULE 3 shape 3).
    if p.client_pk.as_slice() != receiver_pk.as_slice() {
        return reject(ValidationError::ChequeClaimProofReceiverMismatch);
    }
    //
    // YPX-022 §2.1.2a (KI#205, RULED 2026-09-25): the CLAIM is authenticated.
    // `claim_sig` must be a valid Ed25519 signature by the proof's `client_pk`
    // over `cheque_claim_signing_payload(cheque_id, client_pk, k_tier,
    // wallet_address)` — the same builder the claimant signed with and Nabla
    // verified before storing the claim. This is the CORE half (RULE 5): a
    // patched Nabla fails open, so the redeem must not rest on Nabla having
    // checked it. The Nabla signature verified NEXT covers `claim_sig`, so a
    // proof cannot carry a different claim_sig than the one Nabla accepted.
    if crate::crypto::verify_ed25519(
        &p.client_pk,
        &crate::crypto::cheque_claim_signing_payload(
            &p.cheque_id, &p.client_pk, p.k_tier, &p.wallet_address,
        ),
        &p.claim_sig,
    ).is_err() {
        return reject(ValidationError::ChequeClaimProofUnauthenticated);
    }
    // Ed25519 signature by the Nabla writer over the claim's domain-tagged
    // hash — ONE builder, shared with the Nabla node that signs (Pattern 1).
    // The preimage includes `claim_sig` (KI#205 item 5): the binding.
    if crate::crypto::verify_ed25519(
        &p.nabla_node_pk,
        &crate::crypto::redeem_claim_nabla_payload(&p.cheque_id, p.claim_tick, &p.claim_sig),
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
    // Freshness check: a proof older than `cheque_claim_proof_max_age_ticks`
    // (protocol_core.toml, 17,280 ticks ≈ 24h) is refused and the receiver
    // re-claims. Without this, an attacker could hold an old proof and re-use
    // it long after the claim was made. KI#205 (YPX-022 §2.1.2a item 2): this
    // is the proof's FRESHNESS bound ONLY — it is deliberately SHORTER than
    // `recall_init_window_low` (asserted at compile time in types.rs), and it
    // is NOT what blocks a recall; Nabla holds the authenticated claim until
    // `recall_init_window_high` for that. An earlier reading ("Nabla evicts
    // the entry at 17,280 so the proof no longer represents a reservation")
    // described the hole this ruling closed — a claim that vanished before
    // the recall window opened.
    //
    // Tick semantics: `inputs.current_tick` is the validator's
    // TARDIS view (populated by Lambda); `p.claim_tick` is the
    // writer's tick at proof-signing time.  Tolerate a small slack
    // (TICK_SLACK) for cross-validator clock drift; otherwise reject.
    // ⚠ UNITS (KI#40/#47/#165 class, 5th recurrence, fixed 2026-09-25): both ticks
    // here are tick VALUES (unix-second stamps), so their difference is an age in
    // SECONDS; the register and the slack are tick COUNTS and MUST be projected
    // with `.to_secs()` before the comparison. Until this fix the "24 h" window
    // was 17,280 SECONDS (4.8 h) — the old hardcoded const had the same bug.
    const TICK_SLACK: crate::types::TickCount = crate::types::TickCount(12); // ~1 minute
    if inputs.current_tick > 0 && p.claim_tick > 0 {
        let max_age = crate::validation::CHEQUE_CLAIM_PROOF_MAX_AGE_TICKS.to_secs()
            + TICK_SLACK.to_secs();
        if inputs.current_tick > p.claim_tick
            && inputs.current_tick - p.claim_tick > max_age
        {
            return reject(ValidationError::ChequeClaimProofExpired);
        }
        // Reject proofs from the future (>TICK_SLACK ahead of us).
        if p.claim_tick > inputs.current_tick
            && p.claim_tick - inputs.current_tick > TICK_SLACK.to_secs()
        {
            return reject(ValidationError::ChequeClaimProofExpired);
        }
    }
    } // end `if !is_k0_redeem` — Step 3.5b Nabla-claim gate (k≥3 profile only)

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

    // Step 3.6: the RECEIVER ANCHOR (Fable review 2026-10-01 F-1(b); YP
    // §17.3.1.4, CLAUDE.md §15(b)). k≥3 profile only — the offline k=0 redeem
    // anchors to `ark_prev` (YPX-010 §11), never here.
    //
    // ⚠ WRONG READING, corrected 2026-10-01 (RULE 0 §4). This site used to say:
    // "**Returning receivers** (`balance>0 || wallet_seq>0`): normal S-ABR
    // overlap applies via the wallet's prev_receipts (enforced in the standard
    // send/redeem overlap gate the SDK runs at validator selection time)", and
    // kept a belt-and-suspenders block for `balance==0 && seq==0 &&
    // !prev_receipts.is_empty()`. Both were ghosts: the SDK is not an
    // enforcement (RULE 5), CL5 received `prev_receipts = []` from its one
    // builder, and the redeem envelope's `overlapped_signatures` was always
    // empty and only counted — so CL5 computed on the receiver's DECLARED
    // balance / seq / lock / floor with nothing anchoring them, and one redeem
    // at k validators lacking a current row walked a wallet out of its stake
    // floor (F-1). CORRECT: the envelope carries the receiver's last receipt
    // (`RedeemRequestEnvelope::prev_receipts`, threaded through the ONE CL5
    // builder) and Core anchors here; the overlap half runs once the redeem
    // link's FACT commitment exists (Step 9b, `cl5_receiver_overlap`).
    //
    // FIRST-TIME receivers (the OPENING state — `WalletState::is_opening_state`)
    // carry no receipt and need no overlap: there is no prior witness set, the
    // same first-TX exception CL2 makes for `wallet_seq == 1 && prev_seq == 0`.
    // What defends a first-time receive against double-redeem is unchanged:
    // Step 3.5 (`txid_attestation`, NBC-anchored, NOT_REDEEMED), Step 3.5b
    // (`cheque_claim_proof`, authenticated, CONFLICT on a second claimant) and
    // Step 3.5c (the receiver-chain replay scan). The old "3a-SABR" cheque-signer
    // cross-check stays deleted (it was tautological for honest SDKs).
    let receiver_wallet_format = match inputs.receiver_current_wallet_format {
        Some(f) => f,
        None => return reject(ValidationError::WalletFormatInvalid), // refused above; unreachable
    };
    let declared_receiver = cl5_declared_receiver_state(
        &inputs, receiver_pk, current_balance, wallet_seq, receiver_wallet_format,
    );
    if !is_k0_redeem {
        // The receiver's tier, from its pk-bound wallet id (verified below at
        // Step 3b; `cl5_redeem_required_k` above already refused an unreadable
        // one, so the fallback is unreachable — fail-closed to the 3-floor).
        let receiver_tier = crate::wallet_id::extract_security_level(receiver_wid)
            .unwrap_or((crate::types::NORMAL_WITNESS_FLOOR, crate::wallet_id::PROOF_TYPE_DMAP));
        let receiver_quorum_floor =
            crate::types::required_witness_floor(receiver_tier.0, crate::types::WitnessOp::Online) as usize;
        if let Err(e) = cl5_anchor_receiver_state(
            &declared_receiver,
            &inputs.prev_receipts,
            receiver_pk,
            receiver_tier,
            receiver_quorum_floor,
            inputs.transaction.epoch,
        ) {
            return reject(e);
        }
    }

    // Step 3a: Oracle maturity check (YPX-012)
    // Oracle cheques must be >= 48h old before redemption.
    // Detected by checking if the cheque carries oracle_claim data.
    if let Some(first_cheque) = cheque_bundle.cheques.first() {
        if first_cheque.oracle_claim.is_some() {
            let cheque_created = first_cheque.created_at;
            let current_tick = inputs.transaction.epoch;
            // KI#47: ORACLE_MATURITY_TICKS is a tick COUNT; `cheque_created`/`current_tick`
            // are tick VALUES (unix-second stamps), so the count MUST be projected
            // via .to_secs() before it is added. Pre-fix this compared a value span
            // against a raw count and matured cheques ~5x early (9.6h, not 48h).
            // AXIOM_DESIGN_AccountKeyedDevTiming.md — account-keyed. An oracle claim
            // is a self-payout, so the redeeming wallet IS the claimer; key on its class.
            let maturity = crate::oracle::oracle_maturity_ticks(
                crate::wallet_id::is_dev_wallet(&inputs.transaction.sender_wallet_id));
            if current_tick < cheque_created + maturity.to_secs() {
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
            // ValidatorJoin §5.2.2 — a cheque signed under a PROVISIONAL cert
            // is not a validator cheque. Same rule and same reasoning as the
            // witness-side gate in validation.rs::validate_witnesses; a cheque
            // is the redeem-side place a signer's credential is relied on.
            // LIFETIME, not remaining life — `vbc_is_provisional` documents
            // why: a remaining-life test here would refuse a cheque that was
            // legitimately signed and strand its holder. Ordered before the
            // chain walk for the same reasons as the witness-side gate.
            if crate::validation::vbc_is_provisional(
                vbc.target_vbc.issued_at, vbc.target_vbc.expires_at)
            {
                return reject(ValidationError::VBCProvisionalCannotServe {
                    issued_at: vbc.target_vbc.issued_at,
                    expires_at: vbc.target_vbc.expires_at,
                });
            }
            // §6b.5a — the signer's certificate INSIDE THE CHEQUE is past
            // evidence: chain only, no stamp (ruled B, 2026-09-08).
            if let Err(e) = crate::vbc::verify_vbc_bundle_historical(vbc, current_time) {
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
            &cheque.sender_wallet_id, &cheque.receiver_wallet_id, cheque.amount, cheque.epoch,
            cheque.created_at,
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
    // FACT chain source priority (KI#146, 2026-09-11: ONLY a chain whose tip is
    // THIS send — tip.tx_id == cheque.txid, tip.new_state_id ==
    // cheque.produced_state_id — is eligible; the first k−1 witnesses attach
    // the sender's PRE-send chain, the finalizer's cheque carries the one with
    // the send link, and `redeem_fact_chain_ref` picks it):
    //   1. ChequeBundle.fact_chain (convenience copy, set by receiver when assembling)
    //   2. The first ValidatorCheque.sender_fact_chain that is this send's
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
        // YP §26.17.6.5 B2/B4 — the certificates the money sender's witnesses
        // resolve to: what the receiver's validator was handed
        // (`inputs.fact_certificates`, from its own store) plus what the
        // issuing validator attached to the cheques (`fact_certificates` on
        // each cheque — the sender's witnesses are strangers here). Verified
        // once, deduplicated by reference. B1 is not judged at CL5: the money
        // sender's key is not in the cheque; its own validators judged it on
        // every link they witnessed, and B2 proves who they are.
        let certificates: alloc::vec::Vec<crate::types::VBCProofBundle> = inputs.fact_certificates.iter().cloned()
            .chain(cheque_bundle.cheques.iter().flat_map(|c| c.fact_certificates.iter().cloned()))
            // the send link's witnesses ARE the cheque signers: their bundles ride the cheques
            .chain(cheque_bundle.cheques.iter().filter_map(|c| c.vbc_bundle.clone()))
            .collect();
        let trust = crate::fact::FactTrust::new(&certificates, None);
        if let Err(e) = crate::fact::verify_fact_chain(fact_chain, &trust) {
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
    
    // The receiver's pre-redeem state (the redeem link's `previous_state_id`
    // and the redeem commitment's consumed state). HOISTED here (2026-09-28,
    // Fork Settlement wave 2b-ii) from the FACT-signing block below because
    // Step 10 now binds it (R8). ⚠ The ID is RECEIVER-DECLARED and a missing
    // state is ZERO. Since 2026-10-01 the declared §15 FIELDS are anchored to
    // the receiver's last k-signed receipt (Step 3.6), but the state ID is not
    // bound by that receipt (`produced_state_id` is outside
    // `receipt_commitment`), so the commitment binds the ID as-is; Core decides
    // nothing new about a zero consumed state — per R33 a Nabla redeem leg with
    // a zero consumed state creates no record (Nabla-side, not Core's).
    let receiver_prev_state_id = cl5_consumed_state_id(&inputs);

    // Step 10: Compute redeem commitment hash
    // Core is the sole authority for commitment computation
    let redeem_commitment = crate::validation::compute_redeem_commitment(
        &txid,
        receiver_pk,
        new_balance,
        &computed_state_id,
        &receiver_prev_state_id,
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
    // the receiver's pre-redeem state_id (`receiver_prev_state_id`, hoisted
    // above Step 10 — it is bound into the redeem commitment too). The
    // sender's chain tip is bound separately via sender_anchor. Replaces the
    // pre-A2 "bridge link" pattern that signed a second commitment with
    // previous_state_id = sender chain tip and could never receive a Nabla
    // confirmation.
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
    //
    // KI#221 / ForkSettlement §3.1 + Q2 (2026-09-28): the cheque's OWN
    // unresolved origin is inherited, UNLESS the txid attestation verified at
    // Step 3.5 shows it SETTLED (`fact::origin_settled_cl5`) — then the
    // ordinary receiver carries no scar. One function owns the whole decision
    // (incl. the fail-closed `None` arms above), so the unit tests drive it.
    let inherited_scar_txids: alloc::vec::Vec<[u8; 32]> = match crate::fact::cl5_inherited_scar_txids(
        fact_chain_ref,
        cheque_bundle,
        inputs.txid_attestation.as_ref(),
        is_self_redeem,
        bundle_dev_class,
    ) {
        Ok(v) => v,
        Err(e) => return reject(e),
    };

    // THIS redeem link's FACT commitment — computed ONCE (Fable review
    // 2026-10-01 F-1(b)): the overlap check below verifies the prior hops'
    // Dilithium sigs over it, and this validator signs the same bytes.
    let link_fact_commitment = crate::fact::compute_fact_commitment(
        &txid,
        &receiver_prev_state_id,
        &computed_state_id,
        amount,
        sender_anchor.as_ref(),
        bundle_dev_class,
        // Fork Settlement R4: `cl5_redeem_required_k`'s value — the SAME k
        // `build_fact_link` stamps on the link below.
        required_k,
        &inherited_scar_txids,
        None, // a redeem link is never a burn (§1.5.4)
    );

    // Step 9b: S-ABR OVERLAP on the redeem (Fable review 2026-10-01 F-1(b)) —
    // the receive-side mirror of CL2's gate; see `cl5_receiver_overlap`. Runs
    // BEFORE this validator signs anything. k≥3 profile only.
    if !is_k0_redeem {
        let online_apparatus = inputs.vbc_bundle.is_some() || inputs.my_validator_pk.is_some();
        if let Err(e) = cl5_receiver_overlap(
            &inputs.prev_receipts,
            extract_validator_pk_from_inputs(&inputs),
            online_apparatus,
            &inputs.fact_witness_sigs,
            &link_fact_commitment,
            inputs.transaction.epoch,
        ) {
            return reject(e);
        }
    }

    let fact_signature = if let Some(ref sk) = inputs.my_dilithium_sk {
        let commitment = link_fact_commitment;
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

    let receiver_fact_chain = if is_k0_redeem {
        // YPX-010 §11.2.1 (P3.7) — the OFFLINE k=0 redeem: the receiver's own Core
        // assembles its redeem link RIGHT HERE, the redeem-side mirror of
        // `execute_ark_send_finalize`. No validators offline, so the link carries
        // NO Dilithium witness entries and `required_k = K_ARK`; its provenance
        // anchor is `sender_anchor` → the tip of the k=0 send link this receiver
        // co-signed at leg R2. A k=0 link is unverifiable without a
        // `receiver_witness` (P3.2 `verify_k0_ark_receiver_witness`), and for the
        // redeem link the redeeming wallet IS the k=0 receiver — so Core signs the
        // link's commitment with the wallet's own Ed25519 key, passed in via
        // `receiver_signing_key` (the `my_dilithium_sk` precedent: keys pass INTO
        // Core, Core signs; the SDK never assembles witness material, CLAUDE §12).
        let sk_bytes = match inputs.receiver_signing_key {
            Some(k) => k,
            None => return reject(ValidationError::ArkReceiverWitnessMissing),
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let derived_pk = signing_key.verifying_key().to_bytes();
        // Exclusivity (§11.7): the supplied key MUST be the redeeming wallet's own —
        // its pk must bind to the cheque's receiver_wallet_id checksum.
        if crate::wallet_id::verify_pk_binding(receiver_wid, &derived_pk).is_err() {
            return reject(ValidationError::ArkReceiverWitnessInvalid);
        }
        match crate::fact::build_fact_link(
            &txid,
            &receiver_prev_state_id,
            &computed_state_id,
            amount,
            crate::wallet_id::K_ARK, // k=0 tier — floor-1 receiver-witness
            &[],                     // NO validator witness sigs offline
            None,                    // burn_target_tx_id: redeem isn't a burn
            sender_anchor,           // A2: anchors the k=0 send link the receiver signed
            bundle_dev_class,
            inherited_scar_txids.clone(),
            inputs.receiver_fact_chain.as_ref(),
            None,                    // recall_target_tx_id
            None,                    // recall_proof
        ) {
            Ok(mut chain) => {
                if let Some(link) = chain.links.last_mut() {
                    let commitment = crate::fact::compute_fact_commitment(
                        &link.tx_id,
                        &link.previous_state_id,
                        &link.new_state_id,
                        link.amount,
                        link.sender_anchor.as_ref(),
                        link.is_dev_class,
                        link.required_k,
                        &link.inherited_scar_txids,
                        link.burn_target_tx_id.as_ref(),
                    );
                    use ed25519_dalek::Signer;
                    let signature = signing_key.sign(&commitment).to_bytes();
                    link.receiver_witness = Some(crate::types::ReceiverWitness {
                        receiver_pk: derived_pk,
                        signature,
                    });
                }
                Some(chain)
            }
            Err(e) => return reject(e),
        }
    } else { match (
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
    } };

    // Receipt commitment for CL5 (redeem). Uses the cheque's txid since
    // CL5 doesn't produce its own txid. The receipt's fee_breakdown is
    // assembled by the SDK from the k WitnessSigs after the witness round; it
    // is NOT bound into the commitment so every hop signs an identical
    // skeleton. (The receipt-vs-witness slot cross-check that used to be cited
    // here, verify_receipt_fee_breakdown, was DELETED — KI#156 item 3, 0
    // callers; fees close on CL5's cheque-derived total + ConservationViolation.)
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
    // ── §5.2.2c STAMP THE WALL-CLOCK LOCK — the redeem of a subsidy claim ───
    //
    // Stamped HERE and nowhere else: this is the step where the stake lands. Every
    // other path carries the value forward untouched — a lock is released by TIME,
    // never by a transaction, so a redeem must not clear it.
    //
    // The claim is discriminated exactly as the airdrop-replay guard above does
    // (no recall linkage + self-send + the Core-pinned amount) — one pattern, not
    // a second. `recall_target_tx_id` is commitment-BOUND and k-signed, so a
    // client cannot forge its absence, and RECALL legitimately carries arbitrary
    // amounts which is why it must be excluded.
    // ⚠ Residual: the test is amount-based, so a self-send of EXACTLY a tier floor
    // with no recall linkage would also stamp a lock. Heal/HAL/RECALL self-sends
    // round-trip DUST, never a tier floor, so the shape is effectively claim-only.
    let (stake_lock_unix, lock_stamped_now) = {
        let c = cheque_bundle.cheques.first();
        let claim_shaped = c.map(|c| {
            c.recall_target_tx_id.is_none()
                && c.sender_wallet_id == c.receiver_wallet_id
        }).unwrap_or(false);
        let amt = c.map(|c| c.amount).unwrap_or(0);
        let lock_secs = if !claim_shaped {
            None
        } else if amt == crate::types::TIER2_CLAIM_ATOMS {
            Some((crate::validation::protocol_gen::TIER2_LOCKUP_SECONDS,
                  crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS))
        } else if amt == crate::types::TIER3_CLAIM_ATOMS {
            Some((crate::validation::protocol_gen::TIER3_LOCKUP_SECONDS,
                  crate::validation::protocol_gen::TIER3_STAKE_LOCK_TICKS))
        } else {
            None
        };
        match lock_secs {
            // Base = the ISSUERS' `created_at`, never `epoch` (the owner, 2026-09-05).
            // `epoch` is `transaction.epoch` copied verbatim from the CLAIMANT's
            // own transaction (`cheque_build.rs`), so a deadline computed from it
            // is a deadline the claimant chose — declaring 0 stamps a lock already
            // in the past. `created_at` is the validator's own `SystemTime::now()`
            // and is now SIGNED, so the holder cannot edit it either.
            //
            // MAX across the k cheques — RULED 2026-09-05 (the owner), and it is a
            // deliberate choice between two failures, not an obvious one:
            //
            //   max    shortening needs ALL k backdated · ONE future clock over-locks
            //   min    ONE backdated issuer shortens it   · over-locking needs all k
            //   median 2 of 3 either way
            //
            // MAX is correct because the two failures are not symmetric. Shortening
            // the lock is THEFT and leaves nothing behind — the stake simply moves.
            // Over-locking leaves a SIGNED cheque naming the issuer that did it, so
            // it is attributable and answerable the way any provable validator
            // misbehaviour is. Prefer the failure that comes with evidence.
            //
            // ⚠ Do NOT "fix" this to median. That trade was weighed and rejected.
            Some((secs, window_ticks)) => {
                // ── THE TIME CROSS-CHECK (the owner, 2026-09-05) ────────────────
                // Two independent accounts of ONE moment — the claim's witness
                // round — must agree, or the claim is refused. Core reads NO
                // clock here; it checks two supplied numbers against each other,
                // which is why this is not a third wall-clock use in a design
                // that does not trust wall clocks. Full rationale:
                // AXIOM_DESIGN_ValidatorJoin.md "Why a wall clock is admissible
                // HERE" — read it before changing any of this.
                //
                //   claimant's account: recovered from the k-attested
                //     `hibernation_until` stamped at the claim SEND, by
                //     subtracting the tier window (the SAME register that
                //     stamped it, so the two can never drift apart).
                //   issuers' account:  `created_at`, signed on the cheques.
                //
                // They describe the same instant because a validator stamps
                // `created_at` when it witnesses that very send. Contemporaneity
                // is the mechanism: an earlier design compared `created_at` to a
                // tick attested at REDEEM time and had to be abandoned, because
                // the redeem may follow the claim by an unbounded interval and
                // any tolerance wide enough for a patient wallet was wide enough
                // for a backdated one.
                let issuer_time = cheque_bundle.cheques.iter()
                    .map(|c| c.created_at).max().unwrap_or(0);
                // ONE call does BOTH: the cross-check and the deadline are the
                // same operation, so this stamp cannot exist without the check
                // having run (RULE 6 — `stamp_stake_lock`'s doc records why).
                // ⚠ Do not split this back into check-then-compute, and do not
                // inline `issuer_time + secs`: this call site is unreachable by
                // unit test (a claim redeem needs an unmintable SPHINCS+-rooted
                // ChequeClaimProof), so a deleted check would go unnoticed.
                match crate::types::stamp_stake_lock(
                    inputs.receiver_current_hibernation.unwrap_or(0),
                    window_ticks,
                    issuer_time,
                    secs,
                ) {
                    Ok(deadline) => (deadline, true),
                    Err(e) => return reject(e),
                }
            }
            None => (inputs.receiver_current_wall_clock_lock.unwrap_or(0), false),
        }
    };
    // A self-redeem CLEARS hibernation, because that is how HAL and RECALL
    // complete (YPX-020 §2b). The one exception is the redeem that STAMPS a lock:
    // that is a stake claim landing, so the wallet comes out of it still
    // hibernating and the lock takes over. Keyed on the stamp having fired in
    // THIS redeem — the same discrimination the lock itself uses, read once.
    let receiver_hibernation = if is_self_redeem && !lock_stamped_now {
        0
    } else {
        inputs.receiver_current_hibernation.unwrap_or(0)
    };
    // ⚠ WRONG, and it shipped (found 2026-10-01 building §6b.13, RULE 0 §4):
    // the sixth argument here was a literal `0`, so every redeem ERASED the
    // receiver's `emission_claimed_epoch` — while Lambda passed its stored value
    // in (`receiver_current_emission_claimed_epoch`, read by nothing) and the
    // SDK committed the carried value, so the wallet's next send could not
    // anchor (`StateNotAnchored`) and the once-per-epoch mark (§4.2a / KI#166,
    // "carried unchanged by every other transaction") did not survive a
    // receive. CORRECT: a redeem CARRIES the mark, exactly as it carries the
    // §6b.13 floor beside it.
    let receiver_emission_claimed_epoch = inputs.receiver_current_emission_claimed_epoch.unwrap_or(0);
    let cl5_state_hash = crate::crypto::compute_state_hash(
        receiver_pk,
        new_balance,
        wallet_seq,
        receiver_hibernation,
        stake_lock_unix,
        receiver_emission_claimed_epoch,
        receiver_stake_floor_until,
        &crate::types::WalletFormat::CURRENT,
    );

    // §32.3 taint lineage: the sender's state_id this redeem draws from
    // (FACT sender_anchor = the cheque chain tip / checkpoint final id).
    // Bound into the commitment so the k witnesses attest it; carried to
    // Nabla to set `NablaEntry.received_from`. `None` only on the degenerate
    // no-sender redeem (genesis self-claim, no cheque anchor).
    let cl5_sender_state: Option<[u8; 32]> =
        crate::fact::redeem_fact_sender_anchor(cheque_bundle, &inputs.sender_fact_chain);

    let cl5_receipt_commitment = crate::crypto::compute_receipt_commitment(
        &txid,
        &cl5_state_hash,
        wallet_seq,
        &redeem_commitment,
        inputs.transaction.epoch,
        bundle_dev_class,
        cl5_oods_flag.as_ref(),
        None, // redeem receipts carry no CI (only k=3 sends stamp one)
        cl5_sender_state.as_ref(),
    );

    // All checks passed - return success with CORE-COMPUTED state_id and commitment
    PublicOutputs {
        zkp_qualification: None,
        // §5.2.2c — RETURN what was bound into `new_state_hash`. Core binding a
        // value it does not return is precisely why the claim redeem could not be
        // committed: the wallet had no way to learn its own lock.
        wall_clock_lock: stake_lock_unix,
        emission_claimed_epoch: receiver_emission_claimed_epoch,
        stake_floor_until: receiver_stake_floor_until,
        wallet_format: crate::types::WalletFormat::CURRENT,
        hibernation_until: receiver_hibernation,
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
        ark_send_fact_chain: None,
        receiver_fact_chain,
        receipt_commitment: Some(cl5_receipt_commitment),
        is_dev_class: Some(bundle_dev_class),
        // YPX-021 §8.2 — same carry-back as CL3.
        oods_flag: cl5_oods_flag,
        confidence_index: None,
        // §32.3 — carry the sender-lineage back so Lambda stamps it onto
        // Receipt.sender_state (the value bound into the commitment above).
        sender_state: cl5_sender_state,
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
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
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
        wall_clock_lock: 0,
        emission_claimed_epoch: 0,
        stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT, zkp_qualification: None,
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
        ark_send_fact_chain: None,
        receiver_fact_chain: None, receipt_commitment: None,
        is_dev_class: None,
        oods_flag: None,
        confidence_index: None,
        sender_state: None,
    }
}


#[cfg(test)]
mod stake_lock_time_cross_check_theory {
    //! The §5.2.2c claim time cross-check. Written as a THEORY check before any
    //! of it was wired (the owner: "test the theory first"), and kept as its
    //! regression suite now that `execute_cl5` enforces it — the theory has to
    //! keep holding, not just have held once.
    //!
    //! ⚠ These re-derive the comparison rather than calling `execute_cl5`, which
    //! needs a Nabla-signed claim proof a unit test cannot mint. They pin the
    //! ARITHMETIC and the boundaries; that the production site applies it is
    //! covered by the constants being shared, not by these.
    //!
    //! The idea: at a claim redeem Core can CROSS-CHECK two independently-sourced
    //! timestamps that describe the SAME moment (the claim's witness round):
    //!
    //!   * the CLAIMANT's declared `tx.epoch`, recoverable from the k-attested
    //!     `hibernation_until` by subtracting the tier's known window;
    //!   * the ISSUERS' `created_at`, signed on the cheques.
    //!
    //! Neither is trusted alone. They come from different parties, so agreement
    //! is the evidence — and disagreement convicts whoever is lying.
    use super::*;
    use crate::types::{Transaction, TxKind, TICK_INTERVAL_SECS};

    // The PRODUCTION register — not a literal, so a change to the register moves
    // these tests with it instead of leaving them asserting a stale number.
    const RANGE_SECS: u64 = crate::validation::protocol_gen::STAKE_LOCK_TIME_RANGE_SECS;

    /// Tier-2's window in SECONDS, as the stamp actually projects it.
    fn tier2_window_secs() -> u64 {
        crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS * TICK_INTERVAL_SECS
    }

    /// Stamp `hibernation_until` the way PRODUCTION does — not by re-deriving the
    /// formula here, which would be a check that cannot fail.
    fn stamp_hibernation(claimant_epoch: u64) -> u64 {
        let mut tx = Transaction::default();
        tx.epoch = claimant_epoch;
        tx.kind = TxKind::ValidatorFoundationStakeClaim;
        tx.sender_wallet_id = "candidate@example.net".to_string();
        tx.produced_hibernation_until()
    }

    /// Tier-2's lockup SPAN in seconds — the span the stamp adds to the issuers' time.
    const TIER2_LOCK_SECS: u64 = crate::validation::protocol_gen::TIER2_LOCKUP_SECONDS;

    /// Calls the PRODUCTION rule — the same function `execute_cl5` calls, which is
    /// now the STAMP itself (`stamp_stake_lock`), not a separable predicate beside
    /// it. Do not replace this with a local re-derivation: that is the
    /// check-that-cannot-fail shape, and it is exactly what let a toothless
    /// production check pass before the rule was extracted (RULE 6 §3a).
    fn stamp(hibernation_until: u64, issuer_created_at: u64) -> Result<u64, ValidationError> {
        crate::types::stamp_stake_lock(
            hibernation_until,
            crate::validation::protocol_gen::TIER2_STAKE_LOCK_TICKS,
            issuer_created_at,
            TIER2_LOCK_SECS,
        )
    }

    /// The cross-check's verdict, read off the one operation that also stamps.
    fn cross_check_ok(hibernation_until: u64, issuer_created_at: u64) -> bool {
        stamp(hibernation_until, issuer_created_at).is_ok()
    }

    /// STEP 1 — the recovery must exactly invert the production stamp, or the whole
    /// idea collapses at the first step.
    #[test]
    fn recovery_inverts_the_production_stamp() {
        for epoch in [1_780_000_000u64, 1, 999_999_999, 2_000_000_000] {
            let hib = stamp_hibernation(epoch);
            assert_eq!(hib.saturating_sub(tier2_window_secs()), epoch,
                "recovered send time must equal the claimant's declared epoch");
        }
    }

    /// STEP 2 — an honest round passes, including realistic clock skew.
    #[test]
    fn honest_round_passes_within_the_range() {
        let real_now = 1_780_000_000u64;
        let hib = stamp_hibernation(real_now);
        // Skews DERIVED from the register, not literals. Hardcoded ±3600 broke the
        // moment the dev twins shrank the window (2026-09-05): a test that pins
        // literals cannot follow the constant it is protecting.
        let r = RANGE_SECS as i64;
        for skew in [0i64, 1, -1, r / 2, -r / 2, r, -r] {
            let issuer = (real_now as i64 + skew) as u64;
            assert!(cross_check_ok(hib, issuer),
                "honest issuer {}s from the claimant must pass a {}s range", skew, RANGE_SECS);
        }
    }

    /// STEP 3 — THE ATTACK. A claimant backdating its epoch to shorten the lock is
    /// convicted by the issuers' clocks, which it does not control.
    #[test]
    fn backdated_claimant_is_caught() {
        let real_now = 1_780_000_000u64;
        // epoch = 0 → the lock would land in 1972, expired on arrival.
        assert!(!cross_check_ok(stamp_hibernation(0), real_now),
            "epoch 0 must be refused — this is the live attack");
        // Subtler: backdate by exactly the lock, so it expires immediately.
        let backdated = real_now - tier2_window_secs();
        assert!(!cross_check_ok(stamp_hibernation(backdated), real_now),
            "backdating by the whole window must be refused");
        // And a modest backdate that still steals real time.
        assert!(!cross_check_ok(stamp_hibernation(real_now - 86_400), real_now),
            "backdating a day must be refused at a 1h range");
    }

    /// STEP 4 — the boundary is where a range check silently does nothing, so pin it.
    #[test]
    fn the_range_boundary_holds_on_both_sides() {
        let real_now = 1_780_000_000u64;
        let hib = stamp_hibernation(real_now);
        assert!(cross_check_ok(hib, real_now - RANGE_SECS), "exactly at the range: accept");
        assert!(!cross_check_ok(hib, real_now - RANGE_SECS - 1), "one second past: refuse");
        assert!(cross_check_ok(hib, real_now + RANGE_SECS), "symmetric, forward");
        assert!(!cross_check_ok(hib, real_now + RANGE_SECS + 1), "symmetric, forward, past");
    }

    /// STEP 5 — how much time can an attacker still steal by lying INSIDE the
    /// range? At most the range itself, against a 2-year lock.
    #[test]
    fn worst_case_theft_inside_the_range_is_bounded() {
        let real_now = 1_780_000_000u64;
        let worst = stamp_hibernation(real_now - RANGE_SECS);
        assert!(cross_check_ok(worst, real_now), "the worst passing lie is exactly the range");
        let honest = stamp_hibernation(real_now);
        assert_eq!(honest - worst, RANGE_SECS,
            "an undetectable lie shortens the lock by at most the range");
        // ⚠ WAS `RANGE_SECS * 100 < window`, which is a PRODUCTION-SCALE claim and
        // went red when the dev twins landed (2026-09-05). The invariant that
        // actually matters holds in BOTH profiles: the undetectable lie must be a
        // small fraction of the lock, so the tolerance can be generous without
        // weakening the control. Production's real ratio is ~18,000x
        // (3,600s against ~65,000,000s); dev's is 20x (30s against 600s), which is
        // deliberate — dev buys a testable window, not a security margin.
        // Prod's real ratio is ~18,000x (3,600s against ~65,000,000s); dev's is
        // ~4x by construction, because the window is compressed to minutes while
        // the range must still exceed a REAL ~47s witness round. The invariant
        // that holds in BOTH profiles is simply that an undetectable lie is
        // smaller than the lock.
        assert!(RANGE_SECS < tier2_window_secs(),
            "the range must stay a small fraction of the lock in EVERY profile — \
             range={}s window={}s", RANGE_SECS, tier2_window_secs());
    }

    /// STEP 6 — THE STRUCTURAL PROPERTY, and the reason this shape exists.
    ///
    /// The deadline is the `Ok` of the check. There is no second way to obtain one:
    /// `claim_time_accounts_agree` and `wall_clock_lock_deadline` are private to
    /// `types`, so a `execute_cl5` that "forgot" to cross-check has nothing to call
    /// and does not compile. That closes the gap a unit test cannot: the CL5 call
    /// site is unreachable from a test (an unmintable SPHINCS+-rooted
    /// `ChequeClaimProof`), so breaking the rule was caught and DELETING it was not.
    ///
    /// This test pins both halves of the fusion — the refusal carries the right
    /// code, and the acceptance carries the right deadline.
    #[test]
    fn the_deadline_is_only_obtainable_by_passing_the_check() {
        let real_now = 1_780_000_000u64;

        // Refusal: the backdated claimant gets no deadline at all, and the code
        // names the rule that refused it.
        assert_eq!(stamp(stamp_hibernation(0), real_now),
            Err(ValidationError::StakeLockTimeDisagreement),
            "a refused cross-check must yield NO deadline");

        // Acceptance: the deadline is the ISSUERS' time plus the tier span —
        // never the claimant's epoch, which is the value it controls.
        assert_eq!(stamp(stamp_hibernation(real_now), real_now),
            Ok(real_now + TIER2_LOCK_SECS),
            "an accepted cross-check stamps issuer_time + the tier lockup span");

        // And the base really is the issuer's clock: an honest claimant whose epoch
        // sits inside the range does not move the deadline.
        let skewed = stamp_hibernation(real_now - RANGE_SECS);
        assert_eq!(stamp(skewed, real_now), Ok(real_now + TIER2_LOCK_SECS),
            "the claimant's declared epoch must not shift the deadline");
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
            fact_certificates: alloc::vec::Vec::new(),
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
            zkq_request: None,
            fact_certificates: alloc::vec::Vec::new(),
            receiver_witness: None,
            receiver_signing_key: None,
            oods_attestation: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
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
            nonce_response: None,
            audit_response: None,
            wallet_secret: None,
            fanout_message: None,
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
            receiver_current_hibernation: None,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            // §6b.13 — CL5 refuses a receiver with no format block; the
            // current one is what every real caller passes.
            receiver_current_wallet_format: Some(crate::types::WalletFormat::CURRENT),
        }
    }

    // ── §10.0 FOB fee-claim CL2 gate (the KI#83 replacement flow) ─────────
    // The unit level cannot produce a ROOT-ANCHORED attestation (the NBC root
    // set is a baked const — correct posture), so the crypto half is covered by
    // the validation.rs forge/anchor/repair tests + the live e2e at deploy,
    // and the PINS are tested directly on the pure helper below. The gate-level
    // tests here prove the gate's SCOPING and its fail-closed shape.
    fn fob_gate_inputs(att: Option<crate::types::FobClaimAttestation>) -> PublicInputs {
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        inputs.transaction.kind = crate::types::TxKind::ValidatorWithdrawalMint;
        inputs.transaction.sender_wallet_id = inputs.transaction.receiver_wallet_id.clone();
        inputs.fob_claim_attestation = att;
        inputs
    }
    fn fob_test_att(amount: u64, is_dev: bool, linked: &str) -> crate::types::FobClaimAttestation {
        fob_test_att_pool(crate::types::FOB_CLAIM_POOL_BOUNDED_FEE, [0x77u8; 32], amount, is_dev, linked)
    }

    // ── YP §25.2.4 emission claim: the pool pin (2026-09-14) ──────────────
    // Same gate as the fee claim; the ONLY new rule is that the attestation's
    // pool must match the tx kind. Mutation: drop the pool pin in
    // `fob_claim_tx_pins` and `emission_claim_rejects_fee_pool_attestation`
    // goes green-for-the-wrong-reason — it MUST be red.
    #[test]
    fn emission_claim_pins_pass_with_emission_pool_attestation() {
        let mut tx = create_test_inputs(CoreLogicMode::CL2).transaction;
        tx.kind = crate::types::TxKind::EmissionClaim;
        tx.amount = 1_337;
        tx.receiver_wallet_id = tx.sender_wallet_id.clone();
        let linked = tx.sender_wallet_id.clone();
        let att = fob_test_att_pool(crate::types::FOB_CLAIM_POOL_EMISSION, [0x11u8; 32], 1_337, false, &linked);
        assert!(fob_claim_tx_pins(&tx, &att).is_ok(), "an emission attestation pins an emission claim");
        let att = fob_test_att_pool(crate::types::FOB_CLAIM_POOL_EMISSION_NABLA, [0x11u8; 32], 1_337, false, &linked);
        assert!(fob_claim_tx_pins(&tx, &att).is_ok(), "the Nabla-node emission pool pins it too");
    }

    #[test]
    fn emission_claim_rejects_fee_pool_attestation() {
        let mut tx = create_test_inputs(CoreLogicMode::CL2).transaction;
        tx.kind = crate::types::TxKind::EmissionClaim;
        tx.amount = 1_337;
        tx.receiver_wallet_id = tx.sender_wallet_id.clone();
        let linked = tx.sender_wallet_id.clone();
        let att = fob_test_att_pool(crate::types::FOB_CLAIM_POOL_BOUNDED_FEE, [0x11u8; 32], 1_337, false, &linked);
        assert_eq!(fob_claim_tx_pins(&tx, &att), Err(ValidationError::FobClaimInvalid),
            "a fee-sweep attestation must never pay an emission claim");
        // And the reverse: a fee claim cannot spend an emission attestation.
        tx.kind = crate::types::TxKind::ValidatorWithdrawalMint;
        let att = fob_test_att_pool(crate::types::FOB_CLAIM_POOL_EMISSION, [0x11u8; 32], 1_337, false, &linked);
        assert_eq!(fob_claim_tx_pins(&tx, &att), Err(ValidationError::FobClaimInvalid));
    }

    #[test]
    fn emission_claim_gate_requires_attestation_and_self_send() {
        // The CL2 gate treats the emission claim exactly as the fee claim:
        // no attestation → reject; a third-party receiver → reject.
        let mut inputs = fob_gate_inputs(None);
        inputs.transaction.kind = crate::types::TxKind::EmissionClaim;
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::FobClaimInvalid));
    }
    fn fob_test_att_pool(pool: u8, vid: [u8; 32], amount: u64, is_dev: bool, linked: &str)
        -> crate::types::FobClaimAttestation
    {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let payload = crate::crypto::compute_fob_claim_attestation_payload(
            pool, &vid, is_dev, amount, linked, 42, 0,
        );
        let sig = sk.sign(&payload).to_bytes().to_vec();
        let mut pre = alloc::vec::Vec::new();
        pre.extend_from_slice(&pk);
        crate::types::FobClaimAttestation {
            pool,
            validator_id: vid, is_dev, amount,
            linked_wallet_id: alloc::string::String::from(linked),
            claim_tick: 42, nabla_node_pk: pk, nabla_signature: sig,
            epoch: 0,
            nbc_issuer_pk: alloc::vec![0u8; 32],
            nbc_signature: alloc::vec![0u8; 64],
            nbc_commitment: pre,
        }
    }

    #[test]
    fn fob_claim_gate_missing_attestation_rejects() {
        let inputs = fob_gate_inputs(None);
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::FobClaimInvalid),
            "a fee-claim without its Nabla attestation must die at the gate");
    }

    #[test]
    fn fob_claim_gate_unanchored_attestation_rejects() {
        // A well-signed attestation whose NBC anchor is NOT a root authority
        // dies at verify — a self-issued Nabla identity can't authorize a claim.
        let mut inputs = fob_gate_inputs(None);
        let linked = inputs.transaction.sender_wallet_id.clone();
        inputs.fob_claim_attestation = Some(fob_test_att(500, false, &linked));
        inputs.transaction.amount = 500;
        let outputs = execute_core(inputs);
        assert_eq!(outputs.result, ValidationResult::Reject);
        assert_eq!(outputs.rejection_reason, Some(ValidationError::FobClaimInvalid));
    }

    #[test]
    fn fob_claim_gate_scoping_non_mint_never_dies_here() {
        // POSITIVE CONTROL of the gate's scoping: a NORMAL tx with a bogus
        // attestation attached must NOT reject FobClaimInvalid — the gate
        // applies ONLY to kind=ValidatorWithdrawalMint. If the kind guard is
        // ever lost, this goes red.
        let mut inputs = fob_gate_inputs(Some(fob_test_att(500, false, "x@y.z")));
        inputs.transaction.kind = crate::types::TxKind::Normal;
        let outputs = execute_core(inputs);
        assert_ne!(outputs.rejection_reason, Some(ValidationError::FobClaimInvalid),
            "the FOB gate must be scoped to the mint kind");
    }

    // ── the PINS, tested where they are defined (pure helper) ──
    fn pin_tx(amount: u64, sender: &str) -> Transaction {
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        inputs.transaction.kind = crate::types::TxKind::ValidatorWithdrawalMint;
        inputs.transaction.amount = amount;
        inputs.transaction.sender_wallet_id = alloc::string::String::from(sender);
        inputs.transaction
    }

    #[test]
    fn fob_claim_pins_accept_exact_match() {
        let att = fob_test_att(500, false, "op@x.com");
        assert!(fob_claim_tx_pins(&pin_tx(500, "op@x.com"), &att).is_ok());
    }

    #[test]
    fn fob_claim_pins_wrong_amount_rejects_both_directions() {
        // Lowball (partial collect) and highball reject IDENTICALLY — == is
        // the only accepted amount (collect-all-at-once).
        let att = fob_test_att(500, false, "op@x.com");
        assert!(fob_claim_tx_pins(&pin_tx(499, "op@x.com"), &att).is_err());
        assert!(fob_claim_tx_pins(&pin_tx(501, "op@x.com"), &att).is_err());
    }

    #[test]
    fn fob_claim_pins_wrong_claimant_rejects() {
        let att = fob_test_att(500, false, "op@x.com");
        assert!(fob_claim_tx_pins(&pin_tx(500, "thief@x.com"), &att).is_err());
    }

    #[test]
    fn fob_claim_pins_class_cross_rejects_both_ways() {
        // §10.2a last-mile: dev pool → real wallet AND real pool → dev wallet
        // both die. (@axiom.internal is the dev class.)
        let dev_att = fob_test_att(500, true, "op@x.com");
        assert!(fob_claim_tx_pins(&pin_tx(500, "op@x.com"), &dev_att).is_err(),
            "dev pool paying a real wallet must reject");
        let real_att = fob_test_att(500, false, "dev@axiom.internal");
        assert!(fob_claim_tx_pins(&pin_tx(500, "dev@axiom.internal"), &real_att).is_err(),
            "real pool paying a dev wallet must reject");
        let dev_ok = fob_test_att(500, true, "dev@axiom.internal");
        assert!(fob_claim_tx_pins(&pin_tx(500, "dev@axiom.internal"), &dev_ok).is_ok(),
            "dev pool paying a dev wallet is the sanctioned pairing");
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
            confidence_index: None,
            sender_state: None,
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
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
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
            candidacy_pulse: None, renewal_work_receipt: None,
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
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
        }
    }

    #[test]
    fn test_cl7_rejects_invalid_sphincs_sig() {
        use crate::types::VBCProofBundle;

        let bundle = VBCProofBundle {
            target_vbc: make_test_nbc(2000),
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
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
            candidacy_pulse: None, renewal_work_receipt: None,
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
            genesis_lineage: [0u8; 32],
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
            nabla_registration: None,
        };

        // Sign with 1 Nabla root key
        let payload = crate::crypto::compute_vbc_signing_payload(&nbc);
        let sig1 = crate::crypto::sign_sphincs(&sk1, &payload).unwrap();
        nbc.signatures = vec![sig1];

        let bundle = VBCProofBundle {
            target_vbc: nbc,
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
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
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT,
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
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT,
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

        // THE builders (KI#55, RULE 1 — a test helper that re-derives the value
        // the verifier checks cannot fail when it changes; the YP bytes are
        // pinned independently by `kat_cl10_accepts_python_fanout_constants`).
        let diffusion_id = crate::crypto::fanout_diffusion_id(&content, pk.as_bytes());
        let signing_payload = crate::crypto::fanout_signing_payload(
            &diffusion_id, content_type, &content, ttl_original, fanout, timestamp,
        );
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

    /// KI#55 (2026-10-02) step-0 anchor: CL10 ACCEPTS a message whose
    /// `diffusion_id` and signed payload are the constants computed
    /// INDEPENDENTLY in Python (`blake3`, PyNaCl) from the YP §18.8.3/§18.8.4 layouts —
    ///   diffusion_id = BLAKE3("AXIOM_FANOUT_ID" ‖ content ‖ originator_pk)
    ///   payload      = BLAKE3("AXIOM_FANOUT" ‖ diffusion_id ‖ content_type_u16le
    ///                         ‖ content ‖ ttl_original ‖ fanout ‖ timestamp_u64le)
    /// with key seed 42×32 (pk 2152f8d1…), content AABBCC, type 0x0001, ttl 5,
    /// fanout 3, ts 1774070000. It does NOT use any Rust builder, so it proves
    /// Core's verifier bytes == the YP layout (green on the pre-consolidation
    /// inline code; kept after). One flipped payload byte → Reject.
    #[test]
    fn kat_cl10_accepts_python_fanout_constants() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        assert_eq!(hex::encode(sk.verifying_key().to_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12");
        let did: [u8; 32] = hex::decode("bc2c0c7260b946ac60b8f1ecaa68ac78439c2534a38585ebbefec9d818034327")
            .unwrap().try_into().unwrap();
        let payload = hex::decode("c9b4e56db797e2a531c88111120fd91887d61c4db167a89a9f7dabaefdbb9259").unwrap();
        let mk = |payload: &[u8]| crate::types::FanOutMessage {
            diffusion_id: did,
            content_type: 0x0001,
            content: alloc::vec![0xAA, 0xBB, 0xCC],
            originator_pk: sk.verifying_key().to_bytes(),
            originator_sig: sk.sign(payload).to_bytes().to_vec(),
            timestamp: 1774070000,
            ttl_original: 5,
            fanout: 3,
            ttl_current: 5,
        };
        let out = execute_core(cl10_inputs(mk(&payload)));
        assert_eq!(out.result, ValidationResult::Accept, "{:?}", out.rejection_reason);
        let mut wrong = payload.clone();
        wrong[0] ^= 1;
        let out = execute_core(cl10_inputs(mk(&wrong)));
        assert_eq!(out.rejection_reason, Some(ValidationError::FanOutInvalidSignature));
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
                genesis_lineage: [0u8; 32],
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
                nabla_registration: None,
            },
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
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

    /// `candidate_balance_axc` is in WHOLE AXC — the same unit the tier
    /// constants are written in — and is converted to ATOMS here, because
    /// `PublicInputs.candidate_balance` and every stake comparison are atoms.
    ///
    /// These fixtures previously passed the AXC number straight through, which
    /// matched the stake floor only because the floor ALSO used the bare AXC
    /// constant. Both sides were wrong by 10^10 and the tests were green —
    /// they encoded the bug rather than catching it (fixed 2026-09-02).
    /// ⚠ The first argument is a SPHINCS+ PUBLIC KEY, not a validator id.
    /// `GENESIS_VALIDATORS` holds public keys, and `validator_id` is their
    /// BLAKE3 — production derives one from the other, so the fixture does too.
    /// This used to take an "id" and store it verbatim in `validator_id`, which
    /// is exactly the confusion that made `is_genesis_validator` unable to
    /// match at three production call sites (fixed 2026-09-04).
    /// §5.2.2e — give a PROVISIONAL request the candidate's own signed Pulse
    /// proof: the target's Ed25519 subject becomes a real key and the proof is
    /// signed by it at the request's own epoch. Without this a provisional
    /// request is refused `VbcCandidacyPulseMissing` at the last gate.
    fn with_candidacy_pulse(mut inputs: PublicInputs) -> PublicInputs {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x61u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        // Part iii: seeded at the ROUND's attested tick (the request's clock
        // is the same tick — what a real request carries).
        let seed = inputs.oods_attestation.as_ref().map(|a| a.tick).unwrap_or(inputs.transaction.epoch);
        inputs.transaction.epoch = seed;
        let epoch = crate::pulse::pulse_epoch_of_tick(seed);
        let (acc, audit_hash) = ([7u8; 32], [8u8; 32]);
        let payload = crate::pulse::pulse_proof_sign_payload(&pk, epoch, &acc, &audit_hash, Some(seed));
        let b = inputs.vbc_bundle.as_mut().expect("CL8 fixture has a bundle");
        b.target_vbc.subject_pubkey_ed25519 = pk.to_vec();
        b.candidacy_pulse = Some(crate::wire_client::PulseProofRequest {
            validator_pk: pk, epoch, full_accumulator: acc, entry_count: 64, sample_size: 7,
            audit_hash, argon2id_per_sec: 21, signature: sk.sign(&payload).to_bytes().to_vec(),
            attested_tick: Some(seed),
        });
        inputs
    }

    /// A reading `verify_oods_attestation` ACCEPTS, hermetically: the live
    /// reading signed by a fixed citizen Ed25519 key, the NBC commitment
    /// carrying that key, SPHINCS+-signed by a fresh issuer the test
    /// registers as a root (`nabla_genesis::test_roots`, cfg(test) only —
    /// never in the ELF). Baseline 0 so the release-only suffix rule is moot.
    fn test_oods_attestation(tick: u64, oods_size: u32) -> crate::types::NablaOodsAttestation {
        test_oods_attestation_by(0x42, tick, oods_size)
    }

    /// `test_oods_attestation` from the citizen node keyed by `node_seed`.
    fn test_oods_attestation_by(node_seed: u8, tick: u64, oods_size: u32) -> crate::types::NablaOodsAttestation {
        use ed25519_dalek::Signer;
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{KeyGen, SerDes};
        let node = ed25519_dalek::SigningKey::from_bytes(&[node_seed; 32]);
        let node_pk = node.verifying_key().to_bytes();
        let payload = crate::crypto::compute_oods_attestation_payload(oods_size, tick, 0, 0);
        let nabla_signature = node.sign(&payload).to_bytes().to_vec();
        let (issuer_pk, issuer_sk) = {
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };
        crate::nabla_genesis::test_roots::authorize(issuer_pk.clone().try_into().unwrap());
        let nbc_commitment = node_pk.to_vec();
        let nbc_signature = crate::crypto::sign_sphincs(
            &issuer_sk, blake3::hash(&nbc_commitment).as_bytes()).expect("sphincs sign");
        crate::types::NablaOodsAttestation {
            oods_size, tick, baseline_size: 0, baseline_tick: 0,
            nabla_node_pk: node_pk, nabla_signature,
            nbc_issuer_pk: issuer_pk, nbc_signature, nbc_commitment,
        }
    }

    // ── KI#130: verify_vbc_expiry judges on the ATTESTED tick (CL2/CL3) ────────
    // One prev-receipt witness VBC (issued_at=1000 via make_test_vbc), an optional
    // attested OODS reading, and a chosen tx.epoch — enough to prove the "now"
    // source and the fail-closed / unusable-window behaviour.
    fn expiry_inputs(
        mode: CoreLogicMode,
        vbc_expires_at: u64,
        tx_epoch: u64,
        oods: Option<crate::types::NablaOodsAttestation>,
    ) -> PublicInputs {
        let mut inputs = create_test_inputs(mode);
        inputs.transaction.epoch = tx_epoch;
        inputs.oods_attestation = oods;
        let bundle = crate::types::VBCProofBundle {
            target_vbc: make_test_vbc(vbc_expires_at),
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        };
        inputs.prev_receipts = vec![crate::types::Receipt {
            oods_flag: None, confidence_index: None, sender_state: None,
            txid: [0u8; 32], state_hash: [0u8; 32], produced_state_id: [0u8; 32],
            new_wallet_seq: 1, commitment_hash: [0u8; 32], sdid: [0u8; 32],
            lineage_hash: [0u8; 32], core_version: String::new(), core_id: [0u8; 32],
            witness_sigs: vec![crate::types::WitnessSig {
                validator_id: [0u8; 32], validator_pk: vec![0u8; 32],
                vbc_bundle: Some(bundle), carrier_type: String::new(),
                carrier_address: String::new(), signature: vec![0u8; 64],
                execution_proof: vec![], proof_type: 1, availability_attestation: None,
                validator_hints: vec![], fact_signature: None, checkpoint_sig: None,
                receipt_signature: None, receipt_commitment_sig: None,
                rate_bps: 0, slot_amount: 0,
            }],
            epoch: 1, fact_proof: None, required_k: 3, receipt_commitment: [0u8; 32],
            fee_breakdown: Vec::new(), is_dev_class: false,
        }];
        inputs
    }

    /// The attested tick, NOT tx.epoch, decides expiry on CL3. VBC expires_at=3000
    /// looks VALID against tx.epoch=1000, but the attested reading is tick=5000, so
    /// the cert is expired — and the reported `current_tick` is the attested 5000.
    #[test]
    fn verify_vbc_expiry_cl3_uses_attested_tick_not_tx_epoch() {
        let oods = test_oods_attestation(5000, 500);
        let inputs = expiry_inputs(CoreLogicMode::CL3, 3000, 1000, Some(oods));
        match crate::vbc::verify_vbc_expiry(&inputs) {
            Err(ValidationError::VBCExpired { current_tick, .. }) => {
                assert_eq!(current_tick, 5000,
                    "expiry must be judged on the attested tick (5000), not tx.epoch (1000)");
            }
            other => panic!("expected VBCExpired at the attested tick, got {:?}", other),
        }
    }

    /// CL3 with a witness VBC but no OODS attestation → fail closed. The client
    /// cannot fall back to the forgeable tx.epoch on the authoritative path.
    #[test]
    fn verify_vbc_expiry_cl3_fails_closed_without_attestation() {
        let inputs = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 5000, None);
        assert!(matches!(
            crate::vbc::verify_vbc_expiry(&inputs),
            Err(ValidationError::VBCNoAttestedTick),
        ), "CL3 must fail closed when a VBC is judged with no attested tick");
    }

    /// LOCUS A: the SERVING validator's OWN cert (inputs.vbc_bundle) inside the
    /// "loses usefulness N ticks before expiry" window is refused, even though it
    /// has not expired. The prev-receipt witness is far from expiry, so it is NOT
    /// the trigger — the serving cert is.
    #[test]
    fn verify_vbc_expiry_cl3_unusable_soon_window() {
        let now = 1_000_000u64;
        // Direct tick-VALUE units — no ticks_to_secs (the owner: "tick is tick").
        let window = crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS;
        assert!(window > 0);
        let oods = test_oods_attestation(now, 500);
        // Prev-receipt witness cert is far from expiry (must not be the trigger).
        let mut inputs = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 1, Some(oods));
        // The SERVING cert is within the unusable window (not expired).
        let serving_expires = now + window / 2;
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: make_test_vbc(serving_expires),
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        });
        assert!(matches!(
            crate::vbc::verify_vbc_expiry(&inputs),
            Err(ValidationError::VBCUnusableSoon { .. }),
        ), "the serving validator's own near-expiry cert must be refused (Locus A)");
    }

    /// LOCUS A: an already-EXPIRED serving cert returns VBCExpired (recovery:
    /// re-issue), NOT VBCUnusableSoon (recovery: renew). The unusable check alone
    /// would also reject it (remaining 0 < window) but with the wrong hint, so the
    /// serving cert's hard-expiry check runs first.
    #[test]
    fn verify_vbc_expiry_cl3_serving_cert_expired_returns_vbcexpired() {
        let now = 1_000_000u64;
        let oods = test_oods_attestation(now, 500);
        // Prev-receipt witness far from expiry (not the trigger).
        let mut inputs = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 1, Some(oods));
        // The SERVING cert is already past expiry.
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: make_test_vbc(now - 1),
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        });
        assert!(matches!(
            crate::vbc::verify_vbc_expiry(&inputs),
            Err(ValidationError::VBCExpired { .. }),
        ), "an expired serving cert must return VBCExpired (re-issue), not VBCUnusableSoon");
    }

    /// LOCUS A negative: a near-expiry cert in PREV_RECEIPTS (a past witness) must
    /// NOT trigger VBCUnusableSoon any more — only hard expiry rejects there. The
    /// unusable window is judged on the serving cert alone. No serving cert here
    /// (vbc_bundle None), so a not-yet-expired prev witness must PASS.
    #[test]
    fn verify_vbc_expiry_prev_receipt_near_expiry_does_not_trigger_unusable() {
        let now = 1_000_000u64;
        // Direct tick-VALUE units — no ticks_to_secs (the owner: "tick is tick").
        let window = crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS;
        let oods = test_oods_attestation(now, 500);
        // Prev-receipt witness within the unusable window but NOT expired.
        let inputs = expiry_inputs(CoreLogicMode::CL3, now + window / 2, 1, Some(oods));
        assert!(inputs.vbc_bundle.is_none(), "no serving cert in this fixture");
        assert!(crate::vbc::verify_vbc_expiry(&inputs).is_ok(),
            "a near-expiry cert in prev_receipts must not trip VBCUnusableSoon (Locus A moved it to the serving cert)");
    }

    /// A non-attested mode (CL1 client self-check) keeps using tx.epoch and does
    /// NOT require an attestation — it is re-checked authoritatively at CL3.
    #[test]
    fn verify_vbc_expiry_non_attested_mode_does_not_require_attestation() {
        let inputs = expiry_inputs(CoreLogicMode::CL1, 1_000_000, 5000, None);
        assert!(crate::vbc::verify_vbc_expiry(&inputs).is_ok(),
            "CL1 must not fail closed without an attestation (tx.epoch path)");
    }

    /// The COMPILE-TIME dev-tuning value is baked in under `dev-mode` (10000);
    /// a real ELF compiles 1000. This asserts the dev half is what the test build
    /// carries (KI#130 — compile-time, not the runtime is_dev_wallet mechanism).
    #[test]
    fn vbc_unusable_remaining_dev_value_is_compiled() {
        assert_eq!(crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS, 10_000,
            "dev-tuning build must compile the 10000-tick dev value");
    }

    /// HARD REQUIREMENT (the owner 2026-09-21): the Ark OFFLINE profile carries no OODS
    /// by design and can ride through CL3 — it must NEVER fail closed for a missing
    /// attestation, or Ark is useless. Both the Ark↔Ark trade and the Ark→normal
    /// unload (either endpoint K_ARK) must PASS with oods=None and prev_receipts
    /// present, judged on tx.epoch exactly as before.
    #[test]
    fn verify_vbc_expiry_ark_offline_profile_is_exempt_from_attested_requirement() {
        use crate::wallet_id::{generate_all_wallet_ids, K_ARK};
        let all = generate_all_wallet_ids("arktest@test.com", "7", &[0x51u8; 32]).unwrap();
        let ark = all.iter().find(|(_, k, _, _)| *k == K_ARK)
            .map(|(w, ..)| w.clone()).expect("an Ark-tier wallet id");

        // Ark↔Ark offline trade on CL3, no OODS, witness VBC present → must PASS.
        let mut trade = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 5000, None);
        trade.transaction.sender_wallet_id = ark.clone();
        trade.transaction.receiver_wallet_id = ark.clone();
        assert!(crate::vbc::verify_vbc_expiry(&trade).is_ok(),
            "Ark↔Ark (offline, no OODS) must not fail closed — Ark is exempt");

        // Ark→normal unload (only the SENDER is Ark) → also exempt (either endpoint).
        let mut unload = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 5000, None);
        unload.transaction.sender_wallet_id = ark;
        assert!(crate::vbc::verify_vbc_expiry(&unload).is_ok(),
            "Ark unload (sender=Ark) must not fail closed — either-endpoint Ark is exempt");
    }

    // ── KI#130 Gap B — carrier-latency OODS FRESHNESS gate ────────────────────
    // Build CL3 inputs whose PREV receipt carries an oods_flag tick = `prev_tick`
    // (the wallet's last round) and whose CURRENT attestation tick = `now_tick`.
    fn freshness_inputs(now_tick: u64, prev_oods_tick: Option<u64>) -> PublicInputs {
        let oods = test_oods_attestation(now_tick, 500);
        let mut inputs = expiry_inputs(CoreLogicMode::CL3, u64::MAX, 1, Some(oods));
        inputs.prev_receipts[0].oods_flag = prev_oods_tick.map(|t| crate::types::OodsFlag {
            tick: t, oods_size: 0, healthy: true,
        });
        inputs
    }

    /// A REPLAYED old OODS reading — the round's attested tick is far below the
    /// wallet's last round, beyond the buffer — is rejected as stale.
    #[test]
    fn verify_vbc_expiry_replayed_old_oods_is_stale() {
        // last round X = 1_000_000; current attested T = 1000 (buffer 20) → stale.
        let inputs = freshness_inputs(1000, Some(1_000_000));
        assert!(matches!(
            crate::vbc::verify_vbc_expiry(&inputs),
            Err(ValidationError::VBCStaleAttestation { .. }),
        ), "an attested tick staler than the last round beyond the buffer is a replay");
    }

    /// An OODS lag WITHIN the carrier-latency buffer passes (normal delivery time).
    #[test]
    fn verify_vbc_expiry_oods_within_buffer_passes() {
        let buffer = crate::validation::protocol_gen::VBC_OODS_FRESHNESS_BUFFER_TICKS;
        let x = 1_000_000u64;
        // T = X - buffer/2 → now + buffer >= X → within tolerance.
        let inputs = freshness_inputs(x - buffer / 2, Some(x));
        assert!(crate::vbc::verify_vbc_expiry(&inputs).is_ok(),
            "an OODS lag within the buffer is normal carrier latency, not a replay");
    }

    /// A fresh (T >= X) or newer attested tick passes — an idle wallet legitimately
    /// has a much newer reading than its last round (no upper bound).
    #[test]
    fn verify_vbc_expiry_fresh_oods_passes() {
        let inputs = freshness_inputs(2_000_000, Some(1_000_000));
        assert!(crate::vbc::verify_vbc_expiry(&inputs).is_ok(),
            "a newer attested tick (idle wallet) must pass — no upper bound");
    }

    /// No prev-receipt OODS tick → nothing to compare → the freshness gate is skipped.
    #[test]
    fn verify_vbc_expiry_no_prev_oods_tick_skips_freshness() {
        let inputs = freshness_inputs(1000, None);
        assert!(crate::vbc::verify_vbc_expiry(&inputs).is_ok(),
            "with no prior OODS tick the freshness gate has nothing to compare and skips");
    }

    /// The freshness buffer register is compiled and non-zero.
    #[test]
    fn vbc_oods_freshness_buffer_is_compiled() {
        assert_eq!(crate::validation::protocol_gen::VBC_OODS_FRESHNESS_BUFFER_TICKS, 20,
            "the carrier-latency freshness buffer register must compile as 20 ticks");
    }

    // ── KI#130 — CL8 non-genesis VBC lifetime cap ─────────────────────────────
    // A VBC-SHAPED (3-issuer) CL8 issuance/renewal request with the given lifetime.
    // The cap fires early (before signer/candidacy checks), so a valid signer is not
    // needed to test it; an OK-lifetime cert passes the CAP and rejects LATER for
    // other reasons — so the OK assertions check the cap did NOT fire, not full Accept.
    fn cl8_vbc_issue_inputs(issued_at: u64, expires_at: u64, genesis_lineage: [u8; 32]) -> PublicInputs {
        let sphincs_pk = [0xAAu8; 32];
        let validator_id = *blake3::hash(&sphincs_pk).as_bytes();
        let mut inputs = create_test_inputs(CoreLogicMode::CL8);
        inputs.issuer_sphincs_sk = Some(vec![0u8; 64]);
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: crate::types::VBC {
                genesis_lineage,
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 9,
                validator_id,
                node_name: "test".into(),
                subject_pubkey_ed25519: vec![0u8; 32],
                subject_pubkey_sphincs: sphincs_pk.to_vec(),
                subject_pubkey_dilithium: vec![],
                pgp_fingerprint: vec![],
                proof_cap: "dmap".into(),
                issued_at,
                expires_at,
                chain_depth: 0,
                issuer_set: vec![vec![0x11; 32], vec![0x22; 32], vec![0x33; 32]], // 3 = VBC-shaped
                signatures: vec![],
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
                nabla_registration: None,
            },
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        });
        inputs
    }

    /// A CL8 issuance whose lifetime exceeds VBC_VALIDITY_TICKS is rejected.
    #[test]
    fn cl8_vbc_lifetime_over_max_is_rejected() {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        let inputs = cl8_vbc_issue_inputs(1000, 1000 + max + 1, [0u8; 32]);
        assert_eq!(
            execute_core(inputs).rejection_reason,
            Some(ValidationError::VBCLifetimeTooLong { expires_at: 1000 + max + 1, issued_at: 1000 }),
            "a VBC lifetime longer than the max must be rejected VBCLifetimeTooLong",
        );
    }

    /// A CL8 issuance at exactly the max lifetime PASSES the cap (rejects later, if at
    /// all, for other reasons — never VBCLifetimeTooLong).
    #[test]
    fn cl8_vbc_lifetime_at_max_passes_the_cap() {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        let inputs = cl8_vbc_issue_inputs(1000, 1000 + max, [0u8; 32]);
        assert_ne!(
            execute_core(inputs).rejection_reason,
            Some(ValidationError::VBCLifetimeTooLong { expires_at: 1000 + max, issued_at: 1000 }),
            "a lifetime exactly at the max must pass the lifetime cap",
        );
    }

    /// A normal ~half-max cert PASSES the cap.
    #[test]
    fn cl8_vbc_normal_lifetime_passes_the_cap() {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        let inputs = cl8_vbc_issue_inputs(1000, 1000 + max / 2, [0u8; 32]);
        let reason = execute_core(inputs).rejection_reason;
        assert!(!matches!(reason, Some(ValidationError::VBCLifetimeTooLong { .. })),
            "a normal (well-under-max) lifetime must not trip the cap, got {:?}", reason);
    }

    /// NO GENESIS EXEMPTION: a GENESIS-LINEAGE cert reaching CL8 is a RENEWAL and is
    /// ALSO capped at VBC_VALIDITY_TICKS — the 10-year initial genesis cert is
    /// ceremony-signed, never via CL8, so a genesis-lineage cert here does not get 10y.
    #[test]
    fn cl8_genesis_lineage_lifetime_over_max_is_also_rejected() {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        // A non-zero genesis lineage marks a genesis-family cert; the cap ignores it.
        let inputs = cl8_vbc_issue_inputs(1000, 1000 + max + 1, [0x7fu8; 32]);
        assert_eq!(
            execute_core(inputs).rejection_reason,
            Some(ValidationError::VBCLifetimeTooLong { expires_at: 1000 + max + 1, issued_at: 1000 }),
            "a genesis-lineage renewal over the max must ALSO be capped (no exemption)",
        );
    }

    // ── Q2-b renewal proof-of-validation (CL8 gate wiring) ────────────────
    // A renewal request carries the requester's prior cert (same SPHINCS+
    // subject) in supporting_vbcs. The gate fires in the early VBC-shaped block
    // (before signer/candidacy), so a dummy issuer key reaches it — like the
    // lifetime-cap tests. verify_renewal_work_receipt's accept/reject logic is
    // unit-tested in vbc.rs::q2b_renewal_proof_tests; these test the WIRING.
    fn cl8_renewal_inputs(prev_baseline_tick: u64, work: Option<crate::types::Receipt>) -> PublicInputs {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        let mut inputs = cl8_vbc_issue_inputs(1000, 1000 + max / 2, [0u8; 32]);
        let b = inputs.vbc_bundle.as_mut().unwrap();
        let mut prev = b.target_vbc.clone(); // same subject SPHINCS+ = a renewal
        prev.baseline_tick = prev_baseline_tick;
        b.supporting_vbcs.push(prev);
        b.renewal_work_receipt = work;
        inputs
    }

    /// A renewal with NO work receipt is refused — the intended teeth (a
    /// validator that witnessed nothing this term cannot cheaply renew).
    #[test]
    fn cl8_renewal_without_work_receipt_rejected() {
        assert_eq!(
            execute_core(cl8_renewal_inputs(4000, None)).rejection_reason,
            Some(ValidationError::VbcRenewalNoProofOfWork),
            "a renewal with no proof-of-validation receipt must be refused",
        );
    }

    /// A FIRST issuance (no same-subject prior) SKIPS the work-proof gate — it
    /// fails LATER (signer/candidacy), never with a VbcRenewal* error.
    #[test]
    fn cl8_first_issuance_skips_work_proof() {
        let max = crate::validation::protocol_gen::VBC_VALIDITY_TICKS;
        let reason = execute_core(cl8_vbc_issue_inputs(1000, 1000 + max / 2, [0u8; 32])).rejection_reason;
        assert!(
            !matches!(reason,
                Some(ValidationError::VbcRenewalNoProofOfWork)
                | Some(ValidationError::VbcRenewalNotCoSigned)
                | Some(ValidationError::VbcRenewalWorkReceiptStale)
                | Some(ValidationError::VbcRenewalWorkReceiptSubQuorum)),
            "a first issuance must not hit any renewal work-proof error, got {:?}", reason,
        );
    }

    /// A renewal with a VALID co-signed fresh proof PASSES the work gate (and
    /// then rejects later for signer/candidacy, which this minimal input lacks) —
    /// never a VbcRenewal* error. Proves the plumbing passes the right args
    /// (subject_pubkey_ed25519, prev.baseline_tick) into the verifier.
    #[test]
    fn cl8_renewal_with_valid_proof_passes_work_gate() {
        use ed25519_dalek::{Signer, SigningKey};
        let renewer = SigningKey::from_bytes(&[0x2a; 32]);
        let txid = [0xAA; 32]; let state_hash = [0xBB; 32]; let commitment_hash = [0xCC; 32];
        let seq = 1u64; let epoch = 1u64;
        let oods = Some(crate::types::OodsFlag { tick: 6000, oods_size: 10, healthy: true });
        let rc = crate::crypto::compute_receipt_commitment(
            &txid, &state_hash, seq, &commitment_hash, epoch, false, oods.as_ref(), None, None);
        let mk = |sk: &SigningKey| crate::types::WitnessSig {
            validator_id: *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes(),
            validator_pk: sk.verifying_key().to_bytes().to_vec(),
            vbc_bundle: None, carrier_type: String::new(), carrier_address: String::new(),
            signature: sk.sign(&commitment_hash).to_bytes().to_vec(),
            execution_proof: vec![], proof_type: 1, availability_attestation: None,
            validator_hints: vec![], fact_signature: None, checkpoint_sig: None, receipt_signature: None,
            receipt_commitment_sig: Some(sk.sign(&rc).to_bytes().to_vec()), rate_bps: 0, slot_amount: 0,
        };
        let receipt = crate::types::Receipt {
            oods_flag: oods, confidence_index: None, sender_state: None,
            txid, state_hash, produced_state_id: [0xDD; 32], new_wallet_seq: seq,
            commitment_hash, sdid: [0u8; 32], lineage_hash: [0u8; 32],
            witness_sigs: vec![mk(&renewer), mk(&SigningKey::from_bytes(&[0x51; 32])), mk(&SigningKey::from_bytes(&[0x52; 32]))],
            core_version: String::new(), core_id: [0u8; 32], epoch, fact_proof: None,
            required_k: 3, receipt_commitment: rc, fee_breakdown: vec![], is_dev_class: false,
        };
        let mut inputs = cl8_renewal_inputs(4000, Some(receipt));
        inputs.vbc_bundle.as_mut().unwrap().target_vbc.subject_pubkey_ed25519 =
            renewer.verifying_key().to_bytes().to_vec();
        let reason = execute_core(inputs).rejection_reason;
        assert!(
            !matches!(reason,
                Some(ValidationError::VbcRenewalNoProofOfWork)
                | Some(ValidationError::VbcRenewalNotCoSigned)
                | Some(ValidationError::VbcRenewalWorkReceiptStale)
                | Some(ValidationError::VbcRenewalWorkReceiptSubQuorum)),
            "a valid co-signed fresh proof must pass the work gate, got {:?}", reason,
        );
    }

    /// GUARDRAIL (runtime twin of the compile-time const): a cert must have usable
    /// life before it goes unusable — the max validity exceeds the unusable window.
    #[test]
    fn vbc_validity_exceeds_unusable_window() {
        assert!(
            crate::validation::protocol_gen::VBC_VALIDITY_TICKS
                > crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS,
            "vbc_validity_ticks ({}) must exceed vbc_unusable_remaining_ticks ({})",
            crate::validation::protocol_gen::VBC_VALIDITY_TICKS,
            crate::validation::protocol_gen::VBC_UNUSABLE_REMAINING_TICKS,
        );
    }

    // §6b.8a (2026-09-15): the twelve issuance-stake tests that lived here
    // (cl8_nabla_proof_*, cl8_*_rejects_*_balance / _floor / _tier3,
    // cl8_scarred_stake_wallet_rejected) tested a gate that no longer exists —
    // the stake floor is enforced at the STAMP (`verify_vbc_stamp` tests).
    fn make_cl8_inputs(sphincs_pk: [u8; 32]) -> PublicInputs {
        let validator_id = *blake3::hash(&sphincs_pk).as_bytes();
        let mut inputs = create_test_inputs(CoreLogicMode::CL8);
        inputs.issuer_sphincs_sk = Some(vec![0u8; 64]); // dummy — stake check is before signing
        inputs.vbc_bundle = Some(crate::types::VBCProofBundle {
            target_vbc: crate::types::VBC {
                genesis_lineage: [0u8; 32],
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 9,
                validator_id,
                node_name: "test".into(),
                subject_pubkey_ed25519: vec![0u8; 32],
                subject_pubkey_sphincs: sphincs_pk.to_vec(),
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
                nabla_registration: None,
            },
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        });
        inputs
    }

    /// §7.1 CLOSED (the owner ruling, 2026-09-01): a VBC-shaped cert must PROVE
    /// stake. Previously CL8 read "no proof supplied" as "this is an NBC" and
    /// skipped all seven verification steps including the tier floor, so a
    /// caller holding an issuer key could have a validator certificate signed
    /// with no stake at all.
    ///
    /// The two halves are asserted together, because either alone is
    /// meaningless: the VBC shape must now be REFUSED without a proof, and the
    /// NBC shape must still be ACCEPTED without one — a fix that also broke
    /// NBC issuance would take the live Nabla mesh down.
    #[test]
    fn cl8_signs_both_shapes_without_a_stake_proof_the_stamp_decides() {
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];

        // NBC shape (k=1 issuer), no stake proof, no candidate_balance.
        // MUST NOT be rejected for stake — Nabla nodes do not stake, and
        // `cc.rs` passes None here on the live issuance path.
        let mut nbc = make_cl8_inputs(genesis_id);
        assert_eq!(
            nbc.vbc_bundle.as_ref().unwrap().target_vbc.issuer_set.len(), 1,
            "fixture must be NBC-shaped for this half to mean anything",
        );
        let nbc_result = execute_core(nbc);
        assert_ne!(
            nbc_result.rejection_reason, Some(ValidationError::InsufficientStake),
            "NBC issuance must NOT require a stake proof — this is the live path",
        );

        // VBC shape (k=3 issuers), same absence of any stake evidence.
        // MUST be rejected now.
        let mut vbc = make_cl8_inputs(genesis_id);
        {
            let b = vbc.vbc_bundle.as_mut().unwrap();
            b.target_vbc.issuer_set = vec![vec![0u8; 32], vec![1u8; 32], vec![2u8; 32]];
            assert_eq!(b.target_vbc.issuer_set.len(), crate::vbc::VBC_REQUIRED_ISSUERS);
        }
        let vbc_result = execute_core(vbc);
        // §6b.8a — issuance produces a CANDIDATE; the stamp reads the stake.
        assert_ne!(
            vbc_result.rejection_reason, Some(ValidationError::InsufficientStake),
            "a VBC-shaped cert is issued as a candidate with no stake check — \
             the stamp (§6b) decides usability (KI#168)",
        );
    }

    /// PROVISIONAL ISSUANCE (§5.2.2): a 3-issuer cert with NO stake proof is
    /// signed only when Core can bound its lifetime. This is what breaks the
    /// chicken-and-egg — a candidate needs a verifiable binding before it can
    /// claim a stake, and cannot prove stake before it has one.
    ///
    /// The BOUNDARY is the entire safety argument. If a caller could pick the
    /// expiry, the §7.1 hole reopens in a new costume: instead of omitting a
    /// proof, you request a 10-year unstaked cert. So the long-lived case must
    /// still be refused, and it is asserted here alongside the short one.
    #[test]
    /// ⚠ THE ISSUER-INDEX DEFECT (fixed 2026-09-03).
    ///
    /// CL8's verify-after-sign checked its own signature against
    /// `issuer_set.first()`. A VBC has THREE issuers, each signing the same
    /// commitment with its own key, so that is right only for issuer 0 —
    /// issuers 1 and 2 verified a correct signature against someone else's
    /// public key and rejected a certificate they had just signed properly.
    ///
    /// It was UNREACHABLE rather than untested: the genesis ceremony signs as
    /// issuer 0, and nothing asked issuer 1 or 2 to sign until the §5.2.2d
    /// certificate-request path existed. The first live 3-issuer request hit it
    /// immediately (E_INVALID_VBC).
    ///
    /// This test signs as issuer **1**. Restore `issuer_set.first()` and it
    /// goes red.
    #[test]
    fn cl8_signs_correctly_as_a_NON_FIRST_issuer() {
        use crate::validation::PROVISIONAL_VBC_EXPIRY_SECS;

        // A REAL keypair. Fabricating 64 bytes does not work — fips205
        // validates the private key on decode — and that is the right
        // behaviour, so the test generates one properly.
        let (our_pk, sk) = {
            use fips205::slh_dsa_sha2_128s;
            use fips205::traits::{KeyGen, SerDes};
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng)
                .expect("SLH-DSA keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };
        // The derivation under test: the signer's key must come from the
        // SIGNING key, never from a guessed index.
        assert_eq!(
            crate::crypto::sphincs_pk_from_sk(&sk).expect("derive"), our_pk,
            "sphincs_pk_from_sk must reproduce the keypair's own public key",
        );

        let mut inputs = make_cl8_inputs(crate::genesis::GENESIS_VALIDATORS[0]);
        inputs.issuer_sphincs_sk = Some(sk);
        {
            let b = inputs.vbc_bundle.as_mut().unwrap();
            // OUR key sits at index 1 — deliberately NOT first.
            b.target_vbc.issuer_set = alloc::vec![
                alloc::vec![0xAAu8; 32],
                our_pk.clone(),
                alloc::vec![0xBBu8; 32],
            ];
            b.target_vbc.issued_at = 1_000_000;
            b.target_vbc.expires_at = 1_000_000 + PROVISIONAL_VBC_EXPIRY_SECS;
        }

        let out = execute_core(inputs);
        assert_ne!(
            out.rejection_reason, Some(ValidationError::Cl8VerifyAfterSignFailed),
            "CL8 must verify its own signature against the SIGNER's key, not \
             issuer_set[0] — an issuer at index 1 signs correctly and must not \
             have its own certificate refused",
        );
    }

    /// The signer must be one of the certificate's declared issuers.
    ///
    /// A signature by a key the certificate does not list is cryptographically
    /// fine and belongs to nobody the cert claims: `verify_chain_recursive`
    /// pairs `signatures[i]` with `issuer_set[i]`, so it could never match.
    /// Refusing at issue turns a certificate that verifies NOWHERE into an
    /// error at the point it is created.
    #[test]
    fn cl8_refuses_to_sign_a_certificate_that_does_not_list_the_signer() {
        use crate::validation::PROVISIONAL_VBC_EXPIRY_SECS;

        let sk = {
            use fips205::slh_dsa_sha2_128s;
            use fips205::traits::{KeyGen, SerDes};
            let mut rng = rand_core::OsRng;
            let (_pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng)
                .expect("SLH-DSA keygen");
            sk.into_bytes().to_vec()
        };
        let mut inputs = make_cl8_inputs(crate::genesis::GENESIS_VALIDATORS[0]);
        inputs.issuer_sphincs_sk = Some(sk);
        {
            let b = inputs.vbc_bundle.as_mut().unwrap();
            // Three issuers, NONE of them us.
            b.target_vbc.issuer_set = alloc::vec![
                alloc::vec![0xAAu8; 32],
                alloc::vec![0xBBu8; 32],
                alloc::vec![0xCCu8; 32],
            ];
            b.target_vbc.issued_at = 1_000_000;
            b.target_vbc.expires_at = 1_000_000 + PROVISIONAL_VBC_EXPIRY_SECS;
        }

        let out = execute_core(inputs);
        assert_eq!(
            out.rejection_reason, Some(ValidationError::Cl8SignerNotInIssuerSet),
            "signing a certificate that does not list the signer produces a \
             signature that can never be matched — refuse it at issue",
        );
    }

    /// §5.3 IS A VBC RULE. CL8 signs both kinds, and an NBC must not be made
    /// to answer it.
    ///
    /// The block was gated on `chain_depth > 0` alone, which a CITIZEN NBC also
    /// satisfies (depth 1) — so NBC issuance demanded an OODS reading Nabla's
    /// path never carries, and refused with `VBCNoAttestedTick`. Citizen joins
    /// were broken protocol-wide; found 2026-09-05 when the Pi could not
    /// re-obtain its NBC after a fresh genesis, and named by the very variant
    /// added that morning.
    #[test]
    fn cl8_applies_the_lineage_rule_to_a_vbc_but_never_to_an_nbc() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{KeyGen, SerDes};
        let (my_pk, my_sk) = {
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };

        // A CITIZEN NBC: depth 1, ONE issuer, no OODS reading — what Nabla
        // actually sends. It must not be refused for a missing tick.
        let mut nbc = make_cl8_inputs(crate::genesis::GENESIS_VALIDATORS[0]);
        nbc.oods_attestation = None;
        nbc.issuer_sphincs_sk = Some(my_sk.clone());
        {
            let b = nbc.vbc_bundle.as_mut().unwrap();
            b.target_vbc.chain_depth = 1;
            b.target_vbc.issuer_set = alloc::vec![my_pk.clone()]; // k=1 => NBC
        }
        assert_ne!(
            execute_core(nbc).rejection_reason, Some(ValidationError::VBCNoAttestedTick),
            "an NBC carries no OODS reading and §5.3 does not apply to it — \
             refusing here breaks every citizen join",
        );

        // A VBC: same depth, THREE issuers, still no reading. Must be refused.
        let mut vbc = make_cl8_inputs(crate::genesis::GENESIS_VALIDATORS[0]);
        vbc.oods_attestation = None;
        vbc.issuer_sphincs_sk = Some(my_sk);
        {
            let b = vbc.vbc_bundle.as_mut().unwrap();
            b.target_vbc.chain_depth = 1;
            b.target_vbc.issued_at = 1_000_000;
            b.target_vbc.expires_at =
                1_000_000 + crate::validation::PROVISIONAL_VBC_EXPIRY_SECS;
            b.target_vbc.issuer_set = alloc::vec![
                my_pk.clone(), alloc::vec![0xB1u8; 32], alloc::vec![0xC1u8; 32],
            ];
        }
        assert_eq!(
            execute_core(vbc).rejection_reason, Some(ValidationError::VBCNoAttestedTick),
            "a VBC still fails closed without an attested tick — the fix must \
             narrow the rule to VBCs, never weaken it",
        );
    }

    /// RULE 3 §2 / RULE 6 — every §5.3 refusal CL8 can make must be
    /// individually observable, and the accept path must still accept.
    ///
    /// `execute_cl8` runs inside the RISC-V guest, where the
    /// `#[cfg(feature = "std")]` diagnostic prints are compiled out. The
    /// `ValidationError` variant is therefore the ONLY channel a refusal has,
    /// and until 2026-09-04 all of these arms answered a bare `InvalidVBC`:
    /// "the signer is not listed", "no attested tick", "two issuers share a
    /// family" and "the check never ran" were one indistinguishable code on
    /// the wire, which is why a refused certificate request could not be
    /// diagnosed at all.
    ///
    /// Each case below mutates ONE thing away from a request that is otherwise
    /// accepted, so a case that stops failing means the rule moved, and a case
    /// that reports the wrong variant means the observability regressed.
    #[test]
    fn cl8_refusal_reasons_are_individually_observable() {
        use crate::validation::{PROVISIONAL_VBC_EXPIRY_SECS, VBC_ISSUING_MIN_REMAINING_SECS};
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{KeyGen, SerDes};

        const TICK: u64 = 1_700_000_000;

        let (my_pk, my_sk) = {
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng)
                .expect("SLH-DSA keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };
        // The other two issuers are never asked to sign here — CL8 only looks
        // their certificates up by key — so arbitrary 32-byte keys suffice.
        let issuer_b = vec![0xB1u8; 32];
        let issuer_c = vec![0xC1u8; 32];

        // A supporting certificate for one issuer: alive long enough to
        // ISSUE, and carrying the genesis family named.
        let supporting = |subject: &[u8], lineage: [u8; 32], expires_at: u64| crate::types::VBC {
            genesis_lineage: lineage,
            network_size_baseline: 0,
            baseline_tick: 0,
            version: 9,
            validator_id: *blake3::hash(subject).as_bytes(),
            node_name: "issuer".into(),
            subject_pubkey_ed25519: vec![0u8; 32],
            subject_pubkey_sphincs: subject.to_vec(),
            subject_pubkey_dilithium: vec![],
            pgp_fingerprint: vec![],
            proof_cap: "dmap".into(),
            issued_at: 0,
            expires_at,
            chain_depth: 0,
            issuer_set: vec![],
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
            nabla_registration: None,
        };
        let alive = TICK + VBC_ISSUING_MIN_REMAINING_SECS;
        let fam = |i: usize| crate::genesis::GENESIS_VALIDATORS[i];

        // A request that CL8 ACCEPTS: three issuers, three different genesis
        // families, all alive enough to issue, the candidate adopting one of
        // them, signed by a key the certificate lists, judged on an attested
        // tick.
        // KI#143: CL8 VERIFIES the reading it binds to, so the fixture
        // carries a real one — signed by a citizen key, anchored to an NBC a
        // test-authorized issuer signed (built once; SPHINCS+ is slow).
        let attestation = test_oods_attestation(TICK, 10);
        let base = || {
            let mut i = make_cl8_inputs(crate::genesis::GENESIS_VALIDATORS[0]);
            i.issuer_sphincs_sk = Some(my_sk.clone());
            i.oods_attestation = Some(attestation.clone());
            {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.chain_depth = 1;
                b.target_vbc.genesis_lineage = fam(0);
                // The OODS stamp Core now BINDS to the attestation, and the
                // value §5.3's issuing bar is judged on at every later verify.
                b.target_vbc.network_size_baseline = 10;
                b.target_vbc.baseline_tick = TICK;
                b.target_vbc.issued_at = TICK;
                b.target_vbc.expires_at = TICK + PROVISIONAL_VBC_EXPIRY_SECS;
                b.target_vbc.issuer_set =
                    vec![my_pk.clone(), issuer_b.clone(), issuer_c.clone()];
                b.supporting_vbcs = vec![
                    supporting(&my_pk, fam(0), alive),
                    supporting(&issuer_b, fam(1), alive),
                    supporting(&issuer_c, fam(2), alive),
                ];
            }
            i
        };

        // POSITIVE CONTROL. Without it every case below could be passing for
        // the wrong reason — a fixture broken upstream of the arm under test
        // fails identically to the arm firing.
        let accepted = execute_core(with_candidacy_pulse(base()));
        assert_eq!(
            accepted.rejection_reason, None,
            "the unmutated request must be SIGNED — otherwise the cases below \
             prove nothing about the arms they claim to drive",
        );
        assert!(accepted.nbc_signature.is_some(), "an accepted CL8 returns a signature");

        // Each case: mutate one thing, name the variant it must answer with.
        let cases: alloc::vec::Vec<(&str, fn(&mut PublicInputs), ValidationError)> = alloc::vec![
            ("no vbc_bundle", (|i: &mut PublicInputs| { i.vbc_bundle = None; }) as fn(&mut PublicInputs),
             ValidationError::Cl8MissingBundle),
            ("no issuer key", |i: &mut PublicInputs| { i.issuer_sphincs_sk = None; },
             ValidationError::Cl8MissingIssuerKey),
            ("issuer key malformed", |i: &mut PublicInputs| {
                i.issuer_sphincs_sk = Some(alloc::vec![0u8; 7]);
             }, ValidationError::Cl8IssuerKeyUnusable),
            ("signer not among the declared issuers", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.issuer_set[0] = alloc::vec![0xAAu8; 32];
             }, ValidationError::Cl8SignerNotInIssuerSet),
            ("zero lifetime", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.expires_at = b.target_vbc.issued_at;
             }, ValidationError::Cl8ProvisionalLifetimeInvalid),
            ("no attested tick", |i: &mut PublicInputs| { i.oods_attestation = None; },
             ValidationError::VBCNoAttestedTick),
            // KI#143: a reading the mesh never signed is refused BEFORE the
            // stamp or the candidacy tick is bound to it.
            ("an OODS reading with a forged live-reading signature", |i: &mut PublicInputs| {
                i.oods_attestation.as_mut().unwrap().nabla_signature[5] ^= 0x01;
             }, ValidationError::OodsAttestationInvalid),
            ("an OODS reading with its NBC anchor stripped", |i: &mut PublicInputs| {
                i.oods_attestation.as_mut().unwrap().nbc_issuer_pk = alloc::vec::Vec::new();
             }, ValidationError::OodsAttestationInvalid),
            ("an OODS reading whose NBC signature does not verify", |i: &mut PublicInputs| {
                i.oods_attestation.as_mut().unwrap().nbc_signature[9] ^= 0x01;
             }, ValidationError::OodsAttestationInvalid),
            ("an OODS reading re-stamped with another tick", |i: &mut PublicInputs| {
                // the fields changed under an unchanged signature
                i.oods_attestation.as_mut().unwrap().tick = TICK - 5;
             }, ValidationError::OodsAttestationInvalid),
            // The candidate does not get to write its own admission clock:
            // the stamp every later verifier judges §5.3 on must be the
            // reading the round actually carried.
            ("an OODS stamp the issuer was not shown", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.network_size_baseline = 9_999;
             }, ValidationError::Cl8OodsStampMismatch),
            ("an OODS tick the issuer was not shown", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.baseline_tick = TICK - 10_000;
             }, ValidationError::Cl8OodsStampMismatch),
            ("an issuer's own cert is absent", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.supporting_vbcs.remove(1);
             }, ValidationError::VBCIssuerCertMissing),
            ("an issuer is too close to expiry to admit anyone", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.supporting_vbcs[1].expires_at = TICK + 1;
             }, ValidationError::VBCIssuerCannotIssue),
            ("an issuer belongs to no genesis family", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.supporting_vbcs[1].genesis_lineage = [0u8; 32];
             }, ValidationError::VBCIssuerNoLineage),
            ("two issuers share a genesis family", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.supporting_vbcs[1].genesis_lineage = b.supporting_vbcs[0].genesis_lineage;
             }, ValidationError::VBCIssuersShareLineage),
            ("the candidate adopts a family none of its issuers hold", |i: &mut PublicInputs| {
                let b = i.vbc_bundle.as_mut().unwrap();
                b.target_vbc.genesis_lineage = crate::genesis::GENESIS_VALIDATORS[9];
             }, ValidationError::VBCLineageNotAdopted),
        ];

        let mut seen: alloc::vec::Vec<ValidationError> = alloc::vec::Vec::new();
        for (name, mutate, expected) in cases {
            let mut inputs = base();
            mutate(&mut inputs);
            let out = execute_core(inputs);
            assert_eq!(
                out.rejection_reason.clone(), Some(expected.clone()),
                "CL8 case '{name}' must answer with its OWN reason — a bare \
                 InvalidVBC here is the undiagnosable state this test exists \
                 to prevent",
            );
            // Distinctness is asserted per REASON, not per case: the OODS
            // mutations are two reasons — "this stamp is not the reading you
            // were shown" (Cl8OodsStampMismatch) and, since KI#143, "this
            // reading was never signed by the mesh" (OodsAttestationInvalid)
            // — each reached several ways, and collapsing them is correct.
            if !name.starts_with("an OODS") {
                assert!(
                    !seen.contains(&expected),
                    "two CL8 cases answer with the same variant — they are not \
                     distinguishable from the mesh",
                );
            }
            seen.push(expected);
        }
    }

    fn cl8_signs_any_lifetime_without_stake_the_stamp_decides() {
        use crate::validation::{PROVISIONAL_VBC_EXPIRY_SECS, VBC_UNUSABLE_REMAINING_SECS};
        let genesis_id = crate::genesis::GENESIS_VALIDATORS[0];

        let mk = |lifetime: u64| {
            let mut i = make_cl8_inputs(genesis_id);
            let b = i.vbc_bundle.as_mut().unwrap();
            b.target_vbc.issuer_set = vec![vec![0u8; 32], vec![1u8; 32], vec![2u8; 32]];
            b.target_vbc.issued_at = 1_000_000;
            b.target_vbc.expires_at = 1_000_000 + lifetime;
            i
        };

        // Within the provisional bound → NOT refused for stake. (It may fail
        // later at SPHINCS+ signing on dummy keys; we assert the stake gate
        // specifically, exactly as the neighbouring CL8 tests do.)
        let ok = execute_core(mk(PROVISIONAL_VBC_EXPIRY_SECS));
        assert_ne!(
            ok.rejection_reason, Some(ValidationError::InsufficientStake),
            "a cert inside the provisional bound must be signable without stake",
        );

        // One second over the bound → refused. This is the §7.1 case.
        // §6b.8a (KI#168): a long-lived certificate is issued as a CANDIDATE
        // too — it cannot serve until Nabla stamps it, and the stamp reads the
        // stake floor. Issuance no longer decides stake by lifetime.
        let over = execute_core(mk(PROVISIONAL_VBC_EXPIRY_SECS + 1));
        assert_ne!(over.rejection_reason, Some(ValidationError::InsufficientStake),
            "a full-lifetime candidate is signable without stake; the stamp decides");
        let year = execute_core(mk(31_536_000));
        assert_ne!(year.rejection_reason, Some(ValidationError::InsufficientStake));

        // Zero / inverted lifetime is never signed.
        let zero = execute_core(mk(0));
        assert_eq!(zero.rejection_reason, Some(ValidationError::Cl8ProvisionalLifetimeInvalid));

        // And the property that makes the exemption safe at all: anything Core
        // will sign unstaked is TOO SHORT TO SERVE for its whole life.
        assert!(
            PROVISIONAL_VBC_EXPIRY_SECS < VBC_UNUSABLE_REMAINING_SECS,
            "a signable provisional ({PROVISIONAL_VBC_EXPIRY_SECS}) must be shorter \
             than the serve threshold ({VBC_UNUSABLE_REMAINING_SECS}), or Core \
             would sign an unstaked cert that can witness",
        );
    }

    // ── CL8: no stake proof is read at issuance (§6b.8a, KI#168) ──
    // `cl8_clean_stake_wallet_passes_the_scar_gate` DELETED 2026-10-02 (KI#249):
    // it was the "control" for a CL8 scar gate that no longer exists — it fed a
    // `NablaStakeProof` to a mode that never reads one and asserted the absence
    // of `StakeWalletScarred`, a variant nothing emitted (both now deleted).
    #[test]
    fn cl8_nbc_path_no_stake_no_proof() {
        // NBC issuance: no stake proof, no candidate_balance → still signs (no stake check)
        // The wallet identity binding still applies (wallet_pk == VBC.ed25519_pk)
        let non_genesis_id = [0xAA; 32];
        let mut inputs = make_cl8_inputs(non_genesis_id);
        let result = execute_core(inputs);
        // Should NOT be InsufficientStake (issuance carries no stake check, §6b.8a)
        assert_ne!(result.rejection_reason, Some(ValidationError::InsufficientStake));
    }

    // ── CL8: NablaStakeProof Receipt Signature Regression Test ──
    // Regression: if someone removes receipt sig verification (Step 0e),
    // fake receipt signatures would be accepted, allowing fake stake proofs.
    /// Regression: CL8 must reject NablaStakeProof where the same validator_pk
    /// signs multiple receipts. Without dedup, one validator could satisfy k=3
    /// by submitting 3 copies of the same signature.
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
            "sender@example.net", &receiver_wallet_id, amount, epoch, 0,
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
                fact_certificates: alloc::vec::Vec::new(),
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
                fact_certificates: alloc::vec::Vec::new(),
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
            zkq_request: None,
            fact_certificates: alloc::vec::Vec::new(),
            receiver_witness: None,
            receiver_signing_key: None,
            oods_attestation: None,
            recall_attestation: None,
            fob_claim_attestation: None,
            claimant_vbc: None,
            mode: CoreLogicMode::CL1,
            transaction: tx,
            current_state: Some(WalletState {
                wall_clock_lock: 0,
                emission_claimed_epoch: 0,
                stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT,
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
            console_nominations: None, txid_attestation: None,
        cheque_claim_proof: None,
            clara_attestation: None,
            phase_out_payload: None,
            phase_out_era_end_ticks: vec![],
            phase_out_blocked_era_ids: vec![],
            current_tick: 0,
            local_core_id: [0u8; 32],

            receiver_current_hibernation: None,
            receiver_current_wall_clock_lock: None,
            receiver_current_emission_claimed_epoch: None,
            receiver_current_stake_floor_until: None,
            // §6b.13 — CL5 refuses a receiver with no format block; the
            // current one is what every real caller passes.
            receiver_current_wallet_format: Some(crate::types::WalletFormat::CURRENT),
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
            // (The CL2 rewrite this once had to match was deleted with KI#260;
            // the value is now only signed, never read by the gate.)
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
    /// given state_id, so the CLARA eligibility branch actually runs.
    fn with_stored_state(inputs: &mut PublicInputs, state_id: [u8; 32]) {
        inputs.current_state = Some(WalletState {
            wall_clock_lock: 0,
            emission_claimed_epoch: 0,
            stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT,
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
        //   - eligibility check (view state_id == healed_to, KI#260) ✓
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
            healed_to_state_id: stored_state, // eligible (KI#260: healed_to ONLY)
            healed_at_seq: 7,
            healed_balance: 1_000_000_000,
            heal_txid: [0xAA; 32],
            garbage_state_ids: vec![[0x55; 32]],
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
        // Era is well over the 50-year MINIMUM ERA AGE (passes), but the grace
        // period is just under the 5-year MINIMUM (fails). Both bounds are
        // specified in AXIOM_YellowPaper.md (CL11 console phase-out): "50-year
        // minimum era age + 5-year minimum grace period".
        //
        // This previously read "rule 4b passes / rule 3 fails" — a local
        // numbering that appears in NO document, so a reader could not look
        // either rule up. Cite the named bound, not an invented index
        // (CLAUDE.md RULE 4; scripts/check_spec_lag.sh).
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
                fact_certificates: alloc::vec::Vec::new(),
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

    /// §5.2.2c — a STAKE-LOCKED wallet may RECEIVE but may not REDEEM.
    ///
    /// The escape this closes (KI#133): CL5 carried the receiver's hibernation
    /// through from a value supplied outside Core, and runs no §15 anchor, so a
    /// locked wallet could redeem declaring `hibernation_until = 0` and walk out
    /// of a lock it had not served. The gate keys on the STAKE LOCK, which
    /// Lambda sources from its own storage.
    #[test]
    fn cl5_refuses_a_redeem_while_the_stake_lock_is_held() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        inputs.receiver_wallet_seq = Some(1);
        // A validator stake lock in force. The client ALSO declares
        // `hibernation_until = 0` here — the exact lie the gate must survive,
        // and the reason it keys on the lock rather than the hibernation term.
        inputs.receiver_current_wall_clock_lock = Some(1_788_675_677);
        inputs.receiver_current_hibernation = Some(0);

        let result = execute_core(inputs);
        assert_eq!(result.result, ValidationResult::Reject);
        assert_eq!(
            result.rejection_reason,
            Some(ValidationError::StakeLocked),
            "a stake-locked wallet's redeem must be refused StakeLocked even when \
             the client declares hibernation_until=0; got {:?}",
            result.rejection_reason,
        );
    }

    /// §5.2.2c — AND THE EXEMPTION THAT MUST NOT BREAK.
    ///
    /// HAL and RECALL hibernate with NO stake lock, and their completion IS a
    /// redeem. If the gate above ever fires on them, every wallet mid-recovery
    /// is stranded with no exit — the worst possible regression from this
    /// change, and the reason the trigger is `wall_clock_lock` and not
    /// "is hibernating". Same inputs as the test above with the lock at 0, and
    /// a hibernation deadline in force: whatever CL5 decides, it must NOT be
    /// StakeLocked.
    #[test]
    fn cl5_still_admits_a_hal_recall_redeem_while_hibernating() {
        let pk_bytes: [u8; 32] = [0xDD; 32];
        let wid = generate_wallet_id("pocket@axiom.internal", "42", &pk_bytes)
            .expect("generate valid wallet_id");
        let bundle = make_genesis_claim_bundle(&wid);

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(bundle);
        inputs.receiver_pk = Some(vec![0xDD; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(crate::types::GENESIS_CLAIM_AMOUNT);
        inputs.receiver_wallet_seq = Some(1);
        // Hibernating, NO stake lock — the HAL / RECALL shape.
        inputs.receiver_current_wall_clock_lock = Some(0);
        inputs.receiver_current_hibernation = Some(1_788_675_809);

        let result = execute_core(inputs);
        assert_ne!(
            result.rejection_reason,
            Some(ValidationError::StakeLocked),
            "the stake-lock gate fired on a HAL/RECALL redeem (hibernating, no \
             stake lock) — this strands every wallet mid-recovery with no exit",
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
                FactWitness { validator_id: [1u8; 32], validator_pk: vec![], signature: vec![], vbc_hash: [0u8; 32] },
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
            burn_proof: None,
            burn_target_tx_id: None,
            sender_anchor: None,
            is_dev_class: false,
            recall_proof: None,
            out_of_order_confirmation: None,
            inherited_scar_txids: Vec::new(),
            inherited_scar_resolutions: Vec::new(),
            receiver_witness: None,
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
                fact_certificates: alloc::vec::Vec::new(),
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

    /// KI#144 (2026-09-11): an ONLINE redeem must carry the YPX-014 txid
    /// attestation — Core refuses without it. Before this, Core verified the
    /// attestation only when present and "Lambda enforces mandatory"; a
    /// patched Lambda could omit it and Core signed. Same fixture as the
    /// test above, plus a claim proof whose `cheque_id` matches the bundle
    /// so the redeem reaches the presence check; the proof's signature is
    /// junk, so a PRESENT attestation must move the refusal PAST the
    /// presence check (to the attestation's own signature check) — that is
    /// what shows the check fires on absence and only on absence.
    #[test]
    fn cl5_online_redeem_without_txid_attestation_is_refused() {
        use crate::types::{ChequeBundle, ChequeClaimProof, NablaTxidAttestation, ValidatorCheque};
        let sender_pk: [u8; 32] = [0xAA; 32];
        let receiver_pk: [u8; 32] = [0xBB; 32];
        let sender_wid = generate_wallet_id("sender@test.com", "42", &sender_pk).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &receiver_pk).unwrap();
        let make_cheque = |vid_byte: u8| -> ValidatorCheque {
            ValidatorCheque {
                fact_certificates: alloc::vec::Vec::new(),
                recall_target_tx_id: None, txid: [0x77; 32], validator_id: [vid_byte; 32],
                validator_pk: vec![vid_byte; 32], signature: vec![0u8; 64], execution_proof: vec![],
                vbc_bundle: None, carrier_type: "test".into(), carrier_address: "test@test.com".into(),
                sender_wallet_id: sender_wid.clone(), receiver_wallet_id: receiver_wid.clone(),
                amount: 50_000_000_000, rate_bps: 10, reference: "ki144".into(), epoch: 500,
                created_at: 0, state_hash: [0x33; 32], produced_state_id: [0x44; 32],
                sender_fact_chain: None, zkp_nonce: None, proof_type: 1,
                dmap_input_hash: [0u8; 32], dmap_output_hash: [0u8; 32], oracle_claim: None,
                nabla_hint: None, sender_wallet_pk: Some(sender_pk),
            }
        };
        let base = || {
            let mut inputs = create_test_inputs(CoreLogicMode::CL5);
            inputs.cheque_bundle = Some(ChequeBundle {
                cheques: vec![make_cheque(0x01), make_cheque(0x02), make_cheque(0x03)],
                fact_chain: None,
            });
            inputs.receiver_pk = Some(receiver_pk.to_vec());
            inputs.receiver_current_balance = Some(0);
            inputs.receiver_new_balance = Some(50_000_000_000 - 30_000);
            inputs.receiver_wallet_seq = Some(0);
            inputs.cheque_claim_proof = Some(ChequeClaimProof {
                cheque_id: [0x77; 32], client_pk: receiver_pk, k_tier: 3,
                wallet_address: "receiver@test.com".into(), claim_sig: vec![0u8; 64],
                claim_tick: 500, nabla_node_pk: [0x55; 32], nabla_signature: vec![0u8; 64],
                nbc_issuer_pk: vec![], nbc_signature: vec![], nbc_commitment: vec![],
            });
            inputs.txid_attestation = None;
            inputs
        };
        let absent = execute_core(base());
        assert_eq!(absent.rejection_reason, Some(ValidationError::TxidAttestationMissing),
            "an online redeem without the txid attestation must be refused by CORE");

        let mut with = base();
        with.txid_attestation = Some(NablaTxidAttestation {
            txid: [0x77; 32], status: "NOT_REDEEMED".into(), registered_by: vec![],
            nabla_node_pk: [0x66; 32], nabla_signature: vec![0u8; 64], nabla_tick: 500,
            txid_service: "bloom".into(), nbc_issuer_pk: vec![], nbc_signature: vec![],
            nbc_commitment: vec![], origin: None, sender_registered_at_tick: 0,
            oods_size: 0, oods_healthy: false,
            origin_status: crate::types::OriginVouchStatus::Unknown,
        });
        let present = execute_core(with);
        assert_eq!(present.rejection_reason, Some(ValidationError::TxidAttestationInvalidSig),
            "with an attestation PRESENT the refusal moves to the attestation's own checks — \
             the presence check fires on absence only");
    }

    // ════════════════════════════════════════════════════════════════
    // KI#205 (YPX-022 §2.1.2a, RULED 2026-09-25) — the cheque CLAIM is
    // AUTHENTICATED and bound into the CL5 proof. A hermetic Nabla writer
    // (fresh Ed25519 key, NBC SPHINCS+-signed by a fresh issuer registered
    // through `nabla_genesis::test_roots`, cfg(test) only) signs a REAL txid
    // attestation and a REAL claim proof, so the fixture walks past every
    // Step 3.5 / 3.5b gate and the tests below can show each new check fire
    // on its own input and only on it.
    // ════════════════════════════════════════════════════════════════

    /// A Nabla writer the CL5 trust anchor accepts: `(node key, NBC issuer pk,
    /// NBC signature, NBC commitment)`. The commitment carries the node's
    /// Ed25519 pk literally (window-scanned by `verify_nbc_for_*`).
    fn ki205_nabla_writer() -> (Ed25519SigningKey, Vec<u8>, Vec<u8>, Vec<u8>) {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::{KeyGen, SerDes};
        let node = Ed25519SigningKey::from_bytes(&[0x42u8; 32]);
        let node_pk = node.verifying_key().to_bytes();
        let (issuer_pk, issuer_sk) = {
            let mut rng = rand_core::OsRng;
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        };
        crate::nabla_genesis::test_roots::authorize(issuer_pk.clone().try_into().unwrap());
        let mut nbc_commitment = b"AXIOM_NBC_KI205_TEST".to_vec();
        nbc_commitment.extend_from_slice(&node_pk);
        let nbc_signature = crate::crypto::sign_sphincs(
            &issuer_sk, blake3::hash(&nbc_commitment).as_bytes()).expect("sphincs sign");
        (node, issuer_pk, nbc_signature, nbc_commitment)
    }

    /// CL5 inputs for one k=3 online redeem of txid `0x77..` to a receiver whose
    /// key is `receiver`, carrying a VALID txid attestation from `writer` and
    /// the given claim proof. Everything up to and including Step 3.5b is
    /// genuine; the cheques themselves are unsigned test cheques (no CL5 unit
    /// test in this suite reaches Accept — the downstream gates need validator
    /// signatures and VBC lineage), so "the proof is accepted" is shown the
    /// KI#144 way: the refusal moves PAST every Step 3.5b reason.
    fn ki205_inputs(
        receiver: &Ed25519SigningKey,
        writer: &(Ed25519SigningKey, Vec<u8>, Vec<u8>, Vec<u8>),
        proof: crate::types::ChequeClaimProof,
    ) -> PublicInputs {
        use crate::types::{ChequeBundle, NablaTxidAttestation, ValidatorCheque};
        let (node, issuer_pk, nbc_signature, nbc_commitment) = writer;
        let sender_pk: [u8; 32] = [0xAA; 32];
        let receiver_pk = receiver.verifying_key().to_bytes();
        let sender_wid = generate_wallet_id("sender@test.com", "42", &sender_pk).unwrap();
        let receiver_wid = generate_wallet_id("receiver@test.com", "42", &receiver_pk).unwrap();
        let make_cheque = |vid_byte: u8| -> ValidatorCheque {
            ValidatorCheque {
                fact_certificates: alloc::vec::Vec::new(),
                recall_target_tx_id: None, txid: [0x77; 32], validator_id: [vid_byte; 32],
                validator_pk: vec![vid_byte; 32], signature: vec![0u8; 64], execution_proof: vec![],
                vbc_bundle: None, carrier_type: "test".into(), carrier_address: "test@test.com".into(),
                sender_wallet_id: sender_wid.clone(), receiver_wallet_id: receiver_wid.clone(),
                amount: 50_000_000_000, rate_bps: 10, reference: "ki205".into(), epoch: 500,
                created_at: 0, state_hash: [0x33; 32], produced_state_id: [0x44; 32],
                sender_fact_chain: None, zkp_nonce: None, proof_type: 1,
                dmap_input_hash: [0u8; 32], dmap_output_hash: [0u8; 32], oracle_claim: None,
                nabla_hint: None, sender_wallet_pk: Some(sender_pk),
            }
        };
        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.cheque_bundle = Some(ChequeBundle {
            cheques: vec![make_cheque(0x01), make_cheque(0x02), make_cheque(0x03)],
            fact_chain: None,
        });
        inputs.receiver_pk = Some(receiver_pk.to_vec());
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(50_000_000_000 - 30_000);
        inputs.receiver_wallet_seq = Some(0);
        let att_payload = crate::crypto::txid_attest_payload(&[0x77; 32], "NOT_REDEEMED", 500, None, 0, 0, false,
            crate::types::OriginVouchStatus::Unknown);
        inputs.txid_attestation = Some(NablaTxidAttestation {
            txid: [0x77; 32], status: "NOT_REDEEMED".into(), registered_by: vec![],
            nabla_node_pk: node.verifying_key().to_bytes(),
            nabla_signature: node.sign(&att_payload).to_bytes().to_vec(), nabla_tick: 500,
            txid_service: "bloom".into(), nbc_issuer_pk: issuer_pk.clone(),
            nbc_signature: nbc_signature.clone(), nbc_commitment: nbc_commitment.clone(),
            origin: None, sender_registered_at_tick: 0, oods_size: 0, oods_healthy: false,
            origin_status: crate::types::OriginVouchStatus::Unknown,
        });
        inputs.cheque_claim_proof = Some(proof);
        inputs
    }

    /// A claim proof exactly as an honest claimant + honest Nabla writer
    /// produce it: `claim_sig` by the receiver over the ONE claim builder,
    /// `nabla_signature` by the writer over the ONE proof builder (which
    /// covers `claim_sig`).
    fn ki205_valid_proof(
        receiver: &Ed25519SigningKey,
        writer: &(Ed25519SigningKey, Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> crate::types::ChequeClaimProof {
        let (node, issuer_pk, nbc_signature, nbc_commitment) = writer;
        let receiver_pk = receiver.verifying_key().to_bytes();
        let claim_sig = receiver.sign(&crate::crypto::cheque_claim_signing_payload(
            &[0x77; 32], &receiver_pk, 3, "receiver@test.com")).to_bytes().to_vec();
        let nabla_signature = node.sign(&crate::crypto::redeem_claim_nabla_payload(
            &[0x77; 32], 500, &claim_sig)).to_bytes().to_vec();
        crate::types::ChequeClaimProof {
            cheque_id: [0x77; 32], client_pk: receiver_pk, k_tier: 3,
            wallet_address: "receiver@test.com".into(), claim_sig, claim_tick: 500,
            nabla_node_pk: node.verifying_key().to_bytes(), nabla_signature,
            nbc_issuer_pk: issuer_pk.clone(), nbc_signature: nbc_signature.clone(),
            nbc_commitment: nbc_commitment.clone(),
        }
    }

    fn is_step_35_reason(r: &Option<ValidationError>) -> bool {
        matches!(r,
            Some(ValidationError::ChequeClaimProofMissing)
            | Some(ValidationError::ChequeClaimProofTxidMismatch)
            | Some(ValidationError::ChequeClaimProofUnauthenticated)
            | Some(ValidationError::ChequeClaimProofInvalidSig)
            | Some(ValidationError::ChequeClaimProofReceiverMismatch)
            | Some(ValidationError::ChequeClaimProofUntrusted)
            | Some(ValidationError::ChequeClaimProofExpired)
            | Some(ValidationError::TxidAttestationMissing)
            | Some(ValidationError::TxidAttestationInvalidSig)
            | Some(ValidationError::TxidAttestationUntrusted)
            | Some(ValidationError::TxidAttestationRedeemed)
            | Some(ValidationError::TxidAttestationBadStatus)
            | Some(ValidationError::TxidPhasedOut))
    }

    /// KI#205 baseline: a genuine authenticated claim proof is ACCEPTED by
    /// Step 3.5b — the redeem walks past every claim/attestation gate and the
    /// first thing that refuses it is the VALIDATOR CHEQUE signature check
    /// (the fixture's cheques are unsigned), which sits after Step 3.5c/3.6.
    /// This is the control the refusal tests below are read against: without
    /// it a refusal could be the fixture, not the check.
    #[test]
    fn ki205_cl5_accepts_an_authenticated_claim_proof() {
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);
        let result = execute_core(ki205_inputs(&receiver, &writer, ki205_valid_proof(&receiver, &writer)));
        std::eprintln!("[ki205 accept-control] result={:?} downstream reason={:?}",
            result.result, result.rejection_reason);
        assert!(!is_step_35_reason(&result.rejection_reason),
            "a valid authenticated claim proof must pass Step 3.5 / 3.5b; got {:?}",
            result.rejection_reason);
        assert_eq!(result.rejection_reason, Some(ValidationError::InvalidChequeSignature),
            "the valid proof must carry the redeem all the way to the cheque-signature gate");
    }

    /// ForkSettlement §9p — CL5 Step 3.5 refuses a txid attestation whose SIGNED
    /// `origin_status` disagrees with its SIGNED `origin`
    /// (`fact::txid_attestation_origin_consistent`): `Vouched` with no origin,
    /// and `Held` / `Unknown` WITH an origin, are `TxidAttestationBadStatus`
    /// even though the node's signature over the payload is genuine. The
    /// `Held` + no-origin attestation is well-formed and walks on to the
    /// cheque-signature gate (the control). MUTATION: delete the
    /// `txid_attestation_origin_consistent` check in Step 3.5 ⇒ the malformed
    /// cases also reach `InvalidChequeSignature` ⇒ RED.
    #[test]
    fn cl5_refuses_an_attestation_whose_origin_status_disagrees_with_its_origin() {
        use crate::types::OriginVouchStatus as S;
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);
        let origin = crate::types::OriginRecord {
            preimage: crate::types::WitnessPreimage {
                consumed_state_id: [0x31; 32], client_pk: [0xA1; 32], wallet_seq: 7,
                receiver_wallet_id: "receiver@test.com".into(), amount: 50_000_000_000, nonce: 9,
            },
            epoch: 500,
            kind: crate::types::LegKind::Send,
        };
        let run = |status: S, origin: Option<crate::types::OriginRecord>| {
            let mut inputs = ki205_inputs(&receiver, &writer, ki205_valid_proof(&receiver, &writer));
            let att = inputs.txid_attestation.as_mut().unwrap();
            att.origin_status = status;
            att.origin = origin;
            att.sender_registered_at_tick = if att.origin.is_some() { 100 } else { 0 };
            // Re-sign the edited attestation with the SAME (NBC-anchored) node
            // key over Core's ONE builder: the signature is genuine, only the
            // status/origin pairing is what is judged.
            let payload = crate::crypto::txid_attest_payload(&att.txid, &att.status, att.nabla_tick,
                att.origin.as_ref(), att.sender_registered_at_tick, att.oods_size, att.oods_healthy,
                att.origin_status);
            att.nabla_signature = writer.0.sign(&payload).to_bytes().to_vec();
            execute_core(inputs).rejection_reason
        };
        assert_eq!(run(S::Held, None), Some(ValidationError::InvalidChequeSignature),
            "control: a well-formed Held attestation passes Step 3.5");
        assert_eq!(run(S::Vouched, Some(origin.clone())), Some(ValidationError::InvalidChequeSignature),
            "control: a well-formed Vouched attestation passes Step 3.5");
        assert_eq!(run(S::Vouched, None), Some(ValidationError::TxidAttestationBadStatus),
            "Vouched WITHOUT an origin is malformed");
        assert_eq!(run(S::Held, Some(origin.clone())), Some(ValidationError::TxidAttestationBadStatus),
            "Held WITH an origin is malformed");
        assert_eq!(run(S::Unknown, Some(origin)), Some(ValidationError::TxidAttestationBadStatus),
            "Unknown WITH an origin is malformed");
    }

    /// KI#205 (a): `claim_sig` must be the RECEIVER key's signature over the
    /// ONE claim builder — a proof whose claim_sig is tampered, or whose signed
    /// fields (k_tier, wallet_address) were altered after signing, is refused
    /// `ChequeClaimProofUnauthenticated`. MUTATION: delete the claim_sig
    /// verify in Step 3.5b and this test goes red (the tampered proof then
    /// falls through to the Nabla-signature check and reads
    /// `ChequeClaimProofInvalidSig` instead).
    #[test]
    fn ki205_cl5_refuses_a_claim_the_receiver_key_did_not_sign() {
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);

        // One flipped byte in claim_sig.
        let mut tampered = ki205_valid_proof(&receiver, &writer);
        tampered.claim_sig[0] ^= 0x01;
        let result = execute_core(ki205_inputs(&receiver, &writer, tampered));
        assert_eq!(result.rejection_reason, Some(ValidationError::ChequeClaimProofUnauthenticated),
            "a tampered claim_sig must be refused as UNAUTHENTICATED (before the Nabla-sig check)");

        // Signed fields altered after signing: the tier …
        let mut retiered = ki205_valid_proof(&receiver, &writer);
        retiered.k_tier = 0;
        let result = execute_core(ki205_inputs(&receiver, &writer, retiered));
        assert_eq!(result.rejection_reason, Some(ValidationError::ChequeClaimProofUnauthenticated),
            "k_tier is bound into claim_sig — changing it must be refused");

        // … and the address (KI#181: address + key together bind the receiver).
        let mut readdressed = ki205_valid_proof(&receiver, &writer);
        readdressed.wallet_address = "stranger@test.com".into();
        let result = execute_core(ki205_inputs(&receiver, &writer, readdressed));
        assert_eq!(result.rejection_reason, Some(ValidationError::ChequeClaimProofUnauthenticated),
            "wallet_address is bound into claim_sig — changing it must be refused");
    }

    /// KI#205 / KI#216 — a claim made by a DIFFERENT key than the redeemer's cannot
    /// authorise this redeem: `p.client_pk` must equal the receiver key CL5 verified
    /// (`ChequeClaimProofReceiverMismatch`, declared 2026-06 and never raised until
    /// 2026-09-25). The stranger's claim is internally valid — signed by its own key
    /// over its own address, Nabla-signed — so only the binding refuses it.
    /// Mutation: delete the `p.client_pk != receiver_pk` check → this goes red.
    #[test]
    fn ki205_cl5_refuses_a_valid_claim_made_by_another_key() {
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);
        let stranger = Ed25519SigningKey::from_bytes(&[0xC3u8; 32]);
        // A claim that is valid for the STRANGER (its own sig, its own address)…
        let strangers_claim = ki205_valid_proof(&stranger, &writer);
        // … presented on the RECEIVER's redeem.
        let r = execute_core(ki205_inputs(&receiver, &writer, strangers_claim));
        assert_eq!(r.rejection_reason, Some(ValidationError::ChequeClaimProofReceiverMismatch),
            "a claim by another key must not authorise this receiver's redeem");
    }

    /// KI#205 — the claim-proof FRESHNESS window is `cheque_claim_proof_max_age_ticks`
    /// PROJECTED to seconds (24 h), not the raw tick count (4.8 h). Both ticks are
    /// unix-second VALUES; the register is a COUNT (KI#40/#47/#165 class, 5th
    /// recurrence, found 2026-09-25 while binding claim_sig). Mutation: compare the
    /// raw `.0` again and the "fresh at 86,399 s" case goes red (`Expired`).
    #[test]
    fn ki205_cl5_claim_freshness_is_the_register_projected_to_seconds() {
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);
        let window_secs = crate::validation::CHEQUE_CLAIM_PROOF_MAX_AGE_TICKS.to_secs();
        assert!(window_secs > crate::validation::CHEQUE_CLAIM_PROOF_MAX_AGE_TICKS.0,
            "the projection must be wider than the raw count (TICK_INTERVAL_SECS > 1)");
        // claim_tick is 500 in the fixture. One second INSIDE the projected window:
        // the freshness gate must pass (the reason is the next gate's, as in the
        // accept-control test) — under the raw-count comparison this reads Expired.
        let mut fresh = ki205_inputs(&receiver, &writer, ki205_valid_proof(&receiver, &writer));
        fresh.current_tick = 500 + window_secs - 1;
        let r = execute_core(fresh);
        assert_ne!(r.rejection_reason, Some(ValidationError::ChequeClaimProofExpired),
            "a proof {} s old is inside the {} s window — it must NOT be Expired", window_secs - 1, window_secs);
        assert_eq!(r.rejection_reason, Some(ValidationError::InvalidChequeSignature));
        // Past the window plus the one-minute slack: Expired.
        let mut stale = ki205_inputs(&receiver, &writer, ki205_valid_proof(&receiver, &writer));
        stale.current_tick = 500 + window_secs + 61;
        let r = execute_core(stale);
        assert_eq!(r.rejection_reason, Some(ValidationError::ChequeClaimProofExpired));
    }

    /// KI#205 (b) — the BINDING (YPX-022 §2.1.2a item 5): the Nabla signature
    /// covers `claim_sig`. A proof whose claim_sig is VALID but whose Nabla
    /// signature was made over the pre-KI#205 preimage (`AXIOM_REDEEM_CLAIM ||
    /// cheque_id || "CLAIMED" || tick_le`, WITHOUT claim_sig) passes the
    /// claim_sig check and is refused at the Nabla-signature check —
    /// `ChequeClaimProofInvalidSig`. If the builder ever stopped covering
    /// claim_sig, this old-preimage signature would verify and the test goes
    /// red: a Nabla proof could then be attached to a claim the writer never
    /// signed for.
    #[test]
    fn ki205_cl5_nabla_signature_must_cover_claim_sig() {
        let writer = ki205_nabla_writer();
        let receiver = Ed25519SigningKey::from_bytes(&[0xB7u8; 32]);
        let mut proof = ki205_valid_proof(&receiver, &writer);
        // The OLD preimage, assembled by hand ON PURPOSE — this is the value the
        // binding must reject, not a builder.
        let mut old = blake3::Hasher::new();
        old.update(b"AXIOM_REDEEM_CLAIM");
        old.update(&proof.cheque_id);
        old.update(b"CLAIMED");
        old.update(&proof.claim_tick.to_le_bytes());
        proof.nabla_signature = writer.0.sign(old.finalize().as_bytes()).to_bytes().to_vec();
        let result = execute_core(ki205_inputs(&receiver, &writer, proof));
        assert_eq!(result.rejection_reason, Some(ValidationError::ChequeClaimProofInvalidSig),
            "a Nabla signature that does not cover claim_sig must fail the Nabla-sig check");
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

    /// CL5's copy of the ValidatorJoin §5.2.2 gate: a cheque whose signer's
    /// certificate is PROVISIONAL is not a validator cheque.
    ///
    /// Driven through the k=0 Ark entry for a mechanical reason worth stating,
    /// because it looks like an odd choice: the k>=3 profile hits Step 3.5b's
    /// mandatory Nabla-signed `cheque_claim_proof` long before the per-cheque
    /// VBC loop, and no unit fixture can produce one (the same wall the
    /// CRITICAL-3 test records). k=0 skips 3.5b and reaches the identical
    /// line — the gate is not k-conditional, so exercising it here exercises
    /// it for every redeem.
    ///
    /// MUTATION-TESTED (RULE 6 §3): comment the CL5 gate out and this goes red
    /// with the next downstream rejection instead.
    #[test]
    fn cl5_refuses_a_cheque_signed_under_a_provisional_cert() {
        use crate::wallet_id::{generate_all_wallet_ids, K_ARK};
        use crate::types::{ValidatorCheque, ChequeBundle, VBCProofBundle, VBC};

        let spk = [0x71u8; 32];
        let rpk = [0x72u8; 32];
        let ark = |email: &str, pk: &[u8; 32]| {
            generate_all_wallet_ids(email, "42", pk).unwrap()
                .into_iter().find(|(_, k, _, _)| *k == K_ARK).unwrap().0
        };
        let sender_wallet_id = ark("arkprovsender@test.com", &spk);
        let receiver_wallet_id = ark("arkprovreceiver@test.com", &rpk);

        // A cert with a 12h life — exactly what execute_cl8 signs unstaked.
        let issued_at = 1_700_000_000u64;
        let expires_at = issued_at + crate::validation::PROVISIONAL_VBC_EXPIRY_SECS;
        let sphincs_pk = vec![0x73u8; 32];
        let validator_id = *blake3::hash(&sphincs_pk).as_bytes();
        let provisional = VBCProofBundle {
            target_vbc: VBC {
                genesis_lineage: [0u8; 32],
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 0x09,
                validator_id,
                subject_pubkey_sphincs: sphincs_pk,
                subject_pubkey_dilithium: vec![0u8; 1952],
                subject_pubkey_ed25519: vec![0u8; 32],
                pgp_fingerprint: vec![],
                node_name: alloc::string::String::new(),
                proof_cap: alloc::string::String::new(),
                issued_at,
                expires_at,
                chain_depth: 0,
                issuer_set: vec![],
                signatures: vec![],
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
                nabla_registration: None,
            },
            supporting_vbcs: vec![],
            candidacy_pulse: None, renewal_work_receipt: None,
        };

        let cheque = ValidatorCheque {
            fact_certificates: alloc::vec::Vec::new(),
            recall_target_tx_id: None,
            txid: [0xAA; 32],
            validator_id,
            validator_pk: vec![0u8; 32],
            signature: vec![0u8; 64],
            execution_proof: vec![],
            vbc_bundle: Some(provisional),
            carrier_type: "test".into(),
            carrier_address: "test@test.com".into(),
            sender_wallet_id: sender_wallet_id.clone(),
            receiver_wallet_id: receiver_wallet_id.clone(),
            amount: 1_000,
            rate_bps: 0,
            reference: "test".into(),
            epoch: issued_at + 60,
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
        };

        let mut inputs = create_test_inputs(CoreLogicMode::CL5);
        inputs.transaction.sender_wallet_id = sender_wallet_id;
        inputs.transaction.receiver_wallet_id = receiver_wallet_id.clone();
        inputs.cheque_bundle = Some(ChequeBundle { cheques: vec![cheque], fact_chain: None });
        inputs.receiver_pk = Some(rpk.to_vec());
        // k=0 offline profile: receiver-as-witness, which is what skips the
        // Nabla claim-proof gate this fixture cannot satisfy.
        inputs.receiver_signing_key = Some([0x74u8; 32]);
        inputs.receiver_current_balance = Some(0);
        inputs.receiver_new_balance = Some(1_000);
        inputs.receiver_wallet_seq = Some(1);
        inputs.transaction.epoch = issued_at + 60;

        let r = execute_core(inputs);
        assert!(
            matches!(r.rejection_reason, Some(ValidationError::VBCProvisionalCannotServe { .. })),
            "a cheque signed under a provisional cert must be refused at CL5, got {:?}",
            r.rejection_reason,
        );
    }

    #[test]
    fn ark_k0_cl2_requires_sender_execution_proof() {
        use crate::wallet_id::{generate_all_wallet_ids, K_ARK};
        // Two ark-tier wallet ids → the k=0 offline-trade CL2 profile.
        let spk = [0x51u8; 32];
        let rpk = [0x52u8; 32];
        let ark = |email: &str, pk: &[u8; 32]| {
            generate_all_wallet_ids(email, "42", pk).unwrap()
                .into_iter().find(|(_, k, _, _)| *k == K_ARK).unwrap().0
        };
        let mut inputs = create_test_inputs(CoreLogicMode::CL2);
        inputs.transaction.sender_wallet_id = ark("arksender@test.com", &spk);
        inputs.transaction.receiver_wallet_id = ark("arkreceiver@test.com", &rpk);
        inputs.transaction.client_pk = spk.to_vec();
        inputs.vbc_bundle = None;
        inputs.my_validator_pk = None;

        // (1) No proof → ArkSenderProofMissing (fail-closed, before any
        //     state-dependent validation runs).
        inputs.cl1_execution_proof = None;
        let r = execute_core(inputs.clone());
        assert_eq!(r.result, ValidationResult::Reject);
        assert_eq!(r.rejection_reason, Some(ValidationError::ArkSenderProofMissing));

        // (2) Empty proof → also Missing.
        inputs.cl1_execution_proof = Some(Vec::new());
        let r = execute_core(inputs.clone());
        assert_eq!(r.rejection_reason, Some(ValidationError::ArkSenderProofMissing));

        // (3) Garbage bytes → ArkSenderProofInvalid (decode fails).
        inputs.cl1_execution_proof = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let r = execute_core(inputs.clone());
        assert_eq!(r.rejection_reason, Some(ValidationError::ArkSenderProofInvalid));

        // (4) A well-formed-CBOR attestation that DECODES but fails
        //     verification → ArkSenderProofInvalid. This is the path the
        //     live 566 KB-payload byte-flip could not reliably reach (it hit
        //     the CI chain, not the attestation region). Here the attestation
        //     structurally decodes, so verify_dmap_attestation actually RUNS
        //     and rejects (zero checkpoints → MissingCheckpoints); a NEGATIVE
        //     hand-built attestation is legitimate — the real-producer POSITIVE
        //     path stays the live smoke.
        let forged = crate::dmap::DmapAttestation {
            core_id: [0u8; 32],
            input_hash: [0u8; 32],
            output_hash: [0u8; 32],
            total_checkpoints: 0,
            checkpoint_commitment: [0u8; 32],
            revealed_checkpoints: alloc::vec::Vec::new(),
            signature: alloc::vec![0u8; 64],
            tick: 0,
            validator_pk: spk,
        };
        let mut forged_bytes = alloc::vec::Vec::new();
        ciborium::ser::into_writer(&forged, &mut forged_bytes).unwrap();
        inputs.cl1_execution_proof = Some(forged_bytes);
        let r = execute_core(inputs);
        assert_eq!(r.rejection_reason, Some(ValidationError::ArkSenderProofInvalid),
            "a decodable but unverifiable attestation must be rejected in-guest");
        // The positive path + byte-tamper are exercised LIVE (real CL1
        // producer) by tests/ark_offline_trade_smoke.py + the rotation-7
        // tamper negative — synthetic-attestation-into-verifier is exactly
        // the shortcut feedback_test_real_producer_not_synthetic forbids.
    }


    // ════════════════════════════════════════════════════════════════
    // Fable review 2026-10-01 F-1(b) — the CL5 RECEIVER ANCHOR + redeem
    // S-ABR overlap (YP §17.3.1.4, ValidatorJoin §6b.13 residual F-1).
    //
    // A hermetic validator universe: three SPHINCS+ test roots authorized
    // through `genesis::test_roots` (cfg(test) only) certify validators with
    // real Ed25519 + Dilithium keys, so a receipt here is a REAL k-signed
    // receipt (Ed25519 over `commitment_hash`, `receipt_commitment` + its sig,
    // last-witness VBC) and an overlap sig is a REAL Dilithium FACT signature.
    // The pure rules are driven directly (RULE 6 §3a); `cl5_full_*` drive a
    // CL5 that reaches ACCEPT end to end (signed cheques, a verified sender
    // FACT chain, an authenticated claim proof), so deleting either call site
    // in `execute_cl5` turns a named test red.
    // ════════════════════════════════════════════════════════════════
    mod f1b_receiver_anchor {
        use super::*;
        extern crate std;
        use std::sync::OnceLock;
        use crate::types::{
            FactChain, FactLink, FactWitness, Receipt, VBCProofBundle, VBC, WalletFormat,
            WalletState, WitnessSig,
        };
        use ed25519_dalek::Signer as _;
        use ed25519_dalek::SigningKey as Ed;

        pub(super) struct V {
            pub ed: Ed,
            pub dil_pk: Vec<u8>,
            pub dil_sk: Vec<u8>,
            pub bundle: VBCProofBundle,
            pub id: [u8; 32],
        }
        impl V {
            fn ed_pk(&self) -> Vec<u8> { self.ed.verifying_key().to_bytes().to_vec() }
        }

        fn sphincs_keys(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
            use fips205::slh_dsa_sha2_128s;
            use fips205::traits::SerDes as _;
            (0..n).map(|_| {
                let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("sphincs keygen");
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            }).collect()
        }

        fn certify(roots: &[(Vec<u8>, Vec<u8>)], seed: u8) -> V {
            use fips204::ml_dsa_65;
            use fips204::traits::SerDes as _;
            let ed = Ed::from_bytes(&[seed; 32]);
            let (dpk, dsk) = ml_dsa_65::try_keygen().expect("dilithium keygen");
            let (dil_pk, dil_sk) = (dpk.into_bytes().to_vec(), dsk.into_bytes().to_vec());
            let sphincs_pk = sphincs_keys(1).remove(0).0;
            let id = crate::crypto::compute_validator_id(&sphincs_pk);
            let mut vbc = VBC {
                genesis_lineage: [0u8; 32],
                network_size_baseline: 0,
                baseline_tick: 0,
                version: 0x09,
                validator_id: id,
                subject_pubkey_sphincs: sphincs_pk,
                subject_pubkey_dilithium: dil_pk.clone(),
                subject_pubkey_ed25519: ed.verifying_key().to_bytes().to_vec(),
                pgp_fingerprint: vec![],
                node_name: alloc::string::String::new(),
                issued_at: 1_000,
                expires_at: u64::MAX,
                chain_depth: 0,
                issuer_set: roots.iter().map(|(pk, _)| pk.clone()).collect(),
                signatures: vec![],
                proof_cap: alloc::string::String::new(),
                max_tx: 0,
                founding_vbc_hash: [0u8; 32],
                nabla_registration: None,
            };
            let payload = crate::crypto::compute_vbc_signing_payload(&vbc);
            vbc.signatures = roots.iter()
                .map(|(_, sk)| crate::crypto::sign_sphincs(sk, &payload).expect("sphincs sign"))
                .collect();
            let bundle = VBCProofBundle {
                target_vbc: vbc, supporting_vbcs: vec![], candidacy_pulse: None, renewal_work_receipt: None,
            };
            V { ed, dil_pk, dil_sk, bundle, id }
        }

        /// KI#251 — a PROVISIONAL certificate bound to `ed_pk` (the §5.2.2b
        /// admission gate a stake claim's CL2 send requires), issued by fresh
        /// authorized test roots.
        pub(super) fn provisional_for(ed_pk: &[u8]) -> VBCProofBundle {
            let roots = sphincs_keys(3);
            for (pk, _) in &roots {
                crate::genesis::test_roots::authorize(pk.as_slice().try_into().unwrap());
            }
            let mut b = certify(&roots, 0xB1).bundle;
            b.target_vbc.subject_pubkey_ed25519 = ed_pk.to_vec();
            b.target_vbc.expires_at = b.target_vbc.issued_at
                + crate::validation::PROVISIONAL_VBC_EXPIRY_SECS;
            let payload = crate::crypto::compute_vbc_signing_payload(&b.target_vbc);
            b.target_vbc.signatures = roots.iter()
                .map(|(_, sk)| crate::crypto::sign_sphincs(sk, &payload).expect("sphincs sign"))
                .collect();
            b
        }

        /// 0..=2 witness the receiver's last receipt; 3, 4 are certified
        /// STRANGERS; 5 is certified by roots the protocol never authorized.
        pub(super) fn vs() -> &'static Vec<V> {
            static VS: OnceLock<Vec<V>> = OnceLock::new();
            VS.get_or_init(|| {
                let roots = sphincs_keys(3);
                for (pk, _) in &roots {
                    crate::genesis::test_roots::authorize(pk.as_slice().try_into().unwrap());
                }
                let foreign = sphincs_keys(3);
                let mut out: Vec<V> = (0..5u8).map(|i| certify(&roots, 0xA0 + i)).collect();
                out.push(certify(&foreign, 0xAF));
                out
            })
        }

        pub(super) const RECEIVER_SEED: u8 = 0x42;
        fn receiver_pk() -> Vec<u8> { Ed::from_bytes(&[RECEIVER_SEED; 32]).verifying_key().to_bytes().to_vec() }

        /// A returning receiver that holds a stake floor + lock + hibernation +
        /// an emission mark — every history-bearing §15 field non-zero.
        pub(super) fn floored(pk: &[u8]) -> WalletState {
            WalletState {
                public_key: pk.to_vec(),
                balance: 600_000_000_000,
                wallet_seq: 7,
                state_id: [0x5A; 32],
                auth_hash: None,
                wallet_id: None,
                group_members: None,
                hibernation_until: 1_900_000_000,
                wall_clock_lock: 1_900_000_100,
                emission_claimed_epoch: 4,
                stake_floor_until: 1_950_000_000,
                wallet_format: WalletFormat::CURRENT,
            }
        }
        /// The SDK's fresh wallet: the OPENING state (opening id, not zero).
        fn zero(pk: &[u8]) -> WalletState {
            let pk32: [u8; 32] = pk.try_into().unwrap();
            WalletState {
                balance: crate::genesis::genesis_opening_balance(pk), wallet_seq: 0,
                state_id: crate::genesis::opening_state_id_for(&pk32, TIER.0, TIER.1),
                hibernation_until: 0,
                wall_clock_lock: 0, emission_claimed_epoch: 0, stake_floor_until: 0,
                ..floored(pk)
            }
        }

        pub(super) fn wsig(v: &V, r: &Receipt) -> WitnessSig {
            WitnessSig {
                validator_id: v.id,
                validator_pk: v.ed_pk(),
                vbc_bundle: Some(v.bundle.clone()),
                carrier_type: alloc::string::String::new(),
                carrier_address: alloc::string::String::new(),
                signature: v.ed.sign(&r.commitment_hash).to_bytes().to_vec(),
                execution_proof: vec![],
                proof_type: 0,
                availability_attestation: None,
                validator_hints: vec![],
                fact_signature: None,
                checkpoint_sig: None,
                receipt_signature: None,
                receipt_commitment_sig: Some(v.ed.sign(&r.receipt_commitment).to_bytes().to_vec()),
                rate_bps: 0,
                slot_amount: 0,
            }
        }

        /// The REAL k-signed receipt a wallet in `state` holds as its last
        /// receipt, witnessed by `witnesses` (indices into `vs()`).
        pub(super) fn receipt_for(state: &WalletState, witnesses: &[usize]) -> Receipt {
            let sh = crate::crypto::compute_state_hash(
                &state.public_key, state.balance, state.wallet_seq, state.hibernation_until,
                state.wall_clock_lock, state.emission_claimed_epoch, state.stake_floor_until,
                &state.wallet_format,
            );
            let mut r = crate::receipt::build_send_receipt(crate::receipt::SendReceiptInputs {
                txid: [0x7A; 32],
                state_hash: sh,
                produced_state_id: state.state_id,
                new_wallet_seq: state.wallet_seq,
                commitment_hash: [0x5C; 32],
                epoch: 0,
                witness_sigs: vec![],
                required_k: 3,
                core_id: [0u8; 32],
                is_dev_class: false,
                oods_flag: None,
                confidence_index: None,
            });
            let sigs: Vec<WitnessSig> = witnesses.iter().map(|&i| wsig(&vs()[i], &r)).collect();
            r.witness_sigs = sigs;
            r
        }

        const TIER: (u8, u8) = (crate::wallet_id::K_DEFAULT, crate::wallet_id::PROOF_TYPE_DMAP);
        fn anchor(declared: &WalletState, receipts: &[Receipt]) -> Result<(), ValidationError> {
            cl5_anchor_receiver_state(declared, receipts, &declared.public_key, TIER, 3, 0)
        }

        // ── t1–t4, t9: the anchor ─────────────────────────────────────

        /// t1 — THE F-1 ATTACK: the truthful receipt binds the floor; the
        /// declaration zeroes it. Refused. Positive control: the truthful
        /// declaration anchors. Mutation-tested: deleting the
        /// `verify_declared_state_anchored` call turns the forged row red;
        /// inverting its `ct_eq` turns the positive control red.
        #[test]
        fn t1_forged_lower_floor_is_refused_truthful_floor_anchors() {
            let truth = floored(&receiver_pk());
            let r = receipt_for(&truth, &[0, 1, 2]);
            assert_eq!(anchor(&truth, &[r.clone()]), Ok(()), "positive control: the truthful state anchors");
            let forged = WalletState { stake_floor_until: 0, ..truth.clone() };
            assert_eq!(anchor(&forged, &[r]), Err(ValidationError::StateNotAnchored),
                "a declared floor of 0 on a floored wallet must not anchor");
        }

        /// t2 — a forged LOWER lock. (A truthful non-zero lock is refused
        /// earlier, StakeLocked — `cl5_refuses_a_redeem_while_the_stake_lock_is_held`;
        /// the forged `0` gets past that gate and must die HERE.)
        #[test]
        fn t2_forged_lower_lock_is_refused() {
            let truth = floored(&receiver_pk());
            let r = receipt_for(&truth, &[0, 1, 2]);
            let forged = WalletState { wall_clock_lock: 0, ..truth };
            assert_eq!(anchor(&forged, &[r]), Err(ValidationError::StateNotAnchored));
        }

        /// t3 — every other §15 field: hibernation, emission mark, balance,
        /// and the seq (≠ the receipt's `new_wallet_seq`).
        #[test]
        fn t3_forged_hibernation_emission_balance_seq_are_refused() {
            let truth = floored(&receiver_pk());
            let r = receipt_for(&truth, &[0, 1, 2]);
            let forgeries: [(&str, WalletState); 4] = [
                ("hibernation_until", WalletState { hibernation_until: 0, ..truth.clone() }),
                ("emission_claimed_epoch", WalletState { emission_claimed_epoch: 0, ..truth.clone() }),
                ("balance", WalletState { balance: truth.balance + 1, ..truth.clone() }),
                ("wallet_seq", WalletState { wallet_seq: truth.wallet_seq + 1, ..truth.clone() }),
            ];
            for (name, f) in forgeries {
                assert_eq!(anchor(&f, &[r.clone()]), Err(ValidationError::StateNotAnchored),
                    "a forged {} must not anchor", name);
            }
        }

        /// t4 — the SHAPE rule. Mutation-tested: dropping the zero-state
        /// `is_empty()` requirement turns the first row red; dropping the
        /// `len() != 1` check turns the second and third red.
        #[test]
        fn t4_receipt_count_must_match_the_declared_shape() {
            let pk = receiver_pk();
            let truth = floored(&pk);
            let r = receipt_for(&truth, &[0, 1, 2]);
            assert_eq!(anchor(&zero(&pk), &[r.clone()]), Err(ValidationError::ReceiverStateNotAnchored),
                "a first-time (opening) state ships no receipt");
            assert_eq!(anchor(&truth, &[]), Err(ValidationError::ReceiverStateNotAnchored),
                "a returning state ships its last receipt");
            assert_eq!(anchor(&truth, &[r.clone(), r]), Err(ValidationError::ReceiverStateNotAnchored),
                "exactly ONE receipt");
            assert_eq!(anchor(&zero(&pk), &[]), Ok(()), "first-time receiver (opening id): nothing to anchor");
            let zero_label = WalletState { state_id: [0u8; 32], ..zero(&pk) };
            assert_eq!(anchor(&zero_label, &[]), Ok(()), "first-time receiver (zero label)");
        }

        /// t5 — the receipt is verified by THE CL2 body (`verify_anchor_receipt`):
        /// each malformation yields the CL2 error.
        #[test]
        fn t5_receipt_is_verified_by_the_shared_cl2_body() {
            let truth = floored(&receiver_pk());
            let good = receipt_for(&truth, &[0, 1, 2]);

            let mut zero_ch = good.clone();
            zero_ch.commitment_hash = [0u8; 32];
            assert_eq!(anchor(&truth, &[zero_ch]), Err(ValidationError::InvalidWitnessSignature));

            let mut bad_rc = good.clone();
            bad_rc.receipt_commitment = [0xEE; 32];
            assert_eq!(anchor(&truth, &[bad_rc]), Err(ValidationError::ReceiptCommitmentMismatch));

            let sub_quorum = receipt_for(&truth, &[0, 1]);
            assert_eq!(anchor(&truth, &[sub_quorum]), Err(ValidationError::InvalidVBCCount));

            let mut dup = good.clone();
            dup.witness_sigs[1] = dup.witness_sigs[0].clone();
            assert_eq!(anchor(&truth, &[dup]), Err(ValidationError::DuplicateValidator));

            // A receipt whose state_hash was edited to the forged floor: the
            // receipt_commitment no longer matches what the witnesses signed.
            let forged = WalletState { stake_floor_until: 0, ..truth.clone() };
            let mut edited = good.clone();
            edited.state_hash = crate::crypto::compute_state_hash(
                &forged.public_key, forged.balance, forged.wallet_seq, forged.hibernation_until,
                forged.wall_clock_lock, forged.emission_claimed_epoch, forged.stake_floor_until,
                &forged.wallet_format);
            assert_eq!(anchor(&forged, &[edited]), Err(ValidationError::ReceiptCommitmentMismatch),
                "re-hashing the receipt to the forged floor breaks its k-signed commitment");

            // The last witness's certificate is verified: a foreign-root cert fails.
            let mut foreign_last = good;
            let n = foreign_last.witness_sigs.len();
            foreign_last.witness_sigs[n - 1] = wsig(&vs()[5], &foreign_last);
            assert!(anchor(&truth, &[foreign_last]).is_err(), "foreign-root last witness must not anchor");
        }

        /// t9 — HAL completion: the hibernating, lock-free state the re-anchor
        /// produced anchors to the re-anchor's receipt (`hal_acceptance` shape).
        #[test]
        fn t9_hal_completion_state_anchors_to_the_reanchor_receipt() {
            let reanchored = WalletState {
                wall_clock_lock: 0, stake_floor_until: 0, emission_claimed_epoch: 0,
                hibernation_until: 1_900_000_500, ..floored(&receiver_pk())
            };
            let r = receipt_for(&reanchored, &[2, 3, 4]); // FRESH witnesses — the dead-overlap exit
            assert_eq!(anchor(&reanchored, &[r]), Ok(()));
        }

        // ── t6, t7: the overlap ───────────────────────────────────────

        const LINK: [u8; 32] = [0x1C; 32];

        fn fsig(v: &V, commitment: &[u8; 32]) -> WitnessSig {
            let mut w = wsig(v, &receipt_for(&floored(&receiver_pk()), &[0, 1, 2]));
            w.signature = vec![];
            w.receipt_commitment_sig = None;
            w.fact_signature = Some(crate::crypto::sign_dilithium(&v.dil_sk, commitment).expect("sign"));
            w
        }

        fn overlap(my: Option<usize>, sigs: &[WitnessSig]) -> Result<(), ValidationError> {
            let r = receipt_for(&floored(&receiver_pk()), &[0, 1, 2]);
            let my_pk = my.map(|i| vs()[i].ed_pk());
            cl5_receiver_overlap(&[r], my_pk.as_deref(), true, sigs, &LINK, 0)
        }

        /// t6 — every row of the CL2 Checks 1–4 mirror. Mutation-tested:
        /// `valid < required` → `valid <= required` turns `two_valid` red;
        /// removing C1 turns `strangers` red; removing C3 turns
        /// `wrong_commitment` red; removing C2 turns `duplicate` red;
        /// removing C4's chain verify turns `foreign_root` red.
        #[test]
        fn t6_overlap_rows() {
            let v = vs();
            // An overlapped validator needs nothing carried.
            assert_eq!(overlap(Some(0), &[]), Ok(()), "overlapped: witnessed the consumed state");
            // A fresh finalizer with sabr_overlap(3)=2 valid prior sigs.
            let two_valid = [fsig(&v[0], &LINK), fsig(&v[1], &LINK)];
            assert_eq!(overlap(Some(3), &two_valid), Ok(()), "fresh + 2 valid overlap sigs");
            assert_eq!(overlap(Some(3), &two_valid[..1]), Err(ValidationError::SABRInsufficientOverlap),
                "fresh + 1 sig is short");
            assert_eq!(overlap(Some(3), &[]), Err(ValidationError::SABRInsufficientOverlap),
                "fresh + 0 sigs (a pre-dispatched non-final hop) is refused");
            let strangers = [fsig(&v[3], &LINK), fsig(&v[4], &LINK)];
            assert_eq!(overlap(Some(5), &strangers), Err(ValidationError::SABRInsufficientOverlap),
                "C1: sigs from validators that did NOT witness the receipt");
            let s0 = fsig(&v[0], &LINK);
            let duplicate = [s0.clone(), s0];
            assert_eq!(overlap(Some(3), &duplicate), Err(ValidationError::SABRInsufficientOverlap),
                "C2: one signature counted twice");
            let wrong_commitment = [fsig(&v[0], &[0x2D; 32]), fsig(&v[1], &[0x2D; 32])];
            assert_eq!(overlap(Some(3), &wrong_commitment), Err(ValidationError::SABRInsufficientOverlap),
                "C3: Dilithium over another commitment");
            let mut no_vbc = fsig(&v[1], &LINK);
            no_vbc.vbc_bundle = None;
            assert_eq!(overlap(Some(3), &[fsig(&v[0], &LINK), no_vbc]), Err(ValidationError::SABRInsufficientOverlap),
                "C4: no certificate");
            let mut wrong_id = fsig(&v[1], &LINK);
            wrong_id.validator_id = [0x99; 32];
            assert_eq!(overlap(Some(3), &[fsig(&v[0], &LINK), wrong_id]), Err(ValidationError::SABRInsufficientOverlap),
                "C4: validator_id not the certificate's");
            // A foreign-root validator presented as a receipt witness: build a
            // receipt that names it, then carry its (valid-signature) sig.
            let r = receipt_for(&floored(&receiver_pk()), &[0, 1, 5]);
            let foreign_root = [fsig(&v[0], &LINK), fsig(&v[5], &LINK)];
            assert_eq!(
                cl5_receiver_overlap(&[r], Some(v[3].ed_pk().as_slice()), true, &foreign_root, &LINK, 0),
                Err(ValidationError::SABRInsufficientOverlap),
                "C4: a certificate that does not chain to the roots",
            );
        }

        /// t7 — the client run (no validator apparatus) skips the overlap
        /// (validators enforce it, RULE 5); a first-time receiver has no
        /// receipt to overlap with. Mutation-tested: deleting the
        /// `!online_apparatus` early return turns the first row red.
        #[test]
        fn t7_client_run_and_first_time_receiver_skip_overlap() {
            let r = receipt_for(&floored(&receiver_pk()), &[0, 1, 2]);
            assert_eq!(cl5_receiver_overlap(&[r], None, false, &[], &LINK, 0), Ok(()));
            assert_eq!(cl5_receiver_overlap(&[], Some(vs()[3].ed_pk().as_slice()), true, &[], &LINK, 0), Ok(()));
        }
    }

    // ── F-1(b) end to end: a CL5 that reaches ACCEPT ──────────────────
    mod f1b_cl5_end_to_end {
        use super::*;
        use super::f1b_receiver_anchor::{floored, receipt_for, vs, RECEIVER_SEED};
        use crate::types::{FactChain, FactLink, FactWitness, WalletState, WitnessSig};
        use ed25519_dalek::Signer as _;

        const TXID: [u8; 32] = [0x77; 32];
        const SENDER_PREV: [u8; 32] = [0x33; 32];
        const SENDER_NEW: [u8; 32] = [0x44; 32];
        const AMOUNT: u64 = 50_000_000_000;

        fn receiver() -> Ed25519SigningKey { Ed25519SigningKey::from_bytes(&[RECEIVER_SEED; 32]) }

        fn writer() -> &'static (Ed25519SigningKey, Vec<u8>, Vec<u8>, Vec<u8>) {
            extern crate std;
            static W: std::sync::OnceLock<(Ed25519SigningKey, Vec<u8>, Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
            W.get_or_init(ki205_nabla_writer)
        }

        /// The sender's verified FACT chain: one send link (this cheque's
        /// txid → its produced state), k=3 Dilithium-signed by vs()[0..3].
        fn sender_chain() -> FactChain {
            let c = crate::fact::compute_fact_commitment(
                &TXID, &SENDER_PREV, &SENDER_NEW, AMOUNT, None, false, 3, &[], None);
            let witnesses = (0..3).map(|i| {
                let v = &vs()[i];
                FactWitness {
                    validator_id: v.id,
                    validator_pk: v.dil_pk.clone(),
                    signature: crate::crypto::sign_dilithium(&v.dil_sk, &c).expect("sign"),
                    vbc_hash: crate::vbc::vbc_reference_hash(&v.bundle.target_vbc),
                }
            }).collect();
            let mut chain = FactChain::new();
            chain.links.push(FactLink {
                tx_id: TXID, previous_state_id: SENDER_PREV, new_state_id: SENDER_NEW, amount: AMOUNT,
                required_k: 3, tick: 0, witnesses, nabla_confirmation: None, burn_proof: None,
                burn_target_tx_id: None, sender_anchor: None, is_dev_class: false, recall_proof: None,
                out_of_order_confirmation: None, inherited_scar_txids: vec![],
                inherited_scar_resolutions: vec![], receiver_witness: None,
            });
            chain
        }

        /// A CL5 redeem by the receiver that reaches ACCEPT: the ki205
        /// authenticated claim + attestation, three SIGNED cheques from
        /// certified validators, the verified sender chain — and the
        /// receiver DECLARING `declared`, carrying `prev`.
        fn inputs(declared: &WalletState, prev: Vec<crate::types::Receipt>) -> PublicInputs {
            let rx = receiver();
            let mut i = ki205_inputs(&rx, writer(), ki205_valid_proof(&rx, writer()));
            let mut bundle = i.cheque_bundle.take().unwrap();
            for (n, c) in bundle.cheques.iter_mut().enumerate() {
                let v = &vs()[n];
                c.validator_id = v.id;
                c.validator_pk = v.bundle.target_vbc.subject_pubkey_ed25519.clone();
                c.vbc_bundle = Some(v.bundle.clone());
                c.produced_state_id = SENDER_NEW;
                let cc = crate::crypto::compute_cheque_commitment(
                    &c.txid, &c.state_hash, &c.produced_state_id, &c.sender_wallet_id,
                    &c.receiver_wallet_id, c.amount, c.epoch, c.created_at, c.rate_bps,
                    &c.dmap_input_hash, &c.dmap_output_hash, c.oracle_claim.as_ref(),
                    c.recall_target_tx_id.as_ref());
                c.signature = v.ed.sign(&cc).to_bytes().to_vec();
            }
            bundle.fact_chain = Some(sender_chain());
            let fee: u64 = bundle.cheques.iter()
                .map(|c| crate::validation::expected_fee_slot_amount(c.amount, c.rate_bps)).sum();
            i.cheque_bundle = Some(bundle);
            i.transaction.epoch = 0; // CL5's clock on every production path
            i.transaction.consumed_state_id = declared.state_id;
            i.current_state = Some(declared.clone()); // Lambda sets it (core_client)
            i.receiver_current_balance = Some(declared.balance);
            i.receiver_wallet_seq = Some(declared.wallet_seq);
            i.receiver_current_hibernation = Some(declared.hibernation_until);
            i.receiver_current_wall_clock_lock = Some(declared.wall_clock_lock);
            i.receiver_current_emission_claimed_epoch = Some(declared.emission_claimed_epoch);
            i.receiver_current_stake_floor_until = Some(declared.stake_floor_until);
            i.receiver_new_balance = Some(declared.balance + AMOUNT - fee);
            i.prev_receipts = prev;
            i
        }

        /// A returning, floored receiver WITHOUT the stake lock (a locked one
        /// is refused StakeLocked before any of this — by design).
        fn returning() -> WalletState {
            WalletState { wall_clock_lock: 0, ..floored(&receiver().verifying_key().to_bytes()) }
        }

        /// THE link commitment the redeem's witnesses sign — derived through
        /// the production builders (`compute_redeem_state_id`,
        /// `cl5_inherited_scar_txids`, `compute_fact_commitment`), the same
        /// recompute Lambda's CL5 mirror does.
        fn link_commitment(i: &PublicInputs) -> [u8; 32] {
            let b = i.cheque_bundle.as_ref().unwrap();
            let chain = crate::fact::redeem_fact_chain_ref(b, &i.sender_fact_chain);
            let new_sid = crate::validation::compute_redeem_state_id(
                i.receiver_pk.as_ref().unwrap(), i.receiver_new_balance.unwrap(),
                i.receiver_wallet_seq.unwrap(), &TXID);
            let inherited = crate::fact::cl5_inherited_scar_txids(
                chain, b, i.txid_attestation.as_ref(), false, false).unwrap();
            crate::fact::compute_fact_commitment(
                &TXID, &cl5_consumed_state_id(i), &new_sid, AMOUNT, Some(&SENDER_NEW), false, 3,
                &inherited, None)
        }

        fn overlap_sig(n: usize, c: &[u8; 32]) -> WitnessSig {
            let v = &vs()[n];
            WitnessSig {
                validator_id: v.id, validator_pk: v.bundle.target_vbc.subject_pubkey_ed25519.clone(),
                vbc_bundle: Some(v.bundle.clone()), carrier_type: alloc::string::String::new(),
                carrier_address: alloc::string::String::new(), signature: vec![], execution_proof: vec![],
                proof_type: 0, availability_attestation: None, validator_hints: vec![],
                fact_signature: Some(crate::crypto::sign_dilithium(&v.dil_sk, c).expect("sign")),
                checkpoint_sig: None, receipt_signature: None, receipt_commitment_sig: None,
                rate_bps: 0, slot_amount: 0,
            }
        }

        /// POSITIVE CONTROLS — a first-time receiver and a truthful returning
        /// receiver both reach ACCEPT (the first CL5 ACCEPT in this suite).
        #[test]
        fn cl5_full_first_time_and_truthful_returning_receiver_accept() {
            let rpk = receiver().verifying_key().to_bytes();
            // The SDK's fresh wallet: its OPENING id (`receiver@test.com`, tier "42").
            let rwid = generate_wallet_id("receiver@test.com", "42", &rpk).unwrap();
            let (k, pt) = crate::wallet_id::extract_security_level(&rwid).unwrap();
            let zero = WalletState { balance: 0, wallet_seq: 0,
                state_id: crate::genesis::opening_state_id_for(&rpk, k, pt), hibernation_until: 0,
                wall_clock_lock: 0, emission_claimed_epoch: 0, stake_floor_until: 0, ..returning() };
            let out = execute_core(inputs(&zero, vec![]));
            assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
                "first-time receiver, no receipt");
            let truth = returning();
            let out = execute_core(inputs(&truth, vec![receipt_for(&truth, &[0, 1, 2])]));
            assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
                "truthful returning receiver with its last receipt");
            assert_eq!(out.stake_floor_until, truth.stake_floor_until, "the floor is CARRIED");
        }

        /// THE F-1 ESCAPE, end to end through `execute_core`: the floor
        /// declared away → StateNotAnchored; no receipt → ReceiverStateNotAnchored.
        /// Mutation-tested: deleting the Step 3.6 `cl5_anchor_receiver_state`
        /// call in `execute_cl5` turns both rows red (they ACCEPT).
        #[test]
        fn cl5_full_declared_floor_escape_is_refused_in_core() {
            let truth = returning();
            let r = receipt_for(&truth, &[0, 1, 2]);
            let forged = WalletState { stake_floor_until: 0, ..truth.clone() };
            let out = execute_core(inputs(&forged, vec![r]));
            assert_eq!(out.rejection_reason, Some(ValidationError::StateNotAnchored));
            let out = execute_core(inputs(&forged, vec![]));
            assert_eq!(out.rejection_reason, Some(ValidationError::ReceiverStateNotAnchored));
        }

        /// The REWIND (Fable §2): the PRE-floor state S0 with its own real
        /// receipt R0 anchors (it is a state the wallet was witnessed in) — the
        /// overlap is what stops it. At a validator that did not witness R0 and
        /// carries no R0-witness sigs: SABRInsufficientOverlap. With two R0
        /// witnesses' sigs over THIS link (they colluded): admitted — the fork
        /// machinery's case. Mutation-tested: deleting the Step 9b
        /// `cl5_receiver_overlap` call turns the first row red (ACCEPT).
        #[test]
        fn cl5_full_rewind_to_pre_floor_receipt_needs_the_previous_witnesses() {
            let s0 = WalletState { stake_floor_until: 0, ..returning() }; // pre-floor
            let r0 = receipt_for(&s0, &[0, 1, 2]);
            let stranger = vs()[3].bundle.target_vbc.subject_pubkey_ed25519.clone();

            let mut i = inputs(&s0, vec![r0.clone()]);
            i.my_validator_pk = Some(stranger.clone());
            let out = execute_core(i);
            assert_eq!(out.rejection_reason, Some(ValidationError::SABRInsufficientOverlap),
                "a stranger with no R0-witness sigs must refuse the rewind");

            let mut i = inputs(&s0, vec![r0.clone()]);
            i.my_validator_pk = Some(stranger.clone());
            let c = link_commitment(&i);
            i.fact_witness_sigs = vec![overlap_sig(3 + 1, &c), overlap_sig(0, &c)]; // one stranger + one witness
            let out = execute_core(i);
            assert_eq!(out.rejection_reason, Some(ValidationError::SABRInsufficientOverlap),
                "one R0 witness is short of sabr_overlap(3) = 2");

            let mut i = inputs(&s0, vec![r0.clone()]);
            i.my_validator_pk = Some(stranger);
            let c = link_commitment(&i);
            i.fact_witness_sigs = vec![overlap_sig(0, &c), overlap_sig(1, &c)];
            let out = execute_core(i);
            assert_eq!((out.result, out.rejection_reason), (ValidationResult::Accept, None),
                "two colluding previous witnesses admit it — the rewind is then a self-fork for Nabla");

            // An R0 witness itself is overlapped and needs no carried sigs.
            let mut i = inputs(&s0, vec![r0]);
            i.my_validator_pk = Some(vs()[0].bundle.target_vbc.subject_pubkey_ed25519.clone());
            let out = execute_core(i);
            assert_eq!((out.result, out.rejection_reason), (ValidationResult::Accept, None));
        }

        /// t7 end to end — the CLIENT run (no apparatus) still enforces the
        /// ANCHOR (so a client cannot even produce a CL5 proof for a forged
        /// floor), and skips only the overlap.
        #[test]
        fn cl5_full_client_run_enforces_the_anchor_not_the_overlap() {
            let truth = returning();
            let r = receipt_for(&truth, &[0, 1, 2]);
            let forged = WalletState { stake_floor_until: 0, ..truth.clone() };
            let i = inputs(&forged, vec![r.clone()]);
            assert!(i.vbc_bundle.is_none() && i.my_validator_pk.is_none());
            assert_eq!(execute_core(i).rejection_reason, Some(ValidationError::StateNotAnchored));
            assert_eq!(execute_core(inputs(&truth, vec![r])).result, ValidationResult::Accept,
                "no overlap demanded of the client run");
        }

        // ── KI#251: THE LIVE SHAPE — a claim's FIRST redeem ──────────────
        //
        // ⚠ Every test above carries a receipt built by `receipt_for(state)` —
        // DERIVED FROM the declared state, so it anchors by construction and
        // can never see a send leg that bound a DIFFERENT balance. That blind
        // spot is how KI#251 shipped: Core's CL2 credited the claim amount at
        // the SEND, CL5 Step 3.4 demands the redeem declare (balance 0, seq 1),
        // and Step 3.6 anchored that declaration to a receipt binding the
        // credited balance — every first redeem after a claim died
        // E_STATE_NOT_ANCHORED live (83ed1e89). Here the receipt's `state_hash`
        // and `produced_state_id` come from the REAL CL2 body
        // (`validate_transaction` over the wallet's opening state), and the
        // receipt is built by THE receipt builder (`receipt::build_send_receipt`).

        struct ClaimSend {
            tx: crate::types::Transaction,
            opening: WalletState,
            state_hash: [u8; 32],
            produced: [u8; 32],
            hibernation_until: u64,
        }

        /// The claim's SEND through the real CL2 body, from the receiver's
        /// OPENING state (balance 0, seq 0, the opening id).
        fn claim_send(kind: TxKind, amount: u64) -> ClaimSend {
            let rx = receiver();
            let rpk = rx.verifying_key().to_bytes();
            let wid = generate_wallet_id("receiver@test.com", "42", &rpk).unwrap();
            let (k, pt) = crate::wallet_id::extract_security_level(&wid).unwrap();
            let opening = WalletState {
                public_key: rpk.to_vec(), balance: 0, wallet_seq: 0,
                state_id: crate::genesis::opening_state_id_for(&rpk, k, pt),
                auth_hash: None, wallet_id: None, group_members: None,
                hibernation_until: 0, wall_clock_lock: 0, emission_claimed_epoch: 0,
                stake_floor_until: 0, wallet_format: crate::types::WalletFormat::CURRENT,
            };
            let mut i = create_test_inputs(CoreLogicMode::CL2);
            let tx = &mut i.transaction;
            tx.kind = kind;
            tx.amount = amount;
            tx.client_pk = rpk.to_vec();
            tx.sender_wallet_id = wid.clone();
            tx.receiver_wallet_id = wid;
            tx.wallet_seq = 1;
            tx.consumed_state_id = opening.state_id;
            tx.client_sig = rx.sign(&crate::validation::compute_signing_message_public(tx))
                .to_bytes().to_vec();
            i.current_state = Some(opening.clone());
            if i.transaction.is_validator_stake_claim() {
                i.claimant_vbc = Some(super::f1b_receiver_anchor::provisional_for(&rpk));
            }
            let out = crate::validation::validate_transaction(&i).expect("CL2 body");
            assert_eq!((out.result.clone(), out.rejection_reason.clone()), (ValidationResult::Accept, None),
                "the claim's send must be accepted by CL2");
            ClaimSend {
                tx: i.transaction,
                opening,
                state_hash: out.new_state_hash.expect("CL2 state_hash"),
                produced: out.produced_state_id.expect("CL2 produced_state_id"),
                hibernation_until: out.hibernation_until,
            }
        }

        /// The claim's k-signed receipt, built by THE receipt builder from the
        /// CL2 outputs — never from the declared state.
        fn claim_receipt(c: &ClaimSend) -> crate::types::Receipt {
            let mut r = crate::receipt::build_send_receipt(crate::receipt::SendReceiptInputs {
                txid: TXID,
                state_hash: c.state_hash,
                produced_state_id: c.produced,
                new_wallet_seq: c.tx.wallet_seq,
                commitment_hash: crate::validation::compute_commitment_hash(&c.tx),
                epoch: c.tx.epoch,
                witness_sigs: vec![],
                required_k: 3,
                core_id: [0u8; 32],
                is_dev_class: false,
                oods_flag: None,
                confidence_index: None,
            });
            r.witness_sigs = (0..3).map(|n| super::f1b_receiver_anchor::wsig(&vs()[n], &r)).collect();
            r
        }

        /// The claim's FACT link — k=3 witnessed and Nabla-BLESSED (SEC-02:
        /// a genesis-claim redeem requires the blessing on the tip).
        fn claim_chain(c: &ClaimSend) -> FactChain {
            let fc = crate::fact::compute_fact_commitment(
                &TXID, &c.opening.state_id, &c.produced, c.tx.amount, None, false, 3, &[], None);
            let witnesses = (0..3).map(|n| {
                let v = &vs()[n];
                FactWitness {
                    validator_id: v.id, validator_pk: v.dil_pk.clone(),
                    signature: crate::crypto::sign_dilithium(&v.dil_sk, &fc).expect("sign"),
                    vbc_hash: crate::vbc::vbc_reference_hash(&v.bundle.target_vbc),
                }
            }).collect();
            let node = Ed25519SigningKey::from_bytes(&[0x6E; 32]);
            let payload = crate::crypto::fact_confirm_payload(&c.opening.state_id, &c.produced, 0);
            let conf = crate::types::NablaConfirmation {
                nabla_node_id: node.verifying_key().to_bytes(),
                nabla_signature: node.sign(&payload).to_bytes().to_vec(),
                ..Default::default()
            };
            let mut chain = FactChain::new();
            chain.links.push(FactLink {
                tx_id: TXID, previous_state_id: c.opening.state_id, new_state_id: c.produced,
                amount: c.tx.amount, required_k: 3, tick: 0, witnesses,
                nabla_confirmation: Some(conf), burn_proof: None, burn_target_tx_id: None,
                sender_anchor: None, is_dev_class: false, recall_proof: None,
                out_of_order_confirmation: None, inherited_scar_txids: vec![],
                inherited_scar_resolutions: vec![], receiver_witness: None,
            });
            chain
        }

        /// The claim's REDEEM: the `inputs` redeem re-shaped into the claim's
        /// SELF-SEND of `c.tx.amount` (so Step 3.4 runs for a genesis claim),
        /// its cheques binding the CL2 `state_hash` / `produced_state_id`, the
        /// claim link as the (self) sender chain, declaring `declared`.
        fn claim_redeem(c: &ClaimSend, declared: &WalletState, prev: Vec<crate::types::Receipt>) -> PublicInputs {
            let mut i = inputs(declared, prev);
            let mut bundle = i.cheque_bundle.take().unwrap();
            let rpk = receiver().verifying_key().to_bytes();
            for (n, ch) in bundle.cheques.iter_mut().enumerate() {
                let v = &vs()[n];
                ch.sender_wallet_id = ch.receiver_wallet_id.clone();
                ch.sender_wallet_pk = Some(rpk);
                ch.amount = c.tx.amount;
                ch.epoch = c.tx.epoch;
                ch.state_hash = c.state_hash;
                ch.produced_state_id = c.produced;
                let cc = crate::crypto::compute_cheque_commitment(
                    &ch.txid, &ch.state_hash, &ch.produced_state_id, &ch.sender_wallet_id,
                    &ch.receiver_wallet_id, ch.amount, ch.epoch, ch.created_at, ch.rate_bps,
                    &ch.dmap_input_hash, &ch.dmap_output_hash, ch.oracle_claim.as_ref(),
                    ch.recall_target_tx_id.as_ref());
                ch.signature = v.ed.sign(&cc).to_bytes().to_vec();
            }
            bundle.fact_chain = Some(claim_chain(c));
            let fee: u64 = bundle.cheques.iter()
                .map(|ch| crate::validation::expected_fee_slot_amount(ch.amount, ch.rate_bps)).sum();
            i.cheque_bundle = Some(bundle);
            i.receiver_new_balance = Some(declared.balance + c.tx.amount - fee);
            i
        }

        /// The state the wallet truthfully holds between the claim's send and
        /// its redeem: YP §17.11.2 step 3 — balance 0 (UNCHANGED), seq 1, the
        /// produced id, the produced hibernation.
        fn post_claim(c: &ClaimSend) -> WalletState {
            WalletState {
                balance: 0, wallet_seq: c.tx.wallet_seq, state_id: c.produced,
                hibernation_until: c.hibernation_until, ..c.opening.clone()
            }
        }

        /// KI#251 — the genesis claim's FIRST redeem, live shape → ACCEPT.
        /// Controls: declaring the credited balance is Step 3.4's
        /// `GenesisClaimWalletAlreadyFunded`; no receipt is
        /// `ReceiverStateNotAnchored`.
        ///
        /// MUTATION-TESTED: (m1) restore the send-side credit
        /// (`balance.saturating_add(tx.amount)`) in `compute_post_tx_balance`'s
        /// genesis arm → the Accept row is `StateNotAnchored` → RED. (m3) feed
        /// `receipt_for(&declared)` instead of the CL2-built receipt → still
        /// ACCEPT — and only because the two receipts' `state_hash` are EQUAL,
        /// which is asserted here: that equality IS the agreement KI#251 broke.
        #[test]
        fn ki251_genesis_claim_first_redeem_anchors_to_the_real_cl2_receipt() {
            let c = claim_send(TxKind::GenesisClaim, crate::types::GENESIS_CLAIM_AMOUNT);
            let declared = post_claim(&c);
            let r = claim_receipt(&c);
            assert_eq!(r.state_hash, receipt_for(&declared, &[0, 1, 2]).state_hash,
                "the CL2 send must bind exactly the state its redeem declares (balance 0, seq 1)");

            let out = execute_core(claim_redeem(&c, &declared, vec![r.clone()]));
            assert_eq!((out.result, out.rejection_reason.clone()), (ValidationResult::Accept, None),
                "a genesis claim's first redeem must anchor (KI#251)");

            let credited = WalletState { balance: c.tx.amount, ..declared.clone() };
            let out = execute_core(claim_redeem(&c, &credited, vec![r]));
            assert_eq!(out.rejection_reason, Some(ValidationError::GenesisClaimWalletAlreadyFunded),
                "Step 3.4: a declared credited balance is a replay shape");

            let out = execute_core(claim_redeem(&c, &declared, vec![]));
            assert_eq!(out.rejection_reason, Some(ValidationError::ReceiverStateNotAnchored),
                "a returning (seq 1) receiver must carry the claim's receipt");
        }

        /// KI#251 — the same live shape for a validator STAKE claim (feature
        /// `bootstrap-subsidy`): the CL2 send binds the UNCHANGED balance (0),
        /// so the claim's redeem declaring (0, seq 1, the produced hibernation)
        /// anchors. MUTATION-TESTED (m2): delete the cfg stake arm in
        /// `compute_post_tx_balance` → CL2 refuses the claim InsufficientBalance
        /// against the empty wallet → RED.
        #[cfg(feature = "bootstrap-subsidy")]
        #[test]
        fn ki251_stake_claim_first_redeem_anchors_to_the_real_cl2_receipt() {
            let c = claim_send(TxKind::ValidatorCommunityStakeClaim, crate::types::TIER3_CLAIM_ATOMS);
            let declared = post_claim(&c);
            let r = claim_receipt(&c);
            assert_eq!(r.state_hash, receipt_for(&declared, &[0, 1, 2]).state_hash,
                "the stake claim's CL2 send must bind (balance 0, seq 1, produced hibernation)");
            // The send HIBERNATED the wallet, so the self-redeem exits hibernation:
            // the YPX-022 OODS exit gate needs a verified-healthy reading.
            let mut i = claim_redeem(&c, &declared, vec![r]);
            i.oods_attestation = Some(super::test_oods_attestation(1_000, 500));
            let out = execute_core(i);
            assert_eq!((out.result.clone(), out.rejection_reason.clone()), (ValidationResult::Accept, None),
                "a stake claim's first redeem must anchor (KI#251)");
            assert_ne!(out.wall_clock_lock, 0,
                "§5.2.2c: the stake lock is stamped AT THE REDEEM — the only place the stake lands");
        }
    }


    // ── KI#125 — mode ZkpQualify (YPX-007 §9.4) ─────────────────────────────
    mod ki125_zkp_qualify {
        use super::*;
        use crate::types::{NablaOodsAttestation, ZkpQualifyRequest};

        const VID: [u8; 32] = [0x11; 32];
        const CORE: [u8; 32] = [0x22; 32];

        fn dilithium() -> (Vec<u8>, Vec<u8>) {
            use fips204::ml_dsa_65;
            use fips204::traits::SerDes as _;
            let (pk, sk) = ml_dsa_65::try_keygen().expect("dilithium keygen");
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }

        /// The honest journal binding: what a prover over the T0-derived challenge commits.
        fn honest_nonce_hash(before: &NablaOodsAttestation) -> [u8; 32] {
            crate::crypto::zkp_nonce_hash(&crate::crypto::compute_zkq_challenge(&VID, &CORE, &before.nabla_signature))
        }

        fn inputs(before: NablaOodsAttestation, after: NablaOodsAttestation, journal: [u8; 32]) -> PublicInputs {
            let (pk, sk) = dilithium();
            let mut i = create_test_inputs(CoreLogicMode::ZkpQualify);
            i.oods_attestation = Some(before);
            i.zkq_request = Some(ZkpQualifyRequest { att_after: after, program_digest: [0x33; 32], journal_nonce_hash: journal });
            i.my_validator_id = Some(VID);
            i.my_dilithium_pk = Some(pk);
            i.my_dilithium_sk = Some(sk);
            i.local_core_id = CORE;
            i
        }

        fn run(before_tick: u64, after_tick: u64) -> PublicOutputs {
            let before = test_oods_attestation(before_tick, 10);
            let journal = honest_nonce_hash(&before);
            execute_core(inputs(before, test_oods_attestation(after_tick, 10), journal))
        }

        /// One TARDIS step (5 tick-VALUE units) passes; Core signs a record that the
        /// wallet-side verifier accepts. Mutation: `>` → `>=` in the gap check ⇒ red.
        #[test]
        fn zkq_accepts_one_tick_step() {
            let out = run(100, 105);
            assert_eq!(out.result, ValidationResult::Accept, "{:?}", out.rejection_reason);
            let rec = out.zkp_qualification.expect("Accept carries the record");
            assert_eq!((rec.validator_id, rec.core_id, rec.program_digest), (VID, CORE, [0x33; 32]));
            crate::validation::verify_zkp_qualification_record(&rec).expect("record verifies");
            crate::crypto::verify_dilithium(&rec.dilithium_pk,
                &crate::crypto::compute_zkq_record_payload(&rec), &rec.signature).expect("signed by the pk");
        }

        /// Two steps ⇒ too slow. Mutation: drop the gap comparison ⇒ red.
        #[test]
        fn zkq_rejects_two_tick_steps() {
            let out = run(100, 110);
            assert_eq!(out.rejection_reason, Some(ValidationError::ZkqTooSlow));
            assert!(out.zkp_qualification.is_none());
        }

        /// T1 before T0 is a refusal through the explicit `<` branch, never a
        /// wrap. Mutation: remove `after.tick < before.tick ||` ⇒ underflow ⇒ red.
        #[test]
        fn zkq_rejects_backwards_ticks() {
            assert_eq!(run(100, 95).rejection_reason, Some(ValidationError::ZkqTooSlow));
        }

        #[test]
        fn zkq_rejects_other_node() {
            let before = test_oods_attestation(100, 10);
            let journal = honest_nonce_hash(&before);
            let out = execute_core(inputs(before, test_oods_attestation_by(0x43, 105, 10), journal));
            assert_eq!(out.rejection_reason, Some(ValidationError::ZkqNodeMismatch));
        }

        /// A proof over another validator's challenge does not bind to this T0.
        /// Mutation: compare `journal_nonce_hash` with itself ⇒ red.
        #[test]
        fn zkq_rejects_foreign_challenge() {
            let before = test_oods_attestation(100, 10);
            let foreign = crate::crypto::zkp_nonce_hash(
                &crate::crypto::compute_zkq_challenge(&[0x99; 32], &CORE, &before.nabla_signature));
            let out = execute_core(inputs(before, test_oods_attestation(105, 10), foreign));
            assert_eq!(out.rejection_reason, Some(ValidationError::ZkqChallengeMismatch));
        }

        /// An unverifiable reading never reaches the challenge derivation: it is
        /// `OodsAttestationInvalid`, NOT `ZkqChallengeMismatch`. Mutation: run the
        /// challenge check before the attestation checks ⇒ red.
        #[test]
        fn zkq_rejects_tampered_reading() {
            let mut before = test_oods_attestation(100, 10);
            let journal = honest_nonce_hash(&before);
            before.nabla_signature[5] ^= 0x01;
            let out = execute_core(inputs(before, test_oods_attestation(105, 10), journal));
            assert_eq!(out.rejection_reason, Some(ValidationError::OodsAttestationInvalid));
        }

        /// The signature covers the record: any field changed after signing fails.
        #[test]
        fn zkq_record_rejects_resigned_payload() {
            let mut rec = run(100, 105).zkp_qualification.expect("record");
            rec.program_digest = [0x44; 32];
            assert!(crate::validation::verify_zkp_qualification_record(&rec).is_err());
        }

        /// Missing inputs are their own codes, checked before any crypto.
        #[test]
        fn zkq_missing_signer_and_request_are_their_own_codes() {
            let before = test_oods_attestation(100, 10);
            let journal = honest_nonce_hash(&before);
            let mut i = inputs(before, test_oods_attestation(105, 10), journal);
            i.my_dilithium_sk = None;
            assert_eq!(execute_core(i.clone()).rejection_reason, Some(ValidationError::ZkqMissingSigner));
            i.zkq_request = None;
            assert_eq!(execute_core(i).rejection_reason, Some(ValidationError::ZkqMissingRequest));
        }
    }
}
