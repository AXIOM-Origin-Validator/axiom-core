//! `From<ValidationError> for ErrorResponse` — converts Core's internal
//! `ValidationError` enum into the structured wire format defined in
//! `AXIOM_YellowPaper_Errors.md`.
//!
//! # Phase 2b.1
//!
//! This module provides CONVERSION functions. It does NOT yet change
//! any existing Core API signature. Callers that currently return
//! `Result<_, ValidationError>` keep doing so; they can convert to
//! `ErrorResponse` at the layer boundary using `From` or `into()`.
//!
//! Converting the primary Core API to return `ErrorResponse` directly
//! is Phase 2b.3 and requires an ELF rebuild + CoreID change.
//!
//! # Coverage
//!
//! The first pass covers the dispatch-critical variants:
//! - `SABRHashMismatch` → StateChainMismatch detail + ClaraHealNextSend
//! - `InconsistentChequeBundle` → ChequeBundle detail + DedupChequeBundle
//! - `InsufficientBalance` → Balance detail
//! - `VBCExpired`, `VBCNotYetValid`, etc. → VbcLifecycle detail
//! - `SABRInsufficientOverlap` → SabrInsufficientOverlap detail
//! - `WalletFrozen`, `GenesisStakeLocked` → WalletLock detail
//!
//! All other variants fall through to a generic mapping that just
//! sets `code` and `category` without any structured detail. Full
//! per-variant mapping is filled in during Phase 2b.2 as each layer
//! starts actually emitting structured errors.

use alloc::string::String;
use alloc::string::ToString;

use axiom_errors::{error_code, ErrorCategory, ErrorCode, ErrorResponse, RecoveryHint};

use crate::types::ValidationError;

impl From<ValidationError> for ErrorResponse {
    fn from(err: ValidationError) -> Self {
        let (code, category, message, recovery, yp_ref) = classify(&err);
        let mut resp = ErrorResponse::new(
            ErrorCode::from_static(code),
            category,
            message.as_str(),
        );
        if let Some(hint) = recovery {
            resp = resp.with_recovery(hint);
        }
        if let Some(r) = yp_ref {
            resp = resp.with_yp_reference(r);
        }
        // Phase 2b.14: populate typed VbcLifecycleDetail for the two
        // VBC timestamp variants. These carry their context as struct
        // fields post-upgrade, so we can fill in expires_at / issued_at
        // / current_tick structurally without parsing the message.
        //
        // IPC-decoded instances coming back through core/ipc/codec.rs
        // carry tick=0 sentinels (the wire format drops the context
        // for compat with existing vector files) — we still populate
        // the detail, and the client treats 0/0 as "no lifecycle
        // data available from this server".
        match &err {
            ValidationError::VBCExpired { expires_at, current_tick } => {
                let ticks_until_valid = if *current_tick == 0 && *expires_at == 0 {
                    None
                } else {
                    Some((*expires_at as i64) - (*current_tick as i64))
                };
                resp = resp.with_detail(axiom_errors::ErrorDetail::VbcLifecycle(
                    axiom_errors::VbcLifecycleDetail {
                        vbc_expires_at_tick: *expires_at,
                        current_tick: *current_tick,
                        ticks_until_valid,
                    },
                ));
            }
            ValidationError::VBCNotYetValid { issued_at, current_tick } => {
                let ticks_until_valid = if *current_tick == 0 && *issued_at == 0 {
                    None
                } else {
                    Some((*issued_at as i64) - (*current_tick as i64))
                };
                resp = resp.with_detail(axiom_errors::ErrorDetail::VbcLifecycle(
                    axiom_errors::VbcLifecycleDetail {
                        // For NotYetValid, expires_at_tick is unknown —
                        // what matters is the "not valid until" time,
                        // which we store in the field of the same name
                        // (slight schema pun: the VbcLifecycleDetail
                        // schema is oriented around "when does this
                        // become valid or invalid"). Use issued_at as
                        // the lifecycle tick for the NotYetValid case.
                        vbc_expires_at_tick: *issued_at,
                        current_tick: *current_tick,
                        ticks_until_valid,
                    },
                ));
            }
            _ => {}
        }
        resp
    }
}

/// Map a `ValidationError` to its tuple of wire fields:
/// `(code, category, message, recovery_hint, yp_reference)`.
///
/// This is a single switch to make adding new variants a mechanical
/// change, and keep the mapping reviewable in one place.
fn classify(
    err: &ValidationError,
) -> (
    &'static str,
    ErrorCategory,
    String,
    Option<RecoveryHint>,
    Option<&'static str>,
) {
    use ValidationError::*;
    match err {
        // ── State chain ────────────────────────────────────────────────────
        SABRHashMismatch => (
            error_code::E_SABR_HASH_MISMATCH,
            ErrorCategory::RecoverableDrift,
            "Wallet state does not match validator's stored state".to_string(),
            Some(RecoveryHint::ClaraHealNextSend),
            Some("§17.10.14 CLARA + YPX-018"),
        ),
        StateIdAlreadyConsumed => (
            error_code::E_STATE_ID_CONSUMED,
            ErrorCategory::ProtocolReject,
            "Transaction replay detected: state_id already consumed".to_string(),
            None,
            None,
        ),
        InvalidStateId => (
            error_code::E_INVALID_STATE_ID,
            ErrorCategory::ProtocolReject,
            "State chain integrity check failed".to_string(),
            None,
            None,
        ),
        StateNotAnchored => (
            error_code::E_STATE_NOT_ANCHORED,
            ErrorCategory::RecoverableDrift,
            "Client-supplied state does not re-derive to k-signed prev_receipt — heal required".to_string(),
            Some(RecoveryHint::ClaraHealNextSend),
            None,
        ),
        InvalidWalletSeq => (
            error_code::E_INVALID_WALLET_SEQ,
            ErrorCategory::RecoverableDrift,
            "Wallet sequence number is out of sync with validator".to_string(),
            Some(RecoveryHint::ClaraHealNextSend),
            None,
        ),
        WalletSeqOverflow => (
            error_code::E_WALLET_SEQ_OVERFLOW,
            ErrorCategory::ProtocolReject,
            "Wallet sequence number overflowed u64".to_string(),
            None,
            None,
        ),

        // ── Identity ──────────────────────────────────────────────────────
        InvalidWalletId => (
            error_code::E_INVALID_WALLET_ID,
            ErrorCategory::ClientBug,
            "Wallet ID is malformed".to_string(),
            None,
            None,
        ),
        MalformedAddress => (
            error_code::E_MALFORMED_ADDRESS,
            ErrorCategory::ClientBug,
            "Address format is invalid".to_string(),
            None,
            None,
        ),
        SenderWalletIdMismatch => (
            error_code::E_SENDER_WALLET_ID_MISMATCH,
            ErrorCategory::ProtocolReject,
            "Sender wallet_id does not match stored wallet identity".to_string(),
            None,
            Some("YPX-007"),
        ),
        MissingWalletState => (
            error_code::E_MISSING_WALLET_STATE,
            ErrorCategory::Internal,
            "Lambda did not provide wallet state for Core check".to_string(),
            None,
            None,
        ),

        // ── Signatures ────────────────────────────────────────────────────
        InvalidClientSignature => (
            error_code::E_INVALID_CLIENT_SIG,
            ErrorCategory::ClientBug,
            "Client signature verification failed".to_string(),
            None,
            Some("YPX-007 §39.3"),
        ),
        InvalidWitnessSignature => (
            error_code::E_INVALID_WITNESS_SIG,
            ErrorCategory::Internal,
            "Witness signature verification failed".to_string(),
            None,
            None,
        ),
        UnsupportedSignatureAlgorithm => (
            error_code::E_UNSUPPORTED_SIG_ALG,
            ErrorCategory::ClientBug,
            "Unsupported signature algorithm".to_string(),
            None,
            None,
        ),

        // ── Balance / amount ──────────────────────────────────────────────
        InsufficientBalance => (
            error_code::E_INSUFFICIENT_BALANCE,
            ErrorCategory::ProtocolReject,
            "Insufficient balance for this transaction".to_string(),
            None,
            None,
        ),
        ConservationViolation => (
            error_code::E_CONSERVATION_VIOLATION,
            ErrorCategory::Internal,
            "Balance conservation check failed (Core math bug)".to_string(),
            None,
            None,
        ),
        ZeroAmount => (
            error_code::E_ZERO_AMOUNT,
            ErrorCategory::ClientBug,
            "Transaction amount is zero".to_string(),
            None,
            None,
        ),
        DustAmount => (
            error_code::E_DUST_AMOUNT,
            ErrorCategory::ClientBug,
            "Transaction amount is below MINIMUM_TX_ATOMS".to_string(),
            None,
            None,
        ),

        // ── VBC ───────────────────────────────────────────────────────────
        InvalidVBC => (
            error_code::E_INVALID_VBC,
            ErrorCategory::RecoverableDrift,
            "Validator credential is invalid".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCExpired { .. } => (
            error_code::E_VBC_EXPIRED,
            ErrorCategory::RecoverableDrift,
            "Validator credential has expired".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCNotYetValid { .. } => (
            error_code::E_VBC_NOT_YET_VALID,
            ErrorCategory::Operational,
            "Validator credential is not yet valid".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCChainTooDeep => (
            error_code::E_VBC_CHAIN_TOO_DEEP,
            ErrorCategory::RecoverableDrift,
            "Validator credential chain is too deep".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCMissingIssuer => (
            error_code::E_VBC_MISSING_ISSUER,
            ErrorCategory::RecoverableDrift,
            "Validator credential issuer chain is incomplete".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCRootKeyMismatch => (
            error_code::E_VBC_ROOT_KEY_MISMATCH,
            ErrorCategory::RecoverableDrift,
            "Validator credential root key does not match trust anchor".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        DuplicateValidator => (
            error_code::E_DUPLICATE_VALIDATOR,
            ErrorCategory::ClientBug,
            "Duplicate validator in witness set".to_string(),
            None,
            None,
        ),
        InvalidVBCCount => (
            error_code::E_INVALID_VBC_COUNT,
            ErrorCategory::ClientBug,
            "Wrong number of VBCs in bundle".to_string(),
            None,
            None,
        ),

        // ── Cheque / redeem ───────────────────────────────────────────────
        InsufficientCheques => (
            error_code::E_INSUFFICIENT_CHEQUES,
            ErrorCategory::RecoverableDrift,
            "Cheque bundle does not have enough distinct validators".to_string(),
            Some(RecoveryHint::DedupChequeBundle),
            Some("§17.9.4.0"),
        ),
        InconsistentChequeBundle => (
            error_code::E_CHEQUE_INCONSISTENT_BUNDLE,
            ErrorCategory::RecoverableDrift,
            "Cheque bundle contains duplicate or inconsistent entries".to_string(),
            Some(RecoveryHint::DedupChequeBundle),
            Some("§17.9.4.0"),
        ),
        InvalidChequeSignature => (
            error_code::E_INVALID_CHEQUE_SIG,
            ErrorCategory::Internal,
            "Cheque signature verification failed".to_string(),
            None,
            None,
        ),
        ChequeAlreadyRedeemed => (
            error_code::E_CHEQUE_ALREADY_REDEEMED,
            ErrorCategory::ProtocolReject,
            "This cheque has already been redeemed".to_string(),
            None,
            None,
        ),

        // ── S-ABR overlap ─────────────────────────────────────────────────
        SABRInsufficientOverlap => (
            error_code::E_SABR_INSUFFICIENT_OVERLAP,
            ErrorCategory::RecoverableDrift,
            "Fresh validator requires k-1 overlap signatures".to_string(),
            Some(RecoveryHint::RetrySameValidator),
            Some("YPX-016"),
        ),
        SABROverlapNotInPrev => (
            error_code::E_SABR_OVERLAP_NOT_IN_PREV,
            ErrorCategory::ClientBug,
            "Overlap signature from validator not in prev_receipts".to_string(),
            None,
            None,
        ),
        SABRMissingValidatorPK => (
            error_code::E_SABR_MISSING_VALIDATOR_PK,
            ErrorCategory::ClientBug,
            "CL3 called without my_validator_pk input".to_string(),
            None,
            None,
        ),

        // ── FACT chain ────────────────────────────────────────────────────
        FactChainTooDeep => (
            error_code::E_FACT_CHAIN_TOO_DEEP,
            ErrorCategory::RecoverableDrift,
            "FACT chain depth exceeds MAX_FACT_DEPTH".to_string(),
            Some(RecoveryHint::FactChainCompress),
            Some("YPX-001"),
        ),
        FactChainBreak => (
            error_code::E_FACT_CHAIN_BREAK,
            ErrorCategory::ClientBug,
            "FACT chain state_id discontinuity".to_string(),
            None,
            None,
        ),
        FactInsufficientWitnesses => (
            error_code::E_FACT_INSUFFICIENT_WITNESSES,
            ErrorCategory::ClientBug,
            "FACT link has fewer than 3 witnesses".to_string(),
            None,
            None,
        ),
        FactInvalidSignature => (
            error_code::E_FACT_INVALID_SIG,
            ErrorCategory::Internal,
            "FACT witness signature verification failed".to_string(),
            None,
            None,
        ),
        FactDuplicateWitness => (
            error_code::E_FACT_DUPLICATE_WITNESS,
            ErrorCategory::ClientBug,
            "FACT link has duplicate validator IDs".to_string(),
            None,
            Some("§17.9.4.0"),
        ),
        FactInvalidCheckpoint => (
            error_code::E_FACT_INVALID_CHECKPOINT,
            ErrorCategory::Internal,
            "FACT checkpoint integrity check failed".to_string(),
            None,
            None,
        ),
        FactChainEmpty => (
            error_code::E_FACT_CHAIN_EMPTY,
            ErrorCategory::Internal,
            "FACT checkpoint provenance anchor read from an empty link set".to_string(),
            None,
            None,
        ),
        FactAmountOverflow => (
            error_code::E_FACT_AMOUNT_OVERFLOW,
            ErrorCategory::Internal,
            "FACT checkpoint amount/count addition overflowed u64".to_string(),
            None,
            None,
        ),
        BurnProofInsufficientWitnesses => (
            error_code::E_BURN_PROOF_INSUFFICIENT_WITNESSES,
            ErrorCategory::ClientBug,
            "BurnProof has fewer than 3 validator signatures".to_string(),
            None,
            Some("YPX-001 §1.5.4"),
        ),
        BurnProofDuplicateValidator => (
            error_code::E_BURN_PROOF_DUPLICATE_VALIDATOR,
            ErrorCategory::ClientBug,
            "BurnProof has duplicate validator IDs".to_string(),
            None,
            Some("YPX-001 §1.5.4"),
        ),
        BurnTxIdNotInChain => (
            error_code::E_BURN_TX_ID_NOT_IN_CHAIN,
            ErrorCategory::ClientBug,
            "BurnProof.burn_tx_id does not reference any link in this FACT chain".to_string(),
            None,
            Some("YPX-001 §1.5.4"),
        ),
        BurnTargetMismatch => (
            error_code::E_BURN_TARGET_MISMATCH,
            ErrorCategory::ProtocolReject,
            "Burn link's witnessed burn_target_tx_id does not name this scar (copied burn proof)".to_string(),
            None,
            Some("YPX-001 §1.5.4"),
        ),

        // ── Ark ───────────────────────────────────────────────────────────
        ArkToNonArkRejected => (
            error_code::E_ARK_TO_NON_ARK,
            ErrorCategory::ProtocolReject,
            "Ark wallet can only send to other Ark wallets".to_string(),
            None,
            Some("§11.9.2"),
        ),
        ArkChargeNotOwner => (
            error_code::E_ARK_CHARGE_NOT_OWNER,
            ErrorCategory::ProtocolReject,
            "Only the wallet owner can charge their Ark wallet".to_string(),
            None,
            Some("§11.9.1"),
        ),
        ArkUnloadScarred => (
            error_code::E_ARK_UNLOAD_SCARRED,
            ErrorCategory::RecoverableDrift,
            "Ark unload requires clean FACT chain (no scars)".to_string(),
            Some(RecoveryHint::BurnExistingScars),
            Some("§11.9.3"),
        ),
        SelfSendRejected => (
            error_code::E_SELF_SEND_REJECTED,
            ErrorCategory::ProtocolReject,
            "Self-send is not allowed except for Ark wallets".to_string(),
            None,
            Some("§11.9.4"),
        ),

        // ── Lockup / frozen / banned ──────────────────────────────────────
        WalletFrozen => (
            "E_WALLET_FROZEN",
            ErrorCategory::ProtocolReject,
            "Wallet is frozen by a JFP order".to_string(),
            None,
            Some("§7 JFP"),
        ),
        GenesisStakeLocked => (
            error_code::E_GENESIS_STAKE_LOCKED,
            ErrorCategory::ProtocolReject,
            "Genesis validator wallet is in 3-year lockup".to_string(),
            None,
            Some("White Paper §2.10.1"),
        ),

        // ── Too many unresolved scars ─────────────────────────────────────
        TooManyUnresolvedScars => (
            error_code::E_TOO_MANY_UNRESOLVED_SCARS,
            ErrorCategory::RecoverableDrift,
            "Wallet exceeds MAX_UNRESOLVED_SCARS".to_string(),
            Some(RecoveryHint::BurnExistingScars),
            None,
        ),

        // ── CLARA ─────────────────────────────────────────────────────────
        ClaraInvalidSignature => (
            error_code::E_CLARA_INVALID_SIGNATURE,
            ErrorCategory::ClientBug,
            "CLARA attestation Ed25519 signature invalid".to_string(),
            None,
            Some("YPX-018 §2.3"),
        ),
        ClaraWalletPkMismatch => (
            error_code::E_CLARA_WALLET_PK_MISMATCH,
            ErrorCategory::ClientBug,
            "CLARA attestation wallet_pk does not match request".to_string(),
            None,
            Some("YPX-018 §2.3"),
        ),
        ClaraStateNotGarbage => (
            error_code::E_CLARA_STATE_NOT_GARBAGE,
            ErrorCategory::ClientBug,
            "Validator's stored state is not in CLARA garbage list".to_string(),
            None,
            Some("YPX-018 §2.3"),
        ),
        ClaraNbcTrustFailed => (
            error_code::E_CLARA_NBC_TRUST_FAILED,
            ErrorCategory::ProtocolReject,
            "CLARA attestation NBC trust anchor verification failed".to_string(),
            None,
            Some("YPX-018 §2.3"),
        ),
        ClaraEmptyGarbage => (
            error_code::E_CLARA_EMPTY_GARBAGE,
            ErrorCategory::ClientBug,
            "CLARA attestation must declare at least one garbage state".to_string(),
            None,
            Some("YPX-018 §2.3"),
        ),

        // ── Auth hash ─────────────────────────────────────────────────────
        AuthHashRequired => (
            error_code::E_AUTH_HASH_REQUIRED,
            ErrorCategory::ClientBug,
            "Wallet has auth_hash but transaction is missing owner_proof".to_string(),
            None,
            Some("YPX-007 §39.3"),
        ),
        InvalidAuthProof => (
            error_code::E_INVALID_AUTH_PROOF,
            ErrorCategory::ClientBug,
            "Owner proof verification failed".to_string(),
            None,
            Some("YPX-007 §39.3"),
        ),

        // ── Cheque-claim proof (CL5 synchronous double-redeem prevention) ─
        ChequeClaimProofMissing => (
            error_code::E_CHEQUE_CLAIM_PROOF_MISSING,
            ErrorCategory::ClientBug,
            "Redeem missing Nabla cheque-claim proof — call register_cheque_claim before redeem".to_string(),
            None,
            Some("§4.6 / AXIOM_REDEEM_CLAIM"),
        ),
        ChequeClaimProofInvalidSig => (
            error_code::E_CHEQUE_CLAIM_PROOF_INVALID_SIG,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof signature failed verification".to_string(),
            None,
            Some("§4.6 / AXIOM_REDEEM_CLAIM"),
        ),
        ChequeClaimProofTxidMismatch => (
            error_code::E_CHEQUE_CLAIM_PROOF_TXID_MISMATCH,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof's cheque_id does not match the bundle's txid".to_string(),
            None,
            Some("§4.6"),
        ),
        ChequeClaimProofReceiverMismatch => (
            error_code::E_CHEQUE_CLAIM_PROOF_RECEIVER_MISMATCH,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof's client_pk does not match the redeem receiver".to_string(),
            None,
            Some("§4.6"),
        ),
        ChequeClaimProofUntrusted => (
            error_code::E_CHEQUE_CLAIM_PROOF_UNTRUSTED,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof's NBC trust anchor is invalid (not a known Nabla root authority)".to_string(),
            None,
            Some("§4.6"),
        ),
        TxidAlreadyInReceiverChain => (
            error_code::E_TXID_ALREADY_IN_RECEIVER_CHAIN,
            ErrorCategory::ProtocolReject,
            "Redeem rejected: txid already appears in receiver's FACT chain (post-finalization replay)".to_string(),
            None,
            Some("CL5 defense-in-depth"),
        ),
        ChequeClaimProofExpired => (
            error_code::E_CHEQUE_CLAIM_PROOF_EXPIRED,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof is outside the freshness window — Nabla writer's claim entry would have expired (24h TTL)".to_string(),
            None,
            Some("§4.6 / CHEQUE_CLAIM_EXPIRY_TICKS"),
        ),

        // ── OODS (YPX-021) ──────────────────────────────────────────────────
        // A recovery re-anchor blocked because the network isn't verified-healthy
        // (§8.5). RETRYABLE: Operational category + WaitAndRetry — the wallet
        // re-attempts when OODS recovers. NOT poisoning, NOT a drift.
        OodsUnhealthyRetry => (
            "E_OODS_UNHEALTHY_RETRY",
            ErrorCategory::Operational,
            "Recovery re-anchor blocked: network OODS is not verified-healthy — \
             retry when the network recovers".to_string(),
            Some(RecoveryHint::WaitAndRetry),
            Some("YPX-021 §8.5"),
        ),
        // A forged/invalid OODS reading — hard protocol reject (a forged reading
        // never becomes valid by retrying).
        OodsAttestationInvalid => (
            "E_OODS_ATTESTATION_INVALID",
            ErrorCategory::ProtocolReject,
            "OODS attestation failed verification (bad signature / NBC anchor / baseline)".to_string(),
            None,
            Some("YPX-021 §8.2"),
        ),

        // ── Fallback ──────────────────────────────────────────────────────
        // Any variant not explicitly mapped above gets a generic
        // ProtocolReject with no detail. Covers the long tail of
        // rarer variants (FanOut, MVIB, Console, Oracle, Stake, Group,
        // DEED, etc.). These can be elevated to specific classifications
        // as they become dispatch-critical.
        _ => (
            "E_CORE_UNCLASSIFIED",
            ErrorCategory::ProtocolReject,
            format_unknown(err),
            None,
            None,
        ),
    }
}

/// Debug-format an unknown `ValidationError` variant for the fallback
/// message. Uses the existing `Display` impl, which emits the code
/// string already defined in `types.rs`. This gives us a stable
/// message for every variant even before we write its explicit
/// classifier.
fn format_unknown(err: &ValidationError) -> String {
    err.to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_errors::{ErrorCategory, RecoveryHint};

    #[test]
    fn sabr_hash_mismatch_maps_to_recoverable_drift() {
        let err = ValidationError::SABRHashMismatch;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_SABR_HASH_MISMATCH");
        assert_eq!(resp.category, ErrorCategory::RecoverableDrift);
        assert_eq!(resp.recovery, Some(RecoveryHint::ClaraHealNextSend));
        assert!(resp.is_retryable());
        assert!(!resp.is_user_visible());
    }

    #[test]
    fn oods_unhealthy_retry_is_retryable_wait_and_retry() {
        // YPX-021 §8.5: a recovery re-anchor blocked on unhealthy OODS must be a
        // RETRYABLE WaitAndRetry — the wallet re-attempts when the network heals,
        // it is NOT stranded and NOT poisoned.
        let resp: ErrorResponse = ValidationError::OodsUnhealthyRetry.into();
        assert_eq!(resp.code.as_str(), "E_OODS_UNHEALTHY_RETRY");
        assert_eq!(resp.category, ErrorCategory::Operational);
        assert_eq!(resp.recovery, Some(RecoveryHint::WaitAndRetry));
        assert!(resp.is_retryable(), "recovery must be able to retry when OODS recovers");
    }

    #[test]
    fn oods_attestation_invalid_is_hard_reject_not_retryable() {
        // A FORGED reading never becomes valid by retrying — distinct from the
        // honestly-unhealthy retry above.
        let resp: ErrorResponse = ValidationError::OodsAttestationInvalid.into();
        assert_eq!(resp.code.as_str(), "E_OODS_ATTESTATION_INVALID");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        assert!(resp.recovery.is_none());
        assert!(!resp.is_retryable());
    }

    #[test]
    fn insufficient_balance_maps_to_protocol_reject() {
        let err = ValidationError::InsufficientBalance;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_INSUFFICIENT_BALANCE");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        assert!(resp.recovery.is_none());
        assert!(resp.is_user_visible());
    }

    #[test]
    fn inconsistent_cheque_bundle_hints_dedup() {
        let err = ValidationError::InconsistentChequeBundle;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_CHEQUE_INCONSISTENT_BUNDLE");
        assert_eq!(resp.category, ErrorCategory::RecoverableDrift);
        assert_eq!(resp.recovery, Some(RecoveryHint::DedupChequeBundle));
        assert_eq!(resp.yp_reference.as_deref(), Some("§17.9.4.0"));
    }

    #[test]
    fn vbc_expired_retries_different_validator() {
        let err = ValidationError::VBCExpired { expires_at: 1000, current_tick: 2000 };
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_VBC_EXPIRED");
        assert_eq!(resp.category, ErrorCategory::RecoverableDrift);
        assert_eq!(resp.recovery, Some(RecoveryHint::RetryDifferentValidator));
    }

    #[test]
    fn client_signature_is_client_bug() {
        let err = ValidationError::InvalidClientSignature;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.category, ErrorCategory::ClientBug);
        assert!(!resp.is_retryable());
        assert!(!resp.is_user_visible());
    }

    #[test]
    fn sabr_insufficient_overlap_hints_retry_same() {
        let err = ValidationError::SABRInsufficientOverlap;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_SABR_INSUFFICIENT_OVERLAP");
        assert_eq!(resp.recovery, Some(RecoveryHint::RetrySameValidator));
        assert_eq!(resp.yp_reference.as_deref(), Some("YPX-016"));
    }

    #[test]
    fn genesis_lockup_rejected_with_no_recovery() {
        let err = ValidationError::GenesisStakeLocked;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_GENESIS_STAKE_LOCKED");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        assert!(resp.recovery.is_none());
    }

    #[test]
    fn unclassified_variants_fall_back() {
        // A variant we haven't written an explicit arm for.
        let err = ValidationError::FanOutMissingMessage;
        let resp: ErrorResponse = err.into();
        assert_eq!(resp.code.as_str(), "E_CORE_UNCLASSIFIED");
        assert_eq!(resp.category, ErrorCategory::ProtocolReject);
        // The Display impl's code string ends up in the message as a
        // stable identifier, so Phase 2b.2 can grep for unclassified
        // variants that show up in the wild.
        assert!(!resp.message.is_empty());
    }

    #[test]
    fn conversion_roundtrips_through_cbor() {
        let err = ValidationError::SABRHashMismatch;
        let resp: ErrorResponse = err.into();
        let mut buf = alloc::vec::Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let decoded: ErrorResponse = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(resp, decoded);
    }
}
