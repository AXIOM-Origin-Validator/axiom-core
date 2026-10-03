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
        VBCUnusableSoon { .. } => (
            error_code::E_VBC_UNUSABLE_SOON,
            ErrorCategory::RecoverableDrift,
            "Validator credential is too close to expiry to serve — renew or retry a fresher validator".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCStaleAttestation { .. } => (
            error_code::E_VBC_STALE_ATTESTATION,
            ErrorCategory::RecoverableDrift,
            "attested OODS reading is stale vs the wallet's last round — fetch a fresh reading".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCLifetimeTooLong { .. } => (
            error_code::E_VBC_LIFETIME_TOO_LONG,
            // Malformed request (the requester chose an out-of-policy lifetime) —
            // retrying identically will not help; the request must carry a shorter
            // expires_at. No RecoveryHint fits "shorten the validity"; the message
            // carries the fix.
            ErrorCategory::Operational,
            "requested VBC validity exceeds the maximum non-genesis lifetime — request a shorter expires_at".to_string(),
            None,
            None,
        ),
        VBCNotYetValid { .. } => (
            error_code::E_VBC_NOT_YET_VALID,
            ErrorCategory::Operational,
            "Validator credential is not yet valid".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        // Q2-b renewal proof-of-validation. Operational, no RecoveryHint:
        // retrying identically will not help — the renewal must carry a valid
        // co-signed fresh receipt, and if the validator did no witnessing this
        // term, the fix is to witness first, not to retry.
        VbcRenewalNoProofOfWork => (
            error_code::E_VBC_RENEWAL_NO_PROOF_OF_WORK,
            ErrorCategory::Operational,
            "VBC renewal must present a k-signed receipt this validator co-signed this term (proof of validation work) — witness a transaction, then renew".to_string(),
            None,
            None,
        ),
        VbcRenewalNotCoSigned => (
            error_code::E_VBC_RENEWAL_NOT_CO_SIGNED,
            ErrorCategory::Operational,
            "the renewal proof receipt is not co-signed by this validator — present a receipt whose witness set carries this validator's key with a valid signature".to_string(),
            None,
            None,
        ),
        VbcRenewalWorkReceiptStale => (
            error_code::E_VBC_RENEWAL_WORK_RECEIPT_STALE,
            ErrorCategory::Operational,
            "the renewal proof receipt does not post-date the current certificate (no OODS reading, or its tick is not newer than the cert) — present an online witnessed receipt from this term".to_string(),
            None,
            None,
        ),
        VbcRenewalWorkReceiptSubQuorum => (
            error_code::E_VBC_RENEWAL_WORK_RECEIPT_SUB_QUORUM,
            ErrorCategory::Operational,
            "the renewal proof receipt does not carry a full witness quorum (fewer than 3 valid distinct signatures)".to_string(),
            None,
            None,
        ),
        // ValidatorJoin §5.2.2. RetryDifferentValidator, NOT WaitAndRetry:
        // a provisional never becomes serviceable by waiting — it expires.
        // The candidate's route forward is to complete its join and obtain a
        // full VBC, which is not something the counterparty can wait out.
        VBCProvisionalCannotServe { .. } => (
            error_code::E_VBC_PROVISIONAL_CANNOT_SERVE,
            ErrorCategory::ProtocolReject,
            "Validator credential is provisional and confers no service rights".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        // ── §5.3 genesis-lineage admission ────────────────────────────────
        // ProtocolReject, not RecoverableDrift: none of these is a timing or
        // staleness problem the caller can wait out. The candidate must change
        // its REQUEST — different issuers, the issuers' own certs included, a
        // lineage one of them actually holds. `RetryDifferentValidator` is the
        // honest hint for the issuer-shaped failures: swapping a meta is
        // exactly the remedy, and §5.3 identifies a meta by the KEY that
        // verifies its signature, not by its slot, so a refused third can be
        // replaced with the first two signatures still good.
        VBCNoAttestedTick => (
            error_code::E_VBC_NO_ATTESTED_TICK,
            ErrorCategory::Operational,
            "No attested tick — the certificate issuing bar cannot be judged".to_string(),
            Some(RecoveryHint::WaitAndRetry),
            None,
        ),
        VBCIssuerCertMissing => (
            error_code::E_VBC_ISSUER_CERT_MISSING,
            ErrorCategory::ProtocolReject,
            "An issuer's own certificate is missing from the request".to_string(),
            None,
            None,
        ),
        VBCIssuerCannotIssue => (
            error_code::E_VBC_ISSUER_CANNOT_ISSUE,
            ErrorCategory::ProtocolReject,
            "An issuer has too little remaining life to admit a newcomer".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCIssuerNoLineage => (
            error_code::E_VBC_ISSUER_NO_LINEAGE,
            ErrorCategory::ProtocolReject,
            "An issuer belongs to no genesis lineage".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCIssuersShareLineage => (
            error_code::E_VBC_ISSUERS_SHARE_LINEAGE,
            ErrorCategory::ProtocolReject,
            "Two issuers share one genesis lineage — three different families are required".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        VBCLineageNotAdopted => (
            error_code::E_VBC_LINEAGE_NOT_ADOPTED,
            ErrorCategory::ProtocolReject,
            "The certificate's genesis lineage is not one of its issuers'".to_string(),
            None,
            None,
        ),
        // ── CL8 certificate issuance ──────────────────────────────────────
        // The three Core-fault arms (key unusable / signing failed /
        // verify-after-sign) are Internal, NOT ProtocolReject: nothing the
        // candidate sent is wrong, so telling it to change its request would
        // send it chasing a defect on the issuer's side.
        Cl8MissingBundle => (
            error_code::E_CL8_MISSING_BUNDLE,
            ErrorCategory::ProtocolReject,
            "Certificate signing called with no certificate".to_string(),
            None,
            None,
        ),
        Cl8MissingIssuerKey => (
            error_code::E_CL8_MISSING_ISSUER_KEY,
            ErrorCategory::Internal,
            "Certificate signing called with no issuer key".to_string(),
            None,
            None,
        ),
        Cl8SignerNotInIssuerSet => (
            error_code::E_CL8_SIGNER_NOT_IN_ISSUER_SET,
            ErrorCategory::ProtocolReject,
            "This validator is not among the certificate's declared issuers".to_string(),
            Some(RecoveryHint::RetryDifferentValidator),
            None,
        ),
        Cl8ProvisionalLifetimeInvalid => (
            error_code::E_CL8_PROVISIONAL_LIFETIME_INVALID,
            ErrorCategory::ProtocolReject,
            "Certificate lifetime is zero or runs backwards".to_string(),
            None,
            None,
        ),
        Cl8IssuerKeyUnusable => (
            error_code::E_CL8_ISSUER_KEY_UNUSABLE,
            ErrorCategory::Internal,
            "Issuer signing key is malformed".to_string(),
            None,
            None,
        ),
        Cl8SigningFailed => (
            error_code::E_CL8_SIGNING_FAILED,
            ErrorCategory::Internal,
            "Certificate signing failed".to_string(),
            None,
            None,
        ),
        Cl8OodsStampMismatch => (
            error_code::E_CL8_OODS_STAMP_MISMATCH,
            ErrorCategory::ProtocolReject,
            "Certificate OODS stamp disagrees with the attestation supplied".to_string(),
            None,
            None,
        ),
        Cl8VerifyAfterSignFailed => (
            error_code::E_CL8_VERIFY_AFTER_SIGN_FAILED,
            ErrorCategory::Internal,
            "Certificate signature did not verify after signing".to_string(),
            None,
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
        GenesisNameReserved => (
            error_code::E_GENESIS_NAME_RESERVED,
            ErrorCategory::RecoverableDrift,
            "Genesis validator name is reserved to its pinned genesis key".to_string(),
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
        // YP §26.17.6.5 FACT Provenance Binding (2026-09-11, KI#145)
        FactWitnessUncertified => (
            error_code::E_FACT_WITNESS_UNCERTIFIED,
            ErrorCategory::ClientBug,
            "FACT witness resolves to no presented, verified certificate (or its keys differ) — present the witnessing validators' certificate bundles with the chain; Core never fetches them".to_string(),
            None,
            Some("§26.17.6.5"),
        ),
        FactOriginInvalid => (
            error_code::E_FACT_ORIGIN_INVALID,
            ErrorCategory::ClientBug,
            "FACT chain does not start at the wallet's derived opening state".to_string(),
            None,
            Some("§26.17.6.5"),
        ),
        FactCertificateInvalid => (
            error_code::E_FACT_CERTIFICATE_INVALID,
            ErrorCategory::ClientBug,
            "a presented FACT certificate bundle does not verify to this network's roots".to_string(),
            None,
            Some("§26.17.6.5"),
        ),
        FactBurnSigInvalid => (
            error_code::E_FACT_BURN_SIG_INVALID,
            ErrorCategory::ClientBug,
            "burn proof signature is not one of the burn link's verified witnesses".to_string(),
            None,
            Some("§26.17.6.5"),
        ),
        StakeClaimTierInvalid => (
            error_code::E_STAKE_CLAIM_TIER_INVALID,
            ErrorCategory::ProtocolReject,
            "a subsidised stake claim must be addressed to the claimant's Standard-tier (k=3) address".to_string(),
            None,
            Some("§40.3"),
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
        ReceiverStateNotAnchored => (
            error_code::E_RECEIVER_STATE_NOT_ANCHORED,
            ErrorCategory::ClientBug,
            "Redeem: the declared receiver state and the carried prev_receipts do not match \
             (a returning receiver ships exactly its last receipt; a first-time receiver ships none)"
                .to_string(),
            None,
            Some("§17.3.1.4"),
        ),
        ArkChargeScarred => (
            error_code::E_ARK_CHARGE_SCARRED,
            ErrorCategory::RecoverableDrift,
            "Ark charge requires the sending wallet's FACT chain to be clean".to_string(),
            Some(RecoveryHint::BurnExistingScars),
            Some("§11.9.1b"),
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
        // §5.2.2c — the SUBSIDISED stake lock, the general-purpose sibling of the
        // hardcoded genesis lockup above. Classified explicitly (2026-09-05)
        // because the fallback answered `E_CORE_UNCLASSIFIED`: the code string
        // existed only inside the Display message, so a consumer dispatching on
        // `error_response.code` — which CLAUDE.md §10 REQUIRES — could never see it.
        // No recovery hint: like the genesis lockup, the only remedy is time, and
        // `WaitAndRetry` would be a lie at this scale (a lock is ~1-3 YEARS, while
        // that hint means "retry after `retry_after_secs`").
        StakeLocked => (
            error_code::E_STAKE_LOCKED,
            ErrorCategory::ProtocolReject,
            "Validator stake wallet is locked until its wall-clock deadline".to_string(),
            None,
            Some("YP §26.7.3 / ValidatorJoin §5.2.2c"),
        ),
        // KI#137 — NOT retryable, and deliberately worded so a holder is not told
        // to wait: no amount of waiting turns an unmintable pair into a real lock.
        StakeLockPairUnmintable => (
            error_code::E_STAKE_LOCK_PAIR_UNMINTABLE,
            ErrorCategory::ProtocolReject,
            "Stake deadlines are a distance apart that no tier could have minted \
             — the pair is forged, not merely unexpired".to_string(),
            None,
            Some("ValidatorJoin §5.2.2c (interlock)"),
        ),
        // §6b.13 (KI#225) — the stake floor. NOT a lock: the surplus above the
        // floor is spendable, so the message says so. No recovery hint — the
        // cure is a smaller send, or time (the floor lapses at the certificate's
        // maximum life), and `WaitAndRetry` would misstate a months-long wait.
        StakeFloor => (
            error_code::E_STAKE_FLOOR,
            ErrorCategory::ProtocolReject,
            "Validator stake floor: this debit would leave the wallet below 500 AXC \
             while its certificate can still be live — only the surplus above the \
             floor may move".to_string(),
            None,
            Some("ValidatorJoin §6b.13"),
        ),
        // §6b.13 — a wallet state Core neither consumes nor produces.
        WalletFormatInvalid => (
            error_code::E_WALLET_FORMAT_INVALID,
            ErrorCategory::ProtocolReject,
            "Wallet format block is not the current one (wallet_version or a \
             reserved ext field)".to_string(),
            None,
            Some("ValidatorJoin §6b.13"),
        ),
        // The claimant's declared epoch and the issuers' signed clocks disagree
        // about the claim's own witness round. One party is lying, so this is a
        // hard reject and NOT retryable: retrying with the same numbers reproduces
        // it, and changing them is the attack.
        StakeLockTimeDisagreement => (
            error_code::E_STAKE_LOCK_TIME_DISAGREEMENT,
            ErrorCategory::ProtocolReject,
            "Claim time disagreement: the claimant's declared epoch and the issuers' \
             signed timestamps do not agree about the claim's witness round"
                .to_string(),
            None,
            Some("YP §26.7.3 / ValidatorJoin §5.2.2c"),
        ),

        // §23.15 TVL (KI#221) — the wallet moved faster than the tick floor.
        // Network is healthy; the tx simply arrived too soon. WaitAndRetry once
        // the floor elapses (~25 s). NOT poisoning — neither party is byzantine.
        TxVelocityTooFast => (
            error_code::E_TX_VELOCITY_TOO_FAST,
            // OPERATIONAL, not ProtocolReject: the network is healthy and neither
            // party is byzantine — the floor clears itself, so this is a retryable
            // WaitAndRetry (the constructor forbids a recovery hint on a hard
            // ProtocolReject). Same shape as `OodsUnhealthyRetry`.
            ErrorCategory::Operational,
            "Transaction velocity limit: this tx's attested tick is fewer than the \
             minimum ticks after the wallet's previous transaction".to_string(),
            Some(RecoveryHint::WaitAndRetry),
            Some("YP §23.15 (Transaction Velocity Limit) / KI#221"),
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
            "CLARA attestation is not for this state (eligibility = healed_to only, KI#260)".to_string(),
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
        ChequeClaimProofUnauthenticated => (
            error_code::E_CHEQUE_CLAIM_PROOF_UNAUTHENTICATED,
            ErrorCategory::ProtocolReject,
            "Cheque-claim proof's claim_sig is not a valid signature by client_pk over the claim (cheque_id, client_pk, k_tier, wallet_address) — the claim was not made by the addressed receiver".to_string(),
            None,
            Some("YPX-022 §2.1.2a / AXIOM_CHEQUE_CLAIM"),
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
            "Cheque-claim proof is older than cheque_claim_proof_max_age_ticks (CL5 freshness bound, ~24h) — re-register the claim and redeem again".to_string(),
            None,
            Some("§4.6 / YPX-022 §2.1.2a / cheque_claim_proof_max_age_ticks"),
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

        // ── Class isolation: no dev VBC/NBC (the owner 2026-09-20) ─────────────
        DevAccountForbiddenFromValidator => (
            "E_DEV_ACCOUNT_FORBIDDEN_FROM_VALIDATOR",
            ErrorCategory::ProtocolReject,
            "A dev account (@axiom / @axiom.internal) cannot request or hold a \
             validator certificate — validators and Nabla nodes must be real \
             accounts".to_string(),
            None,
            Some("AXIOM_DESIGN_FactClassIsolation.md preamble point 0"),
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
    fn tx_velocity_too_fast_is_retryable_wait_and_retry() {
        // §23.15 TVL (KI#221) — a too-fast tx is NON-poisoning: the network is
        // healthy, the tx just arrived too soon, so it is a RETRYABLE WaitAndRetry
        // (the client re-submits after ~25 s), NOT a hard reject of a byzantine
        // party. This locks that classification against a future "harden it to a
        // hard reject" mistake.
        let resp: ErrorResponse = ValidationError::TxVelocityTooFast.into();
        assert_eq!(resp.code.as_str(), "E_TX_VELOCITY_TOO_FAST");
        assert_eq!(resp.category, ErrorCategory::Operational);
        assert_eq!(resp.recovery, Some(RecoveryHint::WaitAndRetry));
        assert!(resp.is_retryable(), "a velocity floor clears itself — the client must be told to wait and retry");
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

    /// §5.2.2c — the two stake-lock rejections must reach the wire as THEIR OWN
    /// codes, not as `E_CORE_UNCLASSIFIED`.
    ///
    /// Why this test exists (2026-09-05): both variants were falling through to
    /// the generic arm, so their code strings survived only inside the Display
    /// MESSAGE. CLAUDE.md §10 requires consumers to dispatch on
    /// `error_response.code`, and a dispatcher reading `E_CORE_UNCLASSIFIED`
    /// cannot tell a locked stake from any other unclassified reject. Deleting
    /// either arm turns this red.
    #[test]
    fn stake_lock_rejections_carry_their_own_dispatch_codes() {
        let locked: ErrorResponse = ValidationError::StakeLocked.into();
        assert_eq!(locked.code.as_str(), "E_STAKE_LOCKED");
        assert_eq!(locked.category, ErrorCategory::ProtocolReject);
        // Time is the only remedy for a ~1-3 year lock; WaitAndRetry would
        // promise the SDK a `retry_after_secs` that cannot be honoured.
        assert!(locked.recovery.is_none(), "a stake lock has no recovery but time");

        let disagreement: ErrorResponse = ValidationError::StakeLockTimeDisagreement.into();
        assert_eq!(disagreement.code.as_str(), "E_STAKE_LOCK_TIME_DISAGREEMENT");
        assert_eq!(disagreement.category, ErrorCategory::ProtocolReject);
        // Not retryable: the same numbers reproduce it, and new numbers are the attack.
        assert!(disagreement.recovery.is_none());
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
