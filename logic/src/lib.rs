//! AXIOM Core.bin - The Immutable Validation Logic
//! 
//! This crate implements the core transaction validation logic for AXIOM.
//! It is designed to run inside AVM/zkVM and NEVER executes outside of it.
//!
//! # Core Logic Modes
//!
//! Core.bin operates in eight modes:
//! - CL1: Client Core Out - Validate outgoing transaction
//! - CL2: Validator Core In - Verify incoming proof, validate transaction
//! - CL3: Validator Core Out - Verify Lambda's work, produce witness proof
//! - CL4: Client Core In - Verify incoming receipt
//! - CL5: Validator Redeem - Validate cheque redemption (balance increase)
//! - CL6: VBC Verification - Verify VBC bundle (k=3, ROOT_AUTHORITY_PKS)
//! - CL7: NBC Verification - Verify NBC bundle (k=1, NABLA_ROOT_AUTHORITY_PKS)
//! - CL8: NBC Issuance Signing - Sign NBC with issuer's SPHINCS+ key (Nabla)
//!
//! # Security Model
//!
//! - Core.bin is ONE immutable binary with ONE fingerprint
//! - All executions produce ZK proofs
//! - Lambda is sandwiched between CL2 and CL3 (cannot bypass)

#![cfg_attr(not(feature = "std"), no_std)]

// ══════════════════════════════════════════════════════════════
// AXIOM PLATFORM REQUIREMENT: 64-bit Unix Time
//
// AXIOM uses unix timestamps (u64) throughout the protocol:
//   - TARDIS tick numbers = unix seconds
//   - VBC/NBC issued_at / expires_at
//   - Transaction timestamps, maturity calculations
//
// 32-bit unix time overflows on 2038-01-19 (2,147,483,647).
// AXIOM is infrastructure designed to run for decades.
//
// Core checks this at launch — if the environment cannot
// represent time beyond 2038, Core refuses to start.
// This is the ONLY gate. Everything else trusts Core.
// ══════════════════════════════════════════════════════════════

/// 2040-01-01 00:00:00 UTC as unix timestamp.
/// If the environment can represent this, it has 64-bit time.
const UNIX_TIME_2040: u64 = 2_208_988_800;

/// Core calls this at launch. Panics if the environment
/// cannot safely handle unix timestamps beyond 2038.
///
/// Tests:
///   1. u64 can hold a post-2038 value (always true in Rust, but explicit)
///   2. The current time, if available, is sane (not wrapped/truncated)
pub fn verify_time_safety() {
    // Test 1: Can u64 hold 2040? (Rust guarantees this, but be explicit)
    let t: u64 = UNIX_TIME_2040;
    assert!(
        t > 2_147_483_647,
        "AXIOM FATAL: unix time representation cannot exceed 2038. \
         This environment is not safe for AXIOM."
    );

    // Test 2: Verify time hasn't wrapped (a 32-bit truncation would
    // show current time < year 2020, which is impossible)
    #[cfg(feature = "std")]
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("AXIOM FATAL: system clock before unix epoch")
            .as_secs();

        // 2020-01-01 = 1,577,836,800 — if we're below this, time is broken
        assert!(
            now > 1_577_836_800,
            "AXIOM FATAL: system clock reports year before 2020 ({}). \
             Possible 32-bit time truncation. AXIOM requires 64-bit unix time.",
            now
        );
    }
}

extern crate alloc;

// ── 乖乖 (椰子口味) — boot-canary anchor for the Core ELF. ─────
//
// The art bytes live in denomination/assets/kuaikuai.txt. The const
// is `pub` and reachable via this re-export from core-logic; the
// `#[used]` static below forces the linker to keep the bytes in
// the AVM-guest ELF even though no protocol path reads them.
//
// Consequence: changing one byte of the art file bumps the CoreID
// (BLAKE3 of the ELF). That is the intentional canary signal — the
// AXC / L$ / atom conversion library is part of every artifact's
// identity, including the consensus-load-bearing one.
pub use axiom_denomination::KUAIKUAI_ART;

#[used]
static KUAIKUAI_ART_ANCHOR_CORE: &[u8] = KUAIKUAI_ART.as_bytes();

pub mod types;
/// `From<ValidationError> for axiom_errors::ErrorResponse` conversion.
/// See `AXIOM_YellowPaper_Errors.md` Phase 2b.1.
pub mod error_response;
pub mod canonical;
mod crypto;
pub mod wallet_id;
pub mod wallet_seq;
pub mod validation;
pub mod cl5_inputs;
pub mod genesis;
pub mod nabla_genesis;
pub mod oods_verify;
pub mod vbc;
pub mod send_proof_verify;
pub mod modes;
pub mod errors;
pub mod carrier;
pub mod fact;
pub mod receipt;
pub mod nabla_wire;
/// Nabla client wire-protocol typed request/response envelopes.
/// Relocated here from `axiom_nabla::wire_client` (UMP Phase 1) so the
/// SDK can construct them directly. See `wire_client.rs` header.
pub mod wire_client;
pub mod oracle;
pub mod version;
pub mod audit;
pub mod ark;
pub mod genesis_integrity;
pub mod mvib;
pub mod reality;
pub mod console;
/// UMP transport envelope wire type (no_std, used by SDK + ANTIE).
/// See `docs/AXIOM_DESIGN_PublicMailCarriers.md` §3.
pub mod envelope;
/// Transport-layer crypto (X25519 + ChaCha20Poly1305) for sealing the
/// envelope.  Std-only — never compiled into the AVM guest.  This is
/// **transport** crypto, not protocol crypto; CLAUDE.md §1 explicitly
/// scoped to protocol-level operations (signing TXs, verifying chains).
#[cfg(feature = "std")]
pub mod transport_crypto;

// Re-exports
pub use types::*;
pub use errors::*;
pub use modes::execute_core;
pub use crate::wallet_id::generate_wallet_id_with_secret;
pub use crate::wallet_id::generate_all_wallet_ids_with_secret;
pub use crate::wallet_id::verify_wallet_id_with_secret;
pub use modes::{execute_cl3_zkp_checkpoint, ZkpCheckpointOutputs, FactCargo};

// Public verification API — Lambda/Gateway may verify signatures
// but MUST NOT access hashing, commitment computation, or other crypto internals.
pub mod verify {
    pub use crate::crypto::verify_ed25519;
    pub use crate::crypto::verify_signature;
    pub use crate::crypto::verify_vbc_signature;
    pub use crate::crypto::verify_sphincs;
    pub use crate::crypto::verify_dilithium;
    pub use crate::crypto::ct_eq;
    pub use crate::crypto::verify_clara_signature;
}

// Public computation API — ALL domain-specific hashing MUST go through Core.
// Lambda MUST NOT use blake3/sha3 directly. "Core is the bible."
pub mod compute {
    pub use crate::crypto::compute_validator_id;
    pub use crate::crypto::compute_receipt_commitment;
    pub use crate::crypto::compute_oods_attestation_payload;
    pub use crate::crypto::compute_recall_attestation_payload;
    pub use crate::crypto::compute_earnings_attestation_payload;
    pub use crate::crypto::compute_validator_pool_link_payload;
    pub use crate::crypto::compute_validator_claim_payload;
    pub use crate::crypto::compute_validator_withdrawal_payload;
    pub use crate::crypto::compute_withdrawal_mint_commitment;
    pub use crate::crypto::check_validator_withdrawal_conflict;
    pub use crate::crypto::compute_produced_state_id;
    pub use crate::crypto::compute_produced_state_from_tx;
    pub use crate::crypto::compute_state_hash;
    pub use crate::crypto::compute_cheque_commitment;
    pub use crate::crypto::compute_deed_wallet_id;
    pub use crate::crypto::format_deed_address;
    pub use crate::crypto::compute_txid;
    pub use crate::crypto::compute_scar_consent_voucher_payload;
    pub use crate::crypto::compute_redeem_request_commitment;
    pub use crate::crypto::compute_ack_fee_commitment;
    pub use crate::crypto::compute_vbc_signing_payload;
    pub use crate::crypto::compute_vbc_signing_payload_bytes;
    pub use crate::crypto::compute_clara_message;
    pub use crate::fact::compute_fact_commitment;
    pub use crate::fact::redeem_fact_chain_ref;
    pub use crate::fact::redeem_fact_sender_anchor;
    pub use crate::fact::compute_checkpoint_commitment;
    pub use crate::fact::compute_checkpoint_root;
    pub use crate::fact::compute_scar_heal_commitment;
    pub use crate::crypto::compute_burn_commitment;
    pub use crate::fact::verify_scar_recovery_proof;
    pub use crate::fact::sign_scar_heal_commitment;
    pub use crate::fact::sign_fact_commitment;
    pub use crate::fact::compress_fact_chain;
    pub use crate::fact::verify_and_compress_fact_chain;
    pub use crate::fact::merge_checkpoint_endorsements;
    pub use crate::fact::cosign_provisional_checkpoint;
    pub use crate::fact::advance_fact_checkpoint;
    pub use crate::fact::compute_pending_checkpoint_stub;
    #[cfg(feature = "ceremony")]
    pub use crate::crypto::sign_sphincs;
    #[cfg(feature = "ceremony")]
    pub use crate::crypto::sign_dilithium;
    pub use crate::mvib::compute_mvib_commitment;
    pub use crate::mvib::verify_mvib_binding;
    pub use crate::mvib::select_mv_set;
    pub use crate::console::compute_console_chain_hash;
    pub use crate::console::verify_console_certificate;
    pub use crate::console::select_selectors;
    pub use crate::console::resolve_election;
}

/// Client-side owner_proof API.
/// Webclient, PMC, and CLI use these to produce valid owner_proofs.
/// Never reimplement the derivation — always use these functions.
pub mod owner_proof {
    pub use crate::validation::derive_owner_keypair;
    pub use crate::validation::derive_owner_pubkey;
    pub use crate::validation::sign_owner_proof;
}

#[cfg(test)]
mod time_safety_tests {
    use super::*;

    #[test]
    fn test_verify_time_safety_passes() {
        // Must not panic on any 64-bit platform
        verify_time_safety();
    }

    #[test]
    fn test_unix_time_2040_representable() {
        // AXIOM requires timestamps beyond 2038 — u64 must hold 2040
        let t: u64 = UNIX_TIME_2040;
        assert!(t > 2_147_483_647, "64-bit time required");
        assert_eq!(t, 2_208_988_800);
    }

    #[test]
    fn test_system_clock_sane() {
        // Current time must be after 2020-01-01
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now > 1_577_836_800, "clock before 2020 — possible 32-bit truncation");
        // And before 2100 (sanity — catches overflow in the other direction)
        assert!(now < 4_102_444_800, "clock after 2100 — suspicious");
    }
}
