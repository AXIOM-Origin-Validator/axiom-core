//! VBC (Validator Birth Certificate) and NBC (Nabla Birth Certificate) verification — v0.9
//!
//! Verifies the chain of trust from a target VBC/NBC back to root authority keys.
//!
//! VBC chain structure (k=3 issuers):
//!   Target VBC (signed by 3 issuers)
//!     -> Issuer VBCs (each signed by 3 issuers)
//!       -> ... (recurse)
//!         -> Root authority keys (ROOT_AUTHORITY_PKS, chain terminates)
//!
//! NBC chain structure (k=1 issuer):
//!   Target NBC (signed by 1 issuer)
//!     -> Issuer NBC (signed by 1 issuer)
//!       -> ... (recurse)
//!         -> Nabla root authority keys (NABLA_ROOT_AUTHORITY_PKS, chain terminates)
//!
//! Trust model:
//!   - VBC: k=3 issuers, ROOT_AUTHORITY_PKS trust anchor
//!   - NBC: k=1 issuer, NABLA_ROOT_AUTHORITY_PKS trust anchor (key isolation)
//!
//! VBC/NBC v0.9 identity:
//!   - subject_pubkey_sphincs: Primary identity (32 bytes), chain signing
//!   - subject_pubkey_dilithium: Backup identity (1,952 bytes), quantum fallback
//!   - subject_pubkey_ed25519: Operational identity (32 bytes), witness signing + encryption
//!
//! Protocol mandate: All VBC/NBC signatures MUST be SPHINCS+ (SLH-DSA-SHA2-128s).

// CONSENSUS_CRITICAL

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use crate::crypto::{compute_vbc_signing_payload, verify_sphincs};
use crate::errors::CoreResult;
use crate::genesis::is_root_authority;
use crate::nabla_genesis::is_nabla_root_authority;
use crate::types::{ValidationError, VBC, VBCProofBundle};

/// Maximum VBC/NBC chain depth (root-signed = 0, Gen-1 = 1, etc.)
/// Prevents infinite recursion from circular chains.
const MAX_CHAIN_DEPTH: u8 = 10;

/// Check whether a VBC holder is mature enough to approve new validators.
/// Genesis validators are always mature. Others must wait VBC_APPROVAL_MATURITY_SECS.
pub fn is_approval_mature(vbc: &VBC, current_time: u64) -> bool {
    if crate::genesis::is_genesis_validator(&vbc.validator_id) {
        return true;
    }
    current_time.saturating_sub(vbc.issued_at) >= crate::types::VBC_APPROVAL_MATURITY_SECS
}

/// Required number of issuer signatures per VBC (always k=3).
/// This is a protocol constant, not a dev convenience — even dev builds
/// must verify the full issuer chain. The `dev-mode` feature only gates
/// the WALLET_IDENTITY_KEY compile guard, not VBC validation.
const VBC_REQUIRED_ISSUERS: usize = 3;

/// Required number of issuer signatures per NBC (k=1)
const NBC_REQUIRED_ISSUERS: usize = 1;

/// VBC/NBC format version v0.9
const EXPECTED_VERSION: u8 = 0x09;

// ═══════════════════════════════════════════════════════════════════
// VBC verification (k=3, ROOT_AUTHORITY_PKS)
// ═══════════════════════════════════════════════════════════════════

/// Verify a VBC proof bundle (k=3 issuers, ROOT_AUTHORITY_PKS trust anchor).
///
/// This is the main entry point for VBC verification.
/// Returns Ok(()) if the target VBC is valid, or an appropriate error.
///
/// Verification steps:
/// 1. Check VBC version and structure (3 issuers, 3 signatures)
/// 2. Check VBC timestamps (not expired, not future-dated)
/// 3. Verify validator_id = BLAKE3(sphincs_pk)
/// 4. Verify all 3 SPHINCS+ signatures over VBC commitment
/// 5. For root-signed VBCs: verify issuers are root authority keys (instant)
/// 6. For non-root: recurse — verify each issuer's VBC from supporting set
/// 7. All chains must terminate at root authority keys within MAX_CHAIN_DEPTH
// SECURITY-VBC: VBC chain of trust — recursive SPHINCS+ verification back to ROOT_AUTHORITY_PKS
pub fn verify_vbc_bundle(bundle: &VBCProofBundle, current_time: u64) -> CoreResult<()> {
    let mut verified_pks: BTreeSet<Vec<u8>> = BTreeSet::new();
    verify_chain_recursive(
        &bundle.target_vbc,
        &bundle.supporting_vbcs,
        current_time,
        0,
        &mut verified_pks,
        VBC_REQUIRED_ISSUERS,
        is_root_authority,
    )
}

/// Verify a VBC bundle with timestamp=0 (skip time checks — useful for testing)
pub fn verify_vbc_bundle_no_time(bundle: &VBCProofBundle) -> CoreResult<()> {
    verify_vbc_bundle(bundle, 0)
}

/// ⚠️ DANGER — structure-only VBC check, NO SPHINCS+ SIGNATURE VERIFICATION.
///
/// SEC-06: this function checks ONLY structure + that the issuer chain
/// terminates at a root authority key **by value**. The root keys are public
/// constants compiled into Core, so ANYONE can build
/// `issuers = [ROOT_1, ROOT_2, ROOT_3]` with garbage signatures and an
/// attacker-chosen subject key and get `Ok(())`. It is therefore FORGEABLE
/// on untrusted/first-encounter input and MUST NOT gate a trust decision on
/// any network-supplied VBC.
///
/// SAFE uses (the only sanctioned ones):
///   - re-checking a VBC that was ALREADY fully SPHINCS+-verified earlier in
///     the same flow (immutable doc → still valid), or
///   - a cheap corruption/misconfiguration check on the operator's OWN
///     locally-trusted VBC at boot, where the real chain verification happens
///     elsewhere (e.g. Lambda startup full-verify, ceremony issuance).
///
/// The `_DANGER_no_sig` suffix is deliberate — every call site must visibly
/// acknowledge that signatures are skipped. For untrusted input use
/// `verify_vbc_bundle` / `verify_vbc_bundle_no_time` (full SPHINCS+ walk).
/// Checks: version, chain_depth, issuer count, distinct issuers, validator_id,
///         ed25519 pk present, issuer chain terminates at root authority keys.
pub fn verify_vbc_bundle_structure_only_DANGER_no_sig(bundle: &VBCProofBundle) -> CoreResult<()> {
    let mut verified_pks: BTreeSet<Vec<u8>> = BTreeSet::new();
    verify_structure_recursive(
        &bundle.target_vbc,
        &bundle.supporting_vbcs,
        0,
        &mut verified_pks,
        VBC_REQUIRED_ISSUERS,
        is_root_authority,
    )
}

// ═══════════════════════════════════════════════════════════════════
// NBC verification (k=1, NABLA_ROOT_AUTHORITY_PKS)
// ═══════════════════════════════════════════════════════════════════

/// Verify an NBC proof bundle (k=1 issuer, NABLA_ROOT_AUTHORITY_PKS trust anchor).
///
/// Same verification logic as VBC but with:
/// - k=1: Only 1 issuer signature required per NBC
/// - Trust anchor: NABLA_ROOT_AUTHORITY_PKS (separate from VBC root keys)
///
/// NBC trust chain:
///   Genesis NBCs (chain_depth=0): signed by 1 Nabla root authority key
///   Non-genesis (chain_depth=1+): signed by 1 existing Nabla node
///   All chains must trace back to NABLA_ROOT_AUTHORITY_PKS
pub fn verify_nbc_bundle(bundle: &VBCProofBundle, current_time: u64) -> CoreResult<()> {
    let mut verified_pks: BTreeSet<Vec<u8>> = BTreeSet::new();
    verify_chain_recursive(
        &bundle.target_vbc,
        &bundle.supporting_vbcs,
        current_time,
        0,
        &mut verified_pks,
        NBC_REQUIRED_ISSUERS,
        is_nabla_root_authority,
    )
}

/// Verify an NBC bundle with timestamp=0 (skip time checks — useful for testing)
pub fn verify_nbc_bundle_no_time(bundle: &VBCProofBundle) -> CoreResult<()> {
    verify_nbc_bundle(bundle, 0)
}

/// ⚠️ DANGER — structure-only NBC check, NO SPHINCS+ SIGNATURE VERIFICATION.
///
/// SEC-06: NBC sibling of `verify_vbc_bundle_structure_only_DANGER_no_sig`
/// (k=1, Nabla root keys). Same forgeability caveat — the Nabla root keys are
/// public, so structure-only is forgeable on untrusted input. Sanctioned only
/// for already-verified or locally-trusted self-identity NBCs. Use
/// `verify_nbc_bundle` / `verify_nbc_bundle_no_time` for untrusted input.
pub fn verify_nbc_bundle_structure_only_DANGER_no_sig(bundle: &VBCProofBundle) -> CoreResult<()> {
    let mut verified_pks: BTreeSet<Vec<u8>> = BTreeSet::new();
    verify_structure_recursive(
        &bundle.target_vbc,
        &bundle.supporting_vbcs,
        0,
        &mut verified_pks,
        NBC_REQUIRED_ISSUERS,
        is_nabla_root_authority,
    )
}

/// Lightweight VBC expiry-only check — timestamps only, no SPHINCS+ or chain walk.
///
/// Called per-transaction in CL2/CL3 to quickly reject transactions that reference
/// expired validator VBCs. The expensive chain verification happens at Core load time;
/// this is a fast gate that prevents stale validators from witnessing new transactions.
///
/// Checks: each VBC's `expires_at` against `tx_epoch`, and `issued_at` <= `tx_epoch`.
/// Returns Ok(()) if all VBCs in prev_receipts are temporally valid.
pub fn verify_vbc_expiry(inputs: &crate::types::PublicInputs) -> CoreResult<()> {
    let tx_epoch = inputs.transaction.epoch;
    // HIGH-1 fix: epoch=0 bypass REMOVED. Dev-mode uses the dev-mode feature flag,
    // not epoch=0. An attacker could craft epoch=0 TXs to use expired VBCs.
    #[cfg(feature = "dev-mode")]
    if tx_epoch == 0 {
        return Ok(()); // Dev-mode only: skip time checks for testing
    }
    for receipt in &inputs.prev_receipts {
        for witness in &receipt.witness_sigs {
            if let Some(bundle) = &witness.vbc_bundle {
                let vbc = &bundle.target_vbc;
                if vbc.expires_at != 0 && vbc.expires_at < tx_epoch {
                    return Err(crate::types::ValidationError::VBCExpired {
                        expires_at: vbc.expires_at,
                        current_tick: tx_epoch,
                    });
                }
                if vbc.issued_at > tx_epoch {
                    return Err(crate::types::ValidationError::VBCNotYetValid {
                        issued_at: vbc.issued_at,
                        current_tick: tx_epoch,
                    });
                }
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Parameterized inner verification (shared by VBC and NBC paths)
// ═══════════════════════════════════════════════════════════════════

/// Recursive chain verification with full SPHINCS+ signature checks.
///
/// Parameters:
///   - `required_issuers`: k=3 for VBC, k=1 for NBC
///   - `root_check`: is_root_authority for VBC, is_nabla_root_authority for NBC
fn verify_chain_recursive(
    vbc: &VBC,
    supporting: &[VBC],
    current_time: u64,
    depth: u8,
    verified_pks: &mut BTreeSet<Vec<u8>>,
    required_issuers: usize,
    root_check: fn(&[u8]) -> bool,
) -> CoreResult<()> {
    // Guard: prevent infinite recursion
    if depth > MAX_CHAIN_DEPTH {
        return Err(ValidationError::VBCChainTooDeep);
    }

    // Already verified this PK in this chain walk? Skip (prevents cycles)
    if verified_pks.contains(&vbc.subject_pubkey_sphincs) {
        return Ok(());
    }

    // Step 1: Version check
    if vbc.version != EXPECTED_VERSION {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 1: version={} expected={}", vbc.version, EXPECTED_VERSION);
        return Err(ValidationError::InvalidVBC);
    }

    // Step 2: Chain depth in VBC must match actual depth
    if vbc.chain_depth != depth {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 2: chain_depth={} expected_depth={}", vbc.chain_depth, depth);
        return Err(ValidationError::InvalidVBC);
    }

    // Step 3: Must have exactly `required_issuers` issuers and signatures
    if vbc.issuer_set.len() != required_issuers {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 3a: issuer_set.len()={} required={}", vbc.issuer_set.len(), required_issuers);
        return Err(ValidationError::InvalidVBCCount);
    }
    if vbc.signatures.len() != required_issuers {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 3b: signatures.len()={} required={}", vbc.signatures.len(), required_issuers);
        return Err(ValidationError::InvalidVBCCount);
    }

    // Step 4: Check all issuers are distinct
    {
        let mut seen: BTreeSet<&Vec<u8>> = BTreeSet::new();
        for pk in &vbc.issuer_set {
            if !seen.insert(pk) {
                #[cfg(feature = "std")]
                eprintln!("[VBC_DIAG] FAIL step 4: duplicate issuer pk");
                return Err(ValidationError::DuplicateValidator);
            }
        }
    }

    // Step 5: Validator ID must match BLAKE3 of SPHINCS+ PK
    let expected_id = *blake3::hash(&vbc.subject_pubkey_sphincs).as_bytes();
    if vbc.validator_id != expected_id {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 5: validator_id mismatch (sphincs_pk len={})", vbc.subject_pubkey_sphincs.len());
        return Err(ValidationError::InvalidVBC);
    }

    // Step 6: Ed25519 PK must be present (32 bytes)
    if vbc.subject_pubkey_ed25519.len() != 32 {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 6: ed25519_pk len={} (expected 32)", vbc.subject_pubkey_ed25519.len());
        return Err(ValidationError::InvalidVBC);
    }

    // Step 6b: Validate proof_cap if present
    if !vbc.proof_cap.is_empty() && vbc.proof_cap != "dmap" && vbc.proof_cap != "zkvm" {
        #[cfg(feature = "std")]
        eprintln!("[VBC_DIAG] FAIL step 6b: invalid proof_cap='{}'", vbc.proof_cap);
        return Err(ValidationError::InvalidVBC);
    }

    // Step 7: Check timestamps
    if current_time > 0 {
        if vbc.expires_at != 0 && vbc.expires_at < current_time {
            return Err(ValidationError::VBCExpired {
                expires_at: vbc.expires_at,
                current_tick: current_time,
            });
        }
        if vbc.issued_at > current_time {
            return Err(ValidationError::VBCNotYetValid {
                issued_at: vbc.issued_at,
                current_tick: current_time,
            });
        }
    }

    // Step 8: Verify all SPHINCS+ signatures over VBC commitment
    let signing_payload = compute_vbc_signing_payload(vbc);

    for i in 0..required_issuers {
        if let Err(e) = verify_sphincs(
            &vbc.issuer_set[i],
            &signing_payload,
            &vbc.signatures[i],
        ) {
            #[cfg(feature = "std")]
            eprintln!("[VBC_DIAG] FAIL step 8: SPHINCS+ sig {} failed: {:?} (issuer_pk_len={}, sig_len={})",
                i, e, vbc.issuer_set[i].len(), vbc.signatures[i].len());
            return Err(e);
        }
    }

    // Mark this VBC as verified
    verified_pks.insert(vbc.subject_pubkey_sphincs.clone());

    // Step 9: Check if all issuers are root authority keys
    let all_issuers_are_root = vbc.issuer_set.iter()
        .all(|pk| root_check(pk));

    if all_issuers_are_root {
        // Root-signed — chain terminates here
        return Ok(());
    }

    // CRITICAL: chain_depth=0 means this cert MUST be signed by root authority keys.
    // If we get here with depth=0, the issuer PKs don't match the expected root keys.
    // This is either a stale Core build or a mirror universe attack.
    if depth == 0 {
        #[cfg(feature = "std")]
        {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  CRITICAL: ROOT KEY MISMATCH — POSSIBLE MIRROR UNIVERSE     ║");
            eprintln!("╠══════════════════════════════════════════════════════════════╣");
            eprintln!("║  A genesis cert (chain_depth=0) has issuer keys that do NOT ║");
            eprintln!("║  match any root authority keys compiled into this Core.     ║");
            eprintln!("║                                                             ║");
            eprintln!("║  CAUSE 1: Core compiled with stale genesis.rs               ║");
            eprintln!("║    FIX: Copy genesis-output/genesis_constants.rs into       ║");
            eprintln!("║         axiom-core/core-logic/src/genesis.rs, rebuild Core  ║");
            eprintln!("║                                                             ║");
            eprintln!("║  CAUSE 2: Mirror universe attack — cert from outside this   ║");
            eprintln!("║           network's trust root. DO NOT ACCEPT.              ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            eprintln!("  Issuer keys ({}):", vbc.issuer_set.len());
            for (i, pk) in vbc.issuer_set.iter().enumerate() {
                eprintln!("    issuer[{}]: len={} hex={}", i, pk.len(), hex::encode(&pk[..pk.len().min(16)]));
            }
        }
        return Err(ValidationError::VBCRootKeyMismatch);
    }

    // Step 10: Non-root issuers — recurse to verify each issuer's cert
    for issuer_pk in &vbc.issuer_set {
        // Already verified?
        if verified_pks.contains(issuer_pk) {
            continue;
        }

        // Root authority? Instant accept.
        if root_check(issuer_pk) {
            continue;
        }

        // Find issuer's cert in supporting set (match on SPHINCS+ PK)
        let issuer_vbc = supporting.iter()
            .find(|v| v.subject_pubkey_sphincs == *issuer_pk)
            .ok_or(ValidationError::VBCMissingIssuer)?;

        // SEC-10 (latent): when multi-level VBC issuance is enabled, the
        // issuer-maturity gate (is_approval_mature against the consensus-safe
        // tx.epoch carried in `current_time`) must be enforced HERE, inside
        // Core, not only by Lambda — otherwise a malicious Lambda with a
        // freshly-minted validator triplet could present depth>0 chains.
        // NOT wired today because this recursion is unreachable: the entry
        // always starts at depth 0 and the `if depth == 0` mirror-universe
        // guard above requires depth-0 targets to be root-signed, so no
        // chain ever recurses. Wiring this needs the "mature when it issued
        // the child" vs "mature now" semantics decided alongside enabling
        // multi-level issuance — see SEC-10 report note. The `current_time`
        // (tx.epoch) is already threaded so Step 7 below enforces issuer
        // EXPIRY the moment the path becomes reachable.

        // Recurse
        verify_chain_recursive(issuer_vbc, supporting, current_time, depth + 1, verified_pks, required_issuers, root_check)?;
    }

    Ok(())
}

/// Structure-only recursive verification (no SPHINCS+ sig checks).
///
/// Parameters:
///   - `required_issuers`: k=3 for VBC, k=1 for NBC
///   - `root_check`: is_root_authority for VBC, is_nabla_root_authority for NBC
fn verify_structure_recursive(
    vbc: &VBC,
    supporting: &[VBC],
    depth: u8,
    verified_pks: &mut BTreeSet<Vec<u8>>,
    required_issuers: usize,
    root_check: fn(&[u8]) -> bool,
) -> CoreResult<()> {
    if depth > MAX_CHAIN_DEPTH {
        return Err(ValidationError::VBCChainTooDeep);
    }
    if verified_pks.contains(&vbc.subject_pubkey_sphincs) {
        return Ok(());
    }
    if vbc.version != EXPECTED_VERSION {
        return Err(ValidationError::InvalidVBC);
    }
    if vbc.chain_depth != depth {
        return Err(ValidationError::InvalidVBC);
    }
    if vbc.issuer_set.len() != required_issuers || vbc.signatures.len() != required_issuers {
        return Err(ValidationError::InvalidVBCCount);
    }
    {
        let mut seen: BTreeSet<&Vec<u8>> = BTreeSet::new();
        for pk in &vbc.issuer_set {
            if !seen.insert(pk) {
                return Err(ValidationError::DuplicateValidator);
            }
        }
    }
    let expected_id = *blake3::hash(&vbc.subject_pubkey_sphincs).as_bytes();
    if vbc.validator_id != expected_id {
        return Err(ValidationError::InvalidVBC);
    }
    if vbc.subject_pubkey_ed25519.len() != 32 {
        return Err(ValidationError::InvalidVBC);
    }
    // Validate proof_cap if present
    if !vbc.proof_cap.is_empty() && vbc.proof_cap != "dmap" && vbc.proof_cap != "zkvm" {
        return Err(ValidationError::InvalidVBC);
    }

    // NO SPHINCS+ signature verification here — that's the whole point

    verified_pks.insert(vbc.subject_pubkey_sphincs.clone());

    let all_issuers_are_root = vbc.issuer_set.iter()
        .all(|pk| root_check(pk));
    if all_issuers_are_root {
        return Ok(());
    }
    if depth == 0 {
        return Err(ValidationError::VBCRootKeyMismatch);
    }
    for issuer_pk in &vbc.issuer_set {
        if verified_pks.contains(issuer_pk) || root_check(issuer_pk) {
            continue;
        }
        let issuer_vbc = supporting.iter()
            .find(|v| v.subject_pubkey_sphincs == *issuer_pk)
            .ok_or(ValidationError::VBCMissingIssuer)?;
        verify_structure_recursive(issuer_vbc, supporting, depth + 1, verified_pks, required_issuers, root_check)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{VBC, VBCProofBundle};
    
    /// Helper: create a v0.9 VBC with given params
    fn make_test_vbc(
        sphincs_pk: &[u8],
        ed25519_pk: &[u8],
        chain_depth: u8,
        issuer_set: Vec<Vec<u8>>,
        signatures: Vec<Vec<u8>>,
        issued_at: u64,
        expires_at: u64,
    ) -> VBC {
        let validator_id = *blake3::hash(sphincs_pk).as_bytes();
        VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id,
            subject_pubkey_sphincs: sphincs_pk.to_vec(),
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: ed25519_pk.to_vec(),
            pgp_fingerprint: vec![],
            node_name: String::new(),
            issued_at,
            expires_at,
            chain_depth,
            issuer_set,
            signatures,
            proof_cap: String::new(),
            // max_tx=0 in tests: Core doesn't enforce NBC TX budget (Nabla does).
            // Production NBCs use NBC_TX_BUDGET=50,000 (nabla/src/constants.rs, cc.rs).
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Approval maturity tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_approval_maturity_genesis_always_true() {
        // Genesis validator IDs are in GENESIS_VALIDATORS — use the first one
        use crate::genesis::GENESIS_VALIDATORS;
        let vbc = VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: GENESIS_VALIDATORS[0],
            subject_pubkey_sphincs: vec![0u8; 32],
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: vec![0u8; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1000,
            expires_at: u64::MAX,
            chain_depth: 0,
            issuer_set: vec![],
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        };
        // Genesis is always mature, even at time 0
        assert!(is_approval_mature(&vbc, 0));
        assert!(is_approval_mature(&vbc, 1000));
    }

    #[test]
    fn test_approval_maturity_new_validator() {
        let pk = [0xFFu8; 32];
        let vid = *blake3::hash(&pk).as_bytes();
        let vbc = VBC {
            network_size_baseline: 0,
            baseline_tick: 0,
            version: EXPECTED_VERSION,
            validator_id: vid,
            subject_pubkey_sphincs: pk.to_vec(),
            subject_pubkey_dilithium: vec![0u8; 1952],
            subject_pubkey_ed25519: vec![0u8; 32],
            pgp_fingerprint: vec![],
            node_name: String::new(),
            proof_cap: String::new(),
            issued_at: 1_000_000,
            expires_at: u64::MAX,
            chain_depth: 1,
            issuer_set: vec![],
            signatures: vec![],
            max_tx: 0,
            founding_vbc_hash: [0u8; 32],
        };
        let maturity = crate::types::VBC_APPROVAL_MATURITY_SECS;
        // Before 30 days
        assert!(!is_approval_mature(&vbc, 1_000_000 + maturity - 1));
        // At exactly 30 days
        assert!(is_approval_mature(&vbc, 1_000_000 + maturity));
        // After 30 days
        assert!(is_approval_mature(&vbc, 1_000_000 + maturity + 1));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Proof cap validation tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_proof_cap_empty_accepted() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        // proof_cap is empty by default — structure check should pass (fails at root key, not proof_cap)
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        let result = verify_vbc_bundle_structure_only_DANGER_no_sig(&bundle);
        assert!(matches!(result, Err(ValidationError::VBCRootKeyMismatch)));
    }

    #[test]
    fn test_proof_cap_dmap_accepted() {
        let mut vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        vbc.proof_cap = "dmap".into();
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        let result = verify_vbc_bundle_structure_only_DANGER_no_sig(&bundle);
        // Should fail at root key check, not proof_cap
        assert!(matches!(result, Err(ValidationError::VBCRootKeyMismatch)));
    }

    #[test]
    fn test_proof_cap_zkvm_accepted() {
        let mut vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        vbc.proof_cap = "zkvm".into();
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        let result = verify_vbc_bundle_structure_only_DANGER_no_sig(&bundle);
        assert!(matches!(result, Err(ValidationError::VBCRootKeyMismatch)));
    }

    #[test]
    fn test_proof_cap_invalid_rejected() {
        let mut vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        vbc.proof_cap = "invalid".into();
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        let result = verify_vbc_bundle_structure_only_DANGER_no_sig(&bundle);
        assert!(matches!(result, Err(ValidationError::InvalidVBC)));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Existing VBC verification tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_wrong_version_rejected() {
        let mut vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        vbc.version = 0x01;  // Wrong version
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_without_issuers_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![], vec![],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBCCount)));
    }
    
    #[test]
    fn test_wrong_issuer_count_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32]],  // Only 2
            vec![vec![]; 2],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBCCount)));
    }
    
    #[test]
    fn test_duplicate_issuers_rejected() {
        let dup_pk = vec![0x01u8; 32];
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![dup_pk.clone(), dup_pk.clone(), vec![0x02; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::DuplicateValidator)));
    }
    
    #[test]
    fn test_wrong_validator_id_rejected() {
        let mut vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        vbc.validator_id = [0x00u8; 32];  // Wrong ID
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_missing_ed25519_pk_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[],  // Empty ed25519
            0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }
    
    #[test]
    fn test_expired_vbc_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            1000, 2000,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle(&bundle, 5000), Err(ValidationError::VBCExpired { .. })));
    }
    
    #[test]
    fn test_future_vbc_rejected() {
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            10000, 20000,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle(&bundle, 5000), Err(ValidationError::VBCNotYetValid { .. })));
    }

    // ═══════════════════════════════════════════════════════════════════
    // NBC verification tests (k=1, NABLA_ROOT_AUTHORITY_PKS)
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_nbc_wrong_version_rejected() {
        let mut nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32]],
            vec![vec![]],
            0, u64::MAX,
        );
        nbc.version = 0x01;
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBC)));
    }

    #[test]
    fn test_nbc_no_issuers_rejected() {
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![], vec![],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBCCount)));
    }

    #[test]
    fn test_nbc_too_many_issuers_rejected() {
        // NBC requires k=1 — passing 3 issuers should be rejected
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_nbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBCCount)));
    }

    #[test]
    fn test_nbc_accepts_one_issuer() {
        // NBC with 1 issuer — should pass structural checks (will fail on sig since it's fake)
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32]],
            vec![vec![]],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        // Structure-only check should fail at root key check (fake key), not issuer count
        let result = verify_nbc_bundle_structure_only_DANGER_no_sig(&bundle);
        assert!(matches!(result, Err(ValidationError::VBCRootKeyMismatch)));
    }

    #[test]
    fn test_nbc_structure_only_accepts_nabla_root() {
        // NBC with 1 issuer that IS a Nabla root authority key
        use crate::nabla_genesis::NABLA_ROOT_AUTHORITY_PKS;
        let root_pk = NABLA_ROOT_AUTHORITY_PKS[0].to_vec();
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![root_pk],
            vec![vec![0u8; 7856]], // fake sig (structure-only skips sig verification)
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        // Structure-only should accept since issuer is a Nabla root key
        assert!(verify_nbc_bundle_structure_only_DANGER_no_sig(&bundle).is_ok());
    }

    #[test]
    fn test_nbc_structure_rejects_validator_root_key() {
        // NBC with 1 issuer that is a VALIDATOR root key (not Nabla root) — should reject
        use crate::genesis::ROOT_AUTHORITY_PKS;
        let validator_root_pk = ROOT_AUTHORITY_PKS[0].to_vec();
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![validator_root_pk],
            vec![vec![0u8; 7856]],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        // Nabla root check should NOT recognize validator root keys
        assert!(matches!(verify_nbc_bundle_structure_only_DANGER_no_sig(&bundle), Err(ValidationError::VBCRootKeyMismatch)));
    }

    #[test]
    fn test_nbc_expired_rejected() {
        let nbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32]],
            vec![vec![]],
            1000, 2000,
        );
        let bundle = VBCProofBundle { target_vbc: nbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_nbc_bundle(&bundle, 5000), Err(ValidationError::VBCExpired { .. })));
    }

    #[test]
    fn test_vbc_rejects_one_issuer() {
        // Verify VBC path still requires k=3 — passing k=1 should fail
        let vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32]],
            vec![vec![]],
            0, u64::MAX,
        );
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };
        assert!(matches!(verify_vbc_bundle_no_time(&bundle), Err(ValidationError::InvalidVBCCount)));
    }

    /// SEC-10: the production prev_receipt / own-VBC verification paths now
    /// pass the consensus-safe tx.epoch (was _no_time), so a genesis (depth-0,
    /// root-signed) validator's OWN VBC expiry is enforced inside Core. Build
    /// a real root-signed VBC and assert verify_vbc_bundle rejects it once
    /// tx.epoch passes expires_at, but accepts it before — and that epoch=0
    /// (dev/genesis) skips the time check (no honest-validator divergence).
    #[test]
    fn test_target_vbc_expiry_enforced_against_tx_epoch() {
        use fips205::slh_dsa_sha2_128s;
        use fips205::traits::SerDes;

        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let keys_dir = manifest.join("../../root-keys/authority");
        if !keys_dir.join("root_1.key").exists() {
            eprintln!("SKIP: root-keys/authority/ not found — cannot build signed VBC");
            return;
        }
        let root_sk: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(keys_dir.join(format!("root_{i}.key"))).unwrap())
            .collect();
        let root_pk: Vec<Vec<u8>> = (1..=3)
            .map(|i| std::fs::read(keys_dir.join(format!("root_{i}.pub"))).unwrap())
            .collect();

        // A genesis (chain_depth 0) VBC signed by the three real root keys,
        // issued at 1000, expiring at 2000.
        let (pk, _sk) = slh_dsa_sha2_128s::try_keygen().unwrap();
        let pk_b = pk.into_bytes().to_vec();
        let mut vbc = make_test_vbc(&pk_b, &[0xBB; 32], 0, root_pk, vec![], 1_000, 2_000);
        let payload = compute_vbc_signing_payload(&vbc);
        vbc.signatures = root_sk.iter()
            .map(|sk| crate::crypto::sign_sphincs(sk, &payload).unwrap())
            .collect();
        let bundle = VBCProofBundle { target_vbc: vbc, supporting_vbcs: vec![] };

        // Before expiry (tx.epoch=1500): accepted.
        assert!(verify_vbc_bundle(&bundle, 1_500).is_ok(),
            "unexpired root-signed VBC must verify against tx.epoch");
        // After expiry (tx.epoch=5000): rejected — this is the reachable gain
        // from switching the production sites off _no_time.
        assert!(matches!(verify_vbc_bundle(&bundle, 5_000), Err(ValidationError::VBCExpired { .. })),
            "expired VBC must be rejected once tx.epoch passes expires_at");
        // epoch=0 (dev/genesis): time check skipped.
        assert!(verify_vbc_bundle(&bundle, 0).is_ok(),
            "epoch=0 must skip the expiry check");
    }

    // ================================================================
    // CRITICAL bug regression: epoch=0 VBC expiry bypass (HIGH-1 fix)
    // ================================================================

    /// HIGH-1 regression: epoch=0 must NOT bypass VBC expiry checks
    /// (unless dev-mode feature is enabled).
    /// Before the fix, any transaction with epoch=0 would skip all VBC
    /// expiry verification, allowing expired VBCs to be used by simply
    /// setting epoch=0 on the transaction.
    #[cfg(not(feature = "dev-mode"))]
    #[test]
    fn test_epoch_zero_does_not_bypass_vbc_expiry() {
        use crate::types::{
            CoreLogicMode, PublicInputs, Transaction, TxKind, Receipt, WitnessSig,
        };

        // Build an expired VBC (expires_at=2000, well in the past)
        let expired_vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            1000, 2000, // issued_at=1000, expires_at=2000
        );
        let bundle = VBCProofBundle {
            target_vbc: expired_vbc,
            supporting_vbcs: vec![],
        };

        // Create PublicInputs with epoch=0 and a prev_receipt carrying the expired VBC
        let inputs = PublicInputs {
            mode: CoreLogicMode::CL2,
            transaction: Transaction {
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 1,
                receiver_wallet_id: "test@test.com/aabbccdd".into(),
                receiver_address: None,
                amount: 100_000,
                reference: "test".into(),
                nonce: 1,
                epoch: 0, // THE ATTACK VECTOR: epoch=0 used to bypass expiry
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
            prev_receipts: vec![Receipt {
                txid: [0u8; 32],
                state_hash: [0u8; 32],
                produced_state_id: [0u8; 32],
                new_wallet_seq: 1,
                commitment_hash: [0u8; 32],
                sdid: [0u8; 32],
                lineage_hash: [0u8; 32],
                core_version: String::new(),
                core_id: [0u8; 32],
                witness_sigs: vec![WitnessSig {
                    validator_id: [0u8; 32],
                    validator_pk: vec![0u8; 32],
                    vbc_bundle: Some(bundle),
                    carrier_type: String::new(),
                    carrier_address: String::new(),
                    signature: vec![0u8; 64],
                    execution_proof: vec![],
                    proof_type: 1,
                    availability_attestation: None,
                    validator_hints: vec![],
                    fact_signature: None,
                    checkpoint_sig: None,
                    receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
                }],
                epoch: 1,
                fact_proof: None,
                required_k: 3,
                receipt_commitment: [0u8; 32],
                fee_breakdown: Vec::new(),
                is_dev_class: false,
            }],
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
        };

        // verify_vbc_expiry must REJECT even with epoch=0
        let result = verify_vbc_expiry(&inputs);
        assert!(result.is_err(),
            "HIGH-1 REGRESSION: epoch=0 bypasses VBC expiry check! \
             Expired VBCs must be rejected regardless of epoch value. \
             Got: {:?}", result);
        assert!(matches!(result, Err(ValidationError::VBCNotYetValid { .. })),
            "Expected VBCNotYetValid (issued_at=1000 > epoch=0), got: {:?}", result);
    }

    /// Verify that expired VBC is caught even when epoch > 0.
    /// This is the normal (non-bypass) case — sanity check.
    #[test]
    fn test_expired_vbc_rejected_by_verify_vbc_expiry() {
        use crate::types::{
            CoreLogicMode, PublicInputs, Transaction, TxKind, Receipt, WitnessSig,
        };

        let expired_vbc = make_test_vbc(
            &[0xFFu8; 32], &[0xAAu8; 32], 0,
            vec![vec![0x01; 32], vec![0x02; 32], vec![0x03; 32]],
            vec![vec![]; 3],
            1000, 2000,
        );
        let bundle = VBCProofBundle {
            target_vbc: expired_vbc,
            supporting_vbcs: vec![],
        };

        let inputs = PublicInputs {
            oods_attestation: None,
            recall_attestation: None,
            mode: CoreLogicMode::CL2,
            transaction: Transaction {
                consumed_state_id: [0u8; 32],
                client_pk: vec![0u8; 32],
                sender_wallet_id: String::new(),
                wallet_seq: 1,
                receiver_wallet_id: "test@test.com/aabbccdd".into(),
                receiver_address: None,
                amount: 100_000,
                reference: "test".into(),
                nonce: 1,
                epoch: 5000, // well past expires_at=2000
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
            prev_receipts: vec![Receipt {
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
                witness_sigs: vec![WitnessSig {
                    validator_id: [0u8; 32],
                    validator_pk: vec![0u8; 32],
                    vbc_bundle: Some(bundle),
                    carrier_type: String::new(),
                    carrier_address: String::new(),
                    signature: vec![0u8; 64],
                    execution_proof: vec![],
                    proof_type: 1,
                    availability_attestation: None,
                    validator_hints: vec![],
                    fact_signature: None,
                    checkpoint_sig: None,
                    receipt_signature: None,
                receipt_commitment_sig: None,
                rate_bps: 0,
                slot_amount: 0,
                }],
                epoch: 1,
                fact_proof: None,
                required_k: 3,
                receipt_commitment: [0u8; 32],
                fee_breakdown: Vec::new(),
                is_dev_class: false,
            }],
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
        };

        let result = verify_vbc_expiry(&inputs);
        assert!(result.is_err(), "Expired VBC must be rejected");
        assert!(matches!(result, Err(ValidationError::VBCExpired { .. })),
            "Expected VBCExpired, got: {:?}", result);
    }
}
